"""Standalone, explicitly enabled worker for the M4 synthetic validation API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

class APIError(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body
        super().__init__(f'HTTP {status}: {body}')

class API:
    def __init__(self, url, token, timeout=3):
        self.url, self.token, self.timeout = url.rstrip('/'), token, timeout
    def post(self, path, body):
        request = urllib.request.Request(self.url+path, json.dumps(body).encode(), {'Authorization':'Bearer '+self.token,'Content-Type':'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.load(response) if response.status != 204 else None
        except urllib.error.HTTPError as error:
            try: body = json.loads(error.read())
            except ValueError: body = {}
            raise APIError(error.code, body) from error

def digest(path):
    h = hashlib.sha256()
    with open(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def beneath(root, relative):
    if not isinstance(relative,str) or Path(relative).is_absolute():
        raise ValueError('path must be shared-root relative')
    path = (root/relative).resolve()
    if not path.is_relative_to(root): raise ValueError('path escapes shared root')
    return path

class Worker:
    def __init__(self, api, root, worker, *, lease=15, heartbeat=2, timeout=120, log_bytes=65536, memory_bytes=1073741824, file_bytes=67108864, cpu_seconds=60, command=None):
        self.api, self.root, self.worker = api, Path(root).resolve(), worker
        self.lease, self.heartbeat, self.timeout = lease, heartbeat, timeout
        self.log_bytes, self.memory_bytes, self.file_bytes, self.cpu_seconds = log_bytes, memory_bytes, file_bytes, cpu_seconds
        self.command = command
        self.stopping = False
    def stop(self, *_): self.stopping = True
    def attempt(self, claim):
        identity = {key:claim[key] for key in ('attempt','token')}
        identity['worker'] = self.worker
        endpoint = '/v1/jobs/'+claim['id']
        guardian = None
        cancelled = False
        owned = True
        retryable = False
        try:
            payload = claim['payload']
            paths = {}
            for name in ('network','process','profile'):
                paths[name] = beneath(self.root,payload[name]['path'])
                if digest(paths[name]) != payload[name]['sha256']: raise ValueError(name+' hash mismatch')
            output = beneath(self.root,claim['output_dir'])
            # Exclusive attempt namespace. Core writes artifacts before its final manifest.
            output.parent.mkdir(parents=True,exist_ok=True)
            control = output.parent/(output.name+'.worker')
            try:
                control.mkdir(mode=0o700,exist_ok=False)
            except FileExistsError:
                # Another invocation owns this immutable namespace. Never fail
                # its live claim or overwrite its recovery evidence.
                return 'reconciliation_required'
            kind = payload.get('kind')
            module = 'cpag_core.dual_source_export' if kind == 'dual-source' else 'cpag_core'
            command = self.command or [sys.executable,'-m',module]
            command = command + ['--network',str(paths['network']),'--process',str(paths['process']),'--profile',str(paths['profile']),'--output',str(output),'--synthetic']
            if kind == 'dual-source':
                command += ['--run-id',claim['id'],'--attempt-id',str(claim['attempt'])]
            # Deliberately pass only runtime environment; no database/API credentials.
            env = {key:value for key,value in os.environ.items() if key in ('PATH','PYTHONPATH','LANG','LC_ALL','SYSTEMROOT','TMPDIR')}
            config = {'identity':{'id':claim['id'],'attempt':claim['attempt'],'worker':self.worker,'token':claim['token']},'command':command,'env':env,'timeout':self.timeout,'kill_grace':1,'log_bytes':self.log_bytes,'memory_bytes':self.memory_bytes,'file_bytes':self.file_bytes,'cpu_seconds':self.cpu_seconds,'pid_file':str(control/'child.pid'),'exit_file':str(control/'exit.json'),'stdout':str(control/'stdout.log'),'stderr':str(control/'stderr.log')}
            config_file = control/'supervisor.json'
            with open(config_file, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                json.dump(config, stream)
            guardian = subprocess.Popen([sys.executable,str(Path(__file__).with_name('guardian.py')),str(config_file)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env=env)
            next_heartbeat = time.monotonic()
            while guardian.poll() is None:
                if self.stopping: break
                if time.monotonic() >= next_heartbeat:
                    try:
                        response = self.api.post(endpoint+'/heartbeat',{**identity,'lease_seconds':self.lease})
                        if response and response.get('state') == 'cancelling':
                            cancelled = True
                            break
                    except APIError as error:
                        cancelled = error.status == 409 and error.body.get('state') == 'cancelling'
                        owned = cancelled
                        break
                    except (OSError,ValueError):
                        owned = False
                        break
                    next_heartbeat = time.monotonic()+self.heartbeat
                time.sleep(.05)
            if guardian.poll() is None:
                guardian.stdin.close()  # EOF is also guaranteed on SIGKILL of worker.
            guardian.wait(timeout=5)
            if not guardian.stdin.closed: guardian.stdin.close()
            if guardian.returncode != 0 or not (control/'exit.json').exists():
                return 'lost_lease'  # No proof child exited: never ACK or write terminal state.
            result = json.loads((control/'exit.json').read_text())
            if cancelled:
                self.api.post(endpoint+'/ack-cancel',identity)
                return 'cancelled'
            if not owned: return 'lost_lease'
            if self.stopping: return 'stopped'
            if result['returncode'] or result['reason'] != 'exited':
                retryable = result['reason'] == 'timeout' or result['returncode'] < 0
                raise ValueError('core '+result['reason']+' (exit '+str(result['returncode'])+')')
            manifest = json.loads((output/'run_manifest.json').read_text())
            if manifest['config_fingerprint'] != payload['config_fingerprint']: raise ValueError('configuration fingerprint mismatch')
            if kind == 'dual-source':
                from cpag_core.dual_source_export import verify_task
                verify_task(output)
                if manifest['run_id'] != claim['id'] or manifest['attempt_id'] != claim['attempt']:
                    raise ValueError('dual-source run/attempt identity mismatch')
            publication = {'config_fingerprint':manifest['config_fingerprint'],'inputs':{name:payload[name]['sha256'] for name in paths},'artifacts':[]}
            for entry in manifest['artifacts']:
                path = beneath(output,entry['path'])
                publication['artifacts'].append({'path':entry['path'],'sha256':digest(path),'size':path.stat().st_size})
            publication['artifacts'].append({'path':'run_manifest.json','sha256':digest(output/'run_manifest.json'),'size':(output/'run_manifest.json').stat().st_size})
            (output/'manifest.json').write_text(json.dumps(publication,sort_keys=True)+'\n')
            try:
                self.api.post(endpoint+'/complete',{**identity,'manifest_sha256':digest(output/'manifest.json')})
            except APIError as error:
                if error.status >= 500:
                    return 'publication_pending'
                if error.status == 409:
                    return 'lost_lease'
                raise
            except (OSError, ValueError):
                # Completion may have committed before the response was lost.
                # Do not send fail or destroy durable files on an unknown outcome.
                return 'publication_pending'
            return 'succeeded'
        except (OSError,ValueError,KeyError,APIError,subprocess.TimeoutExpired) as error:
            if guardian and guardian.poll() is None:
                if not guardian.stdin.closed: guardian.stdin.close()
                try: guardian.wait(timeout=8)
                except subprocess.TimeoutExpired: return 'lost_lease'
            if guardian and not guardian.stdin.closed: guardian.stdin.close()
            if guardian and (guardian.returncode != 0 or not (control/'exit.json').exists()):
                return 'lost_lease'
            if owned and not self.stopping:
                try: self.api.post(endpoint+'/fail',{**identity,'message':str(error)[:1024],'retryable':(error.status >= 500 if isinstance(error,APIError) else retryable)})
                except (OSError,ValueError,APIError): pass
            return 'failed'
    def once(self):
        claim = self.api.post('/v1/claim',{'worker':self.worker,'lease_seconds':self.lease})
        return self.attempt(claim) if claim and claim.get('id') else 'idle'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enable-m4-worker',action='store_true',required=True)
    parser.add_argument('--once',action='store_true')
    args = parser.parse_args()
    token, url, root = [os.environ.get(key) for key in ('CPAG_WORKER_TOKEN','CPAG_API_URL','CPAG_SHARED_ROOT')]
    if not all((token,url,root)): parser.error('CPAG_WORKER_TOKEN, CPAG_API_URL and CPAG_SHARED_ROOT required')
    worker = Worker(API(url,token),root,os.environ.get('CPAG_WORKER_ID','worker-'+str(os.getpid())))
    signal.signal(signal.SIGTERM,worker.stop)
    signal.signal(signal.SIGINT,worker.stop)
    while not worker.stopping:
        try:
            result = worker.once()
            code = 0 if result in ('succeeded','cancelled','idle') else 75 if result in ('lost_lease','publication_pending','reconciliation_required','stopped') else 1
            print(json.dumps({'outcome':result,'retryable':code == 75}), flush=True)
        except (OSError,ValueError,APIError) as error:
            code = 75
            print(json.dumps({'outcome':'dependency_unavailable','error_type':type(error).__name__,'retryable':True}), file=sys.stderr, flush=True)
        if args.once: return code
        for _ in range(20):
            if worker.stopping: break
            time.sleep(.1)
    return 0
