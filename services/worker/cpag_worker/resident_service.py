"""Sequential resident compact worker. This supervisor is the container PID 1.

Compute runs behind an unprivileged, network-denied guardian boundary. Durable
API ownership and container-termination recovery remain coordinator authority.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from urllib.request import Request, urlopen
import ssl

from .isolated import DockerExecutor, atomic_json, seal_handoff, sync_dir
from .kube_job import compact_command
from .worker import API, beneath, digest, network_refs


def read_config(path):
    path = Path(path)
    info, parent = path.lstat(), path.parent.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid()
            or not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077 or parent.st_uid != os.geteuid()):
        raise ValueError('private owner-only config file and parent directory required')
    config = json.loads(path.read_text())
    required = {'api_url', 'shared_root', 'control_root', 'worker_id', 'worker_token', 'coordinator_token', 'resource_profile'}
    if not isinstance(config, dict) or not required <= config.keys() or config.keys() - required - {'image', 'poll_seconds', 'recovery_seconds'}:
        raise ValueError('invalid resident configuration fields')
    if config['api_url'].rstrip('/') not in ('http://cpag-resident-internal:8096', 'http://127.0.0.1:8094'):
        raise ValueError('resident internal API required')
    if config.get('resource_profile') != 'storage-budget-2':
        raise ValueError('resident compact resource profile required')
    if any(not isinstance(config[k], str) or len(config[k]) < 24 for k in ('worker_token', 'coordinator_token')) or config['worker_token'] == config['coordinator_token']:
        raise ValueError('distinct private credentials required')
    for name in ('shared_root', 'control_root'):
        if not Path(config[name]).is_absolute():
            raise ValueError('absolute storage required')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', config['worker_id']):
        raise ValueError('invalid worker identity')
    poll = config.get('poll_seconds', 1)
    if type(poll) not in (float, int) or not .2 <= poll <= 60:
        raise ValueError('invalid poll interval')
    return config


def registration(previous=None):
    name = os.environ['CPAG_POD_NAME']
    uid = os.environ['CPAG_POD_UID']
    container = os.environ.get('CPAG_CONTAINER_NAME', 'worker')
    runtime = os.environ.get('CPAG_CONTAINER_ID')
    if runtime is None:
        service = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        request = Request('https://kubernetes.default.svc/api/v1/namespaces/cpag/pods/'+name,
                          headers={'Authorization': 'Bearer '+(service/'token').read_text().strip()})
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            with urlopen(request, context=ssl.create_default_context(cafile=str(service/'ca.crt')), timeout=5) as response:
                pod = json.load(response)
            if pod['metadata']['uid'] != uid:
                raise ValueError('resident Pod replacement')
            for row in pod.get('status', {}).get('containerStatuses', []):
                if row['name'] == container and 'running' in row['state'] and row.get('containerID') != previous:
                    runtime = row.get('containerID')
                    break
            if runtime:
                break
            time.sleep(.5)
        if not runtime:
            raise RuntimeError('current resident container status unavailable')
    if not re.fullmatch(r'containerd://[0-9a-f]{64}', runtime):
        raise ValueError('invalid resident container identity')
    return {'version': 'resident-registration-1', 'namespace': 'cpag', 'pod_name': name,
            'pod_uid': uid, 'container_name': container, 'container_id': runtime}


class ResidentWorker:
    def __init__(self, config, work_root, resident=None):
        self.config = config
        self.root, self.control = Path(config['shared_root']).resolve(), Path(config['control_root']).resolve()
        self.work_root = Path(work_root)
        if resident is None:
            instance_file = self.control / 'resident-instance.json'
            previous = json.loads(instance_file.read_text()) if instance_file.exists() else {}
            resident = registration(previous.get('container_id'))
            atomic_json(instance_file, resident)
        self.resident = resident
        self.location = 'resident:'+os.environ['CPAG_NAMESPACE_UID']
        self.api = API(config['api_url'], config['worker_token'])
        self.coord = API(config['api_url'], config['coordinator_token'])
        self.helper = DockerExecutor(self.api, self.coord, self.root, self.control, config['worker_id'],
                                     resource_profile='storage-budget-2', lease=90, heartbeat=5)
        self.journal = self.control/'resident-active.json'

    def stage(self, claim, base):
        # Reuse the exact compact Kubernetes CLI/resource contract without a Job.
        if not re.fullmatch(r'[0-9a-f]{32}', claim['id']) or type(claim['attempt']) is not int or not 1 <= claim['attempt'] <= 100:
            raise ValueError('invalid resident attempt identity')
        if claim['worker'] != self.config['worker_id']:
            raise ValueError('resident worker identity mismatch')
        command = compact_command(claim['payload'], claim['id'], claim['attempt'])
        # No prior compute survives a settled attempt or container restart.
        # Remove stale staging before exposing any inputs to the next child.
        for stale in self.work_root.iterdir():
            if stale.is_symlink() or not stale.is_dir():
                raise ValueError('foreign resident staging entry')
            shutil.rmtree(stale)
        work = self.work_root/(claim['id']+'-'+str(claim['attempt']))
        work.mkdir(mode=0o755)
        inputs = work/'inputs'; inputs.mkdir(mode=0o755)
        payload = claim['payload']
        refs = [(f'network-{i}.'+ref['path'].rsplit('.', 1)[-1].lower(), ref) for i, ref in enumerate(network_refs(payload))]
        refs += [('process.csv', payload['process']), ('profile.json', payload['profile'])]
        for name, ref in refs:
            target = inputs/name
            with beneath(self.root, ref['path']).open('rb') as source, target.open('xb') as out:
                shutil.copyfileobj(source, out)
                out.flush(); os.fsync(out.fileno())
            if digest(target) != ref['sha256']:
                raise ValueError('staged input hash mismatch')
            target.chmod(0o444)
        profile = json.loads((inputs/'profile.json').read_text())
        for key in ('capacity_profile', 'storage_format', 'storage_budget_version'):
            if profile.get(key) != payload[key]:
                raise ValueError('compact profile binding mismatch')
        if payload['kind'] == 'dual-source-replay' and any(profile.get('replay', {}).get(k) != payload.get('replay_version' if k == 'version' else k) for k in ('version', 'history_format')):
            raise ValueError('replay profile binding mismatch')
        inputs.chmod(0o555)
        output = work/'output'; output.mkdir(mode=0o700); os.chown(output, 65532, 65532)
        temporary = work/'tmp'; temporary.mkdir(mode=0o700); os.chown(temporary, 65532, 65532)
        command = [sys.executable if i == 0 else str(work)+arg if arg.startswith(('/inputs/', '/output/')) else arg for i, arg in enumerate(command)]
        # Explicit allowlist: no HTTP authority, Kubernetes token, proxies or HOME.
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONPATH': os.environ.get('PYTHONPATH', '/app/services/analysis/src:/app/services/worker'),
               'TMPDIR': str(temporary), 'CPAG_PHASE_METRICS': str(output/'phases.jsonl'), 'CPAG_PHASE_STRATEGY': 'phase-resources-3',
               'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1'}
        config = {'command': command, 'env': env, 'identity': {k: claim[k] for k in ('id', 'attempt', 'worker', 'token')},
                  'pid_file': str(base/'child.pid'), 'exit_file': str(base/'exit.json'), 'resident_receipt': self.resident, 'location': self.location,
                  'stdout': str(base/'stdout.log'), 'stderr': str(base/'stderr.log'),
                  'timeout': self.helper.timeout, 'kill_grace': 2, 'cpu_seconds': self.helper.cpu_seconds,
                  'memory_bytes': self.helper.memory_bytes, 'file_bytes': self.helper.output_bytes,
                  'log_bytes': 65536, 'resident_sandbox': {'cwd': str(work)}, 'output_root': str(output)}
        atomic_json(base/'guardian.json', config)
        return work

    def once(self):
        # A journal means an ambiguous prior supervisor lifetime. Do not restart
        # compute or clear it: container restart/termination is coordinator proof.
        if self.journal.exists():
            previous = json.loads(self.journal.read_text())
            claim = previous['claim']
            status = self.helper.get_json(self.api, '/v1/jobs/'+claim['id'])
            if status['attempt'] == claim['attempt'] and status['state'] not in ('succeeded', 'failed', 'cancelled', 'queued'):
                return 'recovery_required' if previous['execution'].get('container_id') == self.resident['container_id'] else 'recovery_wait'
            base = self.control/'jobs'/claim['id']/f"attempt-{claim['attempt']}.worker"
            self.helper.capacity(claim, settle=True)
            os.replace(self.journal, base/'resident-recovered.json')
            sync_dir(self.control)
            shutil.rmtree(self.work_root/(claim['id']+'-'+str(claim['attempt'])), ignore_errors=True)
        claim = self.api.post('/v1/claim', {'worker': self.config['worker_id'], 'lease_seconds': 90,
                              'execution_type': 'resident-v1', 'location': self.location})
        if not claim:
            return 'idle'
        base = self.control/'jobs'/claim['id']/f"attempt-{claim['attempt']}.worker"
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        identity = {k: claim[k] for k in ('attempt', 'worker', 'token')}
        endpoint = '/v1/jobs/'+claim['id']
        execution = {**identity, 'container_id': self.resident['container_id'], 'location': self.location, 'resident': self.resident}
        atomic_json(self.journal, {'claim': claim, 'execution': execution})
        done = threading.Event(); health = {'owned': True, 'cancelled': False, 'phase': 'resident_compute'}
        keeper = threading.Thread(target=self.helper.keep_lease, args=(claim, done, health), daemon=True)
        guardian = None
        try:
            # Register durably before any compute can start.
            self.coord.post(endpoint+'/execution', execution)
            keeper.start()
            self.helper.capacity(claim)
            work = self.stage(claim, base)
            self.api.post(endpoint+'/heartbeat', {**identity, 'lease_seconds': 90})
            if self.helper.stopping or not health['owned'] or health['cancelled']:
                raise ValueError('ownership lost before launch')
            guardian = subprocess.Popen([sys.executable, '-m', 'cpag_worker.guardian', str(base/'guardian.json')],
                                        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
            while guardian.poll() is None:
                if self.helper.stopping or not health['owned'] or health['cancelled']:
                    guardian.stdin.close()
                    break
                time.sleep(.05)
            guardian.wait(timeout=15)
            if os.getpid() == 1:
                while True:
                    try:
                        if os.waitpid(-1, os.WNOHANG)[0] == 0: break
                    except ChildProcessError: break
            guardian.stdin.close()
            receipt = json.loads((base/'exit.json').read_text())
            proof = receipt['resident']
            if not proof.get('group_exited') or any(receipt.get(k) != claim[k] for k in ('id', 'attempt', 'worker', 'token')) or receipt.get('container_id') != self.resident['container_id']:
                raise ValueError('guardian exit identity mismatch')
            self.coord.post(endpoint+'/exit', {k: v for k, v in receipt.items() if k != 'id'})
            if health['cancelled']:
                self.api.post(endpoint+'/ack-cancel', identity)
            elif health['owned'] and not self.helper.stopping:
                if proof['returncode'] or proof['reason'] != 'exited':
                    self.api.post(endpoint+'/fail', {**identity, 'message': 'resident compute failed', 'retryable': False})
                else:
                    output = beneath(self.root, claim['output_dir']); output.parent.mkdir(parents=True, exist_ok=True)
                    if output.parent.stat().st_uid == 65532 or output.parent.stat().st_mode & 0o022:
                        raise ValueError('publication parent permits compute writes')
                    stage = output.with_name('.resident-handoff-'+str(claim['attempt']))
                    sha = self.helper.read_archive(['tar', '-C', str(work/'output/run'), '-cf', '-', '.'], stage, claim['payload'], claim['id'], claim['attempt'])
                    seal_handoff(stage, compact=True)
                    os.rename(stage, output); sync_dir(output.parent)
                    self.helper.complete(claim, sha, lease_health=health)
                    atomic_json(base/'publication.json', {'manifest_sha256': sha})
            else:
                return 'recovery_required'
            self.helper.capacity(claim, settle=True)
            shutil.rmtree(work)
            os.replace(self.journal, base/'resident-completed.json'); sync_dir(self.control)
            return 'settled'
        finally:
            if guardian is not None and guardian.poll() is None:
                guardian.stdin.close()
                guardian.wait(timeout=15)
            done.set()
            if keeper.ident is not None: keeper.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--work-root', default='/resident-work')
    args = parser.parse_args()
    config = read_config(args.config)
    if sys.platform != 'linux' or os.getuid() != 0:
        parser.error('resident supervisor requires Linux root')
    control = Path(config['control_root']); control.mkdir(mode=0o700, parents=True, exist_ok=True); control.chmod(0o700)
    work = Path(args.work_root); work.mkdir(mode=0o711, parents=True, exist_ok=True); work.chmod(0o711)
    shared = Path(config['shared_root'])
    if shared.stat().st_uid == 65532 or shared.stat().st_mode & 0o022:
        parser.error('shared root must deny compute UID writes')
    owner = ResidentWorker(config, work)
    stopped = threading.Event()
    def stop(*_): stopped.set(); owner.helper.stop()
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    with (control/'.maintenance.lock').open('a+') as maintenance, (control/'.resident-owner.lock').open('a+') as lock:
        fcntl.flock(maintenance, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while not stopped.is_set():
            try:
                result = owner.once()
                if result == 'recovery_required':
                    # Exit PID1: coordinator fences old container before retry.
                    raise SystemExit(1)
            except Exception as error:
                print(json.dumps({'event': 'resident_recovery_pending', 'error_type': type(error).__name__}), flush=True)
                if owner.journal.exists(): raise SystemExit(1)
            stopped.wait(config.get('poll_seconds', 1))


if __name__ == '__main__':
    main()
