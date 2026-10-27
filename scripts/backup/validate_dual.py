#!/usr/bin/env python3
"""Disposable PostgreSQL + API dual-source backup/restore drill.

Run with --serve to keep the restored API available for browser verification.
The private state file contains the test credential; do not commit it.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.error
import urllib.request

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'scripts/backup'),str(REPO/'scripts/validation'),
             str(REPO/'services/worker'),str(REPO/'services/analysis/src')]
import bundle
from dual_source_fixtures import make_case
from cpag_core.dual_source import strict_json
from cpag_core.pipeline import fingerprint
from cpag_worker.worker import API, Worker, digest

IMAGE='mirror.gcr.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94'


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def get(url, token):
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token})
    with urllib.request.urlopen(request,timeout=10) as response:
        return json.load(response)


def restored_api_refusals(work, api_binary, env, token, job, restored, network_rel, process_rel):
    """Use read-only second APIs over altered copies; keep the valid API live."""
    cases={}
    for name,relative,action in (
            ('missing_original_capture',network_rel,'missing'),
            ('tampered_original_process',process_rel,'tamper'),
            ('missing_nested_artifact',f'jobs/{job}/attempt-1/dual/analysis.json','missing')):
        root=work/('negative-'+name)
        shutil.copytree(restored,root)
        target=root/relative
        if action=='missing':target.unlink()
        else:
            target.chmod(0o600)
            target.write_bytes(target.read_bytes()+b'corruption')
        port=free_port();negative_env=dict(env,CPAG_SHARED_ROOT=str(root),CPAG_JOB_API_ADDR=f'127.0.0.1:{port}')
        with (work/('negative-'+name+'.log')).open('ab') as log:
            process=subprocess.Popen([str(api_binary)],env=negative_env,stdout=log,stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if process.poll() is not None:raise RuntimeError(name+' negative API exited')
                    try:
                        get(f'http://127.0.0.1:{port}/ready',token)
                    except urllib.error.HTTPError as error:
                        if error.code in (400,404):break
                    except OSError:pass
                    time.sleep(.1)
                else:raise RuntimeError(name+' negative API readiness timeout')
                try:get(f'http://127.0.0.1:{port}/v1/jobs/{job}/dual-result',token)
                except urllib.error.HTTPError as error:
                    cases[name]={'rejected':True,'http_status':error.code}
                else:raise RuntimeError(name+' restored API accepted altered evidence')
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
    return cases


def run_drill(work, serve=False):
    container='cpag-r14-dual-backup-'+secrets.token_hex(4)
    pg_port,api_port=free_port(),free_port()
    shared=work/'source';shared.mkdir()
    api_process=None;created=False
    try:
        subprocess.run(['docker','run','--name',container,'-d','-e','POSTGRES_DB=m4_validation',
                        '-e','POSTGRES_PASSWORD=m4-disposable-only',
                        '-p',f'127.0.0.1:{pg_port}:5432',IMAGE],check=True,stdout=subprocess.DEVNULL)
        created=True
        for _ in range(100):
            if subprocess.run(['docker','exec',container,'pg_isready','-h','127.0.0.1','-U','postgres',
                               '-d','m4_validation'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                break
            time.sleep(.1)
        else:raise RuntimeError('database readiness timeout')
        for migration in sorted((REPO/'internal/jobs/migrations').glob('*.sql')):
            with migration.open('rb') as source:
                bundle.pg(container,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
        env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(REPO/'services/worker'),str(REPO/'services/analysis/src')]),
                 GOCACHE=os.environ.get('GOCACHE',str(Path(tempfile.gettempdir())/'cpag-r14-go-build')),
                 GOMODCACHE=os.environ.get('GOMODCACHE',str(Path(tempfile.gettempdir())/'cpag-go-mod')))
        os.environ['PYTHONPATH']=env['PYTHONPATH']
        subprocess.run(['go','build','-o',str(work/'api'),'./cmd/m4-job-api'],cwd=REPO/'internal/jobs/integration',env=env,check=True)
        token=secrets.token_urlsafe(32)
        env.update(CPAG_ENABLE_M4='1',M4_DATABASE_URL=f'postgres://postgres:m4-disposable-only@127.0.0.1:{pg_port}/m4_validation?sslmode=disable',
                   CPAG_SHARED_ROOT=str(shared),CPAG_WORKER_TOKEN=token,
                   CPAG_COORDINATOR_TOKEN=secrets.token_urlsafe(32),CPAG_JOB_API_ADDR=f'127.0.0.1:{api_port}')
        api_url=f'http://127.0.0.1:{api_port}'
        def start_api():
            nonlocal api_process
            api_process=subprocess.Popen([str(work/'api')],env=env,stdout=(work/'api.log').open('ab'),stderr=subprocess.STDOUT)
            for _ in range(100):
                if api_process.poll() is not None:raise RuntimeError('API exited; see api.log')
                try:
                    get(api_url+'/ready',token)
                    return
                except urllib.error.HTTPError as error:
                    if error.code in (400,404):return
                    time.sleep(.1)
                except OSError:time.sleep(.1)
            raise RuntimeError('API readiness timeout')
        start_api()
        network,process,profile=make_case(shared/'inputs')
        payload={'kind':'dual-source','config_fingerprint':fingerprint(strict_json(profile.read_text()))}
        for role,path in [('network',network),('process',process),('profile',profile)]:
            payload[role]={'path':path.relative_to(shared).as_posix(),'sha256':digest(path)}
        api=API(api_url,token,timeout=10)
        job='r14-dual-backup'
        api.post('/v1/jobs',{'id':job,'max_attempts':1,'payload':payload})
        outcome=Worker(api,shared,'r14-backup-worker',lease=15,heartbeat=.2,timeout=120).once()
        status=get(api_url+'/v1/jobs/'+job,token)
        if outcome!='succeeded' or status['state']!='succeeded':
            raise RuntimeError('dual worker failed: '+json.dumps({'outcome':outcome,'state':status['state'],'error':status.get('last_error')}))
        source_result=get(api_url+'/v1/jobs/'+job+'/dual-result',token)
        api_process.terminate();api_process.wait(timeout=5);api_process=None
        snapshot=bundle.backup(container,'m4_validation',shared,work/'bundle')
        if not snapshot['source_audit']['valid'] or not snapshot['attempt_audit']['valid']:
            raise RuntimeError('source snapshot audit failed')
        persisted_payload=next(row['payload'] for row in snapshot['rows'] if row['id']==job)
        database_absent=bundle.pg(container,'m4_validation','psql','-X','-qAt','-c',
            "SELECT count(*) FROM pg_database WHERE datname='m4_restore_validation'",
            capture_output=True,text=True).stdout.strip()=='0'
        if not database_absent:raise RuntimeError('restore target database already exists')
        restored=work/'restored-new-directory'
        audit=bundle.restore(container,work/'bundle',restored)
        if not audit['valid'] or not audit['metadata_equal'] or not audit['attempt_history_equal']:
            raise RuntimeError('restored metadata/attempt audit failed')
        env.update(M4_DATABASE_URL=env['M4_DATABASE_URL'].replace('/m4_validation?','/m4_restore_validation?'),
                   CPAG_SHARED_ROOT=str(restored))
        start_api()
        restored_status=get(api_url+'/v1/jobs/'+job,token)
        restored_result=get(api_url+'/v1/jobs/'+job+'/dual-result',token)
        if restored_status['state']!='succeeded' or restored_result!=source_result:
            raise RuntimeError('restored API status/result differs')
        analysis=json.loads((restored/'jobs'/job/'attempt-1'/'analysis.json').read_text())
        operation=analysis['operations'][0]['operation_id']
        change=analysis['changes'][0]['event_id']
        evidence=get(api_url+'/v1/jobs/'+job+'/dual-evidence?'+urllib.parse.urlencode({'operation':operation}),token)
        changed=get(api_url+'/v1/jobs/'+job+'/dual-evidence?'+urllib.parse.urlencode({'change':change}),token)
        refs=evidence['verified_original_evidence']
        if len(refs)<4 or not changed['verified_original_evidence']:
            raise RuntimeError('restored API did not resolve four original references')
        original_kinds={item['source_ref']['file_sha256'] for item in refs}
        if original_kinds!={payload['network']['sha256'],payload['process']['sha256']}:
            raise RuntimeError('restored evidence lacks both originals')
        negative=restored_api_refusals(work,work/'api',env,token,job,restored,
                                       persisted_payload['network']['path'],persisted_payload['process']['path'])
        state={'valid':True,'synthetic_only':True,'job':job,'state':'succeeded',
               'container':container,'api_url':api_url,'shared_root':str(restored),
               'source_shared_root':str(shared),'database':'m4_restore_validation',
               'bundle':str(work/'bundle'),'restore_audit':str(restored.parent/(restored.name+'-audit.json')),
               'raw_reference_count':len(refs),'restored_change_reference_count':len(changed['verified_original_evidence']),
               'restore_target_database_absent_before':database_absent,
               'restored_metadata_equal':audit['metadata_equal'],'restored_attempt_history_equal':audit['attempt_history_equal'],
               'restored_file_inventory_equal':audit['file_inventory_equal'],'restored_api_refusals':negative,
               'worker_token':token,'coordinator_token':env['CPAG_COORDINATOR_TOKEN'],'work_dir':str(work)}
        state_path=work/'state.json'
        with state_path.open('x') as stream:
            os.chmod(state_path,0o600);json.dump(state,stream,indent=2);stream.write('\n')
        print(json.dumps({'valid':True,'state_file':str(state_path),'raw_reference_count':len(refs),
                          'api_url':api_url,'shared_root':str(restored),'serve':serve}),flush=True)
        if serve:
            signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
            while True:time.sleep(1)
        return state
    finally:
        if api_process is not None:
            api_process.terminate()
            try:api_process.wait(timeout=5)
            except subprocess.TimeoutExpired:api_process.kill();api_process.wait()
        if created:
            subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve',action='store_true')
    parser.add_argument('--work-dir',type=Path)
    args=parser.parse_args()
    if args.work_dir:
        args.work_dir.mkdir(mode=0o700,parents=False,exist_ok=False)
        run_drill(args.work_dir,args.serve)
    else:
        with tempfile.TemporaryDirectory(prefix='cpag-r14-dual-backup-') as tmp:
            run_drill(Path(tmp),False)


if __name__=='__main__':main()
