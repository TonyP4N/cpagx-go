#!/usr/bin/env python3
"""Standalone disposable Docker PostgreSQL + real worker bundle restore check."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'services/worker'),str(REPO/'services/analysis/src')]
import bundle
from cpag_worker.worker import API,Worker,digest
from cpag_core.pipeline import run, canonical
from cpag_core.packet_job import query_evidence
import hashlib

CONTAINER='cpag-m4-backup-validation'
PG_PORT='55443'
API_PORT='18098'
IMAGE='mirror.gcr.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94'
REPORT=Path(os.environ.get('CPAG_BACKUP_REPORT_DIR',str(REPO/'docs/refactor/validation-round5')))


def execute(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)


def main():
    REPORT.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cpag-backup-validation-') as temporary:
        work=Path(temporary);shared=work/'source';shared.mkdir()
        api_process=None;created=False
        try:
            # docker run refuses name/port collisions; cleanup touches only our new container.
            execute('docker','run','--name',CONTAINER,'-d','-e','POSTGRES_DB=m4_validation',
                    '-e','POSTGRES_PASSWORD=m4-disposable-only','-p','127.0.0.1:'+PG_PORT+':5432',IMAGE,
                    stdout=subprocess.DEVNULL)
            created=True
            for _ in range(100):
                if subprocess.run(['docker','exec',CONTAINER,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
                time.sleep(.1)
            else:raise RuntimeError('database readiness timeout')
            for migration in sorted((REPO/'internal/jobs/migrations').glob('*.sql')):
                with migration.open('rb') as source:
                    bundle.pg(CONTAINER,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
            env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(REPO/'services/worker'),str(REPO/'services/analysis/src')]),
                     GOCACHE=os.environ.get('GOCACHE',str(Path(tempfile.gettempdir())/'cpag-backup-go-build')),
                     GOMODCACHE=os.environ.get('GOMODCACHE',str(Path(tempfile.gettempdir())/'cpag-go-mod')))
            execute('go','build','-o',str(work/'api'),'./cmd/m4-job-api',cwd=REPO/'internal/jobs/integration',env=env)
            env.update(CPAG_ENABLE_M4='1',M4_DATABASE_URL='postgres://postgres:m4-disposable-only@127.0.0.1:'+PG_PORT+'/m4_validation?sslmode=disable',
                       CPAG_SHARED_ROOT=str(shared),CPAG_WORKER_TOKEN=secrets.token_urlsafe(32),CPAG_JOB_API_ADDR='127.0.0.1:'+API_PORT)
            os.environ['PYTHONPATH']=env['PYTHONPATH']
            def start_api():
                nonlocal api_process
                api_process=subprocess.Popen([str(work/'api')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                for _ in range(100):
                    if api_process.poll() is not None:raise RuntimeError('API exited')
                    try:urllib.request.urlopen('http://127.0.0.1:'+API_PORT+'/ready',timeout=.2)
                    except urllib.error.HTTPError as e:
                        if e.code==401:return
                    except OSError:pass
                    time.sleep(.1)
                raise RuntimeError('API readiness timeout')
            start_api()
            api=API('http://127.0.0.1:'+API_PORT,env['CPAG_WORKER_TOKEN'])
            def status(job):
                request=urllib.request.Request(api.url+'/v1/jobs/'+job,headers={'Authorization':'Bearer '+api.token})
                with urllib.request.urlopen(request,timeout=3) as source:return json.load(source)
            payload={}
            (shared/'inputs').mkdir(exist_ok=True)
            for role,src in [('network','tests/fixtures/synthetic/network.normalized.jsonl'),('process','tests/fixtures/synthetic/process.csv'),('profile','profiles/synthetic-demo.json')]:
                dest=shared/'inputs'/(role+Path(src).suffix);shutil.copyfile(REPO/src,dest)
                payload[role]={'path':dest.relative_to(shared).as_posix(),'sha256':digest(dest)}
            core=run(*(shared/payload[k]['path'] for k in ('network','process','profile')),work/'baseline',synthetic=True)
            payload['config_fingerprint']=core['config_fingerprint']
            api.post('/v1/jobs',{'id':'backup-success','max_attempts':1,'payload':payload})
            assert Worker(api,shared,'backup-worker',lease=5,heartbeat=.2).once()=='succeeded'
            api.post('/v1/jobs',{'id':'backup-cancelled','max_attempts':1,'payload':payload})
            api.post('/v1/jobs/backup-cancelled/cancel',{})
            bad=copy.deepcopy(payload);(shared/'inputs/bad.jsonl').write_text('invalid synthetic input\n')
            bad['network']={'path':'inputs/bad.jsonl','sha256':digest(shared/'inputs/bad.jsonl')}
            api.post('/v1/jobs',{'id':'backup-failed','max_attempts':1,'payload':bad})
            assert Worker(api,shared,'backup-worker',lease=5,heartbeat=.2).once()=='failed'
            assert [status(x)['state'] for x in ('backup-success','backup-cancelled','backup-failed')]==['succeeded','cancelled','failed']
            # Actual packet task through the same API/worker/publication contract.
            packet_payload=copy.deepcopy(payload);packet_payload['kind']='packet'
            capture=shared/'inputs/synthetic.pcap'
            shutil.copyfile(REPO/'docs/refactor/validation-round4/protocol-synthetic.pcap',capture)
            packet_profile=shared/'inputs/packet-profile.json'
            config={'synthetic':True,'adapter':'synthetic-packet-1'}
            packet_profile.write_bytes(canonical(config)+b'\n')
            for role,path in [('network',capture),('profile',packet_profile)]:
                packet_payload[role]={'path':path.relative_to(shared).as_posix(),'sha256':digest(path)}
            packet_payload['config_fingerprint']=hashlib.sha256(canonical(config)).hexdigest()
            api.post('/v1/jobs',{'id':'backup-packet','max_attempts':1,'payload':packet_payload})
            packet_status=Worker(api,shared,'backup-packet-worker',lease=5,heartbeat=.2,
                          command=[sys.executable,'-m','cpag_core.packet_job']).once()
            record=status('backup-packet')
            assert packet_status=='succeeded',{'worker_result':packet_status,'state':record['state'],'last_error':record.get('last_error')}
            assert status('backup-packet')['state']=='succeeded'
            (shared/'orphan-retained.txt').write_text('unreferenced synthetic diagnostic; retain\n')
            snapshot=bundle.backup(CONTAINER,'m4_validation',shared,work/'bundle')
            assert snapshot['source_audit']['valid']
            assert 'orphan-retained.txt' in snapshot['source_audit']['unreferenced_files']
            api_process.terminate();api_process.wait(timeout=5);api_process=None
            restored=work/'restored-new-directory'
            result=bundle.restore(CONTAINER,work/'bundle',restored)
            assert result['valid'] and result['metadata_equal'] and result['file_inventory_equal']
            assert (restored/'orphan-retained.txt').read_bytes()==(shared/'orphan-retained.txt').read_bytes()
            env.update(M4_DATABASE_URL=env['M4_DATABASE_URL'].replace('/m4_validation?','/m4_restore_validation?'),CPAG_SHARED_ROOT=str(restored))
            start_api()
            for job,state in [('backup-success','succeeded'),('backup-cancelled','cancelled'),('backup-failed','failed'),('backup-packet','succeeded')]:
                assert status(job)['state']==state
            rows=bundle.rows_now(CONTAINER,'m4_restore_validation')
            packet_row=next(row for row in rows if row['id']=='backup-packet')
            packet_output=(restored/packet_row['artifact_path']).parent
            packet_capture=restored/packet_row['payload']['network']['path']
            packet_events=json.loads((packet_output/'events.json').read_text())
            packet_query=query_evidence(packet_output,packet_capture,packet_events[0]['event_id'],'cip.path')
            assert packet_query['observation']['fields']['cip.path']['hex']=='200124013001'
            assert len(packet_query['node']['evidence_refs'])==3
            (REPORT/'backup-packet-restored-query.json').write_text(json.dumps(packet_query,indent=2)+'\n')
            packet_missing=work/'packet-missing';shutil.copytree(restored,packet_missing)
            (packet_missing/packet_row['payload']['network']['path']).unlink()
            packet_missing_report=bundle.audit(rows,packet_missing);assert not packet_missing_report['valid']
            query_failures={}
            try:query_evidence((packet_missing/packet_row['artifact_path']).parent,packet_missing/packet_row['payload']['network']['path'],packet_events[0]['event_id'],'cip.path')
            except (OSError,ValueError) as error:query_failures['missing_capture']=type(error).__name__
            else:raise AssertionError('packet query accepted missing capture')
            packet_tamper=work/'packet-tamper';shutil.copytree(restored,packet_tamper)
            altered=packet_tamper/packet_row['payload']['network']['path'];altered.chmod(0o600)
            data=bytearray(altered.read_bytes());data[-1]^=1;altered.write_bytes(data)
            packet_tamper_report=bundle.audit(rows,packet_tamper);assert not packet_tamper_report['valid']
            try:query_evidence((packet_tamper/packet_row['artifact_path']).parent,altered,packet_events[0]['event_id'],'cip.path')
            except (OSError,ValueError) as error:query_failures['tampered_capture']=type(error).__name__
            else:raise AssertionError('packet query accepted tampered capture')
            (REPORT/'backup-packet-query-negatives.json').write_text(json.dumps(query_failures,indent=2)+'\n')
            for name,report in [('backup-packet-missing-audit.json',packet_missing_report),('backup-packet-tamper-audit.json',packet_tamper_report)]:
                (REPORT/name).write_text(json.dumps(report,indent=2)+'\n')
            missing=work/'missing-copy';shutil.copytree(restored,missing)
            manifest=next(r for r in rows if r['state']=='succeeded')['artifact_path']
            (missing/manifest).unlink()
            missing_report=bundle.audit(rows,missing);assert not missing_report['valid']
            tampered=work/'tampered-copy';shutil.copytree(restored,tampered)
            success_row=next(r for r in rows if r['state']=='succeeded')
            p=tampered/success_row['payload']['network']['path'];p.chmod(0o600);p.write_bytes(p.read_bytes()+b' ')
            tamper_report=bundle.audit(rows,tampered);assert not tamper_report['valid']
            for name,report in [('backup-restore-audit.json',result),('backup-missing-audit.json',missing_report),('backup-tamper-audit.json',tamper_report)]:
                (REPORT/name).write_text(json.dumps(report,indent=2)+'\n')
            summary={'valid':True,'synthetic_only':True,'source_database':'m4_validation','restored_database':'m4_restore_validation',
                     'independent_postgres_port':int(PG_PORT),'independent_api_port':int(API_PORT),
                     'states_verified':['succeeded','cancelled','failed'],'real_worker_execution':True,
                     'restored_api_read_verified':True,'dump_and_files_checksums_verified':True,
                     'packet_job_restored_query_verified':True,'packet_missing_tamper_detected':True,
                     'attempt_history_equal':result['attempt_history_equal'],'attempt_history_count':len(snapshot['attempts']),
                     'original_record_and_graph_refs_verified':True,'orphan_retained':True,
                     'missing_file_detected':True,'tampered_input_detected':True,
                     'scope':'disposable synthetic Docker PostgreSQL + host worker; not production restore'}
            (REPORT/'backup-integration-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
            print(json.dumps(summary,sort_keys=True))
        finally:
            if api_process is not None and api_process.poll() is None:
                api_process.terminate();api_process.wait(timeout=5)
            if created:execute('docker','rm','-f','-v',CONTAINER,stdout=subprocess.DEVNULL)

if __name__=='__main__':main()
