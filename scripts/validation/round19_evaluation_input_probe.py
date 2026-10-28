#!/usr/bin/env python3
"""Read-only S100 projection baseline, optionally through a fresh restored API.

The source artifact and retained database are never modified. An immutable code
archive, copied source root and disposable PostgreSQL isolate each probe. This
does not run a new Worker or certify scale/reference performance.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import traceback

REPO=Path(__file__).resolve().parents[2]
BASELINE='aa16a4db525e55d0c435fc16bad5bb5edbab94b6'


def utc():return datetime.now(timezone.utc).isoformat()


def sha(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024**2),b''):value.update(block)
    return value.hexdigest()


def write(path,value):
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');os.replace(temporary,path)


def freeze_runtime(source,target):
    patterns=('internal/**/*.go','internal/jobs/migrations/*.sql','services/analysis/src/**/*.py','services/worker/cpag_worker/*.py','schemas/*.json')
    def paths(root):
        values={p for pattern in patterns for p in root.glob(pattern) if p.is_file() and not p.name.endswith('_test.go')}
        values.update(root/name for name in ('go.mod','go.sum','internal/jobs/integration/go.mod','internal/jobs/integration/go.sum'))
        return values
    before={str(path.relative_to(source)):sha(path) for path in paths(source)}
    for path in paths(target):path.unlink()
    for name in before:
        destination=target/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,destination)
    after={str(path.relative_to(source)):sha(path) for path in paths(source)}
    copied={name:sha(target/name) for name in before}
    if before!=after or copied!=before:raise ValueError('working runtime changed during snapshot; preserve this attempt and use new output')
    return {'files':before,'source_fingerprint':hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()}


def artifact_identity(root):
    root=Path(root);manifest=json.loads((root/'run_manifest.json').read_text())
    files={row['path']:row['sha256'] for row in manifest['artifacts']}
    files['run_manifest.json']=sha(root/'run_manifest.json')
    for name,digest in files.items():
        path=root/name
        if path.is_symlink() or not path.is_file() or sha(path)!=digest:raise ValueError('retained artifact hash mismatch: '+name)
    return {'run_id':manifest['run_id'],'attempt_id':manifest['attempt_id'],
        'input_fingerprint':manifest['input_fingerprint'],'config_fingerprint':manifest['config_fingerprint'],
        'artifacts':files,'mode':manifest['mode'],'total_core_bytes':sum((root/name).stat().st_size for name in files)}


def command_probe(command,root,label,deadline,env):
    start=time.monotonic()
    row={'label':label,'command':command,'deadline_seconds':deadline,'started_at':utc()}
    with (root/(label+'.stdout')).open('wb') as out,(root/(label+'.stderr')).open('wb') as err:
        process=subprocess.Popen(command,env=env,stdout=out,stderr=err)
        try:row.update(status='completed',returncode=process.wait(timeout=deadline))
        except subprocess.TimeoutExpired:
            process.kill();process.wait();row.update(status='timeout',returncode=process.returncode)
    row.update(elapsed_seconds=time.monotonic()-start,stdout_bytes=(root/(label+'.stdout')).stat().st_size,
        stdout_sha256=sha(root/(label+'.stdout')),stderr_sha256=sha(root/(label+'.stderr')))
    if row['status']=='completed' and row['returncode']==0:
        value=json.loads((root/(label+'.stdout')).read_text())
        row['observations']={'events':len(value['predictions']['events']),
            'unlabelled_relations':len(value['predictions']['unlabelled_relations']),
            'run_id':value['binding']['run_id'],'attempt_id':value['binding']['attempt_id']}
    return row


def http_probe(client,run,root,label,route='evaluation-input?projection=dual'):
    path=f'/api/v3/runs/{run}/'+route
    row={'label':label,'method':'GET','path':path,'started_at':utc(),
        'cache_condition':'new API process; application cache empty' if label.endswith('cold') else 'same API process after preceding request',
        'os_cache_condition':'not cleared; copying and hash verification can warm filesystem caches'}
    start=time.monotonic()
    try:
        code,value=client.request('GET',path,timeout=180)
        row.update(status='response',http_status=code)
        raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode() if not isinstance(value,bytes) else value
        if isinstance(value,dict):
            if 'predictions' in value:row['observations']={'events':len(value['predictions']['events']),'unlabelled_relations':len(value['predictions']['unlabelled_relations'])}
            if 'error' in value:row['error']=value['error']
    except Exception as error:
        row.update(status='client_error',error_type=type(error).__name__,error=str(error));raw=str(error).encode()
    row.update(elapsed_seconds=time.monotonic()-start,response_bytes=len(raw),response_sha256=hashlib.sha256(raw).hexdigest())
    (root/(label+'.response')).write_bytes(raw)
    return row


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retained-root',type=Path,required=True);p.add_argument('--run-id',required=True)
    p.add_argument('--attempt',type=int,default=1);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-commit',default=BASELINE);p.add_argument('--http',action='store_true')
    p.add_argument('--skip-cli',action='store_true',help='skip separately preserved CLI baseline; HTTP only')
    p.add_argument('--worktree-source',action='store_true',help='freeze current runtime bytes over archive; fingerprint exact dirty runtime')
    p.add_argument('--preparation-restart-fault',action='store_true',help='after real ready, kill a second preparing API operation and prove same-root recovery')
    p.add_argument('--preparation-lifecycle',action='store_true',help='explicit persisted preparation + density v3 full HTTP; no new Worker')
    p.add_argument('--artifact-cost-only',action='store_true',help='fresh-process /artifacts requests measure Go verification with small response')
    args=p.parse_args();root=args.output.resolve();root.mkdir(parents=True,mode=0o700,exist_ok=False)
    public=root/'public';public.mkdir()
    report={'schema_version':'r19-evaluation-input-request-probe-1','status':'running','started_at':utc(),
        'source_commit':args.source_commit,'scope':'same retained S100 read-only projection baseline; not new analysis or reference performance',
        'reference_accepted':False,'functional_acceptance':False,'measurements':[]}
    def save():write(public/'report.json',report)
    save();app=None;created=False;database='cpag-eval-probe-'+secrets.token_hex(4)
    shutil.copyfile(__file__,root/'probe-source.py');report['probe_sha256']=sha(root/'probe-source.py')
    try:
        retained=args.retained_root.resolve();original_source=retained/'source'
        original_artifact=original_source/'jobs'/args.run_id/('attempt-'+str(args.attempt))
        identity=artifact_identity(original_artifact);report['original_artifact']=str(original_artifact);report['identity']=identity;save()
        archive=root/'source.tar'
        with archive.open('wb') as stream:subprocess.run(['git','archive','--format=tar',args.source_commit],cwd=REPO,stdout=stream,check=True)
        frozen=root/'frozen-source';frozen.mkdir()
        with tarfile.open(archive) as stream:stream.extractall(frozen,filter='data')
        report['source_archive_sha256']=sha(archive)
        if args.worktree_source:
            snapshot=freeze_runtime(REPO,frozen);write(public/'runtime-source-manifest.json',snapshot)
            report['runtime_source_fingerprint']=snapshot['source_fingerprint'];report['runtime_head']=snapshot['head'];report['runtime_kind']='working runtime snapshot; archive commit is base only'
        cloned_source=root/'restored-source';shutil.copytree(original_source,cloned_source,copy_function=shutil.copyfile,symlinks=True)
        artifact=cloned_source/'jobs'/args.run_id/('attempt-'+str(args.attempt))
        if artifact_identity(artifact)!=identity:raise ValueError('copy changed original artifact identity')
        env=dict(os.environ,PYTHONPATH=str(frozen/'services/analysis/src'),GOCACHE='/tmp/cpag-r19-go-cache',GOMODCACHE='/tmp/cpag-go-mod')
        cli=[sys.executable,'-m','cpag_core.evaluation_artifacts','--artifact',str(artifact),'--batch','review-s100',
            '--sample-sha256',identity['input_fingerprint'],'--projection','dual']
        report['cli_skipped']=args.skip_cli
        for seconds in (() if args.skip_cli else (10,60)):
            report['measurements'].append(command_probe(cli,public,'cli-'+str(seconds)+'s',seconds,env));save()
        if args.http:
            sys.path[:0]=[str(REPO/'scripts/validation'),str(REPO/'services/analysis/src')]
            import round16_acceptance as r
            r.REPO=frozen
            r.build(root,env,skip_image_build=True)
            report['api_binary_sha256']=sha(root/'cpagx-v3')
            pg,port,internal=[r.port() for _ in range(3)]
            with (root/'postgres-start.log').open('wb') as stream:r.run('docker','run','--name',database,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only','-p',f'127.0.0.1:{pg}:5432',r.PG_IMAGE,stdout=stream,stderr=subprocess.STDOUT)
            created=True
            for _ in range(100):
                if subprocess.run(['docker','exec',database,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],capture_output=True).returncode==0:break
                time.sleep(.1)
            else:raise RuntimeError('disposable PostgreSQL not ready')
            with (retained/'database.sql').open('rb') as source,(root/'database-restore.log').open('wb') as log:r.bundle.pg(database,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=log,stderr=subprocess.STDOUT)
            with (root/'migrations.log').open('wb') as log:
                for migration in sorted((frozen/'internal/jobs/migrations').glob('*.sql')):
                    with migration.open('rb') as source:r.bundle.pg(database,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=log,stderr=subprocess.STDOUT)
            cfg=json.loads((retained/'app-config.json').read_text());control=root/'private-control';control.mkdir()
            cfg.update(database_url=f'postgres://postgres:m4-disposable-only@127.0.0.1:{pg}/m4_validation?sslmode=disable',
                shared_root=str(cloned_source),control_root=str(control),public_addr=f'127.0.0.1:{port}',internal_addr=f'127.0.0.1:{internal}',
                python_bin=sys.executable,python_path=str(frozen/'services/analysis/src'))
            if not Path(cfg.get('static_root','')).is_dir():cfg['static_root']=''
            app=r.start_app(root,'probe-api',root/'cpagx-v3',cfg);report['api_pid']=app.pid;save()
            client=r.Client(f'http://127.0.0.1:{port}')
            client.expect('POST','/api/v3/session',{'username':cfg['bootstrap_admin_username'],'password':cfg['bootstrap_admin_password']})
            labels=('go-artifacts-cold','go-artifacts-warm-1','go-artifacts-warm-2') if args.artifact_cost_only else ('http-cold','http-warm-1','http-warm-2')
            for label in (() if args.preparation_lifecycle else labels):
                route='artifacts' if args.artifact_cost_only else 'evaluation-input?projection=dual'
                report['measurements'].append(http_probe(client,args.run_id,public,label,route));save()
            if args.preparation_lifecycle:
                import round19_density_evaluation as lifecycle
                def restart():
                    nonlocal app
                    app.terminate();app.wait(timeout=20)
                    app=r.start_app(root,'prepared-restarted-api',root/'cpagx-v3',cfg)
                    fresh=r.Client(f'http://127.0.0.1:{port}')
                    fresh.expect('POST','/api/v3/session',{'username':cfg['bootstrap_admin_username'],'password':cfg['bootstrap_admin_password']})
                    return fresh
                report['lifecycle']=lifecycle.run(client,args.run_id,artifact,public/'lifecycle',scale='S',restart=restart)
                save()
                if args.preparation_restart_fault:
                    faults={'version':'evaluation-preparation-restart-fault-1','status':'running','projection':'network','samples':[]}
                    def faultsave():write(public/'preparation-restart-fault.json',faults)
                    faultsave()
                    def sql(query):
                        return subprocess.check_output(['docker','exec',database,'psql','-U','postgres','-d','m4_validation','-Atc',query],text=True).strip()
                    started=time.monotonic()
                    code,value=client.request('POST',f'/api/v3/runs/{args.run_id}/evaluation-preparation',{'projection':'network'},timeout=10)
                    if code!=202:raise ValueError('restart fault projection was not queued')
                    prep_id=value['preparation']['id']
                    while True:
                        code,value=client.request('GET',f'/api/v3/runs/{args.run_id}/evaluation-preparation?projection=network',timeout=10)
                        faults['samples'].append(value);faultsave()
                        if code!=200:raise ValueError('preparing status unavailable')
                        if value['preparation']['state']=='preparing':break
                        if time.monotonic()-started>20:raise ValueError('preparing state not observed')
                        time.sleep(.05)
                    # Kill during Go verification, before any guarded Python is
                    # spawned. The separate launcher test proves a surviving
                    # child keeps its inherited lock until its real exit/alarm.
                    old_owner=sql("SELECT owner FROM v3_evaluation_preparations WHERE id='"+prep_id+"'")
                    faults['killed_api_pid']=app.pid;app.kill();app.wait(timeout=10)
                    app=r.start_app(root,'fault-recovered-api',root/'cpagx-v3',cfg)
                    client=r.Client(f'http://127.0.0.1:{port}')
                    client.expect('POST','/api/v3/session',{'username':cfg['bootstrap_admin_username'],'password':cfg['bootstrap_admin_password']})
                    tested_cas=False
                    while True:
                        code,value=client.request('GET',f'/api/v3/runs/{args.run_id}/evaluation-preparation?projection=network',timeout=10)
                        faults['samples'].append(value);faultsave()
                        if code!=200:raise ValueError('recovered status unavailable')
                        state=value['preparation']
                        if state['state']=='preparing' and state['preparation_attempt']>=2 and not tested_cas:
                            changed=sql("UPDATE v3_evaluation_preparations SET error_detail='stale_owner_probe' WHERE id='"+prep_id+"' AND owner='"+old_owner+"' AND state='preparing'")
                            if changed!='UPDATE 0':raise ValueError('old preparation owner was allowed to update newer execution')
                            tested_cas=True
                        if state['state']=='ready':break
                        if state['state']=='failed' or time.monotonic()-started>180:raise ValueError('restart recovery did not produce real ready')
                        time.sleep(.2)
                    history=json.loads(sql("SELECT json_agg(json_build_object('attempt',attempt,'state',state,'reason_code',reason_code,'cost',cost_json) ORDER BY attempt) FROM v3_evaluation_preparation_attempts WHERE preparation_id='"+prep_id+"'"))
                    if not tested_cas or len(history)!=2 or history[0]['state']!='failed' or history[0]['reason_code']!='service_restarted' or history[1]['state']!='ready':raise ValueError('restart attempt history not preserved')
                    code,value=client.request('GET',f'/api/v3/runs/{args.run_id}/evaluation-input?projection=network',timeout=10)
                    if code!=200 or value['binding']['projection']!='network':raise ValueError('recovered ready is not queryable')
                    faults.update(status='passed',history=history,old_owner_update_refused=tested_cas,total_seconds=time.monotonic()-started)
                    faultsave();report['restart_fault']=faults;save()
        if artifact_identity(original_artifact)!=identity:raise ValueError('original retained artifact changed during probe')
        report['original_unchanged']=True;report['status']='measurements_completed'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error))
        (root/'error.log').write_text(traceback.format_exc())
    finally:
        if app is not None:
            app.terminate()
            try:app.wait(timeout=20)
            except subprocess.TimeoutExpired:app.kill();app.wait(timeout=5)
        if created:
            with (root/'post-probe-database.sql').open('wb') as stream:
                dump=subprocess.run(['docker','exec',database,'pg_dump','-U','postgres','m4_validation'],stdout=stream,stderr=subprocess.PIPE)
            (root/'database-dump.stderr').write_bytes(dump.stderr);report['database_dump_returncode']=dump.returncode
            cleanup=subprocess.run(['docker','rm','-f',database],capture_output=True);report['cleanup_returncode']=cleanup.returncode
        report['finished_at']=utc();save()
    print(json.dumps({'status':report['status'],'report':str(public/'report.json'),'measurements':report['measurements']}))
    return 0 if report['status']=='measurements_completed' else 1


if __name__=='__main__':raise SystemExit(main())
