#!/usr/bin/env python3
"""R18-only real Go/PG/isolated Worker lifecycle checks on generated inputs.

Fault injection stops an actual replay after arrival 3 (request admitted, response
not arrived), rather than treating an old offline fault test as replay coverage.
Private claims/configs stay outside public/. No task state machine is added.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
import urllib.request

import round16_acceptance as r
from round16_supplement import intake
from round18_profile import fixture
import bundle
from cpag_core.pipeline import canonical,fingerprint
from cpag_core.replay_export import verify_task
from cpag_worker.isolated import DockerExecutor
from cpag_worker.worker import API,APIError,digest

GATE_CODE="""from pathlib import Path
import json,time
import cpag_core.replay_core as core
real_consume=core.ReplayCore.consume
def gated(self,*args,**kwargs):
    result=real_consume(self,*args,**kwargs)
    if kwargs.get('arrival_seq')==3:
        Path('/runtime/replay-prefix.json').write_text(json.dumps({'arrival_seq':3,'snapshot_id':result['snapshot_id'],'state_fingerprint':result['state_fingerprint'],'operation_statuses':[o['replay']['status'] for o in result['analysis']['operations']]}))
        time.sleep(60)
    return result
core.ReplayCore.consume=gated
import cpag_core.replay_export as export
export.main()
"""


def source_manifest():
    patterns=('internal/**/*.go','internal/jobs/migrations/*.sql','services/analysis/src/**/*.py','services/worker/cpag_worker/*.py','schemas/*.json')
    paths={p for pattern in patterns for p in r.REPO.glob(pattern) if p.is_file() and not p.name.endswith('_test.go')}
    paths.update(r.REPO/p for p in ('go.mod','go.sum','internal/jobs/integration/go.mod','internal/jobs/integration/go.sum','deployments/isolated-executor/Dockerfile'))
    rows={p.relative_to(r.REPO).as_posix():digest(p) for p in sorted(paths)}
    return {'files':rows,'source_fingerprint':fingerprint(rows)}


def build_identity(binary):
    raw=subprocess.check_output(['go','version','-m',str(binary)],text=True)
    result={'raw':raw,'binary_sha256':digest(binary)}
    for line in raw.splitlines():
        if 'vcs.revision=' in line:result['vcs_revision']=line.split('vcs.revision=',1)[1].strip()
        if 'vcs.modified=' in line:result['vcs_modified']=line.split('vcs.modified=',1)[1].strip()=='true'
    return result


def image_sources(image):
    code="import hashlib,json,pathlib;root=pathlib.Path('/app');files=sorted([*root.glob('services/analysis/src/**/*.py'),*root.glob('schemas/*.json'),root/'entry.py']);rows={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files};print(json.dumps({'files':rows,'source_fingerprint':hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()},sort_keys=True))"
    raw=subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--entrypoint','python',image,'-c',code],text=True)
    return json.loads(raw)


def internal_state(api,job):
    request=urllib.request.Request(api.url+'/v1/jobs/'+job,headers={'Authorization':'Bearer '+api.token})
    with urllib.request.urlopen(request,timeout=5) as response:return json.load(response)


def wait_for(check,*,seconds=45,description='condition'):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        result=check()
        if result:return result
        time.sleep(.1)
    raise RuntimeError('timed out waiting for '+description)


def main(work,*,skip_image_build=False,image='cpag-isolated:r18-lifecycle'):
    work=work.resolve();work.mkdir(parents=True,mode=0o700,exist_ok=False);public=work/'public';public.mkdir()
    shared=work/'source';shared.mkdir();control=work/'control';control.mkdir()
    env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(r.REPO/'services/worker'),str(r.REPO/'services/analysis/src')]),
             GOCACHE=os.environ.get('GOCACHE','/tmp/cpag-go-build'),GOMODCACHE=os.environ.get('GOMODCACHE','/tmp/cpag-go-mod'))
    r.WORKER_IMAGE=image
    pg,port,internal=[r.port() for _ in range(3)];database='cpag-r18-life-'+secrets.token_hex(5)
    app=child=None;created=False;tracked=[]
    report={'scope':'generated R18 software lifecycle checks only; no industrial validation','checks':{},'jobs':{},'status':'running',
            'fault_window':'after arrival 3 while actual replay is pending response','source_commit':os.environ.get('GITHUB_SHA',os.environ.get('CPAG_VALIDATION_SOURCE_COMMIT','uncommitted worktree'))}
    def save(): (public/'lifecycle.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        sources=source_manifest()
        r.build(work,env,skip_image_build=skip_image_build)
        if source_manifest()!=sources:raise RuntimeError('source_changed_during_build')
        (public/'source-manifest.json').write_text(json.dumps(sources,indent=2)+'\n')
        identity=build_identity(work/'cpagx-v3');report['go_build_identity']=identity
        if report['source_commit']=='uncommitted worktree':report['source_commit']=identity.get('vcs_revision','unavailable');report['vcs_modified']=identity.get('vcs_modified')
        report['source_fingerprint']=sources['source_fingerprint']
        report['go_binary_sha256']=digest(work/'cpagx-v3')
        report['worker_image_id']=subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],text=True).strip()
        image_manifest=image_sources(report['worker_image_id']);(public/'image-source-manifest.json').write_text(json.dumps(image_manifest,indent=2)+'\n');report['image_source_fingerprint']=image_manifest['source_fingerprint']
        r.run('docker','run','--name',database,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only',
              '-p',f'127.0.0.1:{pg}:5432',r.PG_IMAGE,stdout=subprocess.DEVNULL);created=True
        wait_for(lambda:subprocess.run(['docker','exec',database,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0,description='disposable PostgreSQL')
        for migration in sorted((r.REPO/'internal/jobs/migrations').glob('*.sql')):
            with migration.open('rb') as source:bundle.pg(database,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
        # Actual idempotence, not a schema-only source inspection.
        with (r.REPO/'internal/jobs/migrations/009_v3_replay_runs.sql').open('rb') as source:
            bundle.pg(database,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
        report['checks']['migration009_applied_twice']=True
        username='r18-lifecycle';password=secrets.token_urlsafe(24);wt=secrets.token_urlsafe(32);ct=secrets.token_urlsafe(32)
        cfg=r.make_config(pg,'m4_validation',shared,control,port,internal,wt,ct,username,password,r.REPO/'webui/out')
        app=r.start_app(work,'app',work/'cpagx-v3',cfg);client=r.Client(f'http://127.0.0.1:{port}')
        client.expect('POST','/api/v3/session',{'username':username,'password':password})
        api=API('http://127.0.0.1:'+str(internal),wt);coordinator=API(api.url,ct)
        def driver(worker,**kwargs):return DockerExecutor(api,coordinator,shared,control,worker,image=image,heartbeat=.2,lease=20,timeout=45,**kwargs)
        location=driver('locator').location()
        def state(job):return internal_state(api,job)
        def prepare(label,*,invalid=False):
            networks,process,profile_path,profile=fixture(work/('input-'+label))
            if invalid:networks[0].write_bytes(b'not-a-valid-pcap-container')
            provenance=profile['source_provenance']
            dataset=client.expect('POST','/api/v3/datasets',{'name':'R18 lifecycle '+label,'source_kind':'synthetic',
                'source':provenance['source'],'batch':provenance['release'],'authorization_ref':provenance['authorization_ref']},code=201)['dataset']['id']
            for i,path in enumerate(networks):r.upload(client,dataset,'network',path,label+'-network-'+str(i))
            r.upload(client,dataset,'process',process,label+'-process')
            intake_id=client.expect('POST',f'/api/v3/datasets/{dataset}/configs',{'kind':'intake','document':intake(dataset)},code=201)['config']['id']
            preflight_id=client.expect('POST',f'/api/v3/datasets/{dataset}/preflight',{'config_version_id':intake_id})['preflight_id']
            version=client.expect('POST',f'/api/v3/datasets/{dataset}/configs',{'kind':'dual','document':profile},code=201)['config']['id']
            run=client.expect('POST','/api/v3/runs',{'dataset_id':dataset,'config_version_id':version,'preflight_id':preflight_id,'mode':'dual_source_replay'},code=201)['run']
            if run['replay_version']!='dual-source-replay-1':raise AssertionError('replay binding version missing')
            return run['id']
        def claim(job,label,lease=20):
            item=wait_for(lambda:api.post('/v1/claim',{'worker':'r18-'+label,'lease_seconds':lease,'executor':'isolated-v2','location':location}),seconds=30,description='eligible existing retry claim')
            if not item or item['id']!=job:raise AssertionError('wrong task claimed')
            item.update(executor='isolated-v2',location=location)
            if item['payload'].get('kind')!='dual-source-replay' or item['payload'].get('replay_version')!='dual-source-replay-1':raise AssertionError('claim replay identity differs')
            tracked.append(item);return item
        def execution(item):
            path=control/'jobs'/item['id']/f"attempt-{item['attempt']}.worker"/'execution.json'
            return json.loads(path.read_text()) if path.exists() else None
        def marker(item):
            record=execution(item)
            if not record:return None
            result=subprocess.run(['docker','exec',record['container_id'],'cat','/runtime/replay-prefix.json'],capture_output=True,text=True)
            if result.returncode:return None
            value=json.loads(result.stdout)
            if value.get('arrival_seq')!=3 or 'pending_response' not in value.get('operation_statuses',[]):raise AssertionError('fault was not injected at declared replay prefix')
            return value
        def exit_summary(item):
            path=control/'jobs'/item['id']/f"attempt-{item['attempt']}.worker"/'exit.json'
            receipt=json.loads(path.read_text())
            if receipt.get('exited') is not True or receipt.get('removed') is not True or receipt.get('running') is not False or receipt.get('pid')!=0 or receipt.get('inspected_id')!=receipt.get('container_id'):raise AssertionError('missing irreversible inspected exit/removal proof')
            if receipt['labels'].get('cpag.job')!=item['id'] or receipt['labels'].get('cpag.attempt')!=str(item['attempt']):raise AssertionError('exit proof identity mismatch')
            return {'attempt':item['attempt'],'exited':True,'removed':True,'running':False,'pid':0,'container_id':receipt['container_id']}
        queued=prepare('queued-cancel');client.expect('POST',f'/api/v3/runs/{queued}/cancel',{})
        queued_status=state(queued)
        if queued_status['state']!='cancelled' or queued_status['attempt']!=0:raise AssertionError('queued cancellation acquired an attempt')
        report['jobs']['queued_cancel']={'id':queued,'state':'cancelled','attempt':0,'exit_proof':'not applicable; never claimed'}
        report['checks']['queued_cancel_no_publication']=True;save()

        running=prepare('running-cancel');running_claim=claim(running,'running-cancel')
        observed={}
        def cancel_at_prefix(phase):
            if phase=='during_execution':
                observed.update(wait_for(lambda:marker(running_claim),description='actual pending replay prefix'))
                client.expect('POST',f'/api/v3/runs/{running}/cancel',{})
        result=driver(running_claim['worker'],command=['python','-c',GATE_CODE],checkpoint=cancel_at_prefix).attempt(running_claim)
        if result!='cancelled' or state(running)['state']!='cancelled' or (shared/running_claim['output_dir']).exists():raise AssertionError('running replay cancellation published partial output')
        report['jobs']['running_cancel']={'id':running,'state':'cancelled','prefix':observed,'exit':exit_summary(running_claim)}
        report['checks']['running_cancel_after_replay_prefix_exit_confirmed']=True;save()

        bad=prepare('invalid-input',invalid=True);failure_attempts=[]
        for number in range(1,4):
            item=claim(bad,'invalid-'+str(number));result=driver(item['worker']).attempt(item)
            if result!='failed':raise AssertionError('invalid replay input was not a calculation failure')
            failure_attempts.append(exit_summary(item))
        failed=state(bad)
        if failed['state']!='failed' or failed['attempt']!=3 or failed.get('artifact_path') is not None:raise AssertionError('bounded invalid replay retries did not end failed without publication')
        report['jobs']['invalid_input']={'id':bad,'state':'failed','attempts':failure_attempts,'last_error':failed.get('last_error')}
        report['checks']['invalid_input_failed_no_trusted_partial_history']=True;save()

        lost=prepare('worker-kill');lost_claim=claim(lost,'worker-kill',lease=5)
        private_claim=work/'lost-claim.json';r.write_private(private_claim,lost_claim)
        private_config=work/'lost-worker.json';r.write_private(private_config,{'api_url':api.url,'worker_token':wt,'coordinator_token':ct,'shared_root':str(shared),'control_root':str(control),'image':image})
        child_code="""import json,sys,time
from pathlib import Path
from cpag_worker.worker import API
from cpag_worker.isolated import DockerExecutor
claim=json.load(open(sys.argv[1]));cfg=json.load(open(sys.argv[2]));ready=Path(sys.argv[3]);gate=sys.argv[4]
def checkpoint(phase):
    if phase=='during_execution':
        folder=Path(cfg['control_root'])/'jobs'/claim['id']/('attempt-'+str(claim['attempt'])+'.worker')
        record=json.loads((folder/'execution.json').read_text())
        import subprocess
        for _ in range(300):
            value=subprocess.run(['docker','exec',record['container_id'],'cat','/runtime/replay-prefix.json'],capture_output=True,text=True)
            if value.returncode==0:
                ready.write_text(value.stdout)
                while True:time.sleep(1)
            time.sleep(.1)
        raise RuntimeError('missing actual replay prefix')
worker=DockerExecutor(API(cfg['api_url'],cfg['worker_token']),API(cfg['api_url'],cfg['coordinator_token']),cfg['shared_root'],cfg['control_root'],claim['worker'],image=cfg['image'],heartbeat=.2,lease=5,timeout=45,command=['python','-c',gate],checkpoint=checkpoint)
worker.attempt(claim)
"""
        ready=work/'kill-ready.json';log=(work/'lost-worker.log').open('wb')
        child=subprocess.Popen([sys.executable,'-c',child_code,str(private_claim),str(private_config),str(ready),GATE_CODE],env=env,cwd=r.REPO,stdout=log,stderr=subprocess.STDOUT);log.close()
        wait_for(lambda:ready.exists(),description='kill injection ready')
        prefix=json.loads(ready.read_text())
        if prefix.get('arrival_seq')!=3 or 'pending_response' not in prefix.get('operation_statuses',[]):raise AssertionError('worker kill occurred outside declared replay prefix')
        child.kill();child.wait(timeout=10)
        wait_for(lambda:not state(lost).get('lease_valid'),seconds=15,description='actual lease expiry')
        recovery=driver('recovery').recover(lost)
        if not any(item.get('id')==lost and item.get('exited') for item in recovery):raise AssertionError('killed replay container lacks recovery exit proof')
        old_exit=exit_summary(lost_claim)
        retry=claim(lost,'retry-from-start')
        if retry['attempt']!=2:raise AssertionError('interrupted replay did not create attempt two')
        result=driver(retry['worker']).attempt(retry)
        succeeded=state(lost)
        if result!='succeeded' or succeeded['state']!='succeeded' or succeeded['attempt']!=2:raise AssertionError('replay retry did not publish exactly one successful attempt')
        output=shared/retry['output_dir'];manifest=verify_task(output)
        snapshots=[json.loads(line) for line in (output/'snapshots.jsonl').read_text().splitlines()]
        if snapshots[0]['snapshot_number']!=0 or snapshots[0]['arrival_seq']!=0 or manifest['attempt_id']!=2:raise AssertionError('retry did not start replay from initial snapshot')
        if (shared/lost_claim['output_dir']).exists():raise AssertionError('interrupted attempt published partial history')
        client.expect('GET',f'/api/v3/runs/{lost}/result')
        history=client.expect('GET',f'/api/v3/runs/{lost}/revisions')['revisions']
        if not history:raise AssertionError('successful retry history unavailable through public API')
        sha=succeeded['artifact_sha256'];identity={key:retry[key] for key in ('worker','attempt','token')}
        api.post('/v1/jobs/'+lost+'/complete',{**identity,'manifest_sha256':sha})
        if state(lost)['artifact_sha256']!=sha:raise AssertionError('idempotent retry replaced the publication')
        try:api.post('/v1/jobs/'+lost+'/complete',{**{key:lost_claim[key] for key in ('worker','attempt','token')},'manifest_sha256':sha})
        except APIError as error:
            if error.status!=409:raise
        else:raise AssertionError('old interrupted attempt was allowed to complete')
        anchors=list(output.glob('*.json'));anchors=[p for p in anchors if len(p.stem)==64]
        if len(anchors)!=1 or state(lost)['artifact_sha256']!=sha:raise AssertionError('duplicate terminal publication')
        report['jobs']['worker_kill_retry']={'id':lost,'prefix':prefix,'old_exit':old_exit,'retry_exit':exit_summary(retry),'state':'succeeded','attempt':2,'artifact_sha256':sha,'snapshots':len(snapshots),'revisions':len(history),'normalized_analysis_sha256':fingerprint(json.loads((output/'analysis.json').read_text()))}
        report['checks'].update(worker_kill_actual_lease_expiry=True,retry_from_initial_snapshot=True,old_attempt_complete_refused=True,idempotent_complete_one_publication=True)
        report['status']='passed';save()
        print(json.dumps({'status':'passed','public_report':str(public/'lifecycle.json'),'checks':report['checks']},indent=2))
    except Exception as error:
        report['status']='failed';report['error_type']=type(error).__name__;report['error']=str(error);save();raise
    finally:
        if child is not None and child.poll() is None:child.kill();child.wait(timeout=10)
        r.stop(app)
        for item in tracked:
            path=control/'jobs'/item['id']/f"attempt-{item['attempt']}.worker"/'execution.json'
            if path.exists():
                try:record=json.loads(path.read_text());subprocess.run(['docker','rm','-f',record['container_id']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                except (OSError,ValueError,KeyError):pass
        if created:subprocess.run(['docker','rm','-f',database],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path);parser.add_argument('--skip-image-build',action='store_true');parser.add_argument('--image',default='cpag-isolated:r18-lifecycle');args=parser.parse_args()
    main(args.output,skip_image_build=args.skip_image_build,image=args.image)
