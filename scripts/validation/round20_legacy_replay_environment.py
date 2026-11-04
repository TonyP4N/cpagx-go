#!/usr/bin/env python3
"""One real Go/PG/isolated Worker legacy-spool fixture for focused UI checks.

Only the hand-built normal R18 fixture runs. This uses the ordinary public API;
no task/catalog writes, fake responses or analysis-result injection. Private
credentials and complete endpoint responses stay outside the repository.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time
from urllib.parse import urlencode

import round16_acceptance as r
from round16_supplement import intake
from round18_profile import fixture


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--image',required=True)
    parser.add_argument('--static-root',type=Path,default=r.REPO/'webui/out')
    args=parser.parse_args();work=args.output.resolve()
    work.mkdir(parents=True,exist_ok=False,mode=0o700)
    root,control=work/'source',work/'control';root.mkdir();control.mkdir()
    env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(r.REPO/'services/worker'),str(r.REPO/'services/analysis/src')]),
             GOPROXY=os.environ.get('GOPROXY','off'),NO_PROXY='127.0.0.1,localhost',no_proxy='127.0.0.1,localhost')
    r.build(work,env,skip_image_build=True)
    pg_name='cpag-r20-legacy-'+secrets.token_hex(5);pg,public,internal=[r.port() for _ in range(3)]
    app=worker=None
    r.run('docker','run','--name',pg_name,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only','-p',f'127.0.0.1:{pg}:5432',r.PG_IMAGE,stdout=subprocess.DEVNULL)
    try:
        for _ in range(150):
            if subprocess.run(['docker','exec',pg_name,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],capture_output=True).returncode==0:break
            time.sleep(.1)
        else:raise RuntimeError('postgres_readiness_timeout')
        with (work/'migrations.log').open('wb') as log:
            for migration in sorted((r.REPO/'internal/jobs/migrations').glob('*.sql')):
                with migration.open('rb') as stream:r.bundle.pg(pg_name,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=stream,stdout=log,stderr=subprocess.STDOUT)
        username='legacy-review-admin';password=secrets.token_urlsafe(24);wt=secrets.token_urlsafe(32);ct=secrets.token_urlsafe(32)
        config=r.make_config(pg,'m4_validation',root,control,public,internal,wt,ct,username,password,args.static_root)
        app=r.start_app(work,'app',work/'cpagx-v3',config)
        worker_config={'api_url':f'http://127.0.0.1:{internal}','shared_root':str(root),'control_root':str(control),'worker_token':wt,'coordinator_token':ct,'worker_id':'r20-legacy-review','image':args.image,'poll_seconds':.2,'recovery_seconds':2}
        r.write_private(work/'worker-config.json',worker_config);worker=r.start_worker(work,'worker',work/'worker-config.json',env)
        origin=f'http://127.0.0.1:{public}';client=r.Client(origin);client.expect('POST','/api/v3/session',{'username':username,'password':password})
        networks,process,profile,config_doc=fixture(work/'fixture')
        config_doc['replay']['history_format']='replay-history-checkpoint-delta-2';profile.write_text(json.dumps(config_doc,indent=2)+'\n')
        ds=client.expect('POST','/api/v3/datasets',{'name':'R20 legacy normal spool','source_kind':'synthetic','source':'independent generated R18 fixture','batch':'legacy-normal','authorization_ref':'synthetic software verification only'},code=201)['dataset']['id']
        for index,path in enumerate(networks):r.upload(client,ds,'network',path,'network-'+str(index))
        r.upload(client,ds,'process',process,'legacy-process')
        cid=client.expect('POST',f'/api/v3/datasets/{ds}/configs',{'kind':'intake','document':intake(ds)},code=201)['config']['id']
        preflight=client.expect('POST',f'/api/v3/datasets/{ds}/preflight',{'config_version_id':cid})
        dual=client.expect('POST',f'/api/v3/datasets/{ds}/configs',{'kind':'dual','document':config_doc},code=201)['config']['id']
        run=client.expect('POST','/api/v3/runs',{'dataset_id':ds,'config_version_id':dual,'preflight_id':preflight['preflight_id'],'mode':'dual_source_replay'},code=201)['run']['id']
        status=r.status_until(client,run,seconds=180)
        if status['state']!='succeeded' or status['attempt']!=1:raise RuntimeError('legacy_fixture_did_not_finish_attempt1')
        result=client.expect('GET',f'/api/v3/runs/{run}/result');count=result['data']['replay']['snapshot_count']
        assert count==16 and result['history_format']=='replay-history-checkpoint-delta-2'
        snapshots=[client.expect('GET',f'/api/v3/runs/{run}/snapshots/{n}') for n in range(count)]
        pending=next(row for row in snapshots if row['analysis']['operations'] and row['analysis']['operations'][0]['response']['state']=='missing')
        operation=result['data']['analysis']['operations'][0]['operation_id']
        expected={'result':result,'last':count-1,'pending':pending['snapshot_number'],'snapshots':snapshots,'operation_id':operation,'evidence':{}}
        for number in [pending['snapshot_number'],count-1]:
            expected['evidence'][str(number)]=client.expect('GET',f'/api/v3/runs/{run}/evidence?'+urlencode({'revision':number,'operation':operation,'ref_offset':0,'ref_limit':25}))
        (work/'expected-private.json').write_text(json.dumps(expected,indent=2)+'\n');(work/'expected-private.json').chmod(0o600)
        state={'url':origin,'username':username,'password':password,'dataset_id':ds,'run_id':run,'last_snapshot':count-1,'pending_snapshot':pending['snapshot_number'],'source_root':str(root),'control_root':str(control),'pg_container':pg_name,'app_pid':app.pid,'worker_pid':worker.pid,'harness_pid':os.getpid()}
        r.write_private(work/'state.json',state)
        public_context={'url':origin,'datasetId':ds,'runId':run,'lastSnapshot':count-1,'pendingSnapshot':pending['snapshot_number'],'expectedPath':str(work/'expected-private.json')}
        (work/'run-context.json').write_text(json.dumps(public_context,indent=2)+'\n')
        print(json.dumps({'status':'ready','run_context':str(work/'run-context.json'),'url':origin,'last_snapshot':count-1,'pending_snapshot':pending['snapshot_number']}),flush=True)
        halt=False
        def stop(*_):
            nonlocal halt
            halt=True
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        while not halt:
            if app.poll() is not None or worker.poll() is not None:raise RuntimeError('isolated_legacy_service_exited')
            time.sleep(.5)
    finally:
        r.stop(worker);r.stop(app)
        with (work/'database.sql').open('wb') as stream:subprocess.run(['docker','exec',pg_name,'pg_dump','-U','postgres','m4_validation'],stdout=stream,stderr=subprocess.PIPE)
        subprocess.run(['docker','stop',pg_name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':main()
