#!/usr/bin/env python3
"""Actual isolated PG/Go/idle-Worker operations checks; no industrial acceptance."""
import argparse, hashlib, json, os, secrets, subprocess, sys, tempfile, time, traceback
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import round16_acceptance as base

REPO=Path(__file__).resolve().parents[2]
def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,reason):
    if not value:raise AssertionError(reason)
def allowed_output(path):
    target=Path(path).resolve(); roots={Path(tempfile.gettempdir()).resolve(),Path('/tmp').resolve()}
    return any(target != root and target.is_relative_to(root) for root in roots)

def main(output):
    output=output.resolve();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    public=output/'public';public.mkdir();report={'version':'r21-observability-short-1','status':'running','scope':'actual isolated PG/Go/idle Worker plus explicit synthetic queue/lease records; not an analysis/industrial/reference acceptance','checks':{},'failures':[]}
    api=worker=None;pg=None;paused=False;denied=None
    def save():write(public/'report.json',report)
    def command(label,args,**kw):
        result=subprocess.run(args,capture_output=True,**kw);(output/(label+'.stdout')).write_bytes(result.stdout);(output/(label+'.stderr')).write_bytes(result.stderr)
        require(result.returncode==0,label+'_failed');return result.stdout
    def sql(query):return command('sql-'+secrets.token_hex(3),['docker','exec',pg,'psql','-U','postgres','-d','m4_validation','-Atc',query],timeout=10).decode().strip()
    def raw(method,url,body=None,token=None):
        data=None if body is None else json.dumps(body).encode();headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        req=Request(url,data=data,method=method,headers=headers)
        try:response=urlopen(req,timeout=10)
        except HTTPError as error:response=error
        with response:payload=response.read();return response.status,json.loads(payload) if payload else None
    save()
    try:
        report['git_head']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
        report['source_sha256']={name:sha(REPO/name) for name in ['internal/catalog/health.go','internal/catalog/operations.go','internal/jobapi/worker_observation.go','internal/jobs/migrations/017_worker_observability.sql', 'scripts/validation/round21_observability.py']}
        report['platform']=subprocess.check_output(['uname','-sm'],text=True).strip()
        pg='cpag-r21-observe-'+secrets.token_hex(4);pgport,port,internal=[base.port() for _ in range(3)]
        command('postgres-start',['docker','run','--name',pg,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only','-p',f'127.0.0.1:{pgport}:5432',base.PG_IMAGE],timeout=60)
        for _ in range(100):
            if subprocess.run(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],capture_output=True).returncode==0:break
            time.sleep(.1)
        else:raise RuntimeError('postgres_not_ready')
        for migration in sorted((REPO/'internal/jobs/migrations').glob('*.sql')):
            result=subprocess.run(['docker','exec','-i',pg,'psql','-U','postgres','-d','m4_validation','-v','ON_ERROR_STOP=1'],input=migration.read_bytes(),capture_output=True,timeout=10)
            (output/(migration.name+'.log')).write_bytes(result.stdout+result.stderr);require(result.returncode==0,'migration_failed')
        env=dict(os.environ,GOCACHE=os.environ.get('GOCACHE') or str(Path(tempfile.gettempdir())/'cpag-r21-go-cache'),PYTHONPATH=os.pathsep.join([str(REPO/'services/worker'),str(REPO/'services/analysis/src')]))
        command('build-go',['go','build','-o',str(output/'cpagx-v3'),'./cmd/cpagx-v3'],cwd=REPO/'internal/jobs/integration',env=env,timeout=120)
        source=output/'source';control=output/'control';source.mkdir();control.mkdir()
        wt,ct=secrets.token_urlsafe(32),secrets.token_urlsafe(32);origin=f'http://127.0.0.1:{port}';inside=f'http://127.0.0.1:{internal}'
        cfg=base.make_config(pgport,'m4_validation',source,control,port,internal,wt,ct,'r21-admin',secrets.token_urlsafe(24),output/'no-static')
        api=base.start_app(output,'api',output/'cpagx-v3',cfg)
        client=base.Client(origin);client.expect('POST','/api/v3/session',{'username':cfg['bootstrap_admin_username'],'password':cfg['bootstrap_admin_password']},headers={'Content-Type':'application/json','Origin':origin})
        ops='/api/v3/health/operations';report['checks']['unauthenticated_denied']=raw('GET',origin+ops)[0]==401
        client.expect('POST','/api/v3/users',{'username':'r21-viewer','password':'synthetic-viewer-pass','role':'viewer'},code=201,headers={'Content-Type':'application/json','Origin':origin})
        viewer=base.Client(origin);viewer.expect('POST','/api/v3/session',{'username':'r21-viewer','password':'synthetic-viewer-pass'},headers={'Content-Type':'application/json','Origin':origin});report['checks']['viewer_denied']=viewer.request('GET',ops)[0]==403
        require(all(report['checks'].values()),'authorization_boundary_failed')
        initial=client.expect('GET',ops);write(public/'initial.json',initial)
        require(initial['worker_total']==0,'new_database_claimed_online_worker')
        worker_config={'api_url':inside,'shared_root':str(source),'control_root':str(control),'worker_token':wt,'coordinator_token':ct,'worker_id':'r21-real-idle','poll_seconds':.2,'recovery_seconds':1}
        worker_path=output/'worker.json';base.write_private(worker_path,worker_config);worker=base.start_worker(output,'worker',worker_path,env)
        for _ in range(100):
            if sql("SELECT count(*) FROM m4_worker_observations WHERE worker='r21-real-idle'")=='1':break
            require(worker.poll() is None,'idle_worker_exited');time.sleep(.1)
        else:raise RuntimeError('idle_worker_observation_timeout')
        live=client.expect('GET',ops+'?worker_stale_seconds=2');write(public/'live-worker.json',live);require(live['worker_fresh']>=1,'fresh_worker_missing');report['checks']['real_idle_worker_poll']=True
        require(raw('POST',inside+'/v1/claim',{'worker':'unauthorized','lease_seconds':2},'invalid-token')[0]==401,'bad_worker_credential_accepted')
        require(sql("SELECT count(*) FROM m4_worker_observations WHERE worker='unauthorized'")=='0','unauthorized_observation_recorded');report['checks']['bad_worker_credential_no_observation']=True
        base.stop(worker);worker=None
        sql("INSERT INTO m4_jobs(id,max_attempts) VALUES('r21-active',3)")
        code,claim=raw('POST',inside+'/v1/claim',{'worker':'r21-lease','lease_seconds':2},wt);require(code==200,'claim_failed')
        identity={key:claim[key] for key in ('worker','attempt','token')};require(raw('POST',inside+'/v1/jobs/r21-active/heartbeat',{**identity,'lease_seconds':2},wt)[0]==200,'heartbeat_failed')
        require(sql("SELECT last_kind FROM m4_worker_observations WHERE worker='r21-lease'")=='heartbeat','active_heartbeat_not_recorded');report['checks']['valid_attempt_heartbeat']=True
        sql("INSERT INTO m4_jobs(id,max_attempts) VALUES('r21-queued',1)")
        time.sleep(2.3)
        expired=client.expect('GET',ops+'?worker_stale_seconds=2&queue_warn_seconds=1');write(public/'expired-worker.json',expired)
        codes={row['code'] for row in expired['alerts']};require({'lease_expired','worker_heartbeat_stale','workers_unavailable','queue_wait_exceeded'}<=codes,'fault_alert_missing')
        before=sql("SELECT last_seen FROM m4_worker_observations WHERE worker='r21-lease'")
        require(raw('POST',inside+'/v1/jobs/r21-active/heartbeat',{**identity,'lease_seconds':2},wt)[0]==409,'expired_heartbeat_accepted')
        require(sql("SELECT last_seen FROM m4_worker_observations WHERE worker='r21-lease'")==before,'stale_heartbeat_refreshed_observation');report['checks']['lease_and_missing_worker_alerts']=True
        code,retry=raw('POST',inside+'/v1/claim',{'worker':'r21-retry','lease_seconds':10},wt);require(code==200 and retry['attempt']==2,'retry_claim_failed')
        retry_identity={key:retry[key] for key in ('worker','attempt','token')};require(raw('POST',inside+'/v1/jobs/r21-active/fail',{**retry_identity,'message':'invalid CSV record width: private-fixture-content','retryable':True},wt)[0]==200,'fail_rpc_failed')
        errors=client.expect('GET',ops+'?errors=parse&limit=1');write(public/'parse-query.json',errors)
        require(errors['retained_error_counts'].get('parse')==1 and len(errors['errors'])==1 and errors['errors'][0]['run_id']=='r21-active','parse_query_failed')
        require('private-fixture-content' not in json.dumps(errors),'raw_error_leaked');require(errors['queue']['retry_queued']==1 and errors['queue']['additional_attempts']==1,'retry_counter_failed');report['checks']['synthetic_queue_retry_and_parse_classification']=True
        command('database-pause',['docker','pause',pg],timeout=10);paused=True
        require(raw('GET',origin+'/health/live')[0]==200,'db_outage_broke_liveness');began=time.monotonic();code,value=raw('GET',origin+'/health/ready');write(public/'database-down.json',value)
        require(code==503 and value['checks']['database'] is False,'db_outage_declared_ready');report['checks']['database_live_ready_split']={'ready_status':code,'seconds':time.monotonic()-began}
        command('database-unpause',['docker','unpause',pg],timeout=10);paused=False
        for _ in range(30):
            if raw('GET',origin+'/health/ready')[0]==200:break
            time.sleep(.1)
        else:raise RuntimeError('database_readiness_not_recovered')
        denied=source/'jobs';saved=source/'jobs.hidden';denied.rename(saved)
        require(raw('GET',origin+'/health/live')[0]==200,'storage_outage_broke_liveness');code,value=raw('GET',origin+'/health/ready');write(public/'storage-down.json',value);require(code==503 and value['checks']['storage'] is False,'missing_storage_declared_ready')
        saved.rename(denied);denied=None;require(raw('GET',origin+'/health/ready')[0]==200,'restored_storage_not_ready');report['checks']['storage_live_ready_split_and_recovery']=True
        report['status']='passed';report['limits']=['Queue/parse error records were explicit synthetic control-plane records, not a new parser execution.','No actual disk-full, OOM, PID exhaustion, partial SQLite write, or industrial material run in this short check.'];save();print(json.dumps({'status':'passed','report':str(public/'report.json')}))
    except Exception as error:
        (output/'failure-traceback.txt').write_text(traceback.format_exc());report['status']='failed';report['failures'].append({'type':type(error).__name__,'reason':'see private failure traceback'});save();raise
    finally:
        if denied is not None and (source/'jobs.hidden').exists() and not denied.exists():(source/'jobs.hidden').rename(denied)
        if worker is not None:base.stop(worker)
        if api is not None:base.stop(api)
        if pg:
            if paused:subprocess.run(['docker','unpause',pg],capture_output=True)
            subprocess.run(['docker','rm','-f',pg],capture_output=True)
        report['cleanup_completed']=True;save()
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if not allowed_output(args.output):parser.error('fresh isolated output below the system temporary directory required')
    main(args.output)
