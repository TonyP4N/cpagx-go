#!/usr/bin/env python3
"""Disposable V3 application/Worker/catalog backup and fresh restore drill.

Use --serve to keep both the source and restored public applications available
for browser inspection. state.json is private; report.json contains no secrets.
"""
import argparse
import copy
from http.cookiejar import CookieJar
import hashlib
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
from urllib.parse import urlencode, quote
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen
from urllib.error import HTTPError, URLError

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'scripts/backup'),str(REPO/'scripts/validation'),
             str(REPO/'services/analysis/src')]
import bundle
from dual_source_fixtures import make_case

PG_IMAGE='mirror.gcr.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94'
WORKER_IMAGE='cpag-isolated:round5'


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def write_private(path,value):
    path=Path(path)
    with open(path,'x',encoding='utf-8',opener=lambda p,f:os.open(p,f,0o600)) as stream:
        json.dump(value,stream,indent=2);stream.write('\n')


def run(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)


class Client:
    def __init__(self,origin):
        self.origin=origin;self.cookies=CookieJar();self.opener=build_opener(HTTPCookieProcessor(self.cookies))
    def request(self,method,path,body=None,headers=None,timeout=30):
        if body is not None and not isinstance(body,bytes):body=json.dumps(body,separators=(',',':')).encode()
        req=Request(self.origin+path,data=body,method=method,
                    headers=headers or {'Content-Type':'application/json'})
        try:response=self.opener.open(req,timeout=timeout)
        except HTTPError as error:response=error
        with response:
            raw=response.read();code=response.status
            ctype=response.headers.get('Content-Type','')
        if 'json' in ctype and not path.endswith('/download'):
            try:value=json.loads(raw)
            except ValueError:value={'invalid_json':True}
        else:value=raw
        return code,value
    def expect(self,method,path,body=None,code=200,headers=None,timeout=30):
        status,value=self.request(method,path,body,headers,timeout)
        if status!=code:
            raise RuntimeError(f'{method} {path} returned {status}, expected {code}: {value!r}')
        return value
    def cookie(self):
        for item in self.cookies:
            if item.name=='cpag_session':return item.value
        raise RuntimeError('session cookie missing')


def wait_ready(url,process,seconds=30):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if process.poll() is not None:raise RuntimeError('service exited before readiness')
        try:
            with urlopen(url+'/health/ready',timeout=1) as response:
                if response.status==200:return
        except (OSError,HTTPError,URLError):pass
        time.sleep(.2)
    raise RuntimeError('service readiness timeout')


def stop(process):
    if process is None or process.poll() is not None:return
    process.terminate()
    try:process.wait(timeout=20)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


def build(work,env,skip_image_build=False,build_ui=False):
    with (work/'build-go.log').open('wb') as log:
        run('go','build','-o',str(work/'cpagx-v3'),'./cmd/cpagx-v3',
            cwd=REPO/'internal/jobs/integration',env=env,stdout=log,stderr=subprocess.STDOUT)
        run('go','build','-o',str(work/'cpagctl'),'./cmd/cpagctl',
            cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT)
    if not skip_image_build:
        with (work/'build-image.log').open('wb') as log:
            run('docker','build','-t',WORKER_IMAGE,'-f','deployments/isolated-executor/Dockerfile','.',
                cwd=REPO,stdout=log,stderr=subprocess.STDOUT)
    if build_ui:
        with (work/'build-ui.log').open('wb') as log:
            run('npm','run','build',cwd=REPO/'webui',env=env,stdout=log,stderr=subprocess.STDOUT)


def start_app(work,label,binary,config):
    path=work/(label+'-config.json');write_private(path,config)
    log=(work/(label+'.log')).open('ab')
    process=subprocess.Popen([str(binary),'--config',str(path)],cwd=REPO,
                             stdout=log,stderr=subprocess.STDOUT)
    log.close()
    wait_ready('http://'+config['public_addr'],process)
    return process


def start_worker(work,label,config_path,env):
    log=(work/(label+'.log')).open('ab')
    process=subprocess.Popen([sys.executable,'-m','cpag_worker.service','--config',str(config_path)],
                             cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT)
    log.close()
    return process


def make_config(pg_port,db,root,control,public,internal,worker_token,coordinator_token,
                username,password,static_root):
    return {'database_url':f'postgres://postgres:m4-disposable-only@127.0.0.1:{pg_port}/{db}?sslmode=disable',
            'shared_root':str(root),'control_root':str(control),
            'public_addr':f'127.0.0.1:{public}','internal_addr':f'127.0.0.1:{internal}',
            'worker_token':worker_token,'coordinator_token':coordinator_token,
            'bootstrap_admin_username':username,'bootstrap_admin_password':password,
            'static_root':str(static_root) if static_root.is_dir() else '',
            'python_bin':sys.executable,
            'python_path':str(REPO/'services/analysis/src')}


def upload(client,dataset,role,path,key,sha_override=None,expected=201):
    data=Path(path).read_bytes();digest=hashlib.sha256(data).hexdigest()
    query=urlencode({'role':role,'name':Path(path).name})
    headers={'Content-Type':'application/octet-stream','X-Content-SHA256':sha_override or digest,
             'Idempotency-Key':key}
    return client.expect('POST',f'/api/v3/datasets/{dataset}/files?{query}',data,
                         code=expected,headers=headers,timeout=60)


def cli_request(binary,work,url,user,password,path):
    session=work/'cli-session.json'
    credentials=json.dumps({'username':user,'password':password})
    base=[str(binary),'--url',url,'--session',str(session)]
    login=run(*base,'login',input=credentials,text=True,capture_output=True)
    if not json.loads(login.stdout).get('user'):raise RuntimeError('CLI login returned no user')
    result=run(*base,'request','GET',path,text=True,capture_output=True)
    return json.loads(result.stdout)


def cli_call(binary,work,url,method,path,body=None):
    base=[str(binary),'--url',url,'--session',str(work/'cli-session.json')]
    result=run(*base,'request',method,path,input=json.dumps(body) if body is not None else None,
               text=True,capture_output=True)
    return json.loads(result.stdout)


def status_until(client,job,seconds=180):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        value=client.expect('GET','/api/v3/runs/'+job)['run']
        if value['state'] in ('succeeded','failed','cancelled'):return value
        time.sleep(.5)
    raise RuntimeError('run did not reach terminal state')


def check_evidence(client,job,root,attempt):
    analysis=json.loads((root/'jobs'/job/f'attempt-{attempt}'/'analysis.json').read_text())
    operation=analysis['operations'][0]['operation_id']
    change=analysis['changes'][0]['event_id']
    result=client.expect('GET','/api/v3/runs/'+job+'/result')
    graph=client.expect('GET','/api/v3/runs/'+job+'/graph')
    evidence=client.expect('GET','/api/v3/runs/'+job+'/evidence?'+urlencode({'operation':operation}))
    changed=client.expect('GET','/api/v3/runs/'+job+'/evidence?'+urlencode({'change':change}))
    refs=evidence.get('verified_original_evidence',[])
    if len(refs)<4 or not changed.get('verified_original_evidence'):
        raise RuntimeError('fewer than four original evidence references resolved')
    artifacts=client.expect('GET','/api/v3/runs/'+job+'/artifacts')['artifacts']
    item=next((item for item in artifacts if item['path']=='analysis.json'),None)
    if item is None:raise RuntimeError('analysis artifact missing')
    downloaded=client.expect('GET','/api/v3/runs/'+job+'/artifacts/analysis.json/download')
    if not isinstance(downloaded,bytes) or hashlib.sha256(downloaded).hexdigest()!=item['sha256']:
        raise RuntimeError('download differs from verified artifact')
    return {'result':result,'graph':graph,'operation':operation,'change':change,
            'original_refs':len(refs),'artifact_count':len(artifacts)}


def drill(work,serve=False,skip_image_build=False,build_ui=False):
    container='cpag-r16-'+secrets.token_hex(4)
    pg_port,source_public,source_internal,restored_public,restored_internal=[port() for _ in range(5)]
    source_root=work/'source';source_root.mkdir()
    source_control=work/'control';source_control.mkdir()
    restored_root=work/'restored-new-directory';restored_control=work/'restored-control';restored_control.mkdir()
    fixture=work/'fixture';network,process,dual_profile=make_case(fixture,'success')
    admin_user='admin-'+secrets.token_hex(3);admin_password=secrets.token_urlsafe(24)
    user='analyst-'+secrets.token_hex(3);password=secrets.token_urlsafe(24)
    viewer='viewer-'+secrets.token_hex(3);viewer_password=secrets.token_urlsafe(24)
    worker_token=secrets.token_urlsafe(32);coordinator_token=secrets.token_urlsafe(32)
    source_app=restored_app=worker=None;created=False
    env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(REPO/'services/worker'),str(REPO/'services/analysis/src')]),
             GOCACHE=os.environ.get('GOCACHE',str(Path(tempfile.gettempdir())/'cpag-r16-go-build')),
             GOMODCACHE=os.environ.get('GOMODCACHE',str(Path(tempfile.gettempdir())/'cpag-go-mod')))
    try:
        build(work,env,skip_image_build,build_ui)
        run('docker','run','--name',container,'-d','-e','POSTGRES_DB=m4_validation',
            '-e','POSTGRES_PASSWORD=m4-disposable-only','-p',f'127.0.0.1:{pg_port}:5432',
            PG_IMAGE,stdout=subprocess.DEVNULL)
        created=True
        for _ in range(100):
            if subprocess.run(['docker','exec',container,'pg_isready','-h','127.0.0.1','-U','postgres',
                               '-d','m4_validation'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
            time.sleep(.1)
        else:raise RuntimeError('PostgreSQL readiness timeout')
        for migration in sorted((REPO/'internal/jobs/migrations').glob('*.sql')):
            with migration.open('rb') as source:
                bundle.pg(container,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,
                          stdout=subprocess.DEVNULL)
        static_root=REPO/'webui/out'
        if not (static_root/'index.html').is_file():
            raise RuntimeError('webui/out/index.html missing; build the frontend before V3 acceptance')
        config=make_config(pg_port,'m4_validation',source_root,source_control,source_public,
                           source_internal,worker_token,coordinator_token,admin_user,admin_password,static_root)
        source_app=start_app(work,'source-app',work/'cpagx-v3',config)
        origin='http://127.0.0.1:'+str(source_public)
        admin=Client(origin);admin.expect('POST','/api/v3/session',{'username':admin_user,'password':admin_password})
        analyst_info=admin.expect('POST','/api/v3/users',{'username':user,'password':password,'role':'analyst'},code=201)['user']
        viewer_info=admin.expect('POST','/api/v3/users',{'username':viewer,'password':viewer_password,'role':'viewer'},code=201)['user']
        analyst=Client(origin);analyst.expect('POST','/api/v3/session',{'username':user,'password':password})
        dataset=analyst.expect('POST','/api/v3/datasets',{'name':'Round 16 synthetic intake','source_kind':'synthetic',
            'source':'generated fixture','batch':'round16','authorization_ref':'synthetic fixture only'},code=201)['dataset']['id']
        admin.expect('POST',f'/api/v3/datasets/{dataset}/acl',{'user_id':viewer_info['id'],'access':'viewer'})
        viewer_client=Client(origin);viewer_client.expect('POST','/api/v3/session',
            {'username':viewer,'password':viewer_password})
        if viewer_client.expect('GET',f'/api/v3/datasets/{dataset}')['dataset']['id']!=dataset:
            raise RuntimeError('viewer cannot read granted dataset')
        bad=upload(analyst,dataset,'network',network,'bad-digest-1','0'*64,expected=422)
        if bad['error']['code']!='checksum_mismatch':raise RuntimeError('bad upload not rejected')
        network_file=upload(analyst,dataset,'network',network,'network-upload-1')['file']
        process_file=upload(analyst,dataset,'process',process,'process-upload-1')['file']
        duplicate=upload(analyst,dataset,'network',network,'network-upload-1',expected=200)['file']
        if duplicate['id']!=network_file['id']:raise RuntimeError('idempotent upload changed identity')
        intake={'dataset_id':dataset,'synthetic':True,
            'authorization':{'allowed_use':'test','evidence_ref':'fixture','reviewer':'automation'},
            'time_basis':{'timezone':'UTC','precision':'seconds','synchronization':'fixture clocks','evidence_ref':'fixture'},
            'mapping':{'field_units_ref':'fixture','device_map_ref':'fixture','effective_period_ref':'fixture'}}
        intake_cfg=analyst.expect('POST',f'/api/v3/datasets/{dataset}/configs',
            {'kind':'intake','document':intake},code=201)['config']
        preflight=analyst.expect('POST',f'/api/v3/datasets/{dataset}/preflight',
            {'config_version_id':intake_cfg['id']},code=200)
        if not preflight.get('preflight_id') or not preflight['report'].get('status'):
            raise RuntimeError('preflight report unavailable')
        dual=json.loads(dual_profile.read_text())
        incomplete=copy.deepcopy(dual);incomplete['mappings']=[]
        incomplete_cfg=analyst.expect('POST',f'/api/v3/datasets/{dataset}/configs',
            {'kind':'dual','document':incomplete},code=201)['config']
        denied=analyst.expect('POST','/api/v3/runs',{'dataset_id':dataset,
            'config_version_id':incomplete_cfg['id'],'preflight_id':preflight['preflight_id'],'mode':'dual_source'},code=422)
        if denied['error']['code']!='insufficient_basis':raise RuntimeError('missing mapping permitted')
        dual_cfg=analyst.expect('POST',f'/api/v3/datasets/{dataset}/configs',
            {'kind':'dual','document':dual},code=201)['config']
        if dual_cfg['id']==incomplete_cfg['id'] or dual_cfg['version']<=incomplete_cfg['version']:
            raise RuntimeError('config update did not create new version')
        worker_config={'api_url':'http://127.0.0.1:'+str(source_internal),'shared_root':str(source_root),
            'control_root':str(source_control),'worker_token':worker_token,
            'coordinator_token':coordinator_token,'worker_id':'r16-worker',
            'image':WORKER_IMAGE,'poll_seconds':.2,'recovery_seconds':2}
        worker_config_path=work/'worker-config.json';write_private(worker_config_path,worker_config)
        worker=start_worker(work,'worker',worker_config_path,env)
        run_id=analyst.expect('POST','/api/v3/runs',{'dataset_id':dataset,
            'config_version_id':dual_cfg['id'],'preflight_id':preflight['preflight_id'],'mode':'dual_source'},code=201)['run']['id']
        viewer_code,viewer_reply=viewer_client.request('POST','/api/v3/runs',{'dataset_id':dataset,
            'config_version_id':dual_cfg['id'],'preflight_id':preflight['preflight_id'],'mode':'dual_source'})
        if viewer_code not in (403,404) or viewer_reply['error']['code'] not in ('forbidden','not_found'):
            raise RuntimeError('viewer write denied with unexpected result')
        status=status_until(analyst,run_id)
        if status['state']!='succeeded':raise RuntimeError('worker run failed: '+str(status.get('last_error')))
        source_evidence=check_evidence(analyst,run_id,source_root,status['attempt'])
        cli_datasets=cli_request(work/'cpagctl',work,origin,user,password,'/api/v3/datasets')['datasets']
        api_datasets=analyst.expect('GET','/api/v3/datasets')['datasets']
        if cli_datasets!=api_datasets:raise RuntimeError('CLI and API dataset semantics differ')
        cli_status=cli_call(work/'cpagctl',work,origin,'GET','/api/v3/runs/'+run_id)
        api_status=analyst.expect('GET','/api/v3/runs/'+run_id)
        if cli_status!=api_status:raise RuntimeError('CLI and API run status differ')
        cli_result=cli_call(work/'cpagctl',work,origin,'GET','/api/v3/runs/'+run_id+'/result')
        api_result=analyst.expect('GET','/api/v3/runs/'+run_id+'/result')
        if cli_result!=api_result:raise RuntimeError('CLI and API result differ')
        real=analyst.expect('POST','/api/v3/datasets',{'name':'Declared real branch with generated test bytes',
            'source_kind':'real','source':'generated fixture for branch test',
            'batch':'test-only','authorization_ref':'pending review'},code=201)['dataset']['id']
        real_file=upload(analyst,real,'network',network,'real-network-1')['file']
        real_intake={'dataset_id':real,'synthetic':False}
        real_config=analyst.expect('POST',f'/api/v3/datasets/{real}/configs',
            {'kind':'intake','document':real_intake},code=201)['config']['id']
        real_report=analyst.expect('POST',f'/api/v3/datasets/{real}/preflight',
            {'config_version_id':real_config},code=200)['report']
        if real_report['synthetic'] is not False or real_file['role']!='network':
            raise RuntimeError('real single source metadata changed semantics')
        stop(worker);worker=None
        queued=cli_call(work/'cpagctl',work,origin,'POST','/api/v3/runs',
            {'dataset_id':dataset,'config_version_id':dual_cfg['id'],'preflight_id':preflight['preflight_id'],'mode':'dual_source'})['run']['id']
        queued_status=analyst.expect('GET','/api/v3/runs/'+queued)['run']
        if queued_status['state']!='queued':raise RuntimeError('CLI submission was not queued')
        cli_cancel=cli_call(work/'cpagctl',work,origin,'POST','/api/v3/runs/'+queued+'/cancel',{})
        cancelled=analyst.expect('GET','/api/v3/runs/'+queued)['run']
        if cli_cancel['run']['state']!='cancelled' or cancelled['state']!='cancelled':
            raise RuntimeError('CLI cancellation did not match API state')
        stop(source_app);source_app=None
        snapshot=bundle.backup(container,'m4_validation',source_root,work/'bundle')
        if snapshot['format_version']!=5 or not snapshot['catalog_audit']['valid']:
            raise RuntimeError('catalog backup failed')
        restored_audit=bundle.restore(container,work/'bundle',restored_root)
        if not restored_audit['valid'] or not restored_audit.get('catalog_equal'):
            raise RuntimeError('fresh restore audit failed')
        restore_config=make_config(pg_port,'m4_restore_validation',restored_root,restored_control,
            restored_public,restored_internal,worker_token,coordinator_token,
            admin_user,admin_password,static_root)
        restored_app=start_app(work,'restored-app',work/'cpagx-v3',restore_config)
        restored_origin='http://127.0.0.1:'+str(restored_public)
        stale=Request(restored_origin+'/api/v3/session',headers={'Cookie':'cpag_session='+analyst.cookie()})
        try:
            with urlopen(stale,timeout=5) as response:stale_code=response.status
        except HTTPError as error:stale_code=error.code
        if stale_code!=401:raise RuntimeError('restored session remained valid')
        restored_client=Client(restored_origin)
        restored_client.expect('POST','/api/v3/session',{'username':user,'password':password})
        restored_status=restored_client.expect('GET','/api/v3/runs/'+run_id)['run']
        if restored_status['state']!='succeeded' or restored_status['config_version_id']!=dual_cfg['id']:
            raise RuntimeError('restored run/version differs')
        restored_evidence=check_evidence(restored_client,run_id,restored_root,restored_status['attempt'])
        if restored_evidence['result']!=source_evidence['result'] or restored_evidence['graph']!=source_evidence['graph']:
            raise RuntimeError('restored projections differ')
        source_app=start_app(work,'source-app-restarted',work/'cpagx-v3',config)
        worker=start_worker(work,'worker-restarted',worker_config_path,env)
        report={'valid':True,'scope':('synthetic software validation; real-source admission branch '
            'exercised with generated test bytes, no real material validated'),
            'source_database':'m4_validation','restored_database':'m4_restore_validation',
            'catalog_tables':snapshot['catalog_audit']['counts'],
            'source_job_state':status['state'],'restored_job_state':restored_status['state'],
            'source_attempt':status['attempt'],'restored_attempt':restored_status['attempt'],
            'original_evidence_refs':restored_evidence['original_refs'],
            'session_revoked_on_restore':stale_code==401,'sessions_revoked':restored_audit['sessions_revoked'],
            'cli_api_dataset_equal':True,'cli_api_status_equal':True,'cli_api_result_equal':True,
            'cli_submit_cancel_same_state_machine':True,
            'viewer_write_denied':True,'bad_upload_rejected':True,
            'idempotent_upload_same_file':True,'incomplete_mapping_blocked':True,
            'new_config_version_bound':True,
            'declared_real_test_branch_preflight_status':real_report['status'],
            'restored_catalog_equal':restored_audit['catalog_equal'],'restored_attempt_history_equal':restored_audit['attempt_history_equal']}
        (work/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        (work/'public').mkdir()
        (work/'public/report.json').write_text(json.dumps(report,indent=2)+'\n')
        state={'url':origin,'restored_url':restored_origin,'username':admin_user,'password':admin_password,
               'analyst_username':user,'analyst_password':password,
               'viewer_username':viewer,'viewer_password':viewer_password,
               'admin_username':admin_user,'admin_password':admin_password,
               'fixture_dir':str(fixture),'run_id':run_id,'restored_run_id':run_id,
               'dataset_id':dataset,'real_dataset_id':real,'source_root':str(source_root),
               'restored_root':str(restored_root),'pg_container':container}
        write_private(work/'state.json',state)
        print(json.dumps(report,sort_keys=True),flush=True)
        if serve:
            stopping=False
            def shutdown(*_):
                nonlocal stopping
                stopping=True
            signal.signal(signal.SIGTERM,shutdown);signal.signal(signal.SIGINT,shutdown)
            while not stopping:
                if source_app.poll() is not None or restored_app.poll() is not None or worker.poll() is not None:
                    raise RuntimeError('served application or worker exited')
                time.sleep(.5)
        return report
    finally:
        stop(worker);stop(source_app);stop(restored_app)
        if created:subprocess.run(['docker','rm','-f','-v',container],stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='new private acceptance directory')
    parser.add_argument('--serve',action='store_true')
    parser.add_argument('--skip-image-build',action='store_true')
    parser.add_argument('--build-ui',action='store_true')
    args=parser.parse_args()
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    drill(args.output.resolve(),args.serve,args.skip_image_build,args.build_ui)


if __name__=='__main__':main()
