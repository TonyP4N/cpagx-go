#!/usr/bin/env python3
"""Bounded real cpagx-v3/PG/isolated Worker DAG6 acceptance; never a proxy.

Small mode exercises one offline and one replay analysis, then focused integrity,
ACL, cancellation and restart checks. S100 submits exactly one frozen replay.
All outputs, including failures, remain; private state contains credentials.
"""
import argparse
from copy import deepcopy
import hashlib
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, quote
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener

import round16_acceptance as r
from round16_supplement import intake, sql, literal
from round19_core_small import inputs as small_inputs
from round19_core_oracle import check_raw_evidence

REPO=r.REPO
sys.path.insert(0,str(REPO/'services/worker'))
FORMAT='shared-observation-dag-6';CAPACITY='engineering-core-capacity-3';RESOURCE='storage-budget-2'
FROZEN=REPO.parent/'outputs/cpag-r19-core-cached-generator-S6-attempt1'


def sha(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(65536),b''):value.update(chunk)
    return value.hexdigest()


def write(path,value):
    Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


MEASUREMENT_VERSION='formal-service-wall-clock-2'
CLOCK_GAP_SECONDS=5


class InvalidEnvironment(RuntimeError):
    """A host pause or clock adjustment invalidates this performance cell."""


def clock_start():
    return {'wall':time.time(),'monotonic':time.monotonic()}


def clock_elapsed(start):
    wall=time.time()-start['wall'];monotonic=time.monotonic()-start['monotonic']
    return {'wall_seconds':wall,'monotonic_seconds':monotonic,'wall_minus_monotonic_seconds':wall-monotonic}


class MeasuredClient(r.Client):
    def __init__(self,origin):
        super().__init__(origin)
        self.opener=build_opener(ProxyHandler({}),HTTPCookieProcessor(self.cookies))
        self.timings=[]
    def request(self,method,path,body=None,headers=None,timeout=30):
        start=clock_start();code=None;value=None
        try:
            code,value=super().request(method,path,body,headers,timeout)
            return code,value
        finally:
            size=len(value) if isinstance(value,bytes) else len(json.dumps(value,separators=(',',':')).encode())
            measurement={'method':method,'path':path,'status':code,'response_bytes':size,**clock_elapsed(start)}
            self.timings.append(measurement)
            observer=getattr(self,'clock_observer',None)
            if observer:observer(path,measurement)


class Harness:
    def __init__(self,args):
        self.args=args;self.work=args.output;self.app=self.worker=None;self.created=False
        self.pg='cpag-r19-formal-'+secrets.token_hex(5)
        self.root=self.work/'source';self.control=self.work/'control'
        self.report={'measurement_version':MEASUREMENT_VERSION,'clock_gap_policy':{'maximum_absolute_wall_minus_monotonic_seconds':CLOCK_GAP_SECONDS,'failure_classification':'invalid_environment','action':'cancel_and_record_bounded_cleanup'},'status':'running','mode':args.mode,'image':args.image,'scope':'synthetic formal software integration; no industrial/reference-environment capacity claim',
                     'limits':{'core_seconds':1800,'service_seconds':2100,'extra_service_seconds':300,'cpu':4,'memory_bytes':8*1024**3,'temporary_bytes':4*1024**3,'output_bytes':1024**3,'query_seconds':10,'query_bytes':8*1024**2,'page_items':100,'download_seconds':120,'download_bytes':1024**3,'download_client_chunk_bytes':65536},'checks':{},'runs':[]}
        self.env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(REPO/'services/worker'),str(REPO/'services/analysis/src')]),GOCACHE=os.environ.get('GOCACHE','/tmp/cpag-r19-go-cache'),GOMODCACHE=os.environ.get('GOMODCACHE','/tmp/cpag-go-mod'),NO_PROXY='127.0.0.1,localhost',no_proxy='127.0.0.1,localhost')
        self.state={};self.restart_number=0
    def flush(self):
        write(self.work/'report.json',self.report)
        write(self.work/'http-timings.json',getattr(getattr(self,'client',None),'timings',[]))
        if self.state:
            self.state.update(app_pid=self.app.pid if self.app and self.app.poll() is None else None,worker_pid=self.worker.pid if self.worker and self.worker.poll() is None else None,harness_pid=os.getpid())
            path=self.work/'state.json'
            if path.exists():
                with path.open('w') as stream:json.dump(self.state,stream,indent=2);stream.write('\n')
                path.chmod(0o600)
            else:r.write_private(path,self.state)
    def cancel_cleanup(self,run,row,key):
        """Cancellation response is separate from terminal/exit evidence."""
        started=clock_start();deadline=started['wall']+5;mono_deadline=started['monotonic']+5
        cleanup={'status':'cancel_request_pending','terminal_observed':False};self._clock_cleanup_active=True
        try:
            self.client.expect('POST',f'/api/v3/runs/{run}/cancel',{},timeout=1)
            row['extra_attempt_cancel_requested' if key=='extra_attempt_cleanup' else 'invalid_environment_cancel_requested']=True
            cleanup['status']='cancellation_pending'
            while time.time()<deadline and time.monotonic()<mono_deadline:
                remaining=min(deadline-time.time(),mono_deadline-time.monotonic(),1)
                if remaining<=0:break
                current=self.client.expect('GET',f'/api/v3/runs/{run}',timeout=remaining)['run']
                cleanup.update(last_state=current['state'],attempt=current['attempt'],attempt_history=current.get('attempt_history',[]))
                if current['state'] in ('succeeded','failed','cancelled'):
                    cleanup.update(status='terminal_observed',terminal_observed=True);break
                time.sleep(min(.1,max(0,deadline-time.time()),max(0,mono_deadline-time.monotonic())))
        except (OSError,ValueError,RuntimeError) as error:
            cleanup.update(status='cancellation_observation_unavailable',error_type=type(error).__name__)
        finally:
            cleanup.update(clock_elapsed(started));self._clock_cleanup_active=False
            if not cleanup['terminal_observed']:cleanup['required_action']='verify_extra_attempt_exit_and_cancellation_after_cleanup'
            row[key]=cleanup;self.flush()

    def guard_clock(self,run,row,start,phase,request_measurement=None):
        observation=clock_elapsed(start)
        whole=clock_elapsed({'wall':row['submit_wall'],'monotonic':row['submit_monotonic']})
        observations=[observation,whole]+([request_measurement] if request_measurement else [])
        if any(abs(value['wall_minus_monotonic_seconds'])>CLOCK_GAP_SECONDS for value in observations):
            proof={'phase':phase,'phase_clock':observation,'run_clock':whole,'request_clock':request_measurement}
            row['invalid_environment']=proof
            self.report.update(status='invalid_environment',valid=False,reason='wall_monotonic_gap_exceeds_5_seconds')
            self.flush();self.cancel_cleanup(run,row,'invalid_environment_cleanup')
            raise InvalidEnvironment('wall_monotonic_gap_exceeds_5_seconds')
        return observation

    def observe_http_clock(self,path,measurement):
        if getattr(self,'_clock_cleanup_active',False):return
        match=re.match(r'/api/v3/runs/([^/?]+)',path)
        if not match:return
        row=next((row for row in self.report['runs'] if row['id']==match[1]),None)
        if row is not None and 'submit_wall' in row:
            self.guard_clock(row['id'],row,{'wall':row['submit_wall'],'monotonic':row['submit_monotonic']},'http_request',measurement)

    def run_row(self,run):
        return next(row for row in self.report['runs'] if row['id']==run)

    def setup(self):
        self.root.mkdir();self.control.mkdir()
        inspected=json.loads(subprocess.check_output(['docker','image','inspect',self.args.image],text=True))[0]
        self.report['resolved_image_id']=inspected['Id'];self.report['git_head']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
        self.report['source_files']={str(p.relative_to(REPO)):sha(p) for p in sorted(REPO.rglob('*.py')) if '.git' not in p.parts and ('cpag_core' in p.parts or 'cpag_worker' in p.parts)}
        r.build(self.work,self.env,skip_image_build=True)
        self.report['binary_sha256']=sha(self.work/'cpagx-v3')
        pg,public,internal=[r.port() for _ in range(3)]
        r.run('docker','run','--name',self.pg,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only','-p',f'127.0.0.1:{pg}:5432',r.PG_IMAGE,stdout=subprocess.DEVNULL);self.created=True
        for _ in range(150):
            if subprocess.run(['docker','exec',self.pg,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],capture_output=True).returncode==0:break
            time.sleep(.1)
        else:raise RuntimeError('postgres_readiness_timeout')
        migrations=sorted((REPO/'internal/jobs/migrations').glob('*.sql'))
        if not any(p.name.startswith('016') for p in migrations):raise RuntimeError('migration016_required')
        with (self.work/'migrations.log').open('wb') as log:
            for migration in migrations:
                with migration.open('rb') as source:r.bundle.pg(self.pg,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=log,stderr=subprocess.STDOUT)
        self.report['migrations']={p.name:sha(p) for p in migrations}
        user='formal-admin';password=secrets.token_urlsafe(24);wt=secrets.token_urlsafe(32);ct=secrets.token_urlsafe(32)
        self.config=r.make_config(pg,'m4_validation',self.root,self.control,public,internal,wt,ct,user,password,REPO/'webui/out')
        self.config.update(resource_profile=RESOURCE,capacity_policy=CAPACITY,compact_verifier_image=self.args.image)
        self.app=r.start_app(self.work,'app-initial',self.work/'cpagx-v3',self.config)
        self.origin=f'http://127.0.0.1:{public}';self.client=MeasuredClient(self.origin);self.client.clock_observer=self.observe_http_clock
        self.client.expect('POST','/api/v3/session',{'username':user,'password':password})
        viewer_password=secrets.token_urlsafe(24)
        self.client.expect('POST','/api/v3/users',{'username':'formal-viewer','password':viewer_password,'role':'viewer'},code=201)
        self.viewer=MeasuredClient(self.origin);self.viewer.expect('POST','/api/v3/session',{'username':'formal-viewer','password':viewer_password})
        self.anonymous=MeasuredClient(self.origin)
        self.worker_config=self.work/'worker-config.json'
        r.write_private(self.worker_config,{'api_url':f'http://127.0.0.1:{internal}','shared_root':str(self.root),'control_root':str(self.control),'worker_token':wt,'coordinator_token':ct,'worker_id':'r19-formal-worker','image':self.args.image,'poll_seconds':.2,'recovery_seconds':2,'resource_profile':RESOURCE})
        from cpag_worker.worker import API
        self.internal=API(f'http://127.0.0.1:{internal}',wt)
        self.state={'url':self.origin,'internal_url':f'http://127.0.0.1:{internal}','username':user,'password':password,'admin_username':user,'admin_password':password,'viewer_username':'formal-viewer','viewer_password':viewer_password,'source_root':str(self.root),'control_root':str(self.control),'pg_container':self.pg,'run_ids':[]}
        self.start_worker();self.flush()
    def start_worker(self):
        self.worker=r.start_worker(self.work,'worker',self.worker_config,self.env)
    def admit(self,label,networks,process,profile):
        config=json.loads(Path(profile).read_text())
        dataset=self.client.expect('POST','/api/v3/datasets',{'name':'R19 formal '+label,'source_kind':'synthetic','source':'fixed generated raw fixture','batch':'r19-formal-'+label,'authorization_ref':'synthetic engineering acceptance only'},code=201)['dataset']['id']
        for number,path in enumerate(networks):r.upload(self.client,dataset,'network',path,label+'-network-'+str(number))
        r.upload(self.client,dataset,'process',process,label+'-process')
        version=self.client.expect('POST',f'/api/v3/datasets/{dataset}/configs',{'kind':'intake','document':intake(dataset)},code=201)['config']['id']
        preflight=self.client.expect('POST',f'/api/v3/datasets/{dataset}/preflight',{'config_version_id':version})
        if not preflight.get('preflight_id'):raise RuntimeError('native_intake_preflight_required')
        cfg=self.client.expect('POST',f'/api/v3/datasets/{dataset}/configs',{'kind':'dual','document':config},code=201)['config']['id']
        body={'dataset_id':dataset,'config_version_id':cfg,'preflight_id':preflight['preflight_id'],'mode':'dual_source_replay' if 'replay' in config else 'dual_source'}
        return body
    def submit_wait(self,body,label):
        started=clock_start();began=started['wall'];run=self.client.expect('POST','/api/v3/runs',body,code=201)['run']['id']
        row={'id':run,'label':label,'submit_wall':began,'submit_monotonic':started['monotonic']};self.report['runs'].append(row);self.state['run_ids'].append(run);self.state['run_id']=run;self.state['dataset_id']=body['dataset_id'];self.flush()
        self.guard_clock(run,row,started,'submit')
        while True:
            self.guard_clock(run,row,started,'status_poll_before_request')
            if time.time()-began>=2100:raise RuntimeError('formal_service_2100s_timeout')
            status=self.client.expect('GET',f'/api/v3/runs/{run}')['run']
            self.guard_clock(run,row,started,'status_poll')
            if status.get('attempt',0)>1:
                # This is one bounded measurement, never an automatic retry cell.
                row.update(state=status['state'],attempt=status['attempt'],first_attempt_retried=True,
                           retry_observed_seconds=time.time()-began,attempt_history=status.get('attempt_history',[]))
                # The cell is failed before cleanup begins; cleanup is not more measurement time.
                self.report.update(status='failed',valid=False,reason='first_attempt_failed_or_expired')
                self.flush();self.cancel_cleanup(run,row,'extra_attempt_cleanup')
                raise RuntimeError('first_attempt_failed_or_expired_extra_attempt_cleanup_recorded')
            if status['state'] in ('succeeded','failed','cancelled'):break
            if self.worker.poll() is not None:raise RuntimeError('real_worker_exited')
            time.sleep(.25)
        row.update(state=status['state'],attempt=status['attempt'],terminal_seconds=time.time()-began,terminal_monotonic_seconds=time.monotonic()-started['monotonic'])
        if status['state']!='succeeded':
            row['last_error']=status.get('last_error');raise RuntimeError('formal_worker_run_failed')
        if status['attempt']!=1:raise RuntimeError('bounded_cell_must_have_exactly_one_attempt')
        row['attempt_history']=status['attempt_history'];return run,row
    def shared(self,run,action,**query):
        path=f'/api/v3/runs/{run}/shared-query?'+urlencode(dict(action=action,**{k:json.dumps(v,separators=(',',':')) if k=='path' else v for k,v in query.items()}))
        start=clock_start();value=self.client.expect('GET',path,timeout=11);elapsed=self.guard_clock(run,self.run_row(run),start,'shared_query')['wall_seconds']
        if elapsed>10 or len(json.dumps(value,separators=(',',':')).encode())>8*1024**2:raise RuntimeError('bounded_shared_query_exceeded')
        return value,elapsed
    def stream_download(self,run):
        items=self.client.expect('GET',f'/api/v3/runs/{run}/artifacts')['artifacts'];item=next(row for row in items if row['path']=='shared/shared.sqlite3')
        path=f'/api/v3/runs/{run}/artifacts/'+quote(item['path'],safe='/')+'/download'
        start=clock_start();deadline=start['wall']+120;count=0;digest=hashlib.sha256()
        with self.client.opener.open(Request(self.origin+path),timeout=10) as response:
            if response.status!=200:raise RuntimeError('stream_download_denied')
            with (self.work/(run+'-shared.sqlite3.download')).open('xb') as stream:
                while True:
                    self.guard_clock(run,self.run_row(run),start,'stream_download')
                    if time.time()>=deadline:raise RuntimeError('stream_download_deadline')
                    try:raw=response.read(65536)
                    finally:self.guard_clock(run,self.run_row(run),start,'stream_download_read')
                    if not raw:break
                    count+=len(raw)
                    if count>1024**3:raise RuntimeError('stream_download_byte_limit')
                    digest.update(raw);stream.write(raw)
        download_clock=self.guard_clock(run,self.run_row(run),start,'stream_download_eof')
        if time.time()>deadline:raise RuntimeError('stream_download_deadline_after_eof')
        expected=item.get('size',item.get('size_bytes'))
        if digest.hexdigest()!=item['sha256'] or expected is not None and count!=expected:raise RuntimeError('stream_download_digest_or_size')
        return {'bytes':count,'sha256':digest.hexdigest(),**download_clock,'chunk_bytes':65536,'file':'shared/shared.sqlite3'}
    def inspect_result(self,run,row,networks,process):
        selected_start=clock_start();first_query=len(self.client.timings);metadata,tick=self.shared(run,'metadata');ticks=[tick]
        manifest=metadata['manifest'];self.state['replay_run_id' if manifest['mode']=='replay' else 'offline_run_id']=run
        if manifest['storage_format']!=FORMAT or manifest['config_fingerprint']!=json.loads((self.root/'jobs'/run/'attempt-1/run_manifest.json').read_text())['config_fingerprint']:raise RuntimeError('service_manifest_binding')
        samples={}
        for collection,key in [('operations','operation_id'),('changes','event_id')]:
            page,tick=self.shared(run,'page',logical_root='analysis.json',path=[collection],offset=0,limit=1);ticks.append(tick)
            identity,tick=self.shared(run,'get',logical_root='analysis.json',path=[collection,0,key]);ticks.append(tick);samples[collection]=identity
        evidence_path=f'/api/v3/runs/{run}/evidence?'+urlencode({'operation':samples['operations']})
        first=len(self.client.timings);evidence=self.client.expect('GET',evidence_path,timeout=11);ticks.append(self.client.timings[first]['wall_seconds'])
        original=evidence['verified_original_evidence'];audit=check_raw_evidence(original,[str(p) for p in networks],str(process))
        identities={json.dumps(row['source_ref'],sort_keys=True) for row in original}
        kinds=[row['kind'] for row in audit['checked_references']]
        if len(identities)<4 or kinds.count('frame')<2 or kinds.count('csv')<2:raise RuntimeError('four_request_response_before_after_raw_references_required')
        changed=self.client.expect('GET',f'/api/v3/runs/{run}/evidence?'+urlencode({'change':samples['changes']}),timeout=11)
        if not changed['verified_original_evidence']:raise RuntimeError('change_original_evidence_missing')
        if manifest['mode']=='replay':
            count=manifest['counts']['snapshots'];history=[]
            for number in sorted({0,count//2,count-1}):
                identity,tick=self.shared(run,'get',logical_root='history/snapshots',path=[number,'snapshot_id']);ticks.append(tick);history.append({'number':number,'snapshot_id':identity})
            final,tick=self.shared(run,'snapshot',snapshot=count-1,path=['snapshot_id']);ticks.append(tick)
            if final!=manifest['final_snapshot_id']:raise RuntimeError('terminal_snapshot_binding_changed')
            revisions,tick=self.shared(run,'revisions',after=0,limit=1);ticks.append(tick);row['selected_history']=history
        selected_clock=self.guard_clock(run,row,selected_start,'selected_queries');selected_seconds=selected_clock['wall_seconds']
        if any(q['wall_seconds']>10 or q['response_bytes']>8*1024**2 for q in self.client.timings[first_query:]):raise RuntimeError('selected_http_read_limit_exceeded')
        row.update(selected_http_seconds=selected_seconds,selected_http_monotonic_seconds=selected_clock['monotonic_seconds'],individual_selected_query_seconds=ticks,raw_evidence_references=len(identities),independent_raw_evidence=audit,queried_success_seconds=time.time()-row['submit_wall'],queried_success_monotonic_seconds=time.monotonic()-row['submit_monotonic'])
        if any(t>10 for t in ticks) or row['queried_success_seconds']>2100:raise RuntimeError('selected_query_or_service_deadline')
        self.resource_proof(run,row,selected_seconds)
        row['download']=self.stream_download(run)
        denied={}
        for label,client in [('anonymous',self.anonymous),('viewer_without_acl',self.viewer)]:
            for suffix in ('shared-query?action=metadata','evidence?operation='+quote(samples['operations']),'artifacts/shared/shared.sqlite3/download'):
                code,_=client.request('GET',f'/api/v3/runs/{run}/'+suffix,timeout=11)
                if code not in (401,403,404):raise RuntimeError('acl_denial_missing')
                denied[label+':'+suffix.split('?')[0]]=code
        row['acl_denials']=denied
        code,_=self.client.request('GET',f'/api/v3/runs/{run}/shared-query?'+urlencode({'action':'page','logical_root':'analysis.json','path':'["operations"]','limit':101}),timeout=11)
        if code<400:raise RuntimeError('over_budget_page_was_accepted')
        row['invalid_page_limit_status']=code;self.flush()
        return metadata
    def resource_proof(self,run,row,selected_seconds):
        base=self.control/'jobs'/run/'attempt-1.worker'
        compute=json.loads((base/'compute-result.json').read_text());cgroup=json.loads((base/'compute-cgroup.json').read_text());resources=json.loads((base/'resources.json').read_text());phases=json.loads((base/'compute-phases.json').read_text())
        receipts=sorted(self.control.glob('compact-verification-'+run+'-1-*.json'))
        if len(receipts)!=1:raise RuntimeError('exactly_one_source_verifier_receipt_required')
        receipt=json.loads(receipts[0].read_text());metrics=receipt.get('execution_metrics',{})
        host=receipt.get('docker_inspection',{}).get('HostConfig',{})
        if host.get('NanoCpus')!=4000000000 or host.get('Memory')!=8*1024**3 or host.get('MemorySwap')!=8*1024**3 or host.get('ReadonlyRootfs') is not True or host.get('NetworkMode')!='none' or 'size=4g' not in str(host.get('Tmpfs',{}).get('/tmp','')):
            raise RuntimeError('actual_verifier_container_resource_inspection_mismatch')
        if not receipt.get('cleanup_completed') or receipt.get('verification_report',{}).get('status')!='passed':raise RuntimeError('trusted_verifier_cleanup_or_source_proof_missing')
        if any(metrics.get(name) is None for name in ('wall_seconds','process_cpu_seconds','max_rss_bytes','cgroup_memory_peak_bytes','cgroup_cpu_usage_usec')):raise RuntimeError('verifier_resource_measurement_missing')
        if not any(p.get('kind')=='terminal_measurement_summary' for p in phases) or not any(p.get('kind')=='terminal_measurement_summary' for p in metrics.get('phase_resources',[])):raise RuntimeError('complete_phase_resources3_summary_missing')
        if resources['memory_bytes']!=8*1024**3 or resources['cpus']!='4' or resources['temporary_bytes']!=4*1024**3 or resources['output_bytes']!=1024**3:raise RuntimeError('fixed_compute_resources_mismatch')
        if cgroup['cgroup_memory_peak_bytes']>8*1024**3 or metrics['cgroup_memory_peak_bytes']>8*1024**3 or cgroup['tmp_bytes']>4*1024**3 or cgroup['output_bytes']>1024**3:raise RuntimeError('observed_container_budget_exceeded')
        core=compute['wall_seconds']+receipt['wall_seconds']+selected_seconds
        overhead=row['queried_success_seconds']-core
        if core>1800 or overhead>300:raise RuntimeError('preregistered_core_or_service_overhead_budget_exceeded')
        ledger=json.loads(sql(self.pg,"SELECT COALESCE(json_agg(row_to_json(t)),'[]') FROM (SELECT job_id,attempt,container_name,state,started_at,exited_at FROM m4_compact_verifications WHERE job_id="+literal(run)+") t"))
        if len(ledger)!=1 or ledger[0]['state']!='exited' or not ledger[0]['exited_at']:raise RuntimeError('durable_verifier_exit_ledger_missing')
        row.update(core_export_verify_selected_seconds=core,service_overhead_seconds=overhead,compute_resources=resources,compute_usage=compute,compute_cgroup=cgroup,verification_metrics=metrics,verifier_receipt=receipts[0].name,verifier_ledger=ledger)
        write(self.work/(run+'-resource-proof.json'),{'compute':compute,'compute_cgroup':cgroup,'compute_phases':phases,'verifier':receipt,'ledger':ledger})
    def negatives_small(self,run,body):
        r.stop(self.worker);self.worker=None
        queued=self.client.expect('POST','/api/v3/runs',body,code=201)['run']['id']
        state=self.client.expect('GET',f'/api/v3/runs/{queued}')['run']
        if state['state']!='queued' or state['attempt']!=0:raise RuntimeError('queued_cancel_was_not_unstarted')
        self.client.expect('POST',f'/api/v3/runs/{queued}/cancel',{})
        state=self.client.expect('GET',f'/api/v3/runs/{queued}')['run']
        if state['state']!='cancelled' or state['attempt']!=0:raise RuntimeError('queued_cancel_did_not_remain_unstarted')
        from cpag_worker.worker import APIError
        try:self.internal.post('/v1/jobs/'+queued+'/complete',{'worker':'r19-formal-worker','attempt':999,'token':'invalid-attempt-token','manifest_sha256':'0'*64})
        except APIError as error:
            if error.status!=409:raise RuntimeError('stale_attempt_wrong_denial')
        else:raise RuntimeError('stale_attempt_publication_accepted')
        self.report['checks']['queued_cancel_and_stale_publish']={'id':queued,'cancelled_at_attempt':0,'invalid_attempt_complete_status':409}
        for relative in ('sources/process.csv','shared/shared.sqlite3'):
            target=self.root/'jobs'/run/'attempt-1'/relative
            original=target.read_bytes();original_sha=sha(target);before_mode=target.stat().st_mode & 0o777
            for kind in ('tamper','missing'):
                saved=self.work/('negative-'+kind+'-'+target.name)
                try:
                    target.chmod(0o600)
                    if kind=='tamper':target.write_bytes(bytes([original[0]^1])+original[1:]);saved.write_bytes(target.read_bytes())
                    else:
                        target.parent.chmod(0o700);target.rename(saved)
                    code,value=self.client.request('GET',f'/api/v3/runs/{run}/shared-query?action=metadata',timeout=11)
                    proof={'status':code,'body':value,'original_sha256':original_sha,'same_size':kind=='tamper'}
                    self.report['checks'][kind+'_'+relative+'_denied']=proof;self.flush()
                    if code!=409:raise RuntimeError('changed_or_missing_bytes_did_not_fail_closed')
                finally:
                    if kind=='missing' and saved.exists():saved.rename(target)
                    elif target.exists():target.write_bytes(original)
                    target.chmod(before_mode);target.parent.chmod(0o555)
                    if sha(target)!=original_sha:raise RuntimeError('controlled_negative_restore_hash_mismatch')
        r.stop(self.app);self.app=None;self.restart_number+=1
        self.app=r.start_app(self.work,'app-restarted-'+str(self.restart_number),self.work/'cpagx-v3',self.config)
        code,_=self.client.request('GET',f'/api/v3/runs/{run}/shared-query?action=metadata',timeout=11)
        if code!=409:raise RuntimeError('restart_must_lose_in_memory_verification_approval')
        restart_clock=clock_start();deadline=restart_clock['wall']+120
        while True:
            self.guard_clock(run,self.run_row(run),restart_clock,'restart_reverification')
            if time.time()>=deadline:raise RuntimeError('small_restart_reverification_timeout')
            code,value=self.client.request('GET',f'/api/v3/runs/{run}/shared-query?action=metadata',timeout=11)
            if code==200:break
            if code!=409:raise RuntimeError('restart_reverification_unexpected_status')
            time.sleep(.25)
        self.report['checks']['restart_reverification']={'first_status':409,'eventual_status':200,'run_id':run}
        self.start_worker();self.flush()
    def legacy_before_compact(self):
        """Create an ordinary old task through the same V3 API, then upgrade policy."""
        r.stop(self.worker);self.worker=None;r.stop(self.app);self.app=None
        legacy=deepcopy(self.config)
        for name in ('resource_profile','capacity_policy','compact_verifier_image'):legacy.pop(name,None)
        self.app=r.start_app(self.work,'app-legacy-policy',self.work/'cpagx-v3',legacy)
        worker=json.loads(self.worker_config.read_text());worker.pop('resource_profile',None)
        legacy_worker=self.work/'legacy-worker-config.json';r.write_private(legacy_worker,worker)
        self.worker=r.start_worker(self.work,'legacy-worker',legacy_worker,self.env)
        from dual_source_fixtures import make_case
        from round17_profile import profile as legacy_profile
        network,process,profile=make_case(self.work/'fixture-legacy','success')
        profile.write_text(json.dumps(legacy_profile()))
        body=self.admit('legacy-offline',[network],process,profile)
        run,row=self.submit_wait(body,'old-format-historical-read')
        before=r.check_evidence(self.client,run,self.root,1)
        if before['original_refs']<4:raise RuntimeError('legacy_original_reference_count')
        r.stop(self.worker);self.worker=None;r.stop(self.app);self.app=None
        self.app=r.start_app(self.work,'app-compact-policy',self.work/'cpagx-v3',self.config)
        self.start_worker()
        after=r.check_evidence(self.client,run,self.root,1)
        if before!=after:raise RuntimeError('old_result_changed_after_compact_policy_upgrade')
        row['original_evidence_refs']=before['original_refs']
        self.report['checks']['old_format_read']={'status':'passed','run_id':run,'created_through_formal_api':True,'read_before_and_after_explicit_policy_upgrade':True,'original_evidence_refs':before['original_refs']}
        self.flush()

    def execute(self):
        self.setup()
        if self.args.mode=='small':
            if self.args.legacy_evidence:
                previous=json.loads(self.args.legacy_evidence.read_text())
                proof=previous.get('checks',{}).get('old_format_read',{})
                if proof.get('status')!='passed':raise RuntimeError('legacy_reference_not_passed')
                self.report['checks']['old_format_read']={**proof,'reused_evidence_sha256':sha(self.args.legacy_evidence),'reused_evidence_path':str(self.args.legacy_evidence)}
            else:self.legacy_before_compact()
            bodies=[]
            for mode,case in [('offline','success'),('replay','normal')]:
                networks,process,profile,config=small_inputs(self.work/('fixture-'+mode),case,mode)
                body=self.admit(mode,networks,process,profile);bodies.append(body)
                run,row=self.submit_wait(body,mode);metadata=self.inspect_result(run,row,networks,process)
                from round19_shared_business_check import compare_all_business_roots
                comparison=compare_all_business_roots(self.root/'jobs'/run/'attempt-1',networks,process,profile,
                    self.work/('complete-business-'+mode),expected_manifest=metadata['manifest'])
                row['complete_business_comparison']={key:comparison[key] for key in ('status','version','output',
                    'independent_core_export','complete_named_root_count','complete_business_root_count',
                    'unapproved_business_differences','wall_seconds')};self.flush()
                projection=self.client.expect('GET',f'/api/v3/runs/{run}/evaluation-input?projection=dual',timeout=11)
                from round19_shared_evaluation_check import check_saved_evaluation
                row['saved_evaluation']=check_saved_evaluation(self.client,run,projection,work=self.work/('evaluation-'+mode),dataset_id=body['dataset_id']);self.flush()
            self.negatives_small(run,bodies[-1])
        else:
            fixture=self.args.fixture.resolve()
            required=[fixture/name for name in ('fixture.json','network.pcap','process.csv','replay-profile.json')]
            if any(not p.is_file() for p in required):raise RuntimeError('original_s100_fixture_missing')
            before={p.name:sha(p) for p in sorted(fixture.iterdir()) if p.is_file()};config=json.loads((fixture/'replay-profile.json').read_text());declaration=json.loads((fixture/'fixture.json').read_text())
            if declaration.get('operations')!=100 or declaration.get('schema_version')!='r19-density-capacity-6' or config.get('storage_format')!=FORMAT:raise RuntimeError('frozen_s100_identity_mismatch')
            self.report['fixed_fixture']={'path':str(fixture),'files':before,'declaration':declaration}
            networks=[fixture/'network.pcap'];process=fixture/'process.csv';body=self.admit('s100',networks,process,fixture/'replay-profile.json')
            run,row=self.submit_wait(body,'s100-replay-only');self.inspect_result(run,row,networks,process)
            after={p.name:sha(p) for p in sorted(fixture.iterdir()) if p.is_file()}
            if before!=after:raise RuntimeError('original_frozen_fixture_changed')
            self.report['checks']['frozen_fixture_unchanged']=True
        self.report['status']='passed';self.report['valid']=True;self.flush()
        print(json.dumps({'status':'passed','report':str(self.work/'report.json'),'state':str(self.work/'state.json'),'mode':self.args.mode}),flush=True)
        if self.args.serve:
            halt=False
            def stop_signal(*_):
                nonlocal halt
                halt=True
            signal.signal(signal.SIGTERM,stop_signal);signal.signal(signal.SIGINT,stop_signal)
            while not halt:
                if self.app.poll() is not None or self.worker.poll() is not None:raise RuntimeError('retained_service_exited')
                time.sleep(.5)
    def close(self):
        r.stop(self.worker);r.stop(self.app)
        if self.created:
            with (self.work/'database.sql').open('wb') as dump:
                r.bundle.pg(self.pg,'m4_validation','pg_dump',stdout=dump)
            with (self.work/'postgres.log').open('wb') as log:subprocess.run(['docker','logs',self.pg],stdout=log,stderr=subprocess.STDOUT)
            if self.report.get('status') in ('failed','invalid_environment'):
                subprocess.run(['docker','stop',self.pg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.report['failed_database_preserved']={'container':self.pg,'state':'stopped_private_database_retained'}
            else:subprocess.run(['docker','rm','-f','-v',self.pg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.flush()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('small','s100'),required=True);parser.add_argument('--image',required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--fixture',type=Path,default=FROZEN);parser.add_argument('--serve',action='store_true')
    parser.add_argument('--legacy-evidence',type=Path,help='Reuse a previously passed unchanged formal legacy check')
    args=parser.parse_args()
    if re.fullmatch(r'(?:sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})',args.image) is None:parser.error('immutable Docker image ID/digest required')
    args.output=args.output.resolve()
    if not args.output.is_relative_to(Path('/private/tmp')):parser.error('output must be a fresh directory under /private/tmp')
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    harness=Harness(args)
    try:harness.execute()
    except BaseException as error:
        harness.report.update(status='invalid_environment' if isinstance(error,InvalidEnvironment) else 'failed',valid=False,error_type=type(error).__name__,reason=str(error)[:2048]);harness.flush();raise
    finally:harness.close()


if __name__=='__main__':main()
