"""Formal HTTP evaluation lifecycle for a completed generated density task.

No client timeout is relaxed. Preparation is separately awaited to an actual
ready/failed state and its elapsed cost is retained. Applications may supply a
restart callback to measure a fresh process; otherwise cold state is explicitly
unverified. OS cache state is always unverified by this helper.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request

from round19_density_reference import generate, SCALES

VERSION='r19-formal-density-evaluation-1'
DOCUMENT_BYTES=128*1024**2
QUERY_BYTES=8*1024**2


class HTTPMeasurements:
    def __init__(self,root,client):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=False,mode=0o700)
        self.client=client;self.rows=[]
    def request(self,label,method,path,body=None,*,expected=200,maximum=DOCUMENT_BYTES+65536,cache='unverified'):
        number=len(self.rows)+1;row={'number':number,'label':label,'method':method,'path':path,
            'cache':cache,'os_cache':'unverified','timeout_seconds':10,'response_byte_limit':maximum}
        self.rows.append(row);start=time.monotonic()
        try:
            data=None if body is None else json.dumps(body,ensure_ascii=False,separators=(',',':')).encode()
            req=Request(self.client.origin+path,data=data,method=method,headers={'Content-Type':'application/json'})
            try:response=self.client.opener.open(req,timeout=10)
            except HTTPError as error:response=error
            with response:raw=response.read(maximum+1);row['http_status']=response.status
            file=self.root/f'{number:04d}-{label}.response';file.write_bytes(raw)
            row.update(response_bytes=len(raw),response_sha256=hashlib.sha256(raw).hexdigest(),response_file=file.name)
            if len(raw)>maximum:raise ValueError('complete_response_byte_limit_exceeded')
            allowed=expected if isinstance(expected,(list,tuple)) else [expected]
            if row['http_status'] not in allowed:raise ValueError(f'http_status_{row["http_status"]}_expected_{expected}')
            value=json.loads(raw)
            row['status']='passed';return value
        except BaseException as error:
            row.update(status='failed',error_type=type(error).__name__,reason=str(error));raise
        finally:
            row['seconds']=time.monotonic()-start
            if row['seconds']>10 and row.get('status')=='passed':row.update(status='failed',reason='full_http_request_exceeded_10_seconds')
            with (self.root/'http-measurements.jsonl').open('a') as stream:
                stream.write(json.dumps(row,sort_keys=True)+'\n')
            if row['seconds']>10 and row.get('reason')=='full_http_request_exceeded_10_seconds':
                raise ValueError('full_http_request_exceeded_10_seconds')


def run(client,job,artifact,output,*,scale,restart=None,deadline_seconds=1800):
    from cpag_core import evaluation_bundle as eb
    from cpag_core.evaluation import digest
    from cpag_core.evaluation_details import V2_MATCHING_VERSION
    from cpag_core.evaluation_context import service_publication
    from cpag_core.pipeline import file_hash
    from cpag_core.reference_inventory import build_inventory
    root=Path(output);root.mkdir(parents=True,exist_ok=False,mode=0o700)
    requests=HTTPMeasurements(root/'http',client);began=time.monotonic()
    report={'version':VERSION,'scope':'generated density, actual HTTP service; no reference-environment or industrial acceptance',
            'scale':scale,'job':job,'status':'running','os_cache':'unverified','preparation_samples':[]}
    def flush():(root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    flush();base=f'/api/v3/runs/{job}'
    try:
        submitted=requests.request('prepare-submit','POST',base+'/evaluation-preparation',{'projection':'dual'},expected=(200,202))
        report['prepare_submission']=submitted
        while True:
            state=requests.request('prepare-status','GET',base+'/evaluation-preparation?projection=dual',maximum=1024**2)['preparation']
            report['preparation_samples'].append({'elapsed_seconds':time.monotonic()-began,'preparation':state})
            if state['state']=='ready':break
            if state['state']=='failed':raise ValueError('evaluation_preparation_failed:'+state.get('reason_code','unknown'))
            if time.monotonic()-began>=deadline_seconds:raise ValueError('evaluation_preparation_full_deadline')
            time.sleep(1)
        report['ready_identity']={key:state.get(key) for key in ('id','document_sha256','document_size','preparation_attempt','source_attempt','publication_sha256','strategy_version')}
        report['prepare_seconds']=time.monotonic()-began
        if restart is not None:
            client=restart();requests.client=client;cache='application_process_cold'
        else:cache='application_cache_not_reset'
        cold=requests.request('evaluation-input-cold','GET',base+'/evaluation-input?projection=dual',cache=cache)
        hot=requests.request('evaluation-input-hot','GET',base+'/evaluation-input?projection=dual',cache='application_warm')
        if cold!=hot:raise ValueError('cold_hot_projection_mismatch')
        adapted=cold;b=adapted['binding'];expected=2*SCALES[scale]-1
        if len(adapted['predictions']['events'])!=expected:raise ValueError('independent_density_event_count_mismatch')
        generate(root/'reference',scale,batch=b['batch'],sample_sha256=b['sample_sha256'])
        labels=json.loads((root/'reference/annotations.json').read_text())
        refs=json.loads((root/'reference/references.json').read_text())
        split={'schema_version':'1.0.0','synthetic':True,'rule_windows_seconds':{'association':5},'isolation_seconds':5,'blocks':[
            {'partition':'calibration','batch':b['batch'],'start':'2025-12-01T00:00:00Z','end':'2025-12-01T00:30:00Z','sample_sha256':['a'*64],'normal':False},
            {'partition':'holdout','batch':b['batch'],'start':'2026-01-01T00:00:00Z','end':'2026-01-01T00:30:00Z','sample_sha256':[b['sample_sha256']],'normal':False}]}
        now=datetime.now(timezone.utc);opening=now+timedelta(seconds=10)
        registration={'schema_version':'1.0.0','synthetic':True,'registered_at':now.isoformat(),'holdout_opened_at':opening.isoformat(),
            'input_fingerprint':b['input_fingerprint'],'config_fingerprint':b['config_fingerprint'],
            'split_sha256':digest(split),'tolerance_seconds':0,'thresholds':{}}
        inventory=build_inventory(root/'reference',json.loads((root/'reference/reference-files.json').read_text()))
        start=time.monotonic()
        with service_publication(artifact,file_hash(Path(artifact)/'run_manifest.json'),prepared_adapted=adapted):
            eb.freeze(artifact,split,registration,root/'frozen',batch=b['batch'],sample_sha256=b['sample_sha256'],
                      matching_version=V2_MATCHING_VERSION,bundle_version=eb.V3_VERSION,reference_inventory=inventory)
        report['freeze_seconds']=time.monotonic()-start
        # Labels/reference material is never placed beneath any analysis input mount.
        wait_start=time.monotonic()
        time.sleep(max(0,(opening-datetime.now(timezone.utc)).total_seconds())+.01)
        report['holdout_wait_seconds']=time.monotonic()-wait_start
        start=time.monotonic()
        with service_publication(artifact,file_hash(Path(artifact)/'run_manifest.json'),prepared_adapted=adapted):
            measured=eb.evaluate_bundle(root/'frozen',artifact,labels,refs,root/'bundle')
        report['evaluate_seconds']=time.monotonic()-start
        actual=tuple(measured['record']['metrics'][key] for key in ('tp','fp','fn'))
        if actual!=(expected,0,0):raise ValueError('independent_density_matching_oracle_mismatch:'+repr(actual))
        document={path.name:eb.read(path,limit=eb.V2_DOCUMENT_BYTES) for path in (root/'bundle').iterdir()}
        saved=requests.request('evaluation-import','POST',base+'/evaluations',document,expected=201)
        eid=saved['evaluation']['id'];route=base+'/evaluations/'+eid
        duplicate=requests.request('evaluation-duplicate','POST',base+'/evaluations',document)
        if duplicate['evaluation']['id']!=eid:raise ValueError('duplicate_evaluation_identity_changed')
        detail=requests.request('evaluation-detail','GET',route)
        downloaded=requests.request('evaluation-download','GET',route+'/download')
        if downloaded!=document or detail['result']!=measured:raise ValueError('saved_evaluation_content_changed')
        pid=next(row['id'] for row in adapted['predictions']['events'] if row['kind']=='network_operation')
        evidence=requests.request('prediction-evidence','GET',route+'/evidence?'+urlencode({'event':pid}),maximum=QUERY_BYTES)
        if not evidence['evidence']['evidence']['verified_original_evidence']:raise ValueError('raw_evidence_missing')
        expected_reference=next(iter(refs));query=route+'/evidence?'+urlencode({'event':expected_reference,'reference':'true'})
        original=requests.request('reference-locator','GET',query,maximum=QUERY_BYTES)['evidence']
        selected=original['resolved_record'];fragment=selected['fragment'];raw=base64.b64decode(fragment['content_base64'],validate=True)
        full=(root/'reference/independent-reference.csv').read_bytes()
        if raw!=full[fragment['byte_offset']:fragment['byte_offset']+fragment['size_bytes']] or selected['values']['id']!=expected_reference:
            raise ValueError('independent_reference_fragment_mismatch')
        report.update(status='passed',evaluation_id=eid,expected_tp_fp_fn=[expected,0,0],actual_tp_fp_fn=list(actual),
                      adapted_sha256=digest(adapted),document_sha256=digest(document),reference_fragment_sha256=fragment['sha256'],
                      total_seconds=time.monotonic()-began,binding=b,application_cold_verified=restart is not None)
        return report
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__,reason=str(error),total_seconds=time.monotonic()-began);raise
    finally:flush()


def verify_restored(client,job,original,output):
    """Check persisted preparation, bundle and raw references after real DB restore."""
    from cpag_core.evaluation import digest
    original=Path(original);root=Path(output);root.mkdir(parents=True,exist_ok=False,mode=0o700)
    previous=json.loads((original/'report.json').read_text())
    if previous['status']!='passed':raise ValueError('original_density_evaluation_not_passed')
    requests=HTTPMeasurements(root/'http',client);base=f'/api/v3/runs/{job}';eid=previous['evaluation_id'];route=base+'/evaluations/'+eid
    report={'version':VERSION,'status':'running','job':job,'scope':'empty-database/new-directory query; caller must supply independent restore audit'}
    try:
        state=requests.request('restored-preparation','GET',base+'/evaluation-preparation?projection=dual',maximum=1024**2)['preparation']
        if state['state']!='ready':raise ValueError('restored_preparation_not_ready')
        expected_identity=previous.get('ready_identity')
        if not expected_identity:raise ValueError('original_ready_identity_missing')
        if {key:state.get(key) for key in expected_identity}!=expected_identity:
            raise ValueError('restored_preparation_identity_changed')
        adapted=requests.request('restored-evaluation-input','GET',base+'/evaluation-input?projection=dual',cache='application_process_cold')
        if digest(adapted)!=previous['adapted_sha256']:raise ValueError('restored_evaluation_projection_changed')
        document=requests.request('restored-download','GET',route+'/download')
        if digest(document)!=previous['document_sha256']:raise ValueError('restored_evaluation_document_changed')
        requests.request('restored-detail','GET',route)
        pid=next(row['id'] for row in adapted['predictions']['events'] if row['kind']=='network_operation')
        evidence=requests.request('restored-prediction','GET',route+'/evidence?'+urlencode({'event':pid}),maximum=QUERY_BYTES)
        if not evidence['evidence']['evidence']['verified_original_evidence']:raise ValueError('restored_raw_evidence_missing')
        refs=json.loads((original/'reference/references.json').read_text());identity=next(iter(refs))
        reference=requests.request('restored-reference','GET',route+'/evidence?'+urlencode({'event':identity,'reference':'true'}),maximum=QUERY_BYTES)['evidence']
        if reference['resolved_record']['fragment']['sha256']!=previous['reference_fragment_sha256']:
            raise ValueError('restored_reference_fragment_changed')
        report.update(status='passed',adapted_sha256=previous['adapted_sha256'],document_sha256=previous['document_sha256'],reference_fragment_sha256=previous['reference_fragment_sha256'])
        return report
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__,reason=str(error));raise
    finally:(root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
