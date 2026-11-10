#!/usr/bin/env python3
"""One replay/evaluation and real transport/role checks on the retained Linux dataset.

The offline run is supplied from the one ordinary-browser submission. No offline
run is resubmitted. Large receive-only fixtures never enter an analysis call.
"""
import argparse
import csv
from datetime import datetime,timedelta,timezone
import hashlib
from http.cookiejar import CookieJar
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode,urlsplit
from urllib.request import build_opener,ProxyHandler,HTTPCookieProcessor,HTTPSHandler,Request

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'services/analysis/src'),str(REPO/'scripts/validation')]
from cpag_core import evaluation_bundle as eb
from cpag_core.evaluation import digest
from cpag_core.evaluation_details import evaluate_detailed,V2_MATCHING_VERSION,V2_DETAILS_VERSION
from cpag_core.reference_inventory import build_inventory,LOCATOR_VERSION,LOCATED_STATUS
from round19_core_oracle import check_raw_evidence

class Client:
 def __init__(self,state):
  self.base=state['url'];self.context=ssl.create_default_context(cafile=state['caFile']);self.opener=build_opener(ProxyHandler({}),HTTPCookieProcessor(CookieJar()),HTTPSHandler(context=self.context));self.last_raw=None
 def call(self,method,path,body=None,headers=None,timeout=180):
  headers=dict(headers or {})
  if method not in ('GET','HEAD'):headers.setdefault('Origin',self.base)
  if isinstance(body,(dict,list)):body=json.dumps(body,separators=(',',':')).encode();headers.setdefault('Content-Type','application/json')
  request=Request(self.base+path,method=method,data=body,headers=headers)
  try:response=self.opener.open(request,timeout=timeout)
  except HTTPError as error:response=error
  with response:
   raw=response.read();self.last_raw=raw
   try:value=json.loads(raw)
   except ValueError:value=raw
   return response.status,value
 def expect(self,method,path,body=None,code=200,**kw):
  actual,value=self.call(method,path,body,**kw)
  if actual!=code:raise RuntimeError(f'{method} {path} returned {actual}: '+str(value)[:600])
  return value
 def login(self,user,password):return self.expect('POST','/api/v3/session',{'username':user,'password':password})
 def settled(self,path,seconds=120):
  end=time.monotonic()+seconds;statuses=[]
  while time.monotonic()<end:
   code,value=self.call('GET',path);statuses.append(code)
   if code==200:return value,statuses
   if code!=409 or value.get('error',{}).get('code') not in ('verification_pending','preparation_pending','evaluation_preparation_pending'):raise RuntimeError(str((path,code,value))[:600])
   time.sleep(.25)
  raise RuntimeError('bounded verification timeout')

def one_evaluation(projection,root):
 binding=projection['binding'];batch=binding['batch'];sample=binding['sample_sha256'];rows=[('manual-operation','network_operation','["192.0.2.2",44818]','2026-01-01T00:00:10Z'),('manual-transition','process_change','["synthetic-pump","pump_state"]','2026-01-01T00:00:14Z')]
 split={'schema_version':'1.0.0','synthetic':True,'rule_windows_seconds':{'association':5},'isolation_seconds':5,'blocks':[{'partition':'calibration','batch':batch,'start':'2025-12-01T00:00:00Z','end':'2025-12-01T00:01:00Z','sample_sha256':['a'*64],'normal':False},{'partition':'holdout','batch':batch,'start':'2026-01-01T00:00:00Z','end':'2026-01-01T00:01:00Z','sample_sha256':[sample],'normal':False}]}
 originals=root/'reference-originals';originals.mkdir();stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\r\n');writer.writerow(['event_id','kind','asset','time']);writer.writerows(rows);raw=stream.getvalue().encode();name='handwritten-shifted-reference.csv';(originals/name).write_bytes(raw);sha=hashlib.sha256(raw).hexdigest();inventory=build_inventory(originals,{name:sha})
 now=datetime.now(timezone.utc);opening=now+timedelta(seconds=2);registration={'schema_version':'1.0.0','synthetic':True,'registered_at':now.isoformat(),'holdout_opened_at':opening.isoformat(),'input_fingerprint':binding['input_fingerprint'],'config_fingerprint':binding['config_fingerprint'],'split_sha256':digest(split),'tolerance_seconds':0,'thresholds':{}}
 frozen={'version':eb.V3_VERSION,'observed_frozen_at':datetime.now(timezone.utc).isoformat(),'registration_sha256':digest(registration),'split_sha256':digest(split),'adapted_sha256':digest(projection),'binding_sha256':digest(binding),'matching':V2_MATCHING_VERSION,'details_version':V2_DETAILS_VERSION,'custody':eb.CUSTODY,'reference_inventory_sha256':digest(inventory),'reference_locator_version':LOCATOR_VERSION};eb.validate_freeze(frozen,registration)
 common={'registration.json':registration,'split.json':split,'adapted.json':projection,'freeze.json':frozen,'reference_inventory.json':inventory};eb.publish(root/'frozen',common);assert datetime.now(timezone.utc)<opening;time.sleep(max(0,(opening-datetime.now(timezone.utc)).total_seconds())+.01)
 labels={'schema_version':'1.0.0','synthetic':True,'origin':'independent','source_ref':'handwritten before freeze','review_ref':'synthetic deployment acceptance','annotation_version':'r21-shifted-1','disputed_intervals':[],'events':[{'id':identity,'kind':kind,'asset':asset,'time':at,'batch':batch,'sample_sha256':sample} for identity,kind,asset,at in rows]}
 references={identity:{'source_ref':'handwritten shifted reference','sha256':sha,'locator':{'version':LOCATOR_VERSION,'file_sha256':sha,'record_number':index+1,'columns':['event_id','kind','asset','time']}} for index,(identity,*_) in enumerate(rows)}
 result=evaluate_detailed(projection['predictions'],labels,split,registration,matching_version=V2_MATCHING_VERSION);assert tuple(result['record']['metrics'][key] for key in ('tp','fp','fn'))==(1,1,1)
 result['bundle_binding']={'version':eb.V3_VERSION,'freeze_sha256':digest(frozen),'artifact_binding_sha256':digest(binding),'annotations_sha256':digest(labels),'references_sha256':digest(references),'observed_opened_at':datetime.now(timezone.utc).isoformat(),'reference_status':LOCATED_STATUS,'reference_inventory_sha256':digest(inventory),'reference_locator_version':LOCATOR_VERSION}
 values=dict(common,**{'annotations.json':labels,'references.json':references,'result.json':result});document=dict(values,**{'manifest.json':{'version':eb.V3_VERSION,'files':{name:digest(value) for name,value in values.items()}}});eb.publish(root/'evaluation',document);return document

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,required=True);p.add_argument('--dataset',required=True);p.add_argument('--offline-run',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();state=json.loads(a.state.read_text());work=a.output.resolve();work.mkdir(parents=True,exist_ok=False,mode=0o700);client=Client(state);client.login(state['username'],state['password']);report={'status':'running','scope':'one retained small synthetic Linux deployment workflow; not capacity or industrial acceptance','dataset_id':a.dataset,'offline_run':a.offline_run,'checks':{}}
 def save(): (work/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  offline=client.expect('GET','/api/v3/runs/'+a.offline_run)['run'];assert offline['state']=='succeeded' and offline['attempt']==1
  profile=json.loads(Path(state['replay_profile']).read_text());cfg=client.expect('POST',f'/api/v3/datasets/{a.dataset}/configs',{'kind':'dual','document':profile},code=201)['config']['id'];preflight=client.expect('GET',f'/api/v3/datasets/{a.dataset}/preflights')['preflights'][0]['id']
  replay=client.expect('POST','/api/v3/runs',{'dataset_id':a.dataset,'config_version_id':cfg,'preflight_id':preflight,'mode':'dual_source_replay'},code=201)['run']['id'];report['replay_run']=replay;save();deadline=time.monotonic()+180
  while time.monotonic()<deadline:
   current=client.expect('GET','/api/v3/runs/'+replay)['run']
   if current['state'] in ('succeeded','failed','cancelled'):break
   time.sleep(.2)
  assert current['state']=='succeeded' and current['attempt']==1,current
  result,polls=client.settled(f'/api/v3/runs/{replay}/result');assert all(result['manifest']['counts'][key]==1 for key in ('operations','changes','candidates'))
  operation=client.expect('GET',f'/api/v3/runs/{replay}/shared-query?'+urlencode({'action':'get','logical_root':'analysis.json','path':json.dumps(['operations',0,'operation_id'])}))
  evidence=client.expect('GET',f'/api/v3/runs/{replay}/evidence?'+urlencode({'operation':operation}));assert len(evidence['verified_original_evidence'])==4
  fixture=Path(state['fixture_dir']);audit=check_raw_evidence(evidence['verified_original_evidence'],[fixture/'network.pcap',fixture/'response.pcap'],fixture/'process.csv')
  zero=client.expect('GET',f'/api/v3/runs/{replay}/shared-query?'+urlencode({'action':'snapshot','snapshot':0,'path':json.dumps(['analysis','operations'])}));assert zero==[]
  report['checks']['replay_attempt1_complete_four_originals_and_no_future_prefix']={'status':'passed','counts':result['manifest']['counts'],'query_statuses':polls,'independent_raw_bytes':audit['all_returned_references_match_independent_originals']};save()
  projection,polls=client.settled(f'/api/v3/runs/{replay}/evaluation-input?projection=dual');document=one_evaluation(projection,work);body=json.dumps(document,separators=(',',':')).encode();limit=128*1024*1024;assert len(body)<limit;body+=b' '*(limit-len(body))
  evaluation=client.expect('POST',f'/api/v3/runs/{replay}/evaluations',body,headers={'Content-Type':'application/json'},code=201)['evaluation']['id'];del body;report['evaluation_id']=evaluation
  detail=client.expect('GET',f'/api/v3/runs/{replay}/evaluations/{evaluation}');assert detail['result']==document['result.json']
  fp=detail['result']['details']['false_positives'][0]['event_id'];predicted=client.expect('GET',f'/api/v3/runs/{replay}/evaluations/{evaluation}/evidence?'+urlencode({'event':fp}))['evidence'];assert predicted['evidence']['verified_original_evidence']
  reference=client.expect('GET',f'/api/v3/runs/{replay}/evaluations/{evaluation}/evidence?event=manual-transition&reference=true')['evidence'];assert reference['status']==LOCATED_STATUS and reference['resolved_record']['values']['time']=='2026-01-01T00:00:14Z'
  downloaded=client.expect('GET',f'/api/v3/runs/{replay}/evaluations/{evaluation}/download');assert downloaded==document
  report['checks']['valid_128MiB_evaluation_import_and_FP_FN_originals']={'status':'passed','wire_bytes':limit,'evaluation_id':evaluation,'tp':1,'fp':1,'fn':1,'reference_record':reference['resolved_record']['record_number']};save()
  private_roles={}
  for role in ['viewer','analyst']:
   username='r21-'+role+'-'+secrets.token_hex(3);password=secrets.token_urlsafe(24);user=client.expect('POST','/api/v3/users',{'username':username,'password':password,'role':role},code=201)['user'];account=Client(state);account.login(username,password)
   code,_=account.call('GET',f'/api/v3/runs/{replay}/artifacts/shared/shared.sqlite3/download');assert code==404
   client.expect('POST',f'/api/v3/datasets/{a.dataset}/acl',{'user_id':user['id'],'access':role})
   value,_=account.settled(f'/api/v3/runs/{replay}/result');assert value['manifest']['run_id']==replay
   if role=='viewer':account.expect('POST',f'/api/v3/datasets/{a.dataset}/configs',{'kind':'dual','document':profile},code=403);account.expect('GET','/api/v3/health/operations',code=403)
   else:account.expect('POST',f'/api/v3/datasets/{a.dataset}/configs',{'kind':'dual','document':profile},code=201)
   rows=account.expect('GET',f'/api/v3/runs/{replay}/artifacts')['artifacts'];artifact=next(x for x in rows if x['path']=='shared/shared.sqlite3');raw=account.expect('GET',f'/api/v3/runs/{replay}/artifacts/shared/shared.sqlite3/download');assert hashlib.sha256(raw).hexdigest()==artifact['sha256']
   private_roles[role]={'username':username,'password':password};report['checks'][role+'_role_and_download']={'status':'passed','without_acl':404,'artifact_sha256':artifact['sha256']}
  anonymous=Client(state);anonymous.expect('GET',f'/api/v3/runs/{replay}/artifacts/shared/shared.sqlite3/download',code=401);operations=client.expect('GET','/api/v3/health/operations');assert operations['worker_fresh']>=1
  report['checks']['anonymous_and_live_worker_observations']={'status':'passed','anonymous_download':401,'worker_fresh':operations['worker_fresh']}
  with open(work/'roles-private.json','x',opener=lambda p,f:os.open(p,f,0o600)) as stream:json.dump(private_roles,stream,indent=2)
  report['status']='passed';save();print(json.dumps(report))
 except BaseException as error:report.update(status='failed',failure=str(error));save();raise
if __name__=='__main__':main()
