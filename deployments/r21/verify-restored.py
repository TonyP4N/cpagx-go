#!/usr/bin/env python3
"""Read the restored target, then separately submit one analyst-owned small run.

Private credential/session files are inputs only; reports never contain passwords
or cookie values. The analyst phase must follow the restored read/browser checks.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time
from urllib.parse import urlencode

spec=importlib.util.spec_from_file_location('r21_business',Path(__file__).with_name('verify-business.py'))
business_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(business_module)
Client=business_module.Client;check_raw_evidence=business_module.check_raw_evidence


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--state',type=Path,required=True)
 p.add_argument('--source-session',type=Path,required=True)
 p.add_argument('--business-report',type=Path,required=True)
 p.add_argument('--roles',type=Path,required=True)
 p.add_argument('--phase',choices=['read','analyst'],required=True)
 p.add_argument('--config-id',required=True)
 p.add_argument('--preflight-id',required=True)
 p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();state=json.loads(a.state.read_text());source=json.loads(a.source_session.read_text());business=json.loads(a.business_report.read_text());roles=json.loads(a.roles.read_text())
 assert source['source_status']==200 and source['cookie']
 a.output.parent.mkdir(parents=True,exist_ok=True)
 report={'status':'running','phase':a.phase,'scope':'restored independent Linux target; same retained synthetic dataset','dataset_id':business['dataset_id'],'checks':{}}
 def save():
  with open(a.output,'w',opener=lambda path,flags:os.open(path,flags,0o600)) as stream:json.dump(report,stream,indent=2)
 try:
  if a.phase=='read':
   old=Client(state);old.expect('GET','/api/v3/session',headers={'Cookie':source['cookie']},code=401)
   report['checks']['real_pre_backup_session_invalidated']={'status':'passed','source_status':200,'restored_status':401};save()
   admin=Client(state);admin.login(state['username'],state['password'])
   for identity in [business['offline_run'],business['replay_run']]:
    run=admin.expect('GET','/api/v3/runs/'+identity)['run'];assert run['state']=='succeeded' and run['attempt']==1
    result,polls=admin.settled('/api/v3/runs/'+identity+'/result',seconds=180)
    assert all(result['manifest']['counts'][key]==1 for key in ('operations','changes','candidates'))
    report['checks']['retained_run_'+identity]={'status':'passed','attempt':1,'verification_statuses':polls,'counts':result['manifest']['counts']};save()
   run=business['replay_run'];base='/api/v3/runs/'+run
   operation=admin.expect('GET',base+'/shared-query?'+urlencode({'action':'get','logical_root':'analysis.json','path':json.dumps(['operations',0,'operation_id'])}))
   evidence=admin.expect('GET',base+'/evidence?'+urlencode({'operation':operation}));fixture=Path(state['fixture_dir'])
   raw=check_raw_evidence(evidence['verified_original_evidence'],[fixture/'network.pcap',fixture/'response.pcap'],fixture/'process.csv');assert len(evidence['verified_original_evidence'])==4 and raw['all_returned_references_match_independent_originals']
   zero=admin.expect('GET',base+'/shared-query?'+urlencode({'action':'snapshot','snapshot':0,'path':json.dumps(['analysis','operations'])}));assert zero==[]
   ev=base+'/evaluations/'+business['evaluation_id'];detail=admin.expect('GET',ev);metrics=detail['result']['record']['metrics'];assert tuple(metrics[k] for k in ('tp','fp','fn'))==(1,1,1)
   fp=detail['result']['details']['false_positives'][0]['event_id'];pred=admin.expect('GET',ev+'/evidence?'+urlencode({'event':fp}))['evidence'];assert pred['evidence']['verified_original_evidence']
   ref=admin.expect('GET',ev+'/evidence?event=manual-transition&reference=true')['evidence'];assert ref['resolved_record']['record_number']==2 and ref['resolved_record']['values']['time']=='2026-01-01T00:00:14Z'
   report['checks']['replay_four_originals_no_future_prefix_and_FP_FN']={'status':'passed','verified_originals':4,'tp':1,'fp':1,'fn':1,'reference_record':2};save()
   for role in ['viewer','analyst']:
    account=Client(state);session=account.login(**{'user':roles[role]['username'],'password':roles[role]['password']});assert session['user']['role']==role
    artifact=next(x for x in account.expect('GET',base+'/artifacts')['artifacts'] if x['path']=='shared/shared.sqlite3')
    payload=account.expect('GET',base+'/artifacts/shared/shared.sqlite3/download');sha=hashlib.sha256(payload).hexdigest();assert sha==artifact['sha256']==business['checks'][role+'_role_and_download']['artifact_sha256']
    account.expect('GET','/api/v3/health/operations',code=403)
    if role=='viewer':account.expect('POST',f"/api/v3/datasets/{business['dataset_id']}/configs",{},code=403)
    report['checks'][role+'_restored_acl_download']={'status':'passed','role':role,'artifact_sha256':sha}
   Client(state).expect('GET',base+'/artifacts/shared/shared.sqlite3/download',code=401)
  else:
   analyst=Client(state);session=analyst.login(roles['analyst']['username'],roles['analyst']['password']);assert session['user']['role']=='analyst'
   created=analyst.expect('POST','/api/v3/runs',{'dataset_id':business['dataset_id'],'config_version_id':a.config_id,'preflight_id':a.preflight_id,'mode':'dual_source'},code=201)['run']
   identity=created['id'];report.update(analyst_user_id=session['user']['id'],analyst_role='analyst',submission_status=201,run_id=identity,config_id=a.config_id,preflight_id=a.preflight_id);save()
   end=time.monotonic()+180
   while time.monotonic()<end:
    current=analyst.expect('GET','/api/v3/runs/'+identity)['run']
    if current['state'] in ('succeeded','failed','cancelled'):break
    time.sleep(.25)
   assert current['state']=='succeeded' and current['attempt']==1,current
   result,polls=analyst.settled('/api/v3/runs/'+identity+'/result');assert all(result['manifest']['counts'][key]==1 for key in ('operations','changes','candidates'))
   report['checks']['analyst_actual_submit_and_worker_attempt1']={'status':'passed','state':current['state'],'attempt':current['attempt'],'attempt_history':current['attempt_history'],'verification_statuses':polls}
   admin=Client(state);admin.login(state['username'],state['password'])
   event=next(row for row in admin.expect('GET','/api/v3/audit')['events'] if row['job_id']==identity and row['action']=='run_create')
   assert event['outcome']=='ok' and event['user_id']==session['user']['id']
   report['checks']['persisted_analyst_submission_audit']={'status':'passed','event_id':event['id'],'user_id':event['user_id'],'action':event['action'],'outcome':event['outcome']}
  report['status']='passed';save();print(json.dumps(report))
 except BaseException as error:
  report.update(status='failed',failure=str(error));save();raise


if __name__=='__main__':main()
