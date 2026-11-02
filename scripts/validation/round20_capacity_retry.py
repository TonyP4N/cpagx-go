#!/usr/bin/env python3
"""One formal-service transient durable-capacity retry probe; no mocked helpers.

A tiny newly submitted compute is temporarily paused to hold its actual durable
slot. An existing completed run must stay pending then become queryable after
release in the same Go instance, with unchanged old bytes/attempt. No old run is
recomputed. All interference is restricted to this probe's new job.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
import round19_formal_service_acceptance as formal
r=formal.r

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 s=json.loads(a.state.read_text());w=a.output.resolve();w.mkdir(mode=0o700,parents=True,exist_ok=False)
 c=formal.MeasuredClient(s['url']);c.expect('POST','/api/v3/session',{'username':s['username'],'password':s['password']})
 old=s['ui_cases']['out_of_order']['run_id'];before=c.expect('GET','/api/v3/runs/'+old)['run'];base=Path(s['source_root'])/'jobs'/old/'attempt-1'
 hashes={str(x.relative_to(base)):formal.sha(x) for x in sorted((base/'sources').rglob('*')) if x.is_file()}
 ds=c.expect('GET','/api/v3/runs/'+s['offline_run_id'])['run']['dataset_id'];detail=c.expect('GET','/api/v3/datasets/'+ds)
 configs=[x for x in detail['configs'] if x['kind']=='dual'];preflight=c.expect('GET','/api/v3/datasets/'+ds+'/preflights')['preflights'][0]
 run=c.expect('POST','/api/v3/runs',{'dataset_id':ds,'config_version_id':configs[0]['id'],'preflight_id':preflight['id'],'mode':'dual_source'},code=201)['run']['id']
 report={'status':'running','version':'real-durable-busy-same-instance-retry-1','probe_new_run':run,'unchanged_history_run':old,'checks':{},'polls':[],'app_pid':s['app_pid']};paused=None
 def save():formal.write(w/'report.json',report)
 save()
 try:
  deadline=time.monotonic()+45
  while time.monotonic()<deadline:
   rows=subprocess.check_output(['docker','ps','-q','--filter','label=cpag.job='+run],text=True).split()
   for identity in rows:
    data=json.loads(subprocess.check_output(['docker','inspect',identity],text=True))[0]
    if data['State']['Running'] and data['Config']['Labels'].get('cpag.role')!='dag6-source-verifier':
     result=subprocess.run(['docker','pause',identity],capture_output=True,text=True)
     if result.returncode==0:paused=identity;report['paused_new_compute']={'id':identity,'labels':data['Config']['Labels'],'image':data['Image']};break
   if paused:break
   status=c.expect('GET','/api/v3/runs/'+run)['run']
   if status['state'] in ('succeeded','failed','cancelled'):raise RuntimeError('probe_compute_exited_before_slot_hold')
   time.sleep(.03)
  if not paused:raise RuntimeError('new_compute_container_not_observed')
  status=c.expect('GET','/api/v3/runs/'+run)['run'];assert status['state']=='running' and status['attempt']==1
  query='/api/v3/runs/'+old+'/result'
  for _ in range(3):
   code,value=c.request('GET',query,timeout=12);report['polls'].append({'phase':'slot_held','status':code,'code':value.get('error',{}).get('code')});save()
   assert code==409 and value['error']['code']=='verification_pending'
   time.sleep(1.1)
  subprocess.run(['docker','unpause',paused],check=True,stdout=subprocess.DEVNULL);paused=None
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   code,value=c.request('GET',query,timeout=12);report['polls'].append({'phase':'slot_released','status':code,'code':value.get('error',{}).get('code')});save()
   if code==200:break
   assert code==409 and value['error']['code']=='verification_pending';time.sleep(.5)
  else:raise RuntimeError('history_did_not_become_queryable_after_slot_release')
  after=c.expect('GET','/api/v3/runs/'+old)['run'];new=r.status_until(c,run,seconds=120)
  current=json.loads(a.state.read_text());assert current['app_pid']==s['app_pid'];assert before==after
  assert hashes=={str(x.relative_to(base)):formal.sha(x) for x in sorted((base/'sources').rglob('*')) if x.is_file()}
  assert new['state']=='succeeded' and new['attempt']==1
  report['checks']={'actual_new_compute_held_durable_slot':True,'busy_reads_pending_not_permanent_error':True,'same_instance_auto_recheck_200_after_release':True,'historical_run_and_attempt_unchanged':True,'old_source_bytes_unchanged':True,'new_probe_attempt1_succeeded':True,'no_historical_recomputation':True};report['status']='passed';save();print(json.dumps(report))
 except BaseException as error:
  report.update(status='failed',reason=str(error));save();raise
 finally:
  if paused:subprocess.run(['docker','unpause',paused],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if __name__=='__main__':main()
