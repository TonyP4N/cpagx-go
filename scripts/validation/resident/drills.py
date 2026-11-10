"""Isolated k3s resident fault drills. No task mutation without --execute.
Requires a succeeded immutable baseline run; clones only its stored payload.
"""
import argparse, datetime, json, os, pathlib, secrets, subprocess, time
ROOT = pathlib.Path(os.environ.get('CPAG_DRILL_OUTPUT', '.')).resolve()
NODE = os.environ.get('CPAG_LAB_NODE', 'cpag-resident-k3s')
K = ['docker','exec','-i',NODE,'kubectl','-n','cpag']

def run(cmd, data=None):
    p = subprocess.run(cmd, input=data, text=True, capture_output=True)
    if p.returncode: raise RuntimeError('command failed: '+p.stderr[-2000:])
    return p.stdout.strip()

def sql(query):
    return run(K+['exec','-i','deploy/cpag-postgres','--','psql','-qAtX','-v','ON_ERROR_STOP=1','-U','postgres','-d','cpag_app'],query)

def row(job):
    return json.loads(sql("SELECT row_to_json(t) FROM (SELECT j.id,j.state,j.attempt,j.worker,j.attempt_token,j.artifact_path,j.artifact_sha256,j.lease_until,a.container_id,a.location,a.exited_at,a.exit_receipt,a.resident_execution FROM m4_jobs j LEFT JOIN m4_job_attempts a ON a.job_id=j.id AND a.attempt=j.attempt WHERE j.id='"+job+"') t"))

def api(path, payload, coordinator=False):
    code = '''import json,urllib.request,urllib.error,sys
c=json.load(open('/etc/cpag/app.json'));v=json.load(sys.stdin)
r=urllib.request.Request('http://127.0.0.1:8094'+v['path'],data=json.dumps(v['body']).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+c['coordinator_token' if v['coord'] else 'worker_token']})
try:
 with urllib.request.urlopen(r,timeout=15) as p: print(p.status)
except urllib.error.HTTPError as e: print(e.code)
'''
    return int(run(K+['exec','-i','deploy/cpag-api','-c','api','--','python3','-c',code],json.dumps({'path':path,'body':payload,'coord':coordinator})))

def wait(job, predicate, timeout=180):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        current=row(job)
        if predicate(current): return current
        time.sleep(.3)
    raise TimeoutError('task condition timed out '+job+' '+current['state'])

def watcher(job):
    # Start the watcher before queueing. It freezes the exact compute group as
    # soon as the guardian has written its PID. No application source is edited.
    code='''import json,os,pathlib,signal,time,sys
p=pathlib.Path('/state/control/jobs/'+sys.argv[1]+'/attempt-1.worker/child.pid')
deadline=time.monotonic()+45
while time.monotonic()<deadline:
 if p.exists():
  try:
   pid=int(p.read_text());os.killpg(pid,signal.SIGSTOP)
   print(json.dumps({'child_pid':pid,'stopped':True}),flush=True);break
  except (ProcessLookupError,ValueError): pass
 time.sleep(.001)
else: raise RuntimeError('compute group not observed')
'''
    return subprocess.Popen(K+['exec','-i','deploy/cpag-worker','-c','worker','--','python3','-c',code,job],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

def clone(source,job):
    partition='rabbit-v3' if os.environ.get('CPAG_RABBIT_CANARY')=='1' else 'poll'
    inserted=sql("INSERT INTO m4_jobs(id,max_attempts,payload,dispatch_partition) SELECT '"+job+"',2,payload,'"+partition+"' FROM m4_jobs WHERE id='"+source+"' AND state='succeeded' RETURNING id")
    assert job in inserted, 'baseline not succeeded'

def frozen(source,job):
    process=watcher(job)
    time.sleep(.5)
    clone(source,job)
    out,err=process.communicate(timeout=50)
    assert process.returncode==0,err
    seen=json.loads(out)
    current=wait(job,lambda r:r['state']=='running' and bool(r['container_id']))
    assert current['attempt']==1
    return current,seen

def identity(r): return {'attempt':r['attempt'],'worker':r['worker'],'token':r['attempt_token']}

def snapshot(r):
    return {k:r[k] for k in ('id','state','attempt','container_id','location','lease_until','exited_at','artifact_path','artifact_sha256')}

def main():
    p=argparse.ArgumentParser();p.add_argument('--baseline',required=True);p.add_argument('--execute',action='store_true');args=p.parse_args()
    assert args.baseline.replace('-','').replace('_','').isalnum()
    if not args.execute:
        print('Prepared cancel and container SIGKILL drills; execution requires --execute and a succeeded baseline.');return
    ROOT.mkdir(parents=True,exist_ok=True)
    source=row(args.baseline);assert source['state']=='succeeded'
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')
    results={'scope':'isolated local k3s synthetic resident fault validation','baseline':args.baseline,'started_at':stamp}
    target=ROOT/('drill-results-'+stamp+'.json')
    def save(): target.write_text(json.dumps(results,indent=2))
    cancel=secrets.token_hex(16)
    print(json.dumps({'phase':'cancel_start','id':cancel}),flush=True)
    before,seen=frozen(args.baseline,cancel)
    assert api('/v1/jobs/'+cancel+'/cancel',{})==200
    assert api('/v1/jobs/'+cancel+'/heartbeat',{**identity(before),'lease_seconds':90})==409
    settled=wait(cancel,lambda r:r['state']=='cancelled',60)
    receipt=settled['exit_receipt'];assert receipt['resident']['group_exited']
    group=receipt['resident']['child_pid'];assert group==seen['child_pid']
    code='''import pathlib,json,sys
pg=int(sys.argv[1]);live=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  f=(p/'stat').read_text().rsplit(')',1)[1].split()
  if int(f[2])==pg and f[0]!='Z':live.append(int(p.name))
 except FileNotFoundError:pass
print(json.dumps(live))
'''
    live=json.loads(run(K+['exec','-i','deploy/cpag-worker','-c','worker','--','python3','-c',code,str(group)]));assert not live
    results['cancel']={'before':snapshot(before),'after':snapshot(settled),'group_exited':True,'live_group_members':live,'stale_heartbeat_status':409};save()
    crash=secrets.token_hex(16)
    print(json.dumps({'phase':'sigkill_start','id':crash}),flush=True)
    before,seen=frozen(args.baseline,crash)
    old=before['container_id'];assert old.startswith('containerd://')
    results['sigkill_pending']={'id':crash,'before':snapshot(before)};save()
    print(json.dumps({'phase':'sigkill_container','id':crash,'container_id':old}),flush=True)
    started=time.monotonic()
    run(['docker','exec',NODE,'ctr','-n','k8s.io','tasks','kill','--signal','SIGKILL','--all',old.removeprefix('containerd://')])
    # Natural lease expiration fences ownership. No database lease timestamps
    # or job state are modified by this drill.
    replacement=wait(crash,lambda r:r['attempt']>=2,180)
    stale_heartbeat=api('/v1/jobs/'+crash+'/heartbeat',{**identity(before),'lease_seconds':90});assert stale_heartbeat==409
    stale_fail=api('/v1/jobs/'+crash+'/fail',{**identity(before),'message':'stale-drill','retryable':True});assert stale_fail==409
    final=wait(crash,lambda r:r['state'] in ('succeeded','failed','cancelled'),180);assert final['state']=='succeeded',snapshot(final)
    assert final['attempt']==2 and final['container_id']!=old and final['artifact_path']
    stale_complete=api('/v1/jobs/'+crash+'/complete',{**identity(before),'manifest_sha256':final['artifact_sha256']});assert stale_complete in (400,409),stale_complete
    history=json.loads(sql("SELECT json_agg(t ORDER BY attempt) FROM (SELECT attempt,executor_kind,container_id,publication_state,exited_at,exit_receipt-'token' AS exit_receipt FROM m4_job_attempts WHERE job_id='"+crash+"') t"))
    assert len(history)==2 and sum(a['publication_state']=='published' for a in history)==1
    assert history[0]['exit_receipt']['resident']['version']=='resident-container-terminated-1'
    assert history[1]['exit_receipt']['resident']['version']=='resident-guardian-1'
    results['sigkill']={'before':snapshot(before),'after':snapshot(final),'attempts':history,'natural_expiry_and_retry_seconds':round(time.monotonic()-started,3),'stale_heartbeat_status':stale_heartbeat,'stale_fail_status':stale_fail,'stale_complete_status':stale_complete,'published_attempt_count':1};save()
    print(json.dumps({'result_file':str(target),'cancel_id':cancel,'sigkill_id':crash,'status':'passed'}))
if __name__=='__main__':main()
