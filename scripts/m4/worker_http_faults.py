#!/usr/bin/env python3
"""Synthetic-only live Go API/PostgreSQL fault checks. API must already be running."""
import hashlib
import atexit
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/worker'),str(ROOT/'services/analysis/src')]
from cpag_worker.worker import API,APIError,Worker,digest
from cpag_core.pipeline import run

children=[]
def cleanup():
    for child in children:
        if child.poll() is None:
            child.terminate()
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: child.kill();child.wait(timeout=3)
atexit.register(cleanup)

api=API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN'])
shared=Path(os.environ['CPAG_SHARED_ROOT']).resolve()
source=shared/'inputs';source.mkdir(exist_ok=True)
import shutil
payload={}
for role,src in [('network',ROOT/'tests/fixtures/synthetic/network.normalized.jsonl'),('process',ROOT/'tests/fixtures/synthetic/process.csv'),('profile',ROOT/'profiles/synthetic-demo.json')]:
    dest=source/('worker-fixture-'+src.name);shutil.copyfile(src,dest)
    payload[role]={'path':str(dest.relative_to(shared)),'sha256':digest(dest)}
baseline=shared/('baseline-'+uuid.uuid4().hex)
manifest=run(shared/payload['network']['path'],shared/payload['process']['path'],shared/payload['profile']['path'],baseline,synthetic=True)
payload['config_fingerprint']=manifest['config_fingerprint']
os.environ['PYTHONPATH']=os.pathsep.join([str(ROOT/'services/worker'),str(ROOT/'services/analysis/src')])

def enqueue(attempts=2):
    job='worker-'+uuid.uuid4().hex
    api.post('/v1/jobs',{'id':job,'max_attempts':attempts,'payload':payload})
    return job

def status(job):
    request=urllib.request.Request(api.url+'/v1/jobs/'+job,headers={'Authorization':'Bearer '+api.token})
    with urllib.request.urlopen(request,timeout=3) as response:return json.load(response)

def wait_for(predicate,seconds=8):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.05)
    raise AssertionError('timed out waiting for process/state')

def absent(pid):
    try:os.kill(pid,0);return False
    except ProcessLookupError:return True

def spawn_attempt(claim,timeout=30):
    # This override exists only in this local fault runner, never in HTTP payloads.
    helper=shared/'worker-test-hang.py'
    helper.write_text('import time\nprint("synthetic fault fixture",flush=True)\ntime.sleep(60)\n')
    driver=shared/('worker-driver-'+uuid.uuid4().hex+'.py')
    driver.write_text('import json,signal\nfrom cpag_worker.worker import API,Worker\nimport os\nw=Worker(API(os.environ["CPAG_API_URL"],os.environ["CPAG_WORKER_TOKEN"]),os.environ["CPAG_SHARED_ROOT"],'+repr(claim['worker'])+',lease=2,heartbeat=.2,timeout='+repr(timeout)+',command='+repr([sys.executable,str(helper)])+')\nsignal.signal(signal.SIGTERM,w.stop)\nw.attempt(json.loads('+repr(json.dumps(claim))+'))\n')
    child=subprocess.Popen([sys.executable,str(driver)])
    children.append(child)
    return child

def claim_for(worker):
    claim=api.post('/v1/claim',{'worker':worker,'lease_seconds':2})
    assert claim and claim.get('id'),claim
    return claim

def pid_for(claim):
    path=shared/(claim['output_dir']+'.worker')/'child.pid'
    wait_for(path.exists)
    return int(path.read_text())

def main():
    for bearer in (None,'wrong-bearer'):
        headers={} if bearer is None else {'Authorization':'Bearer '+bearer}
        request=urllib.request.Request(api.url+'/v1/claim',data=b'{}',headers={'Content-Type':'application/json',**headers},method='POST')
        try: urllib.request.urlopen(request,timeout=3)
        except urllib.error.HTTPError as error: assert error.code==401,error
        else: raise AssertionError('unauthenticated claim accepted')
    print('PASS live authorization: missing and wrong bearer rejected')

    job=enqueue(); assert api.post('/v1/jobs/'+job+'/cancel',{})['state']=='cancelled'
    assert status(job)['state']=='cancelled'
    print('PASS queued cancellation reports actual cancelled state')

    job=enqueue();claim=claim_for('success');assert claim['id']==job
    try:
        api.post('/v1/jobs/'+job+'/complete',{'attempt':claim['attempt'],'worker':claim['worker'],'token':'wrong-attempt-token','manifest_sha256':'0'*64})
    except APIError as error: assert error.status==409,error
    else: raise AssertionError('wrong attempt token accepted')
    print('PASS live wrong attempt token fenced before reading nonexistent manifest')
    assert Worker(api,shared,'success',lease=2,heartbeat=.2).attempt(claim)=='succeeded'
    assert status(job)['state']=='succeeded'
    for name in ('events.json','graph.json'):
        assert digest(shared/claim['output_dir']/name)==digest(baseline/name)
    completion={'attempt':claim['attempt'],'worker':claim['worker'],'token':claim['token'],'manifest_sha256':digest(shared/claim['output_dir']/'manifest.json')}
    api.post('/v1/jobs/'+job+'/complete',completion)
    artifact=shared/claim['output_dir']/'events.json'
    original=artifact.read_bytes()
    try:
        artifact.write_bytes(original+b'\nTAMPERED')
        try: api.post('/v1/jobs/'+job+'/complete',completion)
        except APIError as error: assert error.status==400,error
        else: raise AssertionError('tampering after success was not detected')
    finally: artifact.write_bytes(original)
    print('PASS live core success: events/graph match direct core; repeat completion idempotent; later tampering detected')

    job=enqueue(1);claim=claim_for('timeout');process=spawn_attempt(claim,.3)
    process.wait(timeout=8);assert status(job)['state']=='failed';assert absent(pid_for(claim))
    print('PASS live timeout: child exited, final attempt failed')

    job=enqueue();claim=claim_for('cancel');process=spawn_attempt(claim)
    pid=pid_for(claim);api.post('/v1/jobs/'+job+'/cancel',{})
    process.wait(timeout=8);assert absent(pid);assert status(job)['state']=='cancelled'
    print('PASS live cancellation: ACK only after child exit')

    job=enqueue();claim=claim_for('crash');process=spawn_attempt(claim)
    pid=pid_for(claim);process.kill();process.wait(timeout=3);wait_for(lambda:absent(pid))
    time.sleep(2.2)
    replacement=claim_for('recovered');assert replacement['id']==job and replacement['attempt']==2,replacement
    assert Worker(api,shared,'recovered',lease=2,heartbeat=.2).attempt(replacement)=='succeeded'
    assert status(job)['state']=='succeeded'
    try:
        api.post('/v1/jobs/'+job+'/complete',{'attempt':claim['attempt'],'worker':claim['worker'],'token':claim['token'],'manifest_sha256':'0'*64})
    except APIError as error:assert error.status==409,error
    else:raise AssertionError('stale completion accepted')
    print('PASS live SIGKILL: watchdog removed child; lease expiry recovered attempt 2; stale completion fenced')

    job=enqueue();claim=claim_for('corrupt')
    out=shared/claim['output_dir'];out.mkdir(parents=True)
    (out/'events.json').write_text('tampered')
    publication={'config_fingerprint':payload['config_fingerprint'],'inputs':{name:payload[name]['sha256'] for name in ('network','process','profile')},'artifacts':[{'path':'events.json','sha256':'0'*64,'size':8}]}
    (out/'manifest.json').write_text(json.dumps(publication))
    try:
        api.post('/v1/jobs/'+job+'/complete',{'attempt':claim['attempt'],'worker':claim['worker'],'token':claim['token'],'manifest_sha256':digest(out/'manifest.json')})
    except APIError as error:assert error.status in (400,409,422),error
    else:raise AssertionError('corrupted artifact accepted')
    api.post('/v1/jobs/'+job+'/fail',{'attempt':claim['attempt'],'worker':claim['worker'],'token':claim['token'],'message':'synthetic corruption fixture cleanup','retryable':False})
    print('PASS live completion rejects corrupted artifact')

if __name__=='__main__':
    try: main()
    finally: cleanup()
