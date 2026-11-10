"""Real PostgreSQL, Go API and Docker fault checks for opt-in dual-source jobs."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request
import uuid

from cpag_core.dual_source import strict_json
from cpag_core.dual_source_export import FILES, verify_task
from cpag_core.pipeline import fingerprint
from cpag_worker.isolated import DockerExecutor
from cpag_worker.worker import API, APIError, Worker, digest
from dual_source_fixtures import make_case

ROOT=Path(__file__).resolve().parents[3]
shared=Path(os.environ['CPAG_SHARED_ROOT'])
control=Path(os.environ['CPAG_CONTROL_ROOT'])
api=API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN'])
coordinator=API(api.url,os.environ['CPAG_COORDINATOR_TOKEN'])
evidence=Path(os.environ['CPAG_R14_EVIDENCE_DIR'])
containers=[]
restarted_api=None
ANALYSIS_MARKER='/output/run/.analysis-complete'
ANALYSIS_GATE_CODE="""from pathlib import Path
import time
import cpag_core.dual_source_export as export
real_run_dual = export.run_dual
def after_analysis(*args):
    result = real_run_dual(*args)
    Path('/output/run/.analysis-complete').write_text('analysis finished')
    time.sleep(60)
    return result
export.run_dual = after_analysis
export.main()
"""

for _ in range(100):
    try:
        api.post('/v1/claim',{'worker':'readiness','lease_seconds':2})
        break
    except OSError:time.sleep(.1)
else:raise RuntimeError('API did not become ready')

inputs=make_case(shared/'inputs')
payload={'kind':'dual-source','config_fingerprint':fingerprint(strict_json(inputs[2].read_text()))}
for name,path in zip(('network','process','profile'),inputs):
    payload[name]={'path':path.relative_to(shared).as_posix(),'sha256':digest(path)}


def state(job):
    request=urllib.request.Request(api.url+'/v1/jobs/'+job,
        headers={'Authorization':'Bearer '+api.token})
    with urllib.request.urlopen(request,timeout=5) as response:return json.load(response)


def driver(worker):
    return DockerExecutor(api,coordinator,shared,control,worker,
        timeout=40,heartbeat=.2,lease=30)


location=driver('locator').location()


def enqueue(label,*,lease=30):
    job='r14-dual-'+label+'-'+uuid.uuid4().hex
    api.post('/v1/jobs',{'id':job,'max_attempts':2,'payload':payload})
    return job


def claim(job,label,*,lease=30):
    item=api.post('/v1/claim',{'worker':'r14-'+label,'lease_seconds':lease,
                                'executor':'isolated-v2','location':location})
    assert item['id']==job,(job,item)
    item.update(executor='isolated-v2',location=location)
    return item


def remember(item):
    path=control/'jobs'/item['id']/('attempt-'+str(item['attempt'])+'.worker')/'execution.json'
    if path.exists():
        record=json.loads(path.read_text());containers.append(record['container_id'])


def wait_for_analysis(item):
    path=control/'jobs'/item['id']/('attempt-'+str(item['attempt'])+'.worker')/'execution.json'
    container=json.loads(path.read_text())['container_id']
    for _ in range(150):
        result=subprocess.run(['docker','exec',container,'test','-f',ANALYSIS_MARKER],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result.returncode==0:return
        time.sleep(.1)
    raise AssertionError('dual-source core did not finish analysis before fault injection')


def crash_claim(item,phase,*,after_core=False,command=None,exit_code=93):
    record=control/(item['id']+'-claim.json');record.write_text(json.dumps(item))
    code=f"""import json,os,subprocess,time
from pathlib import Path
from cpag_worker.worker import API
from cpag_worker.isolated import DockerExecutor
c=json.load(open({str(record)!r}))
def checkpoint(p):
    if p!={phase!r}:return
    if {after_core!r}:
        record=Path(os.environ['CPAG_CONTROL_ROOT'])/'jobs'/c['id']/('attempt-'+str(c['attempt'])+'.worker')/'execution.json'
        container=json.loads(record.read_text())['container_id']
        for _ in range(150):
            result=subprocess.run(['docker','exec',container,'test','-f',{ANALYSIS_MARKER!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if result.returncode==0:break
            time.sleep(.1)
        else:raise AssertionError('dual-source analysis marker missing')
    os._exit({exit_code})
w=DockerExecutor(API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN']),API(os.environ['CPAG_API_URL'],os.environ['CPAG_COORDINATOR_TOKEN']),os.environ['CPAG_SHARED_ROOT'],os.environ['CPAG_CONTROL_ROOT'],c['worker'],timeout=40,lease={2 if after_core else 30},command={command!r},checkpoint=checkpoint)
w.attempt(c)
"""
    result=subprocess.run([sys.executable,'-c',code],check=False)
    assert result.returncode==exit_code,result


def check_published(job,item):
    status=state(job)
    assert status['state']=='succeeded',status
    output=shared/item['output_dir']
    core=verify_task(output)
    assert core['run_id']==job and core['attempt_id']==item['attempt'],core
    assert {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()} == (
        FILES | {'manifest.json',digest(output/'manifest.json')+'.json'})
    assert status['artifact_sha256']==digest(output/'manifest.json'),status
    return status


try:
    job=enqueue('success');first=claim(job,'success');worker=driver(first['worker'])
    outcome=worker.attempt(first);remember(first)
    assert outcome=='succeeded',(outcome,state(job),[p.read_text() for p in control.rglob('failure.json')])
    success=check_published(job,first)
    identity={key:first[key] for key in ('worker','attempt','token')}
    api.post('/v1/jobs/'+job+'/complete',{**identity,'manifest_sha256':success['artifact_sha256']})
    assert worker.attempt(first)=='reconcile_required'
    assert check_published(job,first)['artifact_sha256']==success['artifact_sha256']
    try:api.post('/v1/jobs',{'id':job,'max_attempts':2,'payload':payload})
    except APIError as error:assert error.status in (400,409),error
    else:raise AssertionError('duplicate enqueue accepted')
    assert state(job)['state']=='succeeded' and len(state(job)['attempt_history'])==1
    print('PASS dual-source claim, 11-file nested handoff, reanalysis, immutable complete and idempotency',flush=True)
    print('PASS repeated enqueue rejected without replacing the accepted attempt',flush=True)

    job=enqueue('host-worker')
    host_claim=api.post('/v1/claim',{'worker':'r14-host','lease_seconds':30})
    assert host_claim['id']==job,host_claim
    host=Worker(api,shared,'r14-host',heartbeat=.2,lease=30,timeout=40)
    assert host.attempt(host_claim)=='succeeded',state(job)
    host_status=check_published(job,host_claim)
    print('PASS existing host Worker dispatches the same core and publishes the same 11 artifacts',flush=True)

    job=enqueue('queued-cancel')
    api.post('/v1/jobs/'+job+'/cancel',{})
    assert state(job)['state']=='cancelled',state(job)
    assert api.post('/v1/claim',{'worker':'queued-check','lease_seconds':2,
                                'executor':'isolated-v2','location':location}) in (None,{})
    print('PASS queued cancellation without publication',flush=True)

    job=enqueue('running-cancel');running=claim(job,'running-cancel')
    def cancel(phase):
        if phase=='during_execution':
            wait_for_analysis(running)
            api.post('/v1/jobs/'+job+'/cancel',{})
    worker=DockerExecutor(api,coordinator,shared,control,running['worker'],
        timeout=40,heartbeat=.2,lease=30,
        command=['python','-c',ANALYSIS_GATE_CODE],checkpoint=cancel)
    assert worker.attempt(running)=='cancelled',state(job)
    remember(running)
    assert state(job)['state']=='cancelled' and not (shared/running['output_dir']).exists()
    assert (control/'jobs'/job/'attempt-1.worker'/'exit.json').is_file()
    print('PASS running cancellation after actual dual analysis, before projection; container exit evidenced',flush=True)

    job=enqueue('lost-worker');lost=claim(job,'lost-worker',lease=2)
    crash_claim(lost,'during_execution',after_core=True,
                command=['python','-c',ANALYSIS_GATE_CODE],exit_code=92)
    remember(lost)
    time.sleep(2.4)
    recovered=driver('recovery').recover(job)
    assert any(row.get('id')==job and row.get('exited') for row in recovered),recovered
    retry=claim(job,'retry')
    assert retry['attempt']==2,retry
    worker=driver(retry['worker']);outcome=worker.attempt(retry);remember(retry)
    assert outcome=='succeeded',(outcome,state(job),[p.read_text() for p in control.rglob('failure.json')])
    retried=check_published(job,retry)
    assert not (shared/lost['output_dir']).exists()
    try:api.post('/v1/jobs/'+job+'/complete',{'worker':lost['worker'],'attempt':1,
                'token':lost['token'],'manifest_sha256':retried['artifact_sha256']})
    except APIError as error:assert error.status==409,error
    else:raise AssertionError('stale attempt completed')
    print('PASS killed worker after actual dual analysis, stale lease, attempt 2 and old-attempt fence',flush=True)

    job=enqueue('publish-crash');crash=claim(job,'publish-crash')
    crash_claim(crash,'after_publish')
    remember(crash)
    os.kill(int(os.environ['CPAG_API_PID']),signal.SIGKILL)
    restarted_api=subprocess.Popen([os.environ['CPAG_API_BINARY']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:state(job);break
        except OSError:time.sleep(.1)
    else:raise AssertionError('API did not restart')
    recovered=driver('recovery').recover(job)
    assert any(row.get('id')==job and row.get('publication')=='succeeded' for row in recovered),recovered
    published=check_published(job,crash)
    assert driver('recovery').recover(job) and check_published(job,crash)['artifact_sha256']==published['artifact_sha256']
    print('PASS API restart after durable handoff crash resumes one publication',flush=True)

    job=enqueue('nested-tamper');tampered=claim(job,'nested-tamper')
    crash_claim(tampered,'after_publish')
    remember(tampered)
    nested=shared/tampered['output_dir']/'dual/sources/process.csv'
    nested.chmod(0o644);nested.write_bytes(nested.read_bytes()+b'\n')
    recovered=driver('recovery').recover(job)
    assert any(row.get('id')==job and row.get('pending') for row in recovered),recovered
    assert state(job)['state']!='succeeded'
    api.post('/v1/jobs/'+job+'/cancel',{})
    driver('recovery').recover(job)
    api.post('/v1/jobs/'+job+'/ack-cancel',{key:tampered[key] for key in ('worker','attempt','token')})
    assert state(job)['state']=='cancelled'
    print('PASS changed nested source after handoff cannot be recovered as success',flush=True)

    (evidence/'dual-fault-status.json').write_text(json.dumps({
        'success':success,'host_worker':host_status,'retry':retried,'crash_recovery':published,
        'running_cancel':state(running['id']),'nested_tamper':state(tampered['id'])},indent=2)+'\n')
finally:
    if restarted_api and restarted_api.poll() is None:
        restarted_api.terminate();restarted_api.wait(timeout=5)
    for container in containers:
        subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
