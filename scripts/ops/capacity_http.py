"""Real disposable API/PostgreSQL/Docker capacity repair acceptance fixture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
from cpag_worker.worker import API, digest
from cpag_worker.isolated import DockerExecutor
from cpag_worker.capacity_rebuild import CapacityRebuilder, RebuildRefused
from cpag_core.pipeline import run

repo=Path(__file__).resolve().parents[2]
root=Path(os.environ['CPAG_SHARED_ROOT']);control=Path(os.environ['CPAG_CONTROL_ROOT'])
reports=Path(os.environ['CPAG_VALIDATION_DIR']);reports.mkdir(parents=True,exist_ok=True)
api=API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN']);coordinator=API(api.url,os.environ['CPAG_COORDINATOR_TOKEN'])
for _ in range(100):
    try:api.post('/v1/claim',{'worker':'capacity-ready','lease_seconds':2});break
    except OSError:time.sleep(.1)
else:raise RuntimeError('API not ready')
(root/'inputs').mkdir(exist_ok=True);payload={}
for role,source in [('network',repo/'tests/fixtures/synthetic/network.normalized.jsonl'),('process',repo/'tests/fixtures/synthetic/process.csv'),('profile',repo/'profiles/synthetic-demo.json')]:
    target=root/'inputs'/(role+source.suffix);shutil.copyfile(source,target);payload[role]={'path':str(target.relative_to(root)),'sha256':digest(target)}
payload['config_fingerprint']=run(root/payload['network']['path'],root/payload['process']['path'],root/payload['profile']['path'],root/'baseline',synthetic=True)['config_fingerprint']
worker=DockerExecutor(api,coordinator,root,control,'capacity-worker',image=os.environ.get('CPAG_CAPACITY_IMAGE','cpag-capacity:round7'),heartbeat=.2,lease=15,timeout=30,host_budget_bytes=64*1024*1024)
summary=[]
def status(job):
    req=urllib.request.Request(api.url+'/v1/jobs/'+job,headers={'Authorization':'Bearer '+api.token})
    with urllib.request.urlopen(req,timeout=3) as response:return json.load(response)
def enqueue(label):
    job='capacity-'+label+'-'+uuid.uuid4().hex
    api.post('/v1/jobs',{'id':job,'max_attempts':1,'payload':payload});return job

def repair(label):
    prefix=label+'-'+uuid.uuid4().hex
    preview=reports/(prefix+'-preview.json');applied=reports/(prefix+'-applied.json')
    command=[sys.executable,'-m','cpag_worker.capacity_rebuild','--report',str(preview)]
    subprocess.run(command,check=True)
    plan=json.loads(preview.read_text());assert plan['applicable'],plan['unknown_attempts']
    before=(control/'capacity.json').read_bytes() if (control/'capacity.json').exists() else None
    # Explicit confirmation is mandatory; a plain 'yes' must not mutate anything.
    wrong=subprocess.run([sys.executable,'-m','cpag_worker.capacity_rebuild','--report',str(reports/(prefix+'-wrong.json')),'--apply-plan',str(preview),'--confirm','yes'],capture_output=True,text=True)
    assert wrong.returncode!=0
    assert ((control/'capacity.json').read_bytes() if (control/'capacity.json').exists() else None)==before
    subprocess.run([sys.executable,'-m','cpag_worker.capacity_rebuild','--report',str(applied),'--apply-plan',str(preview),'--confirm',plan['plan_id']],check=True)
    result=json.loads(applied.read_text());backup=Path(result['backup']);assert (backup/'manifest.json').is_file()
    if before is not None:assert (backup/'capacity.original').read_bytes()==before
    else:assert not (backup/'capacity.original').exists()
    return {'label':label,'preview':str(preview),'applied':str(applied),'backup_verified':True}

first=enqueue('initial');assert worker.once()=='succeeded',status(first)
assert status(first)['state']=='succeeded'
print('PASS initial real container published with persistent API attempt exit proof',flush=True)
for label in ('corrupt','missing','oversized'):
    next_job=enqueue(label)
    if label=='corrupt':(control/'capacity.json').write_bytes(b'{broken capacity ledger')
    elif label=='missing':(control/'capacity.json').unlink()
    else:
        ledger=json.loads((control/'capacity.json').read_text());key=next(k for k in ledger['reservations'] if k!='__existing__');ledger['reservations'][key]=128*1024*1024;(control/'capacity.json').write_text(json.dumps(ledger))
    refused=False
    try:worker.capacity({'id':next_job,'attempt':1,'payload':payload})
    except (OSError,ValueError):refused=True
    assert refused,'broken/exhausted ledger did not reject admission gate'
    result=repair(label)
    assert worker.once()=='succeeded',status(next_job)
    assert status(next_job)['state']=='succeeded'
    result.update(new_task_succeeded=True,job=next_job);summary.append(result)
    print('PASS '+label+' ledger preview/diff + exact-byte backup + confirmed rebuild -> actual new Docker task succeeded',flush=True)

# Actual active controller owns owner.lock while its Docker computation runs.
active_job=enqueue('active');claim=api.post('/v1/claim',{'worker':'active-capacity','lease_seconds':15,'executor':'isolated-v2','location':worker.location()})
claim.update(executor='isolated-v2',location=worker.location());assert claim['id']==active_job
claim_file=root.parent/'active-claim.json';claim_file.write_text(json.dumps(claim));os.chmod(claim_file,0o600)
driver=root.parent/'active-driver.py';driver.write_text('import json,os,sys\nfrom cpag_worker.worker import API\nfrom cpag_worker.isolated import DockerExecutor\na=API(os.environ["CPAG_API_URL"],os.environ["CPAG_WORKER_TOKEN"])\nc=API(a.url,os.environ["CPAG_COORDINATOR_TOKEN"])\nv=json.load(open(sys.argv[1]))\nw=DockerExecutor(a,c,os.environ["CPAG_SHARED_ROOT"],os.environ["CPAG_CONTROL_ROOT"],v["worker"],image=os.environ.get("CPAG_CAPACITY_IMAGE","cpag-capacity:round7"),lease=15,heartbeat=.2,timeout=30,host_budget_bytes=67108864,command=["python","-c","import time;time.sleep(60)"])\nprint(w.attempt(v),flush=True)\n')
process=subprocess.Popen([sys.executable,str(driver),str(claim_file)])
try:
    execution=control/'jobs'/active_job/'attempt-1.worker'/'execution.json'
    for _ in range(100):
        if execution.exists():
            record=json.loads(execution.read_text());info=json.loads(subprocess.check_output(['docker','inspect',record['container_id']]))[0]
            if info['State']['Running']:break
        time.sleep(.1)
    else:raise AssertionError('active Docker attempt did not start')
    before=(control/'capacity.json').read_bytes()
    try:CapacityRebuilder(root,control,api.url,api.token).preview()
    except RebuildRefused as error:assert 'owner active' in str(error),error
    else:raise AssertionError('capacity rebuild ignored live owner')
    assert (control/'capacity.json').read_bytes()==before
    print('PASS actual running container/controller owner blocks rebuild with ledger untouched',flush=True)
    # Kill the controller, then lose both its local record and the ledger. The
    # still-running Docker execution must be found from the coordinator API.
    process.kill();process.wait(timeout=5)
    saved_ledger=(control/'capacity.json').read_bytes()
    held=root.parent/('retained-active-'+uuid.uuid4().hex)
    active_base=execution.parent
    shutil.move(str(active_base),str(held));(control/'capacity.json').unlink()
    try:
        tool=CapacityRebuilder(root,control,api.url,api.token,coordinator_token=coordinator.token)
        plan=tool.preview()
        assert active_job+':1' in plan['proposed_ledger']['reservations']
        assert active_job+':1' in plan['unknown_attempts'] and not plan['applicable']
        assert any(item['id']==active_job for item in plan['execution_discovery'])
        try:tool.apply(plan,plan['plan_id'])
        except RebuildRefused:pass
        else:raise AssertionError('database-only active attempt was silently omitted')
        assert not (control/'capacity.json').exists()
        (reports/'capacity-database-only-active.json').write_text(json.dumps(plan,indent=2)+'\n')
        print('PASS actual running Docker attempt with local record+ledger lost is discovered via coordinator and blocks unsafe rebuild',flush=True)
    finally:
        if active_base.exists():shutil.rmtree(active_base)
        shutil.move(str(held),str(active_base));(control/'capacity.json').write_bytes(saved_ledger)
    api.post('/v1/jobs/'+active_job+'/cancel',{})
    worker.recover(active_job)
    api.post('/v1/jobs/'+active_job+'/ack-cancel',{k:claim[k] for k in ('attempt','worker','token')})
    assert status(active_job)['state']=='cancelled',status(active_job)
    print('PASS retained evidence restored; actual orphan removed and API cancellation confirms exit',flush=True)
finally:
    if process.poll() is None:process.terminate();process.wait(timeout=10)
    if 'record' in locals():subprocess.run(['docker','rm','-f',record['container_id']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    claim_file.unlink(missing_ok=True);driver.unlink(missing_ok=True)
image=os.environ.get('CPAG_CAPACITY_IMAGE','cpag-capacity:round7')
image_id=subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],text=True).strip()
(reports/'capacity-live-summary.json').write_text(json.dumps({'compute_image':image,'compute_image_id':image_id,'cases':summary},indent=2)+'\n')
