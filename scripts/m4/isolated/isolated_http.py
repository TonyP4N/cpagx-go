"""Actual Docker + Go API + PostgreSQL synthetic integration."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
from cpag_worker.worker import API,APIError,digest
from cpag_worker.isolated import DockerExecutor
from cpag_core.pipeline import run

ROOT=Path(__file__).resolve().parents[3]
VALIDATION=Path(os.environ.get('CPAG_VALIDATION_DIR',ROOT/'docs/refactor/validation-round5'));VALIDATION.mkdir(parents=True,exist_ok=True)
shared=Path(os.environ['CPAG_SHARED_ROOT']);control=Path(os.environ['CPAG_CONTROL_ROOT'])
api=API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN'])
coordinator=API(api.url,os.environ['CPAG_COORDINATOR_TOKEN'])
for _ in range(60):
    try:api.post('/v1/claim',{'worker':'readiness','lease_seconds':2});break
    except OSError:time.sleep(.1)
source=shared/'inputs';source.mkdir(exist_ok=True)
payload={}
for role,src in [('network',ROOT/'tests/fixtures/synthetic/network.normalized.jsonl'),('process',ROOT/'tests/fixtures/synthetic/process.csv'),('profile',ROOT/'profiles/synthetic-demo.json')]:
    dest=source/(role+src.suffix);shutil.copyfile(src,dest);payload[role]={'path':str(dest.relative_to(shared)),'sha256':digest(dest)}
payload['config_fingerprint']=run(shared/payload['network']['path'],shared/payload['process']['path'],shared/payload['profile']['path'],shared/'baseline',synthetic=True)['config_fingerprint']
containers=[]
api_processes=[]
def state(job):
    request=urllib.request.Request(api.url+'/v1/jobs/'+job,headers={'Authorization':'Bearer '+api.token})
    with urllib.request.urlopen(request) as response:return json.load(response)
def enqueue(label,body=None):
    job='isolated-'+label+'-'+uuid.uuid4().hex
    api.post('/v1/jobs',{'id':job,'max_attempts':2,'payload':body or payload})
    location='docker:'+subprocess.check_output(['docker','info','--format','{{.ID}}'],text=True).strip()+':'+DockerExecutor(api,coordinator,shared,control,'scope').scope
    claim=api.post('/v1/claim',{'worker':'host-'+label,'lease_seconds':30,'executor':'isolated-v2','location':location})
    claim.update(executor='isolated-v2',location=location)
    assert claim['id']==job,claim
    return job,claim
def executor(claim,**options):return DockerExecutor(api,coordinator,shared,control,claim['worker'],timeout=30,heartbeat=.2,lease=30,**options)
def remember(claim):
    path=control/'jobs'/claim['id']/('attempt-'+str(claim['attempt'])+'.worker')/'execution.json'
    if path.exists():record=json.loads(path.read_text())
    else:
        ids=subprocess.check_output(['docker','ps','-a','--no-trunc','--filter','label=cpag.job='+claim['id'],'--format','{{.ID}}'],text=True).splitlines()
        assert len(ids)==1,ids
        record={**{k:claim[k] for k in ('id','attempt','worker','token')},'container_id':ids[0],'location':claim['location']}
    containers.append(record['container_id']);return record
try:
    from cpag_core.packet_job import run as packet_run
    packet_source=source/'capture.pcap';shutil.copyfile(ROOT/'docs/refactor/validation-round4/protocol-synthetic.pcap',packet_source)
    packet_profile=source/'packet-profile.json';packet_profile.write_text(json.dumps({'synthetic':True,'adapter':'synthetic-packet-1'}))
    packet_payload={'kind':'packet','network':{'path':str(packet_source.relative_to(shared)),'sha256':digest(packet_source)},'process':payload['process'],'profile':{'path':str(packet_profile.relative_to(shared)),'sha256':digest(packet_profile)}}
    packet_payload['config_fingerprint']=packet_run(packet_source,shared/payload['process']['path'],packet_profile,shared/'packet-baseline',synthetic=True)['config_fingerprint']
    job,claim=enqueue('packet',packet_payload);worker=executor(claim)
    assert worker.attempt(claim)=='succeeded',(state(job),[p.read_text() for p in control.rglob('failure.json')]);remember(claim)
    assert (shared/claim['output_dir']/'packet_observations.json').is_file()
    print('PASS packet task actual container -> six-artifact durable publication -> API complete',flush=True)
    forged="import json,hashlib;from pathlib import Path;from cpag_core.packet_job import main;main();p=Path('/output/run/packet_observations.json');v=json.loads(p.read_text());v['observations'][0]['operation']='write_attribute';p.write_text(json.dumps(v));m=Path('/output/run/run_manifest.json');v=json.loads(m.read_text());e=next(e for e in v['artifacts'] if e['path']=='packet_observations.json');e['sha256']=hashlib.sha256(p.read_bytes()).hexdigest();e['size_bytes']=p.stat().st_size;m.write_text(json.dumps(v))"
    job,claim=enqueue('forged-packet',packet_payload);worker=executor(claim,command=['python','-c',forged])
    assert worker.attempt(claim)=='failed';remember(claim)
    assert not (shared/claim['output_dir']).exists() and state(job)['state']!='succeeded'
    assert 'original capture decoding' in (control/'jobs'/job/'attempt-1.worker'/'failure.json').read_text()
    api.post('/v1/jobs/'+job+'/cancel',{})
    print('PASS rehashed forged packet semantics rejected by host full capture redecode before durable handoff',flush=True)
    job,claim=enqueue('success');worker=executor(claim)
    assert worker.attempt(claim)=='succeeded',(state(job),list(control.rglob('failure.json'))[0].read_text() if list(control.rglob('failure.json')) else '')
    record=remember(claim);status=state(job);assert status['state']=='succeeded',status
    publication=shared/claim['output_dir']/'manifest.json';sha=digest(publication)
    identity={k:claim[k] for k in ('worker','attempt','token')}
    api.post('/v1/jobs/'+job+'/complete',{**identity,'manifest_sha256':sha})
    assert digest(publication)==sha
    print('PASS actual API claim -> isolated compute -> validated durable handoff -> idempotent complete',flush=True)
    receipt=json.loads((control/'jobs'/job/'attempt-1.worker'/'exit.json').read_text());assert receipt['removed'] and receipt['pid']==0
    inspection=json.loads((control/'jobs'/job/'attempt-1.worker'/'stopped-inspect.json').read_text())
    assert not any('TOKEN=' in item for item in inspection['Config']['Env'])
    binds=[m for m in inspection['Mounts'] if m['Type']=='bind'];assert len(binds)==1 and binds[0]['Destination']=='/inputs' and not binds[0]['RW']
    assert not inspection['HostConfig']['Privileged'] and inspection['HostConfig']['ReadonlyRootfs']
    print('PASS compute sees read-only inputs and bounded output; no credentials/control/socket mount',flush=True)
    assert worker.attempt(claim)=='reconcile_required' and state(job)['state']=='succeeded'
    print('PASS duplicate isolated attempt never mutates accepted job',flush=True)
    job,claim=enqueue('lost-complete')
    class LostComplete(API):
        def post(self,path,body):
            result=super().post(path,body)
            if path.endswith('/complete'):raise OSError('simulated accepted-complete response loss')
            return result
    lost=DockerExecutor(LostComplete(api.url,api.token),coordinator,shared,control,claim['worker'],timeout=30,lease=30)
    assert lost.attempt(claim)=='reconcile_required';remember(claim)
    assert state(job)['state']=='succeeded'
    print('PASS accepted complete response loss preserves immutable handoff and never fails terminal job',flush=True)
    from unittest.mock import patch
    from cpag_worker.isolated import atomic_json as real_atomic_json
    job,claim=enqueue('publication-marker-failure');worker=executor(claim)
    def marker_failure(path,value):
        if path.name=='publication.json':raise OSError(28,'simulated post-complete local marker ENOSPC')
        return real_atomic_json(path,value)
    with patch('cpag_worker.isolated.atomic_json',side_effect=marker_failure):assert worker.attempt(claim)=='reconcile_required'
    remember(claim);assert state(job)['state']=='succeeded'
    print('PASS local publication marker failure after accepted complete preserves terminal success and handoff',flush=True)
    saved_docker=os.environ.get('DOCKER_HOST')
    os.environ['DOCKER_HOST']='unix:///tmp/cpag-deliberately-unavailable.sock'
    try:assert any(o.get('scope')=='global' and o.get('retryable') for o in worker.recover())
    finally:
        if saved_docker is None:os.environ.pop('DOCKER_HOST',None)
        else:os.environ['DOCKER_HOST']=saved_docker
    assert not any(o.get('scope')=='global' for o in worker.recover())
    print('PASS actual Docker connection outage returns global retry and next restored scan succeeds',flush=True)
    saved_api=coordinator.url;coordinator.url='http://127.0.0.1:1'
    try:assert any(o.get('scope')=='global' and o.get('retryable') for o in worker.recover())
    finally:coordinator.url=saved_api
    assert not any(o.get('scope')=='global' for o in worker.recover())
    print('PASS actual coordinator connection outage returns global retry and restored scan succeeds',flush=True)
    subprocess.run(['docker','pause','cpag-m5-isolated-postgres-1'],check=True,stdout=subprocess.DEVNULL)
    try:assert any(o.get('scope')=='global' and o.get('retryable') for o in worker.recover())
    finally:subprocess.run(['docker','unpause','cpag-m5-isolated-postgres-1'],check=True,stdout=subprocess.DEVNULL)
    assert not any(o.get('scope')=='global' for o in worker.recover())
    print('PASS actual dedicated PostgreSQL pause returns global retry and restored scan succeeds',flush=True)
    job,claim=enqueue('cancel')
    def cancel(phase):
        if phase=='during_execution':api.post('/v1/jobs/'+job+'/cancel',{})
    worker=executor(claim,command=['python','-c','import time;time.sleep(60)'],checkpoint=cancel)
    assert worker.attempt(claim)=='cancelled',state(job);remember(claim)
    assert state(job)['state']=='cancelled',state(job)
    print('PASS live cancellation waits for actual Docker stop and external exit evidence',flush=True)
    for label,command in [('disk',['python','-c',"f=open('/output/fill','wb');f.write(b'x'*32000000)"]),('exit',['python','-c','raise SystemExit(7)'])]:
        job,claim=enqueue(label);worker=executor(claim,command=command,output_bytes=1048576)
        assert worker.attempt(claim)=='failed';remember(claim)
        assert state(job)['state']!='succeeded' and not (shared/claim['output_dir']).exists()
        # prevent this retry from being selected by subsequent cases
        api.post('/v1/jobs/'+job+'/cancel',{})
        print('PASS '+label+' cannot publish/complete',flush=True)
    job,claim=enqueue('handoff-enospc')
    def handoff_enospc(phase):
        if phase=='during_copy':raise OSError(28,'simulated host durable handoff ENOSPC')
    worker=executor(claim,checkpoint=handoff_enospc)
    assert worker.attempt(claim)=='failed';remember(claim)
    parent=(shared/claim['output_dir']).parent
    assert not (shared/claim['output_dir']).exists() and not list(parent.glob('.handoff-*'))
    assert state(job)['state']!='succeeded'
    assert 'simulated host durable handoff ENOSPC' in (control/'jobs'/job/'attempt-1.worker'/'failure.json').read_text()
    api.post('/v1/jobs/'+job+'/cancel',{})
    print('PASS simulated host durable-handoff ENOSPC injection prevents complete and cleans partial staging; user disk not filled',flush=True)
    job,claim=enqueue('capacity-reject')
    worker=executor(claim,host_budget_bytes=1)
    assert worker.attempt(claim)=='failed'
    api.post('/v1/jobs/'+job+'/cancel',{})
    api.post('/v1/jobs/'+job+'/ack-cancel',{k:claim[k] for k in ('worker','attempt','token')})
    assert state(job)['state']=='cancelled'
    try:coordinator.post('/v1/jobs/'+job+'/execution',{**{k:claim[k] for k in ('worker','attempt','token')},'location':claim['location'],'container_id':'a'*64})
    except APIError as error:assert error.status==409,error
    else:raise AssertionError('revoked capacity attempt registered')
    print('PASS host capacity rejection revokes never-started gate; cancellation completes and delayed registration fenced',flush=True)
    # Claim succeeds at DB but its response is deliberately discarded; no local job directory exists.
    job='isolated-lost-claim-'+uuid.uuid4().hex
    api.post('/v1/jobs',{'id':job,'max_attempts':2,'payload':payload})
    api.post('/v1/claim',{'worker':'lost-claim-host','lease_seconds':2,'executor':'isolated-v2','location':claim['location']})
    api.post('/v1/jobs/'+job+'/cancel',{})
    worker=executor(claim)
    recovered=worker.recover()
    assert any(item.get('id')==job and item.get('not_started') for item in recovered),recovered
    # Coordinator history supplies identity lost with the original claim response.
    history=worker.get_json(coordinator,'/v1/jobs/'+job+'/attempts')
    lost=history[0]
    api.post('/v1/jobs/'+job+'/ack-cancel',{k:lost[k] for k in ('worker','attempt','token')})
    assert state(job)['state']=='cancelled'
    print('PASS lost claim response with no host files automatically discovered, start gate revoked, cancellation converges',flush=True)
    bare_location=claim['location'].rsplit(':',1)[0]
    job='isolated-bare-upgrade-'+uuid.uuid4().hex
    api.post('/v1/jobs',{'id':job,'max_attempts':2,'payload':payload})
    legacy=api.post('/v1/claim',{'worker':'bare-upgrade-host','lease_seconds':30,'executor':'isolated-v2','location':bare_location})
    assert legacy['id']==job
    worker=executor(legacy)
    cid=worker.docker('create','--network','none','--read-only','--memory','64m','--cpus','.1','--pids-limit','32','--tmpfs','/runtime:rw,size=1m,mode=1777','--label','cpag.job='+job,'--label','cpag.attempt=1','--label','cpag.worker='+legacy['worker'],'cpag-isolated:round5','python','-c','import time;time.sleep(60)')
    containers.append(cid)
    record={**{k:legacy[k] for k in ('id','worker','attempt','token')},'location':bare_location,'container_id':cid}
    from cpag_worker.isolated import atomic_json
    atomic_json(control/'jobs'/job/'attempt-1.worker'/'execution.json',record)
    coordinator.post('/v1/jobs/'+job+'/execution',{k:v for k,v in record.items() if k!='id'})
    worker.docker('start',cid);api.post('/v1/jobs/'+job+'/cancel',{})
    recovered=worker.recover();assert any(item.get('id')==job and item.get('exited') for item in recovered),recovered
    api.post('/v1/jobs/'+job+'/ack-cancel',{k:legacy[k] for k in ('worker','attempt','token')})
    assert state(job)['state']=='cancelled'
    print('PASS known same-control legacy bare-daemon location cancels safely after scoped upgrade',flush=True)
    for phase in ('after_create','before_register','before_start','during_execution','during_copy','after_copy','before_remove','after_remove','after_publish'):
        job,claim=enqueue(phase)
        driver=control/(phase+'.json');driver.write_text(json.dumps(claim))
        code="import json,os;from cpag_worker.worker import API;from cpag_worker.isolated import DockerExecutor;c=json.load(open("+repr(str(driver))+"));w=DockerExecutor(API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN']),API(os.environ['CPAG_API_URL'],os.environ['CPAG_COORDINATOR_TOKEN']),os.environ['CPAG_SHARED_ROOT'],os.environ['CPAG_CONTROL_ROOT'],c['worker'],timeout=30,lease=30,checkpoint=lambda p:os._exit(91) if p=="+repr(phase)+" else None);w.attempt(c)"
        child=subprocess.run([sys.executable,'-c',code]);assert child.returncode==91,child
        record=remember(claim);worker=executor(claim)
        if phase=='after_publish':
            target=shared/claim['output_dir']/'manifest.json';assert target.exists()
            identity={k:claim[k] for k in ('worker','attempt','token')}
            worker.recover(job)
            assert state(job)['state']=='succeeded'
        else:
            api.post('/v1/jobs/'+job+'/cancel',{})
            if phase=='after_create':
                missing_job='00-missing-'+uuid.uuid4().hex
                api.post('/v1/jobs',{'id':missing_job,'max_attempts':2,'payload':payload})
                missing=api.post('/v1/claim',{'worker':'mixed-missing-host','lease_seconds':30,'executor':'isolated-v2','location':claim['location']})
                assert missing['id']==missing_job
                coordinator.post('/v1/jobs/'+missing_job+'/execution',{**{k:missing[k] for k in ('worker','attempt','token')},'location':claim['location'],'container_id':'f'*64})
                api.post('/v1/jobs/'+missing_job+'/cancel',{})
                for bad,value in [('01-corrupt',[]),('02-foreign',{**record,'id':'02-foreign','location':'docker:foreign'})]:
                    from cpag_worker.isolated import atomic_json
                    atomic_json(control/'jobs'/bad/'attempt-1.worker'/'execution.json',value)
            passes=[];calls=[];real_stop=worker.stop_container
            def counted_stop(record):calls.append(record['id']);return real_stop(record)
            worker.stop_container=counted_stop
            for scan in range(3 if phase=='after_create' else 1):
                calls.clear();recovered=worker.recover()
                assert not any(item.get('scope')=='global' for item in recovered),recovered
                if phase=='after_create':
                    expected=['missing_container_without_exit_proof','malformed_execution_record','foreign_daemon']
                    positions=[next(i for i,item in enumerate(recovered) if item.get('pending')==reason) for reason in expected]
                    good=next(i for i,item in enumerate(recovered) if item.get('id')==job and item.get('exited'))
                    assert positions==sorted(positions) and all(i<good for i in positions) and job in calls,recovered
                    passes.append({'scan':scan+1,'called_good_after_bad':True,'outcomes':recovered})
            if phase=='after_create':(VALIDATION/'mixed-recovery-outcomes.json').write_text(json.dumps(passes,indent=2)+'\n')
            identity={k:claim[k] for k in ('worker','attempt','token')}
            api.post('/v1/jobs/'+job+'/ack-cancel',identity)
            assert state(job)['state']=='cancelled' and not (shared/claim['output_dir']).exists(),state(job)
        print('PASS host hard-exit '+phase+' recovered from recorded Docker identity; no partial success',flush=True)
    job,claim=enqueue('start-race')
    def remove_before_start(phase):
        if phase=='before_start':
            record=remember(claim)
            api.post('/v1/jobs/'+job+'/cancel',{})
            worker.stop_container(record)
    worker=executor(claim,checkpoint=remove_before_start)
    assert worker.attempt(claim)=='failed'
    api.post('/v1/jobs/'+job+'/ack-cancel',{k:claim[k] for k in ('worker','attempt','token')})
    assert state(job)['state']=='cancelled'
    print('PASS created-container removal prevents paused original controller from starting after cancellation',flush=True)
    job,first=enqueue('multi-restart')
    def crash_driver(claim):
        driver=control/(uuid.uuid4().hex+'.json');driver.write_text(json.dumps(claim))
        code="import json,os;from cpag_worker.worker import API;from cpag_worker.isolated import DockerExecutor;c=json.load(open("+repr(str(driver))+"));w=DockerExecutor(API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN']),API(os.environ['CPAG_API_URL'],os.environ['CPAG_COORDINATOR_TOKEN']),os.environ['CPAG_SHARED_ROOT'],os.environ['CPAG_CONTROL_ROOT'],c['worker'],timeout=60,lease=2,command=['python','-c','import time;time.sleep(60)'],checkpoint=lambda p:(w.api.post('/v1/jobs/'+c['id']+'/heartbeat',{**{k:c[k] for k in ('worker','attempt','token')},'lease_seconds':2}),os._exit(92)) if p=='during_execution' else None);w.attempt(c)"
        assert subprocess.run([sys.executable,'-c',code]).returncode==92
        remember(claim)
    # Lease is shortened before launch; dead controller cannot renew it.
    crash_driver(first)
    worker=executor(first)
    # Frequent read-only scans must not extend the dead controller lease.
    for _ in range(4):worker.recover();time.sleep(.6)
    second=api.post('/v1/claim',{'worker':'host-multi-second','lease_seconds':30,'executor':'isolated-v2','location':first['location']});second.update(executor='isolated-v2',location=first['location'])
    assert second['id']==job and second['attempt']==2,second
    crash_driver(second)
    api.post('/v1/jobs/'+job+'/cancel',{})
    # Restart actual API process, then independent Go recovery process twice.
    os.kill(int(os.environ['CPAG_API_PID']),9)
    restarted=subprocess.Popen([os.environ['CPAG_API_BINARY']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:state(job);break
            except OSError:time.sleep(.1)
        recovery=subprocess.Popen([os.environ['CPAG_RECOVERY_BINARY']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time.sleep(.3);recovery.terminate();recovery.wait(timeout=5)
        (control/'jobs'/job/'attempt-2.worker'/'execution.json').unlink()
        worker.recover(job)
        recovery=subprocess.Popen([os.environ['CPAG_RECOVERY_BINARY']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                status=state(job)
                if status['state']=='cancelled':break
                time.sleep(.2)
            assert status['state']=='cancelled' and len(status['attempt_history'])==2,status
            assert all(a['exited_at'] for a in status['attempt_history']),status
            try:api.post('/v1/jobs/'+job+'/complete',{**{k:first[k] for k in ('worker','attempt','token')},'manifest_sha256':'0'*64})
            except APIError as error:assert error.status==409,error
            else:raise AssertionError('old attempt completed')
        finally:recovery.terminate();recovery.wait(timeout=5)
    finally:restarted.terminate();restarted.wait(timeout=5)
    print('PASS two actual attempts, expired dead controller, API+Go recovery restarts, cancel all executions, old complete fenced',flush=True)
    evidence=[]
    for path in sorted(control.glob('jobs/*/attempt-*.worker/exit.json')):
        value=json.loads(path.read_text());value.pop('token',None);evidence.append(value)
    (VALIDATION/'isolated-exit-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    (VALIDATION/'isolated-multi-attempt-status.json').write_text(json.dumps(status,indent=2)+'\n')


finally:
    for process in api_processes:
        if process.poll() is None:process.terminate();process.wait(timeout=5)
    for container in containers:subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
