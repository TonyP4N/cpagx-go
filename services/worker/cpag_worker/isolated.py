"""Opt-in Docker executor. All authority and durable publication stay on host."""
import argparse
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import time
import threading
import uuid
import urllib.request
from .worker import API, APIError, beneath, digest


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def atomic_json(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with temporary.open('x') as stream:
        os.chmod(temporary,0o600);json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path);sync_dir(path.parent)


class DockerExecutor:
    def __init__(self,api,coordinator,root,control,worker,*,image='cpag-isolated:round5',timeout=120,
                 heartbeat=1,lease=15,output_bytes=16777216,command=None,checkpoint=None):
        self.api,self.coordinator=api,coordinator
        self.root,self.control=Path(root).resolve(),Path(control).resolve()
        if self.control==self.root or self.control.is_relative_to(self.root):
            raise ValueError('control directory must be outside shared artifact root')
        self.worker,self.image,self.timeout=worker,image,timeout
        self.heartbeat,self.lease,self.output_bytes=heartbeat,lease,output_bytes
        self.command,self.checkpoint=command,checkpoint or (lambda _:None)
        self.stopping=False
    def stop(self,*_): self.stopping=True
    def docker(self,*args,binary=False):
        result=subprocess.run(['docker',*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        return result.stdout if binary else result.stdout.decode().strip()
    def inspect(self,container): return json.loads(self.docker('inspect',container))[0]
    def identity(self,claim): return {key:claim[key] for key in ('id','attempt','worker','token')}
    def endpoint(self,claim): return '/v1/jobs/'+claim['id']
    def exit_receipt(self,record,info):
        state=info['State']
        if state['Running'] or state['Pid']!=0: raise ValueError('container is still running')
        receipt={**record,'scope':'container','exited':True,'inspected_id':info['Id'],
                 'running':state['Running'],'pid':state['Pid'],'labels':info['Config']['Labels'],'removed':True}
        target=self.control/'jobs'/record['id']/('attempt-'+str(record['attempt'])+'.worker')/'exit.json'
        atomic_json(target,receipt)
        self.coordinator.post('/v1/jobs/'+record['id']+'/exit',{k:v for k,v in receipt.items() if k!='id'})
        return receipt
    def stop_container(self,record):
        target=self.control/'jobs'/record['id']/('attempt-'+str(record['attempt'])+'.worker')/'exit.json'
        if target.exists():
            receipt=json.loads(target.read_text())
            if receipt.get('removed') and receipt['container_id']==record['container_id']:
                self.coordinator.post('/v1/jobs/'+record['id']+'/exit',{k:v for k,v in receipt.items() if k!='id'})
                return receipt
        info=self.inspect(record['container_id'])
        labels=info['Config'].get('Labels') or {}
        if labels.get('cpag.attempt')!=str(record['attempt']) or labels.get('cpag.job')!=record['id'] or labels.get('cpag.worker')!=record['worker']:
            raise ValueError('container identity labels differ')
        if info['State']['Running']:
            self.docker('kill',record['container_id'])
        self.docker('wait',record['container_id'])
        info=self.inspect(record['container_id'])
        if info['State']['Running'] or info['State']['Pid']!=0:raise ValueError('container not stopped')
        atomic_json(target.with_name('stopped-inspect.json'),info)
        self.docker('rm',record['container_id'])
        return self.exit_receipt(record,info)
    def resume_publication(self,record,status):
        base=self.control/'jobs'/record['id']/('attempt-'+str(record['attempt'])+'.worker')
        handoff=json.loads((base/'handoff.json').read_text())
        proof=json.loads((base/'exit.json').read_text())
        if not proof.get('removed') or proof['container_id']!=record['container_id']:raise ValueError('missing removed-container proof')
        output=beneath(self.root,handoff['output_dir'])
        if digest(output/'manifest.json')!=handoff['manifest_sha256']:raise ValueError('handoff manifest changed')
        publication=json.loads((output/'manifest.json').read_text())
        payload=status['payload']
        if publication['config_fingerprint']!=payload['config_fingerprint'] or publication['inputs']!={name:payload[name]['sha256'] for name in ('network','process','profile')}:raise ValueError('handoff identity differs')
        for entry in publication['artifacts']:
            if Path(entry['path']).name!=entry['path']:raise ValueError('unsafe handoff path')
            path=output/entry['path']
            if path.is_symlink() or digest(path)!=entry['sha256'] or path.stat().st_size!=entry['size']:raise ValueError('handoff artifact changed')
        if payload.get('kind')=='packet':
            from cpag_core.packet_job import verify_artifacts
            verify_artifacts(output,beneath(self.root,payload['network']['path']))
        self.api.post('/v1/jobs/'+record['id']+'/complete',{**{k:record[k] for k in ('worker','attempt','token')},'manifest_sha256':handoff['manifest_sha256']})
        sync_dir(output);os.chmod(output,0o555);sync_dir(output.parent)
        atomic_json(base/'publication.json',handoff)
        return 'succeeded'

    def recover(self,job_id=None):
        """Only recorded container identities; missing Docker evidence never implies exit."""
        outcomes=[]
        jobs={path.name for path in (self.control/'jobs').glob('*') if path.is_dir()}
        if job_id:jobs.add(job_id)
        for job in jobs:
            request=urllib.request.Request(self.coordinator.url+'/v1/jobs/'+job+'/attempts',headers={'Authorization':'Bearer '+self.coordinator.token})
            with urllib.request.urlopen(request,timeout=3) as response:history=json.load(response)
            # DB is authoritative even if a host execution file was lost.
            if isinstance(history,dict):history=history.get('attempts',[])
            for item in history:
                if not item.get('container_id'):
                    outcomes.append({'id':job,'attempt':item['attempt'],'pending':'execution_identity_missing'});continue
                target=self.control/'jobs'/job/('attempt-'+str(item['attempt'])+'.worker')/'execution.json'
                if not target.exists() and not item.get('exited_at'):
                    atomic_json(target,{key:item[key] for key in ('id','attempt','worker','token','location','container_id')})
        daemon='docker:'+self.docker('info','--format','{{.ID}}')
        for path in sorted(self.control.glob('jobs/*/attempt-*.worker/execution.json')):
            record=json.loads(path.read_text())
            if record['location']!=daemon: raise ValueError('execution belongs to another daemon')
            request=urllib.request.Request(self.api.url+'/v1/jobs/'+record['id'],headers={'Authorization':'Bearer '+self.api.token})
            with urllib.request.urlopen(request,timeout=3) as response:status=json.load(response)
            if status['state']=='running' and status['attempt']==record['attempt'] and status.get('lease_valid',True):
                base=path.parent
                if (base/'handoff.json').exists() and (base/'exit.json').exists() and (beneath(self.root,json.loads((base/'handoff.json').read_text())['output_dir'])/'manifest.json').is_file():
                    outcomes.append({'id':record['id'],'attempt':record['attempt'],'publication':self.resume_publication(record,status)});continue
                outcomes.append({'id':record['id'],'attempt':record['attempt'],'skipped':'active_lease'});continue
            self.stop_container(record)
            outcomes.append({'id':record['id'],'attempt':record['attempt'],'exited':True})
        return outcomes
    def read_output(self,container,target,payload):
        process=subprocess.Popen(['docker','exec',container,'tar','-C','/output/run','-cf','-','.'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        expired=threading.Event()
        def cutoff(): expired.set();process.kill()
        timer=threading.Timer(30,cutoff);timer.start()
        try:
            raw=process.stdout.read(self.output_bytes+1048577)
            if len(raw)>self.output_bytes+1048576:process.kill()
            code=process.wait(timeout=3)
            if expired.is_set():raise ValueError('output transfer deadline')
            if code:raise ValueError('output archive command failed')
        finally:
            timer.cancel();process.stdout.close()
            if process.poll() is None:process.kill();process.wait()
        if len(raw)>self.output_bytes+1048576: raise ValueError('output transfer limit')
        target.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
            total=0
            for member in archive:
                if member.isdir() and member.name in ('.','./'): continue
                name=member.name.removeprefix('./')
                if not member.isfile() or Path(name).name!=name or name in ('','manifest.json'):
                    raise ValueError('unsafe output archive member')
                total+=member.size
                if total>self.output_bytes: raise ValueError('output transfer limit')
                with (target/name).open('xb') as stream:
                    shutil.copyfileobj(archive.extractfile(member),stream)
                    stream.flush();os.fsync(stream.fileno())
                self.checkpoint('during_copy')
        manifest=json.loads((target/'run_manifest.json').read_text())
        from cpag_core.contracts import validate
        validate('RunManifest',manifest)
        if manifest['config_fingerprint']!=payload['config_fingerprint']: raise ValueError('configuration mismatch')
        expected={'dataset.json','events.json','graph.json','quality.json'}
        if payload.get('kind')=='packet': expected.add('packet_observations.json')
        entries=manifest['artifacts']
        if {e['path'] for e in entries}!=expected or len(entries)!=len(expected): raise ValueError('artifact set differs')
        for entry in entries:
            path=target/entry['path']
            if digest(path)!=entry['sha256'] or path.stat().st_size!=entry['size_bytes']: raise ValueError('artifact hash/size mismatch')
            value=json.loads(path.read_text())
            schema={'dataset.json':'DatasetManifest','graph.json':'GraphArtifact'}.get(path.name)
            if schema:validate(schema,value)
            if path.name=='events.json':
                for event in value:validate('NetworkEvent' if event['event_id'].startswith('packet-') or 'protocol' in event else 'ProcessObservation',event)
        if payload.get('kind')=='packet':
            from cpag_core.packet_job import verify_artifacts
            verify_artifacts(target,beneath(self.root,payload['network']['path']))
        if {p.name for p in target.iterdir()}!=expected|{'run_manifest.json'}: raise ValueError('unexpected output file')
        publication={'config_fingerprint':payload['config_fingerprint'],
                     'inputs':{name:payload[name]['sha256'] for name in ('network','process','profile')},
                     'artifacts':[{'path':p.name,'sha256':digest(p),'size':p.stat().st_size} for p in sorted(target.iterdir())]}
        atomic_json(target/'manifest.json',publication);sync_dir(target)
        return digest(target/'manifest.json')
    def attempt(self,claim):
        record=None;stage=None;owned=True;cancelled=False
        keep_done=threading.Event();keep_thread=None;lease_health={'owned':True,'cancelled':False}
        endpoint=self.endpoint(claim);identity={k:claim[k] for k in ('attempt','worker','token')}
        base=self.control/'jobs'/claim['id']/('attempt-'+str(claim['attempt'])+'.worker')
        base.mkdir(mode=0o700,parents=True,exist_ok=True)
        sync_dir(base.parent);sync_dir(base.parent.parent)
        if (base/'execution.json').exists(): raise ValueError('execution already exists; reconcile first')
        try:
            inputs=base/'inputs';inputs.mkdir()
            for name in ('network','process','profile'):
                source=beneath(self.root,claim['payload'][name]['path'])
                if digest(source)!=claim['payload'][name]['sha256']: raise ValueError('input hash mismatch')
                shutil.copyfile(source,inputs/(name+source.suffix))
                if digest(inputs/(name+source.suffix))!=claim['payload'][name]['sha256']: raise ValueError('staged input hash mismatch')
                with (inputs/(name+source.suffix)).open('rb') as stream:os.fsync(stream.fileno())
                os.chmod(inputs/(name+source.suffix),0o444)
            sync_dir(inputs);os.chmod(inputs,0o555)
            module='cpag_core.packet_job' if claim['payload'].get('kind')=='packet' else 'cpag_core'
            command=self.command or ['python','-m',module]
            command=command+sum((["--"+name,"/inputs/"+name+Path(claim['payload'][name]['path']).suffix] for name in ('network','process','profile')),[])+['--output','/output/run','--synthetic']
            container=self.docker('create','--network','none','--read-only','--user','65532:65532',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--memory-swap','256m',
                '--cpus','.5','--pids-limit','64','--log-driver','local','--log-opt','max-size=64k','--log-opt','max-file=2',
                '--label','cpag.job='+claim['id'],'--label','cpag.attempt='+str(claim['attempt']),'--label','cpag.worker='+claim['worker'],
                '--mount','type=bind,src='+str(inputs)+',dst=/inputs,readonly',
                '--tmpfs','/output:rw,nosuid,nodev,size='+str(self.output_bytes)+',mode=1777',
                '--tmpfs','/runtime:rw,nosuid,nodev,size=1m,mode=1777',
                '-e','CPAG_CONTAINER_SECONDS='+str(self.timeout),self.image,*command)
            record={**self.identity(claim),'container_id':container,'location':'docker:'+self.docker('info','--format','{{.ID}}')}
            atomic_json(base/'execution.json',record)
            self.coordinator.post(endpoint+'/execution',{k:v for k,v in record.items() if k!='id'})
            self.checkpoint('before_start')
            self.docker('start',container)
            def keep_lease():
                while not keep_done.wait(self.heartbeat):
                    try:
                        response=self.api.post(endpoint+'/heartbeat',{**identity,'lease_seconds':self.lease})
                        if response and response.get('state')=='cancelling':lease_health['cancelled']=True;return
                    except APIError as error:
                        lease_health['cancelled']=error.status==409 and error.body.get('state')=='cancelling'
                        lease_health['owned']=False;return
                    except (OSError,ValueError):lease_health['owned']=False;return
            keep_thread=threading.Thread(target=keep_lease,daemon=True);keep_thread.start()
            self.checkpoint('during_execution')
            deadline=time.monotonic()+self.timeout;next_heartbeat=0;result=None
            while time.monotonic()<deadline:
                if self.stopping: break
                if time.monotonic()>=next_heartbeat:
                    try:
                        response=self.api.post(endpoint+'/heartbeat',{**identity,'lease_seconds':self.lease})
                        if response and response.get('state')=='cancelling': cancelled=True;break
                    except APIError as error:
                        cancelled=error.status==409 and error.body.get('state')=='cancelling';owned=cancelled;break
                    except (OSError,ValueError): owned=False;break
                    next_heartbeat=time.monotonic()+self.heartbeat
                if not self.inspect(container)['State']['Running']: break
                try: result=json.loads(self.docker('exec',container,'cat','/runtime/result.json'));break
                except subprocess.CalledProcessError: time.sleep(.05)
            if cancelled or not owned or self.stopping:
                self.stop_container(record)
                if cancelled:self.api.post(endpoint+'/ack-cancel',identity)
                return 'cancelled' if cancelled else 'lost_lease'
            if not result or result['returncode']!=0: raise ValueError('calculation failed or deadline expired: '+self.docker('logs',container))
            output=beneath(self.root,claim['output_dir']);output.parent.mkdir(parents=True,exist_ok=True)
            stage=output.parent/('.handoff-'+uuid.uuid4().hex)
            sha=self.read_output(container,stage,claim['payload'])
            self.checkpoint('after_copy')
            if not lease_health['owned'] or lease_health['cancelled'] or self.stopping:
                self.stop_container(record)
                if lease_health['cancelled']:self.api.post(endpoint+'/ack-cancel',identity)
                return 'cancelled' if lease_health['cancelled'] else 'lost_lease'
            self.stop_container(record)
            # Immutable namespace reservation: never replace an existing attempt.
            if output.exists(): raise ValueError('attempt output already exists')
            atomic_json(base/'handoff.json',{'manifest_sha256':sha,'output_dir':claim['output_dir']})
            self.checkpoint('before_publish')
            lock=os.open(str(output)+'.publish-lock',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            os.fsync(lock);os.close(lock);sync_dir(output.parent)
            if output.exists():raise ValueError('immutable output already exists')
            for path in stage.iterdir():os.chmod(path,0o444)
            sync_dir(stage)
            os.rename(stage,output);sync_dir(output.parent);stage=None
            self.checkpoint('after_publish')
            self.api.post(endpoint+'/complete',{**identity,'manifest_sha256':sha})
            sync_dir(output);os.chmod(output,0o555);sync_dir(output.parent)
            atomic_json(base/'publication.json',{'manifest_sha256':sha,'output_dir':claim['output_dir']})
            return 'succeeded'
        except (OSError,ValueError,KeyError,APIError,subprocess.SubprocessError) as error:
            atomic_json(base/'failure.json',{'error':str(error),'stderr':(getattr(error,'stderr',b'') or b'').decode(errors='replace')})
            if record:
                try:self.stop_container(record)
                except (OSError,ValueError,APIError,subprocess.SubprocessError):return 'lost_lease'
            if owned and not self.stopping:
                try:self.api.post(endpoint+'/fail',{**identity,'message':str(error)[:1024],'retryable':True})
                except (OSError,ValueError,APIError):pass
            return 'failed'
        finally:
            keep_done.set()
            if keep_thread:keep_thread.join(timeout=4)
            if stage and stage.exists():
                os.chmod(stage,0o700);shutil.rmtree(stage)
    def once(self):
        claim=self.api.post('/v1/claim',{'worker':self.worker,'lease_seconds':self.lease})
        return self.attempt(claim) if claim and claim.get('id') else 'idle'


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--enable-isolated-executor',action='store_true',required=True)
    parser.add_argument('--recover',action='store_true');parser.add_argument('--recover-job');args=parser.parse_args()
    worker=DockerExecutor(API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN']),
        API(os.environ['CPAG_API_URL'],os.environ['CPAG_COORDINATOR_TOKEN']),os.environ['CPAG_SHARED_ROOT'],
        os.environ['CPAG_CONTROL_ROOT'],os.environ.get('CPAG_WORKER_ID','isolated-host'))
    signal.signal(signal.SIGTERM,worker.stop);signal.signal(signal.SIGINT,worker.stop)
    print(json.dumps(worker.recover(args.recover_job)) if args.recover else worker.once())

if __name__=='__main__':main()
