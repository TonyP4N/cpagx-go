"""Opt-in Docker executor. All authority and durable publication stay on host."""
import argparse
import io
import re
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import threading
import uuid
import urllib.request
import urllib.error
import urllib.parse
from .worker import API, APIError, beneath, digest, network_refs, publication_inputs, source_flag, compact_payload


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


def prepare_compact_publication_root(output):
    """Let the service owner write its anchor; the verifier may only read.

    Linux bind mounts retain host ownership. The verifier UID differs from the
    service UID and must traverse this root before completion is acknowledged.
    Final successful publication seals the root to 0555 as before.
    """
    if output.is_symlink() or not output.is_dir():raise ValueError('invalid compact publication directory')
    os.chmod(output,0o755);sync_dir(output)


def seal_handoff(stage,*,compact=False):
    for path in stage.rglob('*'):
        if path.is_file():os.chmod(path,0o444)
        elif path.is_dir():os.chmod(path,0o555)
    if compact:prepare_compact_publication_root(stage)
    else:sync_dir(stage)


class RecoveryUnavailable(Exception):
    pass


class CalculationFailure(ValueError):
    def __init__(self, returncode, output):
        self.compute_returncode=returncode
        self.stderr=output[:65536]
        self.failure_category='calculation_exit' if returncode is not None else 'calculation_result_missing'
        # Keep the actionable tail in the bounded job error; retain the full
        # bounded combined output separately in the private failure receipt.
        detail=self.stderr.decode(errors='replace')[-768:]
        super().__init__(self.failure_category+' (compute returncode='+str(returncode)+'): '+detail)




class DockerExecutor:
    def __init__(self,api,coordinator,root,control,worker,*,image='cpag-isolated:round5',timeout=120,
                 heartbeat=1,lease=15,output_bytes=16777216,command=None,checkpoint=None,host_budget_bytes=1073741824,min_free_bytes=67108864,resource_profile=None):
        from .resources import resolve
        resources=resolve(resource_profile)
        self.resource_profile=resource_profile
        self.memory_bytes,self.cpus,self.transfer_seconds=268435456,'.5',30
        self.cpu_seconds=None;self.temporary_bytes=output_bytes+2097152
        if resources is not None:
            timeout=resources['timeout'];output_bytes=resources['output_bytes']
            host_budget_bytes=resources['host_budget_bytes'];min_free_bytes=resources['min_free_bytes']
            self.memory_bytes=resources['memory_bytes'];self.cpus=resources['cpus'];self.transfer_seconds=resources['transfer_seconds']
            self.cpu_seconds=resources['cpu_seconds'];self.temporary_bytes=resources['temporary_bytes']
        self.api,self.coordinator=api,coordinator
        self.publication_api=API(api.url,api.token,timeout=resources['publication_seconds']) if resources and isinstance(api,API) else api
        self.root,self.control=Path(root).resolve(),Path(control).resolve()
        if self.control==self.root or self.control.is_relative_to(self.root):
            raise ValueError('control directory must be outside shared artifact root')
        self.worker,self.image,self.timeout=worker,image,timeout
        self.heartbeat,self.lease,self.output_bytes=heartbeat,lease,output_bytes
        self.command,self.checkpoint=command,checkpoint or (lambda _:None)
        self.stopping=False
        self.host_budget_bytes,self.min_free_bytes=host_budget_bytes,min_free_bytes
        self.scope=hashlib.sha256((str(self.root)+'|'+str(self.control)).encode()).hexdigest()[:24]
    def capacity(self,claim,settle=False):
        self.control.mkdir(parents=True,exist_ok=True)
        key=claim['id']+':'+str(claim['attempt'])
        with (self.control/'capacity.lock').open('a+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            path=self.control/'capacity.json'
            if not path.exists() and any(p.is_file() and p.name!='owner.lock' for p in (self.control/'jobs').rglob('*')):raise ValueError('capacity ledger missing; restore or rebuild required')
            existing=sum(p.stat().st_size for p in (self.root/'jobs').rglob('*') if p.is_file() and not p.is_symlink()) if not path.exists() else 0
            ledger=json.loads(path.read_text()) if path.exists() else {'root':str(self.root),'reservations':{'__existing__':existing}}
            if not isinstance(ledger,dict) or not isinstance(ledger.get('reservations'),dict):raise ValueError('invalid capacity ledger')
            if ledger.get('root')!=str(self.root):raise ValueError('capacity ledger belongs to another root')
            reservations=ledger['reservations']
            if any(type(value) is not int or value<0 for value in reservations.values()):raise ValueError('invalid capacity reservation')
            if settle:
                base=self.control/'jobs'/claim['id']/('attempt-'+str(claim['attempt'])+'.worker')
                output=beneath(self.root,claim.get('output_dir','jobs/'+claim['id']+'/attempt-'+str(claim['attempt'])))
                used=sum(p.stat().st_size for folder in (base,output) if folder.exists() for p in folder.rglob('*') if p.is_file() and not p.is_symlink())
                reservations[key]=used+65536
            elif key not in reservations:
                refs=network_refs(claim['payload'])+[claim['payload'][role] for role in ('process','profile')]
                sizes=sum(beneath(self.root,ref['path']).stat().st_size for ref in refs)
                reserve=sizes+2*self.output_bytes+2097152
                outside=sum(p.stat().st_size for folder in (self.root,self.control) for p in folder.rglob('*') if p.is_file() and not p.is_symlink() and not p.is_relative_to(folder/'jobs') and p.name not in ('capacity.json','capacity.lock'))
                if sum(reservations.values())+outside+reserve>self.host_budget_bytes:raise OSError(28,'executor host storage budget exhausted')
                for filesystem in (self.root,self.control):
                    if shutil.disk_usage(filesystem).free-sum(reservations.values())-reserve<self.min_free_bytes:raise OSError(28,'executor minimum free storage threshold')
                reservations[key]=reserve
            atomic_json(path,ledger)

    def valid_job(self,value):return isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',value) is not None
    def validate_identity(self,record,path=None):
        if not isinstance(record,dict) or not self.valid_job(record.get('id')) or type(record.get('attempt')) is not int or record['attempt']<1 or any(not isinstance(record.get(key),str) or not record[key] for key in ('worker','token')):raise ValueError('invalid execution record')
        if path and (path.parent.name!='attempt-'+str(record['attempt'])+'.worker' or path.parent.parent.name!=record['id']):raise ValueError('execution record path identity mismatch')

    def stop(self,*_): self.stopping=True
    def docker(self,*args,binary=False):
        result=subprocess.run(['docker',*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        return result.stdout if binary else result.stdout.decode().strip()
    def bounded_container_logs(self,container):
        result=subprocess.run(['docker','logs',container],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False,timeout=5)
        return result.stdout[:65536]
    def inspect(self,container):
        values=json.loads(self.docker('inspect',container))
        if not isinstance(values,list) or len(values)!=1 or not isinstance(values[0],dict):raise ValueError('invalid Docker inspect response')
        return values[0]
    def identity(self,claim): return {key:claim[key] for key in ('id','attempt','worker','token')}
    def endpoint(self,claim): return '/v1/jobs/'+claim['id']
    def location(self):return 'docker:'+self.docker('info','--format','{{.ID}}')+':'+self.scope
    def exit_receipt(self,record,info):
        self.validate_identity(record)
        state=info['State']
        if state['Running'] or state['Pid']!=0: raise ValueError('container is still running')
        receipt={**record,'scope':'container','exited':True,'inspected_id':info['Id'],
                 'running':state['Running'],'pid':state['Pid'],'labels':info['Config']['Labels'],'removed':True}
        target=self.control/'jobs'/record['id']/('attempt-'+str(record['attempt'])+'.worker')/'exit.json'
        atomic_json(target,receipt)
        self.coordinator_post('/v1/jobs/'+record['id']+'/exit',{k:v for k,v in receipt.items() if k!='id'})
        return receipt
    def stop_container(self,record):
        self.validate_identity(record)
        target=self.control/'jobs'/record['id']/('attempt-'+str(record['attempt'])+'.worker')/'exit.json'
        if target.exists():
            receipt=json.loads(target.read_text())
            if receipt.get('removed') and receipt['container_id']==record['container_id']:
                self.coordinator_post('/v1/jobs/'+record['id']+'/exit',{k:v for k,v in receipt.items() if k!='id'})
                return receipt
        try:info=self.inspect(record['container_id'])
        except subprocess.CalledProcessError:
            intent=target.with_name('remove-intent.json')
            if not intent.exists():raise
            prepared=json.loads(intent.read_text())
            if prepared['container_id']!=record['container_id']:raise ValueError('remove intent identity differs')
            events=self.docker('events','--since',str(prepared['since']),'--until',str(int(time.time())+1),'--filter','container='+record['container_id'],'--filter','event=destroy','--format','{{json .}}')
            matches=[json.loads(line) for line in events.splitlines() if line]
            matches=[event for event in matches if event.get('Actor',{}).get('ID')==record['container_id'] and all(event['Actor'].get('Attributes',{}).get(key)==value for key,value in prepared['labels'].items())]
            if not matches:raise ValueError('missing container without retained Docker destroy event')
            atomic_json(target.with_name('destroy-event.json'),matches[-1])
            return self.exit_receipt(record,prepared['inspection'])
        labels=info['Config'].get('Labels') or {}
        if labels.get('cpag.attempt')!=str(record['attempt']) or labels.get('cpag.job')!=record['id'] or labels.get('cpag.worker')!=record['worker']:
            raise ValueError('container identity labels differ')
        if info['State']['Running']:
            self.docker('kill',record['container_id'])
        self.docker('wait',record['container_id'])
        info=self.inspect(record['container_id'])
        if info['State']['Running'] or info['State']['Pid']!=0:raise ValueError('container not stopped')
        atomic_json(target.with_name('stopped-inspect.json'),info)
        atomic_json(target.with_name('remove-intent.json'),{'container_id':record['container_id'],'since':int(time.time())-1,'labels':labels,'inspection':info})
        self.checkpoint('before_remove')
        self.docker('rm',record['container_id'])
        self.checkpoint('after_remove')
        return self.exit_receipt(record,info)
    def resume_publication(self,record,status):
        self.validate_identity(record)
        base=self.control/'jobs'/record['id']/('attempt-'+str(record['attempt'])+'.worker')
        handoff=json.loads((base/'handoff.json').read_text())
        proof=json.loads((base/'exit.json').read_text())
        if not proof.get('removed') or proof['container_id']!=record['container_id']:raise ValueError('missing removed-container proof')
        output=beneath(self.root,handoff['output_dir'])
        if digest(output/'manifest.json')!=handoff['manifest_sha256']:raise ValueError('handoff manifest changed')
        publication=json.loads((output/'manifest.json').read_text())
        payload=status['payload']
        if publication['config_fingerprint']!=payload['config_fingerprint'] or any(publication.get(k)!=v for k,v in publication_inputs(payload).items()) or publication.get('networks')!=publication_inputs(payload).get('networks'):raise ValueError('handoff identity differs')
        if payload.get('kind')=='dual-source-replay' and (publication.get('replay_version')!=payload.get('replay_version') or publication.get('history_format')!=payload.get('history_format')):raise ValueError('replay handoff version differs')
        compact=compact_payload(payload)
        dual_source=payload.get('kind') in ('dual-source','dual-source-replay')
        if dual_source:
            from importlib import import_module
            export=import_module('cpag_core.shared_export' if compact else 'cpag_core.replay_export' if payload.get('kind')=='dual-source-replay' else 'cpag_core.dual_source_export')
            FILES=export.artifact_files_for_inputs(len(network_refs(payload)),mode='replay' if payload.get('kind')=='dual-source-replay' else 'offline') if compact else export.artifact_files_for_inputs(len(network_refs(payload)),history_format=payload.get('history_format')) if payload.get('kind')=='dual-source-replay' else export.artifact_files(output)
            verify_task=export.verify_task
            if {entry['path'] for entry in publication['artifacts']}!=FILES or len(publication['artifacts'])!=len(FILES):raise ValueError('dual-source handoff inventory differs')
            if compact:
                from cpag_core.shared_service import _inventory, _envelope
                binding=self.compact_binding(payload,record['id'],record['attempt'])
                _,manifest,rows=_inventory(output,binding)
                with _envelope(output,rows):export._bound(output)
            else:manifest=verify_task(output)
            if manifest['run_id']!=record['id'] or manifest['attempt_id']!=record['attempt']:raise ValueError('dual-source handoff identity differs')
        for entry in publication['artifacts']:
            if not dual_source and Path(entry['path']).name!=entry['path']:raise ValueError('unsafe handoff path')
            path=beneath(output,entry['path'])
            if path.is_symlink() or digest(path)!=entry['sha256'] or path.stat().st_size!=entry['size']:raise ValueError('handoff artifact changed')
        if payload.get('kind')=='packet':
            from cpag_core.packet_job import verify_artifacts
            verify_artifacts(output,beneath(self.root,payload['network']['path']))
        if compact:prepare_compact_publication_root(output)
        self.complete(record,handoff['manifest_sha256'])
        sync_dir(output);os.chmod(output,0o555);sync_dir(output.parent)
        atomic_json(base/'publication.json',handoff)
        return 'succeeded'

    def coordinator_post(self,path,body):
        try:return self.coordinator.post(path,body)
        except (urllib.error.URLError,TimeoutError) as error:raise RecoveryUnavailable('coordinator_unavailable') from error
        except APIError as error:
            if error.status>=500 or error.status in (401,403):raise RecoveryUnavailable('coordinator_unavailable') from error
            raise

    def get_json(self,api,path):
        request=urllib.request.Request(api.url+path,headers={'Authorization':'Bearer '+api.token})
        try:
            with urllib.request.urlopen(request,timeout=3) as response:return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code>=500 or error.code in (401,403):raise RecoveryUnavailable('api_or_database_unavailable') from error
            raise
        except (urllib.error.URLError,TimeoutError) as error:raise RecoveryUnavailable('api_unavailable') from error

    def recovery_reason(self,error):
        if isinstance(error,json.JSONDecodeError):return 'malformed_json'
        if isinstance(error,urllib.error.HTTPError) and error.code==404:return 'job_not_found'
        if isinstance(error,subprocess.CalledProcessError):
            stderr=(error.stderr or b'').decode(errors='replace') if isinstance(error.stderr,bytes) else (error.stderr or '')
            if 'no such container' in stderr.lower() or 'no such object' in stderr.lower():return 'missing_container_without_exit_proof'
            return 'docker_operation_failed'
        known={'invalid execution record':'malformed_execution_record','execution record path identity mismatch':'execution_record_path_mismatch','missing container without retained Docker destroy event':'missing_docker_destroy_event','handoff manifest changed':'handoff_manifest_hash_mismatch','handoff artifact changed':'handoff_artifact_hash_mismatch','container identity labels differ':'container_identity_mismatch','capacity ledger missing; restore or rebuild required':'capacity_ledger_missing'}
        return known.get(str(error),'attempt_evidence_invalid')

    def recover(self,job_id=None):
        """Isolate bad attempts; unavailable infrastructure yields an explicit retry."""
        outcomes=[]
        try:daemon=self.location()
        except (OSError,subprocess.SubprocessError):return [{'scope':'global','pending':'docker_unavailable','retryable':True}]
        try:
            discovered=self.get_json(self.coordinator,'/v1/executions?'+urllib.parse.urlencode({'location':daemon}))
            if isinstance(discovered,dict):discovered=discovered.get('executions',[])
            jobs={path.name for path in (self.control/'jobs').glob('*') if path.is_dir() and self.valid_job(path.name)}
            if not isinstance(discovered,list):raise ValueError('invalid execution discovery envelope')
            for item in discovered:
                if not isinstance(item,dict) or not self.valid_job(item.get('id')):
                    outcomes.append({'pending':'invalid_discovery_record','retryable':True});continue
                jobs.add(item['id'])
            if job_id:
                if not self.valid_job(job_id):raise ValueError('invalid requested job id')
                jobs.add(job_id)
            # Find create-before-registration orphans even if all local job files
            # vanished. Docker labels identify candidates; DB tokens authorize exit.
            ids=self.docker('ps','-a','--no-trunc','--filter','label=cpag.managed=isolated-v1','--filter','label=cpag.scope='+self.scope,'--format','{{.ID}}').splitlines()
            candidates=[]
            for container in ids:
                try:
                    info=self.inspect(container);labels=info['Config'].get('Labels') or {}
                    if not labels.get('cpag.execution'):raise ValueError('missing execution nonce')
                    if not self.valid_job(labels.get('cpag.job')):raise ValueError('invalid Docker job label')
                    jobs.add(labels['cpag.job']);candidates.append(info)
                except (OSError,ValueError,KeyError,TypeError,AttributeError,subprocess.SubprocessError) as error:
                    if isinstance(error,(OSError,subprocess.SubprocessError)):
                        try:self.docker('info','--format','{{.ID}}')
                        except (OSError,subprocess.SubprocessError):raise RecoveryUnavailable('docker_unavailable') from error
                    outcomes.append({'container_id':container,'pending':'container_discovery_invalid','retryable':True})
            histories={}
            for job in sorted(jobs):
                try:
                    history=self.get_json(self.coordinator,'/v1/jobs/'+job+'/attempts')
                    if isinstance(history,dict):history=history.get('attempts',[])
                    if not isinstance(history,list):raise ValueError('invalid history envelope')
                    valid=[]
                    for item in history:
                        if not isinstance(item,dict) or type(item.get('attempt')) is not int or item['attempt']<1 or any(not isinstance(item.get(key),str) for key in ('id','worker','token','location','container_id')) or item['id']!=job:
                            outcomes.append({'id':job,'pending':'invalid_history_record','retryable':True});continue
                        valid.append(item)
                    history=valid
                    histories[job]=history
                    for item in history:
                        try:
                            if not item.get('container_id'):
                                status=self.get_json(self.api,'/v1/jobs/'+job)
                                if item.get('executor')=='isolated-v2' and not (status['state']=='running' and status['attempt']==item['attempt'] and status.get('lease_valid',True)):
                                    self.coordinator_post('/v1/jobs/'+job+'/not-started',{k:item[k] for k in ('attempt','worker','token','location')})
                                    outcomes.append({'id':job,'attempt':item['attempt'],'not_started':True})
                                else:outcomes.append({'id':job,'attempt':item['attempt'],'pending':'execution_identity_missing','retryable':True})
                                continue
                            target=self.control/'jobs'/job/('attempt-'+str(item['attempt'])+'.worker')/'execution.json'
                            if not target.exists() and not item.get('exited_at'):
                                atomic_json(target,{key:item[key] for key in ('id','attempt','worker','token','location','container_id')})
                        except RecoveryUnavailable:raise
                        except (OSError,ValueError,KeyError,TypeError,AttributeError,APIError) as error:
                            if isinstance(error,APIError) and (error.status>=500 or error.status in (401,403)):raise RecoveryUnavailable('coordinator_unavailable') from error
                            outcomes.append({'id':job,'attempt':item.get('attempt'),'pending':'history_attempt_reconstruction_failed','retryable':True,'error_type':type(error).__name__})
                except RecoveryUnavailable:raise
                except (OSError,ValueError,KeyError,TypeError,AttributeError,APIError) as error:
                    if isinstance(error,APIError) and (error.status>=500 or error.status in (401,403)):raise RecoveryUnavailable('coordinator_unavailable') from error
                    outcomes.append({'id':job,'pending':'job_history_invalid_or_missing','retryable':True})
            for info in candidates:
                labels=info['Config']['Labels'];job=labels['cpag.job']
                try:
                    matches=[row for row in histories.get(job,[]) if row['attempt']==int(labels['cpag.attempt']) and row['worker']==labels['cpag.worker']]
                    if len(matches)!=1:raise ValueError('no unique database identity')
                    row=matches[0]
                    if row.get('container_id') and row['container_id']!=info['Id']:raise ValueError('database container differs')
                    record={key:row[key] for key in ('id','attempt','worker','token')}
                    record.update(location=daemon,container_id=info['Id'])
                    target=self.control/'jobs'/job/('attempt-'+str(row['attempt'])+'.worker')/'execution.json'
                    if not target.exists():atomic_json(target,record)
                except (OSError,ValueError,KeyError,TypeError,AttributeError):
                    outcomes.append({'id':job,'container_id':info['Id'],'pending':'orphan_identity_unverified','retryable':True})
            for path in sorted(self.control.glob('jobs/*/attempt-*.worker/execution.json')):
                record=None
                try:
                    record=json.loads(path.read_text())
                    self.validate_identity(record,path)
                    if not isinstance(record,dict) or any(not isinstance(record.get(key),str) or not record[key] for key in ('id','worker','token','location','container_id')) or type(record.get('attempt')) is not int:raise ValueError('invalid execution record')
                    if record['location'] not in (daemon,daemon.rsplit(':',1)[0]):
                        outcomes.append({'id':record['id'],'attempt':record['attempt'],'pending':'foreign_daemon','retryable':False});continue
                    status=self.get_json(self.api,'/v1/jobs/'+record['id'])
                    if status['state']=='running' and status['attempt']==record['attempt'] and status.get('lease_valid',True):
                        base=path.parent
                        if (base/'handoff.json').exists() and (base/'exit.json').exists() and (beneath(self.root,json.loads((base/'handoff.json').read_text())['output_dir'])/'manifest.json').is_file():
                            # The live executor owns publication through verification.
                            # Recovery must not renew/publish the same attempt concurrently.
                            owner=(base/'owner.lock').open('a+')
                            try:fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
                            except BlockingIOError:
                                owner.close();outcomes.append({'id':record['id'],'attempt':record['attempt'],'skipped':'active_owner'});continue
                            try:outcomes.append({'id':record['id'],'attempt':record['attempt'],'publication':self.resume_publication(record,status)})
                            finally:owner.close()
                            continue
                        outcomes.append({'id':record['id'],'attempt':record['attempt'],'skipped':'active_lease'});continue
                    self.stop_container(record)
                    owner=(path.parent/'owner.lock').open('a+')
                    try:fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:
                        owner.close();outcomes.append({'id':record['id'],'attempt':record['attempt'],'exited':True,'capacity':'reserved_owner_active'});continue
                    try:
                        marker=path.parent/'stage.json'
                        if marker.exists():
                            stage=beneath(self.root,json.loads(marker.read_text())['path'])
                            expected=self.root/'jobs'/record['id']
                            if stage.parent!=expected or not stage.name.startswith('.handoff-'):raise ValueError('invalid staged output identity')
                            if stage.exists():os.chmod(stage,0o700);shutil.rmtree(stage)
                        self.capacity(record,settle=True)
                    finally:owner.close()
                    outcomes.append({'id':record['id'],'attempt':record['attempt'],'exited':True})
                except RecoveryUnavailable:raise
                except (OSError,ValueError,KeyError,TypeError,AttributeError,APIError,subprocess.SubprocessError) as error:
                    if isinstance(error,APIError) and (error.status>=500 or error.status in (401,403)):raise RecoveryUnavailable('coordinator_unavailable') from error
                    if isinstance(error,(OSError,subprocess.SubprocessError)):
                        try:self.docker('info','--format','{{.ID}}')
                        except (OSError,subprocess.SubprocessError):raise RecoveryUnavailable('docker_unavailable') from error
                    outcomes.append({'id':record.get('id') if isinstance(record,dict) else path.parent.parent.name,
                                     'attempt':record.get('attempt') if isinstance(record,dict) else None,
                                     'pending':self.recovery_reason(error),'retryable':True,'error_type':type(error).__name__})
        except RecoveryUnavailable as error:
            outcomes.append({'scope':'global','pending':str(error),'retryable':True})
        except (OSError,ValueError,KeyError,TypeError,AttributeError,subprocess.SubprocessError):
            outcomes.append({'scope':'global','pending':'discovery_unavailable','retryable':True})
        return outcomes
    def compact_binding(self,payload,run_id,attempt_id):
        return {**{name:payload[name] for name in ('config_fingerprint','storage_format','capacity_profile','resource_profile','storage_budget_version')},
                'run_id':run_id,'attempt_id':attempt_id,'payload_sha256':hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

    def keep_lease(self,record,done,health):
        """Independent renewal, including slow source verification/publication RPCs."""
        identity={key:record[key] for key in ('worker','attempt','token')}
        endpoint='/v1/jobs/'+record['id']
        trace={'version':'attempt-lease-observation-1','attempt':record['attempt'],'started_at':time.time(),'heartbeats':0,'events':[]}
        target=self.control/'jobs'/record['id']/('attempt-'+str(record['attempt'])+'.worker')/'lease-observation.json'
        while not done.is_set():
            started=time.monotonic();event={'at':time.time(),'phase':health.get('phase','publication')}
            try:
                response=self.api.post(endpoint+'/heartbeat',{**identity,'lease_seconds':self.lease})
                event['outcome']='renewed';trace['heartbeats']+=1;trace['last_renewed_at']=time.time()
                if response and response.get('state')=='cancelling':health['cancelled']=True;event['outcome']='cancelling'
            except APIError as error:
                health['cancelled']=error.status==409 and error.body.get('state')=='cancelling'
                health['owned']=False;event.update(outcome='api_error',status=error.status,state=error.body.get('state'))
            except (OSError,ValueError,TypeError,AttributeError) as error:
                health['owned']=False;event.update(outcome='transport_error',error_type=type(error).__name__)
            event['wall_seconds']=time.monotonic()-started
            trace['events']=(trace['events']+[event])[-64:]
            trace.update(last_event=event,owned=health['owned'],cancelled=health['cancelled'])
            try:atomic_json(target,trace)
            except OSError:pass # A diagnostics failure cannot create lease authority.
            if not health['owned'] or health['cancelled']:return
            if done.wait(self.heartbeat):return

    def complete(self,record,sha,lease_health=None,deadline=None):
        """Keep a pending verifier nonterminal; renew independently of slow RPCs."""
        deadline=deadline if deadline is not None else time.monotonic()+2100
        own_keeper=lease_health is None
        if own_keeper:lease_health={'owned':True,'cancelled':False,'phase':'recovery_publication'}
        done=threading.Event();keeper=None
        if own_keeper:
            keeper=threading.Thread(target=self.keep_lease,args=(record,done,lease_health),daemon=True);keeper.start()
        try:
            identity={key:record[key] for key in ('worker','attempt','token')}
            endpoint='/v1/jobs/'+record['id']
            trace={'version':'attempt-publication-observation-1','attempt':record['attempt'],'calls':0,'events':[]}
            target=self.control/'jobs'/record['id']/('attempt-'+str(record['attempt'])+'.worker')/'publication-observation.json'
            next_observation=0
            def observe(event):
                trace['last_event']=event
                try:atomic_json(target,trace)
                except OSError:pass
            while True:
                if self.stopping or lease_health and (not lease_health['owned'] or lease_health['cancelled']):
                    raise ValueError('publication ownership lost while verification pending')
                tick=time.monotonic();event={'started_at':time.time(),'outcome':'in_flight'};trace['calls']+=1
                if tick>=next_observation:observe(event)
                try:response=self.publication_api.post(endpoint+'/complete',{**identity,'manifest_sha256':sha})
                except (APIError,OSError,ValueError) as error:
                    event.update(outcome='api_error' if isinstance(error,APIError) else 'transport_error',error_type=type(error).__name__,ended_at=time.time(),wall_seconds=time.monotonic()-tick)
                    if isinstance(error,APIError):event.update(status=error.status,state=error.body.get('state'))
                    trace['events']=(trace['events']+[event])[-64:];observe(event);raise
                pending=bool(response and (response.get('verification_pending') or response.get('state')=='verification_pending' or response.get('status')=='verification_pending'))
                event.update(outcome='verification_pending' if pending else 'completed',ended_at=time.time(),wall_seconds=time.monotonic()-tick)
                trace['events']=(trace['events']+[event])[-64:]
                if not pending or tick>=next_observation:observe(event);next_observation=time.monotonic()+1
                if not pending:return response
                if time.monotonic()>=deadline:raise ValueError('service verification publication deadline')
                time.sleep(min(.25,self.heartbeat))

        finally:
            done.set()
            if keeper:keeper.join(timeout=4)

    def read_output(self,container,target,payload,*,run_id=None,attempt_id=None):
        if shutil.disk_usage(self.root).free-self.output_bytes<self.min_free_bytes:raise OSError(28,'executor minimum free storage before handoff')
        process=subprocess.Popen(['docker','exec',container,'tar','-C','/output/run','-cf','-','.'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        expired=threading.Event()
        def cutoff(): expired.set();process.kill()
        timer=threading.Timer(self.transfer_seconds,cutoff);timer.start()
        archive_file=tempfile.TemporaryFile(dir=self.root)
        try:
            total_archive=0
            while True:
                chunk=process.stdout.read(min(1024*1024,self.output_bytes+1048577-total_archive))
                if not chunk:break
                total_archive+=len(chunk)
                if total_archive>self.output_bytes+1048576:
                    process.kill();raise ValueError('output transfer limit')
                archive_file.write(chunk)
            code=process.wait(timeout=3)
            if expired.is_set():raise ValueError('output transfer deadline')
            if code:raise ValueError('output archive command failed')
            archive_file.seek(0)
        except BaseException:
            archive_file.close()
            raise
        finally:
            timer.cancel();process.stdout.close()
            if process.poll() is None:process.kill();process.wait()
        target.mkdir(mode=0o700)
        compact=compact_payload(payload)
        dual_source=payload.get('kind') in ('dual-source','dual-source-replay')
        if dual_source:
            from importlib import import_module
            export=import_module('cpag_core.shared_export' if compact else 'cpag_core.replay_export' if payload.get('kind')=='dual-source-replay' else 'cpag_core.dual_source_export')
            DIRECTORIES=frozenset({'shared','sources'}) if compact else export.DIRECTORIES
            if payload.get('kind')=='dual-source-replay' and payload.get('history_format')=='replay-history-checkpoint-delta-2':DIRECTORIES=frozenset({'sources','history'})
            FILES=export.artifact_files_for_inputs(len(payload.get('networks') or [None]),mode='replay' if payload.get('kind')=='dual-source-replay' else 'offline') if compact else (export.artifact_files_for_inputs(len(payload.get('networks') or [None]),history_format=payload.get('history_format')) if payload.get('kind')=='dual-source-replay' else set(export.FILES)|{f"dual/sources/network-{i:03d}.pcap" for i in range(1,len(payload.get('networks') or [None]))})
        with archive_file, tarfile.open(fileobj=archive_file,mode='r:') as archive:
            total=0
            seen=set()
            for member in archive:
                if member.isdir() and member.name in ('.','./'): continue
                name=member.name.removeprefix('./')
                name=name.rstrip('/') if member.isdir() else name
                allowed_dir=dual_source and member.isdir() and name in DIRECTORIES
                allowed_file=member.isfile() and (name in FILES if dual_source else Path(name).name==name and name not in ('','manifest.json'))
                if name in seen or not (allowed_dir or allowed_file):
                    raise ValueError('unsafe output archive member')
                seen.add(name)
                if allowed_dir:
                    (target/name).mkdir(mode=0o700,parents=True,exist_ok=True)
                    continue
                total+=member.size
                if total>self.output_bytes: raise ValueError('output transfer limit')
                (target/name).parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with (target/name).open('xb') as stream:
                    shutil.copyfileobj(archive.extractfile(member),stream)
                    stream.flush();os.fsync(stream.fileno())
                self.checkpoint('during_copy')
        manifest=json.loads((target/'run_manifest.json').read_text())
        from cpag_core.contracts import validate
        manifest_schema='CompactStoreRunManifest' if compact else 'ReplaySpoolRunManifest' if payload.get('kind')=='dual-source-replay' and payload.get('history_format')=='replay-history-checkpoint-delta-2' else 'ReplayRunManifest' if payload.get('kind')=='dual-source-replay' else 'RunManifest'
        validate(manifest_schema,manifest)
        if payload.get('kind')=='dual-source-replay' and (manifest.get('history_format')!=payload.get('history_format') or manifest.get('replay_version')!=payload.get('replay_version')):raise ValueError('replay output version binding mismatch')
        if manifest['config_fingerprint']!=payload['config_fingerprint']: raise ValueError('configuration mismatch')
        if dual_source and (manifest['run_id']!=run_id or manifest['attempt_id']!=attempt_id):raise ValueError('dual-source run/attempt identity mismatch')
        expected=set(FILES)-{'run_manifest.json'} if dual_source else {'dataset.json','events.json','graph.json','quality.json'}
        if payload.get('kind')=='packet': expected.add('packet_observations.json')
        entries=manifest['artifacts']
        if {e['path'] for e in entries}!=expected or len(entries)!=len(expected): raise ValueError('artifact set differs')
        for entry in entries:
            path=beneath(target.resolve(),entry['path'])
            if digest(path)!=entry['sha256'] or path.stat().st_size!=entry['size_bytes']: raise ValueError('artifact hash/size mismatch')
            schema={'dataset.json':'DatasetManifest','graph.json':'ReplayGraphArtifact' if payload.get('kind')=='dual-source-replay' else 'GraphArtifact'}.get(path.name)
            if schema and not compact:
                value=json.loads(path.read_text());validate(schema,value)
                del value
            if path.name=='events.json' and not dual_source:
                for event in json.loads(path.read_text()):validate('NetworkEvent' if event['event_id'].startswith('packet-') or 'protocol' in event else 'ProcessObservation',event)
        if payload.get('kind')=='packet':
            from cpag_core.packet_job import verify_artifacts
            verify_artifacts(target,beneath(self.root,payload['network']['path']))
        if dual_source:
            if compact:
                # Source replay runs once in the service-owned constrained verifier.
                export._bound(target)
            else:export.verify_task(target)
            found={p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file()}
            if found!=FILES:raise ValueError('unexpected dual-source output file')
        elif {p.name for p in target.iterdir()}!=expected|{'run_manifest.json'}: raise ValueError('unexpected output file')
        publication={'config_fingerprint':payload['config_fingerprint'],
                     **publication_inputs(payload),
                     'artifacts':[{'path':p.relative_to(target).as_posix(),'sha256':digest(p),'size':p.stat().st_size}
                                  for p in sorted(target.rglob('*')) if p.is_file()]}
        if compact:publication.update(run_id=run_id,attempt_id=attempt_id)
        atomic_json(target/'manifest.json',publication);sync_dir(target)
        return digest(target/'manifest.json')
    def attempt(self,claim):
        attempt_started=time.monotonic()
        record=None;stage=None;owned=True;cancelled=False
        keep_done=threading.Event();keep_thread=None;lease_health={'owned':True,'cancelled':False,'phase':'execution'}
        self.validate_identity(claim)
        endpoint=self.endpoint(claim);identity={k:claim[k] for k in ('attempt','worker','token')}
        base=self.control/'jobs'/claim['id']/('attempt-'+str(claim['attempt'])+'.worker')
        base.mkdir(mode=0o700,parents=True,exist_ok=True)
        sync_dir(base.parent);sync_dir(base.parent.parent)
        owner=(base/'owner.lock').open('a+')
        try:fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:owner.close();return 'reconcile_required'
        if (base/'execution.json').exists():owner.close();return 'reconcile_required'
        try:
            self.capacity(claim)
            inputs=base/'inputs';inputs.mkdir()
            payload=claim['payload'];kind=payload.get('kind');compact=compact_payload(payload);network_arguments=[]
            if payload.get('resource_profile') != self.resource_profile:
                raise ValueError('operator resource profile differs from submitted run')
            refs=[('network' if i==0 else f'network-{i:03d}',r) for i,r in enumerate(network_refs(payload))]
            refs += [(name,payload[name]) for name in ('process','profile')]
            profile_path=None
            for name,ref in refs:
                source=beneath(self.root,ref['path'])
                if digest(source)!=ref['sha256']:raise ValueError('input hash mismatch')
                staged=inputs/(name+source.suffix)
                shutil.copyfile(source,staged)
                if digest(staged)!=ref['sha256']:raise ValueError('staged input hash mismatch')
                with staged.open('rb') as stream:os.fsync(stream.fileno())
                os.chmod(staged,0o444)
                if name.startswith('network'):network_arguments+=['--network','/inputs/'+staged.name]
                if name=='profile':profile_path=staged
            if kind=='dual-source-replay' and payload.get('history_format') is not None:
                if payload['history_format']!=('shared-observation-dag-6' if compact else 'replay-history-checkpoint-delta-2'):raise ValueError('unsupported replay history format')
                replay_profile=json.loads(profile_path.read_text()).get('replay',{})
                if replay_profile.get('version')!=payload.get('replay_version') or replay_profile.get('history_format')!=payload.get('history_format'):raise ValueError('replay payload/profile version binding mismatch')
            if compact:
                profile=json.loads(profile_path.read_text())
                for field in ('capacity_profile','storage_format','storage_budget_version'):
                    if profile.get(field)!=payload[field]:raise ValueError('compact payload/profile version binding mismatch')
            sync_dir(inputs);os.chmod(inputs,0o555)
            module='cpag_core.shared_cli' if compact else 'cpag_core.replay_export' if kind=='dual-source-replay' else 'cpag_core.dual_source_export' if kind=='dual-source' else 'cpag_core.packet_job' if kind=='packet' else 'cpag_core'
            command=self.command or ['python','-m',module]
            command=command+(['--action','export','--mode','replay' if kind=='dual-source-replay' else 'offline','--seconds',str(self.timeout)] if compact else [])+network_arguments+sum((["--"+name,"/inputs/"+name+Path(payload[name]['path']).suffix] for name in ('process','profile')),[])+[('--root' if compact else '--output'),'/output/run']+([] if compact else source_flag(profile_path,kind))
            if kind in ('dual-source','dual-source-replay'):command+=['--run-id',claim['id'],'--attempt-id',str(claim['attempt'])]
            if kind=='dual-source-replay' and not compact:command+=['--replay-version',payload['replay_version']]
            nonce=uuid.uuid4().hex
            atomic_json(base/'create-intent.json',{**self.identity(claim),'nonce':nonce,'location':self.location()})
            atomic_json(base/'resources.json',{'version':self.resource_profile or 'legacy-default','memory_bytes':self.memory_bytes,'cpus':self.cpus,'timeout_seconds':self.timeout,'output_bytes':self.output_bytes,'transfer_seconds':self.transfer_seconds,'cpu_seconds':self.cpu_seconds,'temporary_bytes':self.temporary_bytes,'publication_seconds':getattr(self.publication_api,'timeout',None)})
            compute_tmpfs=['--tmpfs','/tmp:rw,nosuid,nodev,size='+str(self.temporary_bytes)+',mode=1777'] if kind in ('dual-source','dual-source-replay') else []
            container=self.docker('create','--name','cpag-isolated-'+nonce,'--network','none','--read-only','--user','65532:65532',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--memory',str(self.memory_bytes),'--memory-swap',str(self.memory_bytes),
                '--cpus',self.cpus,'--pids-limit','64','--log-driver','local','--log-opt','max-size=64k','--log-opt','max-file=2',
                '--label','cpag.scope='+self.scope,'--label','cpag.managed=isolated-v1','--label','cpag.execution='+nonce,'--label','cpag.job='+claim['id'],'--label','cpag.attempt='+str(claim['attempt']),'--label','cpag.worker='+claim['worker'],
                '--mount','type=bind,src='+str(inputs)+',dst=/inputs,readonly',
                '--tmpfs','/output:rw,nosuid,nodev,size='+str(self.output_bytes)+',mode=1777',
                '--tmpfs','/runtime:rw,nosuid,nodev,size=1m,mode=1777',
                *compute_tmpfs,
                *(['--ulimit','cpu='+str(self.cpu_seconds)+':'+str(self.cpu_seconds)] if self.cpu_seconds else []),
                *(['-e','CPAG_PHASE_METRICS=/runtime/phases.jsonl'] if self.resource_profile and (kind=='dual-source' or compact) else []),
                *(['-e','CPAG_PHASE_STRATEGY=phase-resources-3'] if compact else []),
                '-e','CPAG_CONTAINER_SECONDS='+str(self.timeout),self.image,*command)
            self.checkpoint('after_create')
            record={**self.identity(claim),'container_id':container,'location':self.location()}
            atomic_json(base/'execution.json',record)
            self.checkpoint('before_register')
            self.coordinator_post(endpoint+'/execution',{k:v for k,v in record.items() if k!='id'})
            self.checkpoint('before_start')
            self.api.post(endpoint+'/heartbeat',{**identity,'lease_seconds':self.lease})
            self.docker('start',container)
            keep_thread=threading.Thread(target=self.keep_lease,args=(claim,keep_done,lease_health),daemon=True);keep_thread.start()
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
            if result:
                atomic_json(base/'compute-result.json',result)
                if self.resource_profile and (kind=='dual-source' or compact):
                    try:
                        rows=self.docker('exec',container,'cat','/runtime/phases.jsonl')
                        if len(rows.encode())>262144:raise ValueError('phase_measurement_limit')
                        atomic_json(base/'compute-phases.json',[json.loads(line) for line in rows.splitlines() if line])
                    except subprocess.CalledProcessError:
                        atomic_json(base/'compute-phases.json',{'unavailable':'image_has_no_phase_measurements'})
            if compact and result:
                script="import json,os;from pathlib import Path;r=Path('/sys/fs/cgroup');v={'cgroup_memory_peak_bytes':int((r/'memory.peak').read_text()),'cgroup_memory_current_bytes':int((r/'memory.current').read_text()),'cpu_stat':dict((k,int(v)) for k,v in (line.split() for line in (r/'cpu.stat').read_text().splitlines()))};v.update({name+'_bytes':sum(p.stat().st_size for p in Path(path).rglob('*') if p.is_file()) for name,path in [('tmp','/tmp'),('output','/output')]});print(json.dumps(v))"
                atomic_json(base/'compute-cgroup.json',json.loads(self.docker('exec',container,'python','-c',script)))
                atomic_json(base/'compute-inspect.json',self.inspect(container))
            if not result or result['returncode']!=0:raise CalculationFailure(result.get('returncode') if result else None,self.bounded_container_logs(container))
            output=beneath(self.root,claim['output_dir']);output.parent.mkdir(parents=True,exist_ok=True)
            stage=output.parent/('.handoff-'+uuid.uuid4().hex)
            atomic_json(base/'stage.json',{'path':str(stage.relative_to(self.root))})
            lease_health['phase']='handoff'
            sha=self.read_output(container,stage,claim['payload'],run_id=claim['id'],attempt_id=claim['attempt'])
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
            seal_handoff(stage,compact=compact)
            os.rename(stage,output);sync_dir(output.parent);stage=None
            self.checkpoint('after_publish')
            lease_health['phase']='publication'
            self.complete(claim,sha,lease_health=lease_health,deadline=attempt_started+2100 if compact else None)
            sync_dir(output);os.chmod(output,0o555);sync_dir(output.parent)
            atomic_json(base/'publication.json',{'manifest_sha256':sha,'output_dir':claim['output_dir']})
            return 'succeeded'
        except (OSError,ValueError,KeyError,APIError,subprocess.SubprocessError,RecoveryUnavailable) as error:
            try:atomic_json(base/'failure.json',{'error':str(error),'stderr':(getattr(error,'stderr',b'') or b'')[:65536].decode(errors='replace'),'output_streams':'combined_stdout_stderr' if isinstance(error,CalculationFailure) else 'stderr','compute_returncode':getattr(error,'compute_returncode',None),'failure_category':getattr(error,'failure_category',type(error).__name__)})
            except OSError:pass
            if record:
                try:self.stop_container(record)
                except (OSError,ValueError,APIError,subprocess.SubprocessError,RecoveryUnavailable):return 'lost_lease'
            if not record and claim.get('executor')=='isolated-v2':
                try:self.coordinator_post(endpoint+'/not-started',{**identity,'location':claim['location']})
                except (APIError,RecoveryUnavailable,OSError):return 'lost_lease'
            if (base/'handoff.json').exists():return 'reconcile_required'
            if owned and not self.stopping:
                try:self.api.post(endpoint+'/fail',{**identity,'message':str(error)[:1024],'retryable':True})
                except (OSError,ValueError,APIError):pass
            return 'failed'
        finally:
            keep_done.set()
            if keep_thread:keep_thread.join(timeout=4)
            if stage and stage.exists():
                os.chmod(stage,0o700)
                for path in stage.rglob('*'):
                    if path.is_dir():os.chmod(path,0o700)
                shutil.rmtree(stage)
            try:
                proof=base/'exit.json'
                removed=proof.exists() and json.loads(proof.read_text()).get('removed') is True
                if removed or not (base/'create-intent.json').exists():self.capacity(claim,settle=True)
            except (OSError,ValueError,KeyError,TypeError):pass
            owner.close()
    def once(self):
        location=self.location()
        claim=self.api.post('/v1/claim',{'worker':self.worker,'lease_seconds':self.lease,'executor':'isolated-v2','location':location})
        if claim and claim.get('id'):claim.update(executor='isolated-v2',location=location)
        return self.attempt(claim) if claim and claim.get('id') else 'idle'


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--enable-isolated-executor',action='store_true',required=True)
    parser.add_argument('--recover',action='store_true');parser.add_argument('--recover-job');parser.add_argument('--recovery-interval',type=float,default=0);args=parser.parse_args()
    if args.recovery_interval and (not args.recover or args.recovery_interval<1):parser.error('recovery interval requires --recover and at least 1 second')
    worker=DockerExecutor(API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN']),
        API(os.environ['CPAG_API_URL'],os.environ['CPAG_COORDINATOR_TOKEN']),os.environ['CPAG_SHARED_ROOT'],
        os.environ['CPAG_CONTROL_ROOT'],os.environ.get('CPAG_WORKER_ID','isolated-host'),host_budget_bytes=int(os.environ.get('CPAG_HOST_BUDGET_BYTES','1073741824')),min_free_bytes=int(os.environ.get('CPAG_MIN_FREE_BYTES','67108864')))
    signal.signal(signal.SIGTERM,worker.stop);signal.signal(signal.SIGINT,worker.stop)
    if args.recover:
        while not worker.stopping:
            result=worker.recover(args.recover_job);print(json.dumps(result),flush=True)
            code=75 if any(item.get('scope')=='global' for item in result) else 2 if any(item.get('pending') for item in result) else 0
            if not args.recovery_interval:return code
            deadline=time.monotonic()+args.recovery_interval
            while not worker.stopping and time.monotonic()<deadline:time.sleep(max(0,min(.2,deadline-time.monotonic())))
        return 0
    try:result=worker.once()
    except (OSError,APIError,subprocess.SubprocessError,RecoveryUnavailable):print('infrastructure unavailable; retry',flush=True);return 75
    print(result);return 0 if result in ('succeeded','idle','cancelled') else 75 if result in ('lost_lease','reconcile_required') else 1

if __name__=='__main__':raise SystemExit(main())
