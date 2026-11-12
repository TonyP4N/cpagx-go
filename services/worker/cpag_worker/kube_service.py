"""Durable Kubernetes attempt owner; failures retain evidence, never publication rights."""
import fcntl
import json
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote

from .isolated import DockerExecutor, atomic_json, seal_handoff, sync_dir
from .kube_control import JobControl
from .kube_exit import termination
from .kube_job import stage_attempt
from .service import read_config
from .worker import API, APIError, digest


def matches(expected, actual):
    """API defaulted fields may be added; requested execution fields may not change."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and matches(v, actual[k]) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(expected) == len(actual) and all(matches(a,b) for a,b in zip(expected,actual))
    return expected == actual


class KubernetesWorker:
    def __init__(self, config):
        self.config = config
        self.api = API(config['api_url'], config['worker_token'])
        self.coord = API(config['api_url'], config['coordinator_token'])
        self.root, self.control = Path(config['shared_root']), Path(config['control_root'])
        self.location = 'kubernetes:'+os.environ['CPAG_NAMESPACE_UID']
        self.worker = config['worker_id']
        self.helper = DockerExecutor(self.api,self.coord,self.root,self.control,self.worker,
                                     resource_profile=config['resource_profile'],lease=90,heartbeat=5)
        self.kube = JobControl()
        self.journal = self.control/'kube-active.json'

    def save(self, record):
        atomic_json(self.journal,record)

    def status(self, claim):
        return self.helper.get_json(self.api,'/v1/jobs/'+claim['id'])

    def recover_claim(self):
        # Includes a claim whose HTTP response or first journal write was lost.
        rows = self.helper.get_json(self.coord,'/v1/executions?location='+quote(self.location,safe=''))
        for row in rows:
            if row['worker'] != self.worker:
                continue
            st = self.status(row)
            claim = {k:row[k] for k in ('id','attempt','worker','token')}
            claim.update(payload=st['payload'],output_dir=f"jobs/{row['id']}/attempt-{row['attempt']}")
            record = {'claim':claim,'failure':'recovered attempt without owner journal','create_requested':True}
            if row['container_id']:
                record.update(uid=row['container_id'],registered=True,activation_requested=True)
            self.save(record)
            return record
        return None

    def finish(self, record, base):
        self.helper.capacity(record['claim'],settle=True)
        os.replace(self.journal,base/'kube-completed.json')
        sync_dir(base);sync_dir(self.control)

    def settle(self, record, base, st):
        """Record actual exit or fenced non-start before clearing the owner journal."""
        c=record['claim']; identity={k:c[k] for k in ('attempt','token','worker')}
        path='/v1/jobs/'+c['id']; name=f"cpag-{c['id']}-{c['attempt']}"
        proof_path=base/'exit.json'
        if proof_path.exists():
            proof=json.loads(proof_path.read_text())
            if any(proof.get(k)!=c[k] for k in ('id','attempt','token','worker')):
                raise ValueError('exit receipt identity mismatch')
            if proof.get('scope')=='not-started':
                self.coord.post(path+'/not-started',{**identity,'location':self.location})
            else:
                self.coord.post(path+'/exit',{k:v for k,v in proof.items() if k!='id'})
                self.kube.release_exit(proof['container_id'])
        else:
            job=self.kube.get(name) if record.get('create_requested') or record.get('uid') else None
            if job is None and not record.get('uid'):
                # Registration is atomically revoked, including ambiguous create responses.
                self.coord.post(path+'/not-started',{**identity,'location':self.location})
                proof={'id':c['id'],**identity,'scope':'not-started','location':self.location,'start_revoked':True}
            elif job is None and record.get('never_activated') == {'job_uid':record['uid'],'suspended':True,'no_pods':True} and not self.kube.pods(record['uid']):
                end={'version':'kubernetes-not-started-1','run_id':c['id'],'attempt':c['attempt'],
                     'worker':c['worker'],'namespace':'cpag','job_uid':record['uid'],'removed':True,'suspended':True,
                     'finished_at':datetime.now(timezone.utc).isoformat()}
                proof={'id':c['id'],**identity,'location':self.location,'container_id':record['uid'],
                       'scope':'kubernetes-job','exited':True,'kubernetes':end}
            elif job is None:
                # A missing previously registered Job is not proof that its process exited.
                raise ValueError('registered job missing without exit evidence')
            else:
                uid=record.get('uid')
                if uid and uid!=job['metadata']['uid']:
                    raise ValueError('replacement job cannot prove termination')
                expected={'cpag.job':c['id'],'cpag.attempt':str(c['attempt']),'cpag.worker':c['worker']}
                if not expected.items()<=job['metadata'].get('labels',{}).items():
                    raise ValueError('foreign job identity')
                uid=job['metadata']['uid'];record['uid']=uid;self.save(record)
                pods=self.kube.pods(uid)
                if job['spec'].get('suspend') and not record.get('activation_requested') and not pods:
                    # Persist the pre-deletion observation. Never interpret a bare 404 as exit.
                    record['never_activated']={'job_uid':uid,'suspended':True,'no_pods':True}
                    self.save(record)
                    self.kube.remove(name,uid)
                    if self.kube.get(name) is not None or self.kube.pods(uid):
                        return 'stopping'
                    end={'version':'kubernetes-not-started-1','run_id':c['id'],'attempt':c['attempt'],
                         'worker':c['worker'],'namespace':'cpag','job_uid':uid,'removed':True,'suspended':True,
                         'finished_at':datetime.now(timezone.utc).isoformat()}
                else:
                    self.kube.stop(job)
                    try:
                        end=termination(job,pods,job_uid=uid,run_id=c['id'],attempt=c['attempt'],worker=c['worker'])
                    except ValueError:
                        return 'stopping'
                proof={'id':c['id'],**identity,'location':self.location,'container_id':uid,
                       'scope':'kubernetes-job','exited':True,'kubernetes':end}
            atomic_json(proof_path,proof)
            return self.settle(record,base,self.status(c))
        # Re-read after the proof RPC; cancellation can win while computation exits.
        st=self.status(c)
        if st['attempt']==c['attempt'] and st['state']=='cancelling':
            try:self.api.post(path+'/ack-cancel',identity)
            except APIError as error:
                if error.status==409:return 'waiting_for_verifier_exit'
                raise
        elif st['attempt']==c['attempt'] and st['state']=='running' and st.get('lease_valid'):
            self.api.post(path+'/fail',{**identity,'message':record.get('failure','execution stopped'),'retryable':False})
        self.finish(record,base)
        return 'settled'

    def once(self):
        record=json.loads(self.journal.read_text()) if self.journal.exists() else self.recover_claim()
        if record is None:
            claim=self.api.post('/v1/claim',{'worker':self.worker,'lease_seconds':90,
                                           'executor':'kubernetes-job-v1','location':self.location})
            if not claim:return 'idle'
            record={'claim':claim};self.save(record)
        c=record['claim'];identity={k:c[k] for k in ('attempt','token','worker')}
        path='/v1/jobs/'+c['id'];name=f"cpag-{c['id']}-{c['attempt']}"
        base=self.control/'jobs'/c['id']/f"attempt-{c['attempt']}.worker"
        base.mkdir(parents=True,exist_ok=True)
        st=self.status(c)
        if st['attempt']!=c['attempt'] or st['state']!='running' or not st.get('lease_valid') or record.get('failure'):
            return self.settle(record,base,st)
        try:self.api.post(path+'/heartbeat',{**identity,'lease_seconds':90})
        except APIError as error:
            if error.status==409:return self.settle(record,base,self.status(c))
            raise
        # A lease keeper also covers staging and output handoff, not just publication.
        done=threading.Event();health={'owned':True,'cancelled':False,'phase':'kubernetes_attempt'}
        keeper=threading.Thread(target=self.helper.keep_lease,args=(c,done,health),daemon=True)
        try:
            if 'manifest' not in record:
                self.helper.capacity(c)
            keeper.start()
            if 'manifest' not in record:
                record['manifest']=stage_attempt(self.root,c,self.config['image']);self.save(record)
            if 'uid' not in record:
                record['create_requested']=True;self.save(record)
                job=self.kube.get(name)
                if job is None:job=self.kube.create_suspended(record['manifest'])
                if not matches(record['manifest'],job):raise ValueError('job specification conflict')
                record['uid']=job['metadata']['uid'];self.save(record)
            uid=record['uid'];execution={**identity,'location':self.location,'container_id':uid}
            if not record.get('registered'):
                self.coord.post(path+'/execution',execution);record['registered']=True;self.save(record)
            job=self.kube.get(name)
            if job is None or job['metadata']['uid']!=uid:raise ValueError('registered job replaced or missing')
            if job['spec'].get('suspend'):
                self.api.post(path+'/heartbeat',{**identity,'lease_seconds':90})
                if not health['owned'] or health['cancelled']:return 'ownership_changed'
                record['activation_requested']=True;self.save(record)
                self.kube.activate(job)
                return 'running'
            if not any(x['type'] in ('Complete','Failed') and x['status']=='True' for x in job.get('status',{}).get('conditions',[])):
                return 'running'
            if (base/'exit.json').exists():
                proof=json.loads((base/'exit.json').read_text())
                if any(proof.get(k)!=c[k] for k in ('id','attempt','worker','token')) or proof.get('container_id')!=uid:
                    raise ValueError('exit receipt identity mismatch')
                end=proof['kubernetes']
            else:
                end=self.kube.observe_exit(name,uid,c)
                proof={'id':c['id'],**execution,'scope':'kubernetes-job','exited':True,'kubernetes':end}
                atomic_json(base/'exit.json',proof)
            self.coord.post(path+'/exit',{k:v for k,v in proof.items() if k!='id'})
            self.kube.release_exit(uid)
            if end['exit_code']:
                record['failure']='compute exit '+str(end['exit_code']);self.save(record)
                return 'exited_with_error'
            output=self.root/c['output_dir'];temp=output.with_name('.kube-handoff-'+uid)
            if not output.exists():
                source=self.root/'kube-staging'/c['id']/str(c['attempt'])/'output'/'run'
                if source.is_symlink():raise ValueError('invalid output root')
                sha=self.helper.read_archive(['tar','-C',str(source),'-cf','-','.'],temp,c['payload'],c['id'],c['attempt'])
                seal_handoff(temp,compact=True)
                atomic_json(base/'handoff.json',{'output_dir':c['output_dir'],'manifest_sha256':sha})
                os.rename(temp,output);sync_dir(output.parent)
            handoff=json.loads((base/'handoff.json').read_text())
            if digest(output/'manifest.json')!=handoff['manifest_sha256']:raise ValueError('handoff changed')
            self.helper.complete(c,handoff['manifest_sha256'],lease_health=health)
            atomic_json(base/'publication.json',handoff)
            self.finish(record,base)
            return 'published'
        except APIError as error:
            if error.status==409:return 'ownership_changed'
            raise
        except (ValueError,OSError) as error:
            if self.helper.stopping:
                return 'stopping' # Preserve the journal for a graceful process restart.
            # Infrastructure transport errors must be retried, not recast as input failures.
            if isinstance(error,HTTPError) or getattr(error,'reason',None) is not None:raise
            record['failure']=type(error).__name__+': '+str(error)[:240]
            self.save(record)
            return 'failure_recorded'
        finally:
            done.set()
            if keeper.ident is not None:keeper.join(timeout=5)


def run(config):
    owner=KubernetesWorker(config);stopped=threading.Event()
    def stop(*_):stopped.set();owner.helper.stop()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    # Shared with Go and terminal backup: maintenance cannot race an active owner.
    with (owner.control/'.maintenance.lock').open('a+') as maintenance, (owner.control/'.kube-owner.lock').open('a+') as lock:
        fcntl.flock(maintenance,fcntl.LOCK_SH|fcntl.LOCK_NB)
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        while not stopped.is_set():
            try:
                result=owner.once()
                if result not in ('idle','running'):print(json.dumps({'event':'kube_attempt','result':result}),flush=True)
            except Exception as error:
                # Never log API exception bodies: they may contain attempt authority.
                print(json.dumps({'event':'kube_recovery_pending','error_type':type(error).__name__}),flush=True)
            stopped.wait(config.get('poll_seconds',1))


if __name__=='__main__':
    run(read_config(sys.argv[1]))
