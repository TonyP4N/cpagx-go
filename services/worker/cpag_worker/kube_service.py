"""Resident EU worker. Its durable journal is private and contains attempt authority."""
import fcntl
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError

from .isolated import DockerExecutor, atomic_json, seal_handoff, sync_dir
from .kube_control import JobControl
from .kube_job import stage_attempt
from .service import read_config
from .worker import API, APIError, digest


def run(config):
    api = API(config['api_url'], config['worker_token'])
    coord = API(config['api_url'], config['coordinator_token'])
    root, control = Path(config['shared_root']), Path(config['control_root'])
    location = 'kubernetes:'+os.environ['CPAG_NAMESPACE_UID']
    worker = config['worker_id']
    helper = DockerExecutor(api, coord, root, control, worker, resource_profile=config['resource_profile'])
    kube = JobControl()
    journal = control/'kube-active.json'
    while True:
        if journal.exists():
            record = json.loads(journal.read_text())
            claim = record['claim']
        else:
            claim = api.post('/v1/claim', {'worker':worker, 'lease_seconds':90,
                             'executor':'kubernetes-job-v1','location':location})
            if not claim:
                time.sleep(2)
                continue
            record = {'claim':claim}
            atomic_json(journal,record)
        path = '/v1/jobs/'+claim['id']
        identity = {key:claim[key] for key in ('attempt','token','worker')}
        base = control/'jobs'/claim['id']/f"attempt-{claim['attempt']}.worker"
        base.mkdir(parents=True,exist_ok=True)
        try:
            state = api.post(path+'/heartbeat',{**identity,'lease_seconds':90})
        except APIError as error:
            if error.status==409 and error.body.get('state') in ('queued','failed','succeeded','cancelled') and (base/'exit.json').is_file():
                saved=json.loads((base/'exit.json').read_text())
                if saved.get('container_id')==record.get('uid') and saved.get('attempt')==claim['attempt'] and saved.get('token')==claim['token']:
                    os.replace(journal,base/'kube-fenced.json')
                    sync_dir(control)
                    continue
            raise
        name = 'cpag-'+claim['id']+'-'+str(claim['attempt'])
        if 'manifest' not in record:
            helper.capacity(claim)
            record['manifest'] = stage_attempt(root,claim,config['image'])
            atomic_json(journal,record)
        if 'uid' not in record:
            try:
                job = kube.create_suspended(record['manifest'])
            except HTTPError as exc:
                if exc.code!=409:raise
                job=kube.request('GET',kube.jobs+'/'+name)
                if not job['spec']['suspend'] or job['metadata']['labels']!=record['manifest']['metadata']['labels']:
                    raise ValueError('job conflict')
            record['uid']=job['metadata']['uid']
            atomic_json(journal,record)
        uid=record['uid']
        execution={**identity,'location':location,'container_id':uid}
        if not record.get('registered'):
            coord.post(path+'/execution',execution)
            record['registered']=True
            atomic_json(journal,record)
        job=kube.request('GET',kube.jobs+'/'+name)
        if job['metadata']['uid']!=uid:raise ValueError('job replaced')
        if state.get('state')=='cancelling':
            if not record.get('removing'):
                kube.remove(name,uid)
                record['removing']=True
                atomic_json(journal,record)
            raise RuntimeError('cancellation pending confirmed execution exit')
        if job['spec'].get('suspend'):
            kube.activate(job)
        if not any(c['type'] in ('Complete','Failed') and c['status']=='True'
                   for c in job.get('status',{}).get('conditions',[])):
            time.sleep(1)
            continue
        end=kube.observe_exit(name,uid,claim)
        proof={**execution,'scope':'kubernetes-job','exited':True,'kubernetes':end}
        atomic_json(base/'exit.json',{'id':claim['id'],**proof})
        coord.post(path+'/exit',proof)
        if end['exit_code']:
            api.post(path+'/fail',{**identity,'message':'compute exit '+str(end['exit_code']),'retryable':False})
        else:
            output=root/claim['output_dir']
            temp=output.with_name('.kube-handoff-'+uid)
            if not output.exists():
                source=root/'kube-staging'/claim['id']/str(claim['attempt'])/'output'/'run'
                if source.is_symlink():raise ValueError('invalid output root')
                sha=helper.read_archive(['tar','-C',str(source),'-cf','-','.'],temp,claim['payload'],claim['id'],claim['attempt'])
                seal_handoff(temp,compact=True)
                atomic_json(base/'handoff.json',{'output_dir':claim['output_dir'],'manifest_sha256':sha})
                os.rename(temp,output)
                sync_dir(output.parent)
            handoff=json.loads((base/'handoff.json').read_text())
            if digest(output/'manifest.json')!=handoff['manifest_sha256']:raise ValueError('handoff changed')
            helper.complete(claim,handoff['manifest_sha256'])
            atomic_json(base/'publication.json',handoff)
        helper.capacity(claim,settle=True)
        os.replace(journal,base/'kube-completed.json')
        sync_dir(control)


if __name__=='__main__':
    config=read_config(sys.argv[1])
    with (Path(config['control_root'])/'.kube-owner.lock').open('a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        run(config)
