"""Read-only compatibility drill on an isolated round20_legacy_replay_environment.
Enqueue exactly two legacy fixtures using the existing internal admission route.
Never supply a deployment root or production configuration to this validation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import time

import round16_acceptance as r
from round8_compatibility import inspect_history
from cpag_core.pipeline import canonical, file_hash


def dual_export(client,work):
    from dual_source_fixtures import make_case
    from round16_supplement import intake
    network, process, profile=make_case(work/('dual-export-'+secrets.token_hex(4)))
    dataset=client.expect('POST','/api/v3/datasets',{'name':'Compatibility export','source_kind':'synthetic','source':'generated','batch':'r21','authorization_ref':'software test only'},code=201)['dataset']['id']
    base='/api/v3/datasets/'+dataset
    for role,path in [('network',network),('process',process)]:
        r.upload(client,dataset,role,path,'r21-compat-'+role)
    admission=client.expect('POST',base+'/configs',{'kind':'intake','document':intake(dataset)},code=201)['config']['id']
    preflight=client.expect('POST',base+'/preflight',{'config_version_id':admission})
    cfg=client.expect('POST',base+'/configs',{'kind':'dual','document':json.loads(profile.read_text())},code=201)['config']['id']
    job=client.expect('POST','/api/v3/runs',{'dataset_id':dataset,'config_version_id':cfg,'preflight_id':preflight['preflight_id'],'mode':'dual_source'},code=201)['run']['id']
    status=r.status_until(client,job);assert status['state']=='succeeded' and status['attempt']==1
    path='/api/v3/runs/'+job
    members=client.expect('GET',path+'/artifacts')['artifacts']
    assert len(members)==11
    digests={}
    for m in members:
        data=client.expect('GET',path+'/artifacts/'+m['path']+'/download')
        digest=hashlib.sha256(data).hexdigest();assert digest==m['sha256']
        digests[m['path']]=digest
    for view in ['workspace','workbench']:
        assert client.request('GET','/'+view+'/')[0]==200
        assert len(client.expect('GET',path+'/artifacts')['artifacts'])==11
    return {'job_id':job,'attempt':1,'verified_downloads':digests,'retained_after_entry_switch':True}

def run(work,mode):
    state = json.loads((work/'state.json').read_text())
    if not state['pg_container'].startswith('cpag-r20-legacy-'):
        raise ValueError('an isolated validation instance is required')
    wc = json.loads((work/'worker-config.json').read_text())
    worker = r.Client(wc['api_url'])
    headers = {'Authorization': 'Bearer '+wc['worker_token'], 'Content-Type':'application/json'}
    public = r.Client(state['url'])
    public.expect('POST','/api/v3/session', {k:state[k] for k in ('username','password')})
    if mode=='dual': return {'dual_source':dual_export(public,work)}
    viewer = r.Client(state['url'])
    cred = {'username':'reader-'+secrets.token_hex(4),'password':secrets.token_urlsafe(24)}
    public.expect('POST','/api/v3/users',dict(cred,role='viewer'),code=201)
    viewer.expect('POST','/api/v3/session',cred)
    root=Path(state['source_root'])
    inputs=root/'inputs'/('r21-'+secrets.token_hex(4))
    inputs.mkdir()
    proc=inputs/'process.csv'
    shutil.copyfile(r.REPO/'tests/fixtures/synthetic/process.csv',proc)
    report={}
    for kind in ('normalized','packet'):
        if kind=='packet':
            network=inputs/'network.pcap'
            shutil.copyfile(r.REPO/'docs/refactor/validation-round4/protocol-synthetic.pcap',network)
            config={'synthetic':True,'adapter':'synthetic-packet-1'}
        else:
            network=inputs/'network.normalized.jsonl'
            shutil.copyfile(r.REPO/'tests/fixtures/synthetic/network.normalized.jsonl',network)
            config=json.loads((r.REPO/'profiles/synthetic-demo.json').read_text())
        profile=inputs/(kind+'.profile.json')
        profile.write_bytes(canonical(config)+b'\n')
        payload={name:{'path':path.relative_to(root).as_posix(),'sha256':file_hash(path)}
                 for name,path in [('network',network),('process',proc),('profile',profile)]}
        payload['config_fingerprint']=hashlib.sha256(canonical(config)).hexdigest()
        if kind=='packet':
            payload['kind']=kind
        job='r21-'+kind+'-'+secrets.token_hex(5)
        status,_=worker.request('POST','/v1/jobs',{'id':job,'max_attempts':1,'payload':payload},headers)
        assert status in (200,201),status
        for _ in range(240):
            value=worker.expect('GET','/v1/jobs/'+job,headers=headers)
            if value['state'] in ('failed','succeeded','cancelled'): break
            time.sleep(.25)
        assert value['state']=='succeeded',value.get('last_error')
        output=(root/value['artifact_path']).parent
        oracle=inspect_history(kind,output,network,proc)
        path='/api/v3/history/jobs/'+job+'/artifacts'
        items=public.expect('GET',path)['artifacts']
        member=path+'/graph.json/download'
        original=public.expect('GET',member)
        assert hashlib.sha256(original).hexdigest()==file_hash(output/'graph.json')
        assert viewer.request('GET',member)[0]==403
        assert r.Client(state['url']).request('GET',member)[0]==401
        assert public.request('POST',path,{})[0]==405
        assert public.request('GET',path+'/unexpected.json/download')[0]==404
        # Internal admission pins its own immutable copy. The staging file is
        # intentionally free to change after the operator submits the job.
        pinned=root/value['payload']['network']['path']
        assert pinned!=network and file_hash(pinned)==file_hash(network)
        mode=pinned.stat().st_mode & 0o777
        backup=pinned.read_bytes()
        try:
            pinned.chmod(0o600)
            pinned.write_bytes(bytes([backup[0]^1])+backup[1:])
            assert public.request('GET',member)[0]==409
        finally:
            pinned.write_bytes(backup)
            pinned.chmod(mode)
        before=public.expect('GET','/api/v3/runs/'+state['run_id']+'/result')
        for page in ['/workspace/','/workbench/']:
            assert public.request('GET',page)[0]==200
        assert public.expect('GET',member)==original
        assert public.expect('GET','/api/v3/runs/'+state['run_id']+'/result')==before
        report[kind]={'members':len(items),'graph_sha256':file_hash(output/'graph.json'),
                      'events':oracle['event_count'],'job_id':job,'attempt':value['attempt'],
                      'tamper':409,'ungranted':403,'anonymous':401,'read_only':405,
                      'unknown_member':404,'old_new_entry_rechecked':True}
    if mode=='all': report['dual_source']=dual_export(public,work)
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('validation_dir',type=Path)
    p.add_argument('--mode',choices=['all','classic','dual'],default='all')
    a=p.parse_args()
    print(json.dumps(run(a.validation_dir,a.mode),indent=2))
