"""Restartable initialization of project-private volumes; credentials never go to logs."""
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat

os.umask(0o077)
ROOT=Path('/bootstrap')
for name in ('api','worker','relay','postgres','shared','control','verify','verifier'):
    p=ROOT/name;p.mkdir(exist_ok=True)
    st=p.stat()
    if st.st_uid!=0:raise ValueError('private volume owner must be root: '+name)
    if stat.S_IMODE(st.st_mode)!=0o700:
        if any(p.iterdir()):raise ValueError('nonempty private volume mode must already be0700: '+name)
        p.chmod(0o700)

def atomic(name,value):
    target=ROOT/name;temp=target.with_name('.'+target.name+'.'+secrets.token_hex(8)+'.tmp')
    with temp.open('x') as out:
        out.write(value);out.flush();os.fchmod(out.fileno(),0o600);os.fsync(out.fileno())
    os.replace(temp,target)
    descriptor=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)

def private_json(name):
    p=ROOT/name
    if not p.exists():return None
    st=p.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o600:raise ValueError('private configuration permissions invalid: '+name)
    return json.loads(p.read_text())

lock=ROOT/'api'/'bootstrap.lock'
with lock.open('a+') as stream:
    lock.chmod(0o600);fcntl.flock(stream,fcntl.LOCK_EX)
    seed=private_json('api/seed.json')
    if seed is None:
        if (ROOT/'api'/'app.json').exists():raise ValueError('unseeded existing configuration: preserve private volumes and reconcile manually')
        token=lambda:secrets.token_hex(32)
        seed={'version':1,'postgres_password':token(),'worker_token':token(),'coordinator_token':token(),'admin_username':'admin','admin_password':token(),'deployment_id':secrets.token_hex(16)}
        atomic('api/seed.json',json.dumps(seed)+'\n')  # Durable before any derived file.
    identity=Path('/opt/cpag/verifier-source.identity').read_text().strip()
    if not re.fullmatch(r'source-sha256:[0-9a-f]{64}',identity):raise ValueError('baked verifier source identity absent or invalid')
    port=int(os.environ.get('CPAG_HTTP_PORT','3000'))
    if not 1<=port<=65535:raise ValueError('published port invalid')
    origin=os.environ.get('CPAG_EXTERNAL_ORIGIN','') or ('http://127.0.0.1' if port==80 else 'http://127.0.0.1:'+str(port))
    app=private_json('api/app.json') or {'database_url':'postgres://postgres:'+seed['postgres_password']+'@postgres:5432/cpag_v3?sslmode=disable','shared_root':'/state/shared','control_root':'/state/control','public_addr':'127.0.0.1:8095','internal_addr':'127.0.0.1:8094','worker_token':seed['worker_token'],'coordinator_token':seed['coordinator_token'],'bootstrap_admin_username':seed['admin_username'],'bootstrap_admin_password':seed['admin_password'],'static_root':'/opt/cpag/webui/out','python_bin':'python3','python_path':'/opt/cpag/services/analysis/src','resource_profile':'storage-budget-2','capacity_policy':'engineering-core-capacity-3','dispatch_mode':'poll'}
    app.update(compact_verifier_image=identity,external_origin=origin)
    worker=private_json('worker/config.json') or {key:app[key] for key in ('shared_root','control_root','worker_token','coordinator_token','resource_profile')}
    worker.update(api_url='http://cpag-resident-internal:8096',worker_id=worker.get('worker_id','compose-resident'),poll_seconds=worker.get('poll_seconds',1),runtime_backend='compose-pid1-v1',deployment_id=seed['deployment_id'])
    atomic('postgres/password',seed['postgres_password']+'\n')
    atomic('worker/config.json',json.dumps(worker,indent=2)+'\n')
    atomic('relay/worker.json',json.dumps({k:app[k] for k in ('worker_token','coordinator_token')})+'\n')
    atomic('verifier/source.identity',identity+'\n')
    atomic('api/app.json',json.dumps(app,indent=2)+'\n')
    (ROOT/'shared'/'jobs').mkdir(mode=0o700,exist_ok=True)
    atomic('api/bootstrap.json',json.dumps({'version':1,'deployment_id':seed['deployment_id'],'dispatch_mode':app['dispatch_mode'],'verifier_identity':identity})+'\n')
    print('CPAG v3 private configuration ready; existing credentials retained; local admin lookup documented')
