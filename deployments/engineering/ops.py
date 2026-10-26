"""Offline Docker-host installation operations. Compute never sees this authority."""
import hashlib
import io
import tarfile
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from cpag_core.pipeline import run
from cpag_core.packet_job import run as packet_run
from cpag_worker.worker import digest
ROOT=Path(os.environ.get('CPAG_DATA_ROOT','/cpag-root/data'));PROJECT=os.environ.get('CPAG_PROJECT','cpag-engineering')
APP=os.environ.get('CPAG_APP_IMAGE','cpag-engineering:rc1');COMPUTE=os.environ.get('CPAG_COMPUTE_IMAGE','cpag-isolated:round7');PG='mirror.gcr.io/library/postgres:17.6-alpine'
def docker(*args,input=None):return subprocess.check_output(['docker',*args],input=input).decode().strip()
def config():return json.loads((ROOT/'config.json').read_text())
def env(c):return {'CPAG_ENABLE_M4':'1','CPAG_DATA_ROOT':str(ROOT),'CPAG_SHARED_ROOT':str(ROOT/'shared'),'CPAG_CONTROL_ROOT':str(ROOT/'control'),'CPAG_WORKER_TOKEN':c['worker_token'],'CPAG_COORDINATOR_TOKEN':c['coordinator_token'],'CPAG_COMPUTE_IMAGE':COMPUTE,'CPAG_JOB_API_ADDR':':8094','CPAG_API_URL':'http://'+PROJECT+'-api:8094','M4_DATABASE_URL':'postgres://postgres:'+c['database_password']+'@'+PROJECT+'-postgres:5432/m4_validation?sslmode=disable'}
def request(path,body=None):
    c=config();req=urllib.request.Request('http://127.0.0.1:18115'+path,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Bearer '+c['worker_token'],'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=5) as response:return json.load(response)
def init():
    ROOT.mkdir(parents=True,exist_ok=True)
    if (ROOT/'config.json').exists():return
    for name in ('shared','control'):(ROOT/name).mkdir(mode=0o700)
    c={name:secrets.token_hex(24) for name in ('worker_token','coordinator_token','database_password')}
    p=ROOT/'config.json';p.write_text(json.dumps(c));p.chmod(0o600)
    target=ROOT/'shared'/'samples';shutil.copytree('/app/samples',target)
    print('initialized',ROOT)
def inspect_optional(kind,name):
    result=subprocess.run(['docker',kind,'inspect',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if result.returncode==0:return json.loads(result.stdout)[0]
    docker('info','--format','{{.ID}}')
    if 'no such' in result.stderr.lower() or 'not found' in result.stderr.lower():return None
    raise RuntimeError(kind+' inspection failed: '+name)
def validate_pg(info,c,network):
    variables=dict(item.split('=',1) for item in info['Config']['Env'] if '=' in item)
    mounts=[m for m in info['Mounts'] if m['Destination']=='/var/lib/postgresql/data']
    if info['Config']['Image']!=PG or len(mounts)!=1 or mounts[0].get('Name')!=PROJECT+'-pg' or variables.get('POSTGRES_DB')!='m4_validation' or variables.get('POSTGRES_PASSWORD')!=c['database_password'] or network not in info['NetworkSettings']['Networks']:raise RuntimeError('existing PostgreSQL does not match this installation')
def stop(maintenance=False):
    docker('info','--format','{{.ID}}')
    c=config()
    for role in (('controller','recovery','evidence','api') if maintenance else ('controller','recovery','evidence','api','postgres')):
        name=PROJECT+'-'+role;info=inspect_optional('container',name)
        if info is None:continue
        if role=='postgres':validate_pg(info,c,PROJECT+'-internal')
        else:
            variables=dict(item.split('=',1) for item in info['Config']['Env'] if '=' in item)
            if variables.get('CPAG_DATA_ROOT')!=str(ROOT):raise RuntimeError('existing service belongs to another data root')
        docker('rm','-f',name)
def start():
    docker('info','--format','{{.ID}}');c=config();network=PROJECT+'-internal'
    net=inspect_optional('network',network)
    if net is None:docker('network','create','--label','cpag.engineering.project='+PROJECT,network);net=inspect_optional('network',network)
    if net['Driver']!='bridge' or net['Internal'] or net['Name']!=network or (net.get('Labels') or {}).get('cpag.engineering.project')!=PROJECT:raise RuntimeError('service network does not match installation')
    volume=inspect_optional('volume',PROJECT+'-pg')
    if volume is None:docker('volume','create','--label','cpag.engineering.project='+PROJECT,PROJECT+'-pg')
    elif volume['Driver']!='local' or volume['Name']!=PROJECT+'-pg' or (volume.get('Labels') or {}).get('cpag.engineering.project')!=PROJECT:raise RuntimeError('database volume does not match installation')
    info=inspect_optional('container',PROJECT+'-postgres')
    if info is not None:validate_pg(info,c,network);docker('start',PROJECT+'-postgres')
    else:docker('run','-d','--pull=never','--name',PROJECT+'-postgres','--label','cpag.engineering.project='+PROJECT,'--network',network,'-e','POSTGRES_PASSWORD='+c['database_password'],'-e','POSTGRES_DB=m4_validation','-v',PROJECT+'-pg:/var/lib/postgresql/data',PG)
    roles=[inspect_optional('container',PROJECT+'-'+role) for role in ('api','controller','recovery','evidence')]
    if any(roles):
        image=json.loads(docker('image','inspect',APP))[0]['Id']
        if all(info is not None and info['State']['Running'] and info['Image']==image and 'CPAG_DATA_ROOT='+str(ROOT) in info['Config']['Env'] for info in roles):print('already started',PROJECT);return
        raise RuntimeError('partial or different services exist; run maintenance before start')
    for _ in range(60):
        result=subprocess.run(['docker','exec',PROJECT+'-postgres','pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result.returncode==0:break
        time.sleep(.3)
    else:raise RuntimeError('database unavailable')
    docker('exec',PROJECT+'-postgres','psql','-v','ON_ERROR_STOP=1','-U','postgres','-d','m4_validation','-c','CREATE TABLE IF NOT EXISTS cpag_release_migrations(name text PRIMARY KEY,sha256 text NOT NULL);')
    for path in sorted(Path('/app/migrations').glob('*.sql')):
        sha=digest(path)
        found=docker('exec',PROJECT+'-postgres','psql','-At','-U','postgres','-d','m4_validation','-c',"SELECT sha256 FROM cpag_release_migrations WHERE name='"+path.name+"';")
        if found:
            if found!=sha:raise RuntimeError('migration hash mismatch: '+path.name)
            continue
        sql=b"BEGIN; SELECT pg_advisory_xact_lock(7140401);\n"+path.read_bytes()+b"\nINSERT INTO cpag_release_migrations(name,sha256) VALUES ('"+path.name.encode()+b"','"+sha.encode()+b"'); COMMIT;\n"
        docker('exec','-i',PROJECT+'-postgres','psql','-v','ON_ERROR_STOP=1','-U','postgres','-d','m4_validation',input=sql)
    common=['--label','cpag.engineering.project='+PROJECT,'--network',network,'--mount','type=bind,src='+str(ROOT)+',dst='+str(ROOT)]
    variables=env(c);args=sum((['-e',k+'='+v] for k,v in variables.items()),[])
    docker('run','-d','--pull=never','--name',PROJECT+'-api',*common,'-p','127.0.0.1:18115:8094',*args,APP,'/app/bin/job-api')
    for _ in range(60):
        try:request('/v1/jobs/offline-nonexistent');break
        except urllib.error.HTTPError as error:
            if error.code==404:break
        except OSError:pass
        time.sleep(.2)
    else:raise RuntimeError('API did not become ready')
    docker('run','-d','--pull=never','--name',PROJECT+'-recovery',*common,*args,APP,'/app/bin/recovery')
    docker('run','-d','--pull=never','--name',PROJECT+'-controller',*common,'-v','/var/run/docker.sock:/var/run/docker.sock',*args,APP,'python','/app/engineering/controller.py')
    docker('run','-d','--pull=never','--name',PROJECT+'-evidence',*common,'-p','127.0.0.1:18120:8095',*args,APP,'python','/app/engineering/evidence_service.py')
    print('started',PROJECT)
def demo():
    sample=ROOT/'shared'/'samples';records={}
    for kind in ('legacy','packet'):
        network=sample/('network.normalized.jsonl' if kind=='legacy' else 'protocol-synthetic.pcap');profile=sample/('synthetic-demo.json' if kind=='legacy' else 'packet-profile.json');process=sample/'process.csv'
        baseline=ROOT/('config-baseline-'+kind)
        if baseline.exists():shutil.rmtree(baseline)
        manifest=(run if kind=='legacy' else packet_run)(network,process,profile,baseline,synthetic=True)
        payload={role:{'path':str(path.relative_to(ROOT/'shared')),'sha256':digest(path)} for role,path in [('network',network),('process',process),('profile',profile)]}
        payload['config_fingerprint']=manifest['config_fingerprint']
        if kind=='packet':payload['kind']='packet'
        job='offline-'+kind+'-'+secrets.token_hex(6);request('/v1/jobs',{'id':job,'max_attempts':2,'payload':payload})
        for _ in range(180):
            status=request('/v1/jobs/'+job)
            if status['state'] in ('succeeded','failed','cancelled'):break
            time.sleep(.5)
        assert status['state']=='succeeded',status
        records[kind]={'job':job,'output_dir':str(Path(status['artifact_path']).parent),'network':status['payload']['network']['path'],'artifact_sha256':status['artifact_sha256']}
        print('PASS offline task',kind,job,flush=True)
    (ROOT/'demo-results.json').write_text(json.dumps(records,indent=2))
    return records
def check():
    records=json.loads((ROOT/'demo-results.json').read_text());c=config()
    for kind,record in records.items():assert request('/v1/jobs/'+record['job'])['state']=='succeeded'
    event=json.loads((ROOT/'shared'/records['packet']['output_dir']/'events.json').read_text())[0]['event_id']
    base='http://127.0.0.1:18120';headers={'Authorization':'Bearer '+c['worker_token']}
    with urllib.request.urlopen(urllib.request.Request(base+'/evidence?event='+event+'&field=cip.path',headers=headers)) as response:query=json.load(response)
    assert query['verified_fields']['cip.path']
    downloads={}
    for kind in ('legacy','packet'):
        with urllib.request.urlopen(urllib.request.Request(base+'/download?kind='+kind,headers=headers)) as response:data=response.read()
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            members={m.name:archive.extractfile(m).read() for m in archive if m.isfile()}
        publication=json.loads(members['manifest.json'])
        assert {e['path'] for e in publication['artifacts']}==set(members)-{'manifest.json'}
        for entry in publication['artifacts']:assert hashlib.sha256(members[entry['path']]).hexdigest()==entry['sha256'] and len(members[entry['path']])==entry['size']
        assert hashlib.sha256(members['manifest.json']).hexdigest()==records[kind]['artifact_sha256']
        (ROOT/('downloaded-'+kind+'-results.tar.gz')).write_bytes(data)
        downloads[kind]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'verified_files':len(members)}
    refusals=[]
    legacy_output=ROOT/'shared'/records['legacy']['output_dir']
    candidates=[('legacy_missing_artifact',legacy_output/'events.json','missing','legacy'),('legacy_tampered_artifact',legacy_output/'graph.json','tamper','legacy'),('legacy_tampered_original',ROOT/'shared'/records['legacy']['network'],'tamper','legacy'),('packet_tampered_published_wrapper',ROOT/'shared'/request('/v1/jobs/'+records['packet']['job'])['artifact_path'],'tamper','packet')]
    for label,path,fault,kind in candidates:
        original=path.read_bytes();renamed=path.with_name(path.name+'.fault-test')
        try:
            if fault=='missing':path.rename(renamed)
            else:path.write_bytes(original+b' ')
            try:urllib.request.urlopen(urllib.request.Request(base+'/download?kind='+kind,headers=headers),timeout=5)
            except urllib.error.HTTPError as error:assert error.code==409;refusals.append(label)
            else:raise AssertionError('invalid publication was downloadable: '+label)
        finally:
            if fault=='missing':renamed.rename(path)
            else:path.write_bytes(original)
    result={'task_states':'succeeded','packet_query_slices':len(query['verified_fields']['cip.path']),'downloads':downloads,'negative_download_refusals':refusals}
    (ROOT/'offline-check.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
ROOT.mkdir(parents=True,exist_ok=True)
with (ROOT/'ops.lock').open('a+') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    command=sys.argv[1]
    if command=='install':init()
    elif command=='start':start()
    elif command=='stop':stop()
    elif command=='maintenance':stop(True)
    elif command=='restart':stop();start()
    elif command=='demo':demo()
    elif command=='check':check()
    else:raise SystemExit('unknown operation')
