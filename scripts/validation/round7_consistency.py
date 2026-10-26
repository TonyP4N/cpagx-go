#!/usr/bin/env python3
"""Finite synthetic executor consistency check; never enables default deployment."""
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'services/analysis/src'),str(REPO/'services/worker')]
from cpag_core.contracts import validate
from cpag_core.evidence import EvidenceIndex
from cpag_core.pipeline import run,canonical,fingerprint,file_hash
from cpag_core.packet_job import verify_artifacts as verify_packet,query_evidence
from cpag_worker.worker import API,Worker
from cpag_worker.isolated import DockerExecutor

NAMES={'dataset.json','events.json','graph.json','quality.json','run_manifest.json'}


def require(condition,reason):
    if not condition:raise ValueError(reason)


def differences(left,right,path=''):
    if type(left) is not type(right):return [path or '/']
    if isinstance(left,dict):
        out=[]
        for key in sorted(left.keys()|right.keys()):
            next_path=path+'/'+key
            out.extend([next_path] if key not in left or key not in right else differences(left[key],right[key],next_path))
        return out
    if isinstance(left,list):
        if len(left)!=len(right):return [path]
        return [p for i,(a,b) in enumerate(zip(left,right)) for p in differences(a,b,path+'/'+str(i))]
    return [] if left==right else [path]


def load_run(output,root,payload,expected_names=None):
    output,root=Path(output),Path(root)
    read=lambda name:json.loads((output/name).read_text())
    data={name:read(name) for name in NAMES}
    wrapper=read('manifest.json')
    require(len(wrapper['artifacts'])==len(NAMES) and {a['path'] for a in wrapper['artifacts']}==NAMES,'wrapper membership mismatch')
    for artifact in wrapper['artifacts']:
        target=output/artifact['path']
        require(file_hash(target)==artifact['sha256'] and target.stat().st_size==artifact['size'],'publication file hash/size mismatch')
    require(wrapper['inputs']=={role:payload[role]['sha256'] for role in ('network','process','profile')},'wrapper source mismatch')
    require(wrapper['config_fingerprint']==payload['config_fingerprint'],'wrapper configuration mismatch')
    for schema,name in [('DatasetManifest','dataset.json'),('GraphArtifact','graph.json'),('RunManifest','run_manifest.json')]:validate(schema,data[name])
    core=data['run_manifest.json']
    require(len(core['artifacts'])==4 and {a['path'] for a in core['artifacts']}==NAMES-{'run_manifest.json'},'core membership mismatch')
    for artifact in core['artifacts']:
        target=output/artifact['path']
        require(file_hash(target)==artifact['sha256'] and target.stat().st_size==artifact['size_bytes'],'core file hash/size mismatch')
    require(core['result_hashes']=={'events':fingerprint(data['events.json']),'graph':fingerprint(data['graph.json'])},'result fingerprint mismatch')
    require(core['config_fingerprint']==payload['config_fingerprint'],'core config mismatch')
    profile=json.loads((root/payload['profile']['path']).read_text())
    require(hashlib.sha256(canonical(profile)).hexdigest()==payload['config_fingerprint'],'profile bytes/config mismatch')
    indexes={}
    dataset=data['dataset.json']
    require(len(dataset['files'])==2 and {f['kind'] for f in dataset['files']}=={'network','process'},'dataset role mismatch')
    for role in ('network','process','profile'):
        source=root/payload[role]['path']
        require(file_hash(source)==payload[role]['sha256'],'input bytes changed')
        if role=='profile':continue
        entry=next(f for f in dataset['files'] if f['kind']==role)
        require(entry=={'name':(expected_names or {}).get(role,source.name),'sha256':payload[role]['sha256'],'size_bytes':source.stat().st_size,'kind':role},'dataset snapshot filename/source metadata mismatch')
        indexes[payload[role]['sha256']]=EvidenceIndex(source,payload[role]['sha256'])
    input_fp=fingerprint([{k:v for k,v in entry.items() if k!='name'} for entry in dataset['files']])
    require(core['input_fingerprint']==data['graph.json']['input_fingerprint']==input_fp,'input fingerprint mismatch')
    evidence=[]
    for event in data['events.json']:
        validate('NetworkEvent' if 'protocol' in event else 'ProcessObservation',event)
        ref=event['source_ref'];require(ref['file_sha256'] in indexes,'unknown evidence source')
        source=indexes[ref['file_sha256']];original=source.resolve(ref)
        if source.path.suffix=='.csv':require(original[profile['timestamp_column']]==ref['raw_time'],'CSV evidence raw time mismatch')
        evidence.append({'event_id':event['event_id'],'source_ref':ref,'original_record':original})
    for node in data['graph.json']['nodes']:
        for ref in node['evidence_refs']:indexes[ref['file_sha256']].resolve(ref)
    for source in indexes.values():source.verify()
    return data,wrapper,evidence


def compare_runs(legacy,isolated,root,legacy_payload,isolated_payload,expected_python,expected_names=None):
    loaded=[]
    for label,output,payload in [('legacy',legacy,legacy_payload),('isolated',isolated,isolated_payload)]:
        data,wrapper,evidence=load_run(output,root,payload,(expected_names or {}).get(label))
        require(data['run_manifest.json']['tool_versions']['python']==expected_python[label],label+' runtime version differs from observed environment')
        uuid.UUID(data['run_manifest.json']['run_id'])
        loaded.append((data,wrapper,evidence))
    a,b=loaded
    raw_equal={name:(Path(legacy)/name).read_bytes()==(Path(isolated)/name).read_bytes() for name in NAMES}
    for name in ('events.json','graph.json','quality.json'):
        require(raw_equal[name],name+' differs byte-for-byte')
    require(canonical(a[2])==canonical(b[2]),'resolved evidence records differ')
    allowed={};observed={};observed_values={}
    def compare_json(name,left,right,paths):
        changed=differences(left,right)
        require(set(changed)<=set(paths),name+' unexpected differences: '+','.join(set(changed)-set(paths)))
        allowed[name]=paths;observed[name]=changed
        def lookup(value,pointer):
            for key in pointer.strip('/').split('/'):value=value[int(key)] if isinstance(value,list) else value[key]
            return value
        observed_values[name]=[{'path':pointer,'legacy':lookup(left,pointer),'isolated':lookup(right,pointer)} for pointer in changed]
    # These exact names are independently bound to the API's per-job immutable
    # input snapshot paths by load_run. No source bytes/hash/ref is ignored.
    compare_json('dataset.json',a[0]['dataset.json'],b[0]['dataset.json'],['/files/0/name','/files/1/name'])
    core_paths=['/run_id','/tool_versions/python']
    for i,entry in enumerate(a[0]['run_manifest.json']['artifacts']):
        if entry['path']=='dataset.json':core_paths += ['/artifacts/'+str(i)+'/sha256','/artifacts/'+str(i)+'/size_bytes']
    compare_json('run_manifest.json',a[0]['run_manifest.json'],b[0]['run_manifest.json'],core_paths)
    wrapper_paths=[]
    for i,entry in enumerate(a[1]['artifacts']):
        if entry['path'] in ('dataset.json','run_manifest.json'):
            wrapper_paths += ['/artifacts/'+str(i)+'/sha256','/artifacts/'+str(i)+'/size']
    compare_json('manifest.json',a[1],b[1],wrapper_paths)
    require(len(a[0]['events.json'])==8,'fixture must retain two network and six process events')
    require(any('\n' in entry['original_record'].get('note','') for entry in a[2]),'multiline CSV evidence lost')
    return {'valid':True,'raw_equal':raw_equal,'allowed_exact_difference_paths':allowed,
            'observed_difference_paths':observed,'observed_difference_values':observed_values,'event_count':len(a[0]['events.json']),
            'resolved_evidence_equal':True,'resolved_evidence_sha256':hashlib.sha256(canonical(a[2])).hexdigest(),
            'artifact_sha256':{label:{name:file_hash(Path(directory)/name) for name in sorted(NAMES|{'manifest.json'})}
                               for label,directory in [('legacy',legacy),('isolated',isolated)]},
            'wrapper_serialization':{'legacy_trailing_lf':(Path(legacy)/'manifest.json').read_bytes().endswith(b'\n'),
                                     'isolated_trailing_lf':(Path(isolated)/'manifest.json').read_bytes().endswith(b'\n')},
            'observed_python_versions':expected_python,
            'observed_dataset_names':{label:{f['kind']:f['name'] for f in loaded[i][0]['dataset.json']['files']} for i,label in enumerate(('legacy','isolated'))},
            'normalization_boundary':'Only the listed exact JSON paths; linked hash/size values independently checked against actual artifacts.'}


def host_source_hashes():
    analysis=REPO/'services/analysis/src'
    return {'analysis_files':{p.relative_to(analysis).as_posix():file_hash(p) for p in sorted((analysis/'cpag_core').rglob('*.py'))},
            'schema_files':{p.name:file_hash(p) for p in sorted((REPO/'schemas').glob('*.json'))},
            'container_entry_sha256':file_hash(REPO/'services/worker/cpag_worker/container_entry.py')}


def verify_image_sources(observed):
    expected=host_source_hashes()
    for group,value in expected.items():require(observed.get(group)==value,'compute image '+group+' differs from host checkout')
    return expected


IMAGE_PROBE = r"""import hashlib,json,platform
from pathlib import Path
from zoneinfo import ZoneInfo
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
analysis=Path('/app/services/analysis/src')
def zone(name):
 try:ZoneInfo(name);return True
 except Exception:return False
print(json.dumps({'python':platform.python_version(),'system':platform.system(),'machine':platform.machine(),
'analysis_files':{p.relative_to(analysis).as_posix():sha(p) for p in sorted((analysis/'cpag_core').rglob('*.py'))},
'schema_files':{p.name:sha(p) for p in sorted(Path('/app/schemas').glob('*.json'))},
'container_entry_sha256':sha(Path('/app/entry.py')),
'zoneinfo_available':{name:zone(name) for name in ('UTC','America/New_York')}}))"""


def execute(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)


def main():
    report=Path(os.environ.get('CPAG_CONSISTENCY_REPORT_DIR',str(REPO/'docs/refactor/validation-round7')))
    report.mkdir(parents=True,exist_ok=True)
    validation_run=uuid.uuid4().hex;phase='setup'
    (report/'consistency-summary.json').write_text(json.dumps({'valid':False,'validation_run_id':validation_run,'phase':phase})+'\n')
    pg_name='cpag-round7-consistency-pg';pg_port='55457';api_port='18127'
    image=os.environ.get('CPAG_CONSISTENCY_IMAGE','cpag-consistency:round7')
    pg_image='mirror.gcr.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94'
    with tempfile.TemporaryDirectory(prefix='cpag-round7-consistency-') as temporary:
        work=Path(temporary);shared=work/'shared';control=work/'control';shared.mkdir();control.mkdir()
        created=False;server=None
        try:
            execute('docker','run','--name',pg_name,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=synthetic-consistency-only',
                    '-p','127.0.0.1:'+pg_port+':5432',pg_image,stdout=subprocess.DEVNULL);created=True
            for _ in range(100):
                if subprocess.run(['docker','exec',pg_name,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
                time.sleep(.1)
            else:raise ValueError('database readiness timeout')
            for path in sorted((REPO/'internal/jobs/migrations').glob('*.sql')):
                with path.open('rb') as source:execute('docker','exec','-i',pg_name,'psql','-U','postgres','-d','m4_validation','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
            env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(REPO/'services/worker'),str(REPO/'services/analysis/src')]),
                     GOCACHE=os.environ.get('GOCACHE',str(Path(tempfile.gettempdir())/'cpag-go-build')),
                     GOMODCACHE=os.environ.get('GOMODCACHE',str(Path(tempfile.gettempdir())/'cpag-go-mod')))
            execute('go','build','-o',str(work/'api'),'./cmd/m4-job-api',cwd=REPO/'internal/jobs/integration',env=env)
            if os.environ.get('CPAG_CONSISTENCY_SKIP_BUILD')!='1':
                execute('docker','build','-t',image,'-f',str(REPO/'deployments/isolated-executor/Dockerfile'),str(REPO))
            image_id=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',image],text=True).strip()
            runtime=json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--entrypoint','python',image_id,
                    '-c',IMAGE_PROBE],text=True))
            source_identity=verify_image_sources(runtime)
            env.update(CPAG_ENABLE_M4='1',CPAG_SHARED_ROOT=str(shared),CPAG_CONTROL_ROOT=str(control),
                       CPAG_WORKER_TOKEN=secrets.token_urlsafe(32),CPAG_COORDINATOR_TOKEN=secrets.token_urlsafe(32),
                       CPAG_JOB_API_ADDR='127.0.0.1:'+api_port,
                       M4_DATABASE_URL='postgres://postgres:synthetic-consistency-only@127.0.0.1:'+pg_port+'/m4_validation?sslmode=disable')
            os.environ['PYTHONPATH']=env['PYTHONPATH']
            with (work/'api.log').open('w') as log:server=subprocess.Popen([str(work/'api')],env=env,stdout=log,stderr=subprocess.STDOUT)
            api=API('http://127.0.0.1:'+api_port,env['CPAG_WORKER_TOKEN']);coordinator=API(api.url,env['CPAG_COORDINATOR_TOKEN'])
            for _ in range(100):
                if server.poll() is not None:raise ValueError('API exited')
                try:api.post('/v1/claim',{'worker':'readiness','lease_seconds':2});break
                except OSError:time.sleep(.1)
            else:raise ValueError('API readiness timeout')
            def status(job):
                request=urllib.request.Request(api.url+'/v1/jobs/'+job,headers={'Authorization':'Bearer '+api.token})
                with urllib.request.urlopen(request,timeout=3) as source:return json.load(source)
            inputs=shared/'inputs';inputs.mkdir(exist_ok=True);payload={}
            for role,source in [('network',REPO/'tests/fixtures/synthetic/network.normalized.jsonl'),('process',REPO/'tests/fixtures/synthetic/process.csv'),('profile',REPO/'profiles/synthetic-demo.json')]:
                target=inputs/(role+source.suffix);shutil.copyfile(source,target)
                payload[role]={'path':target.relative_to(shared).as_posix(),'sha256':file_hash(target)}
            profile=json.loads((shared/payload['profile']['path']).read_text());payload['config_fingerprint']=hashlib.sha256(canonical(profile)).hexdigest()
            def enqueue(job,body):api.post('/v1/jobs',{'id':job,'max_attempts':1,'payload':body})
            phase='legacy_worker'
            enqueue('round7-legacy',payload)
            legacy=api.post('/v1/claim',{'worker':'round7-legacy-worker','lease_seconds':30})
            require(legacy['id']=='round7-legacy','unexpected legacy claim')
            require(Worker(api,shared,legacy['worker'],lease=30,heartbeat=.2).attempt(legacy)=='succeeded','legacy attempt failed')
            phase='isolated_worker'
            enqueue('round7-docker',payload)
            worker=DockerExecutor(api,coordinator,shared,control,'round7-docker-worker',image=image_id,timeout=60,heartbeat=.2,lease=30)
            location=worker.location()
            isolated=api.post('/v1/claim',{'worker':worker.worker,'lease_seconds':30,'executor':'isolated-v2','location':location})
            isolated.update(executor='isolated-v2',location=location)
            require(isolated['id']=='round7-docker','unexpected isolated claim')
            require(worker.attempt(isolated)=='succeeded','isolated attempt failed')
            require(status(legacy['id'])['state']==status(isolated['id'])['state']=='succeeded','published task state mismatch')
            phase='strict_comparison'
            inspection=json.loads((control/'jobs'/isolated['id']/'attempt-1.worker/stopped-inspect.json').read_text())
            host_config=inspection['HostConfig']
            for key,value in {'Memory':268435456,'MemorySwap':268435456,'NanoCpus':500000000,'PidsLimit':64,
                              'ReadonlyRootfs':True,'NetworkMode':'none'}.items():
                require(host_config.get(key)==value,'observed isolated resource setting differs: '+key)
            require(inspection['Config']['User']=='65532:65532' and 'ALL' in host_config['CapDrop'],'observed compute user/capability policy differs')
            binds=[mount for mount in inspection['Mounts'] if mount['Type']=='bind']
            require(len(binds)==1 and binds[0]['Destination']=='/inputs' and not binds[0]['RW'],'unexpected compute bind mount')
            require(not any(secret in item for secret in (env['CPAG_WORKER_TOKEN'],env['CPAG_COORDINATOR_TOKEN'])
                            for item in inspection['Config']['Env']),'control credential leaked into compute environment')
            command=inspection['Config']['Cmd'];staged={}
            for role in ('network','process','profile'):
                argument=command[command.index('--'+role)+1]
                require(argument=='/inputs/'+role+Path(isolated['payload'][role]['path']).suffix,'unexpected isolated input command')
                if role!='profile':staged[role]=Path(argument).name
            compared=compare_runs(shared/legacy['output_dir'],shared/isolated['output_dir'],shared,legacy['payload'],isolated['payload'],
                                  {'legacy':platform.python_version(),'isolated':runtime['python']},
                                  {'legacy':{role:Path(legacy['payload'][role]['path']).name for role in ('network','process')},'isolated':staged})
            compared['validation_run_id']=validation_run
            (report/'consistency-result.json').write_text(json.dumps(compared,indent=2)+'\n')
            (report/'consistency-exact-differences.json').write_text(json.dumps({'validation_run_id':validation_run,
                'differences':compared['observed_difference_values'],'other_json_fields':'exactly_equal',
                'wrapper_trailing_lf':compared['wrapper_serialization']},indent=2)+'\n')
            # Save immutable public artifacts and equivalent evidence, never claims,
            # attempt tokens, control receipts, API credentials or DB dumps.
            for label,claim in [('legacy',legacy),('isolated',isolated)]:
                destination=report/('consistency-'+label+'-artifacts')
                destination.mkdir(exist_ok=True)
                for name in NAMES|{'manifest.json'}:shutil.copyfile(shared/claim['output_dir']/name,destination/name)
            # Packet is a separate new contract, checked from original bytes. No
            # historical executor output is used as an oracle for packet semantics.
            phase='packet_contract'
            packet=copy.deepcopy(payload);packet['kind']='packet'
            capture=inputs/'synthetic.pcap';shutil.copyfile(REPO/'docs/refactor/validation-round4/protocol-synthetic.pcap',capture)
            packet_profile=inputs/'packet-profile.json';config={'synthetic':True,'adapter':'synthetic-packet-1'};packet_profile.write_bytes(canonical(config)+b'\n')
            for role,path in [('network',capture),('profile',packet_profile)]:packet[role]={'path':path.relative_to(shared).as_posix(),'sha256':file_hash(path)}
            packet['config_fingerprint']=hashlib.sha256(canonical(config)).hexdigest();enqueue('round7-packet',packet)
            packet_worker=DockerExecutor(api,coordinator,shared,control,'round7-packet-worker',image=image_id,timeout=60,heartbeat=.2,lease=30)
            where=packet_worker.location();packet_claim=api.post('/v1/claim',{'worker':packet_worker.worker,'lease_seconds':30,'executor':'isolated-v2','location':where});packet_claim.update(executor='isolated-v2',location=where)
            require(packet_claim['id']=='round7-packet','unexpected packet claim');require(packet_worker.attempt(packet_claim)=='succeeded','packet attempt failed')
            packet_output=shared/packet_claim['output_dir'];packet_capture=shared/packet_claim['payload']['network']['path']
            sidecar=verify_packet(packet_output,packet_capture)
            require(len(sidecar['events'])==2 and len(sidecar['graph']['edges'])==1,'packet limited contract count mismatch')
            request=next(i for i,o in enumerate(sidecar['observations']) if o['direction']=='request')
            query=query_evidence(packet_output,packet_capture,sidecar['events'][request]['event_id'],'cip.path')
            require(query['observation']['fields']['cip.path']['hex']=='200124013001','literal CIP path mismatch')
            require(len(query['node']['evidence_refs'])==3,'retransmission reference lost')
            query['validation_run_id']=validation_run
            (report/'packet-contract-query.json').write_text(json.dumps(query,indent=2)+'\n')
            identity={'validation_run_id':validation_run,'baseline':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),
                'host_python':platform.python_version(),'host_system':platform.system(),'host_machine':platform.machine(),
                'container_runtime':runtime,'core_and_schema_bytes_identical':True,'shared_source_hashes':source_identity,
                'controller_hashes':{name:file_hash(REPO/'services/worker/cpag_worker'/name) for name in ('worker.py','guardian.py','isolated.py')},
                'observed_compute_command':command,
                'observed_compute_limits':{key:inspection['HostConfig'].get(key) for key in ('Memory','MemorySwap','NanoCpus','PidsLimit','ReadonlyRootfs','NetworkMode','CapDrop','SecurityOpt','Tmpfs')},'image_reference':image,'image_id':image_id,
                'api_binary_sha256':file_hash(work/'api'),
                'migration_sha256':{p.name:file_hash(p) for p in sorted((REPO/'internal/jobs/migrations').glob('*.sql'))},
                'docker_engine':subprocess.check_output(['docker','version','--format','{{.Server.Version}}'],text=True).strip(),
                'api_port':int(api_port),'postgres_port':int(pg_port),'synthetic_only':True,
                'shared_fixture_hashes':{role:payload[role]['sha256'] for role in ('network','process','profile')},
                'migrations':[p.name for p in sorted((REPO/'internal/jobs/migrations').glob('*.sql'))],
                'packet_contract_separately_validated':True,'default_entry_changed':False}
            (report/'consistency-environment.json').write_text(json.dumps(identity,indent=2)+'\n')
            (report/'consistency-summary.json').write_text(json.dumps({'valid':True,'validation_run_id':validation_run,'phase':'completed','common_executor_consistency':True,'packet_separate_contract':True},indent=2)+'\n')
            print(json.dumps({'valid':True,'event_count':compared['event_count'],'events_graph_quality_byte_equal':True,'evidence_equal':True,'packet_separate_contract_valid':True},sort_keys=True))
        except Exception as error:
            (report/'consistency-summary.json').write_text(json.dumps({'valid':False,'validation_run_id':validation_run,'phase':phase,'error_type':type(error).__name__},indent=2)+'\n')
            raise
        finally:
            if server is not None and server.poll() is None:server.terminate();server.wait(timeout=5)
            # Only containers labeled with this temporary executor scope belong
            # to this run, and the PG name was created exclusively above.
            if created:
                scope=hashlib.sha256((str(shared.resolve())+'|'+str(control.resolve())).encode()).hexdigest()[:24]
                candidates=subprocess.run(['docker','ps','-aq','--filter','label=cpag.scope='+scope],capture_output=True,text=True)
                if candidates.returncode==0:
                    for container in candidates.stdout.splitlines():subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                execute('docker','rm','-f','-v',pg_name,stdout=subprocess.DEVNULL)

if __name__=='__main__':main()
