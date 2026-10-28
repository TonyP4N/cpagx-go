#!/usr/bin/env python3
"""Fixed-quota core-only density cell runner; no services, Worker or database.

Every call creates a new attempt. Source verify and capability-based cold reader
run in separate container processes. The authority key/approval remain in RAM,
travel only through private stdin, and are removed from durable protocol output.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/validation')]
from round19_core_oracle import canonical
from round19_core_guards import admit_fixture,check_counts

VERSION='r19-core-fixed-quota-matrix-3'
FIXTURE_VERSION='r19-density-capacity-6'
PHASE_STRATEGY='phase-resources-3'
LIMITS={'cpus':4,'memory_bytes':8*1024**3,'tmp_bytes':4*1024**3,'complete_output_bytes':1024**3,'wall_seconds':1800,'query_seconds':10,'query_bytes':8*1024**2,'query_items':100}
CELL_ORDER=[(scale,mode) for scale in ('S','M','L') for mode in ('offline','replay')]


def sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(1024**2),b''):digest.update(data)
    return digest.hexdigest()


def write(path,value):
    path=Path(path);temporary=path.with_suffix(path.suffix+'.partial')
    with temporary.open('w') as stream:json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')
    os.replace(temporary,path)


def command(*args,**kwargs):return subprocess.run(['docker',*args],check=True,capture_output=True,text=True,**kwargs)


def physical(root):
    total=0
    for path in Path(root).rglob('*'):
        if path.is_symlink():raise ValueError('measurement_output_symlink')
        if path.is_file():total+=path.stat().st_size
    return total


def file_inventory(root):
    result={}
    for path in sorted(Path(root).rglob('*')):
        if path.is_symlink():raise ValueError('handoff_symlink_forbidden')
        if path.is_file():result[path.relative_to(root).as_posix()]={'sha256':sha(path),'size_bytes':path.stat().st_size}
    return result


def copy_handoff(source,target,*,new_files_only=False):
    """Full byte identity, independent of changed destination inode/ctime."""
    source=Path(source);target=Path(target);before=file_inventory(source)
    if not new_files_only:
        shutil.copytree(source,target,copy_function=shutil.copyfile)
        target.chmod(0o700)
    else:
        for path,entry in before.items():
            destination=target/path
            if path=='report.json':continue  # final control report is written identically later
            if destination.exists():
                if sha(destination)!=entry['sha256']:raise ValueError('handoff_preserved_file_changed:'+path)
            else:
                destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source/path,destination)
        return
    if file_inventory(source)!=before or file_inventory(target)!=before:
        raise ValueError('complete_handoff_bytes_changed')
    return before


def runtime_sources():
    paths=[*(ROOT/'services/analysis/src/cpag_core').rglob('*.py'),*(ROOT/'schemas').glob('*.schema.json'),
        *[ROOT/'scripts/validation'/name for name in ('round19_core_matrix.py','round19_core_cell.py','round19_core_oracle.py','round19_core_guards.py','round19_scale_fixture.py')]]
    return {path.relative_to(ROOT).as_posix():sha(path) for path in sorted(paths)}


def run_container(root,phase,mode,image,input_dir,key,approval,deadline,record,*,action=None,temporary_retained_bytes=0):
    action=phase if action is None else action
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('core_chain_1800_seconds')
    name='cpag-r19-core-'+secrets.token_hex(8)
    (root/'result').mkdir(exist_ok=True);(root/'measurements').mkdir(exist_ok=True)
    (root/'measurements'/phase).mkdir(exist_ok=False)
    options=['create','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--pids-limit','128','--cpus','4','--memory',str(LIMITS['memory_bytes']),'--memory-swap',str(LIMITS['memory_bytes']),
        '--tmpfs','/tmp:rw,nosuid,nodev,size='+str(LIMITS['tmp_bytes'])+',mode=1777',
        '--user',str(os.getuid())+':'+str(os.getgid()),'--interactive',
        '--mount','type=bind,source='+str(input_dir)+',target=/input,readonly',
        '--mount','type=bind,source='+str(root/'result')+',target=/result'+('' if action=='export' else ',readonly'),
        '--mount','type=bind,source='+str(root/'measurements')+',target=/measurements',
        '--mount','type=bind,source='+str(root/'harness')+',target=/harness,readonly',
        '--env','CPAG_PHASE_STRATEGY='+PHASE_STRATEGY,'--env','CPAG_PHASE_METRICS=/measurements/'+phase+'/phases.jsonl',
        '--entrypoint','python',image,'-B','-u','/harness/round19_core_cell.py','--action',action,'--mode',mode,
        '--seconds',str(remaining),'--run-id',record['run_id']]
    command(*options)
    inspect=json.loads(command('inspect',name).stdout)[0];config=inspect['HostConfig']
    if (config.get('NanoCpus')!=4_000_000_000 or config.get('Memory')!=LIMITS['memory_bytes']
            or not config.get('ReadonlyRootfs') or config.get('NetworkMode')!='none'
            or 'size='+str(LIMITS['tmp_bytes']) not in config.get('Tmpfs',{}).get('/tmp','')):
        command('rm','-f',name);raise ValueError('actual_container_quota_mismatch')
    measured={'phase':phase,'container_id':inspect['Id'],'actual_host_config':{key:config.get(key) for key in ('NanoCpus','Memory','MemorySwap','Tmpfs','PidsLimit','ReadonlyRootfs','NetworkMode')},'status':'running',
        'temporary_retained_scratch_bytes':temporary_retained_bytes}
    record['phases'].append(measured);write(root/'report.json',record)
    wire=b'' if action=='export' else key
    if action=='query':
        raw=canonical(approval)
        if len(raw)>65536:raise ValueError('private_approval_budget')
        wire+=struct.pack('>I',len(raw))+raw
    started=time.monotonic();process=None;packet=None
    with (root/(phase+'-stderr.log')).open('wb') as stderr,(root/(phase+'-docker-stats.jsonl')).open('w') as stats:
        try:
            process=subprocess.Popen(['docker','start','-a','-i',name],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr)
            first=True
            while True:
                try:
                    output,_=process.communicate(input=wire if first else None,timeout=1);break
                except subprocess.TimeoutExpired:
                    first=False
                    now=time.monotonic();size=physical(root)
                    stats.write(json.dumps({'elapsed_seconds':now-started,'attempt_file_bytes_sample':size})+'\n');stats.flush()
                    if size>LIMITS['complete_output_bytes']:raise ValueError('complete_output_physical_budget_exceeded')
                    if now>=deadline:raise TimeoutError('core_chain_1800_seconds')
                    try:
                        sample=command('stats','--no-stream','--format','{{json .}}',name,timeout=3).stdout.strip()
                        stats.write(json.dumps({'elapsed_seconds':time.monotonic()-started,'docker_stats':json.loads(sample) if sample else None})+'\n');stats.flush()
                        tmp=command('exec',name,'python','-B','-c',"import os,json;s=os.statvfs('/tmp');print(json.dumps({'tmp_used_bytes':(s.f_blocks-s.f_bfree)*s.f_frsize}))",timeout=3).stdout.strip()
                        tmp_sample=json.loads(tmp) if tmp else None
                        combined_tmp=(tmp_sample['tmp_used_bytes']+temporary_retained_bytes) if tmp_sample else None
                        stats.write(json.dumps({'elapsed_seconds':time.monotonic()-started,'tmpfs_sample':tmp_sample,
                            'retained_scratch_plus_tmpfs_bytes':combined_tmp})+'\n');stats.flush()
                        if combined_tmp is not None and combined_tmp>LIMITS['tmp_bytes']:
                            raise ValueError('retained_scratch_and_query_tmp_exceed_4GiB')
                    except (subprocess.SubprocessError,json.JSONDecodeError):pass
            if len(output)>LIMITS['query_bytes']:raise ValueError('private_protocol_output_budget')
            packet=json.loads(output)
            private_approval=packet.pop('_approval',None)
            write(root/(phase+'-result.json'),packet)
            expected_python={Path(path).name:digest for path,digest in record['runtime_source_sha256'].items()
                if Path(path).parent.as_posix()=='services/analysis/src/cpag_core'}
            if packet.get('actual_image_runtime_sha256')!=expected_python:
                raise ValueError('frozen_image_runtime_does_not_match_attempt_source')
            if packet.get('status')!='passed':raise RuntimeError(phase+':'+str(packet.get('error_type'))+':'+str(packet.get('reason')))
            state=json.loads(command('inspect',name).stdout)[0]['State']
            if process.returncode!=0 or state.get('ExitCode')!=0 or state.get('OOMKilled'):raise RuntimeError('core_container_nonzero_or_oom_exit')
            if action=='verify' and not isinstance(private_approval,dict):raise ValueError('fresh_complete_verifier_did_not_issue_capability')
            measured.update(status='passed',result=packet)
            return private_approval
        except BaseException as error:
            measured.update(status='failed',error_type=type(error).__name__,reason=str(error)[:4096])
            raise
        finally:
            if process is not None and process.poll() is None:
                subprocess.run(['docker','kill',name],capture_output=True)
                try:process.communicate(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.communicate()
            try:
                final=json.loads(command('inspect',name).stdout)[0]
                measured.update(container_state=final.get('State'),container_image_id=final.get('Image'))
            finally:
                progress=root/'measurements'/phase/'progress.json'
                if progress.is_file():
                    measured['durable_progress']={'path':progress.relative_to(root).as_posix(),'sha256':sha(progress),
                        'meaning':'latest completed-call progress only; does not imply phase or computation success'}
                measured['whole_phase_seconds']=time.monotonic()-started
                command('rm','-f',name)
                write(root/'report.json',record)


def run(output,fixture,profile,scale,mode,image,*,scratch_root=None):
    destination=Path(output).resolve();root=Path(scratch_root).resolve() if scratch_root else destination
    fixture=Path(fixture).resolve();profile=Path(profile).resolve()
    if scratch_root and (not root.is_relative_to(Path('/private/tmp')) or root==Path('/private/tmp') or destination.exists()):
        raise ValueError('fresh_private_tmp_and_handoff_required')
    root.mkdir(parents=True,mode=0o700,exist_ok=False);began=time.monotonic();deadline=began+LIMITS['wall_seconds']
    record={'version':VERSION,'scope':'new whole core output/source verification/reader query only; no formal service or industrial/reference-environment acceptance',
        'scale':scale,'mode':mode,'run_id':'core-'+scale+'-'+mode+'-'+secrets.token_hex(4),'status':'running','limits':LIMITS,
        'runtime_source_sha256':runtime_sources(),'phases':[],'os_cache':'unverified',
        'fixture_version':FIXTURE_VERSION,'phase_measurement_strategy':PHASE_STRATEGY,
        'output_budget_enforcement':'native complete publisher budget and final/sampled complete attempt file checks; bind mount has no independent filesystem size quota',
        'source_and_capability_definition':'fresh complete source verification followed by private per-attempt HMAC; approval is not external independence proof'}
    if scratch_root:record['execution_storage']={'version':'core-local-scratch-1','scratch':str(root),'handoff':str(destination),
        'strict_source_signature_verification':'unchanged','handoff_scope':'development core measurement only; not Worker/service handoff acceptance',
        'complete_output_budget':'each complete published output copy <=1GiB; retained scratch during handoff/query counted separately as temporary space within4GiB'}
    write(root/'report.json',record)
    try:
        image_info=json.loads(command('image','inspect',image).stdout)[0];image_id=image_info['Id'];record['image']={'requested_tag':image,'immutable_id':image_id}
        record['preflight']=admit_fixture(fixture,profile,scale,mode,fixture_version=FIXTURE_VERSION)
        inputs=root/'input';inputs.mkdir()
        harness=root/'harness';harness.mkdir()
        for name in ('round19_core_matrix.py','round19_core_cell.py','round19_core_oracle.py','round19_core_guards.py'):
            shutil.copyfile(ROOT/'scripts/validation'/name,harness/name)
        record['frozen_harness_sha256']={path.name:sha(path) for path in sorted(harness.iterdir())}
        for path,name in ((fixture/'network.pcap','network.pcap'),(fixture/'process.csv','process.csv'),(profile,'profile.json')):
            shutil.copyfile(path,inputs/name)
        record['fixed_inputs']={name:{'sha256':sha(inputs/name),'size_bytes':(inputs/name).stat().st_size} for name in ('network.pcap','process.csv','profile.json')}
        write(root/'report.json',record)
        key=os.urandom(32)
        run_container(root,'export',mode,image_id,inputs,key,None,deadline,record)
        approval=run_container(root,'verify',mode,image_id,inputs,key,None,deadline,record)
        run_container(root,'query',mode,image_id,inputs,key,approval,deadline,record)
        metadata=record['phases'][-1]['result']['metadata'];counts=metadata['counts']
        bound_check=check_counts(counts,scale)
        if scratch_root:
            tick=time.monotonic();write(root/'report.json',record)
            copied=copy_handoff(root,destination)
            record['handoff']={'copy_and_complete_hash_verification_seconds':time.monotonic()-tick,
                'initial_file_count':len(copied),'initial_file_bytes':sum(x['size_bytes'] for x in copied.values()),
                'initial_inventory':copied,'status':'bytes_verified_pending_cold_reader'}
            run_container(destination,'query-after-handoff',mode,image_id,destination/'input',key,approval,deadline,record,
                action='query',temporary_retained_bytes=physical(root))
            if record['phases'][-1]['result']['metadata']!=metadata:raise ValueError('handoff_metadata_changed')
            record['handoff']['status']='complete_bytes_and_new_process_reader_verified'
            copy_handoff(destination,root,new_files_only=True)
        record.update(status='passed',whole_chain_seconds=time.monotonic()-began,counts=counts,independent_count_bounds=bound_check)
        copies=[physical(root)]+([physical(destination)] if scratch_root else [])
        if record['whole_chain_seconds']>LIMITS['wall_seconds'] or any(size>LIMITS['complete_output_bytes']-65536 for size in copies):raise ValueError('complete_chain_time_or_output_budget')
    except BaseException as error:
        record.update(status='failed',error_type=type(error).__name__,reason=str(error)[:4096],whole_chain_seconds=time.monotonic()-began)
        interruption=root/'controller-interruption.json'
        if interruption.is_file():
            record.update(status='interrupted',classification='administrative_interruption',
                controller_interruption=json.loads(interruption.read_text()))
        if isinstance(error,subprocess.CalledProcessError):
            detail={'command':error.cmd,'returncode':error.returncode}
            for name,value in (('stdout',error.stdout),('stderr',error.stderr)):
                data=value.encode() if isinstance(value,str) else value or b''
                path=root/('external-command-'+name+'.log');path.write_bytes(data)
                detail[name]={'path':path.name,'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data)}
            record['external_command_failure']=detail
    finally:
        if scratch_root and not destination.exists():
            tick=time.monotonic()
            try:
                copy_handoff(root,destination)
                record['failed_attempt_preservation']={'status':'complete_bytes_verified','seconds':time.monotonic()-tick}
            except BaseException as error:
                record['failed_attempt_preservation']={'status':'failed','error_type':type(error).__name__,'reason':str(error)}
        record['complete_attempt_file_bytes']=physical(root)
        if scratch_root:
            record['handoff_copy_file_bytes']=physical(destination)
            record['combined_retained_file_bytes']=physical(root)+physical(destination)
            record['whole_chain_seconds']=time.monotonic()-began
        write(root/'report.json',record)
        if scratch_root and destination.exists():
            write(destination/'report.json',record)
            # All complete files, including the final control report, are
            # checked. This inventory excludes only its own identical bytes.
            left=file_inventory(root);right=file_inventory(destination)
            if left!=right:
                if record['status']=='passed':record.update(status='failed',reason='complete_final_handoff_inventory_mismatch')
                else:record.setdefault('finalization_failures',[]).append('complete_final_handoff_inventory_mismatch')
                write(root/'report.json',record);write(destination/'report.json',record)
            if time.monotonic()>deadline or any(physical(path)>LIMITS['complete_output_bytes'] for path in (root,destination)):
                if record['status']=='passed':record.update(status='failed',reason='complete_chain_time_or_output_budget_including_handoff')
                else:record.setdefault('finalization_failures',[]).append('complete_chain_time_or_output_budget_including_handoff')
                write(root/'report.json',record);write(destination/'report.json',record)
            # Refresh only the control report after final decisions. All other
            # verified bytes stay unchanged; the inventory never hashes itself.
            for directory,values in ((root,left),(destination,right)):
                path=directory/'report.json';values['report.json']={'sha256':sha(path),'size_bytes':path.stat().st_size}
            inventory={'version':'core-local-scratch-handoff-inventory-1','status':'identical' if left==right else 'different',
                'scope':'all ordinary files, excluding this inventory itself','files':left,
                'counterpart_inventory_sha256':hashlib.sha256(canonical(right)).hexdigest()}
            write(root/'handoff-inventory.json',inventory);write(destination/'handoff-inventory.json',inventory)
    return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','fixture','profile','image'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--scale',choices=['S','M','L'],required=True);parser.add_argument('--mode',choices=['offline','replay'],required=True)
    parser.add_argument('--scratch-root',help='Explicit core-local-scratch-1 fresh directory below/private/tmp; full retained handoff remains required')
    args=parser.parse_args();record=run(args.output,args.fixture,args.profile,args.scale,args.mode,args.image,scratch_root=args.scratch_root)
    print(json.dumps({'status':record['status'],'scale':record['scale'],'mode':record['mode'],'reason':record.get('reason')}));raise SystemExit(0 if record['status']=='passed' else 1)
