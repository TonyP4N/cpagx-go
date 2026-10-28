#!/usr/bin/env python3
"""L-only coverage4 child; baseline S/M cell remains byte-for-byte frozen."""
import time
MODULE_STARTED=time.monotonic()

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import sys
import traceback

sys.path.insert(0,str(Path(__file__).resolve().parent))
from round19_core_oracle import canonical,check_raw_evidence
from round19_core_guards import EvidencePages
from round19_core_history_coverage import audit_coverage

MAX_PACKET=8*1024**2
QUERY_MEASUREMENT_VERSION='core-query-module-clock-2'


def cgroup_snapshot(root=Path('/sys/fs/cgroup')):
    """Kernel whole-cgroup peak at final report, distinct from process RSS."""
    try:
        peak=int((root/'memory.peak').read_text().strip())
        current=int((root/'memory.current').read_text().strip())
        limit=int((root/'memory.max').read_text().strip())
        cpu={key:int(value) for key,value in (line.split() for line in (root/'cpu.stat').read_text().splitlines())}
        if min(peak,current,limit)<0:raise ValueError('negative_cgroup_counter')
        return {'available':True,'hierarchy':'v2','peak_memory_bytes':peak,'current_memory_bytes':current,
            'memory_limit_bytes':limit,'cpu_stat':cpu,
            'scope':'container cgroup since creation through final report; includes sampler execs; excludes final protocol serialization/exit'}
    except (OSError,ValueError) as error:
        return {'available':False,'reason':type(error).__name__,'scope':'v2 kernel peak unavailable; no peak inferred from RSS'}


def sample_history(core,root,metadata,approval,key,deadline,network,process,profile):
    """Bounded first/middle/last path requests, never whole large snapshots."""
    timings=[];snapshots=[];revisions=[]
    def request(label,read):
        tick=time.monotonic()
        with core.open_reader(root,deadline=min(deadline,tick+10),approval=approval,authority_key=key) as reader:value=read(reader)
        raw=canonical(value);elapsed=time.monotonic()-tick
        if elapsed>10 or len(raw)>MAX_PACKET:raise ValueError('history_query_time_or_byte_limit')
        timings.append({'cache':label,'seconds':elapsed,'complete_response_bytes':len(raw),'response_sha256':hashlib.sha256(raw).hexdigest()})
        return value
    def snapshot_paths(reader,index):
        fields={name:reader.get('history/snapshots',path=[index,name],max_bytes=MAX_PACKET)
            for name in ('snapshot_number','snapshot_id','status','arrival_seq','available_at')}
        if type(fields['snapshot_number']) is not int or fields['snapshot_number']!=index:raise ValueError('history_snapshot_position_mismatch')
        result={'metadata':fields}
        for name,path in [('operations',['analysis','operations']),('events',['events']),('nodes',['graph','nodes']),('edges',['graph','edges']),('claims',['graph','claims'])]:
            result[name]=reader.page('history/snapshots',path=[index,*path],offset=0,limit=1,max_bytes=MAX_PACKET)
        result['graph']={name:reader.get('history/snapshots',path=[index,'graph',name],max_bytes=MAX_PACKET) for name in ('schema_version','graph_id')}
        return result
    total=metadata['counts']['snapshots']
    for index in sorted({0,total//2,total-1}):
        value=request('history_snapshot_paths_'+str(index),lambda reader:snapshot_paths(reader,index))
        snapshots.append({'metadata':value['metadata'],'graph':value['graph'],
            'array_first_pages':{name:{field:page[field] for field in ('offset','limit','returned','total','has_more')}
                for name,page in value.items() if name not in ('metadata','graph')}})
    count=metadata['counts']['revisions']
    def revision_paths(reader,index):
        fields={name:reader.get('history/revisions',path=[index,name],max_bytes=MAX_PACKET) for name in
            ('revision_number','revision_id','old_snapshot_number','new_snapshot_number','old_snapshot_id','new_snapshot_id','old_state_fingerprint','new_state_fingerprint','available_at','reason')}
        for prefix in ('old','new'):
            number=fields[prefix+'_snapshot_number']
            if number is None:continue
            if type(number) is not int or not 0<=number<total:raise ValueError('revision_snapshot_position_invalid')
            for field in ('snapshot_id','state_fingerprint'):
                if reader.get('history/snapshots',path=[number,field],max_bytes=MAX_PACKET)!=fields[prefix+'_'+field]:
                    raise ValueError('revision_snapshot_chain_mismatch')
        return {'metadata':fields,'evidence':reader.page('history/revisions',path=[index,'evidence_refs'],offset=0,limit=100,max_bytes=MAX_PACKET)}
    for index in sorted({0,count//2,count-1}) if count else []:
        value=request('history_revision_paths_'+str(index),lambda reader:revision_paths(reader,index))
        revisions.append({'metadata':value['metadata'],'evidence_first_page':{field:value['evidence'][field]
            for field in ('offset','limit','returned','total','has_more')}})
    available=[row for row in snapshots if row['array_first_pages']['operations']['total']>0]
    if metadata['counts']['operations'] and not available:raise ValueError('historical_operation_sample_missing')
    historical=None
    if available:
        chosen=available[len(available)//2]['metadata'];index=chosen['snapshot_number'];tick=time.monotonic()
        value=core.query_task(root,operation_id='first',snapshot=index,ref_offset=0,ref_limit=100,
            deadline=min(deadline,tick+10),approval=approval,authority_key=key)
        raw=canonical(value);elapsed=time.monotonic()-tick
        if elapsed>10 or len(raw)>MAX_PACKET:raise ValueError('historical_operation_query_limit')
        if value['snapshot_id']!=chosen['snapshot_id'] or value['revision']!=index:raise ValueError('historical_query_used_another_snapshot')
        if not value['verified_original_evidence']:raise ValueError('historical_original_reference_sample_empty')
        prefix=core.read_json(profile)['replay']['sequence'][:chosen['arrival_seq']]
        admitted={(step.get('source_slot'),step.get('record_number')) for step in prefix if 'record_number' in step}
        for row in value['verified_original_evidence']:
            ref=row['source_ref'];number=ref['frame_number'] if ref['frame_number'] is not None else ref['record_number']
            if (ref['source_slot'],number) not in admitted:raise ValueError('historical_reference_outside_independent_arrival_prefix')
        historical={'snapshot_number':index,'snapshot_id':value['snapshot_id'],'evidence_page':value['evidence_page'],
            'independent_raw':check_raw_evidence(value['verified_original_evidence'],network,process),
            'independent_arrival_prefix_checked':True,'scope':'one bounded reference page, not all historical operations or references'}
        timings.append({'cache':'historical_operation_reference_page','seconds':elapsed,'complete_response_bytes':len(raw),'response_sha256':hashlib.sha256(raw).hexdigest()})
    return {'version':'core-reader-history-path-sampling-1','scope':'first/middle/last path and first-page consumption; complete history content separately source-rebuilt',
        'snapshots':snapshots,'revisions':revisions,'historical_operation':historical},timings


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--action',choices=['export','verify','query'],required=True)
    parser.add_argument('--mode',choices=['offline','replay'],required=True);parser.add_argument('--seconds',type=float,required=True)
    parser.add_argument('--run-id',required=True);args=parser.parse_args();started=MODULE_STARTED
    packet={'status':'failed','action':args.action,'harness_version':'r19-core-l-expiry-coverage-4','query_measurement_version':QUERY_MEASUREMENT_VERSION,
        'clock_definition':'wall begins before harness dependencies and argument parsing; cold includes core import, source hashes and private IPC reads; interpreter pre-code startup excluded, whole container phase separately recorded'};key=None;approval=None
    try:
        from cpag_core import shared_export as core
        package=Path(core.__file__).parent
        packet['actual_image_runtime_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(package.glob('*.py'))}
        packet['python_version']=sys.version
        deadline=started+args.seconds
        if args.action!='export':
            key=sys.stdin.buffer.read(32)
            if len(key)!=32:raise ValueError('private_authority_pipe_incomplete')
        if args.action=='query':
            length=sys.stdin.buffer.read(4)
            if len(length)!=4:raise ValueError('private_approval_pipe_incomplete')
            count=struct.unpack('>I',length)[0]
            if not 1<=count<=65536:raise ValueError('private_approval_pipe_budget')
            raw=sys.stdin.buffer.read(count)
            if len(raw)!=count:raise ValueError('private_approval_pipe_incomplete')
            approval=json.loads(raw)
        with contextlib.redirect_stdout(sys.stderr):
            if args.action=='export':
                manifest=core.export_task(['/input/network.pcap'],'/input/process.csv','/input/profile.json','/result/artifact',
                    mode=args.mode,run_id=args.run_id,attempt_id=1,deadline=deadline)
                packet.update(status='passed',manifest=manifest)
            elif args.action=='verify':
                verification_report={};packet['verification_report']=verification_report
                approval=core.issue_approval('/result/artifact',key,deadline=deadline,verification_report=verification_report)
                if (verification_report.get('status')!='passed'
                        or verification_report.get('verification_strategy')!='dag6-full-source-merkle-sink-1'):
                    raise ValueError('complete_source_merkle_report_required')
                packet.update(status='passed',verification='fresh_process_complete_source_merkle_rebuild',_approval=approval)
            else:
                manifest=core.read_json('/result/artifact/run_manifest.json',65536)
                samples=[];answers=[];pages=EvidencePages();first_value=None
                for label in ('fresh_process_cold_reader','same_process_repeat_new_reader'):
                    tick=time.monotonic();query_deadline=min(deadline,tick+10)
                    value=core.query_task('/result/artifact',operation_id='first',ref_limit=100,deadline=query_deadline,approval=approval,authority_key=key)
                    raw=canonical(value);elapsed=time.monotonic()-(started if label=='fresh_process_cold_reader' else tick)
                    if elapsed>10 or len(raw)>MAX_PACKET:raise ValueError('complete_query_time_or_byte_limit')
                    page=value.get('evidence_page',{})
                    independent=check_raw_evidence(value['verified_original_evidence'],['/input/network.pcap'],'/input/process.csv')
                    samples.append({'cache':label,'os_cache':'unverified','seconds':elapsed,'complete_response_bytes':len(raw),'response_sha256':hashlib.sha256(raw).hexdigest(),'evidence_page':page,'independent_raw':independent})
                    answers.append(raw)
                    if first_value is None:first_value=value
                if answers[0]!=answers[1]:raise ValueError('cold_hot_reader_content_changed')
                pages.add(first_value['evidence_page'],first_value['verified_original_evidence'])
                # Every individual page retains its own10s/8MiB/100-item cap;
                # the sum is charged to the same1800s whole-chain deadline.
                while not pages.finished:
                    tick=time.monotonic()
                    value=core.query_task('/result/artifact',operation_id='first',ref_offset=pages.offset,ref_limit=100,
                        deadline=min(deadline,tick+10),approval=approval,authority_key=key)
                    raw=canonical(value);elapsed=time.monotonic()-tick
                    if elapsed>10 or len(raw)>MAX_PACKET:raise ValueError('complete_query_time_or_byte_limit')
                    pages.add(value['evidence_page'],value['verified_original_evidence'])
                    independent=check_raw_evidence(value['verified_original_evidence'],['/input/network.pcap'],'/input/process.csv')
                    samples.append({'cache':'remaining_reference_page_new_reader','os_cache':'unverified','seconds':elapsed,
                        'complete_response_bytes':len(raw),'response_sha256':hashlib.sha256(raw).hexdigest(),
                        'evidence_page':value['evidence_page'],'independent_raw':independent})
                metadata=core.metadata_task('/result/artifact',deadline=deadline,approval=approval,authority_key=key)
                if args.mode=='replay':
                    coverage_report={};packet['ever_observed_coverage']=coverage_report
                    audit_coverage(core,'/result/artifact',['/input/network.pcap'],'/input/process.csv','/input/profile.json',
                        approval,key,deadline,report=coverage_report)
                    metadata['independent_ever_observed_coverage']={name:coverage_report[name] for name in
                        ('version','status','raw_original_units','csv_headers_admitted_not_observations','admitted_units',
                         'ever_observed_data_units','actual_history_events_proven','expired_units','snapshot_count',
                         'missing_or_extra_units','membership_sha256','event_membership_sha256','raw_file_sha256')}
                if args.mode=='replay':
                    history,history_times=sample_history(core,'/result/artifact',metadata,approval,key,deadline,
                        ['/input/network.pcap'],'/input/process.csv','/input/profile.json')
                    packet['history_reader_samples']=history;samples.extend(history_times)
                packet.update(status='passed',metadata=metadata,queries=samples,
                    selected_operation_all_raw_references_checked={'total':pages.total,'returned':pages.offset,'complete':pages.finished},
                    repeat_query_definition='same process calls public API again with a new authenticated reader; OS/decoder warm-cache state unverified')
    except BaseException as error:
        traceback.print_exc(file=sys.stderr)
        reason=str(error);packet.update(error_type=type(error).__name__,reason=reason[:4096],reason_truncated=len(reason)>4096)
    finally:
        usage=resource.getrusage(resource.RUSAGE_SELF)
        packet.update(wall_seconds=time.monotonic()-started,cpu_seconds=usage.ru_utime+usage.ru_stime,
            process_rss_high_water_bytes=usage.ru_maxrss*(1 if sys.platform=='darwin' else 1024),
            rss_definition='process cumulative high-water; not phase allocation or cgroup memory')
        packet['cgroup']=cgroup_snapshot()
        if packet['status']=='passed' and (not packet['cgroup']['available'] or packet['cgroup']['memory_limit_bytes']!=8*1024**3):
            packet.update(status='failed',error_type='ValueError',reason='required_8GiB_cgroup_peak_unavailable_or_limit_mismatch')
        raw=canonical(packet)
        if len(raw)>MAX_PACKET:raise ValueError('private_protocol_packet_limit')
        sys.stdout.buffer.write(raw+b'\n');sys.stdout.buffer.flush()
    return 0 if packet['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
