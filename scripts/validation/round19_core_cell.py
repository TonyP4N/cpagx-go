#!/usr/bin/env python3
"""Private core-container child; not a service or standalone authority source."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import sys
import time
import traceback

sys.path.insert(0,str(Path(__file__).resolve().parent))
from round19_core_oracle import canonical,check_raw_evidence
from round19_core_guards import EvidencePages

MAX_PACKET=8*1024**2


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--action',choices=['export','verify','query'],required=True)
    parser.add_argument('--mode',choices=['offline','replay'],required=True);parser.add_argument('--seconds',type=float,required=True)
    parser.add_argument('--run-id',required=True);args=parser.parse_args();started=time.monotonic()
    packet={'status':'failed','action':args.action};key=None;approval=None
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
                approval=core.issue_approval('/result/artifact',key,deadline=deadline)
                packet.update(status='passed',verification='fresh_process_complete_source_rebuild',_approval=approval)
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
                    tick=time.monotonic()
                    with core.open_reader('/result/artifact',deadline=min(deadline,tick+10),approval=approval,authority_key=key) as reader:
                        history=reader.page('history/snapshots',offset=0,limit=1,max_bytes=MAX_PACKET)
                    elapsed=time.monotonic()-tick;raw=canonical(history)
                    if elapsed>10 or len(raw)>MAX_PACKET:raise ValueError('history_query_time_or_byte_limit')
                    if (history['returned']!=1 or history['total']!=metadata['counts']['snapshots']
                            or any(name not in history['items'][0] for name in ('analysis','graph','events'))):
                        raise ValueError('complete_standard_history_projection_required')
                    samples.append({'cache':'authenticated_history_page','seconds':elapsed,'complete_response_bytes':len(raw),'response_sha256':hashlib.sha256(raw).hexdigest(),'returned':history['returned'],'total':history['total']})
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
        raw=canonical(packet)
        if len(raw)>MAX_PACKET:raise ValueError('private_protocol_packet_limit')
        sys.stdout.buffer.write(raw+b'\n');sys.stdout.buffer.flush()
    return 0 if packet['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
