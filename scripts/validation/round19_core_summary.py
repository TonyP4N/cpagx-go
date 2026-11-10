#!/usr/bin/env python3
"""Allowlisted public core matrix facts; missing/partial measurements stay null.

Only supplied attempt paths are read. Raw inputs, databases, approvals and
secrets are never copied. This summary is derived evidence, not a source verifier.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from datetime import datetime,timezone

ORDER=[(scale,mode) for scale in ('S','M','L') for mode in ('offline','replay')]


def sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(1024**2),b''):digest.update(data)
    return digest.hexdigest()


def bytes_under(path):
    path=Path(path)
    if not path.is_dir():return None
    total=0
    for item in path.rglob('*'):
        if item.is_symlink():raise ValueError('public_summary_symlink_forbidden')
        if item.is_file():total+=item.stat().st_size
    return total


def tmp_samples(path):
    values=[];combined=[]
    if Path(path).is_file():
        for line in Path(path).read_text().splitlines():
            row=json.loads(line);value=(row.get('tmpfs_sample') or {}).get('tmp_used_bytes')
            if type(value) is int:values.append(value)
            value=row.get('retained_scratch_plus_tmpfs_bytes')
            if type(value) is int:combined.append(value)
    return {'sample_count':len(values),'sampled_tmpfs_peak_bytes':max(values) if values else None,
        'sampled_scratch_plus_tmpfs_peak_bytes':max(combined) if combined else None,
        'scope':'observed samples, not a kernel filesystem high-water mark'}


def acceptance_verdict(controller_status,limits,final_bytes,driver_seconds):
    checks={'final_directory_including_handoff_inventory_within_limit':None if final_bytes is None else final_bytes<=limits['complete_output_bytes'],
        'whole_driver_within_wall_limit':None if driver_seconds is None else driver_seconds<=limits['wall_seconds']}
    reasons=[name for name,value in checks.items() if value is False]
    if controller_status=='failed' or reasons:status='failed'
    elif controller_status!='passed':status=controller_status
    elif any(value is None for value in checks.values()):status='not_verified'
    else:status='passed'
    return {'status':status,'controller_status_preserved':controller_status,'checks':checks,'failure_reasons':reasons,
        'scope':'derived final-resource acceptance; original report is never rewritten'}


def phase_summary(root,phase):
    path=Path(root)/(phase['phase']+'-result.json')
    native=phase.get('result') or {};native_source='embedded_report' if native else None
    if not native and path.is_file():native=json.loads(path.read_text());native_source='standalone_packet'
    cgroup=native.get('cgroup') or {}
    result={'phase':phase['phase'],'status':phase['status'],
        'native_status':native.get('status'),'native_result_source':native_source,
        'native_result_sha256':sha(path) if path.is_file() else None,
        'controller_whole_phase_seconds':phase.get('whole_phase_seconds'),
        'native_module_wall_seconds':native.get('wall_seconds'),'native_process_cpu_seconds':native.get('cpu_seconds'),
        'process_rss_high_water_bytes':native.get('process_rss_high_water_bytes'),
        'kernel_cgroup_peak_memory_bytes':cgroup.get('peak_memory_bytes'),
        'kernel_cgroup_cpu_usage_usec':(cgroup.get('cpu_stat') or {}).get('usage_usec'),
        'kernel_cgroup_scope':cgroup.get('scope'),'query_measurement_version':native.get('query_measurement_version'),
        'container_state':phase.get('container_state'),'quota':phase.get('actual_host_config'),
        'temporary_retained_scratch_bytes':phase.get('temporary_retained_scratch_bytes'),
        'verification_report':native.get('verification_report'),'queries':native.get('queries'),
        'history_reader_samples':native.get('history_reader_samples'),
        'all_selected_operation_references':native.get('selected_operation_all_raw_references_checked'),
        'failure_reason':phase.get('reason')}
    result['temporary_samples']=tmp_samples(Path(root)/(phase['phase']+'-docker-stats.jsonl'))
    log=Path(root)/'measurements'/phase['phase']/'phases.jsonl'
    if log.is_file():
        terminal=[json.loads(line) for line in log.read_text().splitlines() if 'terminal_measurement_summary' in line]
        result['native_nested_phase_summary']=terminal[-1] if terminal else None
        result['native_phase_log_sha256']=sha(log)
    else:result.update(native_nested_phase_summary=None,native_phase_log_sha256=None)
    return result


def attempt_summary(root):
    root=Path(root);path=root/'report.json'
    if not path.is_file():return None
    record=json.loads(path.read_text());artifact=root/'result/artifact'
    failure_marker=artifact/'FAILED.json';manifest=artifact/'run_manifest.json'
    data={'attempt':root.name,'report_sha256':sha(path),
        **{name:record.get(name) for name in ('version','scale','mode','status','reason','error_type','image','limits','counts','fixed_inputs','fixture_version','phase_measurement_strategy','frozen_harness_sha256','independent_count_bounds')},
        'controller_whole_chain_seconds':record.get('whole_chain_seconds'),
        'final_controlled_attempt_bytes':bytes_under(root),'artifact_bytes':bytes_under(artifact),
        'artifact_state':'failed_marked' if failure_marker.exists() else 'exported' if manifest.exists() else 'partial_or_not_created',
        'handoff_inventory_sha256':sha(root/'handoff-inventory.json') if (root/'handoff-inventory.json').is_file() else None,
        'phases':[phase_summary(root,value) for value in record['phases']],
        'scope':'development core only; source verification/query failure is not whole-chain acceptance'}
    driver=root.with_name(root.name+'-driver-result.json')
    data['whole_driver_seconds']=json.loads(driver.read_text()).get('whole_driver_seconds') if driver.is_file() else None
    storage=record.get('execution_storage') or {};scratch=Path(storage['scratch']) if storage.get('scratch') else None
    data['retained_scratch_bytes']=bytes_under(scratch) if scratch else None
    data['handoff']=record.get('handoff')
    # Handoff's full file inventory already has a separate, hashed complete
    # custody record; avoid duplicating it inside every public table row.
    if data['handoff']:data['handoff']={k:v for k,v in data['handoff'].items() if k!='initial_inventory'}
    if (root/'controller-interruption.json').is_file():data['controller_interruption']=json.loads((root/'controller-interruption.json').read_text())
    data['external_acceptance']=acceptance_verdict(record['status'],record['limits'],data['final_controlled_attempt_bytes'],data['whole_driver_seconds'])
    return data


def redact(value,workspace):
    if isinstance(value,dict):
        if {'_approval','approval','authority_key','secret','hmac_secret'}.intersection(value):raise ValueError('private_capability_field_forbidden')
        return {key:redact(item,workspace) for key,item in value.items()}
    if isinstance(value,list):return [redact(item,workspace) for item in value]
    if isinstance(value,str):
        value=value.replace(str(workspace),'$WORKSPACE')
        value=re.sub(r'/Users/[^/\\\s"\']+','$USER_HOME',value)
        return re.sub(r'/private/tmp/(cpag-r19-core[^/\\\s"\']*)',r'$CORE_SCRATCH/\1',value)
    return value


def summarize(binding,attempts,failures=(),*,workspace):
    cells={key:{'scale':key[0],'mode':key[1],'status':'not_recorded','measurements':None} for key in ORDER}
    for path in attempts:
        row=attempt_summary(path)
        if row is None:continue
        if (row.get('image') or {}).get('immutable_id')!=binding['image_id']:raise ValueError('matrix_mixed_image_identity')
        key=(row['scale'],row['mode'])
        if key not in cells or cells[key]['measurements'] is not None:raise ValueError('matrix_duplicate_or_unknown_cell')
        cells[key].update(status=row['external_acceptance']['status'],measurements=row)
    result={'version':'core-matrix-public-summary-2','collected_at':datetime.now(timezone.utc).isoformat(),
        'scope':'local development core matrix; no service/Worker/reference-environment/industrial acceptance',
        'image_id':binding['image_id'],'runtime_commit':binding['runtime_commit'],'runtime_file_count':binding['runtime_file_count'],
        'all_runtime_files_match_signed_commit':binding.get('all_equal'),
        'status':'passed' if all(row['status']=='passed' for row in cells.values()) else 'incomplete_or_failed',
        'cells':list(cells.values()),'preserved_historical_attempts':[attempt_summary(path) for path in failures],
        'measurement_definitions':{'missing':'null means not reached/not recorded, never zero-filled',
            'controller':'whole phase includes process/container handling; whole driver adds final summary serialization',
            'native':'module entry clock2 includes dependencies; interpreter pre-code startup excluded',
            'rss':'native process high-water at final report, not container allocation',
            'cgroup':'kernel cumulative peak/CPU through final report, includes sampler execs',
            'tmp':'sampled occupancy, not an exact high-water mark',
            'nested_phases':'overlapping inclusive times must not be summed',
            'artifact':'exported does not imply source verification or whole-chain success',
            'retained_copies':'output and scratch copies separately recorded; scratch during handoff/query counts as temporary occupancy'}}
    return redact(result,Path(workspace).resolve())


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binding',required=True);parser.add_argument('--attempt',action='append',default=[])
    parser.add_argument('--preserved-failure',action='append',default=[]);parser.add_argument('--output',required=True);parser.add_argument('--workspace',default=str(Path(__file__).resolve().parents[3]))
    args=parser.parse_args();output=Path(args.output)
    if output.exists():raise SystemExit('new summary output required; preserve previous snapshots')
    value=summarize(json.loads(Path(args.binding).read_text()),args.attempt,args.preserved_failure,workspace=args.workspace)
    output.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
