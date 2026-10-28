"""Read existing small JSON measurements only; never execute core/test/container work."""
import csv
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path

DEST=Path(__file__).resolve().parent
FYP=DEST.parents[3]
PHASE_NAMES=('export','verify','query','query-after-handoff')
SOURCES={}


def read(path):
    relative=path.relative_to(FYP).as_posix()
    if not path.exists():
        SOURCES[relative]={'exists':False,'size_bytes':None,'sha256':None}
        return None
    raw=path.read_bytes()
    SOURCES[relative]={'exists':True,'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    return json.loads(raw)


def phase_aggregates(path):
    raw=path.read_bytes();relative=path.relative_to(FYP).as_posix()
    SOURCES[relative]={'exists':True,'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    rows=[json.loads(line) for line in raw.splitlines()]
    final=next((row for row in reversed(rows) if row.get('kind')=='terminal_measurement_summary'),None)
    if final is None:return None,None
    return final['phases'],{key:final.get(key) for key in ('version','kind','all_observed_calls','raw_rows_retained','raw_rows_not_retained','progress_write_failures')}


def stage_row(label,phase,controller,packet):
    packet=packet or {};cgroup=packet.get('cgroup') or {};cpu=cgroup.get('cpu_stat') or {}
    return {'case':label,'phase':phase,'controller_status':None if controller is None else controller.get('status'),
        'controller_wall_seconds':None if controller is None else controller.get('whole_phase_seconds'),
        'native_status':packet.get('status'),'native_wall_seconds':packet.get('wall_seconds'),
        'native_process_cpu_seconds':packet.get('cpu_seconds'),
        'native_process_rss_high_water_bytes':packet.get('process_rss_high_water_bytes'),
        'cgroup_peak_memory_bytes':cgroup.get('peak_memory_bytes'),
        'cgroup_cpu_usage_seconds':None if cpu.get('usage_usec') is None else cpu['usage_usec']/1000000,
        'cgroup_nr_throttled':cpu.get('nr_throttled'),
        'error_type':packet.get('error_type'),'reason':packet.get('reason'),
        'native_packet':None if not packet else phase+'-result.json',
        'missing_reason':'not_run_after_failed_source_verification' if not packet and controller is None else None}


cases=[];stage_table=[];nested_table=[];historical=[]
for label in ('S-offline','S-replay','M-offline'):
    folder=FYP/'outputs'/('cpag-r19-core-matrix-dev4-'+label+'-attempt1')
    report=read(folder/'report.json')
    controllers={row['phase']:row for row in report['phases']}
    packets={phase:read(folder/(phase+'-result.json')) for phase in PHASE_NAMES}
    manifest=read(folder/'result/artifact/run_manifest.json')
    store=read(folder/'result/artifact/shared/manifest.json')
    artifact_bytes=sum(path.stat().st_size for path in (folder/'result/artifact').rglob('*') if path.is_file())
    declared_bytes=(folder/'result/artifact/run_manifest.json').stat().st_size+sum(row['size_bytes'] for row in manifest['artifacts'])
    if artifact_bytes!=declared_bytes:raise ValueError('physical stat and existing manifest declarations disagree')
    summary={'case':label,'status':report['status'],'reason':report.get('reason'),'controller_whole_chain_seconds':report.get('whole_chain_seconds'),
        'image_id':report['image']['immutable_id'],'fixture_version':report['fixture_version'],'phase_measurement_strategy':report['phase_measurement_strategy'],
        'counts':manifest['counts'],'counts_provenance':'published producer manifest; independent complete source verification failed' if report['status']=='failed' else 'producer manifest and passed report',
        'complete_artifact_observed_file_bytes':artifact_bytes,'artifact_manifest_declared_complete_bytes':declared_bytes,
        'sqlite_observed_file_bytes':(folder/'result/artifact/shared/shared.sqlite3').stat().st_size,'stored_node_count':store['node_count'],
        'report_complete_attempt_file_bytes':report.get('complete_attempt_file_bytes'),'limits':report['limits'],
        'source_sink_diagnostics':None,'unmeasured_stages':{'evidence_organization_alone_seconds':None,'rule_judgement_alone_seconds':None},
        'queries':{},'terminal_summaries':{}}
    verification=(packets['verify'] or {}).get('verification_report') or {}
    summary['source_sink_diagnostics']={key:verification.get(key) for key in ('status','verification_strategy','physical_artifacts_created','node_count','audit_index_owned_bytes','audit_index_peak_owned_bytes','flat_value_cache_owned_bytes')}
    for phase in PHASE_NAMES:
        row=stage_row(label,phase,controllers.get(phase),packets[phase]);stage_table.append(row)
        packet=packets[phase]
        if phase.startswith('query'):
            summary['queries'][phase]=None if packet is None else [{key:value.get(key) for key in ('cache','seconds','complete_response_bytes','os_cache')} for value in packet.get('queries',[])]
        if phase not in ('export','verify'):continue
        aggregates,terminal=phase_aggregates(folder/f'measurements/{phase}/phases.jsonl')
        summary['terminal_summaries'][phase]=terminal
        for name,value in (aggregates or {}).items():
            nested_table.append({'case':label,'container_phase':phase,'measurement_phase':name,
                **{key:value.get(key) for key in ('calls','returned','failed','wall_seconds','cpu_seconds','rss_high_water_bytes')},
                'is_exclusive':False,'scope_note':'nested call aggregates; not additive; failed outer call is partial execution' if value.get('failed') else 'nested call aggregates; not additive'})
        for name in ('evidence_organization_alone','rule_judgement_alone'):
            nested_table.append({'case':label,'container_phase':phase,'measurement_phase':name,'calls':None,'returned':None,'failed':None,
                'wall_seconds':None,'cpu_seconds':None,'rss_high_water_bytes':None,'is_exclusive':None,'scope_note':'not separately measured inside association_and_evidence'})
    if label=='M-offline':
        summary['legacy_flat_bound']={'bytes':report['preflight']['density_math']['offline_flat_output_lower_bound_bytes'],
            'kind':'mathematical_lower_bound_not_measured_output','proof_scope':report['preflight']['density_math']['proof_scope']}
    cases.append(summary)

for label,attempt in (('S-offline',2),('S-replay',1)):
    folder=FYP/'outputs'/f'cpag-r19-core-matrix-dev3-{label}-attempt{attempt}'
    report=read(folder/'report.json')
    record={'case':label,'attempt':attempt,'status':report['status'],'whole_chain_seconds':report.get('whole_chain_seconds'),
        'image_id':report['image']['immutable_id'],'interpretation':'historical development run only; old verifier integrity gap retained; not isolated-change causal measurement','stages':[],'nested_aggregates':[]}
    controllers={row['phase']:row for row in report['phases']}
    for phase in ('export','verify'):
        record['stages'].append(stage_row(label,phase,controllers.get(phase),read(folder/(phase+'-result.json'))))
        aggregates,terminal=phase_aggregates(folder/f'measurements/{phase}/phases.jsonl')
        for name,value in (aggregates or {}).items():record['nested_aggregates'].append({'container_phase':phase,'measurement_phase':name,**value})
    historical.append(record)

result={'schema_version':'r19-dev4-cost-attribution-1','scope':'partial, read-only development-core measurement attribution; no runtime/test/container computation started; no service/industrial/reference acceptance',
    'created_at_utc':datetime.now(timezone.utc).isoformat(),'units':{'wall_seconds':'seconds by distinct explicitly labelled clocks','cpu_seconds':'CPU time, not elapsed time','memory':'bytes, process RSS and cgroup peak have different scopes'},
    'null_policy':'null means not measured, unavailable, or not reached; reasons retained; never interpreted as zero',
    'additivity':'all nested phase durations overlap and MUST NOT be summed; no evidence-only or judgement-only timing exists',
    'cases':cases,'stage_table':stage_table,'nested_phase_table':nested_table,'historical_dev3_same_mode':historical,
    'comparison_warning':'dev4 standard_projection executes writer/source-sink callbacks inside its span; dev3 standard_projection did not include these same storage operations. 148.334 to 193.684 is not an isolated algorithm slowdown.',
    'L_extrapolation':None,'original_sources':SOURCES}
(DEST/'cost-attribution.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n')
for filename,rows in (('stage-costs.csv',stage_table),('nested-phase-costs.csv',nested_table)):
    with (DEST/filename).open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]),lineterminator='\n');writer.writeheader()
        for row in rows:writer.writerow({key:('null' if value is None else str(value).lower() if isinstance(value,bool) else value) for key,value in row.items()})
print(json.dumps({'cases':[{'case':r['case'],'status':r['status'],'whole_chain_seconds':r['controller_whole_chain_seconds'],'artifact_bytes':r['complete_artifact_observed_file_bytes']} for r in cases],'source_files':len(SOURCES),'stage_rows':len(stage_table),'nested_rows':len(nested_table)}))
