"""Explicit bounded replay task adapter; original integrity and prefix semantics are separate."""
import argparse
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import platform
import shutil
import time
import uuid

from . import __version__
from .contracts import validate
from .dual_source import references, strict_json
from .dual_source_export import event_graph
from .dual_source_rules import validate_profile
from .pipeline import canonical, file_hash, fingerprint
from .replay import instant
from .replay_inputs import ReplayInputs

VERSION='dual-source-replay-1'
ANALYSIS_VERSION='bounded-dual-source-2'
DIRECTORIES=frozenset({'sources'})
STANDARD=('dataset.json','events.json','graph.json','quality.json','analysis.json',
          'replay.json','snapshots.jsonl','revisions.jsonl','arrivals.jsonl','metrics.json','runtime_metrics.json')


def network_names(count):
    if type(count) is not int or not 1<=count<=4:raise ValueError('network_file_limit')
    return ['network.pcap']+['network-%03d.pcap'%i for i in range(1,count)]


def artifact_files_for_inputs(count):
    return frozenset((*STANDARD,'run_manifest.json','sources/profile.json','sources/process.csv',
                      *('sources/'+n for n in network_names(count))))


FILES=artifact_files_for_inputs(1)


def read_json(path):
    return strict_json(Path(path).read_text(encoding='utf-8'))


def artifact_files(output):
    dataset=read_json(Path(output)/'dataset.json')
    count=sum(row.get('kind')=='network' for row in dataset['files'])
    return artifact_files_for_inputs(count)


def _inputs(network,process,profile):
    networks=[Path(p) for p in (network if isinstance(network,(list,tuple)) else [network])]
    network_names(len(networks)); process,profile=Path(process),Path(profile)
    paths=[*networks,process,profile]
    if any(p.is_symlink() or not p.is_file() for p in paths):raise ValueError('invalid_original_file')
    if sum(p.stat().st_size for p in networks)>16*1024*1024 or process.stat().st_size>2*1024*1024 or profile.stat().st_size>65536:
        raise ValueError('input_size_limit')
    return networks,process,profile


def input_rows(networks,process):
    return [{'kind':kind,'sha256':file_hash(path),'size_bytes':path.stat().st_size}
            for kind,path in [('network',p) for p in networks]+[('process',process)]]


def dataset_manifest(config,rows,count):
    dataset={'schema_version':'1.0.0','synthetic':config['synthetic'],'dataset_id':'replay-dataset-'+fingerprint(rows),
             'source':'retained explicitly classified replay inputs','release':VERSION,
             'files':[dict(row,name=name) for row,name in zip(rows,[*network_names(count),'process.csv'])],
             'collection_range':{'start':None,'end':None},'timezone_basis':'versioned arrival and event clock declarations',
             'authorization_ref':'declared source authorization; not industrial validation'}
    if config['synthetic'] is False:
        for key in ('source','release','collection_range','timezone_basis','authorization_ref'):dataset[key]=config['source_provenance'][key]
    validate('DatasetManifest',dataset)
    return dataset


def execute(networks,process,profile,*,pace=False):
    """Consume only the explicitly arriving record; no complete-input parsing."""
    from .replay_core import ReplayCore
    config=deepcopy(profile);validate_profile(config)
    options=config.get('replay',{})
    if options.get('version')!=VERSION:raise ValueError('unsupported_replay_version')
    sequence=options.get('sequence')
    if not isinstance(sequence,list) or not sequence or len(sequence)>22000:raise ValueError('explicit_bounded_arrival_sequence_required')
    if 'finish_at' not in options:raise ValueError('explicit_finish_time_required')
    engine=ReplayCore(config)
    inputs=ReplayInputs(networks,process,config['process'],synthetic=config['synthetic'])
    wall_start=time.monotonic();schedule_start=instant(options['simulation_start']);speed=options.get('speed',1)
    samples=[]
    def pacing(at):
        target=(instant(at)-schedule_start).total_seconds()/speed
        if target<0:raise ValueError('arrival_before_simulation_start')
        if pace and options.get('realtime',options.get('realtime_pacing',False)):
            remaining=target-(time.monotonic()-wall_start)
            if remaining>0:time.sleep(remaining)
        return target
    try:
        for seq,step in enumerate(sequence,1):
            if not isinstance(step,dict) or 'available_at' not in step:raise ValueError('invalid_arrival_step')
            at=step['available_at'];target=pacing(at);started=time.monotonic()
            if step.get('kind')=='advance':
                if set(step)-{'kind','available_at'}:raise ValueError('invalid_advance_step')
                engine.advance(at,arrival_seq=seq)
            elif step.get('kind')=='source_eof':
                if set(step)-{'kind','source_slot','available_at'}:raise ValueError('invalid_eof_step')
                inputs.finish_source(step['source_slot'])
                engine.consume(inputs.snapshot(),available_at=at,arrival_seq=seq,status='source_eof')
            else:
                if set(step)-{'kind','source_slot','record_number','record_sha256','available_at'}:raise ValueError('invalid_arrival_step')
                item=inputs.advance(step)
                engine.consume(inputs.snapshot(),available_at=at,arrival_seq=seq,
                               trigger_ref=item.get('source_ref'),status=item['status'],original_ref=item.get('original_ref'),
                               claimed_record_sha256=item.get('claimed_record_sha256'))
            samples.append({'arrival_seq':seq,'available_at':at,'scheduled_elapsed_seconds':target,
                            'actual_elapsed_seconds':time.monotonic()-wall_start,
                            'processing_seconds':time.monotonic()-started})
        at=options['finish_at'];pacing(at)
        if not inputs.all_sources_exhausted():raise ValueError('input_not_exhausted')
        prefix=inputs.finish()
        engine.consume(prefix,available_at=at,arrival_seq=len(sequence)+1,status='input_exhausted')
        engine.finish(at)
        snapshots=engine.snapshots()
        for row in snapshots:
            projected=event_graph(row['analysis'],replay=True)
            row['graph']=projected['graph.json'];row['events']=projected['events.json']
        result=engine.final_result()
        for revision in engine.history():validate('ReplayRevision',revision)
        runtime={'schema_version':'1.0.0','clock':'monotonic_wall_seconds','speed':speed,
                 'paced':bool(pace and options.get('realtime',options.get('realtime_pacing',False))),
                 'elapsed_seconds':time.monotonic()-wall_start,'samples':samples,
                 'core_samples':engine.runtime_metrics()['samples'],
                 'limitations':['Engineering mechanism samples, not production throughput or R19 acceptance.']}
        return {'analysis':result,'snapshots':snapshots,'revisions':engine.history(),
                'metrics':engine.metrics(),'runtime_metrics':runtime,'inputs':inputs}
    except Exception:
        inputs.close();raise


def _jsonl(rows):return b''.join(canonical(row)+b'\n' for row in rows)


def _semantic_payloads(run,config):
    result=run['analysis'];projected=event_graph(result,replay=True)
    metrics=run['metrics']
    arrivals=metrics.get('arrival_samples',metrics.get('arrivals',[]))
    return {'analysis.json':canonical(result)+b'\n','events.json':canonical(projected['events.json'])+b'\n',
            'graph.json':canonical(projected['graph.json'])+b'\n','quality.json':canonical(result['quality'])+b'\n',
            'replay.json':canonical({'schema_version':'1.0.0','replay_version':VERSION,
                'analysis_version':ANALYSIS_VERSION,'synthetic':config['synthetic'],
                'semantic_config_fingerprint':result['config_fingerprint'],
                'snapshot_count':len(run['snapshots']),'revision_count':len(run['revisions']),
                'final_snapshot_id':run['snapshots'][-1]['snapshot_id']})+b'\n',
            'snapshots.jsonl':_jsonl(run['snapshots']),'revisions.jsonl':_jsonl(run['revisions']),
            'arrivals.jsonl':_jsonl(arrivals),'metrics.json':canonical(metrics)+b'\n'}


def export_task(network,process,profile,output,*,run_id=None,attempt_id=1,replay_version=VERSION):
    networks,process,profile=_inputs(network,process,profile)
    config=read_json(profile);validate_profile(config)
    if replay_version!=VERSION or config.get('replay',{}).get('version')!=VERSION:raise ValueError('unsupported_replay_version')
    if type(attempt_id) is not int or attempt_id<1 or (run_id is not None and (not isinstance(run_id,str) or not 1<=len(run_id)<=128)):raise ValueError('invalid_execution_identity')
    before=input_rows(networks,process);profile_hash=file_hash(profile)
    output=Path(output)
    if output.exists() or output.is_symlink():raise ValueError('output_already_exists')
    output.mkdir(parents=True)
    run=None
    try:
        source=output/'sources';source.mkdir()
        for path,name in zip(networks,network_names(len(networks))):shutil.copyfile(path,source/name)
        shutil.copyfile(process,source/'process.csv');shutil.copyfile(profile,source/'profile.json')
        retained=[source/name for name in network_names(len(networks))]
        if input_rows(retained,source/'process.csv')!=before or file_hash(source/'profile.json')!=profile_hash:raise ValueError('original_changed_during_copy')
        run=execute(retained,source/'process.csv',config,pace=True)
        result=run['analysis']
        if result.get('replay',{}).get('phase')=='incomplete':raise ValueError('incomplete_replay_not_publishable')
        dataset=dataset_manifest(config,before,len(networks))
        payloads=_semantic_payloads(run,config)
        payloads['dataset.json']=canonical(dataset)+b'\n'
        payloads['runtime_metrics.json']=canonical(run['runtime_metrics'])+b'\n'
        for name,data in payloads.items():(output/name).write_bytes(data)
        if input_rows(networks,process)!=before or file_hash(profile)!=profile_hash:raise ValueError('original_changed_during_replay')
        entries=[{'path':name,'sha256':file_hash(output/name),'size_bytes':(output/name).stat().st_size}
                 for name in sorted(artifact_files_for_inputs(len(networks))-{'run_manifest.json'})]
        warnings=['replay_hypotheses_not_causality','real_source_unvalidated'] if config['synthetic'] is False else ['synthetic_replay_engineering_only']
        manifest={'schema_version':'1.0.0','synthetic':config['synthetic'],'run_id':run_id or str(uuid.uuid4()),'attempt_id':attempt_id,
                  'input_fingerprint':fingerprint(before),'config_fingerprint':fingerprint(config),
                  'semantic_config_fingerprint':result['config_fingerprint'],'replay_version':VERSION,'analysis_version':ANALYSIS_VERSION,
                  'tool_versions':{'core':__version__,'python':platform.python_version()},'mode':'replay','artifacts':entries,
                  'result_hashes':{'events':fingerprint(json.loads(payloads['events.json'])),'graph':fingerprint(json.loads(payloads['graph.json']))},
                  'limitations':result['limitations'],'status':'succeeded_with_warnings','warnings':warnings}
        validate('ReplayRunManifest',manifest)
        (output/'run_manifest.json').write_bytes(canonical(manifest)+b'\n')
        total=sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        if total>config['replay']['max_output_bytes']:raise ValueError('replay_output_limit')
        verify_task(output)
        return manifest
    except Exception as error:
        # No partial trusted publication. Failure identity/reason belongs to the
        # existing Worker failure receipt; standalone CLI reports the same reason.
        shutil.rmtree(output)
        raise
    finally:
        if run is not None:run['inputs'].close()


def _verify(output,*,retain_run=False):
    output=Path(output)
    if output.is_symlink() or not output.is_dir():raise ValueError('invalid_replay_root')
    manifest=read_json(output/'run_manifest.json');validate('ReplayRunManifest',manifest)
    if (output/'run_manifest.json').read_bytes()!=canonical(manifest)+b'\n':raise ValueError('run_manifest_encoding_mismatch')
    expected=artifact_files(output);found=set();dirs=set()
    for base,children,files in os.walk(output,followlinks=False):
        for name in children+files:
            path=Path(base)/name
            if path.is_symlink():raise ValueError('symlink_artifact')
        dirs.update((Path(base)/n).relative_to(output).as_posix() for n in children)
        found.update((Path(base)/n).relative_to(output).as_posix() for n in files)
    extras=found-expected
    if extras:
        publication=output/'manifest.json';anchor=file_hash(publication)+'.json' if publication.is_file() else None
        if extras not in ({'manifest.json'},{'manifest.json',anchor}):raise ValueError('artifact_inventory_mismatch')
        if anchor in extras and (output/anchor).read_bytes()!=publication.read_bytes():raise ValueError('publication_anchor_mismatch')
        wrapper=read_json(publication)
        if wrapper.get('replay_version')!=VERSION:raise ValueError('publication_replay_version_mismatch')
        records=wrapper.get('artifacts',[])
        if len(records)!=len(expected) or {r.get('path') for r in records}!=expected:raise ValueError('publication_inventory_mismatch')
        for row in records:
            p=output/row['path']
            if p.stat().st_size!=row['size'] or file_hash(p)!=row['sha256']:raise ValueError('publication_integrity_mismatch')
    if not expected<=found or dirs!=DIRECTORIES:raise ValueError('artifact_inventory_mismatch')
    entries=manifest['artifacts']
    if len(entries)!=len(expected)-1 or {r['path'] for r in entries}!=expected-{'run_manifest.json'}:raise ValueError('manifest_inventory_mismatch')
    for entry in entries:
        path=output/entry['path']
        if file_hash(path)!=entry['sha256'] or path.stat().st_size!=entry['size_bytes']:raise ValueError('artifact_integrity_mismatch:'+entry['path'])
    config=read_json(output/'sources/profile.json');networks=[output/'sources'/name for name in network_names(sum(row['kind']=='network' for row in read_json(output/'dataset.json')['files']))]
    _inputs(networks,output/'sources/process.csv',output/'sources/profile.json')
    rows=input_rows(networks,output/'sources/process.csv')
    if manifest['config_fingerprint']!=fingerprint(config) or manifest['input_fingerprint']!=fingerprint(rows):raise ValueError('original_binding_mismatch')
    if read_json(output/'dataset.json')!=dataset_manifest(config,rows,len(networks)):raise ValueError('dataset_original_binding_mismatch')
    if sum((output/name).stat().st_size for name in expected)>config['replay']['max_output_bytes']:raise ValueError('replay_output_limit')
    run=execute(networks,output/'sources/process.csv',config,pace=False)
    try:
        for name,data in _semantic_payloads(run,config).items():
            if (output/name).read_bytes()!=data:raise ValueError('replay_semantic_mismatch:'+name)
        if manifest['semantic_config_fingerprint']!=run['analysis']['config_fingerprint']:raise ValueError('semantic_profile_mismatch')
        for key,name in [('events','events.json'),('graph','graph.json')]:
            if manifest['result_hashes'][key]!=fingerprint(read_json(output/name)):raise ValueError('result_hash_mismatch')
        runtime=read_json(output/'runtime_metrics.json')
        if runtime.get('clock')!='monotonic_wall_seconds' or len(runtime.get('samples',[]))!=len(config['replay']['sequence']):raise ValueError('runtime_metrics_contract')
        def nonnegative(value):return type(value) in (int,float) and math.isfinite(value) and value>=0
        if runtime.get('speed')!=config['replay'].get('speed',1) or type(runtime.get('paced')) is not bool or not nonnegative(runtime.get('elapsed_seconds')):raise ValueError('runtime_metrics_contract')
        previous=0
        for index,(sample,step) in enumerate(zip(runtime['samples'],config['replay']['sequence']),1):
            expected=(instant(step['available_at'])-instant(config['replay']['simulation_start'])).total_seconds()/runtime['speed']
            if sample.get('arrival_seq')!=index or sample.get('available_at')!=step['available_at'] or sample.get('scheduled_elapsed_seconds')!=expected:raise ValueError('runtime_schedule_mismatch')
            if any(not nonnegative(sample.get(key)) for key in ('actual_elapsed_seconds','processing_seconds')):raise ValueError('runtime_metrics_contract')
            actual=sample['actual_elapsed_seconds']
            if actual<previous or actual>runtime['elapsed_seconds'] or (runtime['paced'] and actual<expected):raise ValueError('runtime_sample_order')
            previous=actual
        if len(runtime.get('core_samples',[]))!=len(run['runtime_metrics']['core_samples']) or any(not nonnegative(sample.get('wall_seconds')) for sample in runtime.get('core_samples',[])):raise ValueError('runtime_core_samples')
        if retain_run:return manifest,run
        return manifest
    except Exception:
        if retain_run:run['inputs'].close()
        raise
    finally:
        if not retain_run:run['inputs'].close()


def verify_task(output):return _verify(output)


def _snapshot(run,revision):
    if isinstance(revision,str) and revision.isdigit():revision=int(revision)
    if type(revision) is not int or revision<0:raise KeyError('invalid_revision')
    rows=[row for row in run['snapshots'] if row.get('snapshot_number')==revision]
    if len(rows)!=1:raise KeyError('unknown_revision')
    return rows[0]


def snapshot_task(output,revision):
    _,run=_verify(output,retain_run=True)
    try:return json.loads(canonical(_snapshot(run,revision)))
    finally:run['inputs'].close()


def list_revisions(output,after=0,limit=100):
    if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=8192:raise ValueError('invalid_history_page')
    _,run=_verify(output,retain_run=True)
    try:return deepcopy(run['revisions'][after:after+limit])
    finally:run['inputs'].close()


def query_task(output,revision,operation_id=None,change_id=None):
    if (operation_id is None)==(change_id is None):raise ValueError('select_exactly_one_operation_or_change')
    _,run=_verify(output,retain_run=True)
    try:
        snapshot=_snapshot(run,revision);analysis=snapshot['analysis']
        if operation_id is not None:
            matches=analysis['operations'][:1] if operation_id=='first' else [r for r in analysis['operations'] if r['operation_id']==operation_id]
            if len(matches)!=1:raise KeyError('unknown_operation')
            selected={'operation':matches[0],'candidates':[r for r in analysis['candidates'] if r['operation_id']==matches[0]['operation_id']]}
        else:
            matches=analysis['changes'][:1] if change_id=='first' else [r for r in analysis['changes'] if r['event_id']==change_id]
            if len(matches)!=1:raise KeyError('unknown_change')
            selected={'change':matches[0]}
        refs=references(selected);inputs=run['inputs']
        resolved=[{'source_ref':r,'original':inputs.resolve(r)} for r in refs]
        selected_frames={(r['source_slot'],r['frame_number']) for r in refs if r['frame_number'] is not None};fields=[]
        for row in analysis['network']:
            if any((r['source_slot'],r['frame_number']) in selected_frames for r in row['observation']['source_refs']):
                fields.append({'event_id':row['event']['event_id'],'fields':{name:[inputs.resolve(piece['source_ref'],piece) for piece in field['slices']] for name,field in row['observation']['fields'].items()}})
        return {'synthetic':analysis['synthetic'],'revision':int(revision),'selection':selected,
                'available_at':snapshot['available_at'],'verified_original_evidence':resolved,'verified_network_fields':fields,
                'config_fingerprint':analysis['config_fingerprint'],'limitations':analysis['limitations']}
    finally:run['inputs'].close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--network',action='append');parser.add_argument('--process');parser.add_argument('--profile');parser.add_argument('--output',required=True)
    parser.add_argument('--run-id');parser.add_argument('--attempt-id',type=int,default=1);parser.add_argument('--replay-version',default=VERSION)
    parser.add_argument('--verify',action='store_true');parser.add_argument('--revision',type=int);parser.add_argument('--operation');parser.add_argument('--change')
    args=parser.parse_args()
    try:
        if args.operation is not None or args.change is not None:
            result=query_task(args.output,args.revision,operation_id=args.operation,change_id=args.change)
        elif args.revision is not None:result=snapshot_task(args.output,args.revision)
        elif args.verify:result=verify_task(args.output)
        else:
            if not all((args.network,args.process,args.profile)):raise ValueError('network_process_profile_required')
            result=export_task(args.network,args.process,args.profile,args.output,run_id=args.run_id,attempt_id=args.attempt_id,replay_version=args.replay_version)
    except (OSError,ValueError,KeyError,TypeError) as error:parser.exit(2,str(error)+'\n')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
