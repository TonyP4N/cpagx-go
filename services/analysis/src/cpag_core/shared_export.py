"""Explicit core-only DAG6 publisher, complete source verifier and bounded reader.

No Worker/service/backup authority is implemented here. Local read approvals are
capabilities issued only after full source rebuilding by a trusted coordinator;
the coordinator keeps the key in RAM and never in the artifact or CLI arguments.
"""
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
import time
import uuid

from . import __version__
from .capacity import resolve_capacity_profile,shared_storage_budget,parser_limits,COMPACT
from .contracts import validate
from .dual_source import analyze,strict_json,network_paths,references,R17_VERSION
from .dual_source_rules import validate_profile
from .dual_source_export import event_graph,_warnings
from .measurement import phase
from .pipeline import canonical,file_hash,fingerprint
from .replay_history import _ordinary,_digest
from .shared_artifact_store_compact import FORMAT,SharedArtifactWriter,SharedArtifactReader,_APPROVED_READ

APPROVAL_VERSION='core-read-approval-2'
QUERY_BYTES=8*1024**2
STANDARD=('analysis.json','dual/analysis.json','events.json','graph.json','quality.json','dataset.json')
INDEX_ROOTS=('indices/operations','indices/changes','indices/candidates_by_operation','indices/network_by_frame','indices/rule_findings')


def read_json(path,maximum=8*1024**2):
    path=Path(path);_ordinary(path)
    if path.stat().st_size>maximum:raise ValueError('shared_json_byte_limit')
    return strict_json(path.read_text())


def network_names(count):
    if type(count) is not int or not 1<=count<=4:raise ValueError('network_file_limit')
    return ['network.pcap']+['network-%03d.pcap'%index for index in range(1,count)]


def artifact_files_for_inputs(count,*,mode='offline',storage_format=FORMAT):
    if mode not in ('offline','replay') or storage_format!=FORMAT:raise ValueError('unsupported_shared_mode_or_format')
    return frozenset(('run_manifest.json','shared/manifest.json','shared/shared.sqlite3','sources/profile.json','sources/process.csv',*('sources/'+name for name in network_names(count))))


def artifact_files(output):
    manifest=read_json(Path(output)/'run_manifest.json',65536)
    return artifact_files_for_inputs(manifest['network_count'],mode=manifest['mode'],storage_format=manifest['storage_format'])


def _inventory(root,manifest):
    expected=artifact_files_for_inputs(manifest['network_count'],mode=manifest['mode'],storage_format=manifest['storage_format'])
    found=set();directories=set()
    if root.is_symlink() or not root.is_dir():raise ValueError('shared_output_invalid')
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in (*dirs,*files):
            if (Path(directory)/name).is_symlink():raise ValueError('shared_symlink_artifact')
        directories.update((Path(directory)/name).relative_to(root).as_posix() for name in dirs)
        for name in files:
            path=Path(directory)/name;_ordinary(path);found.add(path.relative_to(root).as_posix())
    if found!=expected or directories!={'shared','sources'}:raise ValueError('shared_inventory_mismatch')
    entries=manifest['artifacts']
    if len(entries)!=len(expected)-1 or {entry['path'] for entry in entries}!=expected-{'run_manifest.json'}:raise ValueError('shared_artifact_entries_mismatch')
    total=(root/'run_manifest.json').stat().st_size
    for entry in entries:
        path=root/entry['path'];total+=path.stat().st_size
        if path.stat().st_size!=entry['size_bytes'] or file_hash(path)!=entry['sha256']:raise ValueError('shared_artifact_changed:'+entry['path'])
    if total>manifest['storage_budget']['physical_bytes']:raise ValueError('shared_total_physical_limit')


def _source_rows(root,count):
    return [{'kind':kind,'sha256':file_hash(root/'sources'/name),'size_bytes':(root/'sources'/name).stat().st_size}
        for kind,name in [('network',name) for name in network_names(count)]+[('process','process.csv')]]


def writer_options(config,max_bytes,deadline=None):
    budget=shared_storage_budget(config)
    return dict(max_bytes=max_bytes,max_nodes=budget.max_nodes,max_roots=budget.max_roots,
        max_node_bytes=budget.max_node_bytes,max_array_items=500000,max_logical_root_bytes=budget.max_logical_root_bytes,deadline=deadline)


def _dataset(config,rows,count,analysis):
    dataset={'schema_version':'1.0.0','synthetic':config['synthetic'],'dataset_id':'dual-dataset-'+analysis['input_fingerprint'],
        'source':'retained explicitly classified dual-source inputs','release':analysis['analysis_version'],
        'files':[dict(row,name=name) for row,name in zip(rows,[*network_names(count),'process.csv'])],
        'collection_range':{'start':None,'end':None},'timezone_basis':'configured offsets and uncertainties in retained profile',
        'authorization_ref':'declared source authorization; not industrial validation'}
    if config['synthetic'] is False:
        dataset.update({key:config['source_provenance'][key] for key in ('source','release','collection_range','timezone_basis','authorization_ref')})
    validate('DatasetManifest',dataset)
    return dataset


def _indices(writer,analysis):
    writer.add('indices/operations',sorted([[row['operation_id'],index] for index,row in enumerate(analysis['operations'])]))
    writer.add('indices/changes',sorted([[row['event_id'],index] for index,row in enumerate(analysis['changes'])]))
    writer.add('indices/rule_findings',sorted([[row['finding_id'],index] for index,row in enumerate(analysis.get('rule_findings',[]))]))
    grouped=defaultdict(list)
    for index,row in enumerate(analysis['candidates']):grouped[row['operation_id']].append(index)
    writer.add('indices/candidates_by_operation',sorted([[key,value] for key,value in grouped.items()]))
    grouped=defaultdict(list)
    for index,row in enumerate(analysis['network']):
        for ref in row['observation']['source_refs']:
            grouped[canonical([ref.get('source_slot',ref.get('file_sha256')),ref['frame_number']]).decode()].append(index)
    writer.add('indices/network_by_frame',sorted([[key,sorted(set(value))] for key,value in grouped.items()]))


@phase('complete_export')
def export_task(network,process,profile,output,*,run_id=None,attempt_id=1,mode='offline',deadline=None,_rebuild=False):
    """Publish every final observation/claim in an explicit compact core format."""
    output=Path(output)
    if output.exists() or output.is_symlink():raise ValueError('output_already_exists')
    config=read_json(profile)
    validate_profile(config)
    if resolve_capacity_profile(config).version!=COMPACT or config.get('storage_format')!=FORMAT:raise ValueError('compact_capacity_profile_required')
    if mode not in ('offline','replay') or ('replay' in config)!=(mode=='replay'):raise ValueError('shared_mode_profile_mismatch')
    if run_id is None:run_id=str(uuid.uuid4())
    if not isinstance(run_id,str) or not 1<=len(run_id)<=128 or type(attempt_id) is not int or not 1<=attempt_id<=1000000:raise ValueError('invalid_run_attempt')
    networks=network_paths(network);names=network_names(len(networks));budget=shared_storage_budget(config)
    output.mkdir(parents=True,mode=0o700)
    writer=None;run=None
    try:
        (output/'sources').mkdir(mode=0o700)
        for original,name in list(zip(networks,names))+[(Path(process),'process.csv'),(Path(profile),'profile.json')]:
            _ordinary(original);before=file_hash(original);shutil.copyfile(original,output/'sources'/name)
            if file_hash(original)!=before or file_hash(output/'sources'/name)!=before:raise ValueError('source_changed_during_copy')
        rows=_source_rows(output,len(networks));source_fingerprint=fingerprint(rows)
        used=sum(path.stat().st_size for path in (output/'sources').iterdir())
        remaining=budget.physical_bytes-used-65536
        if remaining<256*1024:raise ValueError('shared_source_and_metadata_reserve_limit')
        context={'run_id':run_id,'attempt_id':attempt_id,'input_fingerprint':source_fingerprint,'config_fingerprint':fingerprint(config)}
        writer=SharedArtifactWriter(output/'shared',context=context,version=FORMAT,**writer_options(config,remaining,deadline))
        retained=[output/'sources'/name for name in names]
        if mode=='offline':
            analysis=analyze(retained if len(retained)>1 else retained[0],output/'sources/process.csv',config)
            history={}
        else:
            from .compact_replay import execute_compact
            run=execute_compact(retained,output/'sources/process.csv',config,writer,deadline=deadline)
            analysis=run['analysis'];history=run['history']
        projected=event_graph(analysis,replay=mode=='replay',identity_strategy='merkle-json-dag-1')
        writer.add('analysis.json',analysis);writer.alias('dual/analysis.json','analysis.json')
        for name,value in projected.items():writer.add(name,value)
        writer.add('quality.json',analysis['quality']);writer.add('dataset.json',_dataset(config,rows,len(networks),analysis))
        _indices(writer,analysis)
        if run is not None:
            writer.add('metrics.json',run['metrics']);writer.add('runtime_metrics.json',run['runtime_metrics'])
            writer.add('arrivals.json',run['metrics'].get('arrival_samples',run['metrics'].get('arrivals',[])))
            writer.add('replay.json',history)
        counts={key:len(analysis[key]) for key in ('network','process','operations','changes','candidates')}
        counts.update(snapshots=history.get('snapshot_count',0),revisions=history.get('revision_count',0))
        logical_names=[*STANDARD,*INDEX_ROOTS]+(['metrics.json','runtime_metrics.json','arrivals.json','replay.json','history/snapshots','history/revisions'] if mode=='replay' else [])
        logical=[writer.descriptor(name) for name in logical_names]
        result_hashes={key:writer.descriptor(key+'.json')['digest'] for key in ('events','graph')}
        sealed=writer.seal()
        warnings=_warnings(analysis)
        manifest={'schema_version':'1.0.0','synthetic':config['synthetic'],'run_id':run_id,'attempt_id':attempt_id,'mode':mode,
            'input_fingerprint':analysis['input_fingerprint'],'source_fingerprint':source_fingerprint,'config_fingerprint':fingerprint(config),
            'semantic_config_fingerprint':analysis['config_fingerprint'],'tool_versions':{'core':__version__,'python':platform.python_version()},
            'storage_format':FORMAT,'storage_budget':asdict(budget),'network_count':len(networks),'shared_manifest_sha256':sealed['manifest_sha256'],
            'result_hashes':result_hashes,'result_hash_kind':'merkle-json-dag-1','graph_identity_strategy':'merkle-json-dag-1',
            'logical_artifacts':logical,'counts':counts,'warnings':warnings,'limitations':analysis['limitations'],
            'status':'succeeded_with_warnings' if warnings else 'succeeded','artifacts':[]}
        if mode=='replay':
            manifest.update(history_format=FORMAT,identity_strategy='merkle-json-dag-1',prefix_digest_strategy='incremental-prefix-digest-2',
                replay_version='dual-source-replay-1',final_snapshot_number=counts['snapshots']-1,final_snapshot_id=history['last_snapshot_id'])
        for name in sorted(artifact_files_for_inputs(len(networks),mode=mode)-{'run_manifest.json'}):
            path=output/name;manifest['artifacts'].append({'path':name,'sha256':file_hash(path),'size_bytes':path.stat().st_size})
        validate('CompactStoreRunManifest',manifest)
        raw=canonical(manifest)+b'\n'
        if len(raw)>65536:raise ValueError('shared_run_manifest_byte_limit')
        (output/'run_manifest.json').write_bytes(raw)
        # All physical bytes and source inputs are bound before returning. A
        # separate verify_task rebuild is the independent source check.
        _inventory(output,manifest)
        if not _rebuild:
            with open_reader(output,deadline=deadline):pass
        return manifest
    except BaseException as error:
        if writer is not None:writer.close()
        # Failed-attempt bytes remain available for diagnosis. The marker makes
        # the inventory unconditionally untrusted; no approval can be issued.
        # A new attempt must use a new directory, never overwrite this evidence.
        if output.exists():
            try:
                (output/'FAILED.json').write_bytes(canonical({'version':'compact-failed-attempt-1',
                    'status':'failed','error_type':type(error).__name__,'reason':str(error),
                    'trusted_result':False})+b'\n')
            except OSError:pass  # e.g. disk full: caller still fails explicitly
        raise
    finally:
        if run is not None and run.get('inputs') is not None:run['inputs'].close()


def _bound(output,deadline=None):
    root=Path(output);manifest=read_json(root/'run_manifest.json',65536)
    if (root/'run_manifest.json').read_bytes()!=canonical(manifest)+b'\n':raise ValueError('shared_manifest_encoding_invalid')
    validate('CompactStoreRunManifest',manifest)
    config=read_json(root/'sources/profile.json');validate_profile(config)
    if config.get('storage_format')!=FORMAT or manifest['storage_format']!=FORMAT or manifest['storage_budget']!=asdict(shared_storage_budget(config)) or manifest['config_fingerprint']!=fingerprint(config):raise ValueError('shared_profile_manifest_mismatch')
    if (manifest['mode']=='replay')!=('replay' in config):raise ValueError('shared_mode_profile_mismatch')
    if manifest['synthetic'] is not config['synthetic']:raise ValueError('shared_source_classification_mismatch')
    replay_fields={'history_format','identity_strategy','prefix_digest_strategy','replay_version','final_snapshot_number','final_snapshot_id'}
    if manifest['mode']=='offline' and set(manifest)&replay_fields:raise ValueError('offline_manifest_has_history')
    if manifest['mode']=='replay' and not replay_fields<=set(manifest):raise ValueError('replay_manifest_missing_history')
    _inventory(root,manifest)
    if manifest['source_fingerprint']!=fingerprint(_source_rows(root,manifest['network_count'])):raise ValueError('shared_source_fingerprint_mismatch')
    context={'run_id':manifest['run_id'],'attempt_id':manifest['attempt_id'],'input_fingerprint':manifest['source_fingerprint'],'config_fingerprint':manifest['config_fingerprint']}
    return root,manifest,config,context


@contextmanager
def open_reader(output,*,deadline=None,approval=None,authority_key=None):
    """Read complete logical roots; optional coordinator capability avoids replay."""
    root,manifest,_,context=_bound(output,deadline)
    token=None
    if approval is not None:
        check_approval(root,approval,authority_key,manifest=manifest)
        token=_APPROVED_READ
    reader=SharedArtifactReader(root/'shared',expected_manifest_sha256=manifest['shared_manifest_sha256'],expected_context=context,deadline=deadline,_approval_token=token)
    try:
        declared=manifest['logical_artifacts']
        if reader.manifest['root_count']!=len(declared):raise ValueError('shared_unregistered_logical_root')
        if len({item['name'] for item in declared})!=len(declared):raise ValueError('shared_duplicate_logical_artifact')
        for descriptor in declared:
            if reader.descriptor(descriptor['name'])!=descriptor:raise ValueError('shared_logical_root_binding_mismatch')
        if manifest['mode']=='replay':
            last=manifest['counts']['snapshots']-1
            if last<0 or manifest['final_snapshot_number']!=last:
                raise ValueError('shared_terminal_snapshot_number_mismatch')
            if reader.get('history/snapshots',path=[last,'snapshot_id'])!=manifest['final_snapshot_id']:
                raise ValueError('shared_terminal_snapshot_id_mismatch')
        reader.run_manifest=manifest
        yield reader
    finally:reader.close()


@phase('artifact_verification')
def verify_task(output,*,deadline=None):
    """Full retained-source rebuild and all business-root Merkle comparison."""
    root,manifest,config,_=_bound(output,deadline)
    with open_reader(root,deadline=deadline) as original:
        expected={row['name']:row for row in manifest['logical_artifacts']}
        # Replay wall-clock observations are retained and physically authenticated
        # but are not deterministic claims reconstructed from source timestamps.
        with tempfile.TemporaryDirectory(prefix='cpag-compact-verify-') as temporary:
            destination=Path(temporary)/'replica'
            rebuilt=export_task([root/'sources'/name for name in network_names(manifest['network_count'])],root/'sources/process.csv',root/'sources/profile.json',destination,
                run_id=manifest['run_id'],attempt_id=manifest['attempt_id'],mode=manifest['mode'],deadline=deadline,_rebuild=True)
            actual={row['name']:row for row in rebuilt['logical_artifacts']}
            if set(expected)!=set(actual):raise ValueError('shared_rebuilt_logical_inventory_mismatch')
            for name,descriptor in expected.items():
                if name!='runtime_metrics.json' and descriptor!=actual[name]:raise ValueError('shared_business_root_does_not_match_sources:'+name)
            for key in ('synthetic','final_snapshot_number','final_snapshot_id','counts','input_fingerprint','source_fingerprint','config_fingerprint','semantic_config_fingerprint','result_hashes','warnings','limitations','status'):
                if manifest.get(key)!=rebuilt.get(key):raise ValueError('shared_rebuilt_manifest_mismatch:'+key)
    return manifest


def issue_approval(output,key,*,deadline=None,lifetime_seconds=3600):
    if not isinstance(key,bytes) or len(key)!=32 or type(lifetime_seconds) is not int or not 1<=lifetime_seconds<=3600:raise ValueError('core_approval_key_or_lifetime_invalid')
    manifest=verify_task(output,deadline=deadline)
    issued=int(time.time())
    payload={'version':APPROVAL_VERSION,'storage_format':FORMAT,'run_id':manifest['run_id'],'attempt_id':manifest['attempt_id'],
        'manifest_sha256':hashlib.sha256(canonical(manifest)+b'\n').hexdigest(),'inventory_sha256':fingerprint(manifest['artifacts']),
        'logical_roots_sha256':fingerprint(manifest['logical_artifacts']),'issued_at':issued,'expires_at':issued+lifetime_seconds}
    return {'payload':payload,'mac':hmac.new(key,canonical(payload),hashlib.sha256).hexdigest()}


def check_approval(output,approval,key,*,manifest=None):
    if not isinstance(key,bytes) or len(key)!=32 or not isinstance(approval,dict) or set(approval)!={'payload','mac'}:raise ValueError('core_approval_invalid')
    payload=approval['payload']
    if not isinstance(payload,dict) or set(payload)!={'version','storage_format','run_id','attempt_id','manifest_sha256','inventory_sha256','logical_roots_sha256','issued_at','expires_at'} or not isinstance(approval['mac'],str):raise ValueError('core_approval_invalid')
    if not hmac.compare_digest(approval['mac'],hmac.new(key,canonical(payload),hashlib.sha256).hexdigest()):raise ValueError('core_approval_mac_invalid')
    now=int(time.time())
    if payload['version']!=APPROVAL_VERSION or payload['storage_format']!=FORMAT or type(payload['issued_at']) is not int or type(payload['expires_at']) is not int or not payload['issued_at']<=now<=payload['expires_at'] or not 1<=payload['expires_at']-payload['issued_at']<=3600:raise ValueError('core_approval_expired_or_version_invalid')
    if manifest is None:_,manifest,_,_=_bound(output)
    if payload['manifest_sha256']!=file_hash(Path(output)/'run_manifest.json') or payload['inventory_sha256']!=fingerprint(manifest['artifacts']) or payload['logical_roots_sha256']!=fingerprint(manifest['logical_artifacts']) or payload['run_id']!=manifest['run_id'] or payload['attempt_id']!=manifest['attempt_id']:raise ValueError('core_approval_binding_mismatch')
    return manifest


def metadata_task(output,*,deadline=None,approval=None,authority_key=None):
    if approval is None:verify_task(output,deadline=deadline)
    with open_reader(output,deadline=deadline,approval=approval,authority_key=authority_key) as reader:
        manifest=reader.run_manifest
        first=reader.get('analysis.json',path=['operations',0,'operation_id']) if manifest['counts']['operations'] else None
        return {'storage_format':FORMAT,'mode':manifest['mode'],'manifest':manifest,'counts':manifest['counts'],
            'first_operation_id':first,'final_snapshot_number':manifest.get('final_snapshot_number'),
            'complete_logical_result_hashes':manifest['result_hashes'],'result_hash_kind':'merkle-json-dag-1',
            'verification':'bound_core_read_capability' if approval is not None else 'source_replayed_storage_and_business_fields_verified'}


def _find(reader,root,key):
    total=reader.descriptor(root)['items'];low=0;high=total
    while low<high:
        middle=(low+high)//2;value=reader.get(root,path=[middle])
        if value[0]<key:low=middle+1
        elif value[0]>key:high=middle
        else:return value[1]
    return None


def _bounded(value):
    from .pipeline import json_chunks
    count=0
    for chunk in json_chunks(value):
        count+=len(chunk)
        if count>QUERY_BYTES:raise ValueError('shared_query_output_limit')
    return value


def query_task(output,operation_id=None,change_id=None,*,snapshot=None,trigger=False,ref_offset=0,ref_limit=100,deadline=None,approval=None,authority_key=None):
    if approval is None:verify_task(output,deadline=deadline)
    if type(ref_offset) is not int or ref_offset<0 or type(ref_limit) is not int or not 1<=ref_limit<=100:raise ValueError('evidence_page_outside_budget')
    if sum((operation_id is not None,change_id is not None,trigger))!=1:raise ValueError('select_exactly_one_operation_change_trigger')
    with open_reader(output,deadline=deadline,approval=approval,authority_key=authority_key) as reader:
        manifest=reader.run_manifest
        if manifest['mode']=='replay':
            from .shared_query_replay import query_compact
            return query_compact(output,reader,operation_id=operation_id,change_id=change_id,snapshot=snapshot,trigger=trigger,ref_offset=ref_offset,ref_limit=ref_limit,deadline=deadline)
        if snapshot is not None or trigger:raise ValueError('offline_snapshot_or_trigger_invalid')
        if operation_id is not None:
            index=0 if operation_id=='first' and manifest['counts']['operations'] else _find(reader,'indices/operations',operation_id)
            if index is None:raise KeyError('unknown_operation')
            operation=reader.get('analysis.json',path=['operations',index]);indices=_find(reader,'indices/candidates_by_operation',operation['operation_id']) or []
            candidates=[];selected_size=len(canonical(operation))+64
            for number in indices:
                path=['candidates',number]
                selected_size+=reader._node(reader._select('analysis.json',path))[2]+1
                if selected_size>QUERY_BYTES:raise ValueError('shared_query_output_limit')
                candidates.append(reader.get('analysis.json',path=path))
            changes=[]
            for identity in sorted({row['change_id'] for row in candidates}):
                path=['changes',_find(reader,'indices/changes',identity)]
                selected_size+=reader._node(reader._select('analysis.json',path))[2]+1
                if selected_size>QUERY_BYTES:raise ValueError('shared_query_output_limit')
                changes.append(reader.get('analysis.json',path=path))
            selected={'operation':operation,'candidates':candidates,'changes':changes}
        else:
            index=0 if change_id=='first' and manifest['counts']['changes'] else _find(reader,'indices/changes',change_id)
            if index is not None:selected={'change':reader.get('analysis.json',path=['changes',index])}
            else:
                index=_find(reader,'indices/rule_findings',change_id)
                if index is None:raise KeyError('unknown_change')
                selected={'rule_finding':reader.get('analysis.json',path=['rule_findings',index])}
        _bounded(selected)
        refs=references(selected);total=len(refs);page=refs[ref_offset:ref_offset+ref_limit]
        root=Path(output);config=read_json(root/'sources/profile.json');limits=parser_limits(config)
        from .packet_pipeline import PacketEvidence
        from .evidence import EvidenceIndex
        networks=[root/'sources'/name for name in network_names(manifest['network_count'])]
        packet=PacketEvidence(networks if len(networks)>1 else networks[0],synthetic=config['synthetic'],limits=limits['packet_limits'],capture_limits=limits['capture_limits'])
        csv=EvidenceIndex(root/'sources/process.csv')
        with packet.verified_batch():
            originals=[{'source_ref':ref,'original':packet.resolve(ref) if ref['frame_number'] is not None else csv.resolve(ref)} for ref in page]
            frames={(ref['file_sha256'],ref['frame_number']) for ref in page if ref['frame_number'] is not None};row_indices=set()
            for digest,number in frames:
                row_indices.update(_find(reader,'indices/network_by_frame',canonical([digest,number]).decode()) or [])
            fields=[]
            for number in sorted(row_indices):
                row=reader.get('analysis.json',path=['network',number])
                fields.append({'event_id':row['event']['event_id'],'fields':{name:[packet.resolve(piece['source_ref'],piece) for piece in value['slices'] if (piece['source_ref']['file_sha256'],piece['source_ref']['frame_number']) in frames] for name,value in row['observation']['fields'].items()}})
        csv.verify()
        result={'synthetic':manifest['synthetic'],'storage_format':FORMAT,'selection':selected,'quality':reader.get('quality.json'),
            'verified_original_evidence':originals,'verified_network_fields':fields,'time_configuration':config['clocks'],
            'source_ranges':reader.get('quality.json',path=['source_ranges']),'config_version':config['config_version'],
            'config_fingerprint':manifest['config_fingerprint'],'limitations':manifest['limitations'],
            'evidence_page':{'version':'source-reference-page-1','offset':ref_offset,'limit':ref_limit,'total':total,'returned':len(page),'has_more':ref_offset+len(page)<total,'order':'canonical_source_reference'}}
        return _bounded(result)
