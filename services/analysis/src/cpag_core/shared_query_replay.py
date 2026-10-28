"""Authenticated historical DAG6 selection and genuinely arrived raw evidence."""
from pathlib import Path

from .capacity import parser_limits,resolve_capacity_profile
from .dual_source import references
from .pipeline import canonical
from .replay_inputs import ReplayInputs


def _count(reader,path):
    return reader._node(reader._select('history/snapshots',path))[3]


def _get(reader,path):
    return reader.get('history/snapshots',path=path)


def _find(reader,base,collection,key,identity):
    total=_count(reader,[*base,collection])
    if identity=='first':
        if total:return _get(reader,[*base,collection,0])
        return None
    for index in range(total):
        if _get(reader,[*base,collection,index,key])==identity:return _get(reader,[*base,collection,index])
    return None


def query_compact(output,reader,*,operation_id=None,change_id=None,snapshot=None,trigger=False,ref_offset=0,ref_limit=100,deadline=None):
    from .shared_export import read_json,network_names,_bounded,QUERY_BYTES
    manifest=reader.run_manifest
    if snapshot is None:snapshot=manifest['final_snapshot_number']
    if type(snapshot) is not int or not 0<=snapshot<manifest['counts']['snapshots']:raise KeyError('unknown_snapshot')
    base=[snapshot,'analysis'];metadata={key:_get(reader,[snapshot,key]) for key in ('snapshot_id','available_at','arrival_seq','revision_number','trigger')}
    if trigger:selected={'trigger':metadata['trigger']}
    elif operation_id is not None:
        operation=_find(reader,base,'operations','operation_id',operation_id)
        if operation is None:raise KeyError('unknown_operation')
        wanted=set(operation['candidates']);candidates=[];size=len(canonical(operation))+64
        # Candidates may move when operations close. Match immutable business IDs
        # against this exact snapshot, without reusing final-state row positions.
        total=_count(reader,[*base,'candidates'])
        for index in range(total):
            if not wanted:break
            identity=_get(reader,[*base,'candidates',index,'candidate_id'])
            if identity in wanted:
                path=[*base,'candidates',index]
                size+=reader._node(reader._select('history/snapshots',path))[2]+1
                if size>QUERY_BYTES:raise ValueError('shared_query_output_limit')
                candidates.append(_get(reader,path));wanted.remove(identity)
        if wanted:raise ValueError('historical_operation_candidate_ids_missing')
        changes=[]
        for identity in sorted({row['change_id'] for row in candidates}):
            change=_find(reader,base,'changes','event_id',identity)
            if change is None:raise ValueError('historical_candidate_change_missing')
            size+=len(canonical(change))+1
            if size>QUERY_BYTES:raise ValueError('shared_query_output_limit')
            changes.append(change)
        selected={'operation':operation,'candidates':candidates,'changes':changes}
    else:
        change=_find(reader,base,'changes','event_id',change_id)
        if change is not None:selected={'change':change}
        else:
            try:finding=_find(reader,base,'rule_findings','finding_id',change_id)
            except ValueError:finding=None
            if finding is None:raise KeyError('unknown_change')
            selected={'rule_finding':finding}
    _bounded(selected)
    refs=references(selected)
    def identity(ref):return ref['source_slot'],ref.get('frame_number'),ref.get('record_number'),ref['record_sha256']
    missing={identity(ref) for ref in refs}
    available_path=[*base,'replay','available_record_refs'];total_available=_count(reader,available_path)
    for offset in range(0,total_available,100):
        if not missing:break
        available=reader.page('history/snapshots',path=available_path,offset=offset,limit=100)['items']
        for ref in available:missing.discard(identity(ref))
    if missing:raise ValueError('historical_reference_not_arrived')
    total=len(refs);page=refs[ref_offset:ref_offset+ref_limit]
    root=Path(output);config=read_json(root/'sources/profile.json');limits=parser_limits(config);budget=resolve_capacity_profile(config)
    inputs=ReplayInputs([root/'sources'/name for name in network_names(manifest['network_count'])],root/'sources/process.csv',config['process'],synthetic=config['synthetic'],
        capacity_config=config,digest_strategy='incremental-prefix-digest-2',packet_limits=limits['packet_limits'],process_limits=limits['process_limits'],stream_limits=limits['stream_limits'],
        max_records=budget.frames+budget.process_records+1)
    try:
        # Only replay raw arrival records up to this authenticated snapshot. No
        # source snapshot/judgement is computed and no future raw unit is read.
        for step in config['replay']['sequence'][:metadata['arrival_seq']]:
            kind=step.get('kind')
            if kind=='advance':continue
            if kind=='source_eof':inputs.finish_source(step['source_slot'])
            else:inputs.advance(step)
        originals=[{'source_ref':ref,'original':inputs.resolve(ref)} for ref in page]
        frames={(ref['source_slot'],ref['frame_number']) for ref in page if ref['frame_number'] is not None}
        fields=[]
        if frames:
            for index in range(_count(reader,[*base,'network'])):
                source_refs=_get(reader,[*base,'network',index,'observation','source_refs'])
                if not any((ref['source_slot'],ref['frame_number']) in frames for ref in source_refs):continue
                row=_get(reader,[*base,'network',index])
                fields.append({'event_id':row['event']['event_id'],'fields':{name:[inputs.resolve(piece['source_ref'],piece) for piece in value['slices'] if (piece['source_ref']['source_slot'],piece['source_ref']['frame_number']) in frames] for name,value in row['observation']['fields'].items()}})
        result={'mode':'dual_source_replay','replay_version':'dual-source-replay-1','history_format':manifest['history_format'],'storage_format':manifest['storage_format'],
            'identity_strategy':'merkle-json-dag-1','synthetic':manifest['synthetic'],'revision':snapshot,'snapshot_id':metadata['snapshot_id'],'available_at':metadata['available_at'],
            'selection':selected,'verified_original_evidence':originals,'verified_network_fields':fields,'quality':_get(reader,[*base,'quality']),
            'config_fingerprint':_get(reader,[*base,'config_fingerprint']),'limitations':_get(reader,[*base,'limitations']),
            'evidence_page':{'version':'source-reference-page-1','offset':ref_offset,'limit':ref_limit,'total':total,'returned':len(page),'has_more':ref_offset+len(page)<total,'order':'canonical_source_reference'}}
        return _bounded(result)
    finally:inputs.close()
