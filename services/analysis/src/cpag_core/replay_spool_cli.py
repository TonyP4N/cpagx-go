"""Bounded read-only bridge. Root is selected by the authorized service, never URL paths."""
import argparse
import json
import io
import sqlite3
from .pipeline import canonical, json_chunks
from .replay_history import VERSION as FORMAT
from .replay_export import verify_task, snapshot_task, query_task, list_revisions

LIMIT = 8 * 1024 * 1024


def evidence(root, number, operation, change, trigger, ref_offset=0, ref_limit=100):
    from .replay_export import _verify,_snapshot,_close_run
    from .dual_source import references
    if type(trigger) is not bool or sum((operation is not None,change is not None,trigger))!=1:
        raise ValueError('select_exactly_one_operation_change_or_trigger')
    if type(ref_offset) is not int or ref_offset<0 or type(ref_limit) is not int or not 1<=ref_limit<=100:raise ValueError('evidence_page_outside_budget')
    _,run=_verify(root,retain_run=True)
    try:
        snapshot=_snapshot(run,number);analysis=snapshot['analysis']
        if trigger:selected={'trigger':snapshot['trigger']}
        elif operation is not None:
            rows=analysis['operations'][:1] if operation=='first' else [row for row in analysis['operations'] if row['operation_id']==operation]
            if len(rows)!=1:raise KeyError('unknown_operation')
            candidates=[row for row in analysis['candidates'] if row['operation_id']==rows[0]['operation_id']]
            changes={row['change_id'] for row in candidates}
            selected={'operation':rows[0],'candidates':candidates,'changes':[row for row in analysis['changes'] if row['event_id'] in changes]}
        else:
            rows=analysis['changes'][:1] if change=='first' else [row for row in analysis['changes'] if row['event_id']==change]
            findings=[row for row in analysis.get('rule_findings',[]) if row['finding_id']==change]
            if len(rows)+len(findings)!=1:raise KeyError('unknown_or_ambiguous_change')
            selected={'change':rows[0]} if rows else {'rule_finding':findings[0]}
        refs=references(selected);inputs=run['inputs']
        def key(ref):return ref['source_slot'],ref.get('frame_number'),ref.get('record_number'),ref['record_sha256']
        available={key(ref) for ref in analysis['replay']['available_record_refs']}
        if any(key(ref) not in available for ref in refs):raise ValueError('historical_reference_not_arrived')
        total=len(refs);refs=refs[ref_offset:ref_offset+ref_limit]
        originals=[{'source_ref':ref,'original':inputs.resolve(ref)} for ref in refs]
        selected_frames={(ref['source_slot'],ref['frame_number']) for ref in refs if ref['frame_number'] is not None}
        fields=[]
        for row in analysis['network']:
            if any((ref['source_slot'],ref['frame_number']) in selected_frames for ref in row['observation']['source_refs']):
                fields.append({'event_id':row['event']['event_id'],'fields':{name:[inputs.resolve(piece['source_ref'],piece) for piece in value['slices'] if (piece['source_ref']['source_slot'],piece['source_ref']['frame_number']) in selected_frames] for name,value in row['observation']['fields'].items()}})
        return {'mode':'dual_source_replay','replay_version':'dual-source-replay-1','history_format':FORMAT,
                'synthetic':analysis['synthetic'],'revision':number,'snapshot_id':snapshot['snapshot_id'],
                'available_at':snapshot['available_at'],'selection':selected,'verified_original_evidence':originals,
                'verified_network_fields':fields,'quality':analysis['quality'],'config_fingerprint':analysis['config_fingerprint'],
                'limitations':analysis['limitations'],
                'evidence_page':{'version':'source-reference-page-1','offset':ref_offset,'limit':ref_limit,'total':total,
                                 'returned':len(originals),'has_more':ref_offset+len(originals)<total,'order':'canonical_source_reference'}}
    finally:_close_run(run)


def action(root, kind, *, snapshot=None, after=0, limit=100, operation=None, change=None, trigger=False, ref_offset=0, ref_limit=100):
    from .replay_export import read_json
    from pathlib import Path
    if read_json(Path(root)/'run_manifest.json').get('history_format')!=FORMAT:raise ValueError('spool_history_required')
    if kind in ('verify','metadata','revisions') and snapshot is not None:raise ValueError('snapshot_selector_unsupported')
    if kind!='revisions' and (after!=0 or limit!=100):raise ValueError('revision_page_selector_unsupported')
    if kind!='evidence' and (ref_offset!=0 or ref_limit!=100):raise ValueError('evidence_page_selector_unsupported')
    if kind in ('verify', 'metadata'):
        manifest = verify_task(root)
        if manifest.get('history_format') != FORMAT: raise ValueError('spool_history_required')
        from .replay_export import read_json
        from pathlib import Path
        history = read_json(Path(root) / 'history/manifest.json')
        if kind == 'verify':
            return {'history_format': FORMAT, 'manifest': manifest,
                    'history': {'manifest': history, 'manifest_sha256': manifest['history_manifest_sha256']},
                    'verification': 'source_replayed_storage_and_business_fields_verified'}
        return {'mode': 'dual_source_replay', 'replay_version': manifest['replay_version'], 'history_format': FORMAT,
                'snapshot_count': history['snapshot_count'], 'revision_count': history['revision_count'],
                'final_snapshot_number': history['snapshot_count'] - 1, 'final_snapshot_id': history['last_snapshot_id'],
                'semantic_config_fingerprint': manifest['semantic_config_fingerprint']}
    if kind == 'revisions':
        if type(after) is not int or after<0 or type(limit) is not int or not 1 <= limit <= 100: raise ValueError('history_revision_page_invalid')
        from .replay_export import _verify,_close_run
        manifest,run=_verify(root,retain_run=True)
        try:
            reader=run['history_reader']
            return {'mode': 'dual_source_replay', 'replay_version': manifest['replay_version'],
                    'history_format': FORMAT, 'revisions': reader.revisions(after,limit), 'total': reader.manifest['revision_count']}
        finally:_close_run(run)
    if type(snapshot) is not int or snapshot < 0: raise ValueError('explicit_snapshot_number_required')
    if kind == 'evidence':
        return evidence(root,snapshot,operation,change,trigger,ref_offset,ref_limit)
    value = snapshot_task(root, snapshot)
    if kind == 'snapshot': return value
    if kind == 'graph':
        return {'mode': 'dual_source_replay', 'replay_version': 'dual-source-replay-1', 'history_format': FORMAT,
                'revision_number': value['revision_number'], 'synthetic': value['synthetic'], 'graph': value['graph']}
    raise ValueError('unsupported_spool_query')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--action', choices=('verify', 'metadata', 'snapshot', 'revisions', 'graph', 'evidence'), required=True)
    parser.add_argument('--snapshot', type=int); parser.add_argument('--after', type=int, default=0)
    parser.add_argument('--limit', type=int, default=100); parser.add_argument('--operation'); parser.add_argument('--change')
    parser.add_argument('--trigger', action='store_true')
    parser.add_argument('--ref-offset',type=int,default=0);parser.add_argument('--ref-limit',type=int,default=100)
    args = parser.parse_args()
    try:
        if args.action != 'evidence' and (args.operation is not None or args.change is not None or args.trigger):
            raise ValueError('evidence_selectors_require_evidence_action')
        value = action(args.root, args.action, snapshot=args.snapshot, after=args.after, limit=args.limit,
                       operation=args.operation, change=args.change, trigger=args.trigger,ref_offset=args.ref_offset,ref_limit=args.ref_limit)
        output=io.BytesIO()
        for chunk in json_chunks(value):
            if output.tell()+len(chunk)+1>LIMIT:raise ValueError('spool_query_output_limit')
            output.write(chunk)
        raw=output.getvalue()
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as error:
        parser.exit(2, str(error) + '\n')
    print(raw.decode())


if __name__ == '__main__': main()
