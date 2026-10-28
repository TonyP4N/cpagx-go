#!/usr/bin/env python3
"""Formal small spool replay/restore check using the complete R18 business oracle.

Logical snapshots/revisions are compared in full. Their physical SQLite stores
retain distinct run/attempt bindings and are verified separately, never rewritten
into fabricated JSONL input files. This is not target-scale performance evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'services/worker'),str(ROOT/'scripts/backup')]
import round18_acceptance as r18
from cpag_core import replay_export
from cpag_core.dual_source_export import event_graph
from cpag_core.pipeline import canonical
from cpag_core.replay_history import VERSION as HISTORY_FORMAT


def logical_snapshots(output):
    rows=[]
    for snapshot in replay_export.iter_verified_snapshots(output):
        if 'graph' not in snapshot:
            projection=event_graph(snapshot['analysis'],replay=True)
            snapshot=dict(snapshot,graph=projection['graph.json'],events=projection['events.json'])
        rows.append(snapshot)
    return rows


def logical_revisions(output):
    rows=[]
    while True:
        page=replay_export.list_revisions(output,after=len(rows),limit=100)
        rows.extend(page)
        if len(page)<100:return rows


def logical_hashes(output):
    result={name:r18.bundle.sha(output/name) for name in r18.HASH_FILES if name not in ('snapshots.jsonl','revisions.jsonl')}
    for name,rows in [('logical_snapshots',logical_snapshots(output)),('logical_revisions',logical_revisions(output))]:
        digest=hashlib.sha256()
        for row in rows:digest.update(canonical(row)+b'\n')
        result[name]=digest.hexdigest()
    return result


def check_spool_run(client,job,root,attempt,config,case):
    output=root/'jobs'/job/f'attempt-{attempt}'
    snapshots=logical_snapshots(output);revisions=logical_revisions(output)
    r18.check_metrics(json.loads((output/'metrics.json').read_text()),case)
    assert revisions
    for snapshot in snapshots:r18.check_prefix(snapshot,config)
    answer=r18.history_answers(snapshots,case)
    result=client.expect('GET',f'/api/v3/runs/{job}/result')
    assert result['data']['analysis']==json.loads((output/'analysis.json').read_text())
    history=client.expect('GET',f'/api/v3/runs/{job}/revisions?after=0&limit=100')
    assert history['revisions']==revisions
    for label in ('pending','revised','final'):
        number=answer[label];actual=client.expect('GET',f'/api/v3/runs/{job}/snapshots/{number}')
        assert actual==snapshots[number]
        graph=client.expect('GET',f'/api/v3/runs/{job}/graph?revision={number}')
        assert graph['graph']==actual['graph']
        assert graph['mode']=='dual_source_replay' and graph['replay_version']==config['replay']['version']
        assert graph['revision_number']==actual['revision_number']
    final_graph=client.expect('GET',f'/api/v3/runs/{job}/graph')
    assert final_graph['graph']==snapshots[-1]['graph']
    assert final_graph['mode']=='dual_source_replay' and final_graph['replay_version']==config['replay']['version']
    pending=client.expect('GET',f'/api/v3/runs/{job}/evidence?'+urlencode({'revision':answer['pending'],'operation':answer['operation_id']}))
    assert len(pending['verified_original_evidence'])==1 and len(pending['verified_network_fields'])==1
    assert pending['verified_original_evidence'][0]['source_ref']['source_slot']=='network-0'
    assert pending['verified_original_evidence'][0]['source_ref']['frame_number']==1
    for number in (answer['pending'],answer['revised']):
        trigger=client.expect('GET',f'/api/v3/runs/{job}/evidence?'+urlencode({'revision':number,'trigger':'true'}))
        assert trigger['selection']['trigger']==snapshots[number]['trigger']
        assert [item['source_ref'] for item in trigger['verified_original_evidence']]==snapshots[number]['trigger']['evidence_refs']
        assert len(trigger['verified_original_evidence'])==1
        if number==answer['revised']:
            original=trigger['verified_original_evidence'][0]
            assert original['source_ref']['source_slot']=='process' and original['source_ref']['record_number']==4
            assert original['original']['pump']=='1'
    selected=client.expect('GET',f'/api/v3/runs/{job}/evidence?'+urlencode({'revision':answer['revised'],'operation':answer['operation_id']}))
    changed=client.expect('GET',f'/api/v3/runs/{job}/evidence?'+urlencode({'revision':answer['revised'],'change':answer['change_id']}))
    assert len(changed['verified_original_evidence'])==2
    assert {row['source_ref']['record_number'] for row in changed['verified_original_evidence']}=={3,4}
    assert len(selected['verified_original_evidence'])==(2 if case=='response_expired' else 4)
    for response in (pending,selected,changed):
        for entry in response['verified_original_evidence']:
            assert 'file_sha256' not in entry['source_ref'] and entry['source_ref']['record_sha256']
    artifacts=client.expect('GET',f'/api/v3/runs/{job}/artifacts')['artifacts']
    names={entry['path'] for entry in artifacts}
    assert 'snapshots.jsonl' not in names and 'revisions.jsonl' not in names
    physical={}
    for name in ('history/manifest.json','history/history.sqlite3','analysis.json'):
        entry=next(row for row in artifacts if row['path']==name)
        data=client.expect('GET',f'/api/v3/runs/{job}/artifacts/{name}/download')
        assert isinstance(data,bytes) and hashlib.sha256(data).hexdigest()==entry['sha256']
        physical[name]=entry['sha256']
    return {**answer,'hashes':logical_hashes(output),'snapshot_count':len(snapshots),'revision_count':len(revisions),
            'history_format':HISTORY_FORMAT,'physical_history_hashes':physical,
            'pending_original_refs':1,'normal_operation_original_refs':2 if case=='response_expired' else 4,
            'change_original_refs':2,'pending_trigger_refs':1,'revised_trigger_refs':1}


def run(work,*,image=None):
    fixture=r18.fixture;previous_check=r18.check_run;previous_hashes=r18.hashes
    previous_image=r18.WORKER_IMAGE
    if image is not None:r18.WORKER_IMAGE=image
    physical={};checks=[]
    def spool_fixture(*args,**kwargs):
        networks,process,path,config=fixture(*args,**kwargs)
        config['replay']['history_format']=HISTORY_FORMAT
        path.write_text(json.dumps(config,indent=2)+'\n')
        return networks,process,path,config
    def check(client,job,root,attempt,config,case):
        result=check_spool_run(client,job,root,attempt,config,case)
        key=(job,attempt)
        if key in physical:assert physical[key]==result['physical_history_hashes']
        else:physical[key]=result['physical_history_hashes']
        checks.append({'run_id':job,'attempt':attempt,'stage':'restored' if 'restored' in str(root) else 'original',
                       'case':case,'logical_hashes':result['hashes'],'physical_history_hashes':result['physical_history_hashes']})
        return result
    r18.fixture=spool_fixture;r18.check_run=check;r18.hashes=logical_hashes
    status='failed'
    try:
        r18.main(work);status='passed'
    finally:
        r18.fixture=fixture;r18.check_run=previous_check;r18.hashes=previous_hashes;r18.WORKER_IMAGE=previous_image
        if (work/'public').exists():
            (work/'public/spool-results.json').write_text(json.dumps({'status':status,'history_format':HISTORY_FORMAT,
                'scope':'generated small formal Worker/history/empty-db restore; no scale performance claim',
                'full_business_oracle':'R18 prefix, pending, late, response-clock, graph, evidence and pacing assertions',
                'checks':checks},indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    parser.add_argument('--image',help='reuse an already built Worker image; this harness does not build images')
    args=parser.parse_args()
    run(Path(args.output).resolve(),image=args.image)
