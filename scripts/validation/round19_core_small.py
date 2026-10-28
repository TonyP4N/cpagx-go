#!/usr/bin/env python3
"""Small independent complete-object equivalence and corruption acceptance.

Core layer only. Legacy judgment receives the identical business configuration;
only transport-schema dispatch/factory selection is controlled for reference.
No key or approval is persisted. Complete path reports retain every difference.
"""
from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from round19_core_oracle import canonical,compare_values,IdentityBijection,check_raw_evidence
from dual_source_fixtures import make_case
from round17_profile import profile as bounded_profile
from round18_profile import fixture as replay_fixture,at


def read(path):return json.loads(Path(path).read_text())
def write(path,value):Path(path).write_bytes(canonical(value)+b'\n')
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def wire(value):return json.loads(canonical(value))
def rule(path,old,new,reason):return {'path':path,'old_present':True,'old':old,'new_present':True,'new':new,'reason':reason}


def source_identity():
    paths=[*(ROOT/'services/analysis/src/cpag_core').rglob('*.py'),*(ROOT/'schemas').glob('*.schema.json'),
        Path(__file__),ROOT/'scripts/validation/round19_core_oracle.py']
    return {path.relative_to(ROOT).as_posix():digest(path) for path in sorted(paths)}


def inputs(root,case,mode):
    if mode=='offline':
        network,process,path=make_case(root,case);networks=[network];config=bounded_profile()
    else:
        mapped='missing_response' if case=='missing_response' else 'allowed_late' if case=='allowed_late' else 'response_expired' if case=='response_expired' else 'normal'
        networks,process,path,config=replay_fixture(root,case=mapped)
        if case=='too_late':
            deferred=[];early=[]
            for step in config['replay']['sequence']:
                if step.get('kind') in ('advance','source_eof'):continue
                if step.get('source_slot')=='process' and step.get('record_number',0)>=4:
                    step['available_at']=at(19+.5*(step['record_number']-4));deferred.append(step)
                else:early.append(step)
            config['replay']['sequence']=early+deferred+[
                *[{'kind':'source_eof','source_slot':slot,'available_at':at(20)} for slot in ('network-0','network-1','process')],
                {'kind':'advance','available_at':at(22)}]
            config['replay']['finish_at']=at(22)
        if case=='duplicate_conflict':
            extra=[{'source_slot':'network-0','record_number':1,'available_at':at(10.75)},
                   {'source_slot':'network-0','record_number':1,'available_at':at(10.8),'record_sha256':'f'*64}]
            config['replay']['sequence'][4:4]=extra
        if case=='future_changed':
            raw=bytearray(networks[1].read_bytes());raw[-2]=5;networks[1].write_bytes(raw)
            process.write_text(process.read_text().replace(',1\n',',2\n'))
        config['replay'].update(history_format='shared-observation-dag-6',identity_strategy='merkle-json-dag-1',prefix_digest_strategy='incremental-prefix-digest-2',
            standard_projection='standard-graph-events-1',judgement_strategy='prepared-prefix-cache-1',
            max_output_bytes=1024**3,max_snapshots=65000,max_revisions=90000)
    config.update(capacity_profile='engineering-core-capacity-3',storage_format='shared-observation-dag-6',storage_budget_version='shared-storage-budget-2')
    write(path,config);return networks,process,path,config


def legacy_replay(networks,process,config):
    from cpag_core import replay_core,replay_export,replay_inputs
    original=replay_core.validate
    def schema(name,value,*args,**kwargs):
        return original('ReplayCompactProfile' if name=='ReplayProfile' else name,value,*args,**kwargs)
    class LegacyInputs(replay_inputs.ReplayInputs):pass
    with patch.object(replay_core,'validate',side_effect=schema),patch.object(replay_export,'ReplayInputs',LegacyInputs):
        run=replay_export.execute(networks,process,deepcopy(config))
    try:return {key:wire(run[key]) for key in ('analysis','snapshots','revisions','metrics')}
    finally:run['inputs'].close()


def compare_replay(reference,snapshots,revisions):
    if len(reference['snapshots'])!=len(snapshots) or len(reference['revisions'])!=len(revisions):raise AssertionError('complete_history_cardinality_changed')
    states=IdentityBijection();snaps=IdentityBijection();revs=IdentityBijection();graphs=IdentityBijection();reports=[]
    for old,new in zip(reference['snapshots'],snapshots):
        snaps.bind(old['snapshot_id'],new['snapshot_id']);states.bind(old['state_fingerprint'],new['state_fingerprint'])
        graphs.bind(old['graph']['graph_id'],new['graph']['graph_id'])
        allowed=[rule('/snapshot_id',old['snapshot_id'],new['snapshot_id'],'explicit canonical-to-Merkle snapshot container'),
            rule('/state_fingerprint',old['state_fingerprint'],new['state_fingerprint'],'complete analysis state typed Merkle identity'),
            rule('/graph/graph_id',old['graph']['graph_id'],new['graph']['graph_id'],'complete projected graph typed Merkle identity')]
        result=compare_values(old,new,allowed=allowed);reports.append({'snapshot_number':old['snapshot_number'],**result})
        if not result['equal']:raise AssertionError('snapshot_business_paths_changed:'+json.dumps(result))
    for old,new in zip(reference['revisions'],revisions):
        revs.bind(old['revision_id'],new['revision_id']);allowed=[rule('/revision_id',old['revision_id'],new['revision_id'],'complete revision typed Merkle identity')]
        for key,mapping in (('old_snapshot_id',snaps),('new_snapshot_id',snaps),('old_state_fingerprint',states),('new_state_fingerprint',states)):
            expected=mapping.mapped(old[key])
            if expected!=new[key]:raise AssertionError('revision_identity_chain_not_bijective:'+key)
            allowed.append(rule('/'+key,old[key],expected,'registered complete container identity chain'))
        result=compare_values(old,new,allowed=allowed);reports.append({'revision_number':old['revision_number'],**result})
        if not result['equal']:raise AssertionError('revision_business_paths_changed:'+json.dumps(result))
    return {'path_comparisons':reports,'snapshot_identity_map':snaps.record(),'state_identity_map':states.record(),'revision_identity_map':revs.record(),'graph_identity_map':graphs.record()}


def _refresh_untrusted_outer(root):
    shared=read(root/'shared/manifest.json');database=root/'shared/shared.sqlite3'
    connection=sqlite3.connect(database);index=hashlib.sha256()
    for name,ref in connection.execute('SELECT name,digest FROM roots ORDER BY name'):index.update(canonical([name,ref.hex()])+b'\n')
    shared.update(root_count=connection.execute('SELECT count(*) FROM roots').fetchone()[0],roots_index_sha256=index.hexdigest())
    shared['database'].update(sha256=digest(database),size_bytes=database.stat().st_size);connection.close();write(root/'shared/manifest.json',shared)
    manifest=read(root/'run_manifest.json');manifest['shared_manifest_sha256']=digest(root/'shared/manifest.json')
    for entry in manifest['artifacts']:
        path=root/entry['path'];entry.update(sha256=digest(path),size_bytes=path.stat().st_size)
    write(root/'run_manifest.json',manifest)


def negative_cases(root,output,mode):
    from cpag_core import shared_export as core
    checks=[]
    for mutation in ('missing_source','same_size_source','bad_integer_reference',*(['missing_history_index'] if mode=='replay' else [])):
        target=root/('negative-'+mutation);shutil.copytree(output,target)
        if mutation=='missing_source':(target/'sources/process.csv').unlink()
        elif mutation=='same_size_source':
            path=target/'sources/process.csv';raw=path.read_bytes();path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        else:
            connection=sqlite3.connect(target/'shared/shared.sqlite3')
            if mutation=='bad_integer_reference':connection.execute("UPDATE nodes SET payload=? WHERE id=(SELECT id FROM nodes WHERE kind='array_leaf' AND items>0 LIMIT 1)",(b'R\x01\x00',))
            else:connection.execute("DELETE FROM roots WHERE name='history/snapshots'")
            connection.commit();connection.close();_refresh_untrusted_outer(target)
        try:core.verify_task(target,deadline=time.monotonic()+30)
        except (ValueError,KeyError,OSError,sqlite3.Error) as error:checks.append({'mutation':mutation,'status':'correctly_refused','reason':str(error)})
        else:raise AssertionError('corruption_was_accepted:'+mutation)
    return checks


def run_case(root,case,mode):
    from cpag_core import shared_export as core
    from cpag_core.dual_source import analyze
    from cpag_core.dual_source_export import event_graph
    root.mkdir(parents=True,exist_ok=False);networks,process,path,config=inputs(root/'inputs',case,mode)
    reference={'analysis':wire(analyze(networks if len(networks)>1 else networks[0],process,config))} if mode=='offline' else legacy_replay(networks,process,config)
    output=root/'new';manifest=core.export_task(networks,process,path,output,run_id='independent-'+case,mode=mode,deadline=time.monotonic()+60)
    key=__import__('os').urandom(32);approval=core.issue_approval(output,key,deadline=time.monotonic()+60)
    result={'case':case,'mode':mode,'status':'running','input_sha256':{p.name:digest(p) for p in [*networks,process,path]},'manifest_counts':manifest['counts']}
    with core.open_reader(output,approval=approval,authority_key=key) as reader:
        analysis=reader.get('analysis.json');diff=compare_values(reference['analysis'],analysis);result['analysis_comparison']=diff
        write(root/'analysis-path-comparison.json',diff)
        if not diff['equal']:raise AssertionError('complete_analysis_changed:'+json.dumps(diff))
        for alias in ('dual/analysis.json',):
            if canonical(reader.get(alias))!=canonical(reference['analysis']):raise AssertionError('complete_analysis_alias_changed')
        old_projection=wire(event_graph(reference['analysis'],replay=mode=='replay'));graph=reader.get('graph.json')
        allowed=[rule('/graph_id',old_projection['graph.json']['graph_id'],graph['graph_id'],'explicit complete graph container identity')]
        graph_diff=compare_values(old_projection['graph.json'],graph,allowed=allowed);result['graph_comparison']=graph_diff
        if not graph_diff['equal'] or not compare_values(old_projection['events.json'],reader.get('events.json'))['equal']:raise AssertionError('complete_standard_projection_changed')
        if mode=='replay':
            snapshots=reader.get('history/snapshots');revisions=reader.get('history/revisions')
            history=compare_replay(reference,snapshots,revisions);write(root/'complete-history-path-comparison.json',history)
            result['history_comparison']={'snapshots':len(snapshots),'revisions':len(revisions),'all_business_paths_equal':True}
            if not compare_values(reference['metrics'],reader.get('metrics.json'))['equal']:raise AssertionError('replay_measurement_semantics_changed')
            if case in ('normal','missing_response','future_changed'):
                pending=next(row for row in snapshots if row['analysis']['operations'] and row['analysis']['operations'][0]['response']['state']=='missing')
                if pending['analysis']['operations'][0]['replay']['status']!='pending_response' or pending['analysis']['candidates']:raise AssertionError('future_facts_visible_before_arrival')
            if case=='duplicate_conflict' and (reference['metrics']['counts']['duplicate']!=1 or reference['metrics']['counts']['conflict']!=1):raise AssertionError('duplicate_or_conflict_fact_policy_changed')
            if case=='too_late' and reference['metrics']['counts']['too_late']<1:raise AssertionError('late_closed_history_not_preserved')
        expected={'success':(1,1,1),'normal':(1,1,1),'allowed_late':(1,1,1),'ambiguous':(2,1,2)}.get(case)
        if expected and tuple(manifest['counts'][name] for name in ('operations','changes','candidates'))!=expected:raise AssertionError('handwritten_small_count_oracle_mismatch')
        if case=='error' and analysis['operations'][0]['response']['state']!='error':raise AssertionError('error_response_lost')
        if case=='missing_response' and analysis['operations'][0]['response']['state']!='missing':raise AssertionError('missing_response_invented')
    # Exercise all selected raw references through explicit pages, not a nonempty prefix.
    offset=0;seen=[]
    while True:
        page=core.query_task(output,operation_id='first',ref_offset=offset,ref_limit=100,approval=approval,authority_key=key,deadline=time.monotonic()+10)
        result.setdefault('raw_checks',[]).append(check_raw_evidence(page['verified_original_evidence'],networks,process))
        info=page['evidence_page'];offset+=info['returned'];seen.extend(page['verified_original_evidence'])
        if not info['has_more']:
            if offset!=info['total']:raise AssertionError('raw_reference_pagination_incomplete')
            break
        if info['returned']<1:raise AssertionError('raw_reference_page_did_not_advance')
    result['raw_reference_total']=len(seen)
    if case in ('success','normal'):result['negative_checks']=negative_cases(root,output,mode)
    result['status']='passed';write(root/'case-report.json',result);return result


def compare_future_prefix(normal,changed,*,arrival_seq=4):
    """Change future bytes; compare complete past objects without hash exemptions."""
    from cpag_core import shared_export as core
    selected=[]
    for output in (normal,changed):
        # No caller-supplied trust state: each reader first verifies source truth.
        with core.open_reader(output,deadline=time.monotonic()+60) as reader:
            snapshots=[row for row in reader.get('history/snapshots') if row['arrival_seq']<=arrival_seq]
            identities={row['snapshot_id'] for row in snapshots}
            revisions=[row for row in reader.get('history/revisions') if row['new_snapshot_id'] in identities]
            selected.append({'snapshots':snapshots,'revisions':revisions})
    result=compare_values(*selected)
    if not result['equal']:raise AssertionError('changed_future_altered_past:'+json.dumps(result))
    return {'status':'passed','maximum_arrival_seq':arrival_seq,
        'snapshot_count':len(selected[0]['snapshots']),'revision_count':len(selected[0]['revisions']),
        'scope':'complete past snapshot graph/events/analysis/trigger/revisions, no identity exception',
        'comparison':result}


def run(output,cases):
    root=Path(output);root.mkdir(parents=True,exist_ok=False);report={'version':'r19-independent-small-core-acceptance-1','scope':'small core semantics/integrity only; no quota/performance/service acceptance','status':'running','cases':[],
        'runtime_source_sha256_before':source_identity()}
    try:
        for specification in cases:
            mode,case=specification.split(':',1)
            value=run_case(root/(mode+'-'+case),case,mode);report['cases'].append(value);write(root/'report.json',report)
        if {'replay:normal','replay:future_changed'}.issubset(cases):
            report['future_prefix_comparison']=compare_future_prefix(root/'replay-normal/new',root/'replay-future_changed/new')
        report['runtime_source_sha256_after']=source_identity()
        if report['runtime_source_sha256_before']!=report['runtime_source_sha256_after']:
            raise AssertionError('runtime_source_changed_during_independent_checks')
        report['status']='passed'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__,reason=str(error));raise
    finally:write(root/'report.json',report)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--case',action='append')
    args=parser.parse_args();run(args.output,args.case or ['offline:success','offline:error','offline:missing_response','offline:ambiguous','replay:normal','replay:missing_response','replay:allowed_late','replay:response_expired','replay:duplicate_conflict','replay:too_late','replay:future_changed'])
