"""Explicit synthetic dual-source observations and hypothetical associations only."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from fractions import Fraction
import json
from pathlib import Path
import shutil
import tempfile

from .contracts import validate
from .dual_source_rules import validate_profile, clock_time, validity, finite_findings, REAL_LIMITATIONS, outward
from .evidence import EvidenceIndex
from .packet_pipeline import analyze_capture, PacketEvidence
from .parsers import parse_process
from .pipeline import canonical, file_hash, fingerprint

VERSION = 'synthetic-dual-source-1'
R17_VERSION = 'bounded-dual-source-1'
LIMITATIONS = ['synthetic_only', 'no_attack_or_causality_decision',
               'response_success_is_not_physical_effect', 'endpoint_not_authenticated_actor',
               'configured_offsets_not_estimated', 'existing_bounded_protocol_subset']


def strict_json(data):
    def reject(value): raise ValueError('nonfinite_json')
    return json.loads(data, parse_constant=reject)


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')


def corrected(raw, low, high, clock):
    known = (clock['offset_seconds'] is not None and clock['uncertainty_seconds'] is not None
             and isinstance(clock['basis'], str) and bool(clock['basis'].strip()) and low is not None)
    result = {'raw':raw, 'offset_seconds':clock['offset_seconds'],
              'uncertainty_seconds':clock['uncertainty_seconds'], 'basis':clock['basis'],
              'status':'configured' if known else 'unknown', 'interval':None}
    if known:
        offset,error=clock['offset_seconds'],clock['uncertainty_seconds']
        result['interval']=[low+offset-error,high+offset+error]
    return result


def equal(a,b,tolerance=0):
    numeric=lambda v:type(v) in (int,float)
    if numeric(a) and numeric(b):return abs(a-b)<=tolerance
    return type(a) is type(b) and a==b


def overlaps(a,b): return a[0]<=b[1] and b[0]<=a[1]


def references(values):
    result={}
    def visit(value):
        if isinstance(value,dict):
            if {'file_sha256','frame_number','record_number','column','raw_time'}<=set(value):
                result[canonical(value)]=value
            else:
                for item in value.values():visit(item)
        elif isinstance(value,list):
            for item in value:visit(item)
    visit(values)
    return [result[k] for k in sorted(result)]


def analyze(network, process, config):
    extended=validate_profile(config)
    synthetic=config['synthetic']
    networks=network_paths(network)
    if len(networks)>1 and not extended:raise ValueError('multiple_captures_require_analysis_mode')
    if Path(process).stat().st_size>2*1024*1024:raise ValueError('input_size_limit')
    if not 1<=len(config['process']['columns'])<=16 or len(config['mappings'])>100:
        raise ValueError('profile_size_limit')
    ids=[r['rule_id'] for r in config['mappings']]
    if len(ids)!=len(set(ids)):raise ValueError('duplicate_rule_id')
    capture=analyze_capture(networks if len(networks)>1 else networks[0],synthetic=synthetic,extended=extended)
    if not capture['events']:raise ValueError('unsupported_or_empty_network')
    packet=PacketEvidence(networks if len(networks)>1 else networks[0],synthetic=synthetic)
    index=EvidenceIndex(process)
    # Count logical records (including malformed/empty rows) before parsing.
    import csv,io
    if sum(1 for _ in csv.reader(io.StringIO(index.text),strict=True))-1>1000:
        raise ValueError('process_record_limit')
    parsed=parse_process(process,config['process'],synthetic=synthetic,evidence=index,extended=extended)
    if parsed['quality']['status']=='unsupported' or not parsed['events']:
        raise ValueError('unsupported_or_empty_process: '+','.join(parsed['quality']['reasons']))
    if any(r.startswith(('invalid_csv_record_width','invalid_or_truncated_csv')) for r in parsed['quality']['reasons']):
        raise ValueError('malformed_csv_cannot_establish_adjacent_observations')
    issues=[]
    network_events=[]
    for event,obs in zip(capture['events'],capture['observations']):
        ticks=[packet.frame(r) if hasattr(packet,'frame') else packet.frames[r['frame_number']] for r in obs['source_refs']]
        times=[f['raw_timestamp']/f['ticks_per_second'] for f in ticks]
        raw_ticks=[{'frame_number':f['frame_number'],'raw_timestamp':f['raw_timestamp'],
                    'ticks_per_second':f['ticks_per_second'],**({'file_sha256':r['file_sha256']} if extended else {})} for f,r in zip(ticks,obs['source_refs'])]
        exact=[Fraction(f['raw_timestamp'],f['ticks_per_second']) for f in ticks]
        low=outward(min(exact)) if extended else min(times)
        high=outward(max(exact),True) if extended else max(times)
        timing=clock_time(raw_ticks,low,high,config['clocks']['network'],corrected,extended)
        network_events.append({'event':event,'observation':obs,'time':timing})
    process_events=[];groups=defaultdict(list)
    column_keys=defaultdict(list)
    for column,definition in config['process']['columns'].items():
        column_keys[(definition['asset_id'],definition['tag'])].append(column)
    for event in parsed['events']:
        validate('ProcessObservation',event)
        when=datetime.fromisoformat(event['event_time'].replace('Z','+00:00')).timestamp() if event['event_time'] else None
        low=high=when
        if extended and event['event_time']:
            dt=datetime.fromisoformat(event['event_time'].replace('Z','+00:00'))
            delta=dt-datetime(1970,1,1,tzinfo=timezone.utc)
            exact=Fraction(delta.days*86400+delta.seconds)+Fraction(delta.microseconds,1000000)
            low,high=outward(exact),outward(exact,True)
        wrapped={'event':event,'time':clock_time(event['source_ref']['raw_time'],low,high,config['clocks']['process'],corrected,extended)}
        process_events.append(wrapped);groups[(event['asset_id'],event['tag'])].append(wrapped)
    changes=[];group_issues={}
    for key,rows in groups.items():
        why=[]
        if len(column_keys[key])!=1:why.append('process_mapping_conflict')
        if any(r['time']['interval'] is None for r in rows):why.append('time_basis_missing')
        valid_times=[r['time']['interval'] for r in rows if r['time']['interval'] is not None]
        if len({tuple(t) for t in valid_times})!=len(valid_times):why.append('duplicate_process_time')
        group_issues[key]=why
        if why:continue
        rows.sort(key=lambda r:(r['time']['interval'],r['event']['event_id']))
        previous=None
        for row in rows:
            event=row['event'];interval=row['time']['interval']
            if event['value'] is None or (extended and event['quality']['status']!='valid'):
                issues.append({'reason':'missing_process_value','evidence_refs':[event['source_ref']]})
                previous=None;continue
            if previous is not None:
                before=previous['event'];prior=previous['time']['interval']
                gap=interval[1]-prior[0]
                if gap>config['max_sample_gap_seconds']:
                    issues.append({'reason':'sampling_gap','evidence_refs':[before['source_ref'],event['source_ref']]})
                elif not equal(before['value'],event['value'],config['change_epsilon']):
                    change={'schema_version':'1.0.0','synthetic':synthetic,'event_id':'',
                            'event_type':'observed_sample_transition','rule_version':config['rule_version'],
                            'evidence_refs':[before['source_ref'],event['source_ref']],
                            'time_range':{'start':utc(prior[0]),'end':utc(interval[1])},
                            'parameters':{'config_version':config['config_version'],'change_epsilon':config['change_epsilon'],
                                          'max_sample_gap_seconds':config['max_sample_gap_seconds']},
                            'result':{'asset_id':key[0],'tag':key[1],'before':before['value'],'after':event['value'],
                                      'interval':[prior[0],interval[1]],'before_event_id':before['event_id'],
                                      'after_event_id':event['event_id'],'time_semantics':'transition_somewhere_between_samples','interval_start_inclusive':False}}
                    change['event_id']='change-'+fingerprint(change);validate('DerivedEvent',change);changes.append(change)
            previous=row
    n_intervals=[e['time']['interval'] for e in network_events if e['time']['interval'] is not None]
    p_intervals=[e['time']['interval'] for e in process_events if e['time']['interval'] is not None]
    ranges={name:[min(i[0] for i in values),max(i[1] for i in values)] if values else None
            for name,values in [('network',n_intervals),('process',p_intervals)]}
    global_unknown=[]
    if any(v is None for v in ranges.values()):global_unknown.append('time_basis_missing')
    elif not overlaps(ranges['network'],ranges['process']):global_unknown.append('source_intervals_disjoint')
    operations=[];candidates=[]
    for wrapped in network_events:
        obs,event=wrapped['observation'],wrapped['event']
        if obs['direction']!='request':continue
        if len(operations)>=100:raise ValueError('operation_limit')
        replies=[r for r in network_events if event['correlation_id'] is not None and
                 r['event']['correlation_id']==event['correlation_id'] and r['observation']['direction']=='response']
        response={'state':obs['association_status'],'meaning':'no_unique_protocol_response', 'evidence_refs':[]}
        if len(replies)==1:
            reply=replies[0];status=reply['observation']['general_status']
            response={'state':'success' if status==0 else 'error','general_status':status,
                      'additional_status':reply['observation']['additional_status'],
                      'meaning':'protocol_service_success_only' if status==0 else 'protocol_service_error',
                      'event_id':reply['event']['event_id'],'time':reply['time'],
                      'evidence_refs':reply['observation']['source_refs']}
        interval=wrapped['time']['interval']
        raw_matches=[rule for rule in config['mappings'] if rule['destination_ip']==obs['endpoints'][1][0]
                 and rule['service']==obs['service'] and rule['path']==obs.get('path') and rule['data_hex']==obs['data_hex']]
        matches=[rule for rule in raw_matches if validity(rule,interval) in ('legacy','applicable')]
        uncertain_mappings=[rule for rule in raw_matches if validity(rule,interval) in ('unknown','uncertain')]
        if uncertain_mappings:matches+=uncertain_mappings
        unknown=list(global_unknown)
        if uncertain_mappings:unknown.append('mapping_validity_uncertain')
        if raw_matches and not matches:unknown.append('mapping_outside_validity')
        if extended and any(not all(r.get(k) for k in ('version','basis','valid_from','valid_to')) for r in matches):unknown.append('mapping_materials_missing')
        if capture['unsupported']:unknown.append('unsupported_network_records_present')
        if len(matches)!=1:unknown.append('mapping_missing' if not matches else 'mapping_conflict')
        counter=[]
        if response['state']=='error':counter.append({'reason':'error_response','evidence_refs':response['evidence_refs']})
        elif response['state']!='success':unknown.append('response_'+response['state'])
        interval=wrapped['time']['interval']
        if interval is None and 'time_basis_missing' not in unknown:unknown.append('time_basis_missing')
        if replies and interval and replies[0]['time']['interval'] and replies[0]['time']['interval'][1]<interval[0]:
            unknown.append('response_precedes_request')
        op={'operation_id':event['event_id'],'source_endpoint':event['endpoints']['source'],
            'destination_endpoint':event['endpoints']['destination'],'identity_scope':'captured_endpoint_only',
            'operation':obs['operation'],'protocol':event['protocol'],'path':obs.get('path'),
            'request_data_hex':obs['data_hex'],'time':wrapped['time'],'response':response,
            'mapping':{'status':'matched' if len(matches)==1 else 'missing' if not matches else 'conflict',
                       'rule_ids':[r['rule_id'] for r in matches],'config_version':config['config_version']},
            'request_evidence':obs['source_refs'],'assessment':'unknown','candidates':[],
            'support':[],'counterevidence':counter,'unknown_reasons':unknown,'observation_evidence':[]}
        if extended:
            op['mapping']['versions']=[{k:r[k] for k in ('rule_id','version','basis','valid_from','valid_to') if k in r} for r in matches]
        if len(matches)==1:
            op['mapping'].update(asset_id=matches[0]['asset_id'],tag=matches[0]['tag'],expected_value=matches[0]['expected_value'])
        if len(matches)==1 and interval is not None and not global_unknown and not uncertain_mappings and 'mapping_materials_missing' not in unknown:
            rule=matches[0];key=(rule['asset_id'],rule['tag']);rows=groups.get(key,[])
            op['mapping'].update(asset_id=key[0],tag=key[1],expected_value=rule['expected_value'])
            unknown.extend(group_issues.get(key,[]))
            if not rows:unknown.append('process_mapping_missing')
            if rows and not group_issues[key]:
                window=[interval[0],interval[1]+config['window_seconds']]
                op['window']=window
                found=[c for c in changes if (c['result']['asset_id'],c['result']['tag'])==key
                       and c['result']['interval'][0]<window[1] and c['result']['interval'][1]>=window[0]]
                expected=[c for c in found if equal(c['result']['after'],rule['expected_value'],rule['tolerance'])]
                for change in found:
                    if change not in expected:
                        counter.append({'reason':'unexpected_change','evidence_refs':change['evidence_refs']})
                for change in expected:
                    times=change['result']['interval'];uncertainty=[]
                    # A candidate may intersect a possible window without proving order.
                    if times[0]<interval[1] or times[1]>interval[0]+config['window_seconds']:
                        uncertainty.append('temporal_order_or_window_uncertain')
                    candidate={'candidate_id':'candidate-'+fingerprint([op['operation_id'],change['event_id'],config]),
                               'operation_id':op['operation_id'],'change_id':change['event_id'],
                               'state':'unknown','rule_id':rule['rule_id'],'rule_version':config['rule_version'],
                               'config_version':config['config_version'],'window':window,
                               'support':['explicit_mapping','expected_sample_transition','possible_temporal_window'],
                               'counterevidence':counter.copy(),'unknown_reasons':unknown.copy()+uncertainty,
                               'claim':{'schema_version':'1.0.0','synthetic':synthetic,'claim_id':'',
                                        'relation_type':'candidate_network_process_association','status':'hypothetical',
                                        'evidence_refs':references([obs['source_refs'],response['evidence_refs'],change['evidence_refs']]),
                                        'counterevidence':references(counter),'rule_id':rule['rule_id'],
                                        'assumptions':['configured_mapping_and_clock_basis','sampling_does_not_prove_action_time',
                                                       'no_causality_attack_or_physical_execution_asserted']}}
                    candidate['claim']['claim_id']=candidate['candidate_id'];validate('Claim',candidate['claim'])
                    candidates.append(candidate);op['candidates'].append(candidate['candidate_id'])
                    if len(candidates)>10000:raise ValueError('candidate_limit')
                if expected:
                    op['assessment']='expected_change_observed';op['support']=['expected_sample_transition']
                else:
                    # Bound the negative observation to actually covered samples, never physical absence.
                    before=[r for r in rows if r['time']['interval'][1]<=window[0]]
                    after=[r for r in rows if r['time']['interval'][0]>=window[1]]
                    selected=[]
                    if before and after:
                        left,right=before[-1],after[0]
                        selected=rows[rows.index(left):rows.index(right)+1]
                    op['observation_evidence']=[r['event']['source_ref'] for r in selected]
                    complete=bool(selected) and all(r['event']['value'] is not None for r in selected)
                    complete=complete and all(b['time']['interval'][1]-a['time']['interval'][0]<=config['max_sample_gap_seconds']
                                              for a,b in zip(selected,selected[1:]))
                    if any(reason.startswith('invalid_csv_record_width') or reason.startswith('invalid_or_truncated_csv')
                           for reason in parsed['quality']['reasons']):complete=False
                    if complete:
                        op['assessment']='no_expected_change_observed'
                        counter.append({'reason':'no_expected_change_in_observed_window','evidence_refs':op['observation_evidence']})
                    else:unknown.append('incomplete_process_coverage')
        op['unknown_reasons']=sorted(set(unknown));operations.append(op)
    by_change=defaultdict(list);by_op=defaultdict(list)
    for c in candidates:by_change[c['change_id']].append(c);by_op[c['operation_id']].append(c)
    operation_lookup={o['operation_id']:o for o in operations}
    change_lookup={c['event_id']:c for c in changes}
    for c in candidates:
        competing=[a['operation_id'] for a in by_change[c['change_id']] if a['operation_id']!=c['operation_id']]
        alternatives=[a['change_id'] for a in by_op[c['operation_id']] if a['change_id']!=c['change_id']]
        c['alternative_operation_ids']=competing
        c['alternative_change_ids']=alternatives
        if competing or alternatives:
            c['counterevidence'].append({'reason':'alternative_explanations',
                'evidence_refs':references([operation_lookup[i]['request_evidence'] for i in competing]+
                    [change_lookup[i]['evidence_refs'] for i in alternatives])})
            c['claim']['counterevidence']=references(c['counterevidence'])
        validate('Claim',c['claim'])
        if len(by_change[c['change_id']])>1 or len(by_op[c['operation_id']])>1:
            c['state']='ambiguous';c['unknown_reasons'].append('multiple_possible_operations_or_changes')
        elif c['counterevidence']:c['state']='counterevidence_present'
        elif c['unknown_reasons']:c['state']='unknown'
        else:c['state']='supported_candidate'
    index.verify()
    result={'schema_version':'1.0.0','synthetic':synthetic,'analysis_version':R17_VERSION if extended else VERSION,'config_version':config['config_version'],
            'rule_version':config['rule_version'],'config_fingerprint':fingerprint(config),
            'input_fingerprint':fingerprint([{'kind':kind,'sha256':file_hash(path),'size_bytes':Path(path).stat().st_size}
                for kind,path in [('network',p) for p in networks]+[('process',process)]]),'limitations':LIMITATIONS if synthetic else REAL_LIMITATIONS,
            'network':network_events,'process':process_events,'changes':changes,'operations':operations,
            'candidates':candidates,'orphan_change_ids':[c['event_id'] for c in changes if c['event_id'] not in by_change],
            'quality':{'source_ranges':ranges,'unknown_reasons':global_unknown,'process':parsed['quality'],
                       'network_unsupported':capture['unsupported'],'process_issues':issues,
                       'group_issues':[{'asset_id':k[0],'tag':k[1],'reasons':v} for k,v in group_issues.items() if v]}}
    if extended:
        result['analysis_mode']=config['analysis_mode']
        result['source_provenance']=config.get('source_provenance')
        result['rule_findings']=finite_findings(config,groups,group_issues)
        result['execution_limits']={'max_network_files':4,'aggregate_network_bytes':16*1024*1024,'max_frames':10000,'process_bytes':2*1024*1024,'process_records':1000,'max_finite_rules':100,'max_finite_findings':10000,'max_operations':100,'max_candidates':10000,'max_mappings':100,'max_process_columns':16,'max_profile_bytes':65536}
    return result


def network_paths(network):
    paths=list(network) if isinstance(network,(list,tuple)) else [network]
    if not 1<=len(paths)<=4:raise ValueError('network_file_limit')
    return [Path(p) for p in paths]


def network_names(count):
    return ['network.pcap']+['network-%03d.pcap'%i for i in range(1,count)]


def retained_networks(output, manifest=None):
    output=Path(output)
    if manifest is None:
        try:manifest=strict_json((output/'manifest.json').read_text())
        except (OSError,UnicodeError,ValueError) as exc:raise ValueError('invalid_dual_manifest') from exc
    names=manifest.get('network_inputs',['sources/network.pcap'])
    if not isinstance(names,list) or not 1<=len(names)<=4:raise ValueError('invalid_network_inventory')
    expected=['sources/'+n for n in network_names(len(names))]
    if names!=expected:raise ValueError('invalid_network_inventory')
    return [output/name for name in names]


def run_dual(network, process, profile, output):
    """Retain bounded input bytes, publish new immutable result directory only."""
    output=Path(output)
    if output.exists():raise ValueError('output_already_exists')
    networks=network_paths(network)
    if sum(p.stat().st_size for p in networks)>16*1024*1024:raise ValueError('input_size_limit')
    with tempfile.TemporaryDirectory(prefix='cpag-dual-input-') as tmp:
        base=Path(tmp);sources=base/'sources';sources.mkdir()
        names=network_names(len(networks))
        specs=list(zip(networks,names,[16*1024*1024]*len(names)))+[(process,'process.csv',2*1024*1024),(profile,'profile.json',65536)]
        for source,name,limit in specs:
            with Path(source).open('rb') as stream:
                count=0
                with (sources/name).open('wb') as target:
                    while True:
                        data=stream.read(min(1024*1024,limit+1-count))
                        if not data:break
                        count+=len(data)
                        if count>limit:raise ValueError('input_size_limit')
                        target.write(data)
        config=strict_json((sources/'profile.json').read_text())
        args=[sources/name for name in names]
        result=analyze(args if len(args)>1 else args[0],sources/'process.csv',config)
        output.mkdir(parents=True,exist_ok=False)
        try:
            shutil.copytree(sources,output/'sources')
            (output/'analysis.json').write_bytes(canonical(result)+b'\n')
            manifest={'schema_version':'1.0.0','synthetic':config['synthetic'],'analysis_version':result['analysis_version'],
                      'config_fingerprint':fingerprint(config),'files':{name:file_hash(output/name) for name in
                        tuple('sources/'+name for name in names)+('sources/process.csv','sources/profile.json','analysis.json')}}
            if len(names)>1:manifest['network_inputs']=['sources/'+name for name in names]
            (output/'manifest.json').write_bytes(canonical(manifest)+b'\n')
        except Exception:
            shutil.rmtree(output);raise
    return result


def query(output, operation_id=None, change_id=None):
    output=Path(output)
    if output.is_symlink() or (output/'sources').is_symlink():raise ValueError('symlink_artifact_root')
    manifest=strict_json((output/'manifest.json').read_text())
    network_sources=retained_networks(output,manifest)
    names={p.relative_to(output).as_posix() for p in network_sources}|{'sources/process.csv','sources/profile.json','analysis.json'}
    if set(manifest['files'])!=names:raise ValueError('invalid_artifact_inventory')
    for name in names:
        if (output/name).is_symlink() or file_hash(output/name)!=manifest['files'][name]:raise ValueError('artifact_integrity_mismatch')
    config=strict_json((output/'sources/profile.json').read_text())
    result=strict_json((output/'analysis.json').read_text())
    # Rebuild to reject a changed analysis even if its superficial checksum is updated.
    actual=analyze(network_sources if len(network_sources)>1 else network_sources[0],output/'sources/process.csv',config)
    if canonical(actual)!=canonical(result) or manifest['config_fingerprint']!=fingerprint(config):
        raise ValueError('analysis_does_not_match_sources')
    if operation_id is not None:
        matches=result['operations'][:1] if operation_id=='first' else [o for o in result['operations'] if o['operation_id']==operation_id]
        if len(matches)!=1:raise ValueError('unknown_operation')
        op=matches[0];candidates=[c for c in result['candidates'] if c['operation_id']==op['operation_id']]
        changes=[c for c in result['changes'] if c['event_id'] in {a['change_id'] for a in candidates}]
        selected={'operation':op,'candidates':candidates,'changes':changes}
    else:
        matches=result['changes'][:1] if change_id=='first' else [c for c in result['changes'] if c['event_id']==change_id]
        findings=[f for f in result.get('rule_findings',[]) if f['finding_id']==change_id]
        if len(matches)+len(findings)!=1:raise ValueError('unknown_change')
        selected={'change':matches[0]} if matches else {'rule_finding':findings[0]}
    refs=references(selected);packet=PacketEvidence(network_sources if len(network_sources)>1 else network_sources[0],synthetic=config['synthetic']);csv=EvidenceIndex(output/'sources/process.csv')
    resolved=[]
    for ref in refs:
        resolved.append({'source_ref':ref,'original':packet.resolve(ref) if ref['frame_number'] is not None else csv.resolve(ref)})
    frames={(r['file_sha256'],r['frame_number']) for r in refs if r['frame_number'] is not None}
    fields=[]
    for item in result['network']:
        if any((r['file_sha256'],r['frame_number']) in frames for r in item['observation']['source_refs']):
            fields.append({'event_id':item['event']['event_id'],'fields':{name:[packet.resolve(piece['source_ref'],piece) for piece in field['slices']]
                           for name,field in item['observation']['fields'].items()}})
    csv.verify()
    return {'synthetic':config['synthetic'],'selection':selected,'time_configuration':config['clocks'],
            'source_ranges':result['quality']['source_ranges'],'quality':result['quality'],
            'verified_original_evidence':resolved,'verified_network_fields':fields,
            'config_version':config['config_version'],'config_fingerprint':fingerprint(config),'limitations':result['limitations'],
            **({'source_provenance':result['source_provenance']} if 'analysis_mode' in result else {})}


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    run=sub.add_parser('analyze')
    run.add_argument('--network',required=True,action='append')
    for key in ('process','profile','output'):run.add_argument('--'+key,required=True)
    inspect=sub.add_parser('query');inspect.add_argument('--output',required=True)
    group=inspect.add_mutually_exclusive_group(required=True);group.add_argument('--operation');group.add_argument('--change')
    args=parser.parse_args()
    try:
        if args.command=='analyze':
            result=run_dual(args.network,args.process,args.profile,args.output)
            result={'synthetic':result['synthetic'],'operations':len(result['operations']),'changes':len(result['changes']),
                    'candidates':len(result['candidates']),'output':args.output,'limitations':result['limitations']}
        else:result=query(args.output,args.operation,args.change)
    except (OSError,ValueError,KeyError,TypeError) as exc:parser.exit(2,str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))

if __name__=='__main__':main()
