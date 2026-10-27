"""R18 independent arrival schedules/oracles, fixed before implementation (P01-P14)."""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from dual_source_fixtures import make_case
from round17_profile import profile
from cpag_core.pipeline import canonical,fingerprint
from cpag_core.replay_core import ReplayCore,ReplayIncomplete,semantic_profile
from cpag_core.replay_inputs import ReplayInputs
from cpag_core.dual_source_export import verify_task

BASE=1767225600
SCHEDULE=[('process',1,8),('process',2,9),('network-0',1,10),('process',3,10.5),('network-0',2,11),('process',4,12),('process',5,15),('process',6,16)]

def at(second):
    from datetime import datetime,timezone
    return datetime.fromtimestamp(BASE+second,timezone.utc).isoformat().replace('+00:00','Z')

def config():
    result=profile();result['replay']={'version':'dual-source-replay-1','simulation_start':at(0),
        'arrival_time_basis':'independent generated UTC arrival schedule','warmup_seconds':2,
        'allowed_lateness_seconds':2,'buffer_seconds':60,'max_buffer_records':11000,
        'max_snapshots':4096,'max_revisions':8192,'max_output_bytes':16777216}
    return result


def raw_capture(records):
    data=bytes.fromhex('d4c3b2a1')+struct.pack('<HHiiII',2,4,0,0,65535,1)
    for when,raw in records:
        whole=int(when);fraction=round((when-whole)*1000000)
        data+=struct.pack('<IIII',BASE+whole,fraction,len(raw),len(raw))+raw
    return data


def offline_identity_projection(replay_result, offline_result, offline_profile, network_path, process_path):
    """Declared comparison adapter: replace mode-specific identities, never business facts.

    Full-file hashes here belong solely to this terminal comparison fixture;
    production replay references remain genuine record hashes in every artifact.
    All offline business fields are retained. Replay lifecycle and pending-parser
    metadata have separately asserted terminal equivalence preconditions.
    """
    from cpag_core.pipeline import file_hash
    source_hashes={'network-0':file_hash(network_path),'process':file_hash(process_path)}
    def ref(value):
        return {'file_sha256':source_hashes[value['source_slot']], 'frame_number':value['frame_number'],
                'record_number':value['record_number']-1 if value['record_number'] is not None else None,
                'column':value['column'],'raw_time':value['raw_time']}
    identities={}
    for kind in ('network','process'):
        originals={canonical(item['event']['source_ref']):item['event']['event_id'] for item in offline_result[kind]}
        for item in replay_result[kind]:
            identities[item['event']['event_id']]=originals[canonical(ref(item['event']['source_ref']))]
    for item in replay_result['network']:
        if item['event']['correlation_id'] is None:continue
        original=next(row for row in offline_result['network'] if row['event']['event_id']==identities[item['event']['event_id']])
        identities[item['event']['correlation_id']]=original['event']['correlation_id']
    def convert(value):
        if isinstance(value,str):return identities.get(value,value)
        if isinstance(value,list):return [convert(item) for item in value]
        if isinstance(value,tuple):return [convert(item) for item in value]
        if isinstance(value,dict):
            if {'source_slot','record_sha256','frame_number','record_number','column','raw_time'}<=set(value):return ref(value)
            if {'frame_number','raw_timestamp','ticks_per_second','source_ref'}<=set(value):
                converted={key:convert(item) for key,item in value.items() if key!='source_ref'}
                converted['file_sha256']=source_hashes[value['source_ref']['source_slot']]
                return converted
            return {key:convert(item) for key,item in value.items()}
        return value
    for change in replay_result['changes']:
        converted=convert(change);converted['event_id']=''
        identities[change['event_id']]='change-'+fingerprint(converted)
    for candidate in replay_result['candidates']:
        identities[candidate['candidate_id']]='candidate-'+fingerprint([identities[candidate['operation_id']],identities[candidate['change_id']],offline_profile])
    expected_extra={'replay','replay_version','semantic_config_fingerprint'}
    assert set(replay_result)==set(offline_result)|expected_extra
    assert replay_result['replay']['phase']=='finished'
    assert replay_result['replay']['expired_record_refs']==[]
    result={key:convert(replay_result[key]) for key in offline_result}
    result['input_fingerprint']=offline_result['input_fingerprint']
    result['config_fingerprint']=fingerprint(offline_profile)
    assert result['quality'].pop('network_pending')==[]
    for row in result['network']:
        # R18 exposes the exact TCP-PDU origin as part of its stable event ID;
        # this independent unsegmented fixture starts both directions at 100.
        assert row['observation'].pop('stream_sequence')==100
    for operation in result['operations']:
        lifecycle=operation.pop('replay')
        assert lifecycle['closed'] is True and lifecycle['provisional'] is False
    return result


class ReplayCoreTests(unittest.TestCase):
    def start(self, base, *, cfg=None, case='success'):
        net,process,_=make_case(base,case);cfg=cfg or config()
        inputs=ReplayInputs(net,process,cfg['process'],synthetic=cfg['synthetic']);self.addCleanup(inputs.close)
        return inputs,ReplayCore(cfg)

    def push(self, inputs, core, slot, number, when, *, expected=None):
        step={'source_slot':slot,'record_number':number,'available_at':at(when)}
        if expected:step['record_sha256']=expected
        report=inputs.advance(step)
        return core.consume(inputs.snapshot(),available_at=at(when),arrival_seq=core.arrival_seq+1,
            trigger_ref=report.get('source_ref'),status=report['status'],original_ref=report.get('original_ref'),
            claimed_record_sha256=report.get('claimed_record_sha256'))

    def feed(self, inputs, core, schedule=SCHEDULE):
        return [self.push(inputs,core,*step) for step in schedule]

    def test_pending_then_response_wait_then_change_preserves_historical_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));snapshots=self.feed(inputs,core)
            pending=snapshots[2];wait=snapshots[4];normal=snapshots[5]
            self.assertEqual(pending['analysis']['operations'][0]['replay']['status'],'pending_response')
            self.assertEqual(len(pending['analysis']['network']),1)
            self.assertEqual(pending['analysis']['changes'],[]);self.assertEqual(pending['analysis']['candidates'],[])
            self.assertEqual(wait['analysis']['operations'][0]['replay']['status'],'wait_process')
            self.assertEqual(wait['analysis']['changes'],[])
            self.assertEqual(normal['analysis']['operations'][0]['replay']['status'],'normal')
            self.assertEqual(normal['analysis']['candidates'][0]['state'],'supported_candidate')
            self.assertEqual(pending,core.snapshots()[3])
            self.assertNotIn('file_sha256',canonical(core.snapshots()).decode())
            revisions=core.history()
            self.assertTrue(all('old_snapshot_number' in item and 'new_snapshot_number' in item for item in revisions))
            self.assertEqual(revisions[-1]['config_fingerprint'],fingerprint(semantic_profile(config())))
            for revision in revisions:
                old=core.snapshots()[revision['old_snapshot_number']]
                new=core.snapshots()[revision['new_snapshot_number']]
                self.assertEqual(old['state_fingerprint'],revision['old_state_fingerprint'])
                self.assertEqual(new['state_fingerprint'],revision['new_state_fingerprint'])
                self.assertEqual(new['snapshot_id'],revision['new_snapshot_id'])

    def test_future_bytes_and_future_schedule_and_speed_do_not_change_prefix(self):
        outputs=[]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for variant in (0,1):
                base=root/str(variant);net,process,_=make_case(base)
                if variant:
                    data=bytearray(net.read_bytes());data[-1]^=1;net.write_bytes(data)
                    process.write_text(process.read_text()+'2026-01-01T00:00:20Z,777\n')
                cfg=config();future_sequence=[{'source_slot':slot,'record_number':number,'available_at':at(when)} for slot,number,when in SCHEDULE]
                future_sequence[4]['available_at']=at(11 if not variant else 11.5)
                if variant:future_sequence.append({'source_slot':'process','record_number':7,'available_at':at(20)})
                future_sequence += [{'kind':'source_eof','source_slot':slot,'available_at':at(21)} for slot in ('network-0','process')]
                cfg['replay'].update(sequence=future_sequence,finish_at=at(22+variant),speed=1 if not variant else 10,realtime=bool(variant))
                inputs=ReplayInputs(net,process,cfg['process'],synthetic=True);self.addCleanup(inputs.close);core=ReplayCore(cfg)
                self.feed(inputs,core,SCHEDULE[:4])
                outputs.append((canonical(core.snapshot()),canonical(core.snapshots()),canonical(core.history())))
            self.assertEqual(outputs[0],outputs[1])

    def test_duplicate_and_unverified_reference_claim_do_not_rewrite_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));self.feed(inputs,core,SCHEDULE[:4])
            before=core.final_result();history=core.history()
            duplicate=self.push(inputs,core,'network-0',1,10.75)
            self.assertEqual(duplicate['status'],'duplicate');self.assertEqual(before,core.final_result())
            self.assertEqual(history,core.history())
            conflict=self.push(inputs,core,'network-0',1,10.8,expected='f'*64)
            self.assertEqual(conflict['status'],'conflicting_reference')
            self.assertEqual(history,core.history());self.assertEqual(before,core.final_result())
            self.assertEqual(core.metrics()['counts']['duplicate'],1)
            self.assertEqual(core.metrics()['counts']['conflict'],1)
            self.assertEqual(core.metrics()['arrival_samples'][-1]['reason'],'unverified_digest_claim_not_second_original')

    def test_allowed_late_revision_and_closed_too_late_freeze(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));self.feed(inputs,core,SCHEDULE[:5])
            wait=core.snapshot();late=self.push(inputs,core,'process',4,13)
            self.assertEqual(late['status'],'late');self.assertEqual(len(late['analysis']['candidates']),1)
            self.assertEqual(wait['analysis']['operations'][0]['replay']['status'],'wait_process')
            self.assertEqual(core.history()[-1]['trigger']['available_at'],at(13))
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));self.feed(inputs,core,SCHEDULE[:5])
            core.advance(at(17));self.assertFalse(core.final_result()['operations'][0]['replay']['closed'])
            core.advance(at(18));frozen=copy.deepcopy(core.final_result()['operations'][0])
            late=self.push(inputs,core,'process',4,19)
            self.assertEqual(late['status'],'too_late');self.assertEqual(late['analysis']['operations'][0],frozen)
            self.assertEqual(late['analysis']['candidates'],[])
            self.assertEqual(core.metrics()['counts']['too_late'],1);self.assertEqual(core.metrics()['counts']['discarded'],1)
            self.assertEqual(core.metrics()['discarded'][0]['source_ref']['record_number'],4)

    def test_eof_does_not_satisfy_response_or_process_and_unknown_time_uses_arrival_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=config();cfg['clocks']['network']['basis']=None
            inputs,core=self.start(Path(tmp),cfg=cfg);self.feed(inputs,core,SCHEDULE[:4])
            final=core.consume(inputs.finish(),available_at=at(11),arrival_seq=5,status='input_exhausted')
            operation=final['analysis']['operations'][0]
            self.assertFalse(operation['replay']['closed']);self.assertEqual(final['analysis']['candidates'],[])
            self.assertEqual(operation['replay']['deadline_basis'],'arrival_timeout_unknown')
            core.finish(at(18));operation=core.final_result()['operations'][0]
            self.assertTrue(operation['replay']['closed']);self.assertIn('arrival_timeout_unknown',operation['unknown_reasons'])
            self.assertNotEqual(operation['response']['state'],'success')

    def test_incomplete_limits_and_active_buffer_expiry(self):
        for key,value,reason in [('max_buffer_records',1,'buffer_record_limit'),('max_snapshots',1,'snapshot_limit'),('max_revisions',1,'revision_limit'),('max_output_bytes',1,'output_byte_limit')]:
            with self.subTest(limit=key),tempfile.TemporaryDirectory() as tmp:
                cfg=config();cfg['replay'][key]=value
                with self.assertRaisesRegex(ReplayIncomplete,reason):
                    inputs,core=self.start(Path(tmp),cfg=cfg);self.feed(inputs,core)
        with tempfile.TemporaryDirectory() as tmp:
            cfg=config();cfg['replay'].update(buffer_seconds=1,max_buffer_records=2)
            inputs,core=self.start(Path(tmp),cfg=cfg)
            self.push(inputs,core,'process',1,8);self.push(inputs,core,'process',2,9)
            core.advance(at(11));self.assertEqual(core.metrics()['counts']['expired'],1)
            self.push(inputs,core,'network-0',1,12)
            self.assertEqual(len(core.final_result()['replay']['active_record_refs']),2)
            self.assertEqual(len(core.final_result()['replay']['available_record_refs']),3)

    def test_deterministic_three_runs_metrics_complete_and_runtime_separate(self):
        outputs=[]
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(3):
                inputs,core=self.start(Path(tmp)/str(i));self.feed(inputs,core)
                core.advance(at(18));core.finish(at(18))
                outputs.append(tuple(fingerprint(value) for value in (core.snapshots(),core.history(),core.final_result(),core.metrics())))
                metrics=core.metrics()
                self.assertEqual(metrics['counts']['arrival_attempts'],8)
                self.assertEqual(metrics['counts']['accepted'],8)
                self.assertEqual(metrics['event_latency']['denominator_total_events'],7)
                self.assertEqual(metrics['event_latency']['denominator_computable_events'],7)
                self.assertEqual(metrics['confirmation_latency']['denominator_candidates'],1)
                self.assertTrue(core.runtime_metrics()['excluded_from_semantic_hashes'])
                self.assertTrue(all(sample['wall_seconds']>=0 for sample in core.runtime_metrics()['samples']))
            self.assertEqual(outputs[0],outputs[1]);self.assertEqual(outputs[0],outputs[2])

    def test_terminal_offline_equivalence_preserves_every_business_field(self):
        from cpag_core.dual_source import analyze
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,process,_=make_case(base)
            cfg=config();inputs=ReplayInputs(net,process,cfg['process'],synthetic=True);self.addCleanup(inputs.close)
            core=ReplayCore(cfg);self.feed(inputs,core);core.finish(at(18))
            offline_profile=copy.deepcopy(cfg);offline_profile.pop('replay')
            offline=analyze(net,process,offline_profile)
            equivalent=offline_identity_projection(core.final_result(),offline,offline_profile,net,process)
            self.assertEqual(canonical(equivalent),canonical(offline))

    def test_arrival_clock_automatically_closes_before_late_record_without_explicit_advance(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));self.feed(inputs,core,SCHEDULE[:5])
            late=self.push(inputs,core,'process',4,19)
            self.assertEqual(late['status'],'too_late')
            self.assertTrue(late['analysis']['operations'][0]['replay']['closed'])
            self.assertEqual(late['analysis']['candidates'],[])
            clock_revision=next(item for item in core.history() if item['reason']=='clock_before_arrival')
            self.assertEqual(clock_revision['trigger']['kind'],'clock_advance')
            self.assertEqual(clock_revision['trigger']['evidence_refs'],[])
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));self.feed(inputs,core,SCHEDULE[:5])
            boundary=self.push(inputs,core,'process',4,17)
            self.assertNotEqual(boundary['status'],'too_late')
            self.assertFalse(boundary['analysis']['operations'][0]['replay']['closed'])
            self.assertEqual(len(boundary['analysis']['candidates']),1)

    def test_premature_finish_is_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));self.feed(inputs,core,SCHEDULE[:5])
            with self.assertRaisesRegex(ReplayIncomplete,'open_windows_at_finish'):core.finish(at(12))

    def test_expiring_open_operation_context_is_incomplete_not_silently_forgotten(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=config();cfg['replay']['buffer_seconds']=1
            inputs,core=self.start(Path(tmp),cfg=cfg)
            self.push(inputs,core,'network-0',1,10)
            with self.assertRaisesRegex(ReplayIncomplete,'buffer_time_limit'):core.advance(at(12))

    def test_cross_file_segments_retransmission_emit_no_pdu_before_arrived_bytes(self):
        from dual_source_fixtures import message,frame
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);_,process,_=make_case(base);cfg=config()
            request=message(bytes.fromhex('10032001240130010100'),context=(1).to_bytes(8,'little'))
            response=message(bytes.fromhex('90000000'),context=(1).to_bytes(8,'little'))
            first,second=base/'a.pcap',base/'b.pcap'
            first.write_bytes(raw_capture([(10,frame(request[20:],seq=120)),(10,frame(request[:20],seq=100))]))
            second.write_bytes(raw_capture([(10,frame(request[:20],seq=100)),(11,frame(response,seq=100,reverse=True))]))
            inputs=ReplayInputs([first,second],process,cfg['process'],synthetic=True);self.addCleanup(inputs.close);core=ReplayCore(cfg)
            self.push(inputs,core,'process',1,8);self.push(inputs,core,'process',2,9)
            partial=self.push(inputs,core,'network-0',1,10)
            self.assertEqual(partial['analysis']['network'],[])
            self.assertTrue(partial['analysis']['quality']['network_pending'])
            complete=self.push(inputs,core,'network-1',1,10.1)
            self.assertEqual(len(complete['analysis']['network']),1)
            identity=complete['analysis']['network'][0]['event']['event_id']
            retrans=self.push(inputs,core,'network-0',2,10.2)
            self.assertEqual(retrans['analysis']['network'][0]['event']['event_id'],identity)
            self.assertEqual(len(retrans['analysis']['network'][0]['observation']['source_refs']),3)
            self.assertEqual(core.metrics()['event_latency']['denominator_total_events'],2)
            self.push(inputs,core,'process',3,10.5);self.push(inputs,core,'network-1',2,11)
            normal=self.push(inputs,core,'process',4,12)
            self.assertEqual([c['state'] for c in normal['analysis']['candidates']],['supported_candidate'])
            refs=normal['analysis']['candidates'][0]['claim']['evidence_refs']
            self.assertEqual(len(refs),6)
            for ref in refs:inputs.resolve(ref)

    def test_accepted_tcp_conflict_retracts_previous_current_operation_not_its_history(self):
        from dual_source_fixtures import message,frame
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,process,_=make_case(base);cfg=config()
            request=message(bytes.fromhex('10032001240130010100'),context=(1).to_bytes(8,'little'))
            response=message(bytes.fromhex('90000000'),context=(1).to_bytes(8,'little'))
            net.write_bytes(raw_capture([(10,frame(request,seq=100)),(11,frame(response,seq=100,reverse=True)),(10.1,frame(b'X',seq=110))]))
            inputs=ReplayInputs(net,process,cfg['process'],synthetic=True);self.addCleanup(inputs.close);core=ReplayCore(cfg)
            before=self.feed(inputs,core,SCHEDULE[:6])[-1]
            self.assertEqual(len(before['analysis']['candidates']),1)
            after=self.push(inputs,core,'network-0',3,13)
            self.assertEqual(after['analysis']['candidates'],[])
            self.assertEqual(after['analysis']['operations'],[])
            problem=next(item for item in after['analysis']['quality']['network_unsupported'] if 'conflicting_overlap' in item['reason'])
            self.assertEqual(len(problem['source_refs']),2)
            for ref in problem['source_refs']:inputs.resolve(ref)
            self.assertEqual(before['analysis']['candidates'][0]['state'],'supported_candidate')
            self.assertEqual(core.snapshots()[before['snapshot_number']],before)

    def test_gap_finalization_is_explicit_unsupported_without_inventing_request(self):
        from dual_source_fixtures import message,frame
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,process,_=make_case(base);cfg=config()
            request=message(bytes.fromhex('10032001240130010100'),context=(1).to_bytes(8,'little'))
            response=message(bytes.fromhex('90000000'),context=(1).to_bytes(8,'little'))
            net.write_bytes(raw_capture([(10,frame(request[:20],seq=100)),(10.1,frame(request[21:],seq=121)),(11,frame(response,seq=100,reverse=True))]))
            inputs=ReplayInputs(net,process,cfg['process'],synthetic=True);self.addCleanup(inputs.close);core=ReplayCore(cfg)
            for slot,number,when in [('process',1,8),('process',2,9),('network-0',1,10),('network-0',2,10.1),('network-0',3,11)]:self.push(inputs,core,slot,number,when)
            self.assertTrue(core.final_result()['quality']['network_pending'])
            final=core.consume(inputs.finish(),available_at=at(12),arrival_seq=core.arrival_seq+1,status='input_exhausted')
            self.assertTrue(any('stream_gap' in item['reason'] for item in final['analysis']['quality']['network_unsupported']))
            self.assertEqual(final['analysis']['operations'],[]);self.assertEqual(final['analysis']['candidates'],[])
            self.assertEqual(len(final['analysis']['network']),1)

    def test_r17_clock_validity_basis_precision_order_and_mapping_ambiguity_are_shared(self):
        for case,reason in [('response_outside','response_clock_validity_outside'),('request_outside','request_clock_validity_outside'),('basis','response_clock_basis_missing'),('overlap','response_order_uncertain'),('touch','response_order_uncertain'),('mapping','mapping_conflict')]:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                cfg=config();clock=cfg['clocks']['network']
                if case=='response_outside':clock['valid_to']=at(10.5)
                elif case=='request_outside':clock['valid_from']=at(10.5)
                elif case=='basis':clock['basis']=None
                elif case=='overlap':clock['precision_seconds']=0.6
                elif case=='touch':clock['precision_seconds']=0.5
                elif case=='mapping':cfg['mappings'].append(dict(cfg['mappings'][0],rule_id='ambiguous-other'))
                inputs,core=self.start(Path(tmp),cfg=cfg);self.feed(inputs,core)
                result=core.final_result()
                self.assertEqual(result['candidates'],[])
                self.assertIn(reason,result['operations'][0]['unknown_reasons'])
                self.assertEqual(result['operations'][0]['response']['state'],'success')
                self.assertEqual(result['operations'][0]['replay']['status'],'unknown')

    def test_no_response_error_no_change_missing_and_orphan_outcomes_are_not_effect_claims(self):
        for case in ('missing_response','error','no_change','missing_value','orphan_change'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                inputs,core=self.start(Path(tmp),case=case)
                schedule=[step for step in SCHEDULE if not (case=='missing_response' and step[:2]==('network-0',2))]
                if case=='orphan_change':schedule=[step for step in schedule if step[0]!='network-0'];schedule.insert(3,('network-0',1,11))
                self.feed(inputs,core,schedule);core.finish(at(18));result=core.final_result()
                self.assertFalse(any(candidate['state']=='supported_candidate' for candidate in result['candidates']))
                if case=='missing_response':self.assertIn('response_missing_at_window_close',result['operations'][0]['unknown_reasons'])
                elif case=='error':self.assertEqual(result['operations'][0]['response']['state'],'error')
                elif case=='no_change':self.assertEqual(result['operations'][0]['assessment'],'no_expected_change_observed')
                elif case=='missing_value':self.assertTrue(any(item['event']['value'] is None for item in result['process']))
                elif case=='orphan_change':self.assertEqual(result['operations'],[]);self.assertEqual(len(result['orphan_change_ids']),1)

    def test_closed_final_graph_dependencies_survive_buffer_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));self.feed(inputs,core);core.advance(at(18));core.finish(at(100))
            result=core.final_result();network={row['event']['event_id'] for row in result['network']};process={row['event']['event_id'] for row in result['process']}
            self.assertGreater(core.metrics()['counts']['expired'],0)
            self.assertEqual(len(result['candidates']),1)
            for candidate in result['candidates']:self.assertIn(candidate['operation_id'],network)
            for change in result['changes']:
                self.assertIn(change['result']['before_event_id'],process);self.assertIn(change['result']['after_event_id'],process)

    def test_late_record_unrelated_to_closed_window_remains_admitted(self):
        from dual_source_fixtures import message,frame
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,process,_=make_case(base);cfg=config()
            initial_request=message(bytes.fromhex('10032001240130010100'),context=(1).to_bytes(8,'little'))
            response=message(bytes.fromhex('90000000'),context=(1).to_bytes(8,'little'))
            next_request=message(bytes.fromhex('10032001240130010100'),context=(2).to_bytes(8,'little'))
            net.write_bytes(raw_capture([(10,frame(initial_request,seq=100)),(11,frame(response,seq=100,reverse=True)),(30,frame(next_request,seq=100+len(initial_request)))]))
            inputs=ReplayInputs(net,process,cfg['process'],synthetic=True);self.addCleanup(inputs.close);core=ReplayCore(cfg)
            self.feed(inputs,core);core.advance(at(18));frozen=core.final_result()['operations'][0]
            late=self.push(inputs,core,'network-0',3,33)
            self.assertEqual(late['status'],'late')
            self.assertEqual(core.metrics()['counts']['too_late'],0)
            self.assertEqual(len(late['analysis']['operations']),2)
            self.assertEqual(late['analysis']['operations'][0],frozen)
            self.assertEqual(late['analysis']['operations'][1]['replay']['status'],'pending_response')

    def test_filtered_csv_ordinal_gap_cannot_invent_adjacent_transition_or_negative_coverage(self):
        from cpag_core.dual_source import _analyze_prepared
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,process,_=make_case(base);cfg=profile(rules=True);cfg['window_seconds']=1
            process.write_text('time,pump\n2026-01-01T00:00:09Z,0\n2026-01-01T00:00:10Z,99\n2026-01-01T00:00:12Z,1\n')
            inputs=ReplayInputs(net,process,cfg['process'],synthetic=True);self.addCleanup(inputs.close)
            refs=[]
            for slot,n in [('network-0',1),('network-0',2),('process',1),('process',2),('process',3),('process',4)]:
                report=inputs.advance({'source_slot':slot,'record_number':n,'available_at':at(12)})
                if not(slot=='process' and n==3):refs.append(report['source_ref'])
            prefix=inputs.snapshot(allowed_record_refs=refs)
            self.assertEqual(prefix['parsed']['filtered_record_numbers'],[3])
            result=_analyze_prepared(prefix['capture'],prefix['parsed'],prefix['frames'],cfg,prefix['prefix_fingerprint'],allow_empty=True,source_contract='replay')
            self.assertEqual(result['changes'],[]);self.assertEqual(result['candidates'],[])
            self.assertEqual(result['operations'][0]['assessment'],'unknown')
            self.assertIn('incomplete_process_coverage',result['operations'][0]['unknown_reasons'])
            self.assertEqual(result['quality']['process_issues'][0]['reason'],'filtered_process_record_gap')
            states=[f for f in result['rule_findings'] if f['kind']=='state_change']
            self.assertIn('filtered_process_record_gap',states[1]['unknown_reasons'])

    def test_fin_half_close_preserves_matching_but_reset_prevents_cross_boundary_pair(self):
        from dual_source_fixtures import message,frame
        for flags,expected in ((17,1),(4,0)):
            with self.subTest(flags=flags),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp);net,process,_=make_case(base);cfg=config()
                request=message(bytes.fromhex('10032001240130010100'),context=(1).to_bytes(8,'little'))
                response=message(bytes.fromhex('90000000'),context=(1).to_bytes(8,'little'))
                control=bytearray(frame(b'',seq=100+len(request)));control[14+20+13]=flags
                net.write_bytes(raw_capture([(10,frame(request,seq=100)),(10.2,bytes(control)),(11,frame(response,seq=100,reverse=True))]))
                inputs=ReplayInputs(net,process,cfg['process'],synthetic=True);self.addCleanup(inputs.close);core=ReplayCore(cfg)
                schedule=[('process',1,8),('process',2,9),('network-0',1,10),('network-0',2,10.2),('process',3,10.5),('network-0',3,11),('process',4,12)]
                self.feed(inputs,core,schedule)
                self.assertEqual(sum(c['state']=='supported_candidate' for c in core.final_result()['candidates']),expected)
                if flags==4:self.assertEqual(core.final_result()['candidates'],[])

    def test_backlog_separates_prerequisite_waiting_from_all_open_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs,core=self.start(Path(tmp));self.feed(inputs,core,SCHEDULE[:5])
            waiting=core.metrics()['backlog']['samples'][-1]
            self.assertEqual(waiting['prerequisite_waiting_operations'],1)
            self.assertEqual(waiting['open_window_operations'],1)
            self.push(inputs,core,'process',4,12)
            normal=core.metrics()['backlog']['samples'][-1]
            self.assertEqual(normal['prerequisite_waiting_operations'],0)
            self.assertEqual(normal['waiting_operations'],normal['prerequisite_waiting_operations'])
            self.assertEqual(normal['open_window_operations'],1)
            core.advance(at(18))
            self.assertEqual(core.metrics()['backlog']['samples'][-1]['open_window_operations'],0)

    def test_speed_numeric_enum_rejects_booleans_and_strings_but_preserves_json_numbers(self):
        from cpag_core.contracts import validate
        for value in (True,False,'1','10'):
            with self.subTest(invalid=value):
                cfg=config();cfg['replay']['speed']=value
                with self.assertRaises(ValueError):validate('ReplayProfile',cfg['replay'])
                with self.assertRaises(ValueError):ReplayCore(cfg)
        snapshots=[]
        for value in (1,1.0,10,10.0):
            with self.subTest(valid=value):
                cfg=config();cfg['replay']['speed']=value
                validate('ReplayProfile',cfg['replay']);snapshots.append(canonical(ReplayCore(cfg).snapshot()))
        self.assertTrue(all(snapshot==snapshots[0] for snapshot in snapshots))

    def test_historical_v1_offline_fixture_still_verifies(self):
        manifest=verify_task(ROOT/'tests/fixtures/r17-response-clock-v1')
        self.assertEqual(manifest['status'],'succeeded')

if __name__=='__main__':unittest.main()
