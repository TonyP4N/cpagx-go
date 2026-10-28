"""DAG6 parsing reuse keeps every old arrived-prefix and evidence oracle."""
from copy import deepcopy
from pathlib import Path
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
import test_arrived_inputs as base
from test_arrived_inputs import REQUEST,REPLY,frame,pcap,pcapng,PROFILE,visible
from cpag_core.contracts import validation_session
from cpag_core.dual_source_rules import validate_profile
from cpag_core.pipeline import canonical
from cpag_core.replay_inputs import ReplayInputs
from cpag_core.replay_inputs_compact import CompactReplayInputs
from round17_profile import profile


def compact_config():
    config=profile();config['process']=deepcopy(PROFILE)
    config.update(capacity_profile='engineering-core-capacity-3',storage_format='shared-observation-dag-6')
    config['replay']={'version':'dual-source-replay-1','history_format':'shared-observation-dag-6',
        'identity_strategy':'merkle-json-dag-1','prefix_digest_strategy':'incremental-prefix-digest-2',
        'simulation_start':'2026-01-01T00:00:00Z','arrival_time_basis':'independently generated parser oracle',
        'warmup_seconds':1,'allowed_lateness_seconds':2,'buffer_seconds':300,'max_buffer_records':11000,
        'max_snapshots':4096,'max_revisions':8192,'max_output_bytes':16777216}
    return config


class CompactArrivalInputTests(base.ArrivalInputTests):
    def setUp(self):
        super().setUp()
        # Control schemas may be loaded, but no original byte may be prefetched.
        session=validation_session();session.__enter__();self.addCleanup(session.__exit__,None,None,None)
        self.config=compact_config();validate_profile(self.config)

    def inputs(self,network,process=None):
        if process is None:process=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n','.csv')
        result=ReplayInputs(network,process,PROFILE,synthetic=True,capacity_config=self.config)
        self.assertIsInstance(result,CompactReplayInputs)
        self.addCleanup(result.close);return result

    def test_every_full_filtered_and_final_prefix_matches_old_complete_objects(self):
        one,_=pcap([frame(REQUEST[20:],120),frame(REQUEST[:20]),frame(b'X',110)])
        two,_=pcapng([frame(REQUEST[:20]),frame(REPLY,reverse=True)])
        csv=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n2026-01-01T00:00:00Z,0\nbad-width\n2026-01-01T00:00:01Z,NA\n','.csv')
        paths=[self.source(one),self.source(two)];new=self.inputs(paths,csv)
        old=ReplayInputs(paths,csv,PROFILE,synthetic=True,digest_strategy='incremental-prefix-digest-2');self.addCleanup(old.close)
        sequence=[('process',1),('network-0',1),('process',2),('network-1',1),('network-0',2),('process',3),('network-1',2),('process',4),('process',5),('network-0',3)]
        for slot,number in sequence:
            self.assertEqual(self.advance(new,slot,number),self.advance(old,slot,number))
            for final in (False,True):
                for allowed in (None,[new.seen[k]['source_ref'] for i,k in enumerate(new.ordered) if i%2==0],list(new.seen[k]['source_ref'] for k in new.ordered)):
                    a=old.snapshot(final=final,allowed_record_refs=allowed);b=new.snapshot(final=final,allowed_record_refs=allowed)
                    self.assertEqual(canonical({k:v for k,v in a.items() if k!='frames'}),canonical({k:v for k,v in b.items() if k!='frames'}))

    def test_cache_hit_never_returns_mutated_answers_or_unverified_raw(self):
        data,_=pcap([frame(REQUEST)]);inputs=self.inputs(self.source(data))
        self.advance(inputs,'network-0',1);first=visible(inputs)
        first['capture']['events'][0]['quality']['reasons'].append('external-mutation')
        second=visible(inputs)
        self.assertNotIn('external-mutation',second['capture']['events'][0]['quality']['reasons'])
        self.assertGreater(inputs.parse_statistics['capture_cache_hits'],0)
        inputs.seen[('network-0',1)]['raw']+=b'changed'
        with self.assertRaisesRegex(ValueError,'hash_mismatch'):inputs.snapshot()

    def test_no_new_arrivals_reuses_both_parsers_and_keeps_budget(self):
        data,_=pcap([frame(REQUEST)]);inputs=self.inputs(self.source(data))
        for slot,number in [('process',1),('process',2),('network-0',1)]:self.advance(inputs,slot,number)
        before=canonical(visible(inputs));stats=inputs.parse_statistics
        for _ in range(4):self.assertEqual(before,canonical(visible(inputs)))
        after=inputs.parse_statistics
        self.assertEqual(after['network_parse_calls'],stats['network_parse_calls'])
        self.assertEqual(after['process_parse_calls'],stats['process_parse_calls'])
        self.assertLessEqual(after['cache_bytes'],after['cache_limit_bytes'])

    def test_cache_miss_after_filter_and_final_flag_is_semantic(self):
        raw,_=pcap([frame(REQUEST[:20])]);inputs=self.inputs(self.source(raw));self.advance(inputs,'network-0',1)
        first=inputs.snapshot();self.assertTrue(first['capture']['pending'])
        final=inputs.snapshot(final=True);self.assertFalse(final['capture']['pending']);self.assertTrue(final['capture']['unsupported'])
        filtered=inputs.snapshot(allowed_record_refs=[]);self.assertEqual(filtered['capture']['pending'],[])
        self.assertEqual(inputs.parse_statistics['network_parse_calls'],3)

    def test_strategy_omission_and_partial_binding_do_not_enable_cache(self):
        self.assertIs(type(ReplayInputs('not-read','not-read.csv',PROFILE,synthetic=True)),ReplayInputs)
        for key,value in [('storage_format','shared-observation-dag-5'),('capacity_profile','engineering-capacity-2')]:
            bad=deepcopy(self.config);bad[key]=value
            with self.assertRaises(ValueError):ReplayInputs('not-read','not-read.csv',PROFILE,synthetic=True,capacity_config=bad)
        with self.assertRaisesRegex(ValueError,'explicit_compact'):
            ReplayInputs('not-read','not-read.csv',PROFILE,synthetic=True,capacity_config=self.config,digest_strategy='canonical-prefix-1')

    def test_full_profile_cache_binding_never_drops_run_id_named_columns(self):
        raw,_=pcap([]);csv=self.source(b'time,level,run_id\n2026-01-01T00:00:00Z,0,abc\n','.csv')
        new=self.inputs(self.source(raw),csv)
        old=ReplayInputs(self.source(raw),csv,PROFILE,synthetic=True,digest_strategy='incremental-prefix-digest-2');self.addCleanup(old.close)
        for item in (old,new):
            self.advance(item,'process',1);self.advance(item,'process',2);item.snapshot()
            item.profile['columns']['run_id']={'tag':'identity','asset_id':'tank','value_type':'state'}
        self.assertEqual(canonical(visible(old)),canonical(visible(new)))

    def test_small_cache_eviction_changes_cost_not_facts(self):
        from cpag_core import replay_inputs_compact as compact
        raw,_=pcap([frame(REQUEST),frame(REPLY,reverse=True)]);csv=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n2026-01-01T00:00:00Z,0\n','.csv')
        paths=self.source(raw);old=ReplayInputs(paths,csv,PROFILE,synthetic=True,digest_strategy='incremental-prefix-digest-2');self.addCleanup(old.close)
        with patch.object(compact,'CACHE_BYTES',4096):
            new=self.inputs(paths,csv)
            for slot,number in [('process',1),('process',2),('network-0',1),('process',3),('network-0',2)]:
                self.advance(old,slot,number);self.advance(new,slot,number)
                self.assertEqual(canonical(visible(old)),canonical(visible(new)))
                self.assertLessEqual(new.parse_statistics['cache_bytes'],4096)
            self.assertGreater(new.parse_statistics['oversized_uncached']+new.parse_statistics['evictions'],0)
