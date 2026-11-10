"""Complete standard graph/event equivalence, including storage composition."""
from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from dual_source_fixtures import make_case
from cpag_core.compact_projection import store_standard_projection,STRATEGY_VERSION
from cpag_core.dual_source import analyze
from cpag_core.dual_source_export import event_graph
from cpag_core.pipeline import canonical
from cpag_core.shared_artifact_store_compact import FORMAT,LogicalHasher,SharedArtifactWriter,SharedArtifactReader

CONTEXT={'run_id':'projection-oracle','attempt_id':1,'input_fingerprint':'a'*64,'config_fingerprint':'b'*64}


def analysis(root,case='success'):
    network,process,path=make_case(root,case)
    return analyze(network,process,json.loads(path.read_text()))


class CompactProjectionTests(unittest.TestCase):
    def test_all_complete_fields_and_root_digests_match_independent_projection(self):
        for case in ('success','ambiguous','error','missing_response','no_change','missing_value',
                     'sampling_gap','clock_unknown','uncertain_time','mapping_missing','mapping_conflict','out_of_order'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);result=analysis(root/'source',case)
                expected=event_graph(result,identity_strategy='merkle-json-dag-1')
                writer=SharedArtifactWriter(root/'store',context=CONTEXT,version=FORMAT)
                try:
                    stored=store_standard_projection(result,writer,graph_name='graph.json',events_name='events.json')
                    self.assertEqual(stored['strategy'],STRATEGY_VERSION)
                    self.assertEqual(canonical(stored['projection']),canonical(expected))
                    for key,name in (('graph','graph.json'),('events','events.json')):
                        self.assertEqual(stored[key]['digest'],LogicalHasher().digest(expected[name])['digest'])
                    sealed=writer.seal()
                    with closing(SharedArtifactReader(root/'store',expected_manifest_sha256=sealed['manifest_sha256'])) as reader:
                        for name in expected:self.assertEqual(canonical(reader.get(name)),canonical(expected[name]))
                finally:writer.close()

    def test_mutated_nested_values_are_recomputed_and_previous_values_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);result=analysis(root/'source')
            writer=SharedArtifactWriter(root/'store',context=CONTEXT,version=FORMAT)
            try:
                before=store_standard_projection(result,writer,graph_name='before')
                old=deepcopy(before['projection'])
                result['network'][0]['observation']['source_refs'].append(
                    deepcopy(result['network'][0]['observation']['source_refs'][0]))
                after=store_standard_projection(result,writer,graph_name='after')
                expected=event_graph(result,identity_strategy='merkle-json-dag-1')
                self.assertNotEqual(before['graph']['digest'],after['graph']['digest'])
                self.assertEqual(canonical(after['projection']),canonical(expected))
                sealed=writer.seal()
                with closing(SharedArtifactReader(root/'store',expected_manifest_sha256=sealed['manifest_sha256'])) as reader:
                    self.assertEqual(canonical(reader.get('before')),canonical(old['graph.json']))
                    self.assertEqual(canonical(reader.get('after')),canonical(expected['graph.json']))
            finally:writer.close()

    def test_callback_is_explicit_and_receives_every_complete_graph_field(self):
        with tempfile.TemporaryDirectory() as directory:
            result=analysis(Path(directory)/'source')
            original=event_graph(result,identity_strategy='merkle-json-dag-1');seen=[]
            def complete(value):
                seen.append(deepcopy(value));return LogicalHasher().digest(value)['digest']
            actual=event_graph(result,identity_strategy='merkle-json-dag-1',graph_identity_callback=complete)
            self.assertEqual(canonical(actual),canonical(original))
            self.assertEqual(seen,[{key:value for key,value in original['graph.json'].items() if key!='graph_id'}])
            for callback in (None,lambda value:'bad',lambda value:'G'*64):
                if callback is None:
                    with self.assertRaisesRegex(ValueError,'invalid_graph_identity_callback'):
                        event_graph(result,graph_identity_callback=complete)
                else:
                    with self.assertRaisesRegex(ValueError,'invalid_graph_identity_digest'):
                        event_graph(result,identity_strategy='merkle-json-dag-1',graph_identity_callback=callback)

    def test_sink_and_schema_failures_do_not_return_or_seal_partial_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);result=analysis(root/'source')
            writer=SharedArtifactWriter(root/'store',context=CONTEXT,version=FORMAT)
            try:
                with patch.object(writer,'intern',side_effect=ValueError('injected_full_child_failure')):
                    with self.assertRaisesRegex(ValueError,'injected_full_child_failure'):
                        store_standard_projection(result,writer)
                with patch('cpag_core.dual_source_export.validate',side_effect=ValueError('injected_schema_failure')):
                    with self.assertRaisesRegex(ValueError,'injected_schema_failure'):
                        store_standard_projection(result,writer)
                self.assertFalse((root/'store/manifest.json').exists())
                self.assertEqual(writer.root_count,0)
            finally:writer.close()
        with self.assertRaisesRegex(ValueError,'requires_dag6'):
            store_standard_projection({},object())


if __name__=='__main__':unittest.main()
