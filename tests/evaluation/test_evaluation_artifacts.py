"""Independent R19 adapter oracles, using actual exported final artifacts."""
import copy
import inspect
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'services/analysis/src'), str(ROOT / 'scripts/validation')]
from dual_source_fixtures import make_case, message, frame
from round18_profile import fixture, at
from cpag_core.dual_source_export import export_task
from cpag_core.evaluation_artifacts import adapt_artifact, query_prediction
from cpag_core.pipeline import file_hash
from cpag_core.replay_export import export_task as replay_export, query_task as replay_query


CONTEXT = {'batch': 'independently-registered-batch', 'sample_sha256': 'b' * 64}


class EvaluationArtifactTests(unittest.TestCase):
    def test_handwritten_projection_semantics_and_explicit_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); paths = make_case(root / 'input'); output = root / 'run'
            export_task(*paths, output, run_id='artifact-run', attempt_id=3)
            adapted = adapt_artifact(output, **CONTEXT)
            events = adapted['predictions']['events']
            by_kind = {row['kind']: row for row in events}
            self.assertEqual(set(by_kind), {'network_operation', 'process_change'})
            self.assertEqual(by_kind['network_operation']['asset'], '["192.0.2.2",44818]')
            self.assertEqual(by_kind['network_operation']['time'], '2026-01-01T00:00:10Z')
            self.assertEqual(by_kind['process_change']['asset'], '["synthetic-pump","pump_state"]')
            self.assertEqual(by_kind['process_change']['time'], '2026-01-01T00:00:12Z')
            self.assertEqual(len(adapted['predictions']['unlabelled_relations']), 1)
            self.assertEqual(adapted['binding']['attempt_id'], 3)
            self.assertEqual(adapted['binding']['artifact_sha256']['run_manifest.json'], file_hash(output / 'run_manifest.json'))
            self.assertIsNone(adapted['binding']['final_snapshot'])
            for mode, kind in [('network', 'network_operation'), ('process', 'process_change')]:
                view = adapt_artifact(output, projection=mode, **CONTEXT)
                self.assertEqual(view['predictions']['events'], [by_kind[kind]])
                self.assertEqual(view['predictions']['unlabelled_relations'], [])
            self.assertEqual(adapted, adapt_artifact(output, expected_binding=adapted['binding'], **CONTEXT))

    def test_mapping_or_response_quality_does_not_cherry_pick_network_observation(self):
        for case in ('mapping_missing', 'mapping_conflict', 'error', 'missing_response'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); export_task(*make_case(root / 'input', case), root / 'run')
                adapted = adapt_artifact(root / 'run', projection='network', **CONTEXT)
                self.assertEqual(len(adapted['predictions']['events']), 1)
                self.assertEqual(adapted['predictions']['events'][0]['asset'], '["192.0.2.2",44818]')

    def test_unknown_request_time_is_explicit_exclusion_with_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); paths = make_case(root / 'input')
            profile = json.loads(paths[2].read_text()); profile['clocks']['network']['basis'] = None
            paths[2].write_text(json.dumps(profile)); export_task(*paths, root / 'run')
            adapted = adapt_artifact(root / 'run', **CONTEXT)
            self.assertEqual({row['kind'] for row in adapted['predictions']['events']}, {'process_change'})
            self.assertEqual(len(adapted['exclusions']), 1)
            excluded = adapted['exclusions'][0]
            self.assertEqual(excluded['reason'], 'trustworthy_configured_request_time_unavailable')
            self.assertTrue(query_prediction(root / 'run', adapted, excluded['id'])['evidence']['verified_original_evidence'])

    def test_prediction_and_unlabelled_relation_query_reuse_verified_originals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); export_task(*make_case(root / 'input'), root / 'run')
            adapted = adapt_artifact(root / 'run', **CONTEXT)
            ids = [row['id'] for row in adapted['predictions']['events']] + adapted['predictions']['unlabelled_relations']
            for identity in ids:
                evidence = query_prediction(root / 'run', adapted, identity)
                self.assertEqual(evidence['binding'], adapted['binding'])
                self.assertTrue(evidence['evidence']['verified_original_evidence'])
            with self.assertRaises(KeyError): query_prediction(root / 'run', adapted, 'absent')
            changed = copy.deepcopy(adapted); changed['predictions']['events'][0]['time'] = at(0)
            with self.assertRaisesRegex(ValueError, 'adapted_payload_mismatch'):
                query_prediction(root / 'run', changed, ids[0])

    def test_replay_counts_only_terminal_distinct_ids_and_preserves_process_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); net, process, profile, _ = fixture(root / 'input')
            replay_export(net, process, profile, root / 'run')
            adapted = adapt_artifact(root / 'run', **CONTEXT)
            snapshots = [json.loads(line) for line in (root / 'run/snapshots.jsonl').read_text().splitlines()]
            self.assertGreater(sum(len(row['analysis']['operations']) for row in snapshots), 1)
            self.assertEqual(len(adapted['predictions']['events']), 2)
            self.assertEqual(len({row['id'] for row in adapted['predictions']['events']}), 2)
            self.assertEqual(len(adapted['predictions']['unlabelled_relations']), 1)
            final = adapted['binding']['final_snapshot']
            self.assertEqual(final['snapshot_id'], snapshots[-1]['snapshot_id'])
            self.assertEqual(adapted['process_statistics']['snapshot_count'], len(snapshots))
            self.assertEqual(len(adapted['process_statistics']['candidate_first_visible']), 1)
            self.assertEqual(adapted['process_statistics']['candidate_withdrawal_count'], 0)
            for event in adapted['predictions']['events']:
                result = query_prediction(root / 'run', adapted, event['id'])
                self.assertEqual(result['evidence']['revision'], final['snapshot_number'])

    def test_offline_and_equivalent_replay_share_registered_observation_categories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); net, process, profile, config = fixture(root / 'input', split=False)
            replay_export(net, process, profile, root / 'replay')
            config.pop('replay'); offline_profile = root / 'offline-profile.json'
            offline_profile.write_text(json.dumps(config))
            export_task(net, process, offline_profile, root / 'offline')
            offline = adapt_artifact(root / 'offline', **CONTEXT)
            replay = adapt_artifact(root / 'replay', **CONTEXT)
            # The registered metric projection compares observations. Source-ref
            # identities and replay lifecycle are deliberately not rewritten.
            def metric_rows(value):
                return sorted((row['kind'], row['asset'], row['time'], row['batch'], row['sample_sha256'])
                              for row in value['predictions']['events'])
            self.assertEqual(metric_rows(offline), metric_rows(replay))
            self.assertEqual(len(offline['predictions']['unlabelled_relations']), len(replay['predictions']['unlabelled_relations']))
            self.assertNotEqual(offline['binding']['mode'], replay['binding']['mode'])

    def test_declared_real_branch_preserves_unvalidated_status(self):
        from round17_profile import profile as real_profile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); paths = make_case(root / 'input')
            paths[2].write_text(json.dumps(real_profile(synthetic=False)))
            export_task(*paths, root / 'run')
            adapted = adapt_artifact(root / 'run', **CONTEXT)
            self.assertFalse(adapted['predictions']['synthetic'])
            self.assertFalse(adapted['binding']['synthetic'])
            self.assertTrue(all(event['kind'] != 'attack' for event in adapted['predictions']['events']))

    def test_withdrawn_candidate_is_history_only_and_never_terminal_prediction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); networks, process, profile, config = fixture(root / 'input', split=False)
            network = networks[0]
            request = message(bytes.fromhex('10032001240130010100'), context=(1).to_bytes(8, 'little'))
            response = message(bytes.fromhex('90000000'), context=(1).to_bytes(8, 'little'))
            capture = bytes.fromhex('d4c3b2a1') + struct.pack('<HHiiII', 2, 4, 0, 0, 65535, 1)
            for when, raw in [(10, frame(request, seq=100)), (11, frame(response, seq=100, reverse=True)), (10.1, frame(b'X', seq=110))]:
                capture += struct.pack('<IIII', 1767225600 + int(when), round((when - int(when)) * 1000000), len(raw), len(raw)) + raw
            network.write_bytes(capture)
            config['replay']['sequence'].insert(6, {'source_slot': 'network-0', 'record_number': 3, 'available_at': at(13)})
            profile.write_text(json.dumps(config)); replay_export(networks, process, profile, root / 'run')
            adapted = adapt_artifact(root / 'run', **CONTEXT)
            self.assertEqual(adapted['predictions']['unlabelled_relations'], [])
            self.assertEqual({row['kind'] for row in adapted['predictions']['events']}, {'process_change'})
            stats = adapted['process_statistics']
            self.assertEqual(stats['candidate_withdrawal_count'], 1)
            self.assertEqual(len(stats['candidate_first_visible']), 1)
            prior = stats['candidate_first_visible'][0]
            self.assertTrue(replay_query(root / 'run', prior['snapshot_number'], operation_id='first')['verified_original_evidence'])
            with self.assertRaises(KeyError): query_prediction(root / 'run', adapted, prior['candidate_id'])

    def test_binding_rejects_attempt_context_versions_policy_or_artifact_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); paths = make_case(root / 'input')
            export_task(*paths, root / 'run', run_id='same-run', attempt_id=1)
            export_task(*paths, root / 'next', run_id='same-run', attempt_id=2)
            adapted = adapt_artifact(root / 'run', **CONTEXT)
            for field in ('analysis_version', 'rule_version', 'config_version', 'adapter_version', 'policy_sha256'):
                changed = copy.deepcopy(adapted['binding']); changed[field] = 'changed'
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'frozen_artifact_binding_mismatch'):
                    adapt_artifact(root / 'run', expected_binding=changed, **CONTEXT)
            with self.assertRaisesRegex(ValueError, 'frozen_artifact_binding_mismatch'):
                adapt_artifact(root / 'next', expected_binding=adapted['binding'], **CONTEXT)
            with self.assertRaisesRegex(ValueError, 'frozen_artifact_binding_mismatch'):
                adapt_artifact(root / 'run', projection='network', expected_binding=adapted['binding'], **CONTEXT)
            (root / 'run/analysis.json').write_bytes(b'{}\n')
            with self.assertRaises(ValueError): adapt_artifact(root / 'run', **CONTEXT)

    def test_missing_artifact_rejected_and_no_gold_parameter_or_read(self):
        self.assertNotIn('annotations', inspect.signature(adapt_artifact).parameters)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); export_task(*make_case(root / 'input'), root / 'run')
            gold = root / 'independent-labels.json'; gold.write_text('{"independent":1}')
            before = adapt_artifact(root / 'run', **CONTEXT)
            gold.write_text('{"independent":2}')
            self.assertEqual(before, adapt_artifact(root / 'run', **CONTEXT))
            (root / 'run/graph.json').unlink()
            with self.assertRaises(ValueError): adapt_artifact(root / 'run', **CONTEXT)

    def test_invalid_registration_context_or_projection_is_rejected(self):
        for context in ({'batch': '', 'sample_sha256': 'a' * 64},
                        {'batch': 'batch', 'sample_sha256': 'invented'},
                        dict(CONTEXT, projection='attacks')):
            with self.subTest(context=context), self.assertRaises(ValueError):
                adapt_artifact('/no-artifact-needed', **context)


if __name__ == '__main__':
    unittest.main()
