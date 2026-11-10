"""Hand-counted DAG6 projection, history expiry and label-isolation checks."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'services/analysis/src'), str(ROOT / 'scripts/validation')]
from round19_core_small import inputs, write
from round18_profile import at
from cpag_core import shared_export as core
from cpag_core.evaluation_artifacts import adapt_artifact, query_prediction
from cpag_core.evaluation_context import service_publication
from cpag_core.evaluation_shared import adapt_reader, reader_context
from cpag_core.pipeline import file_hash

CONTEXT = {'batch': 'handwritten-small', 'sample_sha256': 'b' * 64}


class SharedEvaluationTests(unittest.TestCase):
    def make(self, root, mode='offline', case='success', expire=False):
        networks, process, profile, config = inputs(root / 'inputs', case, mode)
        if expire:
            process.write_bytes(process.read_bytes() + (at(30) + ',1\n').encode())
            steps = [s for s in config['replay']['sequence'] if s.get('kind') not in ('source_eof', 'advance')]
            steps.append({'source_slot': 'process', 'record_number': 7, 'available_at': at(30.1)})
            steps.extend({'kind': 'source_eof', 'source_slot': slot, 'available_at': at(31)}
                         for slot in ('network-0', 'network-1', 'process'))
            steps.append({'kind': 'advance', 'available_at': at(59)})
            config['replay'].update(sequence=steps, finish_at=at(59), buffer_seconds=20)
            write(profile, config)
        output = root / 'artifact'
        manifest = core.export_task(networks, process, profile, output, mode=mode, run_id='shared-small', attempt_id=2)
        return output, manifest

    def test_handwritten_two_observations_one_relation_and_raw_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, manifest = self.make(Path(temporary))
            adapted = adapt_artifact(output, **CONTEXT)
            rows = sorted((row['kind'], row['asset'], row['time']) for row in adapted['predictions']['events'])
            self.assertEqual(rows, [('network_operation', '["192.0.2.2",44818]', '2026-01-01T00:00:10Z'),
                                    ('process_change', '["synthetic-pump","pump_state"]', '2026-01-01T00:00:12Z')])
            self.assertEqual(len(adapted['predictions']['unlabelled_relations']), 1)
            self.assertEqual(adapted['binding']['attempt_id'], 2)
            self.assertEqual(adapted['binding']['logical_artifacts'], manifest['logical_artifacts'])
            for event in adapted['predictions']['events']:
                evidence = query_prediction(output, adapted, event['id'])['evidence']
                self.assertTrue(evidence['verified_original_evidence'])
            for key, value in [('attempt_id', 3), ('storage_format', 'shared-observation-dag-5'),
                               ('logical_roots_sha256', '0' * 64), ('rule_version', 'changed')]:
                changed = copy.deepcopy(adapted['binding']); changed[key] = value
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'frozen_artifact_binding_mismatch'):
                    adapt_artifact(output, expected_binding=changed, **CONTEXT)

    def test_ever_observed_keeps_expired_process_and_deduplicates_snapshots(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, manifest = self.make(Path(temporary), mode='replay', case='normal', expire=True)
            adapted = adapt_artifact(output, **CONTEXT)
            stats = adapted['process_statistics']
            # Two network frames and six CSV data records; the header is not an
            # observation. Four expired CSV samples are absent from final state.
            self.assertEqual(stats['ever_observed_distinct_counts'],
                             {'network': 2, 'process': 6, 'operations': 1, 'changes': 1})
            self.assertEqual(stats['terminal_distinct_counts'],
                             {'network': 2, 'process': 2, 'operations': 1, 'changes': 1})
            self.assertGreater(stats['snapshot_count'], 8)
            self.assertEqual(stats['snapshot_count'], manifest['counts']['snapshots'])
            self.assertEqual(len(adapted['predictions']['events']), 2)
            self.assertEqual(len(stats['candidate_first_visible']), 1)

    def test_source_verified_reader_uses_only_bounded_paths_and_never_reruns_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, _ = self.make(Path(temporary), mode='replay', case='normal')
            core.verify_task(output)
            with core.open_reader(output) as reader:
                original = reader.get
                def bounded(name, **kwargs):
                    self.assertTrue(kwargs.get('path'), 'whole logical root decode is forbidden')
                    return original(name, **kwargs)
                with patch.object(reader, 'get', side_effect=bounded), reader_context(output, reader), \
                     patch.object(core, 'verify_task', side_effect=AssertionError('source computation repeated')):
                    adapted = adapt_artifact(output, **CONTEXT)
                    for event in adapted['predictions']['events']:
                        self.assertTrue(query_prediction(output, adapted, event['id'])['evidence']['verified_original_evidence'])
            with self.assertRaisesRegex(ValueError, 'protected_service_reader'):
                with service_publication(output, file_hash(output / 'run_manifest.json')):
                    pass

    def test_unknown_time_keeps_exclusion_and_raw_evidence_not_a_silent_drop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); net, proc, profile, config = inputs(root / 'inputs', 'success', 'offline')
            config['clocks']['network']['basis'] = None; write(profile, config)
            core.export_task(net, proc, profile, root / 'artifact')
            adapted = adapt_artifact(root / 'artifact', **CONTEXT)
            self.assertEqual(len(adapted['predictions']['events']), 1)
            self.assertEqual(len(adapted['exclusions']), 1)
            excluded = adapted['exclusions'][0]
            self.assertTrue(query_prediction(root / 'artifact', adapted, excluded['id'])['evidence']['verified_original_evidence'])

    def test_changed_source_fails_even_with_old_manifest_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, _ = self.make(Path(temporary)); raw = (output / 'sources/process.csv').read_bytes()
            (output / 'sources/process.csv').write_bytes(raw.replace(b',1\n', b',2\n'))
            with self.assertRaises(ValueError): adapt_artifact(output, **CONTEXT)

    def test_same_frozen_service_projection_two_labels_only_changes_evaluation(self):
        from round19_shared_evaluation_check import check_saved_evaluation
        from cpag_core import evaluation_bundle as eb
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output, _ = self.make(root, mode='replay', case='normal')
            core.verify_task(output)
            before = {p.relative_to(output).as_posix(): file_hash(p) for p in output.rglob('*') if p.is_file()}
            with core.open_reader(output) as reader, reader_context(output, reader):
                projection = adapt_reader(reader, **CONTEXT)
                class Client:
                    def __init__(self): self.saved = {}
                    def expect(client, method, path, body=None, code=200, **kwargs):
                        if path.endswith('evaluation-input?projection=dual'): return adapt_reader(reader, **CONTEXT)
                        if method == 'POST':
                            try: result = eb.verify_document(body, output)
                            except ValueError:
                                if code == 409: return {'rejected': True}
                                raise
                            if code != 201: raise AssertionError('invalid sidecar accepted')
                            identity = str(len(client.saved)); client.saved[identity] = body
                            return {'evaluation': {'id': identity}, 'result': result['result']}
                        from urllib.parse import urlparse, parse_qs
                        parsed = urlparse(path); parts = parsed.path.split('/'); identity = parts[parts.index('evaluations') + 1]
                        document = client.saved[identity]
                        if parsed.path.endswith('/download'): return json.dumps(document).encode()
                        query = parse_qs(parsed.query)
                        result = eb.verify_document(document, output, identity=query.get('event', [None])[0], reference=query.get('reference') == ['true'])
                        return {'evidence': result['evidence']} if query else {'result': result['result']}
                result = check_saved_evaluation(Client(), 'shared-small', projection, work=root / 'sidecars')
                self.assertTrue(result['analysis_logical_roots_unchanged'])
                self.assertEqual([row['expected_tp_fp_fn'] for row in result['checks']], [[2, 0, 0], [1, 1, 1]])
            after = {p.relative_to(output).as_posix(): file_hash(p) for p in output.rglob('*') if p.is_file()}
            self.assertEqual(before, after)


if __name__ == '__main__': unittest.main()
