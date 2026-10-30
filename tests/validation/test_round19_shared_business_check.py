"""Complete-root oracle coverage and a validly rehashed unsampled-root negative."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'services/analysis/src'), str(ROOT / 'scripts/validation')]
from round19_core_small import inputs, write, _refresh_untrusted_outer
from round19_shared_business_check import compare_all_business_roots
from cpag_core import shared_export as core
from cpag_core.pipeline import file_hash


class SharedBusinessCheckTests(unittest.TestCase):
    def test_all_offline_and_replay_roots_and_complete_history_match(self):
        for mode, case, expected in [('offline', 'success', 11), ('replay', 'normal', 16)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); networks, process, profile, _ = inputs(root / 'inputs', case, mode)
                manifest = core.export_task(networks, process, profile, root / 'formal',
                                            run_id='formal-business-test', attempt_id=2, mode=mode)
                result = compare_all_business_roots(root / 'formal', networks, process, profile,
                                                    root / 'comparison', expected_manifest=manifest)
                self.assertEqual(result['status'], 'passed')
                self.assertEqual(result['complete_business_root_count'], expected)
                self.assertEqual(result['unapproved_business_differences'], [])
                names = {row['name'] for row in result['comparisons'] if row['business_root']}
                self.assertTrue({'analysis.json', 'events.json', 'graph.json', 'quality.json',
                                 'dataset.json', 'indices/operations', 'indices/rule_findings'} <= names)
                if mode == 'replay':
                    self.assertTrue({'history/snapshots', 'history/revisions', 'metrics.json', 'arrivals.json'} <= names)
                self.assertEqual(result['policy']['permitted_business_identity_differences'], [])
                self.assertTrue((root / 'comparison/formal-core-copy/shared/shared.sqlite3').is_file())
                self.assertTrue((root / 'comparison/independent-core-export/shared/shared.sqlite3').is_file())

    def test_rehashed_unsampled_quality_business_change_fails_and_retains_both_answers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); networks, process, profile, config = inputs(root / 'inputs', 'success', 'offline')
            artifact = root / 'formal'
            manifest = core.export_task(networks, process, profile, artifact, run_id='negative-business-test')
            with core.open_reader(artifact) as reader:
                values = {row['name']: reader.get(row['name']) for row in manifest['logical_artifacts']}
                context = reader.manifest['context']
            # Valid typed nodes and recomputed inventory cannot make an altered
            # unselected business field equivalent to the same original inputs.
            values['quality.json']['acceptance_negative_counterevidence'] = ['must not be omitted from comparison']
            replacement = root / 'replacement-shared'
            writer = core.SharedArtifactWriter(replacement, context=context, version=core.FORMAT,
                                               **core.writer_options(config, 1024**3 - 65536))
            for name, value in values.items(): writer.add(name, value)
            manifest['logical_artifacts'] = [writer.descriptor(row['name']) for row in manifest['logical_artifacts']]
            writer.seal()
            writer.close(); shutil.rmtree(artifact / 'shared'); replacement.rename(artifact / 'shared')
            write(artifact / 'run_manifest.json', manifest); _refresh_untrusted_outer(artifact)
            # Storage remains structurally valid; the independent complete-root
            # oracle, rather than a stale hash or missing file, must reject it.
            with core.open_reader(artifact): pass
            with self.assertRaisesRegex(ValueError, 'complete_business_root_mismatch:quality.json'):
                compare_all_business_roots(artifact, networks, process, profile, root / 'comparison')
            result = json.loads((root / 'comparison/comparison.json').read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['unapproved_business_differences'], ['quality.json'])
            self.assertTrue((root / 'comparison/independent-core-export/shared/shared.sqlite3').is_file())

    def test_original_profile_mismatch_refused_before_reference_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); networks, process, profile, config = inputs(root / 'inputs', 'success', 'offline')
            core.export_task(networks, process, profile, root / 'formal')
            config['rule_version'] = 'wrong-reference-config'; write(profile, config)
            with self.assertRaisesRegex(ValueError, 'configuration_mismatch'):
                compare_all_business_roots(root / 'formal', networks, process, profile, root / 'comparison')
            self.assertEqual(json.loads((root / 'comparison/comparison.json').read_text())['status'], 'failed')
            self.assertFalse((root / 'comparison/independent-core-export').exists())


if __name__ == '__main__': unittest.main()
