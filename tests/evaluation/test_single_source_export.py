"""Actual one-source execution, separate from projection of dual-source output."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'services/analysis/src'), str(ROOT / 'scripts/validation')]
from dual_source_fixtures import make_case
from round17_profile import profile as bounded_profile
from cpag_core.contracts import validate
from cpag_core.dual_source_export import export_task as dual_export
from cpag_core.evaluation_artifacts import adapt_artifact, query_prediction
from cpag_core.pipeline import canonical, file_hash
from cpag_core.single_source_export import export_task, query_task, verify_task


CONTEXT = {'batch': 'independent-common-batch', 'sample_sha256': 'b' * 64}


def inputs(root):
    network, process, profile = make_case(root)
    profile.write_text(json.dumps(bounded_profile()))
    return network, process, profile


class SingleSourceTests(unittest.TestCase):
    def test_network_executes_without_csv_and_process_parser_is_never_called(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); network, process, profile = inputs(root / 'input')
            process.unlink()
            with patch('cpag_core.single_source_export.parse_process', side_effect=AssertionError('CSV parser forbidden')), \
                 patch('cpag_core.single_source_export.EvidenceIndex', side_effect=AssertionError('CSV index forbidden')):
                manifest = export_task('network', network, profile, root / 'run')
                verify_task(root / 'run')
                adapted = adapt_artifact(root / 'run', projection='network', **CONTEXT)
                evidence = query_prediction(root / 'run', adapted, adapted['predictions']['events'][0]['id'])
            self.assertEqual(manifest['source_presence'], {'network': True, 'process': False})
            self.assertEqual(manifest['source_files'], ['sources/network.pcap'])
            self.assertFalse((root / 'run/sources/process.csv').exists())
            analysis = json.loads((root / 'run/analysis.json').read_text())
            self.assertEqual(analysis['process'], []); self.assertEqual(analysis['changes'], [])
            self.assertEqual(analysis['candidates'], [])
            self.assertEqual(analysis['operations'][0]['assessment'], 'unknown')
            self.assertIn('process_source_not_supplied', analysis['quality']['unknown_reasons'])
            self.assertTrue(all(row['source_ref']['frame_number'] is not None for row in evidence['evidence']['verified_original_evidence']))
            with self.assertRaises(KeyError): query_task(root / 'run', change_id='first')

    def test_process_executes_without_capture_and_packet_functions_are_never_called(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); network, process, profile = inputs(root / 'input')
            network.unlink()
            with patch('cpag_core.single_source_export.analyze_capture', side_effect=AssertionError('capture parser forbidden')), \
                 patch('cpag_core.single_source_export.PacketEvidence', side_effect=AssertionError('capture index forbidden')):
                manifest = export_task('process', process, profile, root / 'run')
                verify_task(root / 'run')
                adapted = adapt_artifact(root / 'run', projection='process', **CONTEXT)
                evidence = query_prediction(root / 'run', adapted, adapted['predictions']['events'][0]['id'])
            self.assertEqual(manifest['source_presence'], {'network': False, 'process': True})
            self.assertEqual(manifest['source_files'], ['sources/process.csv'])
            self.assertFalse((root / 'run/sources/network.pcap').exists())
            analysis = json.loads((root / 'run/analysis.json').read_text())
            self.assertEqual(analysis['network'], []); self.assertEqual(analysis['operations'], [])
            self.assertEqual(analysis['candidates'], [])
            self.assertEqual(len(analysis['changes']), 1)
            self.assertIn('network_source_not_supplied', analysis['quality']['unknown_reasons'])
            self.assertTrue(all(row['source_ref']['frame_number'] is None for row in evidence['evidence']['verified_original_evidence']))
            with self.assertRaises(KeyError): query_task(root / 'run', operation_id='first')

    def test_shared_manual_categories_match_dual_without_rewriting_id_or_business_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); network, process, profile = inputs(root / 'input')
            dual_export(network, process, profile, root / 'dual')
            dual = adapt_artifact(root / 'dual', **CONTEXT)
            for mode, source, expected_kind, expected_time in [
                    ('network', network, 'network_operation', '2026-01-01T00:00:10Z'),
                    ('process', process, 'process_change', '2026-01-01T00:00:12Z')]:
                export_task(mode, source, profile, root / mode)
                actual = adapt_artifact(root / mode, projection=mode, **CONTEXT)
                expected = [row for row in dual['predictions']['events'] if row['kind'] == expected_kind]
                self.assertEqual(actual['predictions']['events'], expected)
                self.assertEqual(actual['predictions']['events'][0]['time'], expected_time)
                self.assertEqual(actual['predictions']['unlabelled_relations'], [])
                self.assertEqual(actual['binding']['source_mode'], mode)
                self.assertEqual(actual['binding']['source_execution_version'], 'bounded-single-source-1')
                self.assertNotEqual(actual['binding']['input_fingerprint'], dual['binding']['input_fingerprint'])
                for wrong_projection in {'network', 'process', 'dual'} - {mode}:
                    with self.assertRaisesRegex(ValueError, 'projection_must_match'):
                        adapt_artifact(root / mode, projection=wrong_projection, **CONTEXT)

    def test_strict_manifest_schema_and_deterministic_semantic_and_run_bytes(self):
        from jsonschema import Draft202012Validator, FormatChecker
        from cpag_core.contracts import SCHEMAS
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); network, _, profile = inputs(root / 'input')
            first = export_task('network', network, profile, root / 'a', run_id='fixed-run', attempt_id=2)
            second = export_task('network', network, profile, root / 'b', run_id='fixed-run', attempt_id=2)
            self.assertEqual(first, second)
            validate('SingleSourceRunManifest', first)
            schema = json.loads((SCHEMAS / 'SingleSourceRunManifest.schema.json').read_text())
            Draft202012Validator(schema, format_checker=FormatChecker()).validate(first)
            for path in (root / 'a').rglob('*'):
                if path.is_file():
                    self.assertEqual(path.read_bytes(), (root / 'b' / path.relative_to(root / 'a')).read_bytes())
            extra = copy.deepcopy(first); extra['unexpected'] = True
            with self.assertRaises(Exception): Draft202012Validator(schema).validate(extra)

    def test_extras_missing_sources_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); network, _, profile = inputs(root / 'input')
            export_task('network', network, profile, root / 'run')
            unexpected = root / 'run/sources/process.csv'; unexpected.write_text('time,pump\n')
            with self.assertRaisesRegex(ValueError, 'inventory_mismatch'): verify_task(root / 'run')
            unexpected.unlink()
            path = root / 'run/sources/network.pcap'; data = path.read_bytes(); path.unlink()
            with self.assertRaises(ValueError): verify_task(root / 'run')
            path.symlink_to(network)
            with self.assertRaisesRegex(ValueError, 'symlink_artifact'): verify_task(root / 'run')
            path.unlink(); path.write_bytes(data)
            self.assertEqual(verify_task(root / 'run')['source_mode'], 'network')

    def test_rehashed_analysis_and_wrong_version_are_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); network, _, profile = inputs(root / 'input')
            export_task('network', network, profile, root / 'run')
            path = root / 'run/analysis.json'; analysis = json.loads(path.read_text())
            analysis['operations'][0]['assessment'] = 'fabricated-cross-source-observation'
            path.write_bytes(canonical(analysis) + b'\n')
            mp = root / 'run/run_manifest.json'; manifest = json.loads(mp.read_text())
            for row in manifest['artifacts']:
                if row['path'] == 'analysis.json': row.update(sha256=file_hash(path), size_bytes=path.stat().st_size)
            mp.write_bytes(canonical(manifest) + b'\n')
            with self.assertRaisesRegex(ValueError, 'semantic_mismatch'): verify_task(root / 'run')
            manifest['single_source_version'] = 'future-unknown'; mp.write_bytes(canonical(manifest) + b'\n')
            with self.assertRaises(ValueError): verify_task(root / 'run')

    def test_invalid_input_limits_profile_labels_and_partial_outputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); network, process, profile = inputs(root / 'input')
            with self.assertRaises(ValueError): export_task('process', [process, process], profile, root / 'many')
            with self.assertRaises(ValueError): export_task('attacks', network, profile, root / 'mode')
            with self.assertRaises(ValueError): export_task('network', network, profile, root / 'attempt', attempt_id=0)
            original = process.read_text(); process.write_text(original.replace('time,pump', 'time,pump,label'))
            with self.assertRaises(ValueError): export_task('process', process, profile, root / 'labels')
            self.assertFalse((root / 'labels').exists())
            process.write_text(original)
            with patch('cpag_core.single_source_export.OUTPUT_BYTES', 16):
                with self.assertRaisesRegex(ValueError, 'output_limit'):
                    export_task('process', process, profile, root / 'small')
            self.assertFalse((root / 'small').exists())
            config = json.loads(profile.read_text()); config['replay'] = {'version': 'unsupported'}
            profile.write_text(json.dumps(config))
            with self.assertRaises(ValueError): export_task('process', process, profile, root / 'replay')
            self.assertFalse((root / 'replay').exists())

    def test_backup_copy_and_stale_attempt_binding(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); _, process, profile = inputs(root / 'input')
            export_task('process', process, profile, root / 'one', run_id='run', attempt_id=1)
            adapted = adapt_artifact(root / 'one', projection='process', **CONTEXT)
            shutil.copytree(root / 'one', root / 'restored')
            self.assertEqual(adapted, adapt_artifact(root / 'restored', projection='process', **CONTEXT))
            export_task('process', process, profile, root / 'two', run_id='run', attempt_id=2)
            with self.assertRaisesRegex(ValueError, 'frozen_artifact_binding_mismatch'):
                adapt_artifact(root / 'two', projection='process', expected_binding=adapted['binding'], **CONTEXT)

    def test_cli_source_mode_verify_and_original_query(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); network, _, profile = inputs(root / 'input')
            command = [sys.executable, '-m', 'cpag_core.single_source_export', '--output', str(root / 'run')]
            env = dict(os.environ, PYTHONPATH=str(ROOT / 'services/analysis/src'))
            for args in [command + ['--source-mode', 'network', '--source', str(network), '--profile', str(profile)],
                         command + ['--verify'], command + ['--operation', 'first']]:
                result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['source_mode'], 'network')


if __name__ == '__main__':
    unittest.main()
