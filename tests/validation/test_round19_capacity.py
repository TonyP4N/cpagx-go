"""R19 reference-environment gate and failure-record preservation controls."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/validation'))
import round19_capacity as capacity


class CapacityGateTests(unittest.TestCase):
    def reference(self):
        return {'system': 'Linux', 'os_id': 'ubuntu', 'os_version': '24.04',
                'machine': 'x86_64', 'cpu_count': 8, 'memory_bytes': 16 * capacity.GIB,
                'ssd_verified': True, 'free_bytes': 32 * capacity.GIB, 'docker_ready': True,
                'docker': {'architecture': 'x86_64', 'cpus': 8, 'memory_bytes': 16 * capacity.GIB}}

    def test_reference_check_rejects_missing_and_individual_mismatches(self):
        self.assertEqual(capacity.reference_reasons(self.reference()), [])
        for field, value in [('system', 'Darwin'), ('os_id', 'debian'), ('os_version', '22.04'),
                             ('machine', 'arm64'), ('cpu_count', 10), ('memory_bytes', 8 * capacity.GIB),
                             ('ssd_verified', None), ('free_bytes', 7 * capacity.GIB), ('docker_ready', False)]:
            env = self.reference(); env[field] = value
            with self.subTest(field=field): self.assertTrue(capacity.reference_reasons(env))
        self.assertTrue(capacity.reference_reasons({}))

    def test_remote_or_small_docker_is_not_reference_capable(self):
        for change in ({'architecture': 'aarch64'}, {'memory_bytes': 8217448448}, {'cpus': 2}):
            env = self.reference(); env['docker'].update(change)
            self.assertTrue(capacity.reference_reasons(env))

    def test_reference_refusal_has_failure_record_and_does_not_start_worker(self):
        env = self.reference(); env.update(system='Darwin', reference_environment_qualified=False,
                                           reference_refusal_reasons=['host_not_linux'])
        def probe(recorder):
            recorder.record['environment'] = deepcopy(env)
            (recorder.root / 'raw-probe.stderr').write_text('original probe failure\n')
            return deepcopy(env)
        with tempfile.TemporaryDirectory() as directory, patch.object(capacity, 'probe', side_effect=probe), patch.object(capacity, 'formal_case') as formal:
            root = Path(directory) / 'attempt'
            code, record = capacity.execute(root, probe_only=True)
            self.assertEqual(code, 1); self.assertFalse(record['reference_accepted'])
            self.assertIn('reference_environment_refused', record['error'])
            self.assertEqual(json.loads((root / 'record.json').read_text())['status'], 'failed')
            self.assertEqual((root / 'raw-probe.stderr').read_text(), 'original probe failure\n')
            self.assertTrue(record['failures']); self.assertTrue((root / 'events.jsonl').is_file())
            self.assertTrue((root / 'errors.log').is_file()); formal.assert_not_called()
            with self.assertRaises(FileExistsError): capacity.execute(root, dev_run=True, probe_only=True)
            self.assertEqual((root / 'raw-probe.stderr').read_text(), 'original probe failure\n')

    def test_only_explicit_dev_run_permits_mismatched_host_and_never_accepts(self):
        def probe(recorder):
            env = {'reference_environment_qualified': False, 'reference_refusal_reasons': ['host_not_linux']}
            recorder.record['environment'] = env
            return env
        with tempfile.TemporaryDirectory() as directory, patch.object(capacity, 'probe', side_effect=probe):
            code, record = capacity.execute(Path(directory) / 'dev', dev_run=True, probe_only=True)
            self.assertEqual(code, 0); self.assertEqual(record['status'], 'development_probe')
            self.assertFalse(record['reference_accepted'])

    def test_formal_failure_cannot_be_converted_to_acceptance(self):
        def probe(recorder):
            env = self.reference(); env.update(reference_environment_qualified=True, reference_refusal_reasons=[])
            recorder.record['environment'] = env
            return env
        with tempfile.TemporaryDirectory() as directory, patch.object(capacity, 'probe', side_effect=probe), patch.object(capacity, 'read_case', return_value={}), patch.object(capacity.Recorder, 'command', return_value=(0, 'image')), patch.object(capacity, 'formal_case', side_effect=RuntimeError('operation_limit')):
            code, record = capacity.execute(Path(directory) / 'worker-failure', case_manifest=Path('case.json'))
            self.assertEqual(code, 1); self.assertFalse(record['reference_accepted'])
            self.assertIn('operation_limit', record['error'])
            self.assertTrue(any(row['name'] == 'formal_chain_case' and row['status'] == 'failed' for row in record['stages']))

    def test_density_budget_conflict_refuses_before_image_or_worker(self):
        environment={'reference_environment_qualified':False,'reference_refusal_reasons':['host_not_linux']}
        case={'density_preflight':{'status':'blocked_budget_design','issues':[{'code':'flat_output_lower_bound_exceeds_budget'}]}}
        with tempfile.TemporaryDirectory() as directory, patch.object(capacity,'probe',return_value=environment), patch.object(capacity,'read_case',return_value=case), patch.object(capacity.Recorder,'command') as command, patch.object(capacity,'formal_case') as formal:
            code,record=capacity.execute(Path(directory)/'attempt',dev_run=True,case_manifest=Path('case.json'))
            self.assertEqual(code,1)
            self.assertIn('density_budget_design_refused:flat_output_lower_bound_exceeds_budget',record['error'])
            self.assertEqual(record['density_preflight'],case['density_preflight'])
            command.assert_not_called();formal.assert_not_called()

    def test_density_resource_selection_must_be_explicit_and_consistent(self):
        environment={'reference_environment_qualified':False,'reference_refusal_reasons':['host_not_linux']}
        case={'density_preflight':{'status':'admissible_for_formal_attempt','capacity_profile':'engineering-capacity-1','issues':[]}}
        for resource in (None,'r19-dev-s100-1'):
            with tempfile.TemporaryDirectory() as directory, patch.object(capacity,'probe',return_value=environment), patch.object(capacity,'read_case',return_value=case), patch.object(capacity.Recorder,'command') as command, patch.object(capacity,'formal_case') as formal:
                code,record=capacity.execute(Path(directory)/'attempt',dev_run=True,case_manifest=Path('case.json'),resource_profile=resource)
                self.assertEqual(code,1);self.assertEqual(record['error'],'density_operator_resource_profile_mismatch')
                command.assert_not_called();formal.assert_not_called()

    def test_probe_exception_and_failed_command_keep_raw_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = capacity.Recorder(Path(directory) / 'command')
            code, _ = recorder.command('missing', ['/definitely/not/a/tool'])
            self.assertIsNone(code); self.assertIn('No such file', (recorder.root / 'missing.stderr').read_text())
            with patch.object(capacity, 'probe', side_effect=ValueError('probe-broken')):
                code, record = capacity.execute(Path(directory) / 'probe')
            self.assertEqual(code, 1); self.assertIn('probe-broken', record['error'])
            self.assertFalse(record['reference_accepted'])

    def test_public_summary_strips_worker_tokens_and_environment_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = capacity.Recorder(Path(directory) / 'attempt')
            base = recorder.root / 'control/jobs/job/attempt-1.worker'; base.mkdir(parents=True)
            (base / 'stopped-inspect.json').write_text(json.dumps({'Image': 'sha256:image',
                'Config': {'Env': ['SECRET=private'], 'Labels': {'token': 'private'}},
                'State': {'OOMKilled': True, 'ExitCode': 137}, 'HostConfig': {'Memory': 268435456}}))
            (base / 'failure.json').write_text(json.dumps({'token': 'private', 'compute_returncode': -9, 'failure_category': 'calculation_exit'}))
            summary = capacity.public_summary(recorder.root)
            self.assertNotIn('SECRET=', json.dumps(summary)); self.assertNotIn('"token"', json.dumps(summary))
            self.assertEqual(summary['worker_attempts'][0]['state']['OOMKilled'], True)

    def case(self, root, records=100):
        (root / 'network.pcap').write_bytes(b'raw-pcap-placeholder')
        (root / 'process.csv').write_text('time,pump\n' + '2026-01-01T00:00:00Z,1\n' * records)
        (root / 'profile.json').write_text('{}')
        value = {'schema_version': 'r19-capacity-case-1', 'id': 'S-offline-1', 'scale': 'S',
                 'mode': 'dual_source', 'networks': ['network.pcap'], 'process': 'process.csv',
                 'profile': 'profile.json', 'repetition': 1, 'cache_condition': 'unverified_cold'}
        path = root / 'case.json'; path.write_text(json.dumps(value)); return path, value

    def test_case_counts_logical_csv_records_and_fingerprints_originals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path, _ = self.case(root)
            # Quoted embedded newline is one logical row, not two physical lines.
            (root / 'process.csv').write_text('time,pump\n' + '2026-01-01T00:00:00Z,"one\ntwo"\n' * 100)
            case = capacity.read_case(path)
            self.assertEqual(case['input_logical_records'], 100)
            self.assertEqual(len(case['input_fingerprints']), 3)
            self.assertTrue(all(len(row['sha256']) == 64 for row in case['input_fingerprints']))

    def test_case_rejects_old_jsonl_and_false_density_or_cold_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path, value = self.case(root, records=1)
            with self.assertRaisesRegex(ValueError, 'density'): capacity.read_case(path)
            path, value = self.case(root)
            (root / 'old.jsonl').write_text('{}\n'); value['networks'] = ['old.jsonl']; path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'raw_capture'): capacity.read_case(path)
            path, value = self.case(root); value['cache_condition'] = 'verified_cold'; path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'cold_cache_evidence'): capacity.read_case(path)

    def test_missing_backlog_values_remain_unknown_not_zero(self):
        result = capacity.backlog_measurement({'backlog': {'samples': [{}, {'waiting_operations': 3}]}})
        for field in ('unparsed_records', 'waiting_operations', 'open_window_operations'):
            self.assertIsNone(result['max_' + field])
        empty = capacity.backlog_measurement({})
        self.assertIsNone(empty['max_unparsed_records'])
        valid = capacity.backlog_measurement({'backlog': {'samples': [
            {'unparsed_records': 0, 'waiting_operations': 2, 'open_window_operations': 1},
            {'unparsed_records': 0, 'waiting_operations': 0, 'open_window_operations': 3}]}})
        self.assertEqual(valid['max_unparsed_records'], 0)
        self.assertEqual(valid['max_waiting_operations'], 2)
        self.assertEqual(valid['max_open_window_operations'], 3)

    def test_command_bootstraps_without_pythonpath(self):
        import os
        env = dict(os.environ); env.pop('PYTHONPATH', None)
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/validation/round19_capacity.py'), '--help'], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--dev-run', result.stdout)


if __name__ == '__main__': unittest.main()
