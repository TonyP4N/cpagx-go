"""Evidence refusal tests never stand in for actual formal fault execution."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/validation'))
import round19_short_formal_faults as probe


def event(identifier, action, stamp, *, worker=None, verifier=False):
    labels = {'cpag.job': 'test-job', 'cpag.attempt': '1'}
    if verifier: labels['cpag.role'] = 'dag6-source-verifier'
    else: labels['cpag.worker'] = worker
    return {'Action': action, 'timeNano': stamp, 'Actor': {'ID': identifier, 'Attributes': labels}}


class ShortFormalFaultEvidenceTests(unittest.TestCase):
    def test_actual_global_gate_includes_compute_and_verifier_across_both_workers(self):
        rows = [event('a', 'start', 10, worker='short-A'), event('a', 'die', 20, worker='short-A'),
                event('b', 'start', 20, worker='short-B'), event('b', 'die', 30, worker='short-B'),
                event('v', 'start', 30, verifier=True), event('v', 'die', 40, verifier=True)]
        self.assertEqual([row['role'] for row in probe.lifecycle(rows, {'a','b','v'})], ['compute','compute','verifier'])
        broken = deepcopy(rows); broken[4]['timeNano'] = 29
        with self.assertRaisesRegex(ValueError, 'overlap'): probe.lifecycle(broken, {'a','b','v'})
        with self.assertRaisesRegex(ValueError, 'inventory'): probe.lifecycle(rows, {'a','b','v','unobserved'})
        with self.assertRaisesRegex(ValueError, 'incomplete'): probe.lifecycle(rows[:-1], {'a','b','v'})
        with self.assertRaisesRegex(ValueError, 'duplicate'): probe.lifecycle(rows+[rows[0]], {'a','b','v'})
        broken = deepcopy(rows); broken[2]['Actor']['Attributes']['cpag.worker'] = 'short-A'; broken[3]['Actor']['Attributes']['cpag.worker'] = 'short-A'
        with self.assertRaisesRegex(ValueError, 'two_real'): probe.lifecycle(broken, {'a','b','v'})

    def test_command_failures_retain_actual_output(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = probe.Harness(SimpleNamespace(output=Path(directory), mode='small', image='sha256:'+'a'*64, seconds=60))
            failed = subprocess.CompletedProcess(['docker'], 125, b'original stdout', b'original failure')
            with patch.object(probe.subprocess, 'run', return_value=failed), self.assertRaisesRegex(RuntimeError, 'failed_125'):
                harness.command('fault-first', ['docker','unused'])
            self.assertEqual((Path(directory)/'0001-fault-first.stdout').read_bytes(), failed.stdout)
            self.assertEqual((Path(directory)/'0001-fault-first.stderr').read_bytes(), failed.stderr)

    def test_hold_normalizes_docker_short_id_to_inspected_full_identity(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            harness = probe.Harness(SimpleNamespace(output=Path(directory), mode='small', image='sha256:'+'a'*64, seconds=60))
            full = 'c'*64
            inspection = {'Id': full, 'Image': harness.args.image, 'HostConfig': {
                'Memory': 8*1024**3, 'NanoCpus': 4*10**9, 'ReadonlyRootfs': True}}
            def command(label, args, **kwargs):
                output = (b'123 1 python -m cpag_core.shared_cli --action export\n' if label == 'live-top-compute'
                          else json.dumps([inspection]).encode() if label == 'inspect-compute' else b'')
                return subprocess.CompletedProcess(args, 0, output, b'')
            with patch.object(harness, 'containers', return_value=[full[:12]]), patch.object(harness, 'command', side_effect=command):
                identifier, _ = harness.hold('job', 'compute')
            self.assertEqual(identifier, full)
            self.assertEqual(harness.expected_containers, {full})
            self.assertEqual(harness.paused_containers, {full})


if __name__ == '__main__':
    unittest.main()
