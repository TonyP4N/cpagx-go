import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cpag_core.pipeline import run as run_normalized, fingerprint
from cpag_core.packet_job import run as run_packet
from scripts.validation.round8_compatibility import inspect_history


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tests/packets'))
from test_packet_envelope import pcap
from test_packet_protocol import GET, REPLY, frame


def hashes(paths):
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


class HistoryReadonlyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.network = self.base / 'network.jsonl'
        self.process = self.base / 'process.csv'
        self.profile = self.base / 'profile.json'
        self.network.write_bytes((REPO / 'tests/fixtures/synthetic/network.normalized.jsonl').read_bytes())
        self.process.write_bytes((REPO / 'tests/fixtures/synthetic/process.csv').read_bytes())
        self.profile.write_bytes((REPO / 'profiles/synthetic-demo.json').read_bytes())
        self.artifacts = self.base / 'normalized-output'
        run_normalized(self.network, self.process, self.profile, self.artifacts, synthetic=True)

    def test_normalized_history_is_read_only_and_verified(self):
        paths = [self.network, self.process, self.profile, *self.artifacts.iterdir()]
        before = hashes(paths)
        result = inspect_history('normalized', self.artifacts, self.network, self.process)
        self.assertEqual(result['status'], 'verified_synthetic_format')
        self.assertEqual(result['event_count'], 8)
        self.assertEqual(before, hashes(paths))

    def test_missing_and_unknown_version_rejected_without_rewrite(self):
        target = self.artifacts / 'events.json'
        content = target.read_bytes()
        target.unlink()
        before = hashes([self.network, self.process, *self.artifacts.iterdir()])
        with self.assertRaises(ValueError):
            inspect_history('normalized', self.artifacts, self.network, self.process)
        self.assertEqual(before, hashes([self.network, self.process, *self.artifacts.iterdir()]))
        target.write_bytes(content)
        dataset = self.artifacts / 'dataset.json'
        value = json.loads(dataset.read_text())
        value['schema_version'] = '9.0.0'
        dataset.write_text(json.dumps(value))
        before = hashes([self.network, self.process, *self.artifacts.iterdir()])
        with self.assertRaises(ValueError):
            inspect_history('normalized', self.artifacts, self.network, self.process)
        self.assertEqual(before, hashes([self.network, self.process, *self.artifacts.iterdir()]))

    def test_tampered_artifact_and_symlink_rejected(self):
        graph = self.artifacts / 'graph.json'
        graph.write_bytes(graph.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            inspect_history('normalized', self.artifacts, self.network, self.process)
        graph.unlink()
        graph.symlink_to(self.network)
        with self.assertRaises(ValueError):
            inspect_history('normalized', self.artifacts, self.network, self.process)

    def test_rehashed_valid_but_wrong_node_evidence_rejected(self):
        graph_path = self.artifacts / 'graph.json'
        manifest_path = self.artifacts / 'run_manifest.json'
        graph = json.loads(graph_path.read_text())
        graph['nodes'][0]['evidence_refs'] = graph['nodes'][1]['evidence_refs']
        graph_path.write_text(json.dumps(graph))
        manifest = json.loads(manifest_path.read_text())
        manifest['result_hashes']['graph'] = fingerprint(graph)
        entry = next(item for item in manifest['artifacts'] if item['path'] == 'graph.json')
        entry['sha256'] = hashlib.sha256(graph_path.read_bytes()).hexdigest()
        entry['size_bytes'] = graph_path.stat().st_size
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'history_node_evidence_mismatch'):
            inspect_history('normalized', self.artifacts, self.network, self.process)

    def test_packet_uses_packet_contract_and_preserves_inputs(self):
        capture = self.base / 'synthetic.pcap'
        capture.write_bytes(pcap(list(enumerate([
            frame(GET[20:], 120), frame(GET[:20]), frame(GET[:20]), frame(REPLY, reverse=True)
        ], 1))))
        placeholder = self.base / 'unused.txt'
        placeholder.write_text('compatibility placeholder; unused')
        profile = self.base / 'packet-profile.json'
        profile.write_text(json.dumps({'synthetic': True, 'adapter': 'synthetic-packet-1'}))
        output = self.base / 'packet-output'
        run_packet(capture, placeholder, profile, output, synthetic=True)
        paths = [capture, placeholder, profile, *output.iterdir()]
        before = hashes(paths)
        result = inspect_history('packet', output, capture, placeholder)
        self.assertEqual(result['event_count'], 2)
        self.assertEqual(before, hashes(paths))
        placeholder.write_text('changed')
        with self.assertRaises(ValueError):
            inspect_history('packet', output, capture, placeholder)

    def test_cli_missing_artifact_rejected_with_nonzero_exit(self):
        (self.artifacts / 'quality.json').unlink()
        env = dict(os.environ, PYTHONPATH=str(REPO / 'services/analysis/src'))
        result = subprocess.run([sys.executable, 'scripts/validation/round8_compatibility.py',
                                 '--kind', 'normalized', '--artifacts', str(self.artifacts),
                                 '--network', str(self.network), '--process', str(self.process)],
                                cwd=REPO, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'rejected')


if __name__ == '__main__':
    unittest.main()
