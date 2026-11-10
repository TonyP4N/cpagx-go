"""Public CLI behavior only; synthetic engineering verification, not industrial evaluation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class CLITests(unittest.TestCase):
    def command(self, output):
        return [sys.executable, '-m', 'cpag_core', '--network', str(ROOT/'tests/fixtures/synthetic/network.normalized.jsonl'),
                '--process', str(ROOT/'tests/fixtures/synthetic/process.csv'), '--profile', str(ROOT/'profiles/synthetic-demo.json'),
                '--output', str(output), '--synthetic']

    def invoke(self, command):
        env = dict(os.environ, PYTHONPATH=str(ROOT/'services/analysis/src'))
        return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=15)

    def test_cli_export_and_immutable_attempt(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/'run'
            first = self.invoke(self.command(output))
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn('result_hashes', json.loads(first.stdout))
            manifest = (output/'run_manifest.json').read_bytes()
            second = self.invoke(self.command(output))
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(manifest, (output/'run_manifest.json').read_bytes())

    def test_cli_requires_explicit_synthetic_and_valid_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/'run'
            self.assertNotEqual(self.invoke(self.command(output)[:-1]).returncode, 0)
            self.assertFalse(output.exists())
            command = self.command(output)
            command[command.index('--network')+1] = str(Path(temp)/'missing.jsonl')
            self.assertNotEqual(self.invoke(command).returncode, 0)
            self.assertFalse(output.exists())

if __name__ == '__main__':
    unittest.main()
