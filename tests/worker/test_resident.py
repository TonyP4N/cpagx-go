"""Resident wire, crash fencing and guardian fail-closed regression checks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'services/worker'))
from cpag_worker.resident_service import ResidentWorker, read_config, registration
from cpag_worker.isolated import atomic_json
from test_kubernetes import claim


class ResidentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = {'api_url': 'http://cpag-resident-internal:8096', 'worker_token': 'w'*32,
                       'coordinator_token': 'c'*32, 'worker_id': 'worker-01', 'resource_profile': 'storage-budget-2',
                       'shared_root': str(self.base/'shared'), 'control_root': str(self.base/'control')}
        for name in ('shared', 'control', 'work'): (self.base/name).mkdir()
        self.env = patch.dict(os.environ, {'CPAG_NAMESPACE_UID': 'namespace-uid'}); self.env.start(); self.addCleanup(self.env.stop)
        self.reg = {'version': 'resident-registration-1', 'namespace': 'cpag', 'pod_name': 'resident-abc',
                    'pod_uid': 'pod-uid', 'container_name': 'worker', 'container_id': 'containerd://'+'a'*64}
        self.worker = ResidentWorker(self.config, self.base/'work', self.reg)

    def test_private_config_and_profile(self):
        path = self.base/'config.json'; atomic_json(path, self.config)
        self.assertEqual(read_config(path)['worker_id'], 'worker-01')
        path.chmod(0o644)
        with self.assertRaises(ValueError): read_config(path)
        path.chmod(0o600)
        for key, value in [('api_url', 'http://example.com'), ('resource_profile', 'engineering-capacity-1')]:
            atomic_json(path, {**self.config, key: value})
            with self.assertRaises(ValueError): read_config(path)

    def test_claim_execution_type_and_registration_before_staging(self):
        calls = []
        def post(path, body):
            calls.append((path, body))
            return claim() if path == '/v1/claim' else {}
        self.worker.api.post = post; self.worker.coord.post = post
        self.worker.helper.keep_lease = lambda c, done, health: done.wait()
        self.worker.helper.capacity = lambda c: None
        with patch.object(self.worker, 'stage', side_effect=ValueError('staging rejected')):
            with self.assertRaises(ValueError): self.worker.once()
        self.assertEqual(calls[0][1]['execution_type'], 'resident-v1')
        self.assertTrue(calls[1][0].endswith('/execution'))
        self.assertEqual(calls[1][1]['resident'], self.reg)
        self.assertTrue(self.worker.journal.exists())

    def test_ambiguous_journal_never_relaunches(self):
        atomic_json(self.worker.journal, {'claim': claim(), 'execution': {}})
        self.worker.helper.get_json = lambda *a: {'attempt': 1, 'state': 'cancelling'}
        with patch.object(self.worker.api, 'post', side_effect=AssertionError('must not claim')):
            self.assertEqual(self.worker.once(), 'recovery_wait')
        self.assertTrue(self.worker.journal.exists())

    def test_recovered_terminal_attempt_allows_next_claim(self):
        c = claim(); target = self.worker.control/'jobs'/c['id']/'attempt-1.worker'; target.mkdir(parents=True)
        atomic_json(self.worker.journal, {'claim': c, 'execution': {}})
        self.worker.helper.get_json = lambda *a: {'attempt': 1, 'state': 'cancelled'}
        self.worker.helper.capacity = lambda *a, **kw: None
        self.worker.api.post = lambda *a: None
        self.assertEqual(self.worker.once(), 'idle')
        self.assertFalse(self.worker.journal.exists())
        self.assertTrue((target/'resident-recovered.json').exists())

    def test_guardian_writes_final_receipt_after_group_exit(self):
        import time
        config = {'command': [sys.executable, '-c', 'pass'], 'env': dict(os.environ),
                  'identity': {k: claim()[k] for k in ('id', 'attempt', 'worker', 'token')},
                  'resident_receipt': self.reg, 'location': self.worker.location,
                  'pid_file': str(self.base/'child.pid'), 'exit_file': str(self.base/'exit.json'),
                  'stdout': str(self.base/'stdout'), 'stderr': str(self.base/'stderr'),
                  'timeout': 5, 'kill_grace': .2, 'cpu_seconds': 5, 'memory_bytes': 1024**3,
                  'file_bytes': 1024**2, 'log_bytes': 1024}
        atomic_json(self.base/'guardian.json', config)
        env = {**os.environ, 'PYTHONPATH': str(ROOT/'services/worker')}
        child = subprocess.Popen([sys.executable, '-m', 'cpag_worker.guardian', str(self.base/'guardian.json')], stdin=subprocess.PIPE, env=env)
        try:
            self.assertEqual(child.wait(timeout=10), 0)
            proof = json.loads((self.base/'exit.json').read_text())
            self.assertEqual(proof['resident']['reason'], 'exited')
            self.assertTrue(proof['resident']['group_exited'])
            self.assertEqual(proof['resident']['returncode'], 0)
            self.assertEqual(proof['scope'], 'resident-process-group')
            self.assertEqual(proof['container_id'], self.reg['container_id'])
        finally:
            child.stdin.close()
            if child.poll() is None: child.kill(); child.wait()

    def test_sandbox_fails_closed_outside_linux_root(self):
        from cpag_worker.resident_sandbox import enter
        with patch('cpag_worker.resident_sandbox.os.getuid', return_value=1000):
            with self.assertRaises(RuntimeError): enter({'cwd': '/'})

    def test_staged_command_and_environment_exclude_authority(self):
        c = claim(); payload = c['payload']
        import hashlib
        for key, name, content in [('network', 'a.pcap', b'capture'), ('process', 'p.csv', b'process'),
                                   ('profile', 'c.json', json.dumps({k: payload[k] for k in ('capacity_profile', 'storage_format', 'storage_budget_version')}).encode())]:
            path = self.worker.root/'inputs'/name; path.parent.mkdir(exist_ok=True); path.write_bytes(content)
            payload[key] = {'path': 'inputs/'+name, 'sha256': hashlib.sha256(content).hexdigest()}
        base = self.worker.control/'attempt'; base.mkdir()
        with patch('cpag_worker.resident_service.os.chown'), patch.dict(os.environ, {'CPAG_WORKER_TOKEN': 'secret', 'AWS_SECRET_ACCESS_KEY': 'secret'}):
            work = self.worker.stage(c, base)
        config = json.loads((base/'guardian.json').read_text())
        self.assertEqual(config['command'][:4], [sys.executable, '-m', 'cpag_core.shared_cli', '--action'])
        self.assertIn(str(work/'output/run'), config['command'])
        self.assertNotIn('secret', json.dumps(config['env']))
        self.assertEqual(config['resident_sandbox']['cwd'], str(work))
        self.assertEqual((base/'guardian.json').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
