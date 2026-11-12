import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'services/worker'))
from cpag_worker.resident_generation import ComposeGeneration
from cpag_worker.resident_service import ResidentWorker, read_config
from cpag_worker.isolated import atomic_json


class ComposeGenerationTests(unittest.TestCase):
    def test_requires_linux_root_pid1(self):
        with tempfile.TemporaryDirectory() as root, patch('cpag_worker.resident_generation.os.getpid', return_value=10):
            with self.assertRaises(ValueError): ComposeGeneration(root, 'a'*32, 'worker-01')

    def test_immutable_lock_and_no_descriptor_in_exec_child(self):
        with tempfile.TemporaryDirectory() as root:
            original = Path.lstat
            def root_stat(path, *args, **kwargs):
                value = original(path, *args, **kwargs)
                if path in (Path(root), Path(root)/'resident-generations'):
                    fields = list(value); fields[4] = 0
                    return os.stat_result(fields)
                return value
            with patch('cpag_worker.resident_generation.sys.platform', 'linux'), patch('cpag_worker.resident_generation.os.geteuid', return_value=0), patch('cpag_worker.resident_generation.os.getpid', return_value=1), patch.object(Path, 'lstat', root_stat):
                generation = ComposeGeneration(root, 'a'*32, 'worker-01')
            self.addCleanup(os.close, generation.fd)
            self.assertFalse(os.get_inheritable(generation.fd))
            identity = generation.identity
            path = Path(root)/'resident-generations'/(identity['generation']+'.lock')
            self.assertEqual(json.loads(path.read_text())['pid'], 1)
            self.assertEqual(json.loads((Path(root)/'resident-current.json').read_text())['generation'], identity['generation'])
            with path.open('r') as probe:
                with self.assertRaises(BlockingIOError): fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Exec children cannot retain the generation lock after PID1 exits.
            script = 'import os,sys;\ntry: os.fstat(int(sys.argv[1]))\nexcept OSError: print("closed")\nelse: raise SystemExit("generation descriptor inherited")'
            result = subprocess.check_output([sys.executable, '-c', script, str(generation.fd)], close_fds=True, text=True)
            self.assertEqual(result.strip(), 'closed')
            self.assertFalse(hasattr(generation, 'close'))

    def test_compose_configuration_and_identity_need_no_kubernetes(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            config = {'api_url': 'http://cpag-resident-internal:8096', 'worker_token': 'w'*32, 'coordinator_token': 'c'*32,
                      'worker_id': 'worker-01', 'resource_profile': 'storage-budget-2', 'shared_root': str(base/'shared'),
                      'control_root': str(base/'control'), 'runtime_backend': 'compose-pid1-v1', 'deployment_id': 'a'*32}
            for name in ('shared', 'control', 'work'): (base/name).mkdir(mode=0o700)
            path=base/'config.json';atomic_json(path,config);self.assertEqual(read_config(path),config)
            identity={'version':'resident-registration-1','backend':'compose-pid1-v1','deployment_id':'a'*32,
                      'generation':'b'*32,'supervisor_id':'worker-01','container_id':'pid1://'+'b'*32}
            with patch.dict(os.environ, {}, clear=True):
                worker=ResidentWorker(config,base/'work',resident=identity)
                self.assertEqual(worker.location,'resident-compose:'+'a'*32)
            atomic_json(path,{**config,'deployment_id':'fake-kube-uid'})
            with self.assertRaises(ValueError):read_config(path)
