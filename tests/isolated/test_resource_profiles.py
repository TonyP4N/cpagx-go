from pathlib import Path
import tempfile
import unittest
from cpag_worker.isolated import DockerExecutor
from cpag_worker.resources import resolve

class ResourceProfileTests(unittest.TestCase):
    def test_default_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            w=DockerExecutor(None,None,Path(tmp)/'s',Path(tmp)/'c','test')
            self.assertEqual((w.memory_bytes,w.cpus,w.timeout,w.output_bytes),(268435456,'.5',120,16777216))
    def test_operator_named_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            w=DockerExecutor(None,None,Path(tmp)/'s',Path(tmp)/'c','test',resource_profile='r19-dev-s100-1')
            self.assertEqual((w.memory_bytes,w.cpus,w.timeout,w.output_bytes),(2*1024**3,'2',900,512*1024**2))
            self.assertEqual(w.resource_profile,'r19-dev-s100-1')
    def test_unknown_or_mutated_definition_cannot_raise_budget(self):
        for name in ('',{},'unlimited'):
            with self.assertRaises(ValueError):resolve(name)
        value=resolve('r19-dev-s100-1');value['memory_bytes']=1
        self.assertEqual(resolve('r19-dev-s100-1')['memory_bytes'],2*1024**3)
