import json
from pathlib import Path
import tempfile
import unittest
from cpag_core.evaluation_analysis import analyze

REPO=Path(__file__).resolve().parents[2]
class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.root=self.base/'data'
        for d in ('raw','profiles','annotations'):(self.root/d).mkdir(parents=True)
        for src,dst in [('tests/fixtures/synthetic/network.normalized.jsonl','raw/network.jsonl'),('tests/fixtures/synthetic/process.csv','raw/process.csv'),('profiles/synthetic-demo.json','profiles/profile.json')]:
            (self.root/dst).write_bytes((REPO/src).read_bytes())
    def run_analysis(self,name='out'):
        return analyze(self.root,'raw/network.jsonl','raw/process.csv','profiles/profile.json',self.base/name)
    def test_labels_mutation_does_not_change_analysis(self):
        (self.root/'annotations/test.json').write_text('{"attack":true}')
        a=self.run_analysis('a')
        (self.root/'annotations/test.json').write_text('{"attack":false,"labels":[100]}')
        b=self.run_analysis('b')
        self.assertEqual(a,b)
    def test_labels_path_traversal_symlink_and_hardlink_rejected(self):
        import os
        label=self.root/'annotations/test.json';label.write_text('{}')
        for name in ('annotations/test.json','raw/../annotations/test.json',str(label)):
            with self.subTest(name=name),self.assertRaises(ValueError):analyze(self.root,name,'raw/process.csv','profiles/profile.json',self.base/'no')
        link=self.root/'raw/labels.jsonl';link.symlink_to(label)
        with self.assertRaises(ValueError):analyze(self.root,'raw/labels.jsonl','raw/process.csv','profiles/profile.json',self.base/'no')
        link.unlink();os.link(label,link)
        with self.assertRaises(ValueError):analyze(self.root,'raw/labels.jsonl','raw/process.csv','profiles/profile.json',self.base/'no')
    def test_labels_disguised_as_data_and_config_rejected(self):
        network=self.root/'raw/network.jsonl';original=network.read_text();network.write_text('{"ground_truth":true}\n')
        with self.assertRaises(ValueError):self.run_analysis()
        network.write_text(original)
        process=self.root/'raw/process.csv';process.write_text('time,label\n2026-01-01T00:00:00Z,attack\n')
        with self.assertRaises(ValueError):self.run_analysis()
    def test_output_cannot_overwrite_inputs_or_old_run(self):
        with self.assertRaises(ValueError):analyze(self.root,'raw/network.jsonl','raw/process.csv','profiles/profile.json',self.root/'new')
        self.run_analysis()
        with self.assertRaises(ValueError):self.run_analysis()
