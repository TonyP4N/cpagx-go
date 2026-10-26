import copy
import importlib.util
import json
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[2]/'scripts/m4/linux-isolation/evidence.py'
spec = importlib.util.spec_from_file_location('isolation_evidence', MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProbeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.value = {'probe_result': True, 'worker_result':'failed', 'elapsed_seconds':2.2,
                      'startup': {'child':8, 'guardian':7, 'worker':2, 'escaped':9},
                      'receipt': {'id':'probe','attempt':1,'worker':'linux-probe','token':'synthetic',
                                  'reason':'timeout','group_exited':True,'returncode':-15,
                                  'child_pid':8,'guardian_pid':7}}
        self.record = {'exit':0,'state':{'Running':False,'Pid':0,'OOMKilled':False,'ExitCode':0}}

    def check(self, value=None, record=None, require_startup=True):
        record = copy.deepcopy(record or self.record)
        record['logs'] = json.dumps(value or self.value)
        return module.timeout_proof(record, require_startup=require_startup)

    def test_valid_after_exit(self):
        self.assertEqual(self.check()['receipt']['child_pid'],8)

    def test_timeout_before_ready_is_explicit(self):
        self.value['startup'] = None
        self.assertIsNone(self.check(require_startup=False)['startup'])
        with self.assertRaises(AssertionError): self.check()

    def test_wrong_or_missing_proof_rejected(self):
        mutations = [('receipt',None), ('reason','exited'), ('group_exited',False),
                     ('attempt',2), ('attempt',True), ('group_exited',1), ('id','other'), ('worker','other'), ('token','other'),
                     ('child_pid',0), ('guardian_pid',True), ('returncode',0)]
        for key, value in mutations:
            with self.subTest(key=key):
                changed=copy.deepcopy(self.value)
                if key=='receipt': changed[key]=value
                else: changed['receipt'][key]=value
                with self.assertRaises(AssertionError): self.check(changed)

    def test_startup_identity_mismatch_rejected(self):
        self.value['startup']['child']=99
        with self.assertRaises(AssertionError): self.check()

    def test_ready_not_accepted_as_startup_timeout(self):
        with self.assertRaises(AssertionError): self.check(require_startup=False)

    def test_missing_corrupt_duplicate_logs(self):
        for logs in ('', '{broken', json.dumps(self.value)+'\n'+json.dumps(self.value)):
            with self.subTest(logs=logs):
                with self.assertRaises(AssertionError):
                    module.timeout_proof({**self.record,'logs':logs},require_startup=True)

    def test_still_running_or_oom_is_not_exit_proof(self):
        for key,value in [('Running',True),('Pid',42),('OOMKilled',True),('ExitCode',137)]:
            changed=copy.deepcopy(self.record);changed['state'][key]=value
            with self.subTest(key=key):
                with self.assertRaises(AssertionError): self.check(record=changed)

    def test_container_failure_or_unbounded_elapsed(self):
        changed=copy.deepcopy(self.record);changed['exit']=124
        with self.assertRaises(AssertionError): self.check(record=changed)
        for elapsed in (1,20,100):
            self.value['elapsed_seconds']=elapsed
            with self.assertRaises(AssertionError): self.check()

if __name__ == '__main__': unittest.main()
