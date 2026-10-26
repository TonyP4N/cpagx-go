import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('scaling',ROOT/'scripts/benchmarks/synthetic_scaling.py')
scaling=importlib.util.module_from_spec(spec);spec.loader.exec_module(scaling)


class ScalingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.budget={**json.loads(scaling.BUDGET.read_text()),'sizes':[100]}
        cls.rows=[]
        for phase in ('parse','pipeline'):
            result=scaling.sample(phase,100)
            cls.rows += [{**copy.deepcopy(result),'iteration':i} for i in range(1,4)]

    def test_all_samples_summary_and_rss_units(self):
        summary=scaling.summarize(self.rows,self.budget)
        self.assertEqual(len(summary),2)
        self.assertEqual(scaling.rss_bytes(1024,'Linux'),1048576)
        self.assertEqual(scaling.rss_bytes(1024,'Darwin'),1024)
        with self.assertRaises(ValueError): scaling.rss_bytes(1024,'Unknown')

    def test_missing_duplicate_and_unverified_samples(self):
        variants=[copy.deepcopy(self.rows[:-1]),copy.deepcopy(self.rows)]
        variants[1][-1]['iteration']=1
        for rows in variants:
            with self.assertRaises(ValueError): scaling.summarize(rows,self.budget)
        rows=copy.deepcopy(self.rows);rows[-1]['verified_event_references']=0
        with self.assertRaises(ValueError): scaling.summarize(rows,self.budget)

    def test_measurement_and_budget_failures(self):
        for key,value in [('peak_rss_bytes',536870913),('peak_rss_bytes',0),
                          ('elapsed_seconds',61),('elapsed_seconds',float('nan')),
                          ('events_per_second',float('inf')),('events',301),('bytes_per_second',1)]:
            rows=copy.deepcopy(self.rows);rows[0][key]=value
            with self.subTest(key=key,value=value):
                with self.assertRaises(ValueError): scaling.summarize(rows,self.budget)

    def test_changed_results_rejected(self):
        for key in ('input_fingerprint','config_fingerprint','artifact_hashes','result_hashes'):
            rows=copy.deepcopy(self.rows);rows[-1][key]='changed'
            with self.subTest(key=key):
                with self.assertRaises(ValueError): scaling.summarize(rows,self.budget)

    def test_cross_phase_input_mismatch_rejected(self):
        rows=copy.deepcopy(self.rows)
        for row in rows[3:]:row['input_fingerprint']='different'
        with self.assertRaisesRegex(ValueError,'cross_phase'):scaling.summarize(rows,self.budget)

    def test_actual_child_failure_timeout_and_missing_measurement(self):
        for program,timeout,reason in [('raise SystemExit(7)',2,'sample_exit_7'),
                                       ('import time;time.sleep(5)',.1,'sample_timeout'),
                                       ('print("not json")',2,'invalid_measurement'),
                                       ('print("NaN")',2,'invalid_measurement'),
                                       ('print("[]")',2,'invalid_measurement')]:
            with self.subTest(program=program):
                with self.assertRaisesRegex(ValueError,reason):scaling.execute([sys.executable,'-c',program],timeout)

    def test_tampered_publication_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p=scaling.generate(base,100)
            m=scaling.run(n,p,scaling.PROFILE,base/'out',synthetic=True)
            (base/'out/graph.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'checksum'):
                scaling.verify_publication(base/'out',(n,p),100,m)

    def test_three_different_measurements_use_all_samples(self):
        rows=copy.deepcopy(self.rows)
        for row in rows:
            row['elapsed_seconds']=row['iteration']
            row['bytes_per_second']=row['input_bytes']/row['elapsed_seconds']
            row['events_per_second']=row['events']/row['elapsed_seconds']
        stats=scaling.summarize(rows,self.budget)[0]['statistics']['elapsed_seconds']
        self.assertEqual(stats,{'min':1,'median':2,'max':3})

if __name__=='__main__':unittest.main()
