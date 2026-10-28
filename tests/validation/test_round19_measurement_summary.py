import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from round19_measurement_summary import summarize, SEMANTIC_FILES
from cpag_core.pipeline import file_hash

class SummaryTests(unittest.TestCase):
    def case(self,root,number,*,failed=False,image='fixed',state='unknown'):
        path=root/str(number);path.mkdir();job='run-'+str(number)
        record={'status':'failed' if failed else 'development_case_measured_incomplete_gate',
            'failures':[{'error':'OOM'}] if failed else [],'run_id':job,
            'environment':{'commit':'fixed','source_tree_sha256':'fixed'},'resource_profile':'fixed',
            'terminal':{'state':'failed' if failed else 'succeeded','attempt':1},
            'case':{'input_fingerprints':[{'sha256':'input','bytes':10}]}}
        (path/'record.json').write_text(json.dumps(record))
        (path/'public-summary.json').write_text(json.dumps({'worker_attempts':[{'image_id':image,'state':{'ExitCode':137,'Status':'exited','OOMKilled':failed},'compute_measurements':{'returncode':-9 if failed else 0}}]}))
        receipt=path/'control/jobs'/job/'attempt-1.worker';receipt.mkdir(parents=True)
        (receipt/'exit.json').write_text(json.dumps({'exited':True,'removed':True,'pid':0,'running':False,'scope':'container'}))
        if not failed:
            output=path/'source/jobs'/job/'attempt-1';output.mkdir(parents=True)
            files=[]
            for name in sorted(SEMANTIC_FILES):
                target=output/name;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_text(json.dumps({'run_id':job,'state':state,'evidence':[1,2]}))
                files.append({'path':name,'bytes':target.stat().st_size,'sha256':file_hash(target)})
            record['output']={'files':files};(path/'record.json').write_text(json.dumps(record))
        return path
    def test_three_equal_and_failed_attempt_is_never_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);paths=[self.case(root,i) for i in range(3)]
            value=summarize(paths)
            self.assertTrue(value['three_independent_runs']);self.assertTrue(value['fixed_inputs_code_image_resources'])
            self.assertTrue(value['all_runs_complete']);self.assertTrue(value['semantic_hashes_equal'])
            self.assertFalse(value['reference_accepted'])
            failed=self.case(root,3,failed=True);value=summarize(paths+[failed])
            self.assertFalse(value['all_runs_complete']);self.assertFalse(value['three_independent_runs'])
            self.assertEqual(value['samples'][-1]['failures'],[{'error':'OOM'}])
    def test_missing_or_tampered_retained_file_prevents_completion(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);paths=[self.case(root,i) for i in range(3)]
            target=paths[1]/'source/jobs/run-1/attempt-1/graph.json'
            target.write_text(target.read_text().replace('unknown','changed'))
            self.assertFalse(summarize(paths)['all_runs_complete'])
            target.unlink()
            self.assertFalse(summarize(paths)['all_runs_complete'])

    def test_business_state_and_image_differences_cannot_be_normalized_away(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);paths=[self.case(root,0),self.case(root,1,state='supported_candidate'),self.case(root,2,image='different')]
            value=summarize(paths)
            self.assertFalse(value['semantic_hashes_equal']);self.assertFalse(value['fixed_inputs_code_image_resources'])

if __name__=='__main__':unittest.main()
