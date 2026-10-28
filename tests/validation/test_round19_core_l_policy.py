import copy
from pathlib import Path
import sys
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from round19_core_matrix_l import checked_counts,run
import round19_core_matrix as baseline
from round19_scale_fixture import density_budget_math


class LCoveragePolicyTests(unittest.TestCase):
    def test_private_L_entry_retains_baseline_and_actual_host_policy_bytes(self):
        original=(ROOT/'scripts/validation/round19_core_cell.py').read_bytes();seen=[]
        def fake_native(root,*args,**kwargs):
            record=args[-1];harness=root/'harness'
            self.assertEqual((harness/'round19_core_cell_baseline.py').read_bytes(),original)
            self.assertEqual((harness/'round19_core_cell.py').read_bytes(),(ROOT/'scripts/validation/round19_core_cell_l.py').read_bytes())
            self.assertEqual((harness/'round19_core_matrix_l.py').read_bytes(),(ROOT/'scripts/validation/round19_core_matrix_l.py').read_bytes())
            self.assertEqual(record['frozen_harness_sha256'],{p.name:baseline.sha(p) for p in harness.iterdir()});seen.append(True)
        def fake_run(output,fixture,profile,scale,mode,image,*,scratch_root):
            root=Path(output);(root/'harness').mkdir()
            for name in ('round19_core_matrix.py','round19_core_cell.py','round19_core_oracle.py','round19_core_guards.py'):
                shutil.copyfile(ROOT/'scripts/validation'/name,root/'harness'/name)
            record={};baseline.run_container(root,'export',mode,image,root,None,None,1,record);return record
        with tempfile.TemporaryDirectory() as directory,patch.object(baseline,'run',side_effect=fake_run),patch.object(baseline,'run_container',side_effect=fake_native):
            run(directory,'fixture','profile','offline','immutable','scratch')
        self.assertEqual(seen,[True]);self.assertEqual((ROOT/'scripts/validation/round19_core_cell.py').read_bytes(),original)

    def fixture(self):
        value=density_budget_math('L');counts={'network':20000,'process':9990,'changes':9000,'operations':10000,'candidates':value['candidate_count_lower_bound']}
        coverage={'version':'core-ever-observed-coverage-1','status':'passed','raw_original_units':30001,'admitted_units':30001,
            'csv_headers_admitted_not_observations':1,'ever_observed_data_units':30000,'actual_history_events_proven':30000,
            'missing_or_extra_units':0,'expired_units':10,'raw_file_sha256':{'network-0':'networkhash','process':'processhash'}}
        record={'fixed_inputs':{'network.pcap':{'sha256':'networkhash'},'process.csv':{'sha256':'processhash'}},
            'phases':[{'result':{'metadata':{'independent_ever_observed_coverage':coverage}}}]}
        return counts,record
    def test_final_reduced_live_view_requires_complete_real_coverage(self):
        counts,record=self.fixture();result=checked_counts(counts,'L','replay',record)
        self.assertEqual(result['all_data_units_actually_observed_in_history'],30000)
        for change in (lambda c:c.update(status='failed'),lambda c:c.update(admitted_units=30000),
                lambda c:c.update(actual_history_events_proven=29999),lambda c:c.update(missing_or_extra_units=1),
                lambda c:c['raw_file_sha256'].update(process='wrong')):
            invalid=copy.deepcopy(record);change(invalid['phases'][-1]['result']['metadata']['independent_ever_observed_coverage'])
            with self.assertRaises(ValueError):checked_counts(counts,'L','replay',invalid)
    def test_no_expiry_and_offline_keep_original_strict_counts(self):
        counts,record=self.fixture();record['phases'][0]['result']['metadata']['independent_ever_observed_coverage']['expired_units']=0
        with self.assertRaises(ValueError):checked_counts(counts,'L','replay',record)
        with self.assertRaises(ValueError):checked_counts(counts,'L','offline',record)
        counts.update(process=10000,changes=9999)
        checked_counts(counts,'L','offline',record)
        with self.assertRaises(ValueError):checked_counts(counts,'M','offline',record)
    def test_operation_and_candidate_independent_bounds_are_not_relaxed(self):
        counts,record=self.fixture()
        for key,value in [('operations',9999),('candidates',0),('network',20001),('process',True)]:
            invalid=dict(counts);invalid[key]=value
            with self.assertRaises(ValueError):checked_counts(invalid,'L','replay',record)


if __name__=='__main__':unittest.main()
