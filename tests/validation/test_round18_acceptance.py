"""Independent acceptance-oracle controls: future references and false support."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/validation'),str(ROOT/'services/analysis/src')]
from round18_acceptance import check_prefix, history_answers, check_metrics


def ref(slot):return {'source_slot':slot,'record_sha256':'a'*64,'frame_number':1,'record_number':None,'column':None,'raw_time':'10000000'}


class ReplayAcceptanceOracleTests(unittest.TestCase):
    def test_lifecycle_command_bootstraps_without_inherited_pythonpath(self):
        import os
        import subprocess
        env=dict(os.environ);env.pop('PYTHONPATH',None)
        result=subprocess.run([sys.executable,str(ROOT/'scripts/validation/round18_lifecycle.py'),'--help'],
            cwd=ROOT,env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('--output',result.stdout)


    def test_future_record_and_full_file_identity_cannot_enter_prefix(self):
        profile={'replay':{'sequence':[{'source_slot':'network-0','record_number':1,'available_at':'2026-01-01T00:00:10Z'},
            {'source_slot':'network-1','record_number':1,'available_at':'2026-01-01T00:00:11Z'}]}}
        row={'snapshot_number':3,'arrival_seq':1,'available_at':'2026-01-01T00:00:10Z','analysis':{'refs':[ref('network-0')]}}
        check_prefix(row,profile)
        bad=deepcopy(row);bad['analysis']['refs'].append(ref('network-1'))
        with self.assertRaises(AssertionError):check_prefix(bad,profile)
        bad=deepcopy(row);bad['analysis']['file_sha256']='b'*64
        with self.assertRaises(AssertionError):check_prefix(bad,profile)

    def fixture(self,unknown=False):
        operation={'operation_id':'op','replay':{'status':'pending_response','closed':False},
                   'assessment':'unknown','response':{'state':'missing'},'unknown_reasons':[]}
        pending={'snapshot_number':3,'available_at':'2026-01-01T00:00:10Z','analysis':{'network':[{}],
            'process':[{}],'changes':[],'operations':[operation],'candidates':[]},'graph':{'edges':[]}}
        revised=deepcopy(pending);revised.update(snapshot_number=6,available_at='2026-01-01T00:00:12Z')
        analysis=revised['analysis'];analysis['network']=[{},{}];analysis['changes']=[{'event_id':'change'}]
        op=analysis['operations'][0];op['response']['state']='success'
        if unknown:
            op['replay']['status']='unknown';op['unknown_reasons']=['response_clock_validity_outside']
        else:
            op['replay']['status']='normal';op['assessment']='expected_change_observed'
            analysis['candidates']=[{'state':'supported_candidate','claim':{'status':'hypothetical'}}]
            revised['graph']['edges']=[{}]
        final=deepcopy(revised);final.update(snapshot_number=15,available_at='2026-01-01T00:00:18Z')
        final['analysis']['process']=[{} for _ in range(5)]
        final['analysis']['operations'][0]['replay'].update(status='closed',closed=True)
        return [pending,revised,final]

    def test_normal_and_unknown_independent_answers(self):
        for unknown in (False,True):
            result=history_answers(self.fixture(unknown),'response_expired' if unknown else 'normal')
            self.assertEqual((result['pending'],result['revised'],result['final']),(3,6,15))

    def test_open_window_backlog_is_distinct_from_missing_prerequisites(self):
        metrics={'event_latency':{'denominator_total_events':7,'denominator_computable_events':7},
            'confirmation_latency':{'denominator_candidates':1,'samples':[{'latency_seconds':[2.0,2.0]}]},
            'backlog':{'samples':[{'available_at':'2026-01-01T00:00:12Z','waiting_operations':0,'prerequisite_waiting_operations':0,'open_window_operations':1},
                                  {'available_at':'2026-01-01T00:00:18Z','waiting_operations':0,'prerequisite_waiting_operations':0,'open_window_operations':0}]}}
        check_metrics(metrics,'normal')
        broken=deepcopy(metrics);broken['backlog']['samples'][0]['open_window_operations']=0
        with self.assertRaises(AssertionError):check_metrics(broken,'normal')

    def test_early_response_and_expired_supported_candidate_are_rejected(self):
        normal=self.fixture();normal[0]['analysis']['network'].append({})
        with self.assertRaises(AssertionError):history_answers(normal,'normal')
        expired=self.fixture(True)
        expired[1]['analysis']['candidates']=[{'state':'supported_candidate'}]
        with self.assertRaises(AssertionError):history_answers(expired,'response_expired')


if __name__=='__main__':unittest.main()
