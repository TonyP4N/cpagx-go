"""The supplement's independent oracle rejects the reproduced false support."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/validation'),str(ROOT/'services/analysis/src')]
from round17_response_acceptance import check_boundary, VERSION


class ResponseAcceptanceOracleTests(unittest.TestCase):
    def reference(self):
        operation={'operation_id':'request','response':{'state':'success','general_status':0,
            'time':{'interval':None,'unknown_reasons':['clock_validity_outside']}},
            'time':{'interval':[10,10]},'assessment':'unknown',
            'unknown_reasons':['response_clock_validity_outside'],'candidates':[],'support':[]}
        analysis={'analysis_version':VERSION,'synthetic':True,
            'network':[{'event':{'event_id':'request'}},{'event':{'event_id':'response'}}],
            'process':[{} for _ in range(5)],'changes':[{'event_id':'change'}],
            'candidates':[],'operations':[operation],
            'quality':{'unknown_reasons':[],'operation_time_issues':[{'operation_id':'request','reasons':['response_clock_validity_outside']}]}}
        graph={'edges':[],'claims':[],'nodes':[{'event_id':value} for value in ('request','response','change')]}
        return analysis,graph

    def test_expected_unknown_preserves_protocol_success_and_observations(self):
        analysis,graph=self.reference()
        self.assertEqual(check_boundary(analysis,graph)['assessment'],'unknown')

    def test_reproduced_false_candidate_and_rendered_edge_are_rejected(self):
        for mutation in ('candidate','assessment','edge','missing_response','missing_change','missing_reason','wrong_version','missing_quality','global_quality_leak'):
            analysis,graph=self.reference()
            if mutation=='candidate':analysis['candidates']=[{'state':'supported_candidate'}]
            elif mutation=='assessment':analysis['operations'][0]['assessment']='expected_change_observed'
            elif mutation=='edge':graph['edges']=[{'source':'request','target':'change'}]
            elif mutation=='missing_response':analysis['network'].pop()
            elif mutation=='missing_change':analysis['changes']=[]
            elif mutation=='missing_reason':analysis['operations'][0]['unknown_reasons']=[]
            elif mutation=='wrong_version':analysis['analysis_version']='bounded-dual-source-1'
            elif mutation=='missing_quality':analysis['quality']['operation_time_issues']=[]
            else:analysis['quality']['unknown_reasons']=['response_clock_validity_outside']
            with self.subTest(mutation=mutation),self.assertRaises(AssertionError):
                check_boundary(analysis,graph)

    def test_transport_success_cannot_be_reclassified_as_protocol_failure(self):
        analysis,graph=self.reference()
        analysis['operations'][0]['response']['state']='error'
        with self.assertRaises(AssertionError):check_boundary(analysis,graph)


if __name__=='__main__':unittest.main()
