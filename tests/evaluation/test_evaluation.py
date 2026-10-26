import copy
import json
import unittest
from cpag_core.evaluation import evaluate,validate_splits,digest


def fixture():
    split={'schema_version':'1.0.0','synthetic':True,'rule_windows_seconds':{'synthetic':60},'isolation_seconds':60,'blocks':[
      {'partition':'calibration','batch':'b','start':'2026-01-01T00:00:00Z','end':'2026-01-01T01:00:00Z','sample_sha256':['a'*64],'normal':False},
      {'partition':'holdout','batch':'b','start':'2026-01-01T02:00:00Z','end':'2026-01-01T03:00:00Z','sample_sha256':['b'*64],'normal':False},
      {'partition':'holdout','batch':'b','start':'2026-01-01T03:00:00Z','end':'2026-01-01T04:00:00Z','sample_sha256':['e'*64],'normal':True}]}
    def event(i,t):return {'id':i,'batch':'b','kind':'change','asset':'x','time':'2026-01-01T02:'+t+'Z','sample_sha256':'b'*64}
    pred={'schema_version':'1.0.0','synthetic':True,'run_id':'synthetic-r','input_fingerprint':'c'*64,'config_fingerprint':'d'*64,'events':[event('p1','00:01'),event('p2','10:00')],'unlabelled_relations':['uncertain-edge']}
    pred['events'][1].update(time='2026-01-01T03:10:00Z',sample_sha256='e'*64)
    labels={'schema_version':'1.0.0','synthetic':True,'origin':'independent','source_ref':'synthetic-handwritten-fixture','review_ref':'test-author','annotation_version':'1','events':[event('g1','00:00'),event('g2','20:00')],'disputed_intervals':[]}
    reg={'schema_version':'1.0.0','synthetic':True,'registered_at':'2025-12-01T00:00:00Z','holdout_opened_at':'2026-01-02T00:00:00Z','input_fingerprint':'c'*64,'config_fingerprint':'d'*64,'split_sha256':digest(split),'tolerance_seconds':2,'thresholds':{}}
    return pred,labels,split,reg


class EvaluationTests(unittest.TestCase):
    def test_independent_jsonschema(self):
        from jsonschema import Draft202012Validator, FormatChecker
        from cpag_core.contracts import SCHEMAS
        for name,value in zip(('EvaluationPredictions','EvaluationAnnotations','EvaluationSplit','EvaluationRegistration'),fixture()):
            schema=json.loads((SCHEMAS/(name+'.schema.json')).read_text())
            Draft202012Validator(schema,format_checker=FormatChecker()).validate(value)
            bad=copy.deepcopy(value);bad['unexpected']=True
            with self.assertRaises(Exception):Draft202012Validator(schema).validate(bad)

    def test_hand_calculated(self):
        result=evaluate(*fixture());m=result['record']['metrics']
        self.assertEqual(m,{'tp':1,'fp':1,'fn':1,'precision':.5,'recall':.5,'normal_hours':1,'false_alarms_per_normal_hour':1})
        self.assertEqual(result['unlabelled_relations'],1);self.assertIsNone(result['path_accuracy'])
    def test_empty_and_no_normal_denominator(self):
        p,a,s,r=fixture();p['events']=[];a['events']=[];s['blocks'][2]['normal']=False;r['split_sha256']=digest(s)
        m=evaluate(p,a,s,r)['record']['metrics']
        for key in ('precision','recall','normal_hours','false_alarms_per_normal_hour'):self.assertIsNone(m[key])
    def test_disputes_excluded_and_duration_subtracted(self):
        p,a,s,r=fixture();a['disputed_intervals']=[{'batch':'b','start':'2026-01-01T02:00:00Z','end':'2026-01-01T02:30:00Z'}]
        result=evaluate(p,a,s,r);self.assertEqual(result['excluded_disputed_predictions'],1);self.assertEqual(result['record']['metrics']['normal_hours'],1)
    def test_real_data_never_gets_synthetic_scores(self):
        p,a,s,r=fixture();p['synthetic']=False
        result=evaluate(p,a,s,r);self.assertEqual(result['status'],'not_evaluated');self.assertTrue(all(v is None for v in result['record']['metrics'].values()))
    def test_splits_reject_overlap_duplicates_and_missing_window(self):
        for mode in ('overlap','duplicate','window','gap'):
            _,_,s,_=fixture()
            if mode=='overlap':s['blocks'][1]['start']='2026-01-01T00:59:00Z'
            if mode=='duplicate':s['blocks'][1]['sample_sha256']=['a'*64]
            if mode=='window':s['rule_windows_seconds']={}
            if mode=='gap':s['isolation_seconds']=30
            with self.subTest(mode=mode),self.assertRaises(ValueError):validate_splits(s)
    def test_normal_positive_and_wrong_sample_rejected(self):
        p,a,s,r=fixture();s['blocks'][1]['normal']=True;r['split_sha256']=digest(s)
        with self.assertRaises(ValueError):evaluate(p,a,s,r)
        p,a,s,r=fixture();p['events'][0]['sample_sha256']='a'*64
        with self.assertRaises(ValueError):evaluate(p,a,s,r)

    def test_registration_and_provenance_rejected(self):
        for mode in ('digest','late','gold','identity','outside','duplicate','nan'):
            p,a,s,r=fixture()
            if mode=='digest':r['split_sha256']='0'*64
            if mode=='late':r['registered_at']=r['holdout_opened_at']
            if mode=='gold':a['origin']='prediction_derived'
            if mode=='identity':p['input_fingerprint']='0'*64
            if mode=='outside':p['events'][0]['time']='2026-01-01T01:00:00Z'
            if mode=='duplicate':p['events'].append(copy.deepcopy(p['events'][0]))
            if mode=='nan':r['tolerance_seconds']=float('nan')
            with self.subTest(mode=mode),self.assertRaises(ValueError):evaluate(p,a,s,r)
    def test_one_to_one_maximum_matching(self):
        p,a,s,r=fixture()
        p['events'][0]['time']='2026-01-01T02:00:01Z';p['events'][1]['time']='2026-01-01T02:00:00Z';p['events'][1]['sample_sha256']='b'*64
        a['events'][0]['time']='2026-01-01T02:00:00Z';a['events'][1]['time']='2026-01-01T02:00:02Z';r['tolerance_seconds']=1
        self.assertEqual(evaluate(p,a,s,r)['record']['metrics']['tp'],2)
    def test_exact_tolerance_and_outside_boundary(self):
        p,a,s,r=fixture();r['tolerance_seconds']=1
        self.assertEqual(evaluate(p,a,s,r)['record']['metrics']['tp'],1)
        r['tolerance_seconds']=.9;self.assertEqual(evaluate(p,a,s,r)['record']['metrics']['tp'],0)

if __name__=='__main__':unittest.main()
