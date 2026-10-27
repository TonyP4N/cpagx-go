"""Lifecycle expected labels are handwritten before invoking an exporter."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'services/analysis/src'))
from cpag_core import evaluation_bundle as eb
from cpag_core.evaluation import digest
from cpag_core.dual_source_export import export_task

class Clock(datetime):
    current='2026-10-27T00:00:00+00:00'
    @classmethod
    def now(cls,tz=None):return datetime.fromisoformat(cls.current)

class BundleTests(unittest.TestCase):
    def setup_case(self,root):
        example=ROOT/'examples/round18-replay'
        # Independent expectation from fixture: operation at10; transition upper12.
        events=[{'id':'manual-op','batch':'fixture','kind':'network_operation','asset':'["192.0.2.2",44818]','time':'2026-01-01T00:00:10Z','sample_sha256':'b'*64},
            {'id':'manual-change','batch':'fixture','kind':'process_change','asset':'["synthetic-pump","pump_state"]','time':'2026-01-01T00:00:12Z','sample_sha256':'b'*64}]
        labels={'schema_version':'1.0.0','synthetic':True,'origin':'independent','source_ref':'handwritten fixture table','review_ref':'test-author','annotation_version':'1','events':events,'disputed_intervals':[]}
        manifest=export_task([example/'network.pcap',example/'response.pcap'],example/'process.csv',example/'profile.json',root/'artifact',run_id='binding-test',attempt_id=2)
        split={'schema_version':'1.0.0','synthetic':True,'rule_windows_seconds':{'association':5},'isolation_seconds':5,'blocks':[
            {'partition':'calibration','batch':'fixture','start':'2025-12-01T00:00:00Z','end':'2025-12-01T00:01:00Z','sample_sha256':['a'*64],'normal':False},
            {'partition':'holdout','batch':'fixture','start':'2026-01-01T00:00:00Z','end':'2026-01-01T00:01:00Z','sample_sha256':['b'*64],'normal':False}]}
        reg={'schema_version':'1.0.0','synthetic':True,'registered_at':'2026-10-26T00:00:00Z','holdout_opened_at':'2026-10-28T00:00:00Z','input_fingerprint':manifest['input_fingerprint'],'config_fingerprint':manifest['config_fingerprint'],'split_sha256':digest(split),'tolerance_seconds':0,'thresholds':{}}
        refs={e['id']:{'source_ref':'independent-fixture-notes','record':e['id'],'sha256':'f'*64} for e in events}
        Clock.current='2026-10-27T00:00:00+00:00'
        with patch.object(eb,'datetime',Clock):eb.freeze(root/'artifact',split,reg,root/'frozen',batch='fixture',sample_sha256='b'*64)
        return labels,refs
    def test_freeze_open_verify_query_and_portable_copy(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp);labels,refs=self.setup_case(r)
            with patch.object(eb,'datetime',Clock),self.assertRaisesRegex(ValueError,'holdout_not_open'):
                eb.evaluate_bundle(r/'frozen',r/'artifact',labels,refs,r/'early')
            Clock.current='2026-10-28T00:00:01+00:00'
            with patch.object(eb,'datetime',Clock):result=eb.evaluate_bundle(r/'frozen',r/'artifact',labels,refs,r/'result')
            self.assertEqual(result['record']['metrics']['tp'],2)
            self.assertEqual(eb.verify_bundle(r/'result',r/'artifact'),result)
            document={p.name:eb.read(p) for p in (r/'result').iterdir()}
            self.assertEqual(eb.verify_document(document,r/'artifact')['result'],result)
            self.assertEqual(eb.verify_document(document,r/'artifact')['document_sha256'],digest(document))
            ref=eb.query_error(r/'result',r/'artifact','manual-change',reference=True)
            self.assertEqual(ref['reference'],refs['manual-change'])
            adapted=eb.read(r/'result/adapted.json')
            actual=eb.query_error(r/'result',r/'artifact',adapted['predictions']['events'][0]['id'])
            self.assertIn('evidence',actual)
            shutil.copytree(r/'result',r/'restored-sidecar');shutil.copytree(r/'artifact',r/'restored-artifact')
            self.assertEqual(eb.verify_bundle(r/'restored-sidecar',r/'restored-artifact'),result)
            # This proves directory portability only, not PostgreSQL bundle restoration.
    def test_frozen_policy_and_tolerance_changes_refused(self):
        for filename,field,value in [('registration.json','tolerance_seconds',999),('freeze.json','matching','invented')]:
            with self.subTest(filename=filename),tempfile.TemporaryDirectory() as tmp:
                r=Path(tmp);self.setup_case(r);p=r/'frozen'/filename;doc=eb.read(p);doc[field]=value;p.write_text(json.dumps(doc))
                with self.assertRaises(ValueError):eb.frozen_inputs(r/'frozen',r/'artifact')
    def test_no_reference_or_tampered_result_is_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp);labels,refs=self.setup_case(r);Clock.current='2026-10-28T00:00:01+00:00'
            with patch.object(eb,'datetime',Clock):
                with self.assertRaisesRegex(ValueError,'every_gold'):eb.evaluate_bundle(r/'frozen',r/'artifact',labels,{},r/'bad')
                eb.evaluate_bundle(r/'frozen',r/'artifact',labels,refs,r/'result')
            p=r/'result/result.json';value=eb.read(p);value['record']['metrics']['tp']=99;p.write_text(json.dumps(value))
            with self.assertRaises(ValueError):eb.verify_bundle(r/'result',r/'artifact')
    def test_duplicate_output_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'x';eb.publish(p,{'a.json':{'a':1}})
            with self.assertRaises(ValueError):eb.publish(p,{'a.json':{'a':2}})
            self.assertEqual(eb.read(p/'a.json'),{'a':1})

    def evaluated_case(self,root):
        labels,refs=self.setup_case(root);Clock.current='2026-10-28T00:00:01+00:00'
        with patch.object(eb,'datetime',Clock):
            eb.evaluate_bundle(root/'frozen',root/'artifact',labels,refs,root/'result')
        return labels,refs

    def rewrite_result_document(self,root,changed):
        """Rehash untrusted imported JSON; semantic checks must still reject it."""
        for name,value in changed.items():(root/name).write_text(json.dumps(value))
        manifest=eb.read(root/'manifest.json')
        for name in manifest['files']:manifest['files'][name]=digest(eb.read(root/name))
        (root/'manifest.json').write_text(json.dumps(manifest))

    def test_freeze_completion_must_precede_opening_and_future_registration_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp);self.setup_case(r);split=eb.read(r/'frozen/split.json');reg=eb.read(r/'frozen/registration.json')
            actual_adapter=eb.adapt_artifact
            def crossing_opening(*args,**kwargs):
                result=actual_adapter(*args,**kwargs)
                Clock.current='2026-10-28T00:00:01+00:00'
                return result
            Clock.current='2026-10-27T00:00:00+00:00'
            with patch.object(eb,'datetime',Clock),patch.object(eb,'adapt_artifact',side_effect=crossing_opening):
                with self.assertRaisesRegex(ValueError,'freeze.*opening'):
                    eb.freeze(r/'artifact',split,reg,r/'late',batch='fixture',sample_sha256='b'*64)
            self.assertFalse((r/'late').exists())
            reg['registered_at']='2026-10-27T23:00:00Z';Clock.current='2026-10-27T00:00:00+00:00'
            with patch.object(eb,'datetime',Clock),self.assertRaisesRegex(ValueError,'registration.*freeze'):
                eb.freeze(r/'artifact',split,reg,r/'future-registration',batch='fixture',sample_sha256='b'*64)

    def test_imported_bundle_rejects_late_freeze_even_when_rehashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp);self.evaluated_case(r);root=r/'result'
            frozen=eb.read(root/'freeze.json');frozen['observed_frozen_at']='2026-10-28T00:00:00.5Z'
            result=eb.read(root/'result.json');result['bundle_binding']['freeze_sha256']=digest(frozen)
            self.rewrite_result_document(root,{'freeze.json':frozen,'result.json':result})
            with self.assertRaisesRegex(ValueError,'freeze.*opening'):
                eb.verify_bundle(root,r/'artifact')

    def test_imported_bundle_revalidates_all_independent_reference_declarations(self):
        for mutation in ('missing','empty','bad_hash','extra'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
                r=Path(tmp);_,refs=self.evaluated_case(r);root=r/'result'
                if mutation=='missing':refs.pop('manual-op')
                if mutation=='empty':refs['manual-op']['source_ref']=' '
                if mutation=='bad_hash':refs['manual-op']['sha256']='invented'
                if mutation=='extra':refs['unregistered']=copy.deepcopy(refs['manual-op'])
                result=eb.read(root/'result.json');result['bundle_binding']['references_sha256']=digest(refs)
                self.rewrite_result_document(root,{'references.json':refs,'result.json':result})
                with self.assertRaisesRegex(ValueError,'reference'):
                    eb.verify_bundle(root,r/'artifact')

    def test_imported_bundle_rejects_proof_claims_unknown_versions_and_extra_contract_fields(self):
        cases=[('binding','reference_status','original_bytes_verified'),('binding','version','unknown'),
               ('binding','unexpected',True),('freeze','custody','cryptographic_independence_proven'),
               ('freeze','unexpected',True),('manifest','unexpected',True)]
        for target,field,value in cases:
            with self.subTest(target=target,field=field),tempfile.TemporaryDirectory() as tmp:
                r=Path(tmp);self.evaluated_case(r);root=r/'result'
                result=eb.read(root/'result.json')
                changed={}
                if target=='binding':result['bundle_binding'][field]=value
                elif target=='freeze':
                    frozen=eb.read(root/'freeze.json');frozen[field]=value
                    result['bundle_binding']['freeze_sha256']=digest(frozen);changed['freeze.json']=frozen
                changed['result.json']=result;self.rewrite_result_document(root,changed)
                if target=='manifest':
                    manifest=eb.read(root/'manifest.json');manifest[field]=value
                    (root/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):eb.verify_bundle(root,r/'artifact')

if __name__=='__main__':unittest.main()
