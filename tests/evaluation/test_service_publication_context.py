"""Service verification reuse preserves bytes and the standalone trust boundary."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'services/analysis/src'), str(ROOT/'scripts/validation')]
from dual_source_fixtures import make_case
from cpag_core.dual_source_export import export_task
from cpag_core.evaluation_artifacts import adapt_artifact, query_prediction
from cpag_core.evaluation_context import service_publication, checked_manifest
from cpag_core.pipeline import file_hash

CONTEXT = {'batch':'registered', 'sample_sha256':'a'*64}


class ServicePublicationTests(unittest.TestCase):
    def test_matches_standalone_and_reuses_no_semantic_reexecution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); out=root/'run'; export_task(*make_case(root/'inputs'),out)
            expected=adapt_artifact(out,**CONTEXT)
            digest=file_hash(out/'run_manifest.json')
            identity=expected['predictions']['events'][0]['id']
            evidence=query_prediction(out,expected,identity)
            with service_publication(out,digest), patch('cpag_core.dual_source_export.verify_task',side_effect=AssertionError('duplicate computation')):
                self.assertEqual(adapt_artifact(out,**CONTEXT),expected)
                self.assertEqual(adapt_artifact(out,**CONTEXT),expected)
                self.assertEqual(query_prediction(out,expected,identity),evidence)
            self.assertIsNone(checked_manifest(out))
            with patch('cpag_core.dual_source_export.verify_task',side_effect=ValueError('standalone verification')):
                with self.assertRaisesRegex(ValueError,'standalone verification'):adapt_artifact(out,**CONTEXT)

    def test_prepared_replay_matches_full_history_projection_and_raw_queries(self):
        from round18_profile import fixture
        from cpag_core.replay_export import export_task as export_replay
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);net,process,profile,_=fixture(root/'inputs');out=root/'run'
            export_replay(net,process,profile,out)
            expected=adapt_artifact(out,**CONTEXT)
            identities=[row['id'] for row in expected['predictions']['events']]+expected['predictions']['unlabelled_relations']
            originals={key:query_prediction(out,expected,key) for key in identities}
            with service_publication(out,file_hash(out/'run_manifest.json'),prepared_adapted=expected), patch('cpag_core.replay_export.verify_task',side_effect=AssertionError('unexpected replay')), patch('cpag_core.replay_export.query_task',side_effect=AssertionError('unexpected historical reexecution')):
                self.assertEqual(adapt_artifact(out,**CONTEXT),expected)
                for key in identities:self.assertEqual(query_prediction(out,expected,key),originals[key])

    def test_prepared_binding_and_policy_are_checked_not_user_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);out=root/'run';export_task(*make_case(root/'inputs'),out)
            expected=adapt_artifact(out,**CONTEXT);sha=file_hash(out/'run_manifest.json')
            for key,value in [('attempt_id',999),('batch','another'),('policy',{}),('artifact_sha256',{})]:
                changed=copy.deepcopy(expected);changed['binding'][key]=value
                with self.subTest(key=key),service_publication(out,sha,prepared_adapted=changed),self.assertRaisesRegex(ValueError,'prepared_projection'):
                    adapt_artifact(out,**CONTEXT)
            with self.assertRaisesRegex(ValueError,'requires_service_publication'):
                with service_publication(out,None,prepared_adapted=expected):pass

    def test_prepared_bundle_verification_preserves_legacy_semantics_and_rejects_forgery(self):
        from test_round19_bundle import BundleTests
        from cpag_core import evaluation_bundle as eb
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);BundleTests().evaluated_case(root)
            document={path.name:eb.read(path) for path in (root/'result').iterdir()}
            adapted=document['adapted.json'];identity=adapted['predictions']['events'][0]['id']
            expected=eb.verify_document(document,root/'artifact',identity=identity)
            with service_publication(root/'artifact',file_hash(root/'artifact/run_manifest.json'),prepared_adapted=adapted), patch('cpag_core.dual_source_export.verify_task',side_effect=AssertionError('duplicate analysis')):
                self.assertEqual(eb.verify_document(document,root/'artifact',identity=identity),expected)
                forged=copy.deepcopy(document);forged['result.json']['record']['metrics']['tp']=999
                forged['manifest.json']['files']['result.json']=eb.digest(forged['result.json'])
                with self.assertRaisesRegex(ValueError,'evaluation_result_changed'):
                    eb.verify_document(forged,root/'artifact')

    def test_cached_same_size_change_and_missing_bytes_rejected(self):
        for missing in (False,True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); out=root/'run'; export_task(*make_case(root/'inputs'),out)
                digest=file_hash(out/'run_manifest.json'); path=out/'dual/sources/process.csv'
                with self.assertRaisesRegex(ValueError,'bytes_changed'):
                    with service_publication(out,digest):
                        adapt_artifact(out,**CONTEXT)
                        if missing:path.unlink()
                        else:
                            data=path.read_bytes();path.write_bytes(data[:-1]+(b'X' if data[-1:]!=b'X' else b'Y'))
                        adapt_artifact(out,**CONTEXT)
                self.assertIsNone(checked_manifest(out))

    def test_wrong_manifest_digest_and_root_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); out=root/'run';export_task(*make_case(root/'inputs'),out)
            with self.assertRaisesRegex(ValueError,'manifest_changed'):
                with service_publication(out,'0'*64):pass
            with service_publication(out,file_hash(out/'run_manifest.json')):
                with self.assertRaisesRegex(ValueError,'root_mismatch'):checked_manifest(root)

if __name__=='__main__':unittest.main()
