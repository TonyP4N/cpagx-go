import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from round18_profile import fixture
from cpag_core.replay_export import export_task
from cpag_core.replay_history import VERSION
from cpag_core.evaluation_artifacts import adapt_artifact,query_prediction


class SpoolEvaluationArtifactTests(unittest.TestCase):
    def test_terminal_predictions_and_history_stats_equal_legacy_after_storage_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);networks,process,path,profile=fixture(root/'inputs')
            export_task(networks,process,path,root/'legacy',run_id='same-run',attempt_id=2)
            legacy=adapt_artifact(root/'legacy',batch='registered',sample_sha256='b'*64)
            profile['replay']['history_format']=VERSION;path.write_text(json.dumps(profile))
            export_task(networks,process,path,root/'spool',run_id='same-run',attempt_id=2)
            spool=adapt_artifact(root/'spool',batch='registered',sample_sha256='b'*64)
            self.assertEqual(spool['predictions']['events'],legacy['predictions']['events'])
            self.assertEqual(spool['predictions']['unlabelled_relations'],legacy['predictions']['unlabelled_relations'])
            self.assertEqual(spool['process_statistics'],legacy['process_statistics'])
            self.assertNotIn('history_format',legacy['binding'])
            self.assertEqual(spool['binding']['history_format'],VERSION)
            self.assertIn('history/history.sqlite3',spool['binding']['artifact_sha256'])
            self.assertNotIn('snapshots.jsonl',spool['binding']['artifact_sha256'])
            restored=root/'restored';shutil.copytree(root/'spool',restored)
            self.assertEqual(spool,adapt_artifact(restored,batch='registered',sample_sha256='b'*64,expected_binding=spool['binding']))
            for event in spool['predictions']['events']:
                evidence=query_prediction(restored,spool,event['id'])
                self.assertTrue(evidence['evidence']['verified_original_evidence'])
            changed=copy.deepcopy(spool['binding']);changed['history_format']='unknown'
            with self.assertRaises(ValueError):adapt_artifact(restored,batch='registered',sample_sha256='b'*64,expected_binding=changed)


if __name__=='__main__':unittest.main()
