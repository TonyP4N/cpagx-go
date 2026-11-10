"""Independent complete source roots; no replica serialization or partial proof."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_shared_source_tampering import build,rehash_everything
from cpag_core import shared_export as core


class SourceVerifierStrategyTests(unittest.TestCase):
    def test_both_complete_strategies_agree_without_writing_a_replica(self):
        for mode in ('offline','replay'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);manifest=build(root,mode)
                old=core.verify_task(root/'output',verification_strategy=core.REEXPORT_STRATEGY)
                report={}
                with patch.object(core,'export_task',side_effect=AssertionError('replica export not allowed')):
                    new=core.verify_task(root/'output',verification_report=report)
                self.assertEqual(old,manifest);self.assertEqual(new,manifest)
                self.assertEqual(report['verification_strategy'],core.VERIFICATION_STRATEGY)
                self.assertEqual(report['status'],'passed')
                self.assertEqual(report['physical_artifacts_created'],0)
                self.assertGreater(report['node_count'],0)

    def test_source_sink_rejects_fully_rehashed_false_business_field(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);build(root)
            def fake(documents,manifest):
                documents['analysis.json']['operations'][0]['response']['state']='error'
                documents['dual/analysis.json']=documents['analysis.json']
            rehash_everything(root/'output',fake)
            for strategy in (core.VERIFICATION_STRATEGY,core.REEXPORT_STRATEGY):
                with self.subTest(strategy=strategy),self.assertRaisesRegex(ValueError,'does_not_match_sources'):
                    core.verify_task(root/'output',verification_strategy=strategy)

    def test_source_mutation_during_reconstruction_is_rechecked(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);build(root);original=core._rebuild_source_roots
            def changed(*args,**kwargs):
                answer=original(*args,**kwargs)
                path=root/'output/sources/process.csv';raw=path.read_bytes()
                path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
                return answer
            with patch.object(core,'_rebuild_source_roots',side_effect=changed),self.assertRaisesRegex(ValueError,'shared_artifact_changed'):
                core.verify_task(root/'output')

    def test_unknown_strategy_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'unsupported_source_verification_strategy'):
            core.verify_task('/unused',verification_strategy='skip-source')

if __name__=='__main__':unittest.main()
