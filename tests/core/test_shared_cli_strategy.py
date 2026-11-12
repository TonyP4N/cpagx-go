"""Actual CLI contract for complete source strategies and bounded evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_shared_manifest_binding import build
from cpag_core import shared_export as core


class SharedCLIStrategyTests(unittest.TestCase):
    def test_complete_strategies_evidence_and_invalid_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact=build(Path(directory),'offline')
            env=dict(os.environ,PYTHONPATH=str(Path(core.__file__).parents[1]))
            def invoke(*args):
                return subprocess.run([sys.executable,'-m','cpag_core.shared_cli','--root',str(artifact),*args],
                    env=env,capture_output=True,text=True,timeout=30)
            manifests=[]
            for strategy in (core.VERIFICATION_STRATEGY,core.REEXPORT_STRATEGY):
                result=invoke('--action','verify','--verification-strategy',strategy)
                self.assertEqual(result.returncode,0,result.stderr)
                value=json.loads(result.stdout);self.assertEqual(value['verification_report']['status'],'passed')
                self.assertEqual(value['verification_strategy'],strategy);manifests.append(value['manifest'])
            self.assertEqual(*manifests)
            result=invoke('--action','evidence','--operation','first')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(len(json.loads(result.stdout)['verified_original_evidence']),4)
            for args in (('--action','verify','--verification-strategy','skip-source'),
                         ('--action','metadata','--verification-strategy',core.VERIFICATION_STRATEGY)):
                result=invoke(*args);self.assertEqual(result.returncode,2);self.assertFalse(result.stdout)

if __name__=='__main__':unittest.main()
