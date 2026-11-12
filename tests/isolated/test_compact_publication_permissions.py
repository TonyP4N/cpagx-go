"""Compact handoff roots must be readable by a distinct Linux verifier UID."""
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/worker'),str(ROOT/'services/analysis/src'),str(ROOT/'tests/core'),str(ROOT/'scripts/validation')]
from cpag_worker.isolated import atomic_json,seal_handoff
import test_compact_worker as compact_cases


class CompactPublicationPermissionsTests(unittest.TestCase):
    def test_new_compact_root_allows_only_owner_writes_and_seals_children(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)/'stage';stage.mkdir(mode=0o700)
            (stage/'shared').mkdir(mode=0o700);(stage/'shared/shared.sqlite3').write_bytes(b'fixed')
            seal_handoff(stage,compact=True)
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode),0o755)
            self.assertEqual(stat.S_IMODE((stage/'shared').stat().st_mode),0o555)
            self.assertEqual(stat.S_IMODE((stage/'shared/shared.sqlite3').stat().st_mode),0o444)
            self.assertEqual((stage/'shared/shared.sqlite3').read_bytes(),b'fixed')
    def test_legacy_root_permissions_remain_private_before_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)/'stage';stage.mkdir(mode=0o700);(stage/'analysis.json').write_text('{}')
            seal_handoff(stage,compact=False)
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((stage/'analysis.json').stat().st_mode),0o444)
    def test_recovery_prepares_old_private_root_before_complete_and_finally_seals(self):
        with tempfile.TemporaryDirectory() as directory:
            worker,target,payload,binding,sha=compact_cases.CompactServiceWorkerTests().prepare(Path(directory))
            seal_handoff(target,compact=False)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o700)
            record={'id':'compact','attempt':1,'worker':'host','token':'private-token','container_id':'a'*64}
            base=worker.control/'jobs/compact/attempt-1.worker'
            atomic_json(base/'exit.json',{'removed':True,'container_id':record['container_id']})
            atomic_json(base/'handoff.json',{'output_dir':'jobs/compact/attempt-1','manifest_sha256':sha})
            def complete(*args,**kwargs):
                self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o755)
                # The service owner still needs to create its content-addressed anchor.
                (target/(sha+'.json')).write_bytes((target/'manifest.json').read_bytes())
                return {'state':'succeeded'}
            with patch.object(worker,'complete',side_effect=complete) as publish:
                self.assertEqual(worker.resume_publication(record,{'payload':payload}),'succeeded')
                publish.assert_called_once()
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o555)
            self.assertEqual((target/(sha+'.json')).read_bytes(),(target/'manifest.json').read_bytes())


if __name__=='__main__':unittest.main()
