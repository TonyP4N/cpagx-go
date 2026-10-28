"""Strict new history inventory with original publication and source checks."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import test_replay_bundle as legacy
from cpag_core.pipeline import canonical
from cpag_core.replay_export import iter_verified_snapshots,query_task
from cpag_core.replay_history import VERSION

bundle=legacy.bundle


class ReplaySpoolBackupTests(unittest.TestCase):
    make=legacy.ReplayBundleTests.make

    def test_compact_inventory_copy_and_historical_original_queries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source';root.mkdir();row,out=self.make(root,VERSION)
            self.assertTrue(bundle.audit([row],root)['valid'])
            self.assertFalse((out/'snapshots.jsonl').exists());self.assertFalse((out/'revisions.jsonl').exists())
            restored=Path(tmp)/'restored';shutil.copytree(root,restored)
            self.assertTrue(bundle.audit([row],restored)['valid'])
            destination=restored/'jobs/replay/attempt-1'
            for name in ('history/manifest.json','history/history.sqlite3'):
                self.assertEqual((out/name).read_bytes(),(destination/name).read_bytes())
            snapshots=list(iter_verified_snapshots(out))
            pending=next(snapshot for snapshot in snapshots if any(op['replay']['status']=='pending_response' for op in snapshot['analysis']['operations']))
            self.assertEqual(query_task(out,pending['snapshot_number'],operation_id='first'),
                             query_task(destination,pending['snapshot_number'],operation_id='first'))

    def test_missing_or_extra_history_or_mismatched_format_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);row,out=self.make(root,VERSION)
            changed=copy.deepcopy(row);changed['payload']['history_format']='unknown'
            self.assertFalse(bundle.audit([changed],root)['valid'])
            extra=out/'history/history.sqlite3-wal';extra.write_bytes(b'not_sealed')
            self.assertFalse(bundle.audit([row],root)['valid']);extra.unlink()
            path=out/'history/history.sqlite3';path.unlink()
            self.assertFalse(bundle.audit([row],root)['valid'])

    def test_explicit_null_format_is_not_treated_as_historical_omission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);row,_=self.make(root,VERSION)
            profile=json.loads((root/row['payload']['profile']['path']).read_text())
            profile['replay']['history_format']=None;row['payload']['history_format']=None
            with self.assertRaisesRegex(ValueError,'cannot be null'):
                bundle.replay_files(row['payload'],profile)

    def test_rehashed_storage_cannot_borrow_another_run_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);row,out=self.make(root/'one',VERSION)
            other_root=root/'two';_,other=self.make(other_root,VERSION,run_id='other')
            shutil.rmtree(out/'history');shutil.copytree(other/'history',out/'history')
            manifest_path=out/'run_manifest.json';manifest=json.loads(manifest_path.read_text())
            manifest['history_manifest_sha256']=bundle.sha(out/'history/manifest.json')
            for entry in manifest['artifacts']:
                path=out/entry['path'];entry.update(sha256=bundle.sha(path),size_bytes=path.stat().st_size)
            manifest_path.write_bytes(canonical(manifest)+b'\n')
            wrapper_path=out/'manifest.json';wrapper=json.loads(wrapper_path.read_text())
            for entry in wrapper['artifacts']:
                path=out/entry['path'];entry.update(sha256=bundle.sha(path),size=path.stat().st_size)
            old=out/(row['artifact_sha256']+'.json');old.unlink()
            wrapper_path.write_bytes(canonical(wrapper)+b'\n');digest=bundle.sha(wrapper_path)
            anchor=out/(digest+'.json');anchor.write_bytes(wrapper_path.read_bytes())
            row.update(artifact_sha256=digest,artifact_path=anchor.relative_to(root/'one').as_posix())
            result=bundle.audit([row],root/'one')
            self.assertFalse(result['valid'])
            self.assertTrue(any('context' in error.get('reason','') or 'binding' in error.get('reason','') for error in result['errors']),result)


if __name__=='__main__':unittest.main()
