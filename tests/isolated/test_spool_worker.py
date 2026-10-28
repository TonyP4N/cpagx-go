"""Explicit spool handoff/recovery retains old default history inventory."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'services/worker'),str(ROOT/'scripts/validation')]
from cpag_worker.isolated import DockerExecutor
from cpag_worker.worker import API,digest,publication_inputs
from cpag_core.replay_export import export_task,artifact_files_for_inputs
from round18_profile import fixture
from test_dual_source_worker import FakeTarProcess

FORMAT='replay-history-checkpoint-delta-2'


class SpoolWorkerTests(unittest.TestCase):
    def test_target_output_plus_one_is_refused_before_tar_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); shared=base/'shared'; shared.mkdir()
            worker=DockerExecutor(API('http://unused','x'),API('http://unused','y'),shared,base/'control','worker',resource_profile='engineering-capacity-1')
            payload={'kind':'dual-source-replay','replay_version':'dual-source-replay-1','history_format':FORMAT}
            entry=tarfile.TarInfo('./analysis.json'); entry.size=worker.output_bytes+1
            raw=entry.tobuf()+b'\0'*1024
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(raw)),patch('cpag_worker.isolated.shutil.disk_usage',return_value=SimpleNamespace(free=100*1024**3)):
                with self.assertRaisesRegex(ValueError,'output transfer limit'):
                    worker.read_output('fake',base/'stage',payload,run_id='spool',attempt_id=1)
            self.assertFalse((base/'stage/manifest.json').exists())

    def test_spool_inventory_schema_and_removed_container_recovery_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); shared=base/'shared'; shared.mkdir()
            n,p,c,config=fixture(base/'inputs'); config['replay']['history_format']=FORMAT
            c.write_text(json.dumps(config)); source=base/'source'
            manifest=export_task(n,p,c,source,run_id='spool',attempt_id=1)
            ref=lambda path:{'path':str(path.relative_to(base)),'sha256':digest(path)}
            payload={'kind':'dual-source-replay','replay_version':'dual-source-replay-1','history_format':FORMAT,
                'config_fingerprint':manifest['config_fingerprint'],'network':ref(n[0]),'networks':[ref(path) for path in n],
                'process':ref(p),'profile':ref(c)}
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w') as archive:archive.add(source,arcname='.')
            worker=DockerExecutor(API('http://unused','x'),API('http://unused','y'),shared,base/'control','worker')
            target=shared/'jobs/spool/attempt-1'
            target.parent.mkdir(parents=True)
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(data.getvalue())):
                sha=worker.read_output('fake',target,payload,run_id='spool',attempt_id=1)
            wrapper=json.loads((target/'manifest.json').read_text())
            self.assertEqual(wrapper['history_format'],FORMAT)
            self.assertEqual(publication_inputs(payload)['history_format'],FORMAT)
            self.assertEqual({row['path'] for row in wrapper['artifacts']},artifact_files_for_inputs(2,history_format=FORMAT))
            self.assertNotIn('snapshots.jsonl',{row['path'] for row in wrapper['artifacts']})
            control=base/'control/jobs/spool/attempt-1.worker'; control.mkdir(parents=True)
            record={'id':'spool','attempt':1,'worker':'worker','token':'private-test-token','container_id':'a'*64}
            (control/'exit.json').write_text(json.dumps({'removed':True,'container_id':record['container_id']}))
            (control/'handoff.json').write_text(json.dumps({'output_dir':'jobs/spool/attempt-1','manifest_sha256':sha}))
            # A changed payload format cannot reuse the correctly hashed handoff.
            bad=dict(payload); bad.pop('history_format')
            with self.assertRaisesRegex(ValueError,'identity differs|version differs'):
                worker.resume_publication(record,{'payload':bad})
            with patch.object(worker.publication_api,'post',return_value={}) as publish:
                self.assertEqual(worker.resume_publication(record,{'payload':payload}),'succeeded')
                publish.assert_called_once()

    def test_old_payload_cannot_receive_new_spool_tar(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); shared=base/'shared'; shared.mkdir()
            n,p,c,config=fixture(base/'inputs'); config['replay']['history_format']=FORMAT; c.write_text(json.dumps(config))
            source=base/'source'; manifest=export_task(n,p,c,source,run_id='spool',attempt_id=1)
            ref=lambda path:{'path':str(path.relative_to(base)),'sha256':digest(path)}
            payload={'kind':'dual-source-replay','replay_version':'dual-source-replay-1','config_fingerprint':manifest['config_fingerprint'],
                'network':ref(n[0]),'networks':[ref(path) for path in n],'process':ref(p),'profile':ref(c)}
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w') as archive:archive.add(source,arcname='.')
            worker=DockerExecutor(API('http://unused','x'),API('http://unused','y'),shared,base/'control','worker')
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(data.getvalue())):
                with self.assertRaisesRegex(ValueError,'unsafe output archive member'):
                    worker.read_output('fake',base/'stage',payload,run_id='spool',attempt_id=1)


if __name__=='__main__':unittest.main()
