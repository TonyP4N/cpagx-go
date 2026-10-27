"""Replay uses the existing isolated handoff without publishing partial history."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'services/worker'),str(ROOT/'scripts/validation')]
from cpag_worker.isolated import DockerExecutor
from cpag_worker.worker import API,digest,publication_inputs
from cpag_core.replay_export import export_task,verify_task,artifact_files_for_inputs
from round18_profile import fixture
from test_dual_source_worker import FakeTarProcess

class ReplayHandoffTests(unittest.TestCase):
    def test_complete_replay_inventory_version_and_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);shared=base/'shared';shared.mkdir();networks,process,profile,_=fixture(base/'inputs')
            source=base/'source';core=export_task(networks,process,profile,source,run_id='replay',attempt_id=2)
            ref=lambda p:{'path':str(p.relative_to(base)),'sha256':digest(p)}
            payload={'kind':'dual-source-replay','replay_version':'dual-source-replay-1','config_fingerprint':core['config_fingerprint'],
                     'network':ref(networks[0]),'networks':[ref(p) for p in networks],'process':ref(process),'profile':ref(profile)}
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w') as archive:archive.add(source,arcname='.')
            worker=DockerExecutor(API('http://unused','x'),API('http://unused','y'),shared,base/'control','host')
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(data.getvalue())):
                sha=worker.read_output('fake',base/'stage',payload,run_id='replay',attempt_id=2)
            self.assertEqual(sha,digest(base/'stage/manifest.json'))
            wrapper=json.loads((base/'stage/manifest.json').read_text())
            self.assertEqual(wrapper['replay_version'],'dual-source-replay-1')
            self.assertEqual(wrapper['inputs'],publication_inputs(payload)['inputs'])
            self.assertEqual({row['path'] for row in wrapper['artifacts']},artifact_files_for_inputs(2))
            self.assertEqual(verify_task(base/'stage'),core)
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(data.getvalue())):
                with self.assertRaisesRegex(ValueError,'identity mismatch'):
                    worker.read_output('fake',base/'wrong-attempt',payload,run_id='replay',attempt_id=3)

    def test_truncated_history_cannot_pass_semantic_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);shared=base/'shared';shared.mkdir();n,p,c,_=fixture(base/'inputs')
            source=base/'source';core=export_task(n,p,c,source,run_id='replay',attempt_id=1)
            ref=lambda p:{'path':str(p.relative_to(base)),'sha256':digest(p)}
            payload={'kind':'dual-source-replay','replay_version':'dual-source-replay-1','config_fingerprint':core['config_fingerprint'],
                     'network':ref(n[0]),'networks':[ref(x) for x in n],'process':ref(p),'profile':ref(c)}
            path=source/'snapshots.jsonl';path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
            # Rehashing a superficial artifact table still must fail full replay verification.
            manifest=json.loads((source/'run_manifest.json').read_text())
            for row in manifest['artifacts']:
                if row['path']=='snapshots.jsonl':row.update(sha256=digest(path),size_bytes=path.stat().st_size)
            from cpag_core.pipeline import canonical
            (source/'run_manifest.json').write_bytes(canonical(manifest)+b'\n')
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w') as archive:archive.add(source,arcname='.')
            worker=DockerExecutor(API('http://unused','x'),API('http://unused','y'),shared,base/'control','host')
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(data.getvalue())):
                with self.assertRaisesRegex(ValueError,'semantic_mismatch'):
                    worker.read_output('fake',base/'stage',payload,run_id='replay',attempt_id=1)

if __name__=='__main__':unittest.main()
