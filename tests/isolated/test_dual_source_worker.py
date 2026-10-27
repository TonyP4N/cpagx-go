"""The isolated handoff must retain and verify every dual-source byte."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import struct
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'services/worker'),str(ROOT/'scripts/validation')]

from cpag_worker.isolated import DockerExecutor
from cpag_worker.worker import API, digest, network_refs, publication_inputs, source_flag
from cpag_core.dual_source_export import export_task, verify_task, FILES, artifact_files
from dual_source_fixtures import make_case
from round17_profile import profile


class FakeTarProcess:
    def __init__(self,data):
        self.stdout=io.BytesIO(data)
        self.returncode=0
    def wait(self,timeout=None):return 0
    def poll(self):return 0
    def kill(self):pass


class DualSourceWorkerTests(unittest.TestCase):
    def test_nested_handoff_and_claim_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);shared=base/'shared';shared.mkdir()
            paths=make_case(base/'inputs')
            source=base/'source'
            core=export_task(*paths,source,run_id='job-2',attempt_id=2)
            payload={'kind':'dual-source','config_fingerprint':core['config_fingerprint']}
            for name,path in zip(('network','process','profile'),paths):
                payload[name]={'path':str(path.relative_to(base)),'sha256':digest(path)}
            archive_buffer=io.BytesIO()
            with tarfile.open(fileobj=archive_buffer,mode='w') as archive:
                archive.add(source,arcname='.')
            worker=DockerExecutor(API('http://unused','x'),API('http://unused','y'),shared,base/'control','host')
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(archive_buffer.getvalue())):
                sha=worker.read_output('fake-container',base/'stage',payload,run_id='job-2',attempt_id=2)
            self.assertEqual(sha,digest(base/'stage/manifest.json'))
            self.assertEqual(verify_task(base/'stage'),core)
            wrapper=json.loads((base/'stage/manifest.json').read_text())
            self.assertEqual({entry['path'] for entry in wrapper['artifacts']},FILES)
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(archive_buffer.getvalue())):
                with self.assertRaisesRegex(ValueError,'identity mismatch'):
                    worker.read_output('fake-container',base/'wrong',payload,run_id='job-2',attempt_id=3)

    def test_real_multi_handoff_retains_every_ordered_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);shared=base/'shared';shared.mkdir();paths=make_case(base/'inputs')
            raw=paths[0].read_bytes();first=24+16+struct.unpack_from('<I',raw,32)[0]
            a=base/'inputs/a.pcap';b=base/'inputs/b.pcap';a.write_bytes(raw[:first]);b.write_bytes(raw[:24]+raw[first:])
            paths[2].write_text(json.dumps(profile(synthetic=False,rules=True)))
            source=base/'source';core=export_task([a,b],paths[1],paths[2],source,run_id='multi',attempt_id=1)
            ref=lambda path:{'path':str(path.relative_to(base)),'sha256':digest(path)}
            payload={'kind':'dual-source','config_fingerprint':core['config_fingerprint'],'network':ref(a),'networks':[ref(a),ref(b)],'process':ref(paths[1]),'profile':ref(paths[2])}
            self.assertEqual(source_flag(paths[2],'dual-source'),[])
            self.assertEqual(network_refs(payload),payload['networks'])
            archive_buffer=io.BytesIO()
            with tarfile.open(fileobj=archive_buffer,mode='w') as archive:archive.add(source,arcname='.')
            worker=DockerExecutor(API('http://unused','x'),API('http://unused','y'),shared,base/'control','host')
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(archive_buffer.getvalue())):
                worker.read_output('fake-container',base/'stage',payload,run_id='multi',attempt_id=1)
            wrapper=json.loads((base/'stage/manifest.json').read_text())
            self.assertEqual(wrapper['networks'],[digest(a),digest(b)])
            self.assertEqual(wrapper['inputs'],publication_inputs(payload)['inputs'])
            self.assertEqual({entry['path'] for entry in wrapper['artifacts']},artifact_files(base/'stage'))
            self.assertFalse(verify_task(base/'stage')['synthetic'])
            # A fourth-party archive cannot hide an unreferenced capture in output.
            extra=source/'dual/sources/network-002.pcap';extra.write_bytes(a.read_bytes())
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w') as archive:archive.add(source,arcname='.')
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(data.getvalue())):
                with self.assertRaisesRegex(ValueError,'unsafe output archive member'):
                    worker.read_output('fake-container',base/'extra-stage',payload,run_id='multi',attempt_id=1)

    def test_archive_rejects_nested_extra(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);shared=base/'shared';shared.mkdir()
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w') as archive:
                info=tarfile.TarInfo('./dual/sources/extra.txt');info.size=1
                archive.addfile(info,io.BytesIO(b'x'))
            worker=DockerExecutor(API('http://unused','x'),API('http://unused','y'),shared,base/'control','host')
            with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(data.getvalue())):
                with self.assertRaisesRegex(ValueError,'unsafe output archive member'):
                    worker.read_output('fake-container',base/'stage',{'kind':'dual-source'})


if __name__=='__main__':unittest.main()
