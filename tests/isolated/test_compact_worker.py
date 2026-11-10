"""DAG6 handoff, private service authority and bounded query integration."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'services/worker'),str(ROOT/'tests/core'),str(ROOT/'scripts/validation')]
from cpag_core import shared_export as core
from cpag_core import shared_service as service
from cpag_core.pipeline import fingerprint
from cpag_worker.isolated import DockerExecutor
from cpag_worker.worker import API, digest, compact_payload
from test_dual_source_worker import FakeTarProcess
from test_shared_export import fixture


class CompactServiceWorkerTests(unittest.TestCase):
    def prepare(self,base,mode='offline'):
        if mode=='replay':
            from round18_profile import fixture as replay_fixture
            n,p,c,config=replay_fixture(base/'inputs')
            config.update(capacity_profile=service.CAPACITY,storage_format=core.FORMAT)
            config['replay'].update(history_format=core.FORMAT,identity_strategy='merkle-json-dag-1',prefix_digest_strategy='incremental-prefix-digest-2')
            c.write_text(json.dumps(config))
        else:n,p,c=fixture(base/'inputs')
        config=json.loads(c.read_text());config['storage_budget_version']='shared-storage-budget-2';c.write_text(json.dumps(config))
        source=base/'source';manifest=core.export_task(n,p,c,source,run_id='compact',attempt_id=1,mode=mode)
        ref=lambda path:{'path':str(path.relative_to(base)),'sha256':digest(path)}
        payload={'kind':'dual-source','config_fingerprint':manifest['config_fingerprint'], 'capacity_profile':service.CAPACITY,
                 'resource_profile':service.RESOURCE,'storage_format':core.FORMAT,'storage_budget_version':service.BUDGET,
                 'network':ref(n[0] if isinstance(n,list) else n),'process':ref(p),'profile':ref(c)}
        if isinstance(n,list):payload['networks']=[ref(path) for path in n]
        if mode=='replay':payload.update(kind='dual-source-replay',replay_version='dual-source-replay-1',history_format=core.FORMAT)
        shared=base/'shared';shared.mkdir()
        worker=DockerExecutor(API('http://unused','w'),API('http://unused','c'),shared,base/'control','host',resource_profile=service.RESOURCE)
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as archive:archive.add(source,arcname='.')
        target=shared/'jobs/compact/attempt-1';target.parent.mkdir(parents=True)
        with patch('cpag_worker.isolated.subprocess.Popen',return_value=FakeTarProcess(data.getvalue())),patch('cpag_worker.isolated.shutil.disk_usage',return_value=SimpleNamespace(free=100*1024**3)),patch.object(core,'verify_task',side_effect=AssertionError('worker must not repeat source verification')):
            sha=worker.read_output('fake',target,payload,run_id='compact',attempt_id=1)
        binding=worker.compact_binding(payload,'compact',1)
        return worker,target,payload,binding,sha

    def test_complete_handoff_private_verifier_queries_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            worker,target,payload,binding,sha=self.prepare(Path(directory))
            self.assertEqual((worker.memory_bytes,worker.cpus,worker.temporary_bytes,worker.output_bytes),(8*1024**3,'4',4*1024**3,1024**3))
            publication=json.loads((target/'manifest.json').read_text())
            self.assertEqual(publication['run_id'],'compact')
            self.assertEqual({row['path'] for row in publication['artifacts']},core.artifact_files(target))
            key=b'x'*32
            checked=service.verify(target,binding,key)
            self.assertEqual(checked['verification_report']['status'],'passed')
            # The service content-addressed publication anchor is additional trusted envelope bytes only.
            (target/(sha+'.json')).write_bytes((target/'manifest.json').read_bytes())
            with patch.object(core,'verify_task',side_effect=AssertionError('reads must reuse service verification')):
                metadata=service.query(target,binding,checked['approval'],key,{'action':'metadata'})
                self.assertEqual(metadata['manifest']['run_id'],'compact')
                page=service.query(target,binding,checked['approval'],key,{'action':'page','logical_root':'analysis.json','path':['operations'],'limit':1})
                self.assertTrue(page)
                with self.assertRaises(ValueError):service.query(target,binding,checked['approval'],key,{'action':'page','logical_root':'analysis.json','path':['operations'],'limit':101})
            with self.assertRaisesRegex(ValueError,'mac_invalid'):
                service.query(target,binding,checked['approval'],b'y'*32,{'action':'metadata'})
            bad=dict(binding,attempt_id=2)
            with self.assertRaisesRegex(ValueError,'attempt_binding'):
                service.query(target,bad,checked['approval'],key,{'action':'metadata'})
            (target/'sources/process.csv').write_bytes((target/'sources/process.csv').read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError,'artifact_changed'):
                service.query(target,binding,checked['approval'],key,{'action':'metadata'})

    def test_replay_history_and_raw_evidence_are_bound_to_selected_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            worker,target,payload,binding,sha=self.prepare(Path(directory),mode='replay')
            key=b'r'*32;checked=service.verify(target,binding,key)
            manifest=checked['metadata']['manifest']
            selected=service.query(target,binding,checked['approval'],key,{'action':'evidence','operation':'first'})
            self.assertEqual(selected['snapshot_id'],manifest['final_snapshot_id'])
            self.assertTrue(selected['verified_original_evidence'])
            snapshot=service.query(target,binding,checked['approval'],key,{'action':'snapshot','snapshot':manifest['final_snapshot_number'],'path':['snapshot_id']})
            self.assertEqual(snapshot,manifest['final_snapshot_id'])
            with self.assertRaises(ValueError):
                service.query(target,binding,checked['approval'],key,{'action':'snapshot','snapshot':manifest['counts']['snapshots']})
            with self.assertRaisesRegex(ValueError,'inventory'):
                core.verify_task(target)

    def test_private_stdin_docker_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            worker,target,payload,binding,sha=self.prepare(Path(directory))
            request={'authority_key':('ab'*32),'request':{'action':'verify','output_dir':str(target),'binding':binding}}
            result=subprocess.run([sys.executable,'-m','cpag_core.shared_service','--key-stdin'],input=json.dumps(request),text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={**__import__('os').environ,'PYTHONPATH':str(ROOT/'services/analysis/src')},timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['approval']['payload']['version'],service.VERSION)

    def test_version_mismatch_and_pending_completion_are_fail_closed(self):
        with self.assertRaises(ValueError):compact_payload({'capacity_profile':service.CAPACITY})
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);worker=DockerExecutor(None,None,base/'shared',base/'control','host');worker.api=SimpleNamespace(post=lambda *a:{});worker.publication_api=SimpleNamespace(post=__import__('unittest.mock').mock.Mock(side_effect=[{'verification_pending':True},{'state':'succeeded'}]))
            with patch('cpag_worker.isolated.time.sleep'):
                worker.complete({'id':'compact','worker':'host','attempt':1,'token':'private'},'a'*64)
            self.assertEqual(worker.publication_api.post.call_count,2)


if __name__=='__main__':unittest.main()
