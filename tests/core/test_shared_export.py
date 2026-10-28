"""Core complete-source publisher/reader/query checks; no service integration."""
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from dual_source_fixtures import make_case
from round17_profile import profile
from cpag_core import shared_export as shared
from cpag_core.shared_artifact_store_compact import FORMAT,LogicalHasher
from cpag_core.dual_source import analyze
from cpag_core.dual_source_export import event_graph
from cpag_core.pipeline import canonical,file_hash


def fixture(root):
    network,process,path=make_case(root)
    config=profile();config.update(capacity_profile='engineering-core-capacity-3',storage_format=FORMAT)
    path.write_text(json.dumps(config))
    return network,process,path


class SharedExportTests(unittest.TestCase):
    def test_complete_offline_roots_compare_original_core_and_original_graph_all_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);paths=fixture(root/'source')
            manifest=shared.export_task(*paths,root/'output',run_id='core-independent')
            self.assertEqual(shared.verify_task(root/'output'),manifest)
            original=analyze(paths[0],paths[1],json.loads(paths[2].read_text()))
            old_graph=event_graph(original)['graph.json']
            with shared.open_reader(root/'output') as reader:
                self.assertEqual(canonical(reader.get('analysis.json')),canonical(original))
                self.assertEqual(canonical(reader.get('dual/analysis.json')),canonical(original))
                graph=reader.get('graph.json');expected=dict(old_graph);expected['graph_id']=graph['graph_id']
                self.assertEqual(canonical(graph),canonical(expected))
                self.assertEqual(graph['claims'],[row['claim'] for row in original['candidates']])
                self.assertEqual(graph['graph_id'],'dual-graph-merkle-'+LogicalHasher().digest({key:value for key,value in graph.items() if key!='graph_id'})['digest'])
            self.assertEqual({path.relative_to(root/'output').as_posix() for path in (root/'output').rglob('*') if path.is_file()},shared.artifact_files(root/'output'))
            self.assertFalse((root/'output/analysis.json').exists())

    def test_real_original_query_pagination_and_metadata_with_core_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shared.export_task(*fixture(root/'source'),root/'output')
            key=b'k'*32;approval=shared.issue_approval(root/'output',key)
            metadata=shared.metadata_task(root/'output',approval=approval,authority_key=key)
            self.assertTrue(metadata['first_operation_id']);self.assertGreater(metadata['counts']['process'],0)
            first=shared.query_task(root/'output',operation_id='first',approval=approval,authority_key=key,ref_limit=1)
            self.assertEqual(first['evidence_page']['returned'],1)
            self.assertTrue(first['verified_original_evidence'])
            reference=first['verified_original_evidence'][0]['source_ref']
            original=first['verified_original_evidence'][0]['original']
            self.assertEqual(reference['file_sha256'],original.get('file_sha256',reference['file_sha256']))
            if first['evidence_page']['has_more']:
                second=shared.query_task(root/'output',operation_id='first',approval=approval,authority_key=key,ref_offset=1,ref_limit=1)
                self.assertNotEqual(first['verified_original_evidence'],second['verified_original_evidence'])
            with self.assertRaises(KeyError):shared.query_task(root/'output',operation_id='absent',approval=approval,authority_key=key)
            with self.assertRaises(ValueError):shared.query_task(root/'output',operation_id='first',ref_limit=101,approval=approval,authority_key=key)

    def test_approval_mac_run_version_expiry_and_same_size_byte_changes_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shared.export_task(*fixture(root/'source'),root/'output',run_id='one')
            key=b'k'*32;approval=shared.issue_approval(root/'output',key)
            for mutation in ('mac','run','version','expiry'):
                with self.subTest(mutation=mutation):
                    broken=deepcopy(approval)
                    if mutation=='mac':broken['mac']='0'*64
                    else:
                        if mutation=='run':broken['payload']['run_id']='other'
                        if mutation=='version':broken['payload']['version']='future'
                        if mutation=='expiry':broken['payload'].update(issued_at=0,expires_at=1)
                        broken['mac']=hmac.new(key,canonical(broken['payload']),hashlib.sha256).hexdigest()
                    with self.assertRaises(ValueError):shared.metadata_task(root/'output',approval=broken,authority_key=key)
            target=root/'output/sources/process.csv';raw=target.read_bytes();target.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
            with self.assertRaisesRegex(ValueError,'changed'):shared.metadata_task(root/'output',approval=approval,authority_key=key)

    def test_complete_replay_source_verify_history_and_prefix_query(self):
        from round18_profile import fixture as replay_fixture
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);networks,process,path,config=replay_fixture(root/'source')
            config.update(capacity_profile='engineering-core-capacity-3',storage_format=FORMAT)
            config['replay'].update(history_format=FORMAT,identity_strategy='merkle-json-dag-1',prefix_digest_strategy='incremental-prefix-digest-2')
            path.write_text(json.dumps(config))
            manifest=shared.export_task(networks,process,path,root/'output',mode='replay')
            key=b'r'*32;approval=shared.issue_approval(root/'output',key)
            self.assertGreater(manifest['counts']['snapshots'],1)
            view=shared.query_task(root/'output',operation_id='first',approval=approval,authority_key=key)
            self.assertTrue(view['verified_original_evidence'])
            self.assertEqual(view['snapshot_id'],manifest['final_snapshot_id'])
            with self.assertRaises(KeyError):shared.query_task(root/'output',operation_id='first',snapshot=0,approval=approval,authority_key=key)
            with shared.open_reader(root/'output',approval=approval,authority_key=key) as reader:
                self.assertEqual(reader.descriptor('history/snapshots')['items'],manifest['counts']['snapshots'])
                self.assertEqual(reader.descriptor('history/revisions')['items'],manifest['counts']['revisions'])

    def test_inventory_context_and_source_rebuild_not_only_outer_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shared.export_task(*fixture(root/'source'),root/'output')
            shutil.copytree(root/'output',root/'restored')
            self.assertEqual(shared.verify_task(root/'restored'),shared.verify_task(root/'output'))
            (root/'restored/shared/extra').write_bytes(b'unregistered')
            with self.assertRaises(ValueError):shared.verify_task(root/'restored')
            (root/'restored/shared/extra').unlink()
            path=root/'restored/run_manifest.json';manifest=json.loads(path.read_text());manifest['run_id']='other';path.write_bytes(canonical(manifest)+b'\n')
            with self.assertRaises(ValueError):shared.verify_task(root/'restored')


if __name__=='__main__':unittest.main()
