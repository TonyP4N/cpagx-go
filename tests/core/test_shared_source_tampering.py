"""Rehashed storage is not source proof; every business/history value matters."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from dual_source_fixtures import make_case
from round17_profile import profile
from round18_profile import fixture as replay_fixture
from cpag_core import shared_export as core
from cpag_core.shared_artifact_store_compact import SharedArtifactWriter,FORMAT
from cpag_core.pipeline import canonical,file_hash


def build(root,mode='offline'):
    if mode=='offline':
        network,process,path=make_case(root/'inputs');config=profile()
    else:
        network,process,path,config=replay_fixture(root/'inputs')
        config['replay'].update(history_format=FORMAT,identity_strategy='merkle-json-dag-1',prefix_digest_strategy='incremental-prefix-digest-2')
    config.update(capacity_profile='engineering-core-capacity-3',storage_format=FORMAT)
    path.write_text(json.dumps(config))
    return core.export_task(network,process,path,root/'output',mode=mode,run_id='source-proof-independent')


def rehash_everything(output,mutate):
    """Adversary can forge valid DAG bytes and all unsigned outer declarations."""
    with core.open_reader(output) as reader:
        manifest=deepcopy(reader.run_manifest)
        documents={row['name']:reader.get(row['name']) for row in manifest['logical_artifacts']}
        context=deepcopy(reader.manifest['context'])
        limits=deepcopy(reader.manifest['limits'])
    mutate(documents,manifest)
    shutil.rmtree(output/'shared')
    writer=SharedArtifactWriter(output/'shared',context=context,version=FORMAT,
        max_bytes=limits['max_bytes'],max_nodes=limits['max_nodes'],max_roots=limits['max_roots'],
        max_node_bytes=limits['max_node_bytes'],max_array_items=limits['max_array_items'],max_logical_root_bytes=limits['max_logical_root_bytes'])
    for name,value in documents.items():writer.add(name,value)
    manifest['logical_artifacts']=[writer.descriptor(name) for name in documents]
    manifest['result_hashes']={key:writer.descriptor(key+'.json')['digest'] for key in ('events','graph')}
    sealed=writer.seal();manifest['shared_manifest_sha256']=sealed['manifest_sha256']
    for row in manifest['artifacts']:
        row.update(sha256=file_hash(output/row['path']),size_bytes=(output/row['path']).stat().st_size)
    (output/'run_manifest.json').write_bytes(canonical(manifest)+b'\n')


class RehashedSourceTamperTests(unittest.TestCase):
    def test_valid_rehashed_fake_analysis_cannot_get_source_verified_or_read_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);build(root)
            def mutate(documents,manifest):
                documents['analysis.json']['operations'][0]['response']['state']='error'
                documents['dual/analysis.json']=deepcopy(documents['analysis.json'])
            rehash_everything(root/'output',mutate)
            # Storage is self-consistent after the forgery, so byte/hash checks
            # alone would pass. Independent retained-source reconstruction must not.
            with core.open_reader(root/'output') as reader:
                self.assertEqual(reader.get('analysis.json',path=['operations',0,'response','state']),'error')
            with self.assertRaisesRegex(ValueError,'does_not_match_sources'):core.verify_task(root/'output')
            with self.assertRaisesRegex(ValueError,'does_not_match_sources'):core.issue_approval(root/'output',b'k'*32)

    def test_missing_history_root_mid_snapshot_and_bad_reference_are_rejected(self):
        for mutation in ('missing-root','missing-middle-snapshot','bad-original-reference'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);build(root,'replay')
                def mutate(documents,manifest):
                    if mutation=='missing-root':
                        del documents['history/revisions']
                    elif mutation=='missing-middle-snapshot':
                        rows=documents['history/snapshots'];self.assertGreater(len(rows),3)
                        del rows[len(rows)//2]
                        # Even making the count declaration agree cannot hide the
                        # omitted historical business state from source rebuilding.
                        manifest['counts']['snapshots']=len(rows)
                    else:
                        rows=documents['history/snapshots'];changed=False
                        for snapshot in rows:
                            refs=snapshot['trigger']['evidence_refs']
                            if refs:
                                refs[0]['record_sha256']='d'*64;changed=True;break
                        self.assertTrue(changed)
                rehash_everything(root/'output',mutate)
                with self.assertRaises(ValueError):core.verify_task(root/'output')
                with self.assertRaises(ValueError):core.issue_approval(root/'output',b'k'*32)

    def test_real_historical_dual_and_default_replay_reader_are_preserved(self):
        from cpag_core.dual_source_export import verify_task as old_verify,query_task as old_query
        from cpag_core.replay_export import export_task as old_export,verify_task as old_replay_verify,snapshot_task
        retained=ROOT/'tests/fixtures/r17-response-clock-v1'
        manifest=old_verify(retained)
        self.assertEqual(manifest['mode'],'offline')
        self.assertTrue(old_query(retained,operation_id='first')['verified_original_evidence'])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);network,process,path,_=replay_fixture(root/'inputs')
            result=old_export(network,process,path,root/'old')
            self.assertEqual(old_replay_verify(root/'old'),result)
            self.assertTrue((root/'old/snapshots.jsonl').is_file())
            self.assertNotIn('storage_format',result)
            self.assertIn('analysis',snapshot_task(root/'old',0))


if __name__=='__main__':unittest.main()
