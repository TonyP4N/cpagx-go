"""Run-manifest classification and final-history metadata must match source roots."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from dual_source_fixtures import make_case
from round17_profile import profile
from round18_profile import fixture as replay_fixture
from cpag_core import shared_export as core
from cpag_core.shared_artifact_store_compact import FORMAT
from cpag_core.pipeline import canonical


def build(root,mode):
    if mode=='offline':
        network,process,path=make_case(root/'inputs');config=profile()
    else:
        network,process,path,config=replay_fixture(root/'inputs')
        config['replay'].update(history_format=FORMAT,identity_strategy='merkle-json-dag-1',prefix_digest_strategy='incremental-prefix-digest-2')
    config.update(capacity_profile='engineering-core-capacity-3',storage_format=FORMAT)
    path.write_text(json.dumps(config))
    core.export_task(network,process,path,root/'artifact',mode=mode,run_id='manifest-binding-independent')
    return root/'artifact'


def mutate(root,field,value):
    path=root/'run_manifest.json';manifest=json.loads(path.read_text())
    original_artifacts=deepcopy(manifest['artifacts']);original_roots=deepcopy(manifest['logical_artifacts'])
    manifest[field]=value;path.write_bytes(canonical(manifest)+b'\n')
    assert manifest['artifacts']==original_artifacts and manifest['logical_artifacts']==original_roots


class ManifestBindingTests(unittest.TestCase):
    def test_prior_capability_requires_reverification_but_artifact_remains_readable(self):
        import hashlib,hmac
        with tempfile.TemporaryDirectory() as directory:
            artifact=build(Path(directory),'offline');key=b'k'*32
            approval=core.issue_approval(artifact,key)
            self.assertEqual(approval['payload']['version'],'core-read-approval-2')
            approval['payload']['version']='core-read-approval-1'
            approval['mac']=hmac.new(key,canonical(approval['payload']),hashlib.sha256).hexdigest()
            with self.assertRaisesRegex(ValueError,'version_invalid'):
                core.metadata_task(artifact,approval=approval,authority_key=key)
            self.assertTrue(core.verify_task(artifact)['synthetic'])
            current=core.issue_approval(artifact,key)
            self.assertEqual(core.metadata_task(artifact,approval=current,authority_key=key)['mode'],'offline')

    def test_synthetic_classification_cannot_be_forged_without_changing_sources(self):
        for mode in ('offline','replay'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                artifact=build(Path(directory),mode);mutate(artifact,'synthetic',False)
                for action in ('verify','issue_approval'):
                    with self.subTest(action=action),self.assertRaises(ValueError):
                        core.verify_task(artifact) if action=='verify' else core.issue_approval(artifact,b'k'*32)

    def test_final_snapshot_number_and_id_must_match_complete_history(self):
        for field,value in (('final_snapshot_number',0),('final_snapshot_id','snapshot-'+'f'*64)):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as directory:
                artifact=build(Path(directory),'replay');mutate(artifact,field,value)
                for action in ('verify','issue_approval'):
                    with self.subTest(action=action),self.assertRaises(ValueError):
                        core.verify_task(artifact) if action=='verify' else core.issue_approval(artifact,b'k'*32)



class LogicalRootInventoryBinding(unittest.TestCase):
    def test_unregistered_rehashed_logical_root_cannot_get_approval(self):
        from test_shared_source_tampering import build,rehash_everything
        from cpag_core.pipeline import canonical
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);build(root)
            rehash_everything(root/'output',lambda documents,manifest:documents.update({'undeclared-root':{'claim':'not reconstructed from source'}}))
            p=root/'output/run_manifest.json';manifest=json.loads(p.read_text())
            manifest['logical_artifacts']=[row for row in manifest['logical_artifacts'] if row['name']!='undeclared-root']
            p.write_bytes(canonical(manifest)+b'\n')
            with self.assertRaises(ValueError):core.verify_task(root/'output')
            with self.assertRaises(ValueError):core.issue_approval(root/'output',b'k'*32)

if __name__=='__main__':unittest.main()
