"""Terminal replay bundles retain every immutable snapshot and version binding."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import test_catalog as catalog
bundle=catalog.bundle
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts/validation'))
from round18_profile import fixture
from cpag_core.replay_export import export_task,artifact_files_for_inputs,query_task
from cpag_core.pipeline import canonical,fingerprint

class ReplayBundleTests(unittest.TestCase):
    def make(self,root,history_format=None,*,run_id='replay'):
        n,p,c,config=fixture(root/'inputs')
        if history_format is not None:
            config['replay']['history_format']=history_format;c.write_text(json.dumps(config))
        ref=lambda path:{'path':path.relative_to(root).as_posix(),'sha256':bundle.sha(path)}
        payload={'kind':'dual-source-replay','replay_version':'dual-source-replay-1','network':ref(n[0]),'networks':[ref(x) for x in n],
                 'process':ref(p),'profile':ref(c),'config_fingerprint':fingerprint(config)}
        if history_format is not None:payload['history_format']=history_format
        out=root/'jobs'/run_id/'attempt-1';export_task(n,p,c,out,run_id=run_id,attempt_id=1)
        wrapper={'inputs':{k:payload[k]['sha256'] for k in ('network','process','profile')},
                 'networks':[r['sha256'] for r in payload['networks']],'config_fingerprint':payload['config_fingerprint'],
                 'replay_version':'dual-source-replay-1','artifacts':[{'path':name,'sha256':bundle.sha(out/name),'size':(out/name).stat().st_size} for name in sorted(artifact_files_for_inputs(2,history_format=history_format))]}
        if history_format is not None:wrapper['history_format']=history_format
        publication=out/'manifest.json';publication.write_bytes(canonical(wrapper)+b'\n');digest=bundle.sha(publication);(out/(digest+'.json')).write_bytes(publication.read_bytes())
        return {'id':run_id,'state':'succeeded','attempt':1,'payload':payload,'artifact_path':(out/(digest+'.json')).relative_to(root).as_posix(),'artifact_sha256':digest},out

    def test_replay_terminal_copy_preserves_history_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source';root.mkdir();row,out=self.make(root)
            self.assertTrue(bundle.audit([row],root)['valid'])
            destination=Path(tmp)/'restored';shutil.copytree(root,destination)
            self.assertTrue(bundle.audit([row],destination)['valid'])
            for name in ('snapshots.jsonl','revisions.jsonl','arrivals.jsonl'):
                self.assertEqual((out/name).read_bytes(),(destination/'jobs/replay/attempt-1'/name).read_bytes())
            snapshots=[json.loads(l) for l in (out/'snapshots.jsonl').read_text().splitlines()]
            pending=next(s for s in snapshots if any(o['replay']['status']=='pending_response' for o in s['analysis']['operations']))
            before=query_task(out,pending['snapshot_number'],operation_id='first')
            after=query_task(destination/'jobs/replay/attempt-1',pending['snapshot_number'],operation_id='first')
            self.assertEqual(before,after);self.assertTrue(after['verified_original_evidence'])

    def test_missing_or_rehashed_history_and_wrong_version_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);row,out=self.make(root)
            revised=copy.deepcopy(row);revised['payload']['replay_version']='unknown'
            self.assertFalse(bundle.audit([revised],root)['valid'])
            path=out/'snapshots.jsonl';original=path.read_bytes();path.write_bytes(original.splitlines(keepends=True)[0])
            self.assertFalse(bundle.audit([row],root)['valid'])
            path.write_bytes(original);(out/'sources/network-001.pcap').write_bytes(b'changed')
            self.assertFalse(bundle.audit([row],root)['valid'])

class ReplayCatalogBindingTests(unittest.TestCase):
    setUp=catalog.CatalogBackupTests.setUp
    add_preflight=catalog.CatalogBackupTests.add_preflight
    def make_replay(self):
        config=self.catalog['v3_config_versions'][0];doc=config['profile_json'];doc['replay']={'version':'dual-source-replay-1'}
        path=self.root/config['profile_storage_path'];path.write_bytes(canonical(doc)+b'\n')
        config.update(profile_sha256=bundle.sha(path),config_fingerprint=fingerprint(doc));self.job['payload']['profile']['sha256']=config['profile_sha256'];self.job['payload']['config_fingerprint']=config['config_fingerprint']
        self.job['payload'].update(kind='dual-source-replay',replay_version='dual-source-replay-1')
        self.catalog['v3_run_bindings'][0].update(mode='dual_source_replay',replay_version='dual-source-replay-1')
    def test_replay_mode_profile_and_payload_versions_are_bound(self):
        self.make_replay();self.assertTrue(bundle.audit_catalog(self.catalog,[self.job],self.root)['valid'])
        for target in (self.catalog['v3_run_bindings'][0],self.job['payload']):
            before=target['replay_version'];target['replay_version']='unknown'
            self.assertFalse(bundle.audit_catalog(self.catalog,[self.job],self.root)['valid']);target['replay_version']=before
        self.catalog['v3_run_bindings'][0]['mode']='dual_source'
        self.assertFalse(bundle.audit_catalog(self.catalog,[self.job],self.root)['valid'])
