import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('backup_bundle',REPO/'scripts/backup/bundle.py')
bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle)
from cpag_core.pipeline import run,canonical,fingerprint


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'shared';self.root.mkdir()
        payload={}
        for role,src in [('network','tests/fixtures/synthetic/network.normalized.jsonl'),('process','tests/fixtures/synthetic/process.csv'),('profile','profiles/synthetic-demo.json')]:
            target=self.root/(role+Path(src).suffix);shutil.copyfile(REPO/src,target)
            payload[role]={'path':target.name,'sha256':bundle.sha(target)}
        out=self.root/'jobs/test/attempt-1'
        core=run(*(self.root/payload[k]['path'] for k in ('network','process','profile')),out,synthetic=True)
        payload['config_fingerprint']=core['config_fingerprint']
        self.row={'id':'test','state':'succeeded','payload':payload,'artifact_path':'jobs/test/attempt-1/manifest.json'}
        self.out=out;self.refresh()

    def refresh(self):
        core=json.loads((self.out/'run_manifest.json').read_text())
        for a in core['artifacts']:
            p=self.out/a['path'];a.update(sha256=bundle.sha(p),size_bytes=p.stat().st_size)
        core['result_hashes']={'events':fingerprint(json.loads((self.out/'events.json').read_text())),
                               'graph':fingerprint(json.loads((self.out/'graph.json').read_text()))}
        (self.out/'run_manifest.json').write_bytes(canonical(core)+b'\n')
        wrapper={'inputs':{k:self.row['payload'][k]['sha256'] for k in ('network','process','profile')},
                 'config_fingerprint':core['config_fingerprint'],'artifacts':[]}
        for name in ('dataset.json','events.json','graph.json','quality.json','run_manifest.json'):
            p=self.out/name;wrapper['artifacts'].append({'path':name,'sha256':bundle.sha(p),'size':p.stat().st_size})
        manifest=self.out/'manifest.json';manifest.write_text(json.dumps(wrapper))
        self.row['artifact_sha256']=bundle.sha(manifest)

    def test_original_records_graph_and_orphans(self):
        (self.root/'retained-orphan.log').write_text('diagnostic')
        result=bundle.audit([self.row],self.root)
        self.assertTrue(result['valid'],result)
        self.assertEqual(result['unreferenced_files'],['retained-orphan.log'])
        self.assertTrue((self.root/'retained-orphan.log').exists())

    def test_missing_and_tampered_files(self):
        p=self.out/'events.json';original=p.read_bytes();p.unlink()
        self.assertFalse(bundle.audit([self.row],self.root)['valid'])
        p.write_bytes(original+b' ')
        self.assertFalse(bundle.audit([self.row],self.root)['valid'])

    def test_rehashed_invalid_record_reference_rejected(self):
        p=self.out/'events.json';events=json.loads(p.read_text());events[0]['source_ref']['record_number']=999
        p.write_text(json.dumps(events));self.refresh()
        result=bundle.audit([self.row],self.root)
        self.assertFalse(result['valid']);self.assertIn('logical record',result['errors'][0]['reason'])

    def test_rehashed_graph_reference_rejected(self):
        p=self.out/'graph.json';graph=json.loads(p.read_text());graph['nodes'][0]['evidence_refs'][0]['raw_time']='wrong'
        p.write_text(json.dumps(graph));self.refresh()
        result=bundle.audit([self.row],self.root)
        self.assertFalse(result['valid']);self.assertIn('evidence differs',result['errors'][0]['reason'])

    def test_nonterminal_and_path_escape(self):
        row=copy.deepcopy(self.row);row['state']='running'
        self.assertFalse(bundle.audit([row],self.root)['valid'])
        row=copy.deepcopy(self.row);row['payload']['network']['path']='../escape'
        self.assertFalse(bundle.audit([row],self.root)['valid'])
        (self.root/'symlink').symlink_to(self.out/'events.json')
        with self.assertRaisesRegex(ValueError,'symlink'):bundle.inventory(self.root)

    def test_restore_tampering_reports_before_database_mutation(self):
        source=Path(self.tmp.name)/'bundle';source.mkdir();shutil.copytree(self.root,source/'files')
        (source/'database.dump').write_bytes(b'synthetic fake dump, never executed')
        manifest={'format_version':1,'synthetic_validation_only':True,'rows':[self.row],
                  'database_sha256':bundle.sha(source/'database.dump'),'files':bundle.inventory(source/'files')}
        (source/'bundle.json').write_text(json.dumps(manifest))
        (source/'files/network.jsonl').write_text('TAMPERED')
        dest=Path(self.tmp.name)/'restore'
        with patch.object(bundle.subprocess,'run') as call:
            with self.assertRaisesRegex(ValueError,'integrity'):bundle.restore('unused',source,dest)
            call.assert_not_called()
        report=json.loads((Path(str(dest)+'-audit.json')).read_text())
        self.assertFalse(report['valid']);self.assertEqual(report['phase'],'bundle_integrity')
        self.assertFalse(dest.exists())

    def test_restore_inventory_difference_is_failure_with_report(self):
        source=Path(self.tmp.name)/'bundle';source.mkdir();shutil.copytree(self.root,source/'files')
        (source/'database.dump').write_bytes(b'fake dump, pg call mocked')
        manifest={'format_version':1,'synthetic_validation_only':True,'rows':[self.row],
                  'database_sha256':bundle.sha(source/'database.dump'),'files':bundle.inventory(source/'files')}
        (source/'bundle.json').write_text(json.dumps(manifest))
        dest=Path(self.tmp.name)/'restore'
        original_copy=shutil.copytree
        def mutated_copy(src,target,*args,**kwargs):
            result=original_copy(src,target,*args,**kwargs)
            (Path(target)/'unexpected-file').write_text('simulated restore-time write')
            return result
        with patch.object(bundle.subprocess,'run'),patch.object(bundle,'pg'),\
             patch.object(bundle,'rows_now',return_value=[self.row]),\
             patch.object(bundle.shutil,'copytree',side_effect=mutated_copy):
            with self.assertRaisesRegex(ValueError,'inventory differs'):
                bundle.restore('unused',source,dest)
        report=json.loads(Path(str(dest)+'-audit.json').read_text())
        self.assertFalse(report['valid'])
        self.assertTrue((dest/'unexpected-file').exists())
