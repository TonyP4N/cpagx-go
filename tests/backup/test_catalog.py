import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('backup_bundle',REPO/'scripts/backup/bundle.py')
bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle)
from cpag_core.pipeline import fingerprint


class CatalogBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'shared';self.root.mkdir()
        data=self.root/'inputs/catalog/d1';data.mkdir(parents=True)
        (data/'profiles').mkdir()
        sources={}
        for role,source in [('network','docs/refactor/validation-round4/protocol-synthetic.pcap'),
                            ('process','tests/fixtures/synthetic/process.csv'),
                            ('profile','profiles/synthetic-demo.json')]:
            path=data/('profiles/cfg1.json' if role=='profile' else role+Path(source).suffix)
            shutil.copyfile(REPO/source,path)
            sources[role]={'path':path.relative_to(self.root).as_posix(),'sha256':bundle.sha(path)}
        profile=json.loads((self.root/sources['profile']['path']).read_text())
        self.job={'id':'catalog-job','state':'cancelled','attempt':0,'payload':{
            'kind':'dual-source',**sources,'config_fingerprint':fingerprint(profile)}}
        self.catalog={table:[] for table in bundle.CATALOG_TABLES}
        self.catalog['v3_users']=[{'id':'u1','username':'analyst','role':'analyst'}]
        self.catalog['v3_sessions']=[{'id':'session-1','user_id':'u1'}]
        self.catalog['v3_datasets']=[{'id':'d1','created_by':'u1','source_kind':'synthetic',
            'verification_status':'metadata_checked','source':'synthetic fixture',
            'batch':'1','authorization_ref':'fixture permission'}]
        for role in ('network','process'):
            ref=sources[role];file=self.root/ref['path']
            self.catalog['v3_source_files'].append({'id':role,'storage_path':ref['path'],
                'sha256':ref['sha256'],'size_bytes':file.stat().st_size,
                'created_at':'2026-10-27T00:00:00Z'})
            self.catalog['v3_dataset_files'].append({'id':role+'-link','dataset_id':'d1',
                'source_file_id':role,'role':role,'filename':Path(ref['path']).name,'created_by':'u1',
                'created_at':'2026-10-27T00:00:00Z'})
        self.catalog['v3_config_versions']=[{'id':'cfg1','dataset_id':'d1','kind':'dual','version':1,
            'profile_storage_path':sources['profile']['path'],'profile_sha256':sources['profile']['sha256'],
            'config_fingerprint':fingerprint(profile),'profile_json':profile,'created_by':'u1',
            'created_at':'2026-10-27T00:00:00Z'}]
        self.catalog['v3_run_bindings']=[{'job_id':'catalog-job','dataset_id':'d1',
            'network_file_id':'network-link','process_file_id':'process-link',
            'config_version_id':'cfg1','mode':'dual_source','created_by':'u1',
            'preflight_id':'p1','preflight_link_origin':'native_gate','preflight_link_reason':None,
            'created_at':'2026-10-27T00:02:00Z'}]
        self.add_preflight()
        self.catalog['v3_audit_events']=[{'id':1,'user_id':'u1','dataset_id':'d1',
            'job_id':'catalog-job','details':{'action':'run'}}]

    def add_preflight(self):
        intake={'dataset_id':'d1','synthetic':True,
            'authorization':{'allowed_use':'test','evidence_ref':'fixture','reviewer':'tester'},
            'time_basis':{'timezone':'UTC','precision':'seconds','synchronization':'fixture','evidence_ref':'fixture'},
            'mapping':{'field_units_ref':'fixture','device_map_ref':'fixture','effective_period_ref':'fixture'}}
        path=self.root/'inputs/catalog/d1/profiles/intakecfg.json'
        path.write_bytes(bundle.canonical(intake)+b'\n')
        config={'id':'intakecfg','dataset_id':'d1','kind':'intake','version':1,
            'profile_storage_path':path.relative_to(self.root).as_posix(),
            'profile_sha256':bundle.sha(path),'config_fingerprint':fingerprint(intake),
            'profile_json':intake,'created_by':'u1','created_at':'2026-10-27T00:00:00Z'}
        self.catalog['v3_config_versions'].append(config)
        files=[];manifest_files=[]
        for link in sorted(self.catalog['v3_dataset_files'],key=lambda item:item['id']):
            source=next(item for item in self.catalog['v3_source_files'] if item['id']==link['source_file_id'])
            files.append({'dataset_file_id':link['id'],'source_file_id':source['id'],
                'role':link['role'],'filename':link['filename'],'path':source['storage_path'],
                'sha256':source['sha256'],'size_bytes':source['size_bytes']})
            manifest_files.append({'name':source['storage_path'],'sha256':source['sha256'],
                'size_bytes':source['size_bytes'],'kind':link['role']})
        dataset={key:self.catalog['v3_datasets'][0][key] for key in
                 ('id','source_kind','source','batch','authorization_ref')}
        manifest={'schema_version':'1.0.0','synthetic':True,'dataset_id':'d1',
            'source':dataset['source'],'release':dataset['batch'],'files':manifest_files,
            'collection_range':{'start':None,'end':None},'timezone_basis':None,
            'authorization_ref':dataset['authorization_ref']}
        manifest_path=Path(self.temp.name)/'manifest.json'
        manifest_path.write_bytes(bundle.canonical(manifest)+b'\n')
        report=bundle.verify_intake_preflight(self.root,manifest_path,path)
        snapshot={'schema_version':'v3-preflight-snapshot-1','origin':'native',
            'dataset':dataset,'files':files,'config':{'id':config['id'],'kind':'intake',
            'version':config['version'],'path':config['profile_storage_path'],
            'sha256':config['profile_sha256'],'fingerprint':config['config_fingerprint'],
            'document':intake},'manifest':manifest}
        raw=json.dumps(snapshot,sort_keys=True,separators=(',',':'),ensure_ascii=False)
        self.catalog['v3_preflights']=[{'id':'p1','dataset_id':'d1','config_version_id':'intakecfg',
            'created_by':'u1','report':report,'snapshot_json':raw,
            'snapshot_sha256':hashlib.sha256(raw.encode()).hexdigest(),
            'snapshot_status':'native','snapshot_reason':None,
            'created_at':'2026-10-27T00:01:00Z'}]

    def audited(self,catalog=None):
        return bundle.audit_catalog(catalog if catalog is not None else self.catalog,[self.job],self.root)

    def test_empty_v3_tables_do_not_change_legacy_m4_backup(self):
        empty={table:[] for table in bundle.CATALOG_TABLES}
        report=bundle.audit_catalog(empty,[],self.root)
        self.assertTrue(report['valid'],report)
        self.assertEqual(report['referenced_files'],[])

    def test_catalog_includes_unused_originals_and_versions(self):
        unused=self.root/'inputs/catalog/d1/unused.pcap';unused.write_bytes(b'unused synthetic original')
        self.catalog['v3_source_files'].append({'id':'unused','storage_path':'inputs/catalog/d1/unused.pcap',
            'sha256':bundle.sha(unused),'size_bytes':unused.stat().st_size,
            'created_at':'2026-10-27T00:03:00Z'})
        self.catalog['v3_dataset_files'].append({'id':'unused-link','dataset_id':'d1',
            'source_file_id':'unused','role':'network','filename':'unused.pcap','created_by':'u1',
            'created_at':'2026-10-27T00:03:00Z'})
        newer={'dataset_id':'d1','synthetic':True,'revision':'after-first-preflight'}
        newer_path=self.root/'inputs/catalog/d1/profiles/intakecfg2.json'
        newer_path.write_bytes(bundle.canonical(newer)+b'\n')
        self.catalog['v3_config_versions'].append({'id':'intakecfg2','dataset_id':'d1',
            'kind':'intake','version':2,'profile_storage_path':'inputs/catalog/d1/profiles/intakecfg2.json',
            'profile_sha256':bundle.sha(newer_path),'config_fingerprint':fingerprint(newer),
            'profile_json':newer,'created_by':'u1','created_at':'2026-10-27T00:03:00Z'})
        result=self.audited()
        self.assertTrue(result['valid'],result)
        self.assertEqual(set(result['referenced_files']),{
            'inputs/catalog/d1/network.pcap','inputs/catalog/d1/process.csv',
            'inputs/catalog/d1/profiles/cfg1.json',
            'inputs/catalog/d1/profiles/intakecfg.json',
            'inputs/catalog/d1/profiles/intakecfg2.json','inputs/catalog/d1/unused.pcap'})
        self.catalog['v3_run_bindings']=[]
        self.assertFalse(self.audited()['valid'])
        self.assertIn('lacks run ownership binding',str(self.audited()['errors']))
        self.catalog['v3_run_bindings']=[{'job_id':'catalog-job','dataset_id':'d1',
            'network_file_id':'network-link','process_file_id':'process-link',
            'config_version_id':'cfg1','mode':'dual_source','created_by':'u1',
            'preflight_id':'p1','preflight_link_origin':'native_gate','preflight_link_reason':None,
            'created_at':'2026-10-27T00:02:00Z'}]
        (self.root/'inputs/catalog/d1/profiles/cfg1.json').unlink()
        result=self.audited()
        self.assertFalse(result['valid']);self.assertIn('missing catalog file',str(result['errors']))

    def test_dangling_ownership_and_payload_forgery_rejected(self):
        for table,key,value in [('v3_dataset_files','dataset_id','wrong'),
                                ('v3_run_bindings','network_file_id','process-link'),
                                ('v3_run_bindings','config_version_id','wrong')]:
            changed=copy.deepcopy(self.catalog);changed[table][0][key]=value
            self.assertFalse(self.audited(changed)['valid'],(table,key))
        self.job['payload']['network']['sha256']='0'*64
        self.assertFalse(self.audited()['valid'])

    def test_preflight_is_recomputed_from_originals(self):
        self.assertTrue(self.audited()['valid'],self.audited())
        self.catalog['v3_preflights'][0]['report']['status']='forged'
        self.assertFalse(self.audited()['valid'])

    def test_snapshot_bytes_refs_and_legacy_status_cannot_pass(self):
        baseline=self.catalog['v3_preflights'][0]
        changed=copy.deepcopy(self.catalog)
        changed['v3_preflights'][0]['snapshot_json']+=' '
        self.assertFalse(self.audited(changed)['valid'])
        changed=copy.deepcopy(self.catalog)
        row=changed['v3_preflights'][0]
        snapshot=json.loads(row['snapshot_json'])
        snapshot['files'][0]['sha256']='0'*64
        row['snapshot_json']=json.dumps(snapshot,separators=(',',':'),sort_keys=True)
        row['snapshot_sha256']=hashlib.sha256(row['snapshot_json'].encode()).hexdigest()
        self.assertFalse(self.audited(changed)['valid'])
        changed=copy.deepcopy(self.catalog)
        changed['v3_preflights'][0].update(snapshot_json=None,snapshot_sha256=None,
            snapshot_status='unreconstructable',snapshot_reason='historical input set ambiguous')
        report=self.audited(changed)
        self.assertFalse(report['valid'])
        self.assertIn('unverified legacy',str(report['errors']))
        changed=copy.deepcopy(self.catalog)
        changed['v3_run_bindings'][0].update(preflight_id=None,
            preflight_link_origin='legacy_unbound',preflight_link_reason='old run')
        self.assertFalse(self.audited(changed)['valid'])
        changed=copy.deepcopy(self.catalog)
        changed['v3_preflights'][0]['created_at']='2026-10-27T00:04:00Z'
        self.assertFalse(self.audited(changed)['valid'])
        changed=copy.deepcopy(self.catalog)
        changed['v3_dataset_files'][0]['created_at']='2026-10-27T00:04:00Z'
        self.assertFalse(self.audited(changed)['valid'])
        self.assertEqual(baseline['snapshot_status'],'native')

    def test_reconstructed_history_is_labeled_inferred(self):
        changed=copy.deepcopy(self.catalog)
        row=changed['v3_preflights'][0]
        snapshot=json.loads(row['snapshot_json']);snapshot['origin']='reconstructed'
        row['snapshot_json']=json.dumps(snapshot,separators=(',',':'),sort_keys=True)
        row['snapshot_sha256']=hashlib.sha256(row['snapshot_json'].encode()).hexdigest()
        row['snapshot_status']='reconstructed'
        changed['v3_run_bindings'][0]['preflight_link_origin']='reconstructed_match'
        self.assertTrue(self.audited(changed)['valid'],self.audited(changed))
        changed['v3_run_bindings'][0]['preflight_link_origin']='native_gate'
        self.assertFalse(self.audited(changed)['valid'])

    def test_later_verification_status_does_not_rewrite_preflight_inputs(self):
        changed=copy.deepcopy(self.catalog)
        changed['v3_datasets'][0]['verification_status']='rejected'
        self.assertTrue(self.audited(changed)['valid'],self.audited(changed))

    def test_tampered_profile_even_with_updated_hash_rejected(self):
        config=self.catalog['v3_config_versions'][0]
        profile_path=self.root/'inputs/catalog/d1/profiles/cfg1.json'
        profile=json.loads(profile_path.read_text())
        profile['synthetic']=False
        profile_path.write_text(json.dumps(profile))
        config['profile_sha256']=bundle.sha(profile_path)
        self.assertFalse(self.audited()['valid'])

    def test_manifest_projection_never_contains_auth_verifiers(self):
        changed=copy.deepcopy(self.catalog)
        changed['v3_users'][0]['password_hash']='secret'
        self.assertFalse(self.audited(changed)['valid'])
        changed=copy.deepcopy(self.catalog)
        changed['v3_sessions'][0]['token_hash']='secret'
        self.assertFalse(self.audited(changed)['valid'])
        self.assertNotIn('secret',json.dumps(self.audited(changed)))
        self.assertIn("- 'token_hash'",bundle.catalog_query('v3_sessions'))
        changed=copy.deepcopy(self.catalog)
        changed['v3_audit_events'][0]['details']={'nested':{'token':'secret'}}
        self.assertFalse(self.audited(changed)['valid'])
        self.assertNotIn('secret',json.dumps(self.audited(changed)))

    def test_restore_revokes_sessions_before_file_copy(self):
        source=Path(self.temp.name)/'bundle';source.mkdir()
        shutil.copytree(self.root,source/'files')
        (source/'database.dump').write_bytes(b'mocked dump')
        manifest={'format_version':4,'synthetic_validation_only':True,'rows':[self.job],
                  'attempts':[],'catalog':self.catalog,'database_sha256':bundle.sha(source/'database.dump'),
                  'files':bundle.inventory(source/'files')}
        (source/'bundle.json').write_text(json.dumps(manifest))
        dest=Path(self.temp.name)/'restored'
        calls=[]
        def revoke(_):calls.append('revoke');return 1
        def copy(src,dst,*args,**kwargs):
            calls.append('copy');return shutil_copy(src,dst,*args,**kwargs)
        shutil_copy=shutil.copytree
        with patch.object(bundle.subprocess,'run'),patch.object(bundle,'pg'),\
             patch.object(bundle,'rows_now',return_value=[self.job]),\
             patch.object(bundle,'attempts_now',return_value=[]),\
             patch.object(bundle,'catalog_now',return_value=self.catalog),\
             patch.object(bundle,'revoke_restored_sessions',side_effect=revoke),\
             patch.object(bundle.shutil,'copytree',side_effect=copy):
            result=bundle.restore('mock',source,dest)
        self.assertTrue(result['valid'],result)
        self.assertEqual(calls[0],'revoke')
        self.assertIn('copy',calls[1:])
        self.assertEqual(result['sessions_revoked'],1)

    def test_v3_snapshot_includes_catalog_without_auth_verifiers(self):
        output='CATALOG_PRESENT:true\nSNAPSHOT:mock\nROWS:'+json.dumps([self.job])+'\nATTEMPTS:[]\n'
        output+=''.join('CATALOG:'+table+':'+json.dumps(self.catalog[table])+'\n'
                        for table in bundle.CATALOG_TABLES)
        connection=Mock();connection.stdin=io.StringIO();connection.stdout=io.StringIO(output)
        connection.poll.return_value=0
        def dump(*args,**kwargs):kwargs['stdout'].write(b'fake postgres dump')
        dest=Path(self.temp.name)/'backup'
        with patch.object(bundle.subprocess,'Popen',return_value=connection),patch.object(bundle,'pg',side_effect=dump):
            result=bundle.backup('mock','m4_validation',self.root,dest)
        self.assertEqual(result['format_version'],4)
        self.assertTrue(result['catalog_audit']['valid'])
        self.assertEqual(result['source_audit']['unreferenced_files'],[])
        self.assertIn('v3_run_bindings',connection.stdin.getvalue())
        self.assertNotIn('token_hash',json.dumps(result['catalog']))
        self.assertNotIn('password_hash',json.dumps(result['catalog']))

    def test_dangling_catalog_rejected_before_restore_creates_database(self):
        source=Path(self.temp.name)/'bad-bundle';source.mkdir()
        shutil.copytree(self.root,source/'files')
        (source/'database.dump').write_bytes(b'mocked dump')
        broken=copy.deepcopy(self.catalog)
        broken['v3_run_bindings'][0]['network_file_id']='wrong'
        (source/'bundle.json').write_text(json.dumps({'format_version':4,
            'synthetic_validation_only':True,'rows':[self.job],'attempts':[],
            'catalog':broken,'database_sha256':bundle.sha(source/'database.dump'),
            'files':bundle.inventory(source/'files')}))
        dest=Path(self.temp.name)/'new-target'
        with patch.object(bundle.subprocess,'run') as createdb:
            with self.assertRaisesRegex(ValueError,'bundle catalog invalid'):
                bundle.restore('mock',source,dest)
            createdb.assert_not_called()
        self.assertFalse(dest.exists())
        report=json.loads(Path(str(dest)+'-audit.json').read_text())
        self.assertFalse(report['valid'])

    def test_legacy_v3_bundle_requires_explicit_backfill_before_restore(self):
        source=Path(self.temp.name)/'legacy-bundle';source.mkdir()
        (source/'bundle.json').write_text(json.dumps({'format_version':3,
            'synthetic_validation_only':True}))
        dest=Path(self.temp.name)/'legacy-target'
        with patch.object(bundle.subprocess,'run') as createdb:
            with self.assertRaisesRegex(ValueError,'legacy v3 catalog bundle lacks verified preflight snapshots'):
                bundle.restore('mock',source,dest)
            createdb.assert_not_called()
        report=json.loads(Path(str(dest)+'-audit.json').read_text())
        self.assertFalse(report['valid'])
        self.assertEqual(report['phase'],'bundle_integrity')


if __name__=='__main__':unittest.main()
