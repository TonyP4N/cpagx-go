import copy
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
        for role,source in [('network','tests/fixtures/synthetic/network.normalized.jsonl'),
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
                'sha256':ref['sha256'],'size_bytes':file.stat().st_size})
            self.catalog['v3_dataset_files'].append({'id':role+'-link','dataset_id':'d1',
                'source_file_id':role,'role':role,'created_by':'u1'})
        self.catalog['v3_config_versions']=[{'id':'cfg1','dataset_id':'d1','kind':'dual','version':1,
            'profile_storage_path':sources['profile']['path'],'profile_sha256':sources['profile']['sha256'],
            'config_fingerprint':fingerprint(profile),'profile_json':profile,'created_by':'u1'}]
        self.catalog['v3_run_bindings']=[{'job_id':'catalog-job','dataset_id':'d1',
            'network_file_id':'network-link','process_file_id':'process-link',
            'config_version_id':'cfg1','mode':'dual_source','created_by':'u1'}]
        self.catalog['v3_preflights']=[]
        self.catalog['v3_audit_events']=[{'id':1,'user_id':'u1','dataset_id':'d1',
            'job_id':'catalog-job','details':{'action':'run'}}]

    def audited(self,catalog=None):
        return bundle.audit_catalog(catalog if catalog is not None else self.catalog,[self.job],self.root)

    def test_catalog_includes_unused_originals_and_versions(self):
        unused=self.root/'inputs/catalog/d1/unused.pcap';unused.write_bytes(b'unused synthetic original')
        self.catalog['v3_source_files'].append({'id':'unused','storage_path':'inputs/catalog/d1/unused.pcap',
            'sha256':bundle.sha(unused),'size_bytes':unused.stat().st_size})
        self.catalog['v3_dataset_files'].append({'id':'unused-link','dataset_id':'d1',
            'source_file_id':'unused','role':'network','created_by':'u1'})
        result=self.audited()
        self.assertTrue(result['valid'],result)
        self.assertEqual(set(result['referenced_files']),{
            'inputs/catalog/d1/network.jsonl','inputs/catalog/d1/process.csv',
            'inputs/catalog/d1/profiles/cfg1.json','inputs/catalog/d1/unused.pcap'})
        self.catalog['v3_run_bindings']=[]
        self.assertFalse(self.audited()['valid'])
        self.assertIn('lacks run ownership binding',str(self.audited()['errors']))
        self.catalog['v3_run_bindings']=[{'job_id':'catalog-job','dataset_id':'d1',
            'network_file_id':'network-link','process_file_id':'process-link',
            'config_version_id':'cfg1','mode':'dual_source','created_by':'u1'}]
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
        intake={'dataset_id':'d1','synthetic':True}
        path=self.root/'inputs/catalog/d1/profiles/intakecfg.json'
        path.write_bytes(bundle.canonical(intake)+b'\n')
        self.catalog['v3_config_versions'].append({'id':'intakecfg','dataset_id':'d1',
            'kind':'intake','version':1,'profile_storage_path':path.relative_to(self.root).as_posix(),
            'profile_sha256':bundle.sha(path),
            'config_fingerprint':fingerprint(intake),
            'profile_json':intake,'created_by':'u1'})
        entries=[]
        for link in sorted(self.catalog['v3_dataset_files'],key=lambda item:item['id']):
            source=next(item for item in self.catalog['v3_source_files'] if item['id']==link['source_file_id'])
            entries.append({'name':source['storage_path'],'sha256':source['sha256'],
                            'size_bytes':source['size_bytes'],'kind':link['role']})
        manifest={'schema_version':'1.0.0','synthetic':True,'dataset_id':'d1',
            'source':'synthetic fixture','release':'1','files':entries,
            'collection_range':{'start':None,'end':None},'timezone_basis':None,
            'authorization_ref':'fixture permission'}
        manifest_path=Path(self.temp.name)/'manifest.json'
        manifest_path.write_bytes(bundle.canonical(manifest)+b'\n')
        report=bundle.verify_intake_preflight(self.root,manifest_path,path)
        self.catalog['v3_preflights']=[{'id':'p1','dataset_id':'d1','config_version_id':'intakecfg',
            'created_by':'u1','report':report}]
        self.assertTrue(self.audited()['valid'],self.audited())
        self.catalog['v3_preflights'][0]['report']['status']='forged'
        self.assertFalse(self.audited()['valid'])

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
        manifest={'format_version':3,'synthetic_validation_only':True,'rows':[self.job],
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
        self.assertEqual(result['format_version'],3)
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
        (source/'bundle.json').write_text(json.dumps({'format_version':3,
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


if __name__=='__main__':unittest.main()
