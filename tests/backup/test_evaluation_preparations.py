"""Independent format-6 metadata and bytea integrity unit fixtures (no PostgreSQL)."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('preparation_backup_bundle',ROOT/'scripts/backup/bundle.py')
bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle)


class PreparationBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.catalog={'v3_evaluation_preparations':[],
            'v3_evaluation_preparation_attempts':[],'v3_run_bindings':[],'v3_datasets':[]};self.jobs=[]
        self.document={'binding':{'fixture':'independent semantic expectation','run_id':'job1'},'predictions':{'events':[]}}
        self.raw=json.dumps(self.document,indent=2).encode('utf-8')
        self.add_preparation('job1')

    def add_preparation(self,job_id):
        base=Path('jobs')/job_id/'attempt-1';directory=self.root/base;directory.mkdir(parents=True)
        payload={'config_fingerprint':'c'*64,'kind':'dual-source'}
        core={'run_id':job_id,'attempt_id':1,'mode':'offline','input_fingerprint':'d'*64,'config_fingerprint':'c'*64}
        (directory/'analysis.json').write_bytes(b'independent original analysis bytes\n')
        (directory/'run_manifest.json').write_bytes(bundle.canonical(core)+b'\n')
        artifacts=[{'path':name,'sha256':bundle.sha(directory/name),'size':(directory/name).stat().st_size}
                   for name in ('analysis.json','run_manifest.json')]
        (directory/'manifest.json').write_bytes(bundle.canonical({'artifacts':artifacts})+b'\n')
        publication=bundle.sha(directory/'manifest.json');(directory/(publication+'.json')).write_bytes((directory/'manifest.json').read_bytes())
        job={'id':job_id,'attempt':1,'state':'succeeded','payload':payload,
            'artifact_path':str(base/(publication+'.json')),'artifact_sha256':publication};self.jobs.append(job)
        snapshot={'version':'verified-publication-snapshot-1','run_id':job_id,'attempt_id':1,
            'payload_sha256':bundle.fingerprint(payload),'artifact_path':job['artifact_path'],
            'publication_sha256':publication,'core_manifest_sha256':bundle.sha(directory/'run_manifest.json'),
            'config_fingerprint':'c'*64,'input_fingerprint':'d'*64,'mode':'offline',
            'files':[{'path':item['path'],'sha256':item['sha256'],'size_bytes':item['size']} for item in artifacts]}
        row={'id':'preparation-'+job_id,'job_id':job_id,'dataset_id':'dataset-'+job_id,'attempt':1,
            'payload_sha256':snapshot['payload_sha256'],'publication_sha256':publication,
            'artifact_path':job['artifact_path'],'config_fingerprint':'c'*64,'input_fingerprint':'d'*64,
            'batch':'independent-batch','projection':'dual','strategy_version':'evaluation-preparation-1',
            'state':'ready','preparation_attempt':1,'document_limit':8388608,
            'document_bytes_present':True,'document_stored_size':len(self.raw),'document_size':len(self.raw),
            'document_sha256':hashlib.sha256(self.raw).hexdigest(),'inventory_json':snapshot,'cost_json':{}}
        self.catalog['v3_evaluation_preparations'].append(row)
        self.catalog['v3_evaluation_preparation_attempts'].append({'preparation_id':row['id'],'attempt':1,
            'state':'ready','finished_at':'2026-10-28T00:00:00Z','document_sha256':row['document_sha256']})
        self.catalog['v3_run_bindings'].append({'job_id':job_id,'dataset_id':row['dataset_id']})
        self.catalog['v3_datasets'].append({'id':row['dataset_id'],'batch':row['batch']})
        return row

    def audit(self):return bundle.audit_preparation_metadata(self.catalog,self.jobs,self.root)

    def test_terminal_ready_snapshot_binds_all_actual_source_bytes(self):
        self.assertTrue(self.audit()['valid'],self.audit())
        path=self.root/'jobs/job1/attempt-1/analysis.json';raw=path.read_bytes();path.write_bytes(raw.replace(b'original',b'modified'))
        self.assertEqual(len(raw),path.stat().st_size)
        self.assertFalse(self.audit()['valid'])
        path.write_bytes(raw);path.unlink();self.assertFalse(self.audit()['valid'])

    def test_pending_both_refused_and_failed_does_not_expose_partial_document(self):
        row=self.catalog['v3_evaluation_preparations'][0]
        for state in ('queued','preparing'):
            with self.subTest(state=state):
                row['state']=state;self.assertFalse(self.audit()['valid'])
        row.update(state='failed',document_bytes_present=False,document_stored_size=None,document_size=0,document_sha256=None)
        attempt=self.catalog['v3_evaluation_preparation_attempts'][0];attempt.update(state='failed',document_sha256=None)
        self.assertTrue(self.audit()['valid'],self.audit())
        row['document_bytes_present']=True;self.assertFalse(self.audit()['valid'])

    def test_unavailable_mixed_identity_inventory_history_and_private_fields_refused(self):
        baseline=copy.deepcopy(self.catalog)
        changes=[lambda row:row.update(batch='other'),lambda row:row.update(attempt=2),
            lambda row:row.update(payload_sha256='0'*64),lambda row:row.update(document_stored_size=999),
            lambda row:row.update(document_limit=134217728),lambda row:row.update(owner='private'),
            lambda row:row.update(error_detail='private'),lambda row:row.update(document_bytes='private'),
            lambda row:row['inventory_json'].update(version='unknown'),
            lambda row:row['inventory_json']['files'].pop(),
            lambda row:row['inventory_json'].update(core_manifest_sha256='0'*64)]
        for change in changes:
            with self.subTest(change=change):
                self.catalog=copy.deepcopy(baseline);change(self.catalog['v3_evaluation_preparations'][0]);self.assertFalse(self.audit()['valid'])
        self.catalog=copy.deepcopy(baseline);self.catalog['v3_evaluation_preparation_attempts'].clear();self.assertFalse(self.audit()['valid'])
        self.catalog=copy.deepcopy(baseline);self.catalog['v3_evaluation_preparation_attempts'][0]['state']='preparing';self.assertFalse(self.audit()['valid'])

    def test_ready_global_budget_is_one_gib_not_per_row_unbounded(self):
        for i in range(2,10):self.add_preparation('job'+str(i))
        for job,row in zip(self.jobs,self.catalog['v3_evaluation_preparations']):
            job['payload']['resource_profile']='engineering-capacity-1'
            row.update(document_limit=134217728,document_size=134217728,document_stored_size=134217728,
                payload_sha256=bundle.fingerprint(job['payload']))
            row['inventory_json']['payload_sha256']=row['payload_sha256']
        result=self.audit();self.assertFalse(result['valid']);self.assertTrue(any('global ready byte budget' in item['reason'] for item in result['errors']))

    def test_actual_raw_bytea_hash_and_semantic_projection_checked_once_per_run_projection(self):
        calls=[]
        def pg(container,db,*args,**kwargs):
            self.assertIn(db,('m4_validation','m4_restore_validation'));query=args[-1]
            import re
            offset,count=map(int,re.search(r'FROM (\d+) FOR (\d+)',query).groups());calls.append((db,offset,count))
            return type('Response',(),{'stdout':self.raw[offset-1:offset-1+count].hex()+'\n'})()
        cache={}
        with patch.object(bundle,'pg',side_effect=pg),patch('cpag_core.evaluation_artifacts.adapt_artifact',return_value=self.document) as adapter:
            first=bundle.audit_preparation_documents('db','m4_validation',self.catalog,self.jobs,self.root,semantic_cache=cache)
            second=bundle.audit_preparation_documents('db','m4_restore_validation',self.catalog,self.jobs,self.root,semantic_cache=cache)
        self.assertEqual(adapter.call_count,1);self.assertEqual(len(calls),2)
        self.assertTrue(first['documents'][0]['semantic_verification_executed']);self.assertFalse(second['documents'][0]['semantic_verification_executed'])
        with patch.object(bundle,'pg',return_value=type('Response',(),{'stdout':(b'x'*len(self.raw)).hex()})()),self.assertRaisesRegex(ValueError,'checksum'):
            bundle.audit_preparation_documents('db','m4_restore_validation',self.catalog,self.jobs,self.root)
        wrong=copy.deepcopy(self.document);wrong['binding']['fixture']='wrong source'
        with patch.object(bundle,'pg',side_effect=pg),patch('cpag_core.evaluation_artifacts.adapt_artifact',return_value=wrong),self.assertRaisesRegex(ValueError,'independently verified source'):
            bundle.audit_preparation_documents('db','m4_restore_validation',self.catalog,self.jobs,self.root)
        with patch.object(bundle,'pg',return_value=type('Response',(),{'stdout':''})()),self.assertRaisesRegex(ValueError,'missing or truncated'):
            bundle.audit_preparation_documents('db','m4_restore_validation',self.catalog,self.jobs,self.root)

    def test_rehashed_prepared_body_with_only_wrong_run_identity_is_refused(self):
        source=copy.deepcopy(self.document);bad=copy.deepcopy(source);bad['binding']['run_id']='another-run'
        raw=json.dumps(bad,indent=2).encode('utf-8');row=self.catalog['v3_evaluation_preparations'][0]
        row.update(document_size=len(raw),document_stored_size=len(raw),document_sha256=hashlib.sha256(raw).hexdigest())
        self.catalog['v3_evaluation_preparation_attempts'][0]['document_sha256']=row['document_sha256']
        with patch.object(bundle,'pg',return_value=type('Response',(),{'stdout':raw.hex()})()),\
             patch('cpag_core.evaluation_artifacts.adapt_artifact',return_value=source),\
             self.assertRaisesRegex(ValueError,'independently verified source'):
            bundle.audit_preparation_documents('db','m4_restore_validation',self.catalog,self.jobs,self.root)

    def test_large_bytea_is_read_in_bounded_chunks_without_json_reserialization(self):
        raw=json.dumps({'padding':'x'*(2*1024*1024),'independent':True},indent=2).encode('utf-8')
        row=self.catalog['v3_evaluation_preparations'][0]
        row.update(document_size=len(raw),document_stored_size=len(raw),document_sha256=hashlib.sha256(raw).hexdigest())
        self.catalog['v3_evaluation_preparation_attempts'][0]['document_sha256']=row['document_sha256']
        calls=[]
        def pg(container,db,*args,**kwargs):
            import re
            offset,count=map(int,re.search(r'FROM (\d+) FOR (\d+)',args[-1]).groups());calls.append(count)
            return type('Response',(),{'stdout':raw[offset-1:offset-1+count].hex()})()
        with patch.object(bundle,'pg',side_effect=pg),patch('cpag_core.evaluation_artifacts.adapt_artifact',return_value=json.loads(raw)):
            result=bundle.audit_preparation_documents('db','m4_restore_validation',self.catalog,self.jobs,self.root)
        self.assertTrue(result['valid']);self.assertEqual(len(calls),3);self.assertLessEqual(max(calls),1024*1024)

    def test_metadata_sql_never_serializes_large_bytea_before_redaction(self):
        sql=bundle.catalog_query('v3_evaluation_preparations')
        self.assertNotIn('to_jsonb(t)',sql);self.assertNotIn("'document_bytes',",sql)
        self.assertIn('octet_length(t.document_bytes)',sql)
        self.assertNotIn("'owner',",sql);self.assertNotIn("'error_detail',",sql)
        self.assertIn("- 'owner'",bundle.catalog_query('v3_evaluation_preparation_attempts'))

if __name__=='__main__':unittest.main()
