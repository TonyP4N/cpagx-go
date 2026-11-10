"""Deployment backup policy, irreversible-target refusal and evidence retention."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/backup'))
from postgres_target import DeploymentDatabases, deployment_databases, require_database
spec = importlib.util.spec_from_file_location('r21_backup_operator', ROOT/'scripts/backup/deployment_ops.py')
operator = importlib.util.module_from_spec(spec); spec.loader.exec_module(operator)
bundle = operator.bundle


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.config = {key: str(self.root/key) for key in operator.FIELDS}
        self.config.update(deployment_id='isolated-r21', pg_container='owned-postgres', source_database='cpag_app', restore_database='cpag_restore')
        for key in ('shared_root', 'control_root', 'backup_root', 'log_root', 'run_root'):
            Path(self.config[key]).mkdir()
        self.path = self.root/'operator.json'; self.path.write_text(json.dumps(self.config)); self.path.chmod(0o600)
        self.policy = DeploymentDatabases('a'*64, 'cpag_app', 'cpag_restore')

    def test_validation_default_refuses_real_names_and_capability_does_not_alias(self):
        with patch.object(bundle.subprocess, 'run') as called:
            with self.assertRaisesRegex(ValueError, 'disposable validation'):
                bundle.pg('owned-postgres', 'cpag_app', 'psql')
            called.assert_not_called()
            with deployment_databases(self.policy):
                bundle.pg('a'*64, 'cpag_app', 'psql')
                self.assertEqual(called.call_args.args[0], ['docker','exec','-i','a'*64,'psql','-U','postgres','-d','cpag_app'])
                require_database('a'*64, 'cpag_restore', 'restore')
                for container, database, role in [('other','cpag_app','query'),('a'*64,'cpag_app','restore'),('a'*64,'m4_validation','query')]:
                    with self.assertRaises(ValueError): require_database(container, database, role)
            with self.assertRaises(ValueError): require_database('a'*64, 'cpag_app')

    def test_actual_restore_name_reaches_createdb_unchanged_and_existing_target_is_not_replaced(self):
        source=self.root/'bundle';source.mkdir();(source/'files').mkdir();(source/'database.dump').write_bytes(b'fixed test dump')
        manifest={'format_version':2,'synthetic_validation_only':True,'rows':[],'attempts':[],
                  'database_sha256':bundle.sha(source/'database.dump'),'files':{}}
        (source/'bundle.json').write_text(json.dumps(manifest))
        destination=self.root/'restored'
        with deployment_databases(self.policy),patch.object(bundle.subprocess,'run') as command,patch.object(bundle,'pg'),patch.object(bundle,'rows_now',return_value=[]),patch.object(bundle,'attempts_now',return_value=[]):
            result=bundle.restore('a'*64,source,destination,database='cpag_restore')
        self.assertEqual(command.call_args.args[0],['docker','exec','a'*64,'createdb','-U','postgres','cpag_restore'])
        self.assertEqual(result['database'],'cpag_restore');self.assertTrue(result['valid'])
        import subprocess
        refused=self.root/'refused'
        with deployment_databases(self.policy),patch.object(bundle.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['createdb'])) as command,patch.object(bundle,'pg') as restore:
            with self.assertRaises(subprocess.CalledProcessError):bundle.restore('a'*64,source,refused,database='cpag_restore')
            restore.assert_not_called()
        self.assertFalse(refused.exists());self.assertTrue(source.exists())
        self.assertEqual(json.loads((self.root/'refused-audit.json').read_text())['phase'],'create_new_database')

    def test_system_same_and_injected_database_names_refuse(self):
        for name in ('postgres', 'template0', 'template1', 'pg_catalog', 'bad; DROP DATABASE x', '../db', ''):
            with self.subTest(name=name), self.assertRaises(ValueError): DeploymentDatabases('owned', name, 'restore')
        with self.assertRaisesRegex(ValueError, 'differ'): DeploymentDatabases('owned', 'same', 'same')
        with deployment_databases(self.policy):
            with self.assertRaises(ValueError):
                with deployment_databases(self.policy): pass

    def test_private_config_paths_and_database_owner_required(self):
        self.assertEqual(operator.load_config(self.path)[0]['source_database'], 'cpag_app')
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'owner-private'): operator.load_config(self.path)
        identity='a'*64
        def result(labels, running='true'):
            return SimpleNamespace(stdout=json.dumps(labels)+'\n'+identity+'\n'+running+'\n')
        correct={'cpag.role':'postgres','cpag.deployment_id':'isolated-r21'}
        with patch.object(operator.subprocess,'run',return_value=result(correct)) as command:
            self.assertEqual(operator.owned_postgres(self.config), identity)
            self.assertNotIn('Env', ' '.join(command.call_args.args[0]))
        for labels in ({}, {**correct,'cpag.deployment_id':'other'}):
            with patch.object(operator.subprocess,'run',return_value=result(labels)), self.assertRaisesRegex(ValueError,'ownership mismatch'):
                operator.owned_postgres(self.config)

    def test_restore_cannot_touch_existing_source_or_existing_new_directories(self):
        source=self.root/'bundle'; source.mkdir()
        for target in (Path(self.config['shared_root']), self.root/'already-restored'):
            target.mkdir(exist_ok=True)
            with patch.object(operator,'owned_postgres') as inspected, self.assertRaisesRegex(ValueError,'must be new'):
                operator.restore(self.config, source, target, self.root/'new-control')
            inspected.assert_not_called()
        with patch.object(operator,'owned_postgres') as inspected, self.assertRaisesRegex(ValueError,'separate'):
            operator.restore(self.config, source, Path(self.config['shared_root'])/'nested', self.root/'new-control')
        inspected.assert_not_called()

    def controlled_bundle(self):
        source=Path(self.config['backup_root'])/'owned';source.mkdir()
        (source/'bundle.json').write_text(json.dumps({'format_version':7}))
        digest=bundle.sha(source/'bundle.json')
        owner={'version':operator.VERSION,'deployment_id':self.config['deployment_id'],'bundle_sha256':digest}
        (source/'operator-owner.json').write_text(json.dumps(owner))
        receipt=source.parent/(source.name+'-operation.json')
        receipt.write_text(json.dumps({**owner,'action':'backup','valid':True,'format_version':7,'actor':{'effective_uid':0},'database':self.config['source_database']}))
        return source,receipt

    def test_restore_requires_external_successful_receipt_and_same_deployment_digest(self):
        source,receipt=self.controlled_bundle()
        original=json.loads(receipt.read_text())
        owner_path=source/'operator-owner.json';owner=json.loads(owner_path.read_text())
        for case in ('missing_external','failed_external','wrong_external_deployment','wrong_digest','wrong_owner','nonroot_backup'):
            receipt.write_text(json.dumps(original));owner_path.write_text(json.dumps(owner))
            if case=='missing_external':receipt.unlink()
            elif case=='wrong_owner':owner_path.write_text(json.dumps({**owner,'deployment_id':'foreign'}))
            else:
                changed=dict(original)
                changed.update({'valid':False} if case=='failed_external' else {'deployment_id':'foreign'} if case=='wrong_external_deployment' else {'bundle_sha256':'f'*64} if case=='wrong_digest' else {'actor':{'effective_uid':501}})
                receipt.write_text(json.dumps(changed))
            with patch.object(operator,'owned_postgres') as pg,patch.object(bundle,'restore') as restore:
                with self.assertRaises((OSError,ValueError)):
                    operator.restore(self.config,source,self.root/('new-'+case),self.root/('control-'+case))
                pg.assert_not_called();restore.assert_not_called()
            self.assertTrue(source.exists())
        audits=list(Path(self.config['backup_root']).glob('restore-*-operation.json'))
        self.assertEqual(len(audits),6)
        self.assertTrue(all(json.loads(path.read_text())['valid'] is False for path in audits))
        self.assertTrue(all('effective_uid' in json.loads(path.read_text())['actor'] for path in audits))

    def test_controlled_restore_passes_actual_target_and_records_operator(self):
        source,_=self.controlled_bundle()
        restored={'source_trust':'pending_formal_service_reverification','sessions_revoked':2,
                  'worker_observations_cleared':{'table_present':True,'removed':1},'file_inventory_equal':True,
                  'control_inventory_equal_before_rebase':True}
        destination=self.root/'new-shared';control=self.root/'new-control'
        with patch.object(operator,'owned_postgres',return_value='a'*64),patch.object(bundle,'restore',return_value=restored) as restore:
            report=operator.restore(self.config,source,destination,control)
        self.assertTrue(report['valid']);self.assertEqual(report['database'],'cpag_restore')
        self.assertEqual(restore.call_args.kwargs['database'],'cpag_restore')
        self.assertEqual(restore.call_args.kwargs['control_destination'],control)
        self.assertIn('effective_uid',report['actor']);self.assertTrue(Path(report['audit_path']).is_file())

    def test_backup_parent_escape_or_nested_bundle_cannot_bypass_controlled_root(self):
        for destination in (Path(self.config['backup_root'])/'..'/'escaped',Path(self.config['backup_root'])/'nested'/'bundle'):
            with patch.object(operator,'owned_postgres') as inspected,self.assertRaisesRegex(ValueError,'directly inside'):
                operator.backup(self.config,self.path,destination)
            inspected.assert_not_called();self.assertFalse(destination.exists())

    def test_backup_requires_stopped_service_and_retains_failure_report(self):
        import fcntl
        lock=(Path(self.config['control_root'])/'.maintenance.lock').open('w')
        self.addCleanup(lock.close); fcntl.flock(lock,fcntl.LOCK_SH)
        destination=Path(self.config['backup_root'])/'live-refused'
        with patch.object(operator,'owned_postgres',return_value='a'*64), patch.object(bundle,'_backup') as writes:
            with self.assertRaisesRegex(ValueError,'stopped Go service and Worker'):
                operator.backup(self.config,self.path,destination)
            writes.assert_not_called()
        self.assertFalse(destination.exists())
        report=json.loads((destination.parent/'live-refused-operation.json').read_text())
        self.assertFalse(report['valid']); self.assertEqual(report['retention'],'all_source_and_partial_evidence_retained')

    def test_retention_only_lists_verified_owned_complete_old_bundles(self):
        root=Path(self.config['backup_root'])
        for index in range(3):
            target=root/('complete-'+str(index)); target.mkdir()
            (target/'files').mkdir(); (target/'control').mkdir(); (target/'database.dump').write_bytes(b'synthetic fixed dump')
            manifest={'format_version':7,'database_sha256':bundle.sha(target/'database.dump'),'files':{},'control_files':{}}
            (target/'bundle.json').write_text(json.dumps(manifest))
            owner={'version':operator.VERSION,'deployment_id':self.config['deployment_id'],'created_at':f'2026-11-0{index+1}T00:00:00+00:00','bundle_sha256':bundle.sha(target/'bundle.json')}
            (target/'operator-owner.json').write_text(json.dumps(owner))
        (root/'partial').mkdir(); (root/'partial'/'retained-error.log').write_text('failed evidence')
        shutil.copytree(root/'complete-0',root/'foreign')
        marker=root/'foreign'/'operator-owner.json'; value=json.loads(marker.read_text());value['deployment_id']='other';marker.write_text(json.dumps(value))
        before=sorted(str(item.relative_to(root)) for item in root.rglob('*'))
        report=operator.retention_plan(self.config,2)
        self.assertFalse(report['deletes_data']); self.assertEqual(report['retained_complete'],['complete-2','complete-1'])
        self.assertEqual(report['reviewable_old_complete'],['complete-0'])
        self.assertEqual({row['name'] for row in report['retained_evidence']},{'foreign','partial'})
        self.assertEqual(before,sorted(str(item.relative_to(root)) for item in root.rglob('*')))

    def test_restored_worker_presence_is_cleared_or_old_schema_remains_compatible(self):
        with patch.object(bundle,'pg',return_value=SimpleNamespace(stdout='false\n')):
            self.assertEqual(bundle.clear_restored_worker_observations('c','m4_restore_validation'),{'table_present':False,'removed':0})
        responses=[SimpleNamespace(stdout=value) for value in ('true\n','2\n','','0\n')]
        with patch.object(bundle,'pg',side_effect=responses) as pg:
            self.assertEqual(bundle.clear_restored_worker_observations('c','m4_restore_validation'),{'table_present':True,'removed':2})
            self.assertIn('TRUNCATE m4_worker_observations;',pg.call_args_list[2].args)
        with patch.object(bundle,'pg',return_value=SimpleNamespace(stdout='unrecognized')):
            with self.assertRaisesRegex(ValueError,'cannot establish'):bundle.clear_restored_worker_observations('c','m4_restore_validation')



class ClosedFileCleanupTests(unittest.TestCase):
    def setUp(self):
        import os, time
        self.os=os; self.now=time.time()
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.config={key:str(self.root/key) for key in operator.FIELDS}
        self.config.update(deployment_id='isolated-r21',pg_container='owned-postgres',source_database='cpag_app',restore_database='cpag_restore')
        for key in ('shared_root','control_root','backup_root','log_root','run_root'):
            Path(self.config[key]).mkdir()
        self.log=self.make('log_root','app.log.1',b'closed rotated log')
        self.temporary=self.make('run_root','compute.tmp.closed',b'closed disposable runtime bytes')
        self.live=self.make('log_root','app.log',b'current running log')
        self.business=self.make('shared_root','business.log.1',b'original business material')

    def make(self,scope,name,data):
        target=Path(self.config[scope])/name;target.write_bytes(data)
        self.os.utime(target,(self.now-30*86400,self.now-30*86400));return target

    def preview(self):
        with patch.object(operator.retention,'open_file_identities',return_value=set()):
            return operator.retention.plan(self.config,14,1)

    def test_preview_does_not_delete_and_preserves_current_unknown_hardlinks_and_open_files(self):
        linked=Path(self.config['log_root'])/'linked.log.1';self.os.link(self.business,linked)
        opened=self.make('log_root','open.log.1',b'active writer holds this inode')
        info=opened.stat()
        with patch.object(operator.retention,'open_file_identities',return_value={(info.st_dev,info.st_ino)}):
            planned=operator.retention.plan(self.config)
        self.assertFalse(planned['deletes_data'])
        self.assertEqual({row['relative'] for row in planned['candidates']},{'app.log.1','compute.tmp.closed'})
        self.assertTrue(all(path.exists() for path in (self.log,self.temporary,self.live,self.business,linked,opened)))
        self.assertIn('open_file_retained',{row['reason'] for row in planned['retained']})

    def test_apply_requires_confirmation_stopped_services_and_current_matching_preview(self):
        import fcntl
        planned=self.preview();audit=Path(self.config['backup_root'])/'cleanup-audit.json'
        with self.assertRaisesRegex(ValueError,'confirmation'):operator.retention.apply(self.config,planned,'other',audit)
        self.assertFalse(audit.exists())
        with (Path(self.config['control_root'])/'.maintenance.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_SH)
            with self.assertRaisesRegex(ValueError,'stopped Go service and Worker'):
                operator.retention.apply(self.config,planned,'isolated-r21',audit)
        self.assertFalse(json.loads(audit.read_text())['valid']);self.assertTrue(self.log.exists())

    def test_apply_deletes_only_closed_preview_candidates_and_audits_every_removed_file(self):
        planned=self.preview();audit=Path(self.config['backup_root'])/'cleanup-audit.json'
        with patch.object(operator.retention,'open_file_identities',return_value=set()):
            result=operator.retention.apply(self.config,planned,'isolated-r21',audit)
        self.assertTrue(result['valid']);self.assertEqual(len(result['deleted']),2)
        self.assertFalse(self.log.exists());self.assertFalse(self.temporary.exists())
        self.assertTrue(self.live.exists());self.assertTrue(self.business.exists())
        self.assertEqual(json.loads(audit.read_text()),result)
        with self.assertRaisesRegex(ValueError,'new audit'):operator.retention.apply(self.config,planned,'isolated-r21',audit)

    def test_changed_open_or_forged_business_candidate_never_deletes(self):
        for case in ('changed','open','outside'):
            self.log.write_bytes(b'closed rotated log');self.os.utime(self.log,(self.now-30*86400,self.now-30*86400))
            planned=self.preview();audit=Path(self.config['backup_root'])/(case+'-audit.json')
            opened=set()
            if case=='changed':self.log.write_bytes(b'changed since preview')
            elif case=='open':
                info=self.log.stat();opened={(info.st_dev,info.st_ino)}
            else:planned['candidates'][0]['relative']='../shared_root/business.log.1'
            with patch.object(operator.retention,'open_file_identities',return_value=opened),self.assertRaises(ValueError):
                operator.retention.apply(self.config,planned,'isolated-r21',audit)
            self.assertTrue(self.business.exists());self.assertTrue(self.temporary.exists());self.assertTrue(self.log.exists())
            self.assertFalse(json.loads(audit.read_text())['valid'])


if __name__ == '__main__': unittest.main()
