"""Terminal maintenance/exits and format7 restore refusal, without Docker."""
import copy
import fcntl
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'scripts/backup'), str(ROOT/'services/analysis/src')]
import bundle
import terminal_shared as terminal


class TerminalSharedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.control = self.root/'control'; self.control.mkdir()
        self.jobs = [{'id': 'small-run', 'attempt': 2, 'state': 'succeeded',
                      'artifact_sha256': 'd'*64,
                      'payload': {'storage_format': 'shared-observation-dag-6'}}]
        self.attempts = [{'job_id': 'small-run', 'attempt': 2,
                          'worker': 'test-worker', 'attempt_token': 'fixture-only-token',
                          'executor_kind': 'isolated-v2', 'container_id': 'a'*64, 'location': 'docker:fixture:scope',
                          'exited_at': '2026-11-02T00:00:00Z', 'exit_receipt': {
                              'id': 'small-run', 'attempt': 2, 'worker': 'test-worker', 'token': 'fixture-only-token',
                              'scope': 'container', 'container_id': 'a'*64, 'inspected_id': 'a'*64,
                              'location': 'docker:fixture:scope', 'exited': True, 'removed': True, 'running': False, 'pid': 0,
                              'labels': {'cpag.job': 'small-run', 'cpag.attempt': '2', 'cpag.worker': 'test-worker'}}}]
        self.verifiers = [{'job_id': 'small-run', 'attempt': 2, 'state': 'exited',
                           'container_name': 'verifier-container-small', 'exited_at': '2026-11-02T00:00:01Z'}]
        self.receipt = {'run_id': 'small-run', 'attempt_id': 2,
                        'version': 'service-compact-verification-execution-1', 'publication_sha256': 'd'*64,
                        'container_id': self.verifiers[0]['container_name'], 'cleanup_completed': True}
        self.receipt_path = self.control/'compact-verification-small-run-2-verifier-con.json'
        self.receipt_path.write_text(json.dumps(self.receipt))

    def audit(self, *, jobs=None, attempts=None, verifiers=None):
        return terminal.audit_exits(self.jobs if jobs is None else jobs,
            self.attempts if attempts is None else attempts,
            self.verifiers if verifiers is None else verifiers, self.control, bundle.safe)

    def test_active_shared_service_lock_rejects_backup_before_database_work(self):
        shared = self.root/'shared'; shared.mkdir(); destination = self.root/'backup'
        lock_path = self.control/'.maintenance.lock'
        with lock_path.open('a+') as service_lock:
            fcntl.flock(service_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with patch.object(bundle, '_backup') as operation:
                with self.assertRaisesRegex(ValueError, 'stopped Go service and Worker'):
                    bundle.backup('unused', 'm4_validation', shared, destination,
                                  control_root=self.control, maintenance=True)
                operation.assert_not_called()
            self.assertFalse(destination.exists())
        # The failed exclusive acquisition must not retain its lock handle.
        with terminal.maintenance(self.control) as locked:
            self.assertEqual(locked, self.control.resolve())

    def test_backup_overlapping_paths_refuse_before_lock_database_or_copy(self):
        shared = self.root/'shared'; shared.mkdir()
        nested = self.control/'nested-shared'; nested.mkdir()
        nested_control = shared/'nested-control'; nested_control.mkdir()
        alias = self.root/'control-alias'; alias.symlink_to(self.control, target_is_directory=True)
        cases = [(shared, self.control, self.control/'new-bundle'),
                 (shared, self.control, alias/'new-bundle'),
                 (nested, self.control, self.root/'new-bundle'),
                 (shared, nested_control, self.root/'new-bundle'),
                 (shared, shared, self.root/'new-bundle')]
        before = (bundle.inventory(shared), bundle.inventory(self.control))
        # The test symlink itself is deliberately outside the inventoried roots.
        for source, control, destination in cases:
            with self.subTest(source=source, control=control, destination=destination), \
                 patch.object(terminal, 'maintenance') as lock, patch.object(bundle, '_backup') as operation:
                with self.assertRaisesRegex(ValueError, 'outside separate shared and control'):
                    bundle.backup('unused', 'm4_validation', source, destination,
                                  control_root=control, maintenance=True)
                lock.assert_not_called(); operation.assert_not_called()
                self.assertFalse(destination.exists())
        self.assertEqual((bundle.inventory(shared), bundle.inventory(self.control)), before)

    def test_backup_separate_paths_keep_existing_maintenance_dispatch(self):
        shared = self.root/'shared'; shared.mkdir(); destination = self.root/'new-bundle'
        with patch.object(bundle, '_backup', return_value={'valid': True}) as operation:
            result = bundle.backup('unused', 'm4_validation', shared, destination,
                                   control_root=self.control, maintenance=True)
        self.assertEqual(result, {'valid': True})
        operation.assert_called_once_with('unused', 'm4_validation', shared, destination,
                                          control=self.control.resolve())

    def test_missing_attempt_exit_or_active_unconfirmed_verifier_rejected(self):
        for field, value in [('exited_at', None), ('exit_receipt', None)]:
            attempts = copy.deepcopy(self.attempts); attempts[0][field] = value
            with self.subTest(attempt_field=field), self.assertRaisesRegex(ValueError, 'attempt exit proof missing'):
                self.audit(attempts=attempts)
        for fields in ({'state': 'running'}, {'state': 'exited', 'exited_at': None}):
            verifiers = copy.deepcopy(self.verifiers); verifiers[0].update(fields)
            with self.subTest(verifier=fields), self.assertRaisesRegex(ValueError, 'active or unconfirmed'):
                self.audit(verifiers=verifiers)
        with self.assertRaisesRegex(ValueError, 'lacks verifier exit history'):
            self.audit(verifiers=[])

    def test_verifier_exit_receipt_must_bind_run_attempt_container_and_cleanup(self):
        for field, value in [('run_id', 'other-run'), ('attempt_id', 1),
                             ('container_id', 'other-container'), ('cleanup_completed', False)]:
            receipt = dict(self.receipt); receipt[field] = value
            self.receipt_path.write_text(json.dumps(receipt))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'exit receipt mismatch'):
                self.audit()
        self.receipt_path.write_text(json.dumps(self.receipt))
        result = self.audit()
        self.assertTrue(result['valid'])
        self.assertEqual(result['source_trust'], 'must_reverify_in_restored_service')

    def test_terminal_container_receipt_requires_affirmative_bound_exit(self):
        for field, value in [('exited', False), ('removed', False), ('running', True),
                             ('pid', 1), ('inspected_id', 'b'*64), ('scope', 'unknown'),
                             ('location', 'docker:other:scope'), ('container_id', 'b'*64),
                             ('token', 'different-fixture-token'), ('labels', {})]:
            attempts = copy.deepcopy(self.attempts); attempts[0]['exit_receipt'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'attempt exit'):
                self.audit(attempts=attempts)
        for field in ('exited', 'removed', 'running', 'pid'):
            attempts = copy.deepcopy(self.attempts); del attempts[0]['exit_receipt'][field]
            with self.subTest(missing=field), self.assertRaisesRegex(ValueError, 'attempt exit'):
                self.audit(attempts=attempts)

    def test_terminal_process_and_not_started_receipts_keep_their_existing_contracts(self):
        attempt = copy.deepcopy(self.attempts[0]); attempt.update(executor_kind='legacy', location='legacy-process-group', container_id='')
        identity = {key: attempt['exit_receipt'][key] for key in ('id', 'attempt', 'worker', 'token')}
        attempt['exit_receipt'] = dict(identity, group_exited=True, child_pid=101, guardian_pid=102)
        self.assertTrue(self.audit(attempts=[attempt])['valid'])
        for field, value in [('group_exited', False), ('child_pid', 0), ('guardian_pid', -1)]:
            broken = copy.deepcopy(attempt); broken['exit_receipt'][field] = value
            with self.subTest(process=field), self.assertRaisesRegex(ValueError, 'attempt exit'):
                self.audit(attempts=[broken])
        attempt = copy.deepcopy(self.attempts[0]); attempt.update(container_id='', start_revoked_at='2026-11-02T00:00:00Z')
        attempt['exit_receipt'] = dict(identity, scope='not-started', start_revoked=True, location=attempt['location'])
        jobs = copy.deepcopy(self.jobs); jobs[0]['state'] = 'cancelled'
        self.assertTrue(self.audit(jobs=jobs, attempts=[attempt], verifiers=[])['valid'])
        attempt['exit_receipt']['start_revoked'] = False
        with self.assertRaisesRegex(ValueError, 'attempt exit'):
            self.audit(jobs=jobs, attempts=[attempt], verifiers=[])

    def test_successful_verifier_receipt_requires_exact_publication_and_version(self):
        for field, value in [('publication_sha256', 'f'*64), ('publication_sha256', None),
                             ('version', 'future-verifier-receipt')]:
            self.receipt_path.write_text(json.dumps(dict(self.receipt, **{field: value})))
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'source verifier'):
                self.audit()

    def test_capacity_rebase_changes_only_root_preserving_every_reservation(self):
        original = {'root': '/old/shared', 'reservations': {
            'small-run:1': 0, 'small-run:2': 98304, 'failed-run:7': 101},
            'generation': 9, 'operator_metadata': {'policy': 'preserved'}}
        path = self.control/'capacity.json'; path.write_text(json.dumps(original))
        result = terminal.rebase_capacity(self.control, '/old/shared', self.root/'restored-shared')
        expected = copy.deepcopy(original); expected['root'] = str(self.root/'restored-shared')
        self.assertEqual(json.loads(path.read_text()), expected)
        self.assertTrue(result['reservations_preserved'])
        self.assertFalse(path.with_suffix('.restore-tmp').exists())

    def test_invalid_capacity_rebase_preserves_original_bytes(self):
        for value in ({'root': '/other/shared', 'reservations': {'a:1': 8}},
                      {'root': '/old/shared', 'reservations': {'a:1': -1}},
                      {'root': '/old/shared', 'reservations': {'a:1': True}}):
            path = self.control/'capacity.json'; path.write_text(json.dumps(value)); before = path.read_bytes()
            with self.subTest(value=value), self.assertRaises(ValueError):
                terminal.rebase_capacity(self.control, '/old/shared', '/new/shared')
            self.assertEqual(path.read_bytes(), before)

    def make_bundle(self, name, version=6, *, jobs=None):
        source = self.root/name; source.mkdir(); (source/'files').mkdir(); (source/'control').mkdir()
        (source/'files/retained.bin').write_bytes(b'original bundle evidence')
        (source/'database.dump').write_bytes(b'fixture dump; no database writes authorized')
        value = {'format_version': version, 'synthetic_validation_only': True,
            'rows': self.jobs if jobs is None else jobs, 'attempts': [],
            'database_sha256': bundle.sha(source/'database.dump'), 'files': bundle.inventory(source/'files'),
            'control_files': bundle.inventory(source/'control'), 'verifiers': [],
            'catalog': {name: [] for name in bundle.V5_CATALOG_TABLES}}
        (source/'bundle.json').write_text(json.dumps(value))
        return source

    def test_restore_existing_data_control_or_report_never_overwrites(self):
        source = self.make_bundle('source')
        data = self.root/'existing-data'; data.mkdir(); (data/'keep.txt').write_bytes(b'existing data')
        private = self.root/'existing-control'; private.mkdir(); (private/'keep.txt').write_bytes(b'existing private evidence')
        target = self.root/'new-data'; report = self.root/'new-data-audit.json'
        report.write_bytes(b'existing successful audit')
        before_source = bundle.inventory(source)
        with patch.object(bundle.subprocess, 'run') as database, patch.object(bundle, 'pg') as pg:
            with self.assertRaisesRegex(ValueError, 'destination and report must be new'):
                bundle.restore('unused', source, data)
            with self.assertRaisesRegex(ValueError, 'new separate control destination'):
                bundle.restore('unused', source, self.root/'another-data', control_destination=private)
            with self.assertRaisesRegex(ValueError, 'destination and report must be new'):
                bundle.restore('unused', source, target)
            database.assert_not_called(); pg.assert_not_called()
        self.assertEqual((data/'keep.txt').read_bytes(), b'existing data')
        self.assertEqual((private/'keep.txt').read_bytes(), b'existing private evidence')
        self.assertEqual(report.read_bytes(), b'existing successful audit')
        self.assertEqual(bundle.inventory(source), before_source)

    def test_mixed_shared_bundle_version_rejects_before_copy_or_database_creation(self):
        source = self.make_bundle('mixed-format6', version=6)
        before = bundle.inventory(source); destination = self.root/'restored'
        with patch.object(bundle.subprocess, 'run') as database, patch.object(bundle, 'pg') as pg, \
             patch.object(bundle.shutil, 'copytree') as copytree:
            with self.assertRaisesRegex(ValueError, 'DAG6 requires format7'):
                bundle.restore('unused', source, destination)
            database.assert_not_called(); pg.assert_not_called(); copytree.assert_not_called()
        self.assertFalse(destination.exists()); self.assertEqual(bundle.inventory(source), before)
        self.assertFalse(json.loads((self.root/'restored-audit.json').read_text())['valid'])

    def test_format7_with_old_catalog_cannot_reach_database_or_copy(self):
        source = self.make_bundle('mixed-format7', version=7, jobs=[])
        before = bundle.inventory(source); destination = self.root/'restored7'
        with patch.object(bundle, 'audit', return_value={'valid': True}), \
             patch.object(bundle, 'audit_attempts', return_value={'valid': True}), \
             patch.object(bundle.subprocess, 'run') as database, patch.object(bundle, 'pg') as pg, \
             patch.object(bundle.shutil, 'copytree') as copytree:
            with self.assertRaisesRegex(ValueError, 'format6 preparation catalog required'):
                bundle.restore('unused', source, destination, control_destination=self.root/'new-control')
            database.assert_not_called(); pg.assert_not_called(); copytree.assert_not_called()
        self.assertFalse(destination.exists()); self.assertEqual(bundle.inventory(source), before)
        self.assertFalse(json.loads((self.root/'restored7-audit.json').read_text())['valid'])


if __name__ == '__main__': unittest.main()
