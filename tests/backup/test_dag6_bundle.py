"""Small independent terminal-publication fixtures; no capacity acceptance runs."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'services/analysis/src'))
sys.path.insert(0, str(ROOT / 'scripts/backup'))
sys.path.insert(0, str(ROOT / 'scripts/validation'))
import dag6
from dual_source_fixtures import make_case
from round17_profile import profile
from cpag_core import shared_export as core
from cpag_core import shared_service as service
from cpag_core.pipeline import canonical, file_hash, fingerprint


def make_publication(root, *, replay=False):
    if replay:
        from round18_profile import fixture
        networks, process, config_path, config = fixture(root / 'inputs')
        config['replay'].update(history_format=core.FORMAT, identity_strategy='merkle-json-dag-1',
                                prefix_digest_strategy='incremental-prefix-digest-2')
    else:
        network, process, config_path = make_case(root / 'inputs')
        networks = [network]
        config = profile()
    config.update(storage_format=core.FORMAT, capacity_profile=service.CAPACITY,
                  storage_budget_version=service.BUDGET)
    config_path.write_bytes(canonical(config) + b'\n')
    ref = lambda path: {'path': path.relative_to(root).as_posix(), 'sha256': file_hash(path)}
    payload = {**dag6.VERSIONS, 'kind': 'dual-source-replay' if replay else 'dual-source',
               'network': ref(networks[0]), 'networks': [ref(path) for path in networks],
               'process': ref(process), 'profile': ref(config_path), 'config_fingerprint': fingerprint(config)}
    output = root / 'jobs/independent/attempt-1'
    core.export_task(networks, process, config_path, output, run_id='independent', attempt_id=1,
                     mode='replay' if replay else 'offline')
    wrapper = {**dag6.VERSIONS, 'run_id': 'independent', 'attempt_id': 1,
               'config_fingerprint': fingerprint(config),
               'inputs': {role: payload[role]['sha256'] for role in ('network', 'process', 'profile')},
               'networks': [ref['sha256'] for ref in payload['networks']],
               'artifacts': [{'path': name, 'sha256': file_hash(output / name),
                              'size': (output / name).stat().st_size} for name in sorted(core.artifact_files(output))]}
    if replay:
        payload.update(dag6.REPLAY)
        wrapper.update(dag6.REPLAY)
    row = {'id': 'independent', 'state': 'succeeded', 'attempt': 1, 'payload': payload}
    publish(row, output, wrapper)
    return row, output


def publish(row, output, wrapper):
    old = row.get('artifact_sha256')
    if old and (output / (old + '.json')).exists():
        (output / (old + '.json')).unlink()
    raw = canonical(wrapper) + b'\n'
    (output / 'manifest.json').write_bytes(raw)
    digest = file_hash(output / 'manifest.json')
    (output / (digest + '.json')).write_bytes(raw)
    row.update(artifact_sha256=digest,
               artifact_path='jobs/independent/attempt-1/' + digest + '.json')


class DAG6BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = tempfile.TemporaryDirectory()
        cls.template_root = Path(cls.template.name)
        cls.template_row, _ = make_publication(cls.template_root)

    @classmethod
    def tearDownClass(cls):
        cls.template.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'files'
        shutil.copytree(self.template_root, self.root)
        self.row = deepcopy(self.template_row)
        self.output = self.root / 'jobs/independent/attempt-1'
        self.used = set()

    def verify(self, relative, digest, size=None):
        path = dag6._safe(self.root, relative)
        self.used.add(relative)
        if not path.is_file() or file_hash(path) != digest or (size is not None and path.stat().st_size != size):
            raise ValueError('fixture_checksum_or_size_mismatch')
        return path

    def audit(self):
        return dag6.audit(self.row, self.root, self.verify)

    def wrapper(self):
        return json.loads((self.output / 'manifest.json').read_text())

    def test_storage_copy_audit_never_rebuilds_or_issues_source_approval(self):
        with patch.object(core, 'verify_task', side_effect=AssertionError('source rebuild forbidden')), \
             patch.object(core, '_rebuild_source_roots', side_effect=AssertionError('source rebuild forbidden')), \
             patch.object(core, 'issue_approval', side_effect=AssertionError('approval forbidden')):
            report = self.audit()
            self.assertEqual(report['status'], dag6.STATUS)
            self.assertFalse(report['trusted_result'])
            self.assertTrue(report['storage_integrity_verified'])
            self.assertEqual(report['source_verification'], 'required_by_restored_service')
            self.assertIn(self.row['artifact_path'], self.used)
            self.assertIn('jobs/independent/attempt-1/shared/shared.sqlite3', self.used)
            restored = Path(self.tmp.name) / 'restored'
            shutil.copytree(self.root, restored)
            old = self.root
            self.root = restored
            self.assertEqual(self.audit(), report)
            self.root = old
        # The private service remains the separate complete-source authority.
        binding = dag6._binding(self.wrapper(), self.row['artifact_sha256'], fingerprint(self.row['payload']))
        verified = service.verify(self.output, binding, b'n' * 32)
        self.assertEqual(verified['verification_report']['status'], 'passed')

    def test_missing_anchor_database_or_source_and_extra_files_refuse(self):
        for relative in (self.row['artifact_sha256'] + '.json', 'shared/shared.sqlite3', 'sources/process.csv'):
            with self.subTest(relative=relative):
                path = self.output / relative
                raw = path.read_bytes()
                path.unlink()
                with self.assertRaises((ValueError, OSError)):
                    self.audit()
                path.write_bytes(raw)
        extra = self.output / 'unexpected'
        extra.write_bytes(b'retain unknown bytes but reject published inventory')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.audit()

    def test_same_size_original_database_and_anchor_tampering_refuse(self):
        for path in (self.output / 'shared/shared.sqlite3', self.output / 'sources/process.csv',
                     self.output / (self.row['artifact_sha256'] + '.json'),
                     self.root / self.row['payload']['process']['path']):
            with self.subTest(path=path):
                raw = path.read_bytes()
                changed = bytearray(raw)
                changed[-1] ^= 1
                path.write_bytes(changed)
                with self.assertRaises((ValueError, OSError)):
                    self.audit()
                path.write_bytes(raw)

    def test_wrong_job_attempt_and_payload_profile_mixed_versions_refuse(self):
        pristine = deepcopy(self.row)
        changes = [('id', 'other'), ('attempt', 2), ('attempt', True), ('artifact_path', '../escape')]
        for key, value in changes:
            with self.subTest(key=key):
                self.row = dict(deepcopy(pristine), **{key: value})
                with self.assertRaises((ValueError, OSError)):
                    self.audit()
        for key in dag6.VERSIONS:
            with self.subTest(version=key):
                self.row = deepcopy(pristine)
                self.row['payload'][key] = 'unknown-next-version'
                with self.assertRaisesRegex(ValueError, 'version_mismatch'):
                    self.audit()

    def test_rehashed_publication_cannot_rebind_source_or_run(self):
        initial = self.wrapper()
        for mutate in ('run', 'attempt', 'input', 'networks', 'format'):
            with self.subTest(mutate=mutate):
                wrapper = deepcopy(initial)
                if mutate == 'run': wrapper['run_id'] = 'different'
                if mutate == 'attempt': wrapper['attempt_id'] = 2
                if mutate == 'input': wrapper['inputs']['process'] = 'f' * 64
                if mutate == 'networks': wrapper['networks'] = []
                if mutate == 'format': wrapper['storage_format'] = 'shared-observation-dag-5'
                publish(self.row, self.output, wrapper)
                with self.assertRaises(ValueError):
                    self.audit()

    def test_rehashed_profile_requires_exact_versions_and_config_fingerprint(self):
        original = deepcopy(self.row)
        path = self.root / self.row['payload']['profile']['path']
        config = json.loads(path.read_text())
        for name in ('storage_format', 'capacity_profile', 'storage_budget_version'):
            with self.subTest(profile_version=name):
                altered = dict(config, **{name: 'unknown-next-version'})
                path.write_bytes(canonical(altered) + b'\n')
                self.row = deepcopy(original)
                self.row['payload']['profile']['sha256'] = file_hash(path)
                self.row['payload']['config_fingerprint'] = fingerprint(altered)
                with self.assertRaisesRegex(ValueError, 'profile_version_mismatch'):
                    self.audit()
        path.write_bytes(canonical(config) + b'\n')
        self.row = deepcopy(original)
        self.row['payload']['config_fingerprint'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'config_fingerprint_mismatch'):
            self.audit()

    def test_rehashed_compact_nodes_still_require_logical_integrity(self):
        db = self.output / 'shared/shared.sqlite3'
        connection = sqlite3.connect(db)
        connection.execute("UPDATE nodes SET payload=? WHERE id=(SELECT id FROM nodes WHERE kind='scalar' LIMIT 1)", (b'"forged"',))
        connection.commit()
        connection.close()
        shared_path = self.output / 'shared/manifest.json'
        shared = json.loads(shared_path.read_text())
        shared['database'].update(sha256=file_hash(db), size_bytes=db.stat().st_size)
        shared_path.write_bytes(canonical(shared) + b'\n')
        run_path = self.output / 'run_manifest.json'
        run = json.loads(run_path.read_text())
        run['shared_manifest_sha256'] = file_hash(shared_path)
        for entry in run['artifacts']:
            path = self.output / entry['path']
            entry.update(sha256=file_hash(path), size_bytes=path.stat().st_size)
        run_path.write_bytes(canonical(run) + b'\n')
        wrapper = self.wrapper()
        for entry in wrapper['artifacts']:
            path = self.output / entry['path']
            entry.update(sha256=file_hash(path), size=path.stat().st_size)
        publish(self.row, self.output, wrapper)
        token = core._SERVICE_VERIFIED.set((self.output.resolve(), file_hash(run_path)))
        try:
            with self.assertRaises(ValueError):
                self.audit()
        finally:
            core._SERVICE_VERIFIED.reset(token)

    def test_failed_cancelled_partial_attempts_are_inventory_only(self):
        for state in ('failed', 'cancelled'):
            self.row['state'] = state
            diagnostic = self.output / 'FAILED.json'
            diagnostic.write_bytes(b'{"trusted_result":false}\n')
            with patch.object(core, 'open_reader', side_effect=AssertionError('failed result read forbidden')):
                report = self.audit()
            self.assertEqual(report['status'], 'retained_untrusted_terminal_attempt')
            self.assertFalse(report['trusted_result'])
            self.assertIn('FAILED.json', report['files'])
        shutil.rmtree(self.output)
        self.row.update(state='cancelled', attempt=0, artifact_path=None, artifact_sha256=None)
        self.assertEqual(self.audit()['files'], {})

    def test_markers_route_unknown_and_mixed_shared_formats(self):
        self.assertFalse(dag6.detects({'resource_profile': 'engineering-capacity-1'}))
        for marker in ({'storage_format': 'future'}, {'storage_format': None},
                       {'capacity_profile': service.CAPACITY}, {'resource_profile': service.RESOURCE},
                       {'replay': {'history_format': 'shared-observation-dag-7'}}):
            self.assertTrue(dag6.detects({}, marker))

    def test_replay_multi_capture_publication_retains_complete_logical_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.root = Path(temporary)
            self.row, self.output = make_publication(self.root, replay=True)
            with patch.object(core, 'verify_task', side_effect=AssertionError('source rebuild forbidden')):
                report = self.audit()
                self.assertEqual(report['status'], dag6.STATUS)
                self.assertGreater(report['counts']['snapshots'], 1)
                with dag6.open_storage_reader(self.output) as reader:
                    last = reader.run_manifest['final_snapshot_number']
                    self.assertEqual(reader.get('history/snapshots', path=[last, 'snapshot_id']),
                                     reader.run_manifest['final_snapshot_id'])
            wrapper = self.wrapper()
            wrapper['networks'].reverse()
            publish(self.row, self.output, wrapper)
            with self.assertRaises(ValueError):
                self.audit()


if __name__ == '__main__':
    unittest.main()
