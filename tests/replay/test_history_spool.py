"""V2 storage prototype equivalence; not Worker/Go/publication acceptance."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'services/analysis/src'), str(ROOT / 'scripts/validation')]
from round18_profile import fixture
from cpag_core import replay_core
from cpag_core.pipeline import canonical, file_hash, fingerprint
from cpag_core.replay_export import execute, _semantic_payloads
from cpag_core.replay_history import HistorySink, HistoryReader, VERSION


def make_snapshot(number, previous=None):
    analysis = {'rows': [{'id': i, 'business_value': 'x' * 512} for i in range(200)], 'counter': number}
    trigger = {'kind': 'fixture', 'arrival_seq': number, 'available_at': '2026-01-01T00:00:00Z', 'evidence_refs': []}
    snapshot = {'schema_version': '1.0.0', 'synthetic': True, 'replay_version': 'dual-source-replay-1',
                'snapshot_number': number, 'available_at': trigger['available_at'], 'arrival_seq': number,
                'status': 'fixture', 'revision_number': number, 'config_version': 'fixture-1',
                'config_fingerprint': 'a' * 64, 'semantic_config_fingerprint': 'a' * 64,
                'state_fingerprint': fingerprint(analysis), 'trigger': trigger, 'analysis': analysis}
    snapshot['snapshot_id'] = 'snapshot-' + fingerprint(snapshot)
    revision = None
    if previous is not None:
        revision = {'schema_version': '1.0.0', 'synthetic': True, 'replay_version': 'dual-source-replay-1',
                    'revision_number': number, 'old_snapshot_id': previous['snapshot_id'], 'new_snapshot_id': snapshot['snapshot_id'],
                    'old_snapshot_number': number - 1, 'new_snapshot_number': number,
                    'old_state_fingerprint': previous['state_fingerprint'], 'new_state_fingerprint': snapshot['state_fingerprint'],
                    'available_at': trigger['available_at'], 'trigger': trigger, 'config_version': 'fixture-1',
                    'config_fingerprint': 'a' * 64, 'semantic_config_fingerprint': 'a' * 64,
                    'rule_version': 'fixture-1', 'reason': 'fixture', 'evidence_refs': []}
        revision['revision_id'] = 'revision-' + fingerprint(revision)
    return snapshot, revision


class HistorySpoolTests(unittest.TestCase):
    def run_case(self, root, *, sink=False, mutate_future=False, case='normal'):
        networks, process, _, config = fixture(root / 'inputs', case=case)
        if mutate_future:
            raw = bytearray(networks[1].read_bytes()); raw[-2] = 5; networks[1].write_bytes(raw)
            process.write_text(process.read_text().replace(',1\n', ',2\n'))
        history = HistorySink(root / 'history', run_id='prototype', attempt_id=1, version=VERSION,
                              checkpoint_interval=4) if sink else None
        run = execute(networks, process, config, history_sink=history)
        self.addCleanup(run['inputs'].close)
        return run

    def reader(self, root, run):
        history = HistoryReader(root / 'history', expected_manifest_sha256=run['history_spool']['manifest_sha256'],
                                expected_context=run['history_spool']['manifest']['context'])
        self.addCleanup(history.close)
        return history

    def test_actual_small_snapshots_revisions_and_business_fields_equal_v1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = replay_core.ReplayCore
            instances = []
            def capture(*args, **kwargs):
                engine = original(*args, **kwargs); instances.append(engine); return engine
            legacy = self.run_case(root / 'legacy')
            with patch.object(replay_core, 'ReplayCore', side_effect=capture):
                modern = self.run_case(root / 'spooled', sink=True)
            self.assertEqual(modern['analysis'], legacy['analysis'])
            self.assertEqual(modern['metrics'], legacy['metrics'])
            history = self.reader(root / 'spooled', modern)
            for index, expected in enumerate(legacy['snapshots']):
                self.assertEqual(history.snapshot(index, projection=True), json.loads(canonical(expected)))
            self.assertEqual(history.revisions(limit=100), legacy['revisions'])
            self.assertEqual(instances[0]._snapshots, [])
            self.assertEqual(instances[0]._history, [])
            self.assertEqual(instances[0]._snapshot_count, len(legacy['snapshots']))
            with self.assertRaisesRegex(ValueError, 'indexed_reader'):
                instances[0].snapshots()
            with self.assertRaisesRegex(ValueError, 'v2_publisher'):
                _semantic_payloads(modern, {})
            self.assertIn('source_publication_verification_required', modern['history_status'])
            self.assertIsNone(modern['snapshots'])

    def test_future_source_edits_do_not_change_prefix_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshots = []
            for variant in (False, True):
                root = Path(tmp) / str(variant)
                run = self.run_case(root, sink=True, mutate_future=variant)
                reader = self.reader(root, run)
                snapshots.append([reader.snapshot(index, projection=True) for index in range(4)])
            self.assertEqual(snapshots[0], snapshots[1])
            pending = snapshots[0][3]['analysis']
            self.assertEqual(pending['operations'][0]['replay']['status'], 'pending_response')
            self.assertEqual(pending['candidates'], [])
            self.assertEqual(len(pending['network']), 1)

    def test_expired_and_late_history_remains_field_equivalent(self):
        for case in ('response_expired', 'allowed_late'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                old = self.run_case(root / 'old', case=case)
                new = self.run_case(root / 'new', sink=True, case=case)
                reader = self.reader(root / 'new', new)
                self.assertEqual(new['analysis'], old['analysis'])
                self.assertEqual([reader.snapshot(i, projection=True) for i in range(len(old['snapshots']))], json.loads(canonical(old['snapshots'])))
                self.assertEqual(reader.revisions(), old['revisions'])

    def test_delta_checkpoint_restore_and_disk_sharing_with_bounded_ram_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sink = HistorySink(root / 'history', run_id='synthetic-storage', attempt_id=1, version=VERSION)
            sink.bind('a' * 64, 'dual-source-replay-1')
            previous, logical_bytes, expected = None, 0, {}
            for number in range(140):
                snapshot, revision = make_snapshot(number, previous)
                sink.append(snapshot, revision)
                logical_bytes += len(canonical(snapshot))
                if number in (0, 1, 127, 128, 139):
                    expected[number] = copy.deepcopy(snapshot)
                previous = snapshot
            sealed = sink.seal()
            self.assertLess(sealed['manifest']['database']['size_bytes'], logical_bytes // 2)
            self.assertLessEqual(len(sink._recent), 4096)
            self.assertFalse(hasattr(sink, '_snapshots'))
            restored = root / 'restored'
            shutil.copytree(root / 'history', restored)
            reader = HistoryReader(restored, expected_manifest_sha256=sealed['manifest_sha256'])
            self.addCleanup(reader.close)
            for index, snapshot in expected.items():
                self.assertEqual(reader.snapshot(index), snapshot)
            self.assertEqual(reader.revisions(after=127, limit=3)[0]['revision_number'], 128)
            self.assertEqual(sealed['manifest']['snapshot_count'], 140)
            self.assertEqual(sealed['manifest']['revision_count'], 139)

    def test_missing_changed_inventory_and_wrong_run_are_rejected(self):
        for mutation in ('manifest', 'database', 'missing', 'extra', 'context'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                run = self.run_case(root, sink=True)
                digest = run['history_spool']['manifest_sha256']
                expected = run['history_spool']['manifest']['context']
                if mutation == 'manifest':
                    with (root / 'history/manifest.json').open('ab') as stream: stream.write(b' ')
                if mutation == 'database':
                    with (root / 'history/history.sqlite3').open('ab') as stream: stream.write(b'x')
                if mutation == 'missing': (root / 'history/history.sqlite3').unlink()
                if mutation == 'extra': (root / 'history/unknown').write_text('unlisted')
                if mutation == 'context': expected = dict(expected, attempt_id=2)
                with self.assertRaises(ValueError):
                    HistoryReader(root / 'history', expected_manifest_sha256=digest, expected_context=expected)

    def test_rehashed_missing_object_still_fails_logical_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = self.run_case(root, sink=True)
            database = root / 'history/history.sqlite3'
            con = sqlite3.connect(database)
            con.execute('DELETE FROM objects WHERE digest=(SELECT digest FROM objects LIMIT 1)')
            con.commit()
            count = con.execute('SELECT count(*) FROM objects').fetchone()[0]; con.close()
            path = root / 'history/manifest.json'; manifest = json.loads(path.read_text())
            manifest['object_count'] = count
            manifest['database'].update(sha256=file_hash(database), size_bytes=database.stat().st_size)
            raw = canonical(manifest) + b'\n'; path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'object_missing'):
                HistoryReader(root / 'history', expected_manifest_sha256=hashlib.sha256(raw).hexdigest())

    def test_limits_do_not_publish_partial_history_or_change_v1_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); networks, process, _, config = fixture(root / 'inputs')
            sink = HistorySink(root / 'failed', run_id='run', attempt_id=1, version=VERSION, max_objects=1)
            with self.assertRaises(ValueError):
                execute(networks, process, config, history_sink=sink)
            sink.close()
            self.assertFalse((root / 'failed/manifest.json').exists())
            with self.assertRaises(ValueError):
                sink.seal()
            with self.assertRaises(ValueError):
                HistoryReader(root / 'failed', expected_manifest_sha256='a' * 64)
            with self.assertRaisesRegex(ValueError, 'explicit_supported'):
                HistorySink(root / 'wrong', run_id='run', attempt_id=1, version='legacy')


if __name__ == '__main__':
    unittest.main()
