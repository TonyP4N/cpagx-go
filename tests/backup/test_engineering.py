import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'scripts/backup'))
import engineering
import bundle


class EngineeringSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base/'snapshot'
        host = self.source/'host'
        (host/'shared').mkdir(parents=True)
        (host/'control/jobs/a').mkdir(parents=True)
        (host/'control/jobs/a/proof.json').write_text('retained proof')
        (host/'control/capacity.json').write_text(json.dumps({'root': '/cpag/shared', 'reservations': {'a:1': 65536}}))
        (host/'config.json').write_text('{"secret":"never report"}')
        data = self.source/'database-and-shared'
        data.mkdir()
        shutil.copytree(host/'shared', data/'files')
        (data/'database.dump').write_bytes(b'synthetic dump fixture; never used for database restore')
        self.data = {'rows': [], 'attempts': [], 'files': {}, 'database_sha256': bundle.sha(data/'database.dump')}
        (data/'bundle.json').write_text(json.dumps(self.data))
        self.meta = {'format': 'cpag-engineering-snapshot-v1', 'synthetic_only': True,
                     'data_root': '/cpag', 'source_version': 'test',
                     'host_files': bundle.inventory(host),
                     'database_bundle_sha256': bundle.sha(data/'bundle.json')}
        (self.source/'snapshot.json').write_text(json.dumps(self.meta))

    def test_complete_control_and_ledger_snapshot(self):
        meta, _ = engineering.verify(self.source)
        self.assertIn('control/jobs/a/proof.json', meta['host_files'])
        self.assertIn('config.json', meta['host_files'])

    def test_format6_requires_exact_preparation_metadata_set_but_legacy_stays_readable(self):
        self.data.update(format_version=6,catalog={name:[] for name in bundle.V5_CATALOG_TABLES})
        path=self.source/'database-and-shared/bundle.json'
        def write():
            path.write_text(json.dumps(self.data));self.meta['database_bundle_sha256']=bundle.sha(path)
            (self.source/'snapshot.json').write_text(json.dumps(self.meta))
        write()
        with self.assertRaisesRegex(ValueError,'format6 preparation catalog missing'):engineering.verify(self.source)
        self.data['catalog']={name:[] for name in bundle.CATALOG_TABLES};write()
        self.assertEqual(engineering.verify(self.source)[1]['format_version'],6)

    def test_missing_and_tampered_control_proof_rejected(self):
        proof = self.source/'host/control/jobs/a/proof.json'
        proof.write_text('altered')
        with self.assertRaisesRegex(ValueError, 'checksum'): engineering.verify(self.source)
        proof.unlink()
        with self.assertRaisesRegex(ValueError, 'checksum'): engineering.verify(self.source)

    def test_dump_tamper_rejected(self):
        (self.source/'database-and-shared/database.dump').write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'dump checksum'): engineering.verify(self.source)

    def test_under_counting_or_wrong_root_ledger_rejected(self):
        path = self.source/'host/control/capacity.json'
        path.write_text(json.dumps({'root': '/cpag/shared', 'reservations': {'a:1': 0}}))
        with self.assertRaisesRegex(ValueError, 'undercounts'):
            engineering.ledger_check(self.source/'host', Path('/cpag'))
        path.write_text(json.dumps({'root': '/other/shared', 'reservations': {'a:1': 65536}}))
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            engineering.ledger_check(self.source/'host', Path('/cpag'))

    def test_restore_requires_confirmation_and_original_absent_path(self):
        with self.assertRaisesRegex(ValueError, 'confirm'):
            engineering.restore('cpag-engineering', self.source, '/cpag', 'incorrect')
        with self.assertRaisesRegex(ValueError, 'original absolute'):
            engineering.restore('cpag-engineering', self.source, self.base/'different', bundle.sha(self.source/'snapshot.json'))

    def test_services_or_even_stopped_compute_block_checkpoint(self):
        with patch.object(engineering, 'docker', side_effect=['cpag-engineering-api\ncpag-engineering-postgres', '']):
            with self.assertRaisesRegex(ValueError, 'maintenance'):
                engineering.maintenance('cpag-engineering', Path('/cpag'))
        with patch.object(engineering, 'docker', side_effect=['cpag-engineering-postgres', 'stopped-container-id']):
            with self.assertRaisesRegex(ValueError, 'maintenance'):
                engineering.maintenance('cpag-engineering', Path('/cpag'))

    def test_docker_unavailable_is_not_empty_inventory(self):
        with patch.object(engineering, 'docker', side_effect=OSError('unavailable')):
            with self.assertRaises(OSError): engineering.maintenance('cpag-engineering', Path('/cpag'))

    def test_control_proof_must_match_database_even_before_snapshot(self):
        root = self.source/'host'
        base = root/'control/jobs/a/attempt-1.worker'
        base.mkdir()
        record = {'id': 'a', 'attempt': 1, 'worker': 'w', 'token': 'test', 'container_id': 'c', 'location': 'docker:d:s'}
        proof = {**record, 'removed': True, 'exited': True}
        (base/'execution.json').write_text(json.dumps(record))
        (base/'exit.json').write_text(json.dumps(proof))
        row = {'job_id': 'a', 'attempt': 1, 'worker': 'w', 'attempt_token': 'test', 'container_id': 'c',
               'location': 'docker:d:s', 'executor_kind': 'isolated-v2', 'exited_at': 'timestamp',
               'exit_receipt': {'group_exited': False, 'child_pid': 0, 'guardian_pid': 0, **proof}}
        self.assertTrue(engineering.control_check(root, [row])['valid'])
        row['exit_receipt']['removed'] = False
        with self.assertRaisesRegex(ValueError, 'exit proof differs'): engineering.control_check(root, [row])
        (base/'execution.json').unlink()
        with self.assertRaisesRegex(ValueError, 'control proof missing'): engineering.control_check(root, [row])


if __name__ == '__main__': unittest.main()
