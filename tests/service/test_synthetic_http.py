"""HTTP + actual core regression tests; broker execution is separately exercised live."""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
TEMP = tempfile.TemporaryDirectory()
os.environ['OUTPUT_DIR'] = TEMP.name + '/outputs'
os.environ['UPLOAD_DIR'] = TEMP.name + '/uploads'
sys.path.insert(0, str(ROOT/'services/python-cpag-generator'))
sys.path.insert(0, str(ROOT/'services/analysis/src'))
from fastapi.testclient import TestClient
from api.v2.app import app
from api.v2 import synthetic
client = TestClient(app)

class SyntheticHTTP(unittest.TestCase):
    def files(self, profile=None, network=None):
        return {'network_file': ('network.jsonl', network if network is not None else (ROOT/'tests/fixtures/synthetic/network.normalized.jsonl').read_bytes()),
                'process_file': ('process.csv', (ROOT/'tests/fixtures/synthetic/process.csv').read_bytes()),
                'profile_file': ('profile.json', profile if profile is not None else (ROOT/'profiles/synthetic-demo.json').read_bytes())}

    def submit(self, **kwargs):
        with patch.object(synthetic.celery_app, 'send_task') as queue:
            response = client.post('/cpag/synthetic', files=self.files(**kwargs), data={'synthetic_confirmed': 'true'})
            if response.status_code == 202:
                self.assertEqual(queue.call_args.kwargs['queue'], 'cpag_generation')
            return response

    def execute(self, identifier):
        with patch('infrastructure.slots.acquire'), patch.object(synthetic.execute_synthetic, 'update_state'), patch('redis.from_url'):
            return synthetic.execute_synthetic.run(identifier)

    def test_opt_in_and_profile_required(self):
        self.assertEqual(client.post('/cpag/synthetic', files=self.files()).status_code, 400)
        self.assertEqual(self.submit(profile=b'{"synthetic":false}').status_code, 400)
        self.assertEqual(self.submit(profile=b'{bad').status_code, 400)

    def test_real_core_http_artifacts_and_batch(self):
        response = self.submit()
        self.assertEqual(response.status_code, 202, response.text)
        identifier = response.json()['task_id']
        self.assertEqual(client.get('/cpag/status/'+identifier).json()['status'], 'queued')
        self.execute(identifier)
        batch = client.get('/cpag/status/batch', params={'task_ids': identifier})
        self.assertEqual(batch.json()[identifier]['status'], 'completed')
        tasks = client.get('/cpag/tasks').json()
        self.assertIsInstance(tasks, list)
        self.assertTrue(any(task['task_id'] == identifier for task in tasks))
        result = client.get('/cpag/result/'+identifier+'/json').json()
        self.assertTrue(result['synthetic'])
        self.assertEqual(result['data']['graph']['edges'], [])
        self.assertEqual(result['data']['graph']['claims'], [])
        artifacts = client.get('/cpag/artifacts/'+identifier).json()
        self.assertEqual(len(artifacts['files']), 5)
        for artifact in artifacts['files']:
            download = client.get(artifact['download_url'])
            self.assertEqual(download.status_code, 200)
            self.assertIsNotNone(json.loads(download.content))
        self.assertEqual(client.get('/cpag/download/'+identifier+'/profile.json').status_code, 404)
        self.assertEqual(client.get('/cpag/result/'+identifier).status_code, 200)
        from cpag_core.pipeline import file_hash, resolve_evidence
        source_directory = synthetic.task_dir(identifier) / 'sources'
        dataset = json.loads(synthetic.artifact_path(identifier, 'dataset.json').read_text())
        evidence_files = {}
        for source in dataset['files']:
            retained = source_directory / source['name']
            self.assertTrue(retained.is_file())
            self.assertEqual(file_hash(retained), source['sha256'])
            self.assertEqual(retained.stat().st_size, source['size_bytes'])
            evidence_files[source['sha256']] = retained
        self.assertTrue((source_directory/'profile.json').is_file())
        for event in result['data']['events']:
            self.assertTrue(resolve_evidence(event['source_ref'], evidence_files).is_file())
        self.assertFalse((synthetic.UPLOADS / identifier).exists())
        self.assertEqual(client.get('/cpag/download/'+identifier+'/sources').status_code, 404)


    def test_queue_failure_explicit(self):
        with patch.object(synthetic.celery_app, 'send_task', side_effect=RuntimeError('offline')):
            result = client.post('/cpag/synthetic', files=self.files(), data={'synthetic_confirmed': 'true'})
        self.assertEqual(result.status_code, 503)

    def test_core_failure_visible(self):
        response = self.submit(network=b'{bad\n')
        identifier = response.json()['task_id']
        # Invalid network lines can produce quality warnings while valid process observations survive.
        with patch('cpag_core.pipeline.run', side_effect=ValueError('invalid synthetic input')):
            with self.assertRaises(ValueError):
                self.execute(identifier)
        self.assertEqual(client.get('/cpag/status/'+identifier).json()['status'], 'failed')
        self.assertEqual(client.get('/cpag/result/'+identifier+'/json').status_code, 409)
        self.assertEqual(client.get('/cpag/artifacts/'+identifier).json()['files'], [])
        self.assertTrue((synthetic.task_dir(identifier)/'sources'/'network.jsonl').is_file())
        self.assertFalse((synthetic.UPLOADS/identifier).exists())

    def test_legacy_empty_submission_is_rejected(self):
        self.assertEqual(client.post('/cpag/generate').status_code, 400)

    def test_capacity_rejection_and_redis_failure_are_not_swallowed(self):
        from infrastructure.slots import acquire
        from unittest.mock import Mock
        redis_client = Mock()
        redis_client.eval.return_value = 0
        with self.assertRaises(RuntimeError):
            acquire(redis_client, 'id', 1)
        redis_client.eval.side_effect = ConnectionError('offline')
        with self.assertRaises(ConnectionError):
            acquire(redis_client, 'id', 1)
        with self.assertRaises(RuntimeError):
            acquire(None, 'id', 1)

    def test_completed_delivery_is_verified_and_idempotent(self):
        identifier = self.submit().json()['task_id']
        first = self.execute(identifier)
        with patch('infrastructure.slots.acquire') as admission:
            repeated = synthetic.execute_synthetic.run(identifier)
            admission.assert_not_called()
        self.assertEqual(first, repeated)
        path = synthetic.artifact_path(identifier, 'graph.json')
        path.write_text('{}')
        with self.assertRaises(ValueError):
            synthetic.execute_synthetic.run(identifier)
        self.assertEqual(client.get('/cpag/status/'+identifier).json()['status'], 'completed')

    def test_duplicate_active_preserves_status_and_staging(self):
        from celery.exceptions import Ignore
        from infrastructure.slots import DuplicateActive
        identifier = self.submit().json()['task_id']
        directory = synthetic.UPLOADS / identifier
        original = client.get('/cpag/status/'+identifier).json()
        with patch('infrastructure.slots.acquire', side_effect=DuplicateActive()), patch('redis.from_url'):
            with self.assertRaises(Ignore):
                synthetic.execute_synthetic.run(identifier)
        self.assertTrue((directory/'network.jsonl').is_file())
        self.assertEqual(original, client.get('/cpag/status/'+identifier).json())

    def test_invalid_identifier_bounded(self):
        self.assertEqual(client.get('/cpag/status/not-a-uuid').status_code, 400)
        self.assertEqual(client.get('/cpag/artifacts/not-a-uuid').status_code, 400)

if __name__ == '__main__':
    unittest.main()
