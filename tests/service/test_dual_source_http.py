"""Queued dual-source bridge and publication integrity tests."""
import hashlib
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
sys.path.insert(0, str(ROOT / 'services/python-cpag-generator'))
sys.path.insert(0, str(ROOT / 'services/analysis/src'))
sys.path.insert(0, str(ROOT / 'scripts/validation'))
from fastapi.testclient import TestClient
from api.v2.app import app
from api.v2 import dual_source

client = TestClient(app)


class FakeCore:
    def __init__(self):
        self.calls = 0

    def export_task(self, network, process, profile, output):
        self.calls += 1
        if Path(network).read_bytes() == b'bad pcap':
            raise ValueError('Invalid parsed network input')
        output.mkdir(parents=True)
        retained = output / 'dual' / 'sources'
        retained.mkdir(parents=True)
        (retained / 'network.pcap').write_bytes(Path(network).read_bytes())
        (retained / 'process.csv').write_bytes(Path(process).read_bytes())
        (retained / 'profile.json').write_bytes(Path(profile).read_bytes())
        artifacts = []
        for name in dual_source.ARTIFACTS[:-1]:
            path = output / name
            path.write_text(json.dumps({'name': name}))
            artifacts.append({'path': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                              'size_bytes': path.stat().st_size})
        result = {'synthetic': True, 'status': 'succeeded', 'warnings': [], 'artifacts': artifacts}
        (output / 'run_manifest.json').write_text(json.dumps(result))
        return result

    def verify_task(self, output):
        return True

    def query_task(self, output, operation_id=None, change_id=None):
        identifier = operation_id or change_id
        if identifier == 'missing':
            raise KeyError(identifier)
        return {'identifier': identifier, 'source_ref': {'file_sha256': 'abc'}}


class DualSourceHTTP(unittest.TestCase):
    def files(self, network=b'pcap bytes', process=b'time,tag\n2026-01-01T00:00:00Z,1\n',
              profile=b'{"synthetic":true}', network_name='network.pcap'):
        return {'network_file': (network_name, network),
                'process_file': ('process.csv', process),
                'profile_file': ('profile.json', profile)}

    def submit(self, **overrides):
        with patch.object(dual_source.celery_app, 'send_task') as queue:
            response = client.post('/cpag/dual-source', files=self.files(**overrides),
                                   data={'synthetic_confirmed': 'true'})
            if response.status_code == 202:
                self.assertEqual(queue.call_args.kwargs['queue'], 'cpag_generation')
                self.assertEqual(queue.call_args.args[0], dual_source.TASK_NAME)
            return response

    def execute(self, identifier, core):
        with patch.object(dual_source, '_core', return_value=core), \
             patch('infrastructure.slots.acquire'), \
             patch.object(dual_source.execute_dual_source, 'update_state'), \
             patch('redis.from_url'):
            return dual_source.execute_dual_source.run(identifier)

    def test_opt_in_and_upload_validation(self):
        self.assertEqual(client.post('/cpag/dual-source', files=self.files()).status_code, 400)
        self.assertEqual(self.submit(profile=b'{"synthetic":false}').status_code, 400)
        self.assertEqual(self.submit(profile=b'{bad').status_code, 400)
        self.assertEqual(self.submit(network_name='network.jsonl').status_code, 400)
        self.assertEqual(self.submit(network=b'').status_code, 400)

    def test_queue_failure(self):
        with patch.object(dual_source.celery_app, 'send_task', side_effect=RuntimeError('offline')):
            response = client.post('/cpag/dual-source', files=self.files(),
                                   data={'synthetic_confirmed': 'true'})
        self.assertEqual(response.status_code, 503)

    def test_complete_result_evidence_and_integrity(self):
        response = self.submit(network_name='network.pcapng')
        self.assertEqual(response.status_code, 202, response.text)
        identifier = response.json()['task_id']
        self.assertEqual(response.json()['task_kind'], dual_source.TASK_KIND)
        self.assertEqual(client.get('/cpag/status/' + identifier).json()['status'], 'queued')
        core = FakeCore()
        self.execute(identifier, core)
        self.assertEqual(core.calls, 1)
        # Publication verifier invokes the actual core verifier after the copied-file checks.
        with patch.object(dual_source, '_core', return_value=core):
            result = client.get('/cpag/result/' + identifier + '/json')
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.json()['task_kind'], dual_source.TASK_KIND)
            self.assertEqual(set(result.json()['data']),
                             {'graph', 'events', 'dataset', 'quality', 'analysis', 'run_manifest'})
            self.assertEqual(client.get('/cpag/result/' + identifier).status_code, 200)
            artifacts = client.get('/cpag/artifacts/' + identifier).json()
            self.assertEqual(len(artifacts['files']), 6)
            self.assertEqual(client.get('/cpag/dual-source/' + identifier + '/evidence',
                                        params={'operation': 'op-1'}).json()['identifier'], 'op-1')
            self.assertEqual(client.get('/cpag/dual-source/' + identifier + '/evidence',
                                        params={'change': 'missing'}).status_code, 404)
            self.assertEqual(client.get('/cpag/dual-source/' + identifier + '/evidence').status_code, 400)
            self.assertEqual(client.get('/cpag/dual-source/' + identifier + '/evidence',
                                        params={'operation': 'x', 'change': 'y'}).status_code, 400)
            graph = dual_source.task_dir(identifier) / 'graph.json'
            original = graph.read_bytes()
            for fault in ('tamper', 'missing'):
                if fault == 'tamper':
                    graph.write_text('{}')
                else:
                    graph.unlink()
                for url in ('/cpag/result/' + identifier, '/cpag/result/' + identifier + '/json',
                            '/cpag/artifacts/' + identifier,
                            '/cpag/download/' + identifier + '/graph.json',
                            '/cpag/dual-source/' + identifier + '/evidence?operation=op-1'):
                    self.assertEqual(client.get(url).status_code, 409, url)
                graph.write_bytes(original)
            retained = dual_source.task_dir(identifier) / 'sources' / 'network.pcapng'
            retained.chmod(0o644)
            source_bytes = retained.read_bytes()
            retained.write_bytes(source_bytes + b'changed')
            self.assertEqual(client.get('/cpag/result/' + identifier + '/json').status_code, 409)
            self.assertEqual(client.get('/cpag/dual-source/' + identifier + '/evidence',
                                        params={'operation': 'op-1'}).status_code, 409)
            retained.write_bytes(source_bytes)
            retained.chmod(0o444)
            self.assertEqual(client.get('/cpag/status/' + identifier).json()['status'], 'completed')
            self.assertEqual(client.get('/cpag/download/' + identifier + '/sources').status_code, 404)
        with patch.object(dual_source, '_core', return_value=core):
            self.execute(identifier, core)
        self.assertEqual(core.calls, 1)

    def test_invalid_parsed_input_fails_without_publication(self):
        identifier = self.submit(network=b'bad pcap').json()['task_id']
        with self.assertRaisesRegex(ValueError, 'Invalid parsed network input'):
            self.execute(identifier, FakeCore())
        self.assertEqual(client.get('/cpag/status/' + identifier).json()['status'], 'failed')
        self.assertEqual(client.get('/cpag/result/' + identifier + '/json').status_code, 409)
        self.assertEqual(client.get('/cpag/dual-source/' + identifier + '/evidence',
                                    params={'operation': 'op-1'}).status_code, 409)
        self.assertTrue((dual_source.task_dir(identifier) / 'sources' / 'network.pcap').exists())

    def test_corrupt_copy_fails_before_terminal_success(self):
        identifier = self.submit().json()['task_id']
        actual_copy = dual_source.shutil.copyfile

        def corrupt_analysis(source, destination):
            result = actual_copy(source, destination)
            if Path(destination).name == 'analysis.json' and Path(destination).parent == dual_source.task_dir(identifier):
                Path(destination).write_text('{}')
            return result

        with patch.object(dual_source.shutil, 'copyfile', side_effect=corrupt_analysis):
            with self.assertRaisesRegex(ValueError, 'Published artifact copy differs'):
                self.execute(identifier, FakeCore())
        failed = client.get('/cpag/status/' + identifier).json()
        self.assertEqual(failed['status'], 'failed')
        self.assertEqual(failed['files'], [])
        with self.assertRaisesRegex(ValueError, 'cannot be replayed'):
            self.execute(identifier, FakeCore())
        self.assertEqual(client.get('/cpag/status/' + identifier).json(), failed)

    def test_real_core_fixture_round_trip(self):
        from dual_source_fixtures import make_case
        from cpag_core import dual_source_export
        with tempfile.TemporaryDirectory() as tmp:
            network, process, profile = make_case(Path(tmp) / 'inputs')
            response = self.submit(network=network.read_bytes(), process=process.read_bytes(),
                                   profile=profile.read_bytes())
            self.assertEqual(response.status_code, 202, response.text)
            identifier = response.json()['task_id']
            self.execute(identifier, dual_source_export)
            result = client.get('/cpag/result/' + identifier + '/json')
            self.assertEqual(result.status_code, 200, result.text)
            operation_id = result.json()['data']['analysis']['operations'][0]['operation_id']
            self.assertTrue(operation_id)
            evidence = client.get('/cpag/dual-source/' + identifier + '/evidence',
                                  params={'operation': operation_id})
            self.assertEqual(evidence.status_code, 200, evidence.text)
            self.assertTrue(evidence.json()['verified_original_evidence'])


if __name__ == '__main__':
    unittest.main()
