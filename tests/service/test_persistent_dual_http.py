"""Explicit persistent bridge, no Celery/default replacement."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('persistent_dual', ROOT/'services/python-cpag-generator/api/v2/persistent_dual.py')
bridge = importlib.util.module_from_spec(spec); spec.loader.exec_module(bridge)
app = FastAPI(); bridge.register(app); client = TestClient(app)

class PersistentHTTP(unittest.TestCase):
    def test_upload_preserves_fractional_profile_and_immutable_refs(self):
        sys.path.insert(0, str(ROOT/'scripts/validation'))
        from dual_source_fixtures import make_case
        import json
        with tempfile.TemporaryDirectory() as root:
            paths=make_case(Path(root)/'fixture')
            config=json.loads(paths[2].read_text()); config['clocks']['network']['offset_seconds']=0.125
            paths[2].write_text(json.dumps(config))
            settings={'CPAG_PERSISTENT_ENABLED':'1','CPAG_PERSISTENT_ROOT':root,'CPAG_PERSISTENT_TOKEN':'x'*32,'CPAG_PERSISTENT_API_URL':'http://127.0.0.1:12345'}
            def enqueue(path,body):
                self.assertEqual(path,'/v1/jobs'); self.assertEqual(body['payload']['kind'],'dual-source')
                self.assertEqual(body['payload']['config_fingerprint'],bridge._core().fingerprint(config))
                for role in ('network','process','profile'):
                    self.assertTrue((Path(root)/body['payload'][role]['path']).is_file())
                return {'id':body['id']}
            with patch.dict(os.environ,settings),patch.object(bridge,'call',side_effect=enqueue):
                files={field:(path.name,path.read_bytes()) for field,path in zip(('network_file','process_file','profile_file'),paths)}
                result=client.post('/cpag/persistent/dual-source',files=files,data={'synthetic_confirmed':'true'})
                self.assertEqual(result.status_code,202,result.text)
                self.assertEqual(list((Path(root)/'inputs').iterdir()),[])
                files['profile_file']=('profile.json',b'{"synthetic":false}')
                self.assertEqual(client.post('/cpag/persistent/dual-source',files=files,data={'synthetic_confirmed':'true'}).status_code,400)
    def test_disabled_is_explicit(self):
        with patch.dict(os.environ, {'CPAG_PERSISTENT_ENABLED':'0'}):
            self.assertEqual(client.get('/cpag/persistent/status/test').status_code, 503)
    def test_identity_and_kind(self):
        self.assertEqual(client.get('/cpag/persistent/status/bad.id').status_code,400)
        with patch.object(bridge,'call',return_value={'payload':{'kind':'packet'}}):
            self.assertEqual(client.get('/cpag/persistent/status/test').status_code,409)
    def test_recovery_reason_and_cancel_state_retained(self):
        item={'id':'test','state':'cancelling','payload':{'kind':'dual-source'},'recovery_reason':'attempt 1 lacks exit proof','attempt_history':[{'attempt':1}]}
        with patch.object(bridge,'call',return_value=item):
            result=client.get('/cpag/persistent/status/test').json()
            self.assertEqual(result['status'],'cancelling'); self.assertEqual(result['error'],item['recovery_reason'])
            self.assertEqual(client.post('/cpag/persistent/cancel/test').json()['status'],'cancelling')
    def test_failed_task_reports_worker_error(self):
        item={'id':'failed-input','state':'failed','payload':{'kind':'dual-source'},
              'last_error':'unsupported_or_empty_process: invalid_csv_record_width',
              'recovery_reason':None}
        with patch.object(bridge,'call',return_value=item):
            result=client.get('/cpag/persistent/status/failed-input').json()
            self.assertEqual(result['status'],'failed')
            self.assertEqual(result['error'],item['last_error'])
    def test_no_download_for_unpublished_or_arbitrary_files(self):
        with patch.object(bridge,'call',return_value={'id':'test','state':'running','payload':{'kind':'dual-source'}}):
            self.assertEqual(client.get('/cpag/persistent/download/test/graph.json').status_code,409)
        self.assertEqual(client.get('/cpag/persistent/download/test/secret').status_code,404)
    def test_missing_selection(self):
        with patch.object(bridge,'job',return_value={}):
            self.assertEqual(client.get('/cpag/persistent/dual-source/test/evidence').status_code,400)
            self.assertEqual(client.get('/cpag/persistent/dual-source/test/evidence?operation=x&change=y').status_code,400)
    def test_only_local_api_supported(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ,{'CPAG_PERSISTENT_ENABLED':'1','CPAG_PERSISTENT_ROOT':root,'CPAG_PERSISTENT_TOKEN':'x'*32,'CPAG_PERSISTENT_API_URL':'http://remote:8000'}):
            self.assertEqual(client.get('/cpag/persistent/status/test').status_code,503)
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ,{'CPAG_PERSISTENT_ENABLED':'1','CPAG_PERSISTENT_ROOT':root,'CPAG_PERSISTENT_TOKEN':'x'*32,'CPAG_PERSISTENT_API_URL':'http://127.0.0.1:12345@remote.example'}):
            self.assertEqual(client.get('/cpag/persistent/status/test').status_code,503)
if __name__=='__main__':unittest.main()
