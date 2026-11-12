import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from cpag_core.evidence_web import handler
ROOT=Path(__file__).resolve().parents[2]

class WebEvidenceTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name)/'demo'
        shutil.copytree(ROOT/'docs/refactor/validation-round5/packet-job-demo',self.root)
        self.network=next((self.root/'inputs').glob('*.pcap'))
        self.server=ThreadingHTTPServer(('127.0.0.1',0),handler(self.root/'artifacts',self.network))
        thread=threading.Thread(target=self.server.serve_forever,daemon=True);thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.url='http://127.0.0.1:'+str(self.server.server_port)
    def get(self,path):
        with urllib.request.urlopen(self.url+path) as response:return response.read()
    def test_graph_node_field_raw_frame_chain(self):
        self.assertIn('观测图'.encode(),self.get('/'))
        graph=json.loads(self.get('/api/graph'));edge=graph['graph']['edges'][0]
        q=json.loads(self.get('/api/evidence?event='+edge['source']+'&field=cip.path'))
        self.assertEqual(q['event']['event_id'],edge['source'])
        self.assertTrue(q['verified_fields']['cip.path'][0]['raw_hex'])
    def test_tamper_and_arbitrary_path_rejected(self):
        self.network.write_bytes(b'bad')
        for route in ('/api/graph','/api/evidence?event=bad','/api/evidence?event=bad&path=/etc/passwd'):
            with self.assertRaises(urllib.error.HTTPError) as caught:self.get(route)
            self.assertEqual(caught.exception.code,409)
        with self.assertRaises(urllib.error.HTTPError) as caught:self.get('/etc/passwd')
        self.assertEqual(caught.exception.code,404)
