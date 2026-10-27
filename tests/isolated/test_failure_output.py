"""Native compute errors survive host container cleanup and bounded diagnostics."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from cpag_worker.isolated import DockerExecutor
from cpag_worker.worker import digest

class FakeAPI:
    def __init__(self):self.calls=[]
    def post(self,path,body):self.calls.append((path,body));return {}

class FailingExecutor(DockerExecutor):
    def capacity(self,*args,**kwargs):pass
    def location(self):return 'docker:unit:'+self.scope
    def inspect(self,container):return {'State':{'Running':True}}
    def stop_container(self,record):self.stopped=True
    def docker(self,*args,**kwargs):
        if args[0]=='create':return 'a'*64
        if args[0]=='start':return ''
        if args[0]=='exec':return json.dumps({'returncode':2})
        raise AssertionError(args)

class FailureOutputTests(unittest.TestCase):
    def test_stderr_native_exit_and_limit_retained_in_failure_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);shared=base/'shared';shared.mkdir();payload={'kind':'dual-source-replay','replay_version':'dual-source-replay-1','config_fingerprint':'a'*64}
            for name,content in [('network',b'fixture'),('process',b'time,value\n'),('profile',b'{"synthetic":true}')]:
                path=shared/(name+('.json' if name=='profile' else '.pcap' if name=='network' else '.csv'));path.write_bytes(content)
                payload[name]={'path':path.name,'sha256':digest(path)}
            api=FakeAPI();worker=FailingExecutor(api,api,shared,base/'control','host');claim={'id':'failed','attempt':1,'worker':'host','token':'private-token','payload':payload,'output_dir':'jobs/failed/attempt-1','executor':'isolated-v2','location':worker.location()}
            raw=b'argparse: unrecognized arguments: --synthetic\n'+b'x'*70000
            def logs(*args,**kwargs):
                self.assertEqual(args[0][:2],['docker','logs']);self.assertEqual(kwargs['stderr'],subprocess.STDOUT)
                return subprocess.CompletedProcess(args[0],0,stdout=raw)
            with patch('cpag_worker.isolated.subprocess.run',side_effect=logs):self.assertEqual(worker.attempt(claim),'failed')
            receipt=json.loads((base/'control/jobs/failed/attempt-1.worker/failure.json').read_text())
            self.assertEqual(receipt['compute_returncode'],2)
            self.assertEqual(receipt['failure_category'],'calculation_exit')
            self.assertEqual(receipt['output_streams'],'combined_stdout_stderr')
            self.assertIn('unrecognized arguments',receipt['stderr'])
            self.assertEqual(len(receipt['stderr'].encode()),65536)
            self.assertTrue(worker.stopped)
            self.assertTrue(any(path.endswith('/fail') for path,_ in api.calls))
            self.assertFalse(any(path.endswith('/complete') for path,_ in api.calls))

if __name__=='__main__':unittest.main()
