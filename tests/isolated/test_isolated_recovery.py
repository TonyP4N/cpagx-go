"""Mixed recovery records must not poison unrelated attempts."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from cpag_worker.isolated import DockerExecutor,atomic_json
from cpag_worker.worker import API

class Response:
    def __init__(self,value):self.raw=json.dumps(value).encode()
    def read(self,*_):return self.raw
    def __enter__(self):return self
    def __exit__(self,*_):pass

class RecoveryIsolation(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        base=Path(self.temp.name);self.shared=base/'shared';self.shared.mkdir()
        self.worker=DockerExecutor(API('http://worker','w'),API('http://control','c'),self.shared,base/'control','host')
        self.good={'id':'good','attempt':1,'worker':'host','token':'secret','location':'docker:local:'+self.worker.scope,'container_id':'good-id'}
        self.calls=[]
        self.worker.docker=lambda *args,**kwargs:'local' if args[0]=='info' else '' if args[0]=='ps' else '[]'
        self.worker.stop_container=lambda record:self.calls.append(record['id'])
    def write(self,record):
        path=self.worker.control/'jobs'/record['id']/'attempt-1.worker'/'execution.json';atomic_json(path,record);return path
    def url(self,request,**_):
        if '/executions?' in request.full_url:return Response([])
        if request.full_url.endswith('/attempts'):return Response([])
        return Response({'state':'cancelling','attempt':1,'lease_valid':False})
    def test_bad_records_do_not_block_good(self):
        for fault in ('corrupt','foreign','missing'):
            with self.subTest(fault=fault),patch('urllib.request.urlopen',side_effect=self.url):
                self.calls.clear();self.write(self.good)
                bad={**self.good,'id':'bad','container_id':'bad-id'}
                path=self.write(bad)
                if fault=='corrupt':path.write_text('{')
                elif fault=='foreign':atomic_json(path,{**bad,'location':'docker:foreign'})
                else:
                    def stop(record):
                        if record['id']=='bad':raise subprocess.CalledProcessError(1,['docker','inspect'],stderr=b'No such container')
                        self.calls.append(record['id'])
                    self.worker.stop_container=stop
                outcomes=self.worker.recover()
                self.assertIn('good',self.calls)
                self.assertTrue(any(o.get('pending') for o in outcomes),outcomes)

    def test_non_object_records_are_pending(self):
        self.write(self.good)
        for value in (None,[],1,'bad'):
            path=self.worker.control/'jobs'/'bad'/'attempt-1.worker'/'execution.json';path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value))
            with patch('urllib.request.urlopen',side_effect=self.url):
                result=self.worker.recover()
            self.assertIn('good',self.calls)
            self.assertTrue(any(item.get('pending') for item in result))

    def test_global_docker_failure_is_retryable(self):
        self.write(self.good)
        original=self.worker.docker
        self.worker.docker=lambda *_args,**_kwargs:(_ for _ in ()).throw(OSError('daemon unavailable'))
        result=self.worker.recover();self.assertEqual(result[0]['scope'],'global');self.assertTrue(result[0]['retryable'])
        self.worker.docker=original
        with patch('urllib.request.urlopen',side_effect=self.url):self.worker.recover()
        self.assertIn('good',self.calls)

    def test_global_api_failure_is_retryable(self):
        import urllib.error
        with patch('urllib.request.urlopen',side_effect=urllib.error.HTTPError('http://control',503,'DB unavailable',{},None)):
            result=self.worker.recover()
        self.assertEqual(result[-1]['scope'],'global');self.assertTrue(result[-1]['retryable'])

    def test_missing_capacity_ledger_is_not_empty_budget(self):
        self.write(self.good)
        claim={**self.good,'payload':{name:{'path':name} for name in ('network','process','profile')}}
        for name in ('network','process','profile'):(self.shared/name).write_bytes(b'x')
        with self.assertRaisesRegex(ValueError,'ledger missing'):self.worker.capacity(claim)

    def test_concurrent_capacity_reservation_fails_closed(self):
        from concurrent.futures import ThreadPoolExecutor
        self.worker.host_budget_bytes=40*1024*1024
        for name in ('network','process','profile'):(self.shared/name).write_bytes(b'x')
        def reserve(number):
            claim={**self.good,'id':'budget-'+str(number),'payload':{name:{'path':name} for name in ('network','process','profile')}}
            try:self.worker.capacity(claim);return 'reserved'
            except OSError:return 'rejected'
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(reserve,(1,2)))
        self.assertCountEqual(results,['reserved','rejected'])

    def test_same_attempt_owner_cannot_fail_or_reduce_active_reservation(self):
        import threading
        import hashlib
        import shutil
        from concurrent.futures import ThreadPoolExecutor
        entered=threading.Event();release=threading.Event();posts=[]
        payload={}
        for name in ('network','process','profile'):
            path=self.shared/name;path.write_bytes(b'x');payload[name]={'path':name,'sha256':hashlib.sha256(b'x').hexdigest()}
        claim={**self.good,'payload':payload,'output_dir':'jobs/good/attempt-1'}
        self.worker.api.post=lambda path,body:posts.append(path) or {}
        original_copy=shutil.copyfile
        def blocking_copy(source,target):
            entered.set();release.wait(3);return original_copy(source,target)
        original_docker=self.worker.docker
        self.worker.docker=lambda *args,**kwargs:(_ for _ in ()).throw(OSError('synthetic create unavailable')) if args[0]=='create' else original_docker(*args,**kwargs)
        with patch('cpag_worker.isolated.shutil.copyfile',side_effect=blocking_copy),ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(self.worker.attempt,claim);self.assertTrue(entered.wait(2))
            ledger=self.worker.control/'capacity.json';before=json.loads(ledger.read_text())
            self.assertEqual(self.worker.attempt(claim),'reconcile_required')
            self.assertFalse(any(path.endswith('/fail') for path in posts))
            self.assertEqual(json.loads(ledger.read_text()),before)
            release.set();future.result(timeout=5)

    def test_post_coordinator_network_outage_is_global(self):
        import urllib.error
        self.write(self.good)
        proof=self.worker.control/'jobs'/'good'/'attempt-1.worker'/'exit.json'
        atomic_json(proof,{**self.good,'removed':True})
        self.worker.stop_container=DockerExecutor.stop_container.__get__(self.worker)
        self.worker.coordinator.post=lambda *_:(_ for _ in ()).throw(urllib.error.URLError('offline'))
        with patch('urllib.request.urlopen',side_effect=self.url):outcomes=self.worker.recover()
        self.assertTrue(any(o.get('scope')=='global' and o.get('pending')=='coordinator_unavailable' for o in outcomes),outcomes)

    def test_malformed_history_row_does_not_hide_later_attempt(self):
        self.write(self.good)
        def response(request,**kwargs):
            if request.full_url.endswith('/attempts'):return Response([None,[],{'attempt':'bad'},self.good])
            return self.url(request,**kwargs)
        with patch('urllib.request.urlopen',side_effect=response):result=self.worker.recover()
        self.assertIn('good',self.calls)
        self.assertTrue(any(o.get('pending')=='invalid_history_record' for o in result),result)

    def test_traversal_or_directory_identity_mismatch_is_never_used(self):
        self.write(self.good)
        path=self.worker.control/'jobs'/'bad'/'attempt-1.worker'/'execution.json'
        atomic_json(path,{**self.good,'id':'../outside'})
        with patch('urllib.request.urlopen',side_effect=self.url) as request:result=self.worker.recover()
        self.assertFalse(any('../' in call.args[0].full_url for call in request.call_args_list))
        self.assertIn('good',self.calls);self.assertTrue(any(o.get('pending')=='malformed_execution_record' for o in result))
        atomic_json(path,{**self.good,'id':'good'})
        with patch('urllib.request.urlopen',side_effect=self.url):result=self.worker.recover()
        self.assertTrue(any(o.get('pending')=='execution_record_path_mismatch' for o in result))

    def test_missing_capacity_ledger_with_only_intent_is_not_zero(self):
        claim={**self.good,'payload':{name:{'path':name} for name in ('network','process','profile')}}
        for name in ('network','process','profile'):(self.shared/name).write_bytes(b'x')
        target=self.worker.control/'jobs'/'good'/'attempt-1.worker'
        atomic_json(target/'create-intent.json',self.good)
        (target/'retained-input').write_bytes(b'x'*1024)
        with self.assertRaisesRegex(ValueError,'ledger missing'):self.worker.capacity(claim)

    def test_known_local_bare_daemon_location_is_backward_compatible(self):
        self.write({**self.good,'location':'docker:local'})
        with patch('urllib.request.urlopen',side_effect=self.url):self.worker.recover()
        self.assertIn('good',self.calls)

    def test_malformed_ledger_missing_root_raises_controlled_error(self):
        self.worker.control.mkdir(parents=True,exist_ok=True)
        (self.worker.control/'capacity.json').write_text(json.dumps({'reservations':{}}))
        claim={**self.good,'payload':{name:{'path':name} for name in ('network','process','profile')}}
        for name in ('network','process','profile'):(self.shared/name).write_bytes(b'x')
        with self.assertRaises(ValueError):self.worker.capacity(claim)

    def test_three_bad_records_before_good_remain_isolated_across_scans(self):
        good={**self.good,'id':'zz-good'};self.write(good)
        self.write({**self.good,'id':'00-missing'})
        corrupt=self.worker.control/'jobs'/'01-corrupt'/'attempt-1.worker'/'execution.json';atomic_json(corrupt,[])
        self.write({**self.good,'id':'02-foreign','location':'docker:foreign'})
        atomic_json(self.worker.control/'capacity.json',{'root':str(self.worker.root),'reservations':{}})
        def stop(record):
            if record['id']=='00-missing':raise subprocess.CalledProcessError(1,['docker','inspect'],stderr=b'no such object')
            self.calls.append(record['id'])
        self.worker.stop_container=stop
        for _ in range(3):
            self.calls.clear()
            with patch('urllib.request.urlopen',side_effect=self.url):result=self.worker.recover()
            reasons=['missing_container_without_exit_proof','malformed_execution_record','foreign_daemon']
            positions=[next(i for i,o in enumerate(result) if o.get('pending')==r) for r in reasons]
            healthy=next(i for i,o in enumerate(result) if o.get('id')=='zz-good' and o.get('exited'))
            self.assertEqual(positions,sorted(positions));self.assertTrue(all(i<healthy for i in positions));self.assertIn('zz-good',self.calls)

    def test_history_attempt_path_failure_does_not_block_later_attempt(self):
        job='same-job';first={**self.good,'id':job};second={**first,'attempt':2,'container_id':'second-id'}
        folder=self.worker.control/'jobs'/job;folder.mkdir(parents=True);(folder/'attempt-1.worker').write_text('damaged directory')
        atomic_json(self.worker.control/'capacity.json',{'root':str(self.worker.root),'reservations':{}})
        self.worker.stop_container=lambda record:self.calls.append(record['attempt'])
        def response(request,**kwargs):
            if request.full_url.endswith('/attempts'):return Response([first,second])
            if '/v1/jobs/' in request.full_url:return Response({'state':'cancelling','attempt':2,'lease_valid':False})
            return self.url(request,**kwargs)
        with patch('urllib.request.urlopen',side_effect=response):result=self.worker.recover()
        self.assertIn(2,self.calls)
        self.assertTrue(any(o.get('attempt')==1 and o.get('pending')=='history_attempt_reconstruction_failed' for o in result),result)
        self.assertTrue(any(o.get('attempt')==2 and o.get('exited') for o in result),result)

    def test_periodic_cli_waits_and_retries_global_failure(self):
        import io
        import os
        from cpag_worker.isolated import main
        class Fake:
            stopping=False
            calls=0
            def stop(self,*_):self.stopping=True
            def recover(self,*_):
                self.calls+=1
                if self.calls==1:return [{'scope':'global','pending':'docker_unavailable','retryable':True}]
                self.stopping=True;return [{'exited':True}]
        worker=Fake();clock=[0.0];sleeps=[]
        def sleep(seconds):sleeps.append(seconds);clock[0]+=seconds
        env={'CPAG_API_URL':'http://api','CPAG_WORKER_TOKEN':'w','CPAG_COORDINATOR_TOKEN':'c','CPAG_SHARED_ROOT':str(self.shared),'CPAG_CONTROL_ROOT':str(self.worker.control)}
        output=io.StringIO()
        with patch.dict(os.environ,env),patch('sys.argv',['isolated','--enable-isolated-executor','--recover','--recovery-interval','1']),patch('cpag_worker.isolated.DockerExecutor',return_value=worker),patch('signal.signal'),patch('time.monotonic',side_effect=lambda:clock[0]),patch('time.sleep',side_effect=sleep),patch('sys.stdout',output):
            code=main()
        self.assertEqual(code,0);self.assertEqual(worker.calls,2);self.assertGreaterEqual(sum(sleeps),1)
        lines=[json.loads(line) for line in output.getvalue().splitlines()];self.assertEqual(lines[0][0]['scope'],'global');self.assertTrue(lines[1][0]['exited'])
