"""Short synthetic lease windows expose slow publication and recovery races."""
import fcntl
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/worker'),str(ROOT/'services/analysis/src')]
from cpag_worker.isolated import DockerExecutor,atomic_json
from cpag_worker.worker import APIError


class PublicationLeaseTests(unittest.TestCase):
    def worker(self,path):
        worker=DockerExecutor(None,None,path/'shared',path/'control','host',heartbeat=.02,lease=1)
        worker.root.mkdir();worker.control.mkdir();return worker
    def test_recovery_publication_renews_while_rpc_exceeds_short_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            worker=self.worker(Path(directory));record={'id':'job','worker':'host','attempt':1,'token':'private-token'}
            lease={'until':time.monotonic()+.12,'renewals':0};lock=threading.Lock()
            def heartbeat(path,body):
                with lock:
                    if time.monotonic()>lease['until']:raise APIError(409,{'state':'running'})
                    lease['until']=time.monotonic()+.12;lease['renewals']+=1
                return {'state':'running'}
            def complete(path,body):
                time.sleep(.32) # More than two complete lease windows, no inline heartbeat possible.
                with lock:
                    if time.monotonic()>lease['until']:raise APIError(409,{'state':'running'})
                return {'state':'succeeded'}
            worker.api=SimpleNamespace(post=heartbeat);worker.publication_api=SimpleNamespace(post=complete)
            self.assertEqual(worker.complete(record,'a'*64)['state'],'succeeded')
            self.assertGreaterEqual(lease['renewals'],5)
            trace=json.loads((worker.control/'jobs/job/attempt-1.worker/lease-observation.json').read_text())
            self.assertEqual(trace['last_event']['outcome'],'renewed')
            self.assertNotIn(record['token'],json.dumps(trace))
            publication=json.loads((worker.control/'jobs/job/attempt-1.worker/publication-observation.json').read_text())
            self.assertEqual(publication['last_event']['outcome'],'completed')
            self.assertGreaterEqual(publication['last_event']['wall_seconds'],.32)
            self.assertNotIn(record['token'],json.dumps(publication))
    def test_recovery_never_resumes_publication_while_live_owner_holds_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            worker=self.worker(Path(directory));record={'id':'job','worker':'host','attempt':1,'token':'private-token','location':'docker:test:scope','container_id':'a'*64}
            base=worker.control/'jobs/job/attempt-1.worker';atomic_json(base/'execution.json',record)
            atomic_json(base/'handoff.json',{'output_dir':'jobs/job/attempt-1','manifest_sha256':'a'*64});atomic_json(base/'exit.json',{'removed':True})
            output=worker.root/'jobs/job/attempt-1';output.mkdir(parents=True);(output/'manifest.json').write_text('{}')
            worker.location=lambda:'docker:test:scope';worker.docker=lambda *a,**k:''
            worker.get_json=lambda api,path:[] if '/executions?' in path or path.endswith('/attempts') else {'state':'running','attempt':1,'lease_valid':True}
            with (base/'owner.lock').open('a+') as owner,patch.object(worker,'resume_publication') as resume:
                fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
                results=worker.recover()
                resume.assert_not_called();self.assertTrue(any(row.get('skipped')=='active_owner' for row in results),results)
    def test_failed_renewal_is_recorded_without_extending_lease_or_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            worker=self.worker(Path(directory));record={'id':'job','worker':'host','attempt':1,'token':'private-token'}
            worker.api=SimpleNamespace(post=lambda *a:(_ for _ in ()).throw(APIError(409,{'state':'running'})))
            done=threading.Event();health={'owned':True,'cancelled':False,'phase':'publication'}
            worker.keep_lease(record,done,health)
            self.assertFalse(health['owned'])
            trace=json.loads((worker.control/'jobs/job/attempt-1.worker/lease-observation.json').read_text())
            self.assertEqual(trace['last_event']['status'],409);self.assertEqual(trace['last_event']['outcome'],'api_error')


if __name__=='__main__':unittest.main()
