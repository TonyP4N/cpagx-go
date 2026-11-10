"""v3 queue boundaries and confirmed outbox handoff; no external broker needed."""
import contextlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'services/worker'))
from cpag_worker.resident_dispatch import DispatchServer, dispatch_request, read_line
from cpag_worker.celery_publisher import Publisher
from cpag_worker.worker import APIError
import test_resident

J='a'*32; D='b'*32
ROW={'job_id':J,'dispatch_id':D,'partition':'rabbit-v3','lease_token':'c'*64}

class DispatchTests(unittest.TestCase):
    def setUp(self):
        peer=patch.object(socket,'SO_PEERCRED',getattr(socket,'SO_PEERCRED',17),create=True)
        peer.start();self.addCleanup(peer.stop)

    def test_exact_body_has_no_attempt_authority(self):
        self.assertEqual(dispatch_request({'job_id':J,'dispatch_id':D}),{'job_id':J,'dispatch_id':D,'partition':'rabbit-v3'})
        for value in ({'job_id':J},{'job_id':J,'dispatch_id':D,'token':'authority'}, {'job_id':'../escape','dispatch_id':D}):
            with self.assertRaises(ValueError):dispatch_request(value)

    def test_frame_is_bounded(self):
        left,right=socket.socketpair()
        with left,right:
            left.sendall(b'x'*1025)
            with self.assertRaises(ValueError):read_line(right)

    def owner(self):
        owner=SimpleNamespace(once=Mock(return_value='idle'),helper=SimpleNamespace(stop=Mock()),journal=SimpleNamespace(exists=lambda:False))
        return owner

    def client(self, uid=65531):
        client=Mock();client.getsockopt.return_value=struct.pack('3i',100,uid,uid)
        client.recv.return_value=json.dumps({'job_id':J,'dispatch_id':D}).encode()+b'\n'
        return client

    def test_foreign_compute_uid_cannot_claim(self):
        owner=self.owner();server=DispatchServer('/unused',owner,threading.Lock(),threading.Event())
        with self.assertRaises(PermissionError):server.handle(self.client(65532))
        owner.once.assert_not_called()

    def test_busy_poll_and_duplicate_dispatch(self):
        owner=self.owner();lock=threading.Lock();server=DispatchServer('/unused',owner,lock,threading.Event())
        lock.acquire()
        self.assertEqual(server.handle(self.client()),'retry');owner.once.assert_not_called();self.assertTrue(server.queue_pending())
        lock.release()
        self.assertEqual(server.handle(self.client()),'stale');self.assertFalse(server.queue_pending())
        owner.once.assert_called_once_with(dispatch={'job_id':J,'dispatch_id':D,'partition':'rabbit-v3'})

    def test_active_failure_forces_trusted_container_recovery(self):
        owner=self.owner();owner.once.side_effect=OSError();owner.journal.exists=lambda:True
        fatal=threading.Event();server=DispatchServer('/unused',owner,threading.Lock(),fatal)
        self.assertEqual(server.handle(self.client()),'retry');self.assertTrue(fatal.is_set());owner.helper.stop.assert_called_once()


class ExactClaimTests(unittest.TestCase):
    setUp = test_resident.ResidentTests.setUp

    def test_exact_queue_claim_and_poll_are_distinct(self):
        calls=[]
        self.worker.api.post=lambda path,body:calls.append((path,body)) or None
        self.assertEqual(self.worker.once(dispatch={'job_id':J,'dispatch_id':D,'partition':'rabbit-v3'}),'idle')
        self.assertEqual(calls[0][1]['job_id'],J);self.assertEqual(calls[0][1]['dispatch_id'],D)
        self.assertEqual(calls[0][1]['partition'],'rabbit-v3')
        self.worker.once();self.assertNotIn('job_id',calls[1][1]);self.assertNotIn('partition',calls[1][1])

    def test_idle_queue_reconciliation_does_not_claim(self):
        from cpag_worker.isolated import atomic_json
        from test_kubernetes import claim
        atomic_json(self.worker.journal,{'claim':claim(),'execution':{'container_id':'old'}})
        self.worker.helper.get_json=lambda *a:{'attempt':1,'state':'cancelling'}
        self.worker.api.post=Mock(side_effect=AssertionError('idle recovery cannot claim'))
        self.assertEqual(self.worker.reconcile(),'recovery_wait');self.worker.api.post.assert_not_called()


class PublisherTests(unittest.TestCase):
    def publisher(self):
        api=Mock();api.post.side_effect=[[ROW],{}]
        app=Mock();channel=Mock();connection=Mock();connection.channel.return_value=channel
        app.connection_for_write.return_value=contextlib.nullcontext(connection)
        p=Publisher({'api_url':'http://unused','dispatcher_token':'d'*32,'publisher_id':'relay'},app=app,api=api)
        return p,app,api

    def test_confirms_only_after_blocking_broker_publish_returns(self):
        p,app,api=self.publisher();order=[]
        app.send_task.side_effect=lambda *a,**kw:order.append('broker_confirmed')
        def post(path,body):
            if path.endswith('/lease'):return [ROW]
            order.append('outbox_confirmed');return {}
        api.post.side_effect=post
        self.assertEqual(p.once(),1);self.assertEqual(order,['broker_confirmed','outbox_confirmed'])
        kwargs=app.send_task.call_args.kwargs
        self.assertTrue(kwargs['mandatory']);self.assertFalse(kwargs['retry']);self.assertEqual(kwargs['exchange'],'cpag.v3.tasks')
        self.assertEqual(kwargs['task_id'],D);self.assertEqual(kwargs['delivery_mode'],2)

    def test_broker_error_never_confirms_outbox(self):
        p,app,api=self.publisher();app.send_task.side_effect=OSError('broker unavailable')
        with self.assertRaises(OSError):p.once()
        self.assertEqual(api.post.call_count,1)

    def test_basic_return_never_confirms_even_with_broker_ack(self):
        p,app,api=self.publisher()
        def producer(channel,on_return,auto_declare):
            self.assertFalse(auto_declare)
            app.send_task.side_effect=lambda *a,**kw:on_return(None,None,None,None)
            return Mock()
        app.amqp.Producer.side_effect=producer
        with self.assertRaises(RuntimeError):p.once()
        self.assertEqual(api.post.call_count,1)

    def test_obsolete_confirm_is_safe_and_ambiguous_confirm_retries_later(self):
        p,app,api=self.publisher();api.post.side_effect=[[ROW],APIError(409,{})]
        self.assertEqual(p.once(),1)
        p,app,api=self.publisher();api.post.side_effect=[[ROW],OSError('ambiguous API response')]
        with self.assertRaises(OSError):p.once()


try:
    import celery
except ImportError:
    celery=None

@unittest.skipIf(celery is None,'run with pinned resident Celery requirements')
class ConsumerTests(unittest.TestCase):
    def task(self):
        from cpag_worker.celery_v3 import make_app,install_task
        cfg={'broker_url':'amqp://u:p@localhost/cpag-canary','queue':'cpag.v3.tasks','supervisor_socket':'/dispatch/supervisor.sock','worker_name':'test'}
        app=make_app(cfg);task=install_task(app,cfg)
        return app,task

    def test_private_config_and_dedicated_broker(self):
        from cpag_worker.celery_v3 import read_config
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.json'
            config={'broker_url':'amqp://u:p@localhost/cpag-canary','queue':'cpag.v3.tasks','supervisor_socket':'/dispatch/supervisor.sock','worker_name':'test'}
            path.write_text(json.dumps(config));path.chmod(0o600)
            self.assertEqual(read_config(path)['queue'],'cpag.v3.tasks')
            path.chmod(0o644)
            with self.assertRaises(ValueError):read_config(path)
            path.chmod(0o600);config['broker_url']='amqp://guest:guest@localhost/'
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):read_config(path)

    def test_runtime_configuration_and_registry(self):
        app,task=self.task()
        self.assertEqual(set(app.tasks),{'cpag.v3.execute'})
        self.assertTrue(app.conf.task_acks_late);self.assertTrue(app.conf.task_reject_on_worker_lost)
        self.assertTrue(app.conf.broker_transport_options['confirm_publish'])
        self.assertFalse(app.conf.worker_enable_remote_control)
        self.assertTrue(app.conf.task_queues[0].no_declare)

    def test_more_than_twenty_busy_replies_retain_original_without_publish(self):
        app,task=self.task()
        with patch('cpag_worker.celery_v3.request',side_effect=['retry']*25+['done']) as ipc,patch('cpag_worker.celery_v3.time.sleep') as sleep,patch.object(app,'send_task',side_effect=AssertionError('consumer cannot publish')):
            self.assertEqual(task.run(J,D),'done')
        self.assertEqual(ipc.call_count,26);self.assertEqual(sleep.call_count,25)
        self.assertEqual(sleep.call_args.args,(5,))

    def test_canvas_metadata_and_bad_identity_rejected(self):
        from celery.exceptions import Reject
        app,task=self.task()
        task.push_request(callbacks=[{'task':'celery.chain'}])
        with patch('cpag_worker.celery_v3.request',side_effect=AssertionError('canvas cannot execute')):
            with self.assertRaises(Reject) as caught:task.run(J,D)
        self.assertFalse(caught.exception.requeue);task.pop_request()
        with self.assertRaises(Reject) as caught:task.run('../bad',D)
        self.assertFalse(caught.exception.requeue)

    def test_stale_and_settled_ack_safe(self):
        app,task=self.task()
        for status in ('stale','done'):
            with patch('cpag_worker.celery_v3.request',return_value=status):self.assertEqual(task.run(J,D),status)


if __name__=='__main__':unittest.main()
