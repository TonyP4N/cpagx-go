"""Nonroot, JSON-only Rabbit v3 consumer; supervisor owns all compute authority."""
import argparse
import json
import os
from pathlib import Path
import stat
import time
from urllib.parse import urlsplit

from .resident_dispatch import dispatch_request, request

TASK = 'cpag.v3.execute'
QUEUE = 'cpag.v3.tasks'


def read_config(path, publisher=False):
    path = Path(path).resolve(); info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o027 or (info.st_mode & 0o040 and info.st_gid != os.getegid()):
        raise ValueError('private Celery configuration required')
    value = json.loads(path.read_text())
    required = {'broker_url', 'queue'} | ({'api_url', 'dispatcher_token', 'publisher_id'} if publisher else {'supervisor_socket', 'worker_name'})
    if not isinstance(value, dict) or not required <= value.keys() or value.keys()-required-({'poll_seconds'} if publisher else set()):
        raise ValueError('invalid Celery configuration fields')
    url = urlsplit(value['broker_url'])
    if url.scheme not in ('amqp', 'amqps') or not url.hostname or not url.username or not url.password or url.path in ('', '/', '//') or url.query or url.fragment:
        raise ValueError('dedicated authenticated AMQP virtual host required')
    if value['queue'] != QUEUE:
        raise ValueError('dedicated v3 queue required')
    if publisher:
        if value['api_url'].rstrip('/') not in ('http://cpag-resident-internal:8096', 'http://127.0.0.1:8094'):
            raise ValueError('private dispatch API required')
        if not isinstance(value['dispatcher_token'], str) or len(value['dispatcher_token']) < 24:
            raise ValueError('scoped dispatcher authority required')
        if type(value.get('poll_seconds', .5)) not in (int, float) or not .2 <= value.get('poll_seconds', .5) <= 60:
            raise ValueError('publisher interval invalid')
    elif not Path(value['supervisor_socket']).is_absolute():
        raise ValueError('absolute supervisor socket required')
    return value


def make_app(config, publisher=False):
    from celery import Celery
    from kombu import Exchange, Queue
    app = Celery('cpag_v3', broker=config['broker_url'])
    app.conf.update(task_serializer='json', accept_content=['json'], result_serializer='json',
        task_ignore_result=True, task_acks_late=True, task_acks_on_failure_or_timeout=False,
        task_reject_on_worker_lost=True, worker_prefetch_multiplier=1, worker_concurrency=1,
        broker_connection_retry_on_startup=True, broker_connection_retry=True,
        broker_connection_max_retries=None, broker_heartbeat=10,
        worker_cancel_long_running_tasks_on_connection_loss=True,
        broker_transport_options={'confirm_publish': True, 'confirm_timeout': 10},
        task_publish_retry=True, task_default_delivery_mode='persistent',
        worker_enable_remote_control=False, task_send_sent_event=False,
        worker_send_task_events=False, task_create_missing_queues=False,
        task_default_queue=QUEUE, task_default_exchange=QUEUE, task_default_routing_key=QUEUE,
        task_queues=(Queue(QUEUE, Exchange(QUEUE, type='direct', durable=True), routing_key=QUEUE,
                          durable=True, no_declare=True, queue_arguments={'x-queue-type': 'quorum'}),))
    return app


def install_task(app, config):
    from celery.exceptions import Reject
    @app.task(name=TASK, bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=None, ignore_result=True)
    def execute(self, job_id, dispatch_id):
        if any(getattr(self.request, key, None) is not None for key in ('callbacks', 'errbacks', 'chain', 'chord', 'group')):
            raise Reject('v3 canvas metadata forbidden', requeue=False)
        try:
            dispatch_request({'job_id': job_id, 'dispatch_id': dispatch_id})
        except ValueError:
            raise Reject('invalid v3 dispatch identity', requeue=False)
        delay = .25
        while True:
            try:
                status = request(config['supervisor_socket'], {'job_id': job_id, 'dispatch_id': dispatch_id})
            except (OSError, ValueError):
                status = 'retry'
            if status in ('done', 'stale'):
                return status
            # Retain the original delivery unacked. The prefork parent keeps
            # AMQP heartbeats alive; connection loss terminates this pool child
            # and Rabbit redelivers. Busy never consumes quorum delivery-limit.
            time.sleep(delay)
            delay = min(5, delay * 2)

    app.finalize()
    for name in list(app.tasks):
        if name != TASK: del app.tasks[name]
    return execute


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--config', required=True)
    args = parser.parse_args()
    if os.geteuid() != 65531: parser.error('Celery consumer requires dedicated UID65531')
    config = read_config(args.config)
    app = make_app(config); install_task(app, config)
    app.worker_main(['worker', '--loglevel=WARNING', '--concurrency=1', '--prefetch-multiplier=1',
                     '--queues='+QUEUE, '--hostname='+config['worker_name'], '--without-gossip', '--without-mingle',
                     '--without-heartbeat', '--pidfile='])


if __name__ == '__main__': main()
