"""Scoped outbox relay: broker confirmation precedes durable outbox confirmation."""
import argparse
import json
import os
import signal
import threading

from .celery_v3 import QUEUE, TASK, make_app, read_config
from .resident_dispatch import dispatch_request
from .worker import API, APIError


class Publisher:
    def __init__(self, config, app=None, api=None):
        self.config = config
        self.app = app if app is not None else make_app(config, publisher=True)
        self.api = api if api is not None else API(config['api_url'], config['dispatcher_token'], timeout=10)

    def publish(self, row):
        def unroutable(*_):
            raise RuntimeError('v3 mandatory publish returned unroutable')
        with self.app.connection_for_write() as connection:
            channel = connection.channel()
            try:
                producer = self.app.amqp.Producer(channel, on_return=unroutable, auto_declare=False)
                self.app.send_task(TASK, args=[row['job_id'], row['dispatch_id']],
                    task_id=row['dispatch_id'], producer=producer, queue=QUEUE,
                    exchange=QUEUE, routing_key=QUEUE, serializer='json',
                    delivery_mode=2, mandatory=True, retry=False, confirm_timeout=10)
            finally:
                channel.close()

    def once(self):
        rows = self.api.post('/v1/dispatch/lease', {'publisher': self.config['publisher_id'], 'lease_seconds': 30, 'limit': 1})
        for row in rows or []:
            dispatch_request({k: row[k] for k in ('job_id', 'dispatch_id')})
            if row['partition'] != 'rabbit-v3': raise ValueError('foreign outbox partition')
            # py-amqp's confirm_publish blocks for broker ack/nack; mandatory
            # routing prevents treating an unroutable publish as dispatch success.
            self.publish(row)
            try:
                self.api.post('/v1/dispatch/confirm', {'dispatch_id': row['dispatch_id'],
                    'publisher': self.config['publisher_id'], 'lease_token': row['lease_token']})
            except APIError as error:
                if error.status != 409: raise
                # An obsolete generation is harmless; the consumer exact claim
                # rejects its already-confirmed broker delivery as stale.
        return len(rows or [])


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--config', required=True)
    args = parser.parse_args()
    if os.geteuid() != 65531: parser.error('publisher requires dedicated UID65531')
    config = read_config(args.config, publisher=True); publisher = Publisher(config)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set()); signal.signal(signal.SIGINT, lambda *_: stopped.set())
    while not stopped.is_set():
        try: publisher.once()
        except Exception as error:
            print(json.dumps({'event': 'dispatch_relay_retry', 'error_type': type(error).__name__}), flush=True)
        stopped.wait(config.get('poll_seconds', .5))


if __name__ == '__main__': main()
