"""Check the relay's publisher authorization without a cluster or Secrets."""
import io
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import MagicMock, patch

RELAY = Path(__file__).resolve().parents[2] / 'deployments/resident/private_relay.py'
DISPATCHER = 'd' * 32
WORKER = 'w' * 32
COORDINATOR = 'c' * 32


class DispatchRelayTest(unittest.TestCase):
    def load_handler(self, token=DISPATCHER):
        config = io.StringIO(json.dumps({'worker_token': WORKER, 'coordinator_token': COORDINATOR}))
        with patch('builtins.open', return_value=config), patch.object(Path, 'read_text', return_value=token), patch('http.server.ThreadingHTTPServer'):
            return runpy.run_path(str(RELAY))['Relay']

    def check_route(self, handler, token, path, method='POST'):
        request = MagicMock()
        request.headers = {'Authorization': 'Bearer ' + token}
        request.command, request.path = method, path
        with patch('http.client.HTTPConnection') as upstream:
            handler.relay(request)
            return upstream.called

    def test_publisher_only_leases_and_confirms(self):
        handler = self.load_handler()
        for route in ('lease', 'confirm'):
            path = '/v1/dispatch/' + route
            self.assertTrue(self.check_route(handler, DISPATCHER, path))
            self.assertFalse(self.check_route(handler, DISPATCHER, path, 'GET'))
            self.assertFalse(self.check_route(handler, WORKER, path))
            self.assertFalse(self.check_route(handler, COORDINATOR, path))
        for path in ('/v1/claim', '/v1/dispatch/rollback', '/v1/jobs/a/complete'):
            self.assertFalse(self.check_route(handler, DISPATCHER, path))
        self.assertTrue(self.check_route(handler, WORKER, '/v1/claim'))

    def test_rejects_duplicate_token(self):
        with self.assertRaises(ValueError):
            self.load_handler(COORDINATOR)
