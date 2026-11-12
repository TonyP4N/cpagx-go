#!/usr/bin/env python3
"""Local-only static preview with same-origin API proxy for exported Next pages."""
import argparse
import http.client
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=13000)
parser.add_argument('--api-port', type=int, default=18080)
parser.add_argument('--directory', default='webui/out')
args = parser.parse_args()
root = Path(args.directory).resolve()
class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(root), **kw)
    def proxy(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 50*1024*1024:
                self.send_error(413); return
            body = self.rfile.read(length) if length else None
            headers = {k:v for k,v in self.headers.items() if k.lower() not in {'host','connection','transfer-encoding'}}
            conn = http.client.HTTPConnection('127.0.0.1', args.api_port, timeout=45)
            conn.request(self.command, self.path, body, headers)
            response = conn.getresponse()
            self.send_response(response.status)
            for key,value in response.getheaders():
                if key.lower() not in {'connection','transfer-encoding','server','date'}:
                    self.send_header(key,value)
            self.end_headers()
            while chunk := response.read(65536): self.wfile.write(chunk)
            conn.close()
        except (ValueError, OSError, http.client.HTTPException):
            self.send_error(502, 'Local API unavailable')
    def do_GET(self):
        if urlsplit(self.path).path.startswith('/api/'):
            self.proxy()
        else:
            super().do_GET()
    def do_POST(self):
        if urlsplit(self.path).path.startswith('/api/'):
            self.proxy()
        else: self.send_error(405)
    def list_directory(self, path):
        self.send_error(404); return None
ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()
