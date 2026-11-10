"""Private authenticated relay; API internal listener remains loopback-only."""
import hmac
import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

config=json.load(open('/etc/cpag/worker.json'))
tokens=[config['worker_token'],config['coordinator_token']]
if any(not isinstance(t,str) or len(t)<24 for t in tokens) or tokens[0]==tokens[1]:
    raise ValueError('distinct private credentials required')

try:
    dispatcher_token = Path('/etc/cpag-dispatch/token').read_text().strip()
except FileNotFoundError:
    dispatcher_token = None
if dispatcher_token is not None and (len(dispatcher_token) < 24 or dispatcher_token in tokens):
    raise ValueError('distinct dispatcher credential required')

class Relay(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def relay(self):
        auth=self.headers.get('Authorization','')
        allowed = tokens
        if self.command == 'POST' and self.path in ('/v1/dispatch/lease', '/v1/dispatch/confirm'):
            allowed = [dispatcher_token] if dispatcher_token else []
        if not any(hmac.compare_digest(auth,'Bearer '+t) for t in allowed):
            self.send_error(401);return
        if not self.path.startswith('/v1/'):
            self.send_error(404);return
        try: size=int(self.headers.get('Content-Length','0'))
        except ValueError: self.send_error(400);return
        if size<0 or size>16*1024*1024 or self.headers.get('Transfer-Encoding'):
            self.send_error(413);return
        conn=http.client.HTTPConnection('127.0.0.1',8094,timeout=610)
        try:
            headers={k:v for k,v in self.headers.items() if k.lower() in ('authorization','content-type')}
            conn.request(self.command,self.path,self.rfile.read(size),headers)
            response=conn.getresponse();body=response.read()
            self.send_response(response.status)
            self.send_header('Content-Type',response.getheader('Content-Type','application/json'))
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        except (OSError,http.client.HTTPException): self.send_error(502)
        finally: conn.close()
    do_GET=relay
    do_POST=relay

ThreadingHTTPServer(('0.0.0.0',8096),Relay).serve_forever()
