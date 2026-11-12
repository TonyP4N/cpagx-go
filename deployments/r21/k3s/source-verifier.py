"""Single-process Unix-socket verifier. Mount business data read-only; no API credentials."""
import http.server
import json
import os
from pathlib import Path
import re
import socketserver
import subprocess
import time

SOCKET = '/verify-channel/source.sock'
COMPOSE_IDENTITY = None

def verify_compose_identity():
    if os.environ.get('CPAG_VERIFY_BACKEND') != 'compose-file-sidecar-v1':
        return None
    from verifier_identity import source_identity
    expected = Path(os.environ.get('CPAG_VERIFIER_IDENTITY_FILE', '/etc/cpag-verifier/source.identity')).read_text().strip()
    actual = source_identity(Path(__file__).resolve().parent)
    if expected != actual:
        raise ValueError('trusted Compose verifier source identity differs from bundled code')
    return actual

class Verify(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        status=500
        body=b'verification infrastructure failure'
        try:
            size=int(self.headers['Content-Length'])
            if not 0<size<=65536 or self.path!='/verify':raise ValueError()
            obj=json.loads(self.rfile.read(size))
            if COMPOSE_IDENTITY is not None and obj.get('verifier_identity') != COMPOSE_IDENTITY: raise ValueError('verifier identity mismatch')
            req=obj['request']; binding=req['binding']
            job=binding['run_id']; attempt=binding['attempt_id']
            if not re.fullmatch('[0-9a-f]{32}',job) or type(attempt)!=int or attempt<1 or req['action']!='verify':raise ValueError()
            req['output_dir']=f'/state/shared/jobs/{job}/attempt-{attempt}'
            seconds=req['seconds']
            if type(seconds)!=int or not 1<=seconds<=1800:raise ValueError()
            result=subprocess.run(['python','-m','cpag_core.shared_service','--key-stdin'],input=json.dumps(obj).encode(),capture_output=True,timeout=seconds)
            status=200 if result.returncode==0 else 422 if result.returncode==2 else 500
            body=result.stdout if status==200 else result.stderr[:65536]
            if len(body)>8<<20:raise ValueError()
        except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):pass
        self.send_response(status);self.send_header('Content-Length',str(len(body)))
        if COMPOSE_IDENTITY is not None:self.send_header('X-CPAG-Verifier-Identity', COMPOSE_IDENTITY)
        self.end_headers();self.wfile.write(body)

if __name__=='__main__':
    COMPOSE_IDENTITY = verify_compose_identity()
    Path(SOCKET).unlink(missing_ok=True)
    with socketserver.UnixStreamServer(SOCKET,Verify) as server:
        os.chmod(SOCKET,0o660)
        server.serve_forever()
