"""Authenticated offline evidence/download for registry-listed demo jobs only."""
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import tarfile
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
import urllib.request
from cpag_core.packet_job import verify_artifacts,query_evidence
from cpag_core.contracts import validate
from cpag_core.pipeline import fingerprint
ROOT=Path(os.environ['CPAG_DATA_ROOT']);TOKEN=os.environ['CPAG_WORKER_TOKEN']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def checked_path(relative):
    path=ROOT/'shared'/relative
    if path.is_symlink() or not path.resolve().is_relative_to((ROOT/'shared').resolve()):raise ValueError('unsafe artifact path')
    return path

def verify_publication(record):
    request=urllib.request.Request(os.environ['CPAG_API_URL']+'/v1/jobs/'+record['job'],headers={'Authorization':'Bearer '+TOKEN})
    with urllib.request.urlopen(request,timeout=5) as response:status=json.load(response)
    if status['state']!='succeeded' or status['artifact_sha256']!=record['artifact_sha256'] or str(Path(status['artifact_path']).parent)!=record['output_dir']:raise ValueError('task publication differs')
    wrapper=checked_path(status['artifact_path'])
    if sha(wrapper)!=status['artifact_sha256']:raise ValueError('published wrapper hash differs')
    output=wrapper.parent;publication=json.loads(wrapper.read_text());payload=status['payload']
    download_manifest=output/'manifest.json'
    if download_manifest.is_symlink() or sha(download_manifest)!=status['artifact_sha256']:raise ValueError('download manifest hash differs')
    if record['network']!=payload['network']['path'] or publication['config_fingerprint']!=payload['config_fingerprint']:raise ValueError('configuration identity differs')
    expected_inputs={role:payload[role]['sha256'] for role in ('network','process','profile')}
    if publication['inputs']!=expected_inputs:raise ValueError('input bindings differ')
    for role in expected_inputs:
        if sha(checked_path(payload[role]['path']))!=expected_inputs[role]:raise ValueError('original input changed')
    expected={'dataset.json','events.json','graph.json','quality.json','run_manifest.json'}
    if payload.get('kind')=='packet':expected.add('packet_observations.json')
    if {entry['path'] for entry in publication['artifacts']}!=expected or len(publication['artifacts'])!=len(expected):raise ValueError('artifact set differs')
    for entry in publication['artifacts']:
        if Path(entry['path']).name!=entry['path']:raise ValueError('unsafe artifact name')
        path=output/entry['path']
        if path.is_symlink() or sha(path)!=entry['sha256'] or path.stat().st_size!=entry['size']:raise ValueError('artifact changed')
    core=json.loads((output/'run_manifest.json').read_text());validate('RunManifest',core)
    if core['config_fingerprint']!=payload['config_fingerprint']:raise ValueError('core configuration differs')
    for entry in core['artifacts']:
        if entry['path'] not in expected-{'run_manifest.json'}:raise ValueError('unexpected core artifact')
        path=output/entry['path']
        if sha(path)!=entry['sha256'] or path.stat().st_size!=entry['size_bytes']:raise ValueError('core artifact changed')
    events=json.loads((output/'events.json').read_text());graph=json.loads((output/'graph.json').read_text())
    validate('GraphArtifact',graph);validate('DatasetManifest',json.loads((output/'dataset.json').read_text()))
    if core['result_hashes']!={'events':fingerprint(events),'graph':fingerprint(graph)}:raise ValueError('core result hashes differ')
    for event in events:validate('NetworkEvent' if 'protocol' in event else 'ProcessObservation',event)
    if payload.get('kind')=='packet':verify_artifacts(output,checked_path(record['network']))
    return output,checked_path(record['network']),publication
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+TOKEN):self.send_error(401);return
        route=urlsplit(self.path);args=parse_qs(route.query)
        try:
            registry=json.loads((ROOT/'demo-results.json').read_text());record=registry[args.get('kind',['packet'])[0]]
            output,network,publication=verify_publication(record)
            if route.path=='/graph':value=verify_artifacts(output,network)['graph'];body=json.dumps(value).encode();content='application/json'
            elif route.path=='/evidence':body=json.dumps(query_evidence(output,network,args['event'][0],args.get('field',[None])[0])).encode();content='application/json'
            elif route.path=='/download':
                buffer=io.BytesIO()
                with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
                    for name in sorted([entry['path'] for entry in publication['artifacts']]+['manifest.json']):archive.add(output/name,arcname=name)
                body=buffer.getvalue();content='application/gzip'
            else:self.send_error(404);return
            self.send_response(200);self.send_header('Content-Type',content);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        except (OSError,ValueError,KeyError) as error:
            body=json.dumps({'error':type(error).__name__}).encode();self.send_response(409);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*_):pass
ThreadingHTTPServer(('0.0.0.0',8095),Handler).serve_forever()
