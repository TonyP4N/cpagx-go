"""M1 import/normalize/export only; no alignment, inference or evaluation."""
import csv
import hashlib
import json
from pathlib import Path
import platform
import uuid

from . import __version__, SCHEMA_VERSION
from .contracts import validate, ContractError

VOLATILE = {'run_id', 'ingest_time'}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def stable_value(value):
    if isinstance(value, dict):
        return {k:stable_value(v) for k,v in value.items() if k not in VOLATILE}
    if isinstance(value,list):
        return [stable_value(v) for v in value]
    return value

def fingerprint(value):
    return hashlib.sha256(canonical(stable_value(value))).hexdigest()

def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

def resolve_evidence(ref, files):
    """Resolve only known digest references; never accept a path from evidence."""
    digest = ref['file_sha256']
    if digest not in files:
        raise ContractError('unresolved evidence file digest')
    path = Path(files[digest])
    if file_hash(path) != digest:
        raise ContractError('evidence file changed')
    if ref['frame_number'] is None and ref['record_number'] is None:
        raise ContractError('evidence requires a frame or logical record number')
    record = ref['record_number']
    if record is not None:
        if isinstance(record,bool) or not isinstance(record,int) or record < 1:
            raise ContractError('invalid logical record number')
        with path.open(newline='',encoding='utf-8-sig') as source:
            rows = csv.DictReader(source) if path.suffix.lower()=='.csv' else (json.loads(line) for line in source)
            row = next((row for index,row in enumerate(rows,1) if index==record),None)
        if row is None:
            raise ContractError('evidence logical record does not exist')
        if ref['column'] is not None and ref['column'] not in row:
            raise ContractError('evidence column does not exist')
    else:
        raise ContractError('raw frame evidence is unsupported by the M1 adapters')
    return path

def run(network, process, profile, output, *, synthetic, source='synthetic fixture', release='m1', authorization_ref='repository synthetic fixtures'):
    if synthetic is not True:
        raise ValueError('M1 accepts explicitly synthetic inputs only')
    from .parsers import parse_network, parse_process
    network, process, output = Path(network), Path(process), Path(output)
    config = json.loads(Path(profile).read_text()) if not isinstance(profile,dict) else profile
    # Fingerprints use content hashes and roles, never local paths or volatile fields.
    files = [{'name':p.name,'sha256':file_hash(p),'size_bytes':p.stat().st_size,'kind':kind}
             for kind,p in [('network',network),('process',process)]]
    input_fp = fingerprint([{k:v for k,v in f.items() if k != 'name'} for f in files])
    config_fp = hashlib.sha256(canonical(config)).hexdigest()
    parsed = [('network',parse_network(network,synthetic=True)),('process',parse_process(process,config,synthetic=True))]
    for kind, result in parsed:
        quality = result['quality']
        if quality['status'] == 'unsupported' or (not result['events'] and quality['status'] == 'partial'):
            raise ValueError(kind + ': unsupported or malformed synthetic input: ' + '; '.join(quality['reasons']))
    warnings=[kind+': '+reason for kind,result in parsed for reason in result['quality']['reasons']]
    sources = {file_hash(p):p for p in [network,process]}
    events=[]
    for kind,result in parsed:
        for original in result['events']:
            event = dict(original)
            event.update(schema_version=SCHEMA_VERSION,synthetic=True)
            event.setdefault('ingest_time',None)
            event['event_id'] = kind + '-' + fingerprint({k:v for k,v in event.items() if k != 'event_id'})
            validate('NetworkEvent' if kind=='network' else 'ProcessObservation',event)
            resolve_evidence(event['source_ref'],sources)
            events.append((kind,event))
    events.sort(key=lambda pair:(pair[1]['event_time'] or '',pair[1]['event_id']))
    normalized=[e for _,e in events]
    common={'schema_version':SCHEMA_VERSION,'synthetic':True}
    dataset={**common,'dataset_id':'dataset-'+input_fp,'source':source,'release':release,'files':files,
             'collection_range':{'start':None,'end':None},'timezone_basis':(str(config['timezone'])+': '+str(config['timezone_evidence'])) if config.get('timezone') and config.get('timezone_evidence') else None, 'authorization_ref':authorization_ref}
    nodes=[{'id':e['event_id'],'event_id':e['event_id'],'kind':kind,'evidence_refs':[e['source_ref']]} for kind,e in events]
    graph={**common,'graph_id':'','nodes':nodes,'edges':[],'claims':[],'input_fingerprint':input_fp,'core_version':__version__,
           'statistics':{'nodes':len(nodes),'edges':0},'truncation':{'truncated':False,'reason':None}}
    graph['graph_id']='graph-'+fingerprint({k:v for k,v in graph.items() if k!='graph_id'})
    validate('DatasetManifest',dataset); validate('GraphArtifact',graph)
    payloads={'dataset.json':dataset,'events.json':normalized,'graph.json':graph,'quality.json':{k:v['quality'] for k,v in parsed}}
    # Exclusive directory reservation prevents replacement of any prior attempt.
    output.mkdir(parents=True,exist_ok=False)
    artifacts=[]
    for name,payload in payloads.items():
        path=output/name
        with path.open('xb') as target:
            target.write(canonical(payload)+b'\n')
        artifacts.append({'path':name,'sha256':file_hash(path),'size_bytes':path.stat().st_size})
    manifest={**common,'run_id':str(uuid.uuid4()),'attempt_id':1,'input_fingerprint':input_fp,'config_fingerprint':config_fp,
              'tool_versions':{'core':__version__,'python':platform.python_version()},'mode':'offline','artifacts':artifacts,
              'status':'succeeded_with_warnings' if warnings else 'succeeded','warnings':warnings,
              'result_hashes':{'events':fingerprint(normalized),'graph':fingerprint(graph)},
              'limitations':['Synthetic M1 only; independent timelines; no alignment, correlation, causal claims or detection evaluation.']}
    validate('RunManifest',manifest)
    with (output/'run_manifest.json').open('xb') as target:
        target.write(canonical(manifest)+b'\n')
    return manifest
