"""M1 import/normalize/export only; no alignment, inference or evaluation."""
import hashlib
import json
from pathlib import Path
import platform
import uuid

from . import __version__, SCHEMA_VERSION
from .contracts import validate, ContractError
from .evidence import EvidenceIndex

VOLATILE = {'run_id', 'ingest_time'}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def stable_value(value):
    if isinstance(value, dict):
        return {k:stable_value(v) for k,v in value.items() if k not in VOLATILE}
    if isinstance(value,list):
        return [stable_value(v) for v in value]
    return value

def json_chunks(value, *, stable=False):
    """Canonical UTF-8 without materializing the complete serialization.

    Cache only small flat objects during this call; repeated evidence references
    share bytes, not semantic identity. The cache is bounded and never persisted.
    Tuple contents intentionally retain the legacy stable_value tuple semantics.
    """
    cache = {}
    cache_bytes = 0
    def walk(item, strip):
        nonlocal cache_bytes
        if isinstance(item, dict):
            if any(not isinstance(k, str) for k in item):
                yield canonical(stable_value(item) if strip else item)
                return
            flat = all(not isinstance(v, (dict, list, tuple)) for v in item.values())
            if flat:
                key = (id(item), strip)
                entry = cache.get(key)
                if entry is not None and entry[0] is item:
                    yield entry[1]
                    return
                data = canonical({k:v for k,v in item.items() if not strip or k not in VOLATILE})
                if len(data) <= 2048 and cache_bytes + len(data) <= 1048576:
                    cache[key] = (item, data); cache_bytes += len(data)
                yield data
                return
            yield b'{'
            first = True
            for key in sorted(item):
                if strip and key in VOLATILE: continue
                if not first: yield b','
                first = False
                yield canonical(key); yield b':'
                yield from walk(item[key], strip)
            yield b'}'
        elif isinstance(item, (list, tuple)):
            yield b'['
            for index, child in enumerate(item):
                if index: yield b','
                yield from walk(child, strip and not isinstance(item, tuple))
            yield b']'
        else:
            yield canonical(item)
    yield from walk(value, stable)


def write_canonical(path, value, *, max_bytes=None):
    """Byte-identical canonical JSON plus newline with bounded encoder memory."""
    with Path(path).open('wb') as stream:
        count=1
        for chunk in json_chunks(value):
            count+=len(chunk)
            if max_bytes is not None and count>max_bytes:raise ValueError('artifact_output_limit')
            stream.write(chunk)
        stream.write(b'\n')


def canonical_file_matches(path, value):
    """Fast path for generated canonical files, preserving noncanonical readers."""
    digest = hashlib.sha256()
    for chunk in json_chunks(value): digest.update(chunk)
    digest.update(b'\n')
    return file_hash(path) == digest.hexdigest()


def fingerprint(value):
    digest = hashlib.sha256()
    for chunk in json_chunks(value, stable=True): digest.update(chunk)
    return digest.hexdigest()

def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

def resolve_evidence(ref, files):
    """Resolve a reference against a reusable index (or a verified one-shot path)."""
    digest = ref['file_sha256']
    if digest not in files:
        raise ContractError('unresolved evidence file digest')
    source = files[digest]
    index = source if isinstance(source, EvidenceIndex) else EvidenceIndex(source, digest)
    index.resolve(ref)
    return index.path


def run(network, process, profile, output, *, synthetic, source='synthetic fixture', release='m1', authorization_ref='repository synthetic fixtures'):
    if synthetic is not True:
        raise ValueError('M1 accepts explicitly synthetic inputs only')
    from .parsers import parse_network, parse_process
    network, process, output = Path(network), Path(process), Path(output)
    config = json.loads(Path(profile).read_text()) if not isinstance(profile,dict) else profile
    # Fingerprints use content hashes and roles, never local paths or volatile fields.
    indexes = {kind: EvidenceIndex(p) for kind,p in [('network',network),('process',process)]}
    files = [{'name':index.path.name,'sha256':index.digest,'size_bytes':index.size_bytes,'kind':kind}
             for kind,index in indexes.items()]
    input_fp = fingerprint([{k:v for k,v in f.items() if k != 'name'} for f in files])
    config_fp = hashlib.sha256(canonical(config)).hexdigest()
    parsed = [('network',parse_network(network,synthetic=True, evidence=indexes['network'])),('process',parse_process(process,config,synthetic=True,evidence=indexes['process']))]
    for kind, result in parsed:
        quality = result['quality']
        if quality['status'] == 'unsupported' or not result['events']:
            raise ValueError(kind + ': unsupported or malformed synthetic input: ' + '; '.join(quality['reasons'] or ['no_events']))
    warnings=[kind+': '+reason for kind,result in parsed for reason in result['quality']['reasons']]
    sources = {index.digest:index for index in indexes.values()}
    events=[]
    for kind,result in parsed:
        for original in result['events']:
            event = dict(original)
            event.update(schema_version=SCHEMA_VERSION,synthetic=True)
            event.setdefault('ingest_time',None)
            event['event_id'] = kind + '-' + fingerprint({k:v for k,v in event.items() if k != 'event_id'})
            validate('NetworkEvent' if kind=='network' else 'ProcessObservation',event)
            resolve_evidence(event['source_ref'],sources)
            if kind == 'process':
                raw = indexes[kind].resolve(event['source_ref'])
                if raw.get(config['timestamp_column']) != event['source_ref']['raw_time']:
                    raise ContractError('evidence raw time differs')
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
    for index in indexes.values():
        index.verify()
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
    for index in indexes.values():
        index.verify()
    with (output/'run_manifest.json').open('xb') as target:
        target.write(canonical(manifest)+b'\n')
    return manifest
