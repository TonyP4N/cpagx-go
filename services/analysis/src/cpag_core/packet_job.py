"""Explicit synthetic packet job artifact contract; default M1 entry is unchanged."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import uuid
from . import __version__
from .contracts import validate
from .packet_pipeline import analyze_capture, PacketEvidence
from .pipeline import canonical, fingerprint, file_hash

ARTIFACTS = {'dataset.json','events.json','graph.json','quality.json','run_manifest.json','packet_observations.json'}


def run(network, process, profile, output, *, synthetic=False):
    if synthetic is not True:
        raise ValueError('synthetic_opt_in_required')
    network,process,profile,output=map(Path,(network,process,profile,output))
    config=json.loads(profile.read_text())
    if config.get('synthetic') is not True or config.get('adapter')!='synthetic-packet-1':
        raise ValueError('packet profile must explicitly select synthetic-packet-1')
    files=[{'name':p.name,'sha256':file_hash(p),'size_bytes':p.stat().st_size,'kind':kind}
           for kind,p in [('network',network),('process',process)]]
    profile_hash=file_hash(profile)
    input_fp=fingerprint([{k:v for k,v in f.items() if k!='name'} for f in files])
    config_fp=hashlib.sha256(canonical(config)).hexdigest()
    result=json.loads(canonical(analyze_capture(network,synthetic=True)))
    result['schema_version']='1.0.0'
    if not result['events']:
        raise ValueError('packet capture has no supported synthetic events')
    graph=result['graph'];graph['input_fingerprint']=input_fp
    graph['graph_id']='packet-job-graph-'+fingerprint({k:v for k,v in graph.items() if k!='graph_id'})
    common={'schema_version':'1.0.0','synthetic':True}
    dataset={**common,'dataset_id':'packet-dataset-'+input_fp,'source':'synthetic capture fixture',
             'release':'experimental-packet-1','files':files,'collection_range':{'start':None,'end':None},
             'timezone_basis':None,'authorization_ref':'explicit synthetic job opt-in'}
    validate('DatasetManifest',dataset);validate('GraphArtifact',graph)
    validate('PacketObservationArtifact',result)
    payloads={'dataset.json':dataset,'events.json':result['events'],'graph.json':graph,
              'quality.json':result['quality'],'packet_observations.json':result}
    # All source bytes must remain unchanged before reserving output.
    if [file_hash(network),file_hash(process)]!=[f['sha256'] for f in files] or file_hash(profile)!=profile_hash:
        raise ValueError('packet inputs changed')
    output.mkdir(parents=True,exist_ok=False)
    artifacts=[]
    for name,payload in payloads.items():
        path=output/name;path.write_bytes(canonical(payload)+b'\n')
        artifacts.append({'path':name,'sha256':file_hash(path),'size_bytes':path.stat().st_size})
    manifest={**common,'run_id':str(uuid.uuid4()),'attempt_id':1,'input_fingerprint':input_fp,
              'config_fingerprint':config_fp,'tool_versions':{'core':__version__,'python':platform.python_version()},
              'mode':'offline','artifacts':artifacts,'status':'succeeded_with_warnings',
              'warnings':['synthetic_only','bounded_protocol_subset','process_input_compatibility_placeholder_unused'],
              'result_hashes':{'events':fingerprint(result['events']),'graph':fingerprint(graph)},
              'limitations':['No industrial validation, causal/attack inference, physical success or clock alignment.']}
    validate('RunManifest',manifest)
    if [file_hash(network),file_hash(process)]!=[f['sha256'] for f in files] or file_hash(profile)!=profile_hash:
        raise ValueError('packet inputs changed before publication')
    (output/'run_manifest.json').write_bytes(canonical(manifest)+b'\n')
    return manifest


def verify_artifacts(output, network):
    """Audit packet-specific truth from original bytes, beyond rehashed manifests."""
    output=Path(output)
    manifest=json.loads((output/'run_manifest.json').read_text())
    validate('RunManifest',manifest)
    if {a['path'] for a in manifest['artifacts']}!=ARTIFACTS-{'run_manifest.json'} or len(manifest['artifacts'])!=5:
        raise ValueError('packet artifact membership mismatch')
    for entry in manifest['artifacts']:
        path=output/entry['path']
        if path.is_symlink() or file_hash(path)!=entry['sha256'] or path.stat().st_size!=entry['size_bytes']:
            raise ValueError('packet artifact hash/size mismatch')
    dataset=json.loads((output/'dataset.json').read_text())
    validate('DatasetManifest',dataset)
    input_fp=fingerprint([{k:v for k,v in f.items() if k!='name'} for f in dataset['files']])
    network_files=[f for f in dataset['files'] if f['kind']=='network']
    if len(network_files)!=1 or network_files[0]['sha256']!=file_hash(network) or network_files[0]['size_bytes']!=Path(network).stat().st_size:
        raise ValueError('packet dataset capture mismatch')
    if manifest['input_fingerprint']!=input_fp:raise ValueError('packet input fingerprint mismatch')
    sidecar=json.loads((output/'packet_observations.json').read_text())
    validate('PacketObservationArtifact',sidecar)
    events=json.loads((output/'events.json').read_text())
    graph=json.loads((output/'graph.json').read_text())
    if graph['input_fingerprint']!=input_fp or manifest['result_hashes']!={'events':fingerprint(events),'graph':fingerprint(graph)}:
        raise ValueError('packet result fingerprint mismatch')
    if sidecar['events']!=events or sidecar['graph']!=graph:
        raise ValueError('packet sidecar/events/graph mismatch')
    actual=analyze_capture(network,synthetic=True)
    actual['schema_version']='1.0.0'
    actual['graph']['input_fingerprint']=graph['input_fingerprint']
    actual['graph']['graph_id']='packet-job-graph-'+fingerprint({k:v for k,v in actual['graph'].items() if k!='graph_id'})
    if canonical(sidecar)!=canonical(actual):
        raise ValueError('packet observations differ from original capture decoding')
    index=PacketEvidence(network,synthetic=True)
    for obs in sidecar['observations']:
        for ref in obs['source_refs']:index.resolve(ref)
        for field in obs['field_slices']:index.resolve(field['source_ref'],field)
        for field in obs['fields'].values():
            for piece in field['slices']:index.resolve(piece['source_ref'],piece)
    return sidecar


def query_evidence(output, network, event_id, field=None):
    """Read-only query reusable by CLI or localhost evidence server.

    Revalidates sidecar against original capture, then returns verified named byte
    ranges and raw frames. Caller supplies trusted local paths, never HTTP paths.
    """
    sidecar=verify_artifacts(output,network)
    matches=[i for i,e in enumerate(sidecar['events']) if e['event_id']==event_id]
    if len(matches)!=1:raise ValueError('unknown_event_id')
    i=matches[0];obs=sidecar['observations'][i]
    selected=obs['fields']
    if field is not None:
        if field not in selected:raise ValueError('unknown_field')
        selected={field:selected[field]}
    index=PacketEvidence(network,synthetic=True)
    return {'event':sidecar['events'][i],'node':sidecar['graph']['nodes'][i],
            'observation':obs,'verified_fields':{name:[index.resolve(piece['source_ref'],piece)
                for piece in value['slices']] for name,value in selected.items()}}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('network','process','profile','output'):p.add_argument('--'+name,required=True)
    p.add_argument('--synthetic',action='store_true')
    args=p.parse_args()
    try:result=run(args.network,args.process,args.profile,args.output,synthetic=args.synthetic)
    except (ValueError,OSError) as error:p.exit(2,str(error)+'\n')
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
