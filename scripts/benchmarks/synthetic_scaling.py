"""Bounded synthetic-only scaling; no production core or default entry changes."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import signal
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'services/analysis/src'))
from cpag_core.pipeline import run, canonical, file_hash, fingerprint
from cpag_core.evidence import EvidenceIndex
from cpag_core.parsers import parse_network, parse_process

BUDGET = ROOT/'scripts/benchmarks/synthetic-budget.json'
PROFILE = ROOT/'profiles/synthetic-demo.json'


def rss_bytes(value, system):
    if system == 'Linux': return int(value * 1024)
    if system == 'Darwin': return int(value)
    raise ValueError('unsupported RSS units')


def generate(base, count):
    record = json.loads((ROOT/'tests/fixtures/synthetic/network.normalized.jsonl').read_text().splitlines()[0])
    network, process = base/'network.jsonl', base/'process.csv'
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with network.open('w') as n, process.open('w') as p:
        p.write('time,level,pump\n')
        for i in range(count):
            stamp = (start+timedelta(seconds=i)).isoformat().replace('+00:00','Z')
            record.update(raw_time=stamp, correlation_id=f'synthetic-{i}')
            n.write(json.dumps(record, sort_keys=True)+'\n')
            p.write(f'{stamp},{i % 100},{"ON" if i % 2 else "OFF"}\n')
    return network, process


def verify_publication(output, paths, count, manifest):
    if json.loads((output/'run_manifest.json').read_text()) != manifest:
        raise ValueError('published manifest mismatch')
    for artifact in manifest['artifacts']:
        path=output/artifact['path']
        if path.stat().st_size != artifact['size_bytes'] or file_hash(path) != artifact['sha256']:
            raise ValueError('artifact checksum mismatch')
    events=json.loads((output/'events.json').read_text())
    graph=json.loads((output/'graph.json').read_text())
    if len(events)!=count*3 or len(graph['nodes'])!=count*3 or graph['edges'] or graph['claims']:
        raise ValueError('unexpected event/graph content')
    if manifest['result_hashes'] != {'events':fingerprint(events),'graph':fingerprint(graph)}:
        raise ValueError('result fingerprint mismatch')
    indexes={file_hash(p):EvidenceIndex(p) for p in paths}
    expected={e['event_id']:e['source_ref'] for e in events}
    if len(expected)!=len(events): raise ValueError('duplicate event identity')
    for event in events:
        ref=event['source_ref'];indexes[ref['file_sha256']].resolve(ref)
    for node in graph['nodes']:
        if node['evidence_refs'] != [expected[node['event_id']]]:
            raise ValueError('graph evidence mismatch')
        for ref in node['evidence_refs']: indexes[ref['file_sha256']].resolve(ref)
    for index in indexes.values(): index.verify()
    return {name:file_hash(output/name) for name in ('dataset.json','events.json','graph.json','quality.json')}


def sample(phase, count):
    with tempfile.TemporaryDirectory(prefix='cpag-benchmark-sample-') as tmp:
        base=Path(tmp);network,process=generate(base,count)
        config=json.loads(PROFILE.read_text())
        inputs=[{'kind':kind,'sha256':file_hash(path),'size_bytes':path.stat().st_size}
                for kind,path in [('network',network),('process',process)]]
        started=time.perf_counter()
        if phase=='parse':
            nindex,pindex=EvidenceIndex(network),EvidenceIndex(process)
            parsed=[parse_network(network,synthetic=True,evidence=nindex),
                    parse_process(process,config,synthetic=True,evidence=pindex)]
            events=sum(len(part['events']) for part in parsed)
            nindex.verify();pindex.verify()
        else:
            manifest=run(network,process,PROFILE,base/'out',synthetic=True)
            events=count*3
        elapsed=time.perf_counter()-started
        # Snapshot before post-run evidence verification; includes interpreter,
        # imports and generated-input preparation, not only Python allocations.
        peak=rss_bytes(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,platform.system())
        if events!=count*3: raise ValueError('parser event count mismatch')
        result={'process_pid':os.getpid(),'phase':phase,'records_per_source':count,'events':events,
                'input_bytes':sum(i['size_bytes'] for i in inputs),'input_fingerprint':fingerprint(inputs),
                'config_fingerprint':hashlib.sha256(canonical(config)).hexdigest(),
                'elapsed_seconds':elapsed,'peak_rss_bytes':peak,
                'bytes_per_second':sum(i['size_bytes'] for i in inputs)/elapsed,'events_per_second':events/elapsed}
        if phase=='pipeline':
            result['artifact_hashes']=verify_publication(base/'out',(network,process),count,manifest)
            result['result_hashes']=manifest['result_hashes']
            result['run_manifest_sha256']=file_hash(base/'out/run_manifest.json')
            result['manifest_without_run_id_sha256']=hashlib.sha256(canonical({k:v for k,v in manifest.items() if k!='run_id'})).hexdigest()
            result['verified_event_references']=count*3
            result['verified_graph_references']=count*3
        else:
            result['parsed_fingerprint']=fingerprint(parsed)
        return result


def execute(command, timeout):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True) as child:
        try:
            stdout,stderr=child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL)
            child.communicate()
            raise ValueError('sample_timeout') from None
        if child.returncode: raise ValueError(f'sample_exit_{child.returncode}')
        def reject_constant(value): raise ValueError('nonfinite measurement')
        try:
            value=json.loads(stdout,parse_constant=reject_constant)
            if not isinstance(value,dict): raise ValueError('measurement must be an object')
            return value
        except ValueError: raise ValueError('sample_missing_or_invalid_measurement') from None


def summarize(samples, budget):
    groups=[]
    for phase in ('parse','pipeline'):
        for count in budget['sizes']:
            rows=[r for r in samples if r.get('phase')==phase and r.get('records_per_source')==count]
            if len(rows)!=budget['repeats']: raise ValueError('incomplete_samples')
            if {row.get('iteration') for row in rows} != set(range(1,budget['repeats']+1)):
                raise ValueError('missing_or_duplicate_iteration')
            for row in rows:
                for key in ('elapsed_seconds','peak_rss_bytes','input_bytes','bytes_per_second','events_per_second'):
                    if type(row.get(key)) not in (int,float) or not math.isfinite(row[key]) or row[key]<=0:
                        raise ValueError('invalid_measurement_'+key)
                if not math.isclose(row['bytes_per_second'],row['input_bytes']/row['elapsed_seconds'],rel_tol=1e-9) or not math.isclose(row['events_per_second'],row['events']/row['elapsed_seconds'],rel_tol=1e-9):
                    raise ValueError('throughput_measurement_mismatch')
                if row['events']!=count*3: raise ValueError('wrong_event_count')
                if row['peak_rss_bytes']<=0 or row['peak_rss_bytes']>budget['max_peak_rss_bytes']:
                    raise ValueError('rss_budget_exceeded_or_missing')
                if not 0<row['elapsed_seconds']<=budget['sample_timeout_seconds']:
                    raise ValueError('invalid_sample_duration')
            fields=['input_fingerprint','config_fingerprint','input_bytes']
            fields+=['artifact_hashes','result_hashes','manifest_without_run_id_sha256'] if phase=='pipeline' else ['parsed_fingerprint']
            if any(any(row[key]!=rows[0][key] for key in fields) for row in rows):
                raise ValueError('nonrepeatable_results')
            if phase=='pipeline' and any(row.get(key)!=count*3 for row in rows
                                        for key in ('verified_event_references','verified_graph_references')):
                raise ValueError('unverified_references')
            stats={key:{'min':min(r[key] for r in rows),'median':statistics.median(r[key] for r in rows),
                        'max':max(r[key] for r in rows)} for key in ('elapsed_seconds','peak_rss_bytes','bytes_per_second','events_per_second')}
            groups.append({'phase':phase,'records_per_source':count,'samples':len(rows),'statistics':stats})
    if len(samples)!=len(budget['sizes'])*budget['repeats']*2: raise ValueError('unexpected_samples')
    for count in budget['sizes']:
        rows=[r for r in samples if r['records_per_source']==count]
        if any(any(r[k]!=rows[0][k] for k in ('input_fingerprint','config_fingerprint','input_bytes')) for r in rows):
            raise ValueError('cross_phase_input_mismatch')
    return groups


def environment():
    def read(path):
        try: return Path(path).read_text().strip()
        except OSError: return None
    return {'system':platform.system(),'machine':platform.machine(),'kernel':platform.release(),
            'python':platform.python_version(),'logical_cpus_visible':os.cpu_count(),
            'cpu_max':read('/sys/fs/cgroup/cpu.max'),'memory_max':read('/sys/fs/cgroup/memory.max'),
            'memory_swap_max':read('/sys/fs/cgroup/memory.swap.max'),'pids_max':read('/sys/fs/cgroup/pids.max'),
            'rss_metric':'process ru_maxrss at end of measured phase; includes imports/preparation; excludes later verification',
            'phase_time':'includes index+parse (parse); complete pipeline through publication (pipeline); excludes input generation and later verification'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample',choices=['parse','pipeline'])
    parser.add_argument('--count',type=int)
    args=parser.parse_args()
    budget=json.loads(BUDGET.read_text())
    if args.sample:
        if args.count not in budget['sizes']: parser.error('count outside registered sizes')
        print(json.dumps(sample(args.sample,args.count),allow_nan=False));return 0
    report={'schema_version':'1.0.0','synthetic':True,'status':'failed','budget':budget,
            'budget_sha256':file_hash(BUDGET),'environment':environment(),'samples':[],
            'limitations':['normalized synthetic input only','no protocol throughput or correlation benchmark',
                           'no industrial validation or minimum hardware promise','no cold-cache claim'],
            'replay_backlog':None,'correlation_throughput':None}
    try:
        for phase in ('parse','pipeline'):
            for count in budget['sizes']:
                for iteration in range(budget['repeats']):
                    row=execute([sys.executable,str(Path(__file__).resolve()),'--sample',phase,'--count',str(count)],budget['sample_timeout_seconds'])
                    row['iteration']=iteration+1;report['samples'].append(row)
        report['summary']=summarize(report['samples'],budget)
        report['status']='passed'
    except (ValueError,OSError,KeyError,TypeError) as exc:
        report['error']=str(exc)
    print(json.dumps(report,indent=2,allow_nan=False))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__': raise SystemExit(main())
