#!/usr/bin/env python3
"""Read-only, allowlisted summary of retained formal R19 measurements.

Original records, failures and phase rows are never replaced. This report cannot
confer reference-environment acceptance. Run identity is retained, while only the
existing pipeline VOLATILE fields are excluded from semantic comparisons.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'services/analysis/src'))
from cpag_core.pipeline import fingerprint, file_hash

SEMANTIC_FILES={'dual/analysis.json','events.json','graph.json','quality.json'}


def summarize(roots):
    rows=[]
    for path in roots:
        root=Path(path).resolve()
        record=json.loads((root/'record.json').read_text())
        public=json.loads((root/'public-summary.json').read_text())
        row={'record_sha256':file_hash(root/'record.json'),'public_summary_sha256':file_hash(root/'public-summary.json'),
             'private_evidence_root':str(root),'status':record['status'],'failures':record.get('failures',[]),
             'commit':record.get('environment',{}).get('commit'),'source_tree_sha256':record.get('environment',{}).get('source_tree_sha256'),
             'resource_profile':record.get('resource_profile'),'run_id':record.get('run_id'),
             'measurements':record.get('measurements',{}),'worker_attempts':public.get('worker_attempts',[]),
             'input_fingerprints':record.get('case',{}).get('input_fingerprints',[]),
             'output_bytes':record.get('output',{}).get('bytes'),'semantic_hashes':{},'docker_samples':[],
             'terminal':record.get('terminal',{}),'exit_receipts':[]}
        for receipt in sorted((root/'control/jobs').glob('*/attempt-*.worker/exit.json')):
            value=json.loads(receipt.read_text())
            row['exit_receipts'].append({'sha256':file_hash(receipt),
                **{k:value.get(k) for k in ('scope','exited','running','pid','removed')}})
        terminal=record.get('terminal',{})
        if terminal.get('state')=='succeeded':
            output=root/'source/jobs'/record['run_id']/('attempt-'+str(terminal['attempt']))
            for name in sorted(SEMANTIC_FILES):
                target=output/name
                if target.is_file():
                    # Keep every business field, evidence reference, list order,
                    # time-quality and inference state. No business projection.
                    row['semantic_hashes'][name]=fingerprint(json.loads(target.read_text()))
            row['output_files']=record.get('output',{}).get('files',[])
            row['retained_file_hashes_match']=bool(row['output_files']) and all(
                (output/item['path']).is_file() and not (output/item['path']).is_symlink() and
                (output/item['path']).stat().st_size==item['bytes'] and
                file_hash(output/item['path'])==item['sha256'] for item in row['output_files'])
        for sample in sorted(root.glob('stats-*.stdout')):
            for line in sample.read_text().splitlines():
                try:value=json.loads(line)
                except ValueError:continue
                row['docker_samples'].append({'sample':sample.name,'source_sha256':file_hash(sample),
                    **{key:value.get(key) for key in ('CPUPerc','MemUsage','MemPerc','BlockIO','PIDs')}})
        rows.append(row)
    identities=[(r['commit'],r['source_tree_sha256'],r['resource_profile'],
                 tuple(a.get('image_id') for a in r['worker_attempts']),
                 tuple((i['sha256'],i['bytes']) for i in r['input_fingerprints'])) for r in rows]
    passed=all(r['status']=='development_case_measured_incomplete_gate' and not r['failures'] and
               set(r['semantic_hashes'])==SEMANTIC_FILES and r.get('retained_file_hashes_match') is True and len(r['worker_attempts'])==1 and
               r['terminal'].get('state')=='succeeded' and
               r['worker_attempts'][0]['state'].get('Status')=='exited' and
               r['worker_attempts'][0]['state'].get('OOMKilled') is False and
               r['worker_attempts'][0].get('compute_measurements',{}).get('returncode')==0 and
               len(r['exit_receipts'])==1 and r['exit_receipts'][0].get('exited') is True and
               r['exit_receipts'][0].get('removed') is True and r['exit_receipts'][0].get('pid')==0 and
               r['exit_receipts'][0].get('running') is False for r in rows)
    return {'schema_version':'r19-formal-repeat-summary-1','reference_accepted':False,
        'scope':'development formal Worker repeats, not Ubuntu reference capacity acceptance',
        'semantic_excluded_fields':['run_id','ingest_time'],
        'measurement_definitions':{'phase_rss':'cumulative process high-water, not phase allocation',
            'phase_seconds':'nested wall/CPU durations overlap and must not be added',
            'docker_memory':'includes tmpfs/cgroup pages; not process RSS',
            'container_exit':'host kills the waiting PID1 after transfer; 137 with OOMKilled=false is not compute failure; compute returncode and separate exit receipt are required',
            'cache_condition':'unverified_cold; no OS cache clearing claimed',
            'evidence_query_cache':'after the result API verified and populated the application cache; not a cold-query benchmark'},
        'three_independent_runs':len(rows)==3 and len({r['run_id'] for r in rows})==3,
        'fixed_inputs_code_image_resources':bool(rows) and all(x==identities[0] for x in identities),
        'all_runs_complete':bool(rows) and passed,
        'semantic_hashes_equal':bool(rows) and all(r['semantic_hashes']==rows[0]['semantic_hashes'] for r in rows),
        'samples':rows}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('roots',nargs='+',type=Path)
    args=parser.parse_args()
    value=summarize(args.roots)
    with args.output.open('x') as stream:json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')
    print(json.dumps({k:v for k,v in value.items() if k!='samples'}))
