#!/usr/bin/env python3
"""Independent synthetic density oracle; no analyzer output or prediction input.

Hand-fixed R19 specification: N requests at 10+.05*i seconds, response +.01;
N process observations at 9+.08*i, alternating 0/1. Zero configured clock
uncertainty means N-1 changes at the latter observation's upper time. Candidate
associations are not gold attacks or causal paths and receive no path score.
The caller supplies registration identity only, never selected predictions.
"""
import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

VERSION='r19-independent-density-reference-1'
SCALES={'S':100,'M':1000,'L':10000}
BASE=datetime(2026,1,1,tzinfo=timezone.utc)


def timestamp(microseconds):
    return (BASE+timedelta(microseconds=microseconds)).isoformat(timespec='microseconds').replace('+00:00','Z')


def expected_rows(scale):
    count=SCALES[scale]
    rows=[]
    for number in range(count):
        rows.append({'id':f'manual-network-{number+1:05d}','kind':'network_operation',
                     'asset':'["192.0.2.2",44818]','time':timestamp(10_000_000+50_000*number),
                     'basis':f'independent schedule request ordinal {number+1}; protocol operation only'})
    for number in range(1,count):
        rows.append({'id':f'manual-process-{number+1:05d}','kind':'process_change',
                     'asset':'["synthetic-pump","pump_state"]','time':timestamp(9_000_000+80_000*number),
                     'basis':f'independent alternating observation ordinals {number}/{number+1}; {((number-1)%2)} to {number%2}'})
    return rows


def generate(output,scale,*,batch,sample_sha256):
    if scale not in SCALES:raise ValueError('unsupported_reference_scale')
    if not batch.strip() or re.fullmatch('[0-9a-f]{64}',sample_sha256) is None:raise ValueError('registered_identity_required')
    root=Path(output);root.mkdir(parents=True,exist_ok=False,mode=0o700)
    rows=expected_rows(scale);path=root/'independent-reference.csv'
    columns=['id','kind','asset','time','basis']
    with path.open('w',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=columns,lineterminator='\n');writer.writeheader();writer.writerows(rows)
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    annotations={'schema_version':'1.0.0','synthetic':True,'origin':'independent',
                 'source_ref':VERSION,'review_ref':'hand-fixed R19 density timing specification; generated software oracle, no industrial annotation',
                 'annotation_version':VERSION,'disputed_intervals':[],
                 'events':[{key:row[key] for key in ('id','kind','asset','time')}|{'batch':batch,'sample_sha256':sample_sha256} for row in rows]}
    references={row['id']:{'source_ref':path.name,'sha256':digest,'locator':{
        'version':'csv-logical-record-1','file_sha256':digest,'record_number':number,'columns':columns}}
        for number,row in enumerate(rows,1)}
    report={'version':VERSION,'scale':scale,'synthetic':True,'expected_network_operations':SCALES[scale],
            'expected_process_changes':SCALES[scale]-1,'expected_events':len(rows),'matching_tolerance_seconds':0,
            'path_gold':False,'normal_duration':None,'source_sha256':digest,
            'forbidden_conclusions':['industrial accuracy','causal or attack confirmation','normal-hour false-positive rate without denominator'],
            'independence_scope':'oracle constructed from fixed raw fixture specification, not predictions; this does not establish independent real annotation custody'}
    for name,value in [('annotations.json',annotations),('references.json',references),('reference-files.json',{path.name:digest}),('oracle.json',report)]:
        (root/name).write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True);parser.add_argument('--scale',choices=SCALES,required=True)
    parser.add_argument('--batch',required=True);parser.add_argument('--sample-sha256',required=True)
    args=parser.parse_args();print(json.dumps(generate(args.output,args.scale,batch=args.batch,sample_sha256=args.sample_sha256)))

if __name__=='__main__':main()
