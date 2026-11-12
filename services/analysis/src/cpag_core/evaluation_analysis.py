"""Explicit P3 synthetic analysis input boundary; annotations never accepted.

Trusted local CLI, not an OS sandbox. Stage only allowlisted data/config into a
private temporary input root. Existing runtime/default entry is unchanged.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
from .pipeline import run, canonical, fingerprint
from .parsers import _label_column


def read_input(root, name, prefix):
    path=Path(name)
    if path.is_absolute() or not path.parts or path.parts[0]!=prefix or '..' in path.parts:
        raise ValueError('input must be under declared raw or profiles namespace')
    current=root
    for part in path.parts:
        current=current/part
        if current.is_symlink():raise ValueError('symlink input forbidden')
    if current.stat().st_nlink!=1 or not current.is_file():
        raise ValueError('ordinary unlinked input required')
    return current.read_bytes()


def reject_labels(value):
    if isinstance(value,dict):
        for k,v in value.items():
            if _label_column(k):raise ValueError('annotation field forbidden in analysis input')
            reject_labels(v)
    elif isinstance(value,list):
        for v in value:reject_labels(v)


def analyze(root, network, process, profile, output):
    root=Path(root).resolve(strict=True);output=Path(output).resolve()
    if output==root or root in output.parents:
        raise ValueError('output must be outside input root')
    if output.exists():raise ValueError('analysis output must be new')
    n=read_input(root,network,'raw');p=read_input(root,process,'raw');c=read_input(root,profile,'profiles')
    config=json.loads(c);reject_labels(config)
    allowed={'profile_id','synthetic','timestamp_column','columns','timestamp_format','timezone','timezone_evidence'}
    if set(config)-allowed or config.get('synthetic') is not True:raise ValueError('unsupported analysis config')
    for line in n.decode().splitlines():
        if line.strip():reject_labels(json.loads(line))
    header=next(csv.reader(io.StringIO(p.decode())),[])
    if any(_label_column(v) for v in header):raise ValueError('label column forbidden')
    with tempfile.TemporaryDirectory(prefix='cpag-eval-analysis-') as work:
        work=Path(work);(work/'network.jsonl').write_bytes(n);(work/'process.csv').write_bytes(p)
        result=run(work/'network.jsonl',work/'process.csv',config,output,synthetic=True)
    return {'input_fingerprint':result['input_fingerprint'],'config_fingerprint':result['config_fingerprint'],'result_hashes':result['result_hashes'],'synthetic':True,'annotation_access':'not accepted or staged'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('root','network','process','profile','output'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    try:result=analyze(**vars(args))
    except (ValueError,OSError,KeyError,TypeError):
        print(json.dumps({'status':'rejected','reason':'invalid analysis inputs'}));return 2
    print(json.dumps(result,sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
