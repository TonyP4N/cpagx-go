"""Compare baseline and working-tree M1 in isolated processes; never switch checkout."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tracemalloc

ROOT = Path(__file__).resolve().parents[2]
BASELINE = '75a9e92'


def worker(count):
    from cpag_core.pipeline import run
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        record = (ROOT/'tests/fixtures/synthetic/network.normalized.jsonl').read_text().splitlines()[0]+'\n'
        network = base/'network.jsonl'
        network.write_text(record*count)
        process = base/'process.csv'
        process.write_text('time,level,pump\n'+'2026-01-01T00:00:00Z,1,ON\n'*count)
        tracemalloc.start()
        started = time.perf_counter()
        run(network, process, ROOT/'profiles/synthetic-demo.json', base/'out', synthetic=True)
        elapsed = time.perf_counter()-started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return {'records_per_source':count, 'events':3*count,
                'elapsed_seconds':round(elapsed,3), 'peak_python_mib':round(peak/1024**2,3)}


if len(sys.argv)>1 and sys.argv[1]=='--worker':
    print(json.dumps(worker(int(sys.argv[2]))))
else:
    with tempfile.TemporaryDirectory(prefix='m1-baseline-') as tmp:
        baseline = Path(tmp)
        paths = subprocess.check_output(['git','ls-tree','-r','--name-only',BASELINE,'services/analysis/src/cpag_core','schemas'],cwd=ROOT,text=True).splitlines()
        for relative in paths:
            target = baseline/relative
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(subprocess.check_output(['git','show',BASELINE+':'+relative],cwd=ROOT))
        results = {'baseline_revision':BASELINE,'memory_metric':'tracemalloc peak Python allocations; not process RSS','samples':[]}
        for count in (100,500,1000):
            for variant,source in [('baseline',baseline/'services/analysis/src'),('indexed',ROOT/'services/analysis/src')]:
                env = dict(os.environ,PYTHONPATH=str(source))
                measured = json.loads(subprocess.check_output([sys.executable,str(Path(__file__).resolve()),'--worker',str(count)],cwd=ROOT,env=env,text=True))
                results['samples'].append(dict(variant=variant,**measured))
                print(json.dumps(results),flush=True)
