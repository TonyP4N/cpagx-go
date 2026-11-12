"""Synthetic M1 scaling check; run with PYTHONPATH=services/analysis/src."""
import json
from pathlib import Path
import tempfile
import time
import tracemalloc
from cpag_core.pipeline import run

ROOT=Path(__file__).resolve().parents[2]
fixture=ROOT/'tests/fixtures/synthetic'
profile=ROOT/'profiles/synthetic-demo.json'
results=[]
for count in (100,1000,5000):
    with tempfile.TemporaryDirectory() as tmp:
        base=Path(tmp)
        network=base/'network.jsonl'
        record=(fixture/'network.normalized.jsonl').read_text().splitlines()[0]+'\n'
        network.write_text(record*count)
        process=base/'process.csv'
        process.write_text('time,level,pump\n'+('2026-01-01T00:00:00Z,1,ON\n'*count))
        tracemalloc.start()
        started=time.perf_counter()
        run(network,process,profile,base/'out',synthetic=True)
        elapsed=time.perf_counter()-started
        _,peak=tracemalloc.get_traced_memory()
        tracemalloc.stop()
        results.append({'records_per_source':count,'events':3*count,'elapsed_seconds':round(elapsed,3),'peak_python_mib':round(peak/1024**2,3)})
print(json.dumps(results,indent=2))
