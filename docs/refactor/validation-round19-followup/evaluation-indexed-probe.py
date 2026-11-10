"""Reproduce local evaluator-only dense capacity measurement; no industrial data."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / 'services/analysis/src'), str(ROOT / 'tests/evaluation')]
from cpag_core.evaluation_indexed import maximum_pairs
from cpag_core.evaluation_details import evaluate_detailed, V2_MATCHING_VERSION
from cpag_core.pipeline import canonical
from test_round19_details import fixture, event


def source_hashes():
    return {name: hashlib.sha256((ROOT / 'services/analysis/src/cpag_core' / name).read_bytes()).hexdigest()
            for name in ('evaluation.py', 'evaluation_details.py', 'evaluation_indexed.py', 'pipeline.py')}


def main():
    n = 22000
    before = source_hashes()
    pred = [event(f'p{i:05}', 0) for i in range(n)]
    gold = [event(f'g{i:05}', 0) for i in range(n)]
    start, cpu = time.perf_counter(), time.process_time()
    pairs, _, _ = maximum_pairs(pred, gold, [1.0] * n, [1.0] * n, 0)
    matching = {'wall_seconds': time.perf_counter() - start,
                'cpu_seconds': time.process_time() - cpu, 'tp': len(pairs)}
    values = fixture()
    values[0]['events'], values[1]['events'] = pred, gold
    values[3]['tolerance_seconds'] = 0
    start, cpu = time.perf_counter(), time.process_time()
    result = evaluate_detailed(*values, matching_version=V2_MATCHING_VERSION)
    elapsed, cpu_elapsed = time.perf_counter() - start, time.process_time() - cpu
    after = source_hashes()
    actual = tuple(result['record']['metrics'][key] for key in ('tp', 'fp', 'fn'))
    measured = {
        'observed_at': datetime.now(timezone.utc).isoformat(),
        'status': 'synthetic_evaluator_development_success' if actual == (22000, 0, 0) and before == after else 'failed',
        'scope': 'Local synthetic evaluator only; not final-artifact, Worker, reference environment or real-material acceptance.',
        'python': sys.version.split()[0], 'platform': platform.platform(),
        'source_sha256_before': before, 'source_sha256_after': after,
        'matching_version': V2_MATCHING_VERSION,
        'scenario': '22000 per side, identical time and batch/kind/asset, tolerance0; handwritten expectedTP22000FP0FN0',
        'matching': matching, 'evaluate_wall_seconds': elapsed, 'evaluate_cpu_seconds': cpu_elapsed,
        'measurement_boundary': 'Validation, indexing, matching, metric/details construction and input hashing; result serialization and CLI/bundle/Worker excluded.',
        'process_peak_rss_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == 'darwin' else 1024),
        'memory_boundary': 'Process lifetime high-water mark; not exclusive algorithm memory.',
        'result_canonical_bytes': len(canonical(result)), 'metrics': result['record']['metrics']}
    print(json.dumps(measured, indent=2))
    return 0 if measured['status'] != 'failed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
