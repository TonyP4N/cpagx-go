"""Small actual-artifact development measurement; not S/M/L Worker acceptance."""
from pathlib import Path
import hashlib
import json
import platform
import resource
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from round18_profile import fixture
from cpag_core.replay_export import export_task,verify_task,query_task,iter_verified_snapshots
from cpag_core.replay_history import VERSION
from cpag_core.pipeline import canonical


def measured(name, call, rows):
    start,cpu=time.perf_counter(),time.process_time()
    value=call()
    rows.append({'phase':name,'wall_seconds':time.perf_counter()-start,'cpu_seconds':time.process_time()-cpu})
    return value


def main():
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'services/analysis/src/cpag_core').glob('replay*.py')}
    rows=[]
    with tempfile.TemporaryDirectory(prefix='cpag-spool-small-probe-') as tmp:
        root=Path(tmp);n,p,c,config=fixture(root/'inputs')
        old=measured('old_jsonl_export_including_verification',lambda:export_task(n,p,c,root/'old',run_id='small',attempt_id=1),rows)
        config['replay']['history_format']=VERSION;c.write_text(json.dumps(config))
        new=measured('spool_export_including_verification',lambda:export_task(n,p,c,root/'new',run_id='small',attempt_id=1),rows)
        measured('spool_independent_verify',lambda:verify_task(root/'new'),rows)
        evidence=measured('spool_original_evidence_query',lambda:query_task(root/'new',3,operation_id='first'),rows)
        old_rows=list(iter_verified_snapshots(root/'old'));new_rows=list(iter_verified_snapshots(root/'new'))
        result={'scope':'local small synthetic actual artifacts only; no Worker/reference hardware or S/M/L replay acceptance',
                'platform':platform.platform(),'python':sys.version.split()[0],'source_sha256':hashes,'phases':rows,
                'logical_snapshots_equal':canonical(old_rows)==canonical(new_rows),
                'semantic_config_equal':old['semantic_config_fingerprint']==new['semantic_config_fingerprint'],
                'snapshot_count':len(new_rows),'verified_original_count':len(evidence['verified_original_evidence']),
                'old_history_bytes':sum((root/'old'/name).stat().st_size for name in ('snapshots.jsonl','revisions.jsonl')),
                'spool_history_bytes':sum(path.stat().st_size for path in (root/'new/history').iterdir()),
                'spool_history_manifest':json.loads((root/'new/history/manifest.json').read_text()),
                'process_lifetime_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024),
                'memory_scope':'lifetime high-water includes both formats; not exclusive per-stage memory'}
    print(json.dumps(result,indent=2))
    return 0 if result['logical_snapshots_equal'] and result['semantic_config_equal'] else 1


if __name__=='__main__':raise SystemExit(main())
