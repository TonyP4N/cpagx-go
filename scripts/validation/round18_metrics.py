#!/usr/bin/env python3
"""Actual 1x / 10x input pacing: engineering instrumentation, not R19 throughput."""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from round18_profile import fixture
from cpag_core.replay_export import export_task
from cpag_core.pipeline import file_hash


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    report={'scope':'synthetic replay pacing and metric mechanism only; not performance acceptance',
            'expected':{'speed_1_schedule_seconds':10,'speed_10_schedule_seconds':1,
                        'semantic_hashes_equal':True,'all_samples_retained':True},'runs':[]}
    path=args.output/'results.json'
    try:
        for speed in (1,10):
            base=args.output/f'speed-{speed}';net,process,profile,config=fixture(base/'input')
            config['replay'].update(speed=speed,realtime=True)
            profile.write_text(json.dumps(config,sort_keys=True))
            start=time.monotonic();export_task(net,process,profile,base/'run',run_id=f'pacing-{speed}')
            elapsed=time.monotonic()-start
            runtime=json.loads((base/'run/runtime_metrics.json').read_text())
            semantics={name:file_hash(base/'run'/name) for name in ('analysis.json','events.json','graph.json','snapshots.jsonl','revisions.jsonl','metrics.json')}
            assert runtime['paced'] is True and runtime['speed']==speed
            assert runtime['elapsed_seconds']>=10/speed
            for sample in runtime['samples']:
                assert sample['actual_elapsed_seconds']>=sample['scheduled_elapsed_seconds']
                assert sample['processing_seconds']>=0
            report['runs'].append({'speed':speed,'export_verify_wall_seconds':elapsed,
                                   'runtime':runtime,'semantic_hashes':semantics,
                                   'metric_artifact':str((base/'run/metrics.json').relative_to(args.output))})
            path.write_text(json.dumps(report,indent=2))
        assert report['runs'][0]['semantic_hashes']==report['runs'][1]['semantic_hashes']
        report['status']='passed'
    except BaseException as error:
        report.update(status='failed',error=repr(error));raise
    finally:path.write_text(json.dumps(report,indent=2))
    print(path)


if __name__=='__main__':main()
