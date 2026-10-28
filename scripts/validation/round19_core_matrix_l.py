#!/usr/bin/env python3
"""Explicit L-only coverage4 controller; imports the unchanged S/M controller.

The private native entry is replaced once before export, its complete source and
all hashes retained. No running or historical S/M directory is changed.
"""
import argparse
import json
from pathlib import Path
import shutil

import round19_core_matrix as baseline
from round19_scale_fixture import density_budget_math

VERSION='r19-core-l-expiry-coverage-4'


def checked_counts(counts,scale,mode,record):
    if scale!='L':raise ValueError('L_only_coverage_controller')
    if mode=='offline':return baseline_counts(counts,scale)
    metadata=record['phases'][-1]['result']['metadata'];coverage=metadata.get('independent_ever_observed_coverage')
    if not isinstance(coverage,dict) or coverage.get('version')!='core-ever-observed-coverage-1' or coverage.get('status')!='passed':
        raise ValueError('complete_independent_history_coverage_required')
    n=10000
    if (coverage['raw_original_units']!=3*n+1 or coverage['admitted_units']!=3*n+1
            or coverage['csv_headers_admitted_not_observations']!=1 or coverage['ever_observed_data_units']!=3*n
            or coverage['actual_history_events_proven']!=3*n or coverage['missing_or_extra_units']!=0):
        raise ValueError('independent_original_admission_history_membership_mismatch')
    if coverage['raw_file_sha256']!={'network-0':record['fixed_inputs']['network.pcap']['sha256'],'process':record['fixed_inputs']['process.csv']['sha256']}:
        raise ValueError('coverage_original_file_identity_mismatch')
    if coverage['expired_units']==0:return baseline_counts(counts,scale)
    for name,maximum in (('network',2*n),('process',n),('changes',n-1)):
        if type(counts.get(name)) is not int or not 0<=counts[name]<=maximum:raise ValueError('final_live_frozen_count_outside_raw_bound:'+name)
    geometry=density_budget_math(scale)
    if type(counts.get('operations')) is not int or counts['operations']!=n:raise ValueError('fixed_operation_count_mismatch')
    if (type(counts.get('candidates')) is not int or not geometry['candidate_count_lower_bound']<=counts['candidates']<=geometry['candidate_count_upper_bound']):
        raise ValueError('independent_density_candidate_bound_mismatch')
    return {'candidate_count_lower_bound':geometry['candidate_count_lower_bound'],'candidate_count_upper_bound':geometry['candidate_count_upper_bound'],
        'coverage_version':VERSION,'scope':'final live+frozen counts differ from complete admitted/ever-observed coverage after expiry',
        'all_original_units_admitted':coverage['admitted_units'],'all_data_units_actually_observed_in_history':coverage['actual_history_events_proven']}


baseline_counts=baseline.check_counts


def run(output,fixture,profile,mode,image,scratch_root):
    original_container=baseline.run_container;original_sources=baseline.runtime_sources;original_version=baseline.VERSION;current={}
    def sources():
        result=original_sources()
        for name in ('round19_core_matrix_l.py','round19_core_cell_l.py','round19_core_history_coverage.py'):
            path=baseline.ROOT/'scripts/validation'/name;result[path.relative_to(baseline.ROOT).as_posix()]=baseline.sha(path)
        return result
    def container(root,*args,**kwargs):
        current['record']=args[-1] if args else kwargs['record'];record=current['record'];harness=Path(root)/'harness'
        if not (harness/'round19_core_history_coverage.py').exists():
            shutil.copyfile(harness/'round19_core_cell.py',harness/'round19_core_cell_baseline.py')
            shutil.copyfile(baseline.ROOT/'scripts/validation/round19_core_cell_l.py',harness/'round19_core_cell.py')
            shutil.copyfile(baseline.ROOT/'scripts/validation/round19_core_history_coverage.py',harness/'round19_core_history_coverage.py')
            shutil.copyfile(baseline.ROOT/'scripts/validation/round19_core_matrix_l.py',harness/'round19_core_matrix_l.py')
            record['frozen_harness_sha256']={path.name:baseline.sha(path) for path in sorted(harness.iterdir())}
            record['harness_policy']={'version':VERSION,'core_runtime':'unchanged83files56e106b',
                'native_entry_source':'scripts/validation/round19_core_cell_l.py',
                'coverage':'complete validation audit within1800, not interactive query; no S/M source mutation'}
        return original_container(root,*args,**kwargs)
    try:
        baseline.VERSION=VERSION;baseline.runtime_sources=sources;baseline.run_container=container
        baseline.check_counts=lambda counts,scale:checked_counts(counts,scale,mode,current['record'])
        return baseline.run(output,fixture,profile,'L',mode,image,scratch_root=scratch_root)
    finally:
        baseline.run_container=original_container;baseline.runtime_sources=original_sources;baseline.check_counts=baseline_counts;baseline.VERSION=original_version


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','fixture','profile','image','scratch-root'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--mode',choices=['offline','replay'],required=True);args=parser.parse_args()
    record=run(args.output,args.fixture,args.profile,args.mode,args.image,args.scratch_root)
    print(json.dumps({'status':record['status'],'scale':'L','mode':args.mode,'reason':record.get('reason')}))
    raise SystemExit(0 if record['status']=='passed' else 1)
