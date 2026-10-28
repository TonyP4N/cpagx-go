"""Optional bounded offline phase observations, outside all semantic artifacts.

Enabled by the operator container environment only. RSS is process cumulative
high-water, not phase-local allocation; nested durations overlap. These rows
are measurements, never authority for cancellation or successful publication.
"""
from functools import wraps
import json
import os
from pathlib import Path
import resource
import sys
import time

_COUNT=0

def phase(name):
    def decorate(fn):
        @wraps(fn)
        def measured(*args,**kwargs):
            target=os.environ.get('CPAG_PHASE_METRICS')
            if not target:return fn(*args,**kwargs)
            global _COUNT
            start=time.perf_counter();before=resource.getrusage(resource.RUSAGE_SELF)
            status='failed'
            try:
                result=fn(*args,**kwargs);status='returned';return result
            finally:
                after=resource.getrusage(resource.RUSAGE_SELF);_COUNT+=1
                strategy=os.environ.get('CPAG_PHASE_STRATEGY','offline-phase-resources-1')
                if strategy=='phase-resources-2':
                    from .measurement_v2 import record
                    record(target,name,status,time.perf_counter()-start,
                           after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                           after.ru_maxrss*(1 if sys.platform=='darwin' else 1024))
                    row=None
                elif strategy!='offline-phase-resources-1':
                    raise ValueError('unsupported_phase_measurement_strategy')
                elif _COUNT<=256:
                    row={'version':'offline-phase-resources-1','phase':name,'status':status,
                         'wall_seconds':time.perf_counter()-start,
                         'cpu_seconds':after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                         'rss_high_water_bytes':after.ru_maxrss*(1 if sys.platform=='darwin' else 1024),
                         'definition':'process cumulative RSS high-water; overlapping nested phase durations; excludes tmpfs, host and queue'}
                elif _COUNT==257:row={'version':'offline-phase-resources-1','status':'measurement_limit','reason':'more_than_256_phase_rows_not_retained'}
                else:row=None
                if row is not None:
                    with Path(target).open('a') as stream:stream.write(json.dumps(row,sort_keys=True)+'\n')
        return measured
    return decorate
