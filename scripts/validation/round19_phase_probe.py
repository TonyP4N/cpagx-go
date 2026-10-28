#!/usr/bin/env python3
"""Offline development phase probe. Emits failures/entries before possible OOM.

RSS is process cumulative high-water, not phase-local allocation or Docker usage.
No data labels enter this probe. Profiling does not modify core semantic outputs.
"""
import argparse
import functools
import importlib
import json
import os
from pathlib import Path
import resource
import sys
import time

PHASES = {
    ('dual_source', 'analyze'): 'offline_analysis',
    ('packet_pipeline', 'analyze_capture'): 'network_parse',
    ('parsers', 'parse_process'): 'process_parse',
    ('dual_source', '_analyze_prepared'): 'association_and_evidence',
    ('dual_source', 'references'): 'evidence_references',
    ('dual_source', 'run_dual'): 'retained_export',
    ('dual_source_export', 'projection'): 'standard_projection',
    ('dual_source_export', 'verify_task'): 'artifact_verification',
    ('dual_source_export', 'export_task'): 'complete_export',
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--network', action='append', required=True)
    p.add_argument('--process', required=True)
    p.add_argument('--profile', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--log', required=True)
    p.add_argument('--coarse',action='store_true',help='wrap phase boundaries only; no per-call tracing overhead')
    args = p.parse_args()
    from cpag_core.dual_source_export import export_task
    stacks = {}
    aggregates = {}
    scale = 1 if sys.platform == 'darwin' else 1024
    with open(args.log, 'x', buffering=1) as stream:
        def emit(row):
            stream.write(json.dumps(row, sort_keys=True) + '\n')
            stream.flush()
        def measure():
            r = resource.getrusage(resource.RUSAGE_SELF)
            return time.perf_counter(), r.ru_utime + r.ru_stime, r.ru_maxrss * scale
        def trace(frame, event, arg):
            key = (frame.f_globals.get('__name__', '').rsplit('.', 1)[-1], frame.f_code.co_name)
            phase = PHASES.get(key)
            if phase is None or event not in ('call', 'return'):
                return
            wall, cpu, rss = measure()
            if event == 'call':
                stacks[id(frame)] = (wall, cpu, rss)
                if phase != 'evidence_references':
                    emit({'phase': phase, 'event': 'enter', 'rss_high_water_bytes': rss})
            else:
                start = stacks.pop(id(frame), (wall, cpu, rss))
                row = {'phase': phase, 'event': 'return', 'wall_seconds': wall-start[0],
                       'cpu_seconds': cpu-start[1], 'rss_high_water_bytes': rss}
                a = aggregates.setdefault(phase, {'calls': 0, 'wall_seconds': 0, 'cpu_seconds': 0})
                a['calls'] += 1
                a['wall_seconds'] += row['wall_seconds']; a['cpu_seconds'] += row['cpu_seconds']
                if phase != 'evidence_references': emit(row)
        emit({'schema_version': 'r19-development-phase-probe-1', 'pid': os.getpid(),
              'rss_definition': 'process cumulative high-water bytes; nested phase durations overlap',
              'profiling_overhead': 'Python call/return hook; not production timing'})
        undo=[]
        if args.coarse:
            for (module_name,function_name),phase in PHASES.items():
                if phase=='evidence_references':continue
                module=importlib.import_module('cpag_core.'+module_name)
                original=getattr(module,function_name,None)
                if original is None:continue
                def wrap(fn,phase):
                    @functools.wraps(fn)
                    def measured(*a,**kw):
                        start=measure();emit({'phase':phase,'event':'enter','rss_high_water_bytes':start[2]})
                        try:return fn(*a,**kw)
                        finally:
                            wall,cpu,rss=measure()
                            emit({'phase':phase,'event':'return','wall_seconds':wall-start[0],'cpu_seconds':cpu-start[1],'rss_high_water_bytes':rss})
                    return measured
                wrapped=wrap(original,phase)
                for loaded in list(sys.modules.values()):
                    if loaded is None or not getattr(loaded,'__name__','').startswith('cpag_core'):continue
                    for name,value in list(vars(loaded).items()):
                        if value is original:
                            undo.append((loaded,name,value));setattr(loaded,name,wrapped)
            export_task=importlib.import_module('cpag_core.dual_source_export').export_task
            emit({'profiling_mode':'coarse phase wrappers; nested durations overlap'})
        else:sys.setprofile(trace)
        try:
            export_task(args.network, args.process, args.profile, args.output, run_id='phase-probe')
        except BaseException as e:
            sys.setprofile(None)
            emit({'status': 'failed', 'error': repr(e), 'aggregates': aggregates})
            raise
        finally:
            sys.setprofile(None)
            for module,name,value in reversed(undo):setattr(module,name,value)
        emit({'status': 'succeeded', 'aggregates': aggregates,
              'output_bytes': sum(f.stat().st_size for f in Path(args.output).rglob('*') if f.is_file())})

if __name__ == '__main__':
    main()
