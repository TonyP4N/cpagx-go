#!/usr/bin/env python3
"""Supplementary S export CPU attribution, never a capacity acceptance result.

Run only after the fixed matrix, in its same immutable image and quotas. cProfile
adds overhead: do not compare its timings directly to uninstrumented samples.
"""
import cProfile
import hashlib
import json
from pathlib import Path
import pstats
import resource
import time

from cpag_core.shared_export import export_task


def main():
    out=Path('/result')
    profiler=cProfile.Profile(timer=time.process_time)
    started=time.monotonic();cpu=time.process_time()
    result={'version':'core-function-cpu-diagnostic-1','status':'failed',
        'scope':'supplementary instrumented S offline export only; not full-chain acceptance',
        'definitions':{'self_cpu':'excludes callees','inclusive_cpu':'includes nested callees; cannot sum',
            'memory':'process cumulative RSS; not per-function allocation','overhead':'process_time cProfile overhead included; not comparable to uninstrumented timings'}}
    try:
        profiler.enable()
        export_task(['/input/network.pcap'],'/input/process.csv','/input/profile.json',out/'artifact',
            mode='offline',run_id='r19-function-diagnostic',attempt_id=1,deadline=started+1800)
        profiler.disable();result['status']='exported_not_source_verified'
    except BaseException as error:
        profiler.disable();result.update(reason=str(error),error_type=type(error).__name__)
        raise
    finally:
        profiler.dump_stats(str(out/'cpu.pstats'))
        rows=[]
        for (filename,line,function),(primitive,calls,self_cpu,inclusive_cpu,callers) in pstats.Stats(profiler).stats.items():
            if '/cpag_core/' not in filename:continue
            rows.append({'module':Path(filename).name,'line':line,'function':function,
                'primitive_calls':primitive,'calls':calls,'self_cpu_seconds':self_cpu,'inclusive_cpu_seconds':inclusive_cpu})
        result.update(wall_seconds=time.monotonic()-started,cpu_seconds=time.process_time()-cpu,
            process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            functions=sorted(rows,key=lambda row:-row['inclusive_cpu_seconds']),
            inputs={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/input').iterdir() if p.is_file()})
        try:
            result['cgroup_peak_memory_bytes']=int(Path('/sys/fs/cgroup/memory.peak').read_text())
            result['cgroup_cpu_stat']=Path('/sys/fs/cgroup/cpu.stat').read_text()
        except OSError as error:result['cgroup_unavailable_reason']=type(error).__name__
        (out/'profile.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')


if __name__=='__main__':main()
