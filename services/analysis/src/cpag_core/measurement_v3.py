"""Explicit phase-resources-3: v2 samples/exit summary plus bounded progress.

progress.json is always in_progress/nonterminal and contains ended calls only.
A configured five-second monotonic timer is best effort under OS scheduling/IO;
it is not a hard realtime deadline. An absent exit summary remains incomplete.
"""
import atexit
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import re
import tempfile
import threading
import time

VERSION='phase-resources-3'
MAX_PHASES=64
MAX_RAW=256
MAX_PHASE_NAME=128
MAX_PROGRESS_BYTES=128*1024
MAX_OBSERVED_CALLS=2**53-1
PROGRESS_SECONDS=5.0
_states={}
_lock=threading.RLock()
_stop=threading.Event()
_worker=None
_closed=False


def _target(value):
    value=os.fspath(value)
    if not isinstance(value,str) or not value or len(value)>4096 or any(ord(c)<32 for c in value):
        raise ValueError('invalid_phase_measurement_target')
    path=Path(value)
    if path.name=='progress.json':raise ValueError('phase_progress_target_collision')
    return str(path)


def _validate(phase,status,wall,cpu,rss):
    if not isinstance(phase,str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',phase) is None:
        raise ValueError('invalid_phase_measurement_name')
    if status not in ('returned','failed'):
        raise ValueError('invalid_phase_measurement')
    if any(type(value) not in (int,float) or (type(value) is int and value>MAX_OBSERVED_CALLS) or not math.isfinite(value) or value<0 for value in (wall,cpu)):
        raise ValueError('invalid_phase_measurement')
    if type(rss) is not int or not 0<=rss<=MAX_OBSERVED_CALLS:
        raise ValueError('invalid_phase_measurement')


def _summary(state,kind):
    row={'version':VERSION,'kind':kind,'all_observed_calls':state['calls'],
        'raw_rows_retained':state['raw_rows'],'raw_rows_not_retained':state['calls']-state['raw_rows'],
        'phases':deepcopy(state['phases']),
        'progress_write_failures':state['progress_write_failures'],
        'last_progress_error_type':state['last_progress_error_type'],
        'definition':'all completed decorator calls including failures; nested durations overlap; RSS is cumulative process high water; no compute success or container exit assertion'}
    return row


def _encoded(row):
    value=(json.dumps(row,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    if len(value)>MAX_PROGRESS_BYTES:raise ValueError('phase_progress_byte_limit')
    return value


def _atomic_progress(target,row):
    """One private bounded temporary file, fsync, then same-directory replace.

    A failed replace leaves the prior complete progress document untouched.
    A SIGKILL during a write can leave one temporary file, never partial JSON
    at the published progress.json path.
    """
    value=_encoded(row);path=Path(target).with_name('progress.json');temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='wb',dir=path.parent,prefix='.progress-',suffix='.tmp',delete=False) as stream:
            temporary=Path(stream.name);stream.write(value);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path);temporary=None
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)


def _publish_locked(target,state,now,force=False):
    if not force and now-state['last_progress_attempt']<PROGRESS_SECONDS:return False
    state['last_progress_attempt']=now
    row=_summary(state,'progress_measurement_summary')
    row.update(measurement_state='in_progress',terminal=False,completed_calls_only=True,
        compute_success=None,metrics_file=Path(target).name,progress_interval_seconds=PROGRESS_SECONDS,
        elapsed_monotonic_seconds=max(0,now-state['started_monotonic']))
    try:_atomic_progress(target,row)
    except Exception as error:
        state['progress_write_failures']+=1;state['last_progress_error_type']=type(error).__name__
        return False
    state['progress_writes']+=1;state['last_progress_calls']=state['calls']
    return True


def publish_progress(*,force=False):
    """Timer/ended-call checkpoint; never appends a terminal summary."""
    with _lock:
        now=time.monotonic()
        for target,state in _states.items():_publish_locked(target,state,now,force)


def _progress_loop():
    while True:
        with _lock:
            if not _states:return
            due=min(state['last_progress_attempt']+PROGRESS_SECONDS for state in _states.values())
            delay=max(.01,due-time.monotonic())
        if _stop.wait(delay):return
        publish_progress()


def _start_worker_locked():
    global _worker
    if _worker is None:
        _worker=threading.Thread(target=_progress_loop,name='cpag-phase-progress-3',daemon=True)
        _worker.start()


def begin(target):
    """Called before the first explicit-v3 function, without counting it ended."""
    target=_target(target)
    with _lock:
        if _closed:raise ValueError('phase_measurement_already_terminal')
        if target not in _states:
            if _states:raise ValueError('phase_measurement_output_changed')
            now=time.monotonic()
            state={'calls':0,'raw_rows':0,'phases':{},'started_monotonic':now,
                'last_progress_attempt':now,'progress_writes':0,'last_progress_calls':0,
                'progress_write_failures':0,'last_progress_error_type':None}
            _states[target]=state;_publish_locked(target,state,now,True);_start_worker_locked()
    return target


def record(target,phase,status,wall_seconds,cpu_seconds,rss_bytes):
    _validate(phase,status,wall_seconds,cpu_seconds,rss_bytes)
    target=begin(target)
    with _lock:
        state=_states[target]
        if phase not in state['phases']:
            if len(state['phases'])>=MAX_PHASES:raise ValueError('phase_measurement_phase_limit')
            current={'calls':0,'returned':0,'failed':0,'wall_seconds':0.0,'cpu_seconds':0.0,'rss_high_water_bytes':None}
        else:current=state['phases'][phase]
        wall=current['wall_seconds']+wall_seconds;cpu=current['cpu_seconds']+cpu_seconds
        if state['calls']>=MAX_OBSERVED_CALLS or not math.isfinite(wall) or not math.isfinite(cpu):
            raise ValueError('phase_measurement_aggregate_limit')
        state['calls']+=1;current['calls']+=1;current[status]+=1
        current['wall_seconds']=wall;current['cpu_seconds']=cpu
        current['rss_high_water_bytes']=max(current['rss_high_water_bytes'] or 0,rss_bytes)
        state['phases'][phase]=current
        if state['raw_rows']<MAX_RAW:
            row={'version':VERSION,'kind':'sample','phase':phase,'status':status,
                'wall_seconds':wall_seconds,'cpu_seconds':cpu_seconds,'rss_high_water_bytes':rss_bytes}
            with Path(target).open('a') as stream:stream.write(_encoded(row).decode())
            state['raw_rows']+=1
        # Make the first ended call immediately visible. Later writes are timer
        # bounded; a busy stream cannot produce one progress file per call.
        _publish_locked(target,state,time.monotonic(),state['calls']==1)


def flush_summaries():
    """Ordinary interpreter exit; stopped/failed work is not called successful."""
    global _closed
    with _lock:
        if not _states:return
        _closed=True;_stop.set()
        now=time.monotonic()
        for target,state in list(_states.items()):
            _publish_locked(target,state,now,True)
            row=_summary(state,'terminal_measurement_summary')
            row.update(progress_file='progress.json',progress_writes=state['progress_writes'],
                progress_last_snapshot_calls=state['last_progress_calls'])
            with Path(target).open('a') as stream:stream.write(_encoded(row).decode())
            del _states[target]
    if _worker is not None and _worker is not threading.current_thread():_worker.join(timeout=1)


atexit.register(flush_summaries)
