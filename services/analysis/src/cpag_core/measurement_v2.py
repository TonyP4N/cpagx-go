"""Explicit phase-resources-2: bounded raw rows plus all-call aggregates.

Durations nest and MUST NOT be summed across phase names. RSS is cumulative
process high water, never phase allocation or cgroup usage. An absent terminal
summary means incomplete measurement, e.g. abrupt process death.
"""
import atexit
import json
import math
from pathlib import Path

VERSION = 'phase-resources-2'
MAX_PHASES = 64
MAX_RAW = 256
_states = {}


def record(target, phase, status, wall_seconds, cpu_seconds, rss_bytes):
    # The path comes only from the container operator, not a submitted profile.
    if target not in _states:
        if len(_states) >= 1:
            raise ValueError('phase_measurement_output_changed')
        _states[target] = {'calls': 0, 'raw_rows': 0, 'phases': {}}
    state = _states[target]
    if phase not in state['phases']:
        if len(state['phases']) >= MAX_PHASES:
            raise ValueError('phase_measurement_phase_limit')
        state['phases'][phase] = {'calls': 0, 'returned': 0, 'failed': 0,
                                  'wall_seconds': 0.0, 'cpu_seconds': 0.0,
                                  'rss_high_water_bytes': None}
    if status not in ('returned', 'failed') or any(not math.isfinite(x) or x < 0 for x in (wall_seconds, cpu_seconds, rss_bytes)):
        raise ValueError('invalid_phase_measurement')
    state['calls'] += 1
    item = state['phases'][phase]
    item['calls'] += 1; item[status] += 1
    item['wall_seconds'] += wall_seconds; item['cpu_seconds'] += cpu_seconds
    item['rss_high_water_bytes'] = max(item['rss_high_water_bytes'] or 0, rss_bytes)
    if state['raw_rows'] < MAX_RAW:
        state['raw_rows'] += 1
        with Path(target).open('a') as stream:
            stream.write(json.dumps({'version': VERSION, 'kind': 'sample', 'phase': phase,
                'status': status, 'wall_seconds': wall_seconds, 'cpu_seconds': cpu_seconds,
                'rss_high_water_bytes': rss_bytes}, sort_keys=True)+'\n')


def flush_summaries():
    """Called at ordinary interpreter exit; never asserts compute success."""
    for target, state in list(_states.items()):
        row = {'version': VERSION, 'kind': 'terminal_measurement_summary',
               'all_observed_calls': state['calls'], 'raw_rows_retained': state['raw_rows'],
               'raw_rows_not_retained': state['calls']-state['raw_rows'],
               'phases': state['phases'],
               'definition': 'all completed decorator calls including failures; nested durations overlap; RSS is cumulative process high water; abrupt exits lack this summary'}
        with Path(target).open('a') as stream:
            stream.write(json.dumps(row, sort_keys=True)+'\n')
        del _states[target]


atexit.register(flush_summaries)
