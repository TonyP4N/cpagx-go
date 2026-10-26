"""Strict interpretation of synthetic probe evidence; never invent exit proof."""
import json


def timeout_proof(record, *, require_startup):
    entries = []
    for line in record['logs'].splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('probe_result') is True:
            entries.append(value)
    assert len(entries) == 1, 'missing or duplicate final probe result'
    value = entries[0]
    proof = value.get('receipt')
    assert isinstance(proof, dict), 'missing exit receipt'
    for key, expected in {'id':'probe', 'attempt':1, 'worker':'linux-probe',
                          'token':'synthetic', 'reason':'timeout', 'group_exited':True}.items():
        assert type(proof.get(key)) is type(expected) and proof.get(key) == expected, f'invalid receipt {key}'
    assert type(proof.get('returncode')) is int and proof['returncode'] < 0
    for key in ('child_pid', 'guardian_pid'):
        assert type(proof.get(key)) is int and proof[key] > 1
    assert value['worker_result'] == 'failed'
    assert 2 <= value['elapsed_seconds'] < 20, 'timeout outside bounded container lifetime'
    startup = value.get('startup')
    if require_startup:
        assert isinstance(startup, dict), 'core never reported readiness'
        assert startup['child'] == proof['child_pid'] and startup['guardian'] == proof['guardian_pid']
        assert all(type(startup.get(key)) is int and startup[key] > 1 for key in ('child','guardian','worker','escaped'))
    else:
        assert startup is None, 'delayed startup unexpectedly ready before timeout'
    assert record['exit'] == 0 and record['state']['Running'] is False and record['state']['Pid'] == 0
    assert record['state']['ExitCode'] == record['exit']
    assert not record['state'].get('OOMKilled'), 'OOM is not timeout proof'
    return value
