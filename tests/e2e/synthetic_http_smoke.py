#!/usr/bin/env python3
"""Actual HTTP -> worker -> artifact synthetic smoke; start Go and Python first.
Usage: python3 tests/e2e/synthetic_http_smoke.py --base-url http://127.0.0.1:8080
No real datasets, accuracy evaluation, or industrial validation are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--base-url', default='http://127.0.0.1:8080')
parser.add_argument('--timeout', type=int, default=90)
args = parser.parse_args()
BASE = args.base_url.rstrip('/') + '/api/v2/cpag'

def call(path, body=None, content_type=None):
    request = urllib.request.Request(BASE + path, data=body, headers={'Content-Type': content_type} if content_type else {})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()

def upload(network=None, confirmed=True):
    boundary = 'cpag-' + uuid.uuid4().hex
    parts = []
    inputs = [('network_file', 'network.jsonl', network if network is not None else (ROOT/'tests/fixtures/synthetic/network.normalized.jsonl').read_bytes()),
              ('process_file', 'process.csv', (ROOT/'tests/fixtures/synthetic/process.csv').read_bytes()),
              ('profile_file', 'profile.json', (ROOT/'profiles/synthetic-demo.json').read_bytes())]
    for field, name, data in inputs:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + data + b'\r\n')
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="synthetic_confirmed"\r\n\r\n{str(confirmed).lower()}\r\n--{boundary}--\r\n'.encode())
    return call('/synthetic', b''.join(parts), 'multipart/form-data; boundary=' + boundary)

def poll(task_id):
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        code, raw = call('/status/' + task_id)
        assert code == 200, (code, raw)
        task = json.loads(raw)
        if task['status'] in ('completed', 'failed'):
            return task
        time.sleep(.3)
    raise AssertionError('Worker did not finish before timeout')

def main():
    code, raw = upload()
    assert code in (200, 202), (code, raw)
    task = json.loads(raw)
    task_id = task.get('id') or task['task_id']
    finished = poll(task_id)
    assert finished['status'] == 'completed', finished
    code, raw = call('/result/' + task_id + '/json')
    assert code == 200, (code, raw)
    result = json.loads(raw)
    assert result['synthetic'] is True and 'graph' in result['data'] and 'quality' in result['data'], result
    code, raw = call('/artifacts/' + task_id)
    assert code == 200, (code, raw)
    inventory = json.loads(raw)
    manifest = inventory['run_manifest']
    checks = {entry['path']: entry for entry in manifest['artifacts']}
    for entry in inventory['files']:
        name = entry['filename']
        code, content = call('/download/' + task_id + '/' + name)
        assert code == 200, (name, code, content)
        json.loads(content)
        if name in checks:
            assert hashlib.sha256(content).hexdigest() == checks[name]['sha256'], name
            assert len(content) == checks[name]['size_bytes'], name
    assert set(checks).issubset({entry['filename'] for entry in inventory['files']})
    for path in ['/status/not-a-task', '/result/not-a-task/json', '/download/' + task_id + '/secrets.txt', '/download/' + task_id + '/%2e%2e%2fprofile.json']:
        code, raw = call(path)
        assert 400 <= code < 500, (path, code, raw)
    code, raw = upload(confirmed=False)
    assert 400 <= code < 500, (code, raw)
    code, raw = upload(network=b'{broken-json\n')
    if code in (200, 202):
        bad = json.loads(raw)
        assert poll(bad.get('id') or bad['task_id'])['status'] == 'failed'
    else:
        assert 400 <= code < 500, (code, raw)
    print(json.dumps({'synthetic_only': True, 'task_id': task_id, 'status': finished['status'], 'downloaded': [entry['filename'] for entry in inventory['files']], 'checksum_verified': list(checks), 'negative_cases': 'passed'}, indent=2))

if __name__ == '__main__':
    main()
