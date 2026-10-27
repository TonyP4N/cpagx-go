#!/usr/bin/env python3
"""Independent R16 negative API acceptance against a disposable live harness.

Creates dedicated datasets and runs; never modifies the harness's browser run.
Writes only status/evidence summaries, not passwords, cookies, or internal tokens.
"""
import argparse
import copy
import hashlib
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import time
import urllib.error
import urllib.parse
import urllib.request


def require(ok, message):
    if not ok:
        raise AssertionError(message)


class Client:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, data=None, headers=None):
        headers = dict(headers or {})
        if isinstance(data, (dict, list)):
            data = json.dumps(data, ensure_ascii=False).encode()
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=35) as response:
                raw = response.read()
                return response.status, decode(raw), raw
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            return exc.code, decode(raw), raw

    def login(self, username, password):
        code, value, _ = self.call('POST', '/api/v3/session', {'username': username, 'password': password})
        require(code == 200 and 'user' in value, 'login failed')
        return value['user']


def decode(raw):
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def expect(client, method, path, accepted, data=None, headers=None):
    code, value, raw = client.call(method, path, data, headers)
    if code not in accepted:
        raise AssertionError(f'{method} {path}: status {code}, expected {sorted(accepted)}, error={value.get("error", {})}')
    return value, raw


def upload(client, dataset, role, filename, raw, key):
    path = f'/api/v3/datasets/{dataset}/files?' + urllib.parse.urlencode({'role': role, 'name': filename})
    headers = {'Content-Type': 'application/octet-stream', 'X-Content-SHA256': hashlib.sha256(raw).hexdigest(), 'Idempotency-Key': key}
    return client.call('POST', path, raw, headers)


def poll_run(client, run_id, seconds=180):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value, _ = expect(client, 'GET', f'/api/v3/runs/{run_id}', {200})
        state = value['run']['state']
        if state == 'succeeded':
            return value['run']
        if state in ('failed', 'cancelled'):
            raise AssertionError(f'boundary fixture run ended {state}')
        time.sleep(1)
    raise AssertionError('boundary fixture run timed out')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', required=True, help='round16 live harness state.json')
    parser.add_argument('--output', required=True, help='private JSON report path')
    args = parser.parse_args()
    state = json.loads(Path(args.state).read_text())
    base = state['url'].rstrip('/')
    admin, analyst, viewer, anonymous = (Client(base) for _ in range(4))
    admin_user = admin.login(state['admin_username'], state['admin_password'])
    analyst_user = analyst.login(state['analyst_username'], state['analyst_password'])
    viewer_user = viewer.login(state['viewer_username'], state['viewer_password'])
    checks = []
    def passed(name):
        checks.append(name)

    fixture = Path(state['fixture_dir'])
    network = (fixture / 'network.pcap').read_bytes()
    process = (fixture / 'process.csv').read_bytes()
    profile = json.loads((fixture / 'profile.json').read_text())
    marker = str(int(time.time()))
    synthetic = {'name': 'R16 boundary ' + marker, 'source_kind': 'synthetic', 'source': 'explicit-synthetic-fixture', 'batch': 'boundary-' + marker, 'authorization_ref': 'local-test-fixture'}
    item, _ = expect(admin, 'POST', '/api/v3/datasets', {201}, synthetic)
    did = item['dataset']['id']
    shadow, _ = expect(admin, 'POST', '/api/v3/datasets', {201}, {**synthetic, 'name': 'R16 private shadow ' + marker})
    shadow_id = shadow['dataset']['id']
    expect(admin, 'POST', f'/api/v3/datasets/{did}/acl', {200}, {'user_id': analyst_user['id'], 'access': 'analyst'})
    expect(admin, 'POST', f'/api/v3/datasets/{did}/acl', {200}, {'user_id': viewer_user['id'], 'access': 'viewer'})
    passed('admin_created_dedicated_datasets_and_acl')

    # Server-side ACL is checked for every resource class, including guessed IDs.
    for client, role in ((analyst, 'analyst'), (viewer, 'viewer')):
        for path in (f'/api/v3/datasets/{shadow_id}', f'/api/v3/datasets/{shadow_id}/files',
                     f'/api/v3/datasets/{shadow_id}/configs', f'/api/v3/runs?dataset_id={shadow_id}'):
            expect(client, 'GET', path, {403, 404})
        expect(client, 'POST', f'/api/v3/datasets/{shadow_id}/preflight', {403, 404}, {'config_version_id': 'unknown'})
    for path in (f'/api/v3/datasets/{did}', f'/api/v3/datasets/{did}/files', f'/api/v3/runs?dataset_id={did}'):
        expect(anonymous, 'GET', path, {401})
    config = json.loads((Path(args.state).parent / 'source-app-config.json').read_text())
    for token_name in ('worker_token', 'coordinator_token'):
        expect(anonymous, 'GET', f'/api/v3/datasets/{did}', {401}, headers={'Authorization': 'Bearer ' + config[token_name]})
    for path in ('/v1/claim', '/api/v1/jobs'):
        expect(anonymous, 'GET', path, {404})
    passed('cross_dataset_anonymous_and_internal_credential_boundary')

    # Originals and upload idempotency. File counts must stay fixed on failures.
    key = 'r16-boundary-network-' + marker
    code, value, _ = upload(analyst, did, 'network', 'network.pcap', network, key)
    require(code == 201, 'initial network upload failed')
    network_file = value['file']
    code, value, _ = upload(analyst, did, 'network', 'network.pcap', network, key)
    require(code == 200 and value['file']['id'] == network_file['id'], 'same idempotency key did not return original')
    code, _, _ = upload(analyst, did, 'network', 'network.pcap', network + b'x', key)
    require(code == 409, 'changed bytes under same key did not conflict')
    code, value, _ = upload(analyst, did, 'process', 'process.csv', process, 'r16-boundary-process-' + marker)
    require(code == 201, 'process upload failed')
    process_file = value['file']
    files_before, _ = expect(admin, 'GET', f'/api/v3/datasets/{did}/files', {200})
    count = len(files_before['files'])
    bad_hash_path = f'/api/v3/datasets/{did}/files?role=process&name=bad.csv'
    expect(analyst, 'POST', bad_hash_path, {422}, b'a,b\n1,2\n', {'Content-Type': 'application/octet-stream', 'X-Content-SHA256': '0' * 64, 'Idempotency-Key': 'r16-bad-sha-' + marker})
    expect(analyst, 'POST', bad_hash_path, {413}, b'', {'Content-Type': 'application/octet-stream', 'Content-Length': str((8 << 20) + 1), 'X-Content-SHA256': '0' * 64, 'Idempotency-Key': 'r16-over-limit-' + marker})
    # Declare more bytes than sent, then half-close the socket. No row may appear.
    parsed = urllib.parse.urlparse(base)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    cookie = '; '.join(f'{c.name}={c.value}' for c in analyst.jar)
    conn.putrequest('POST', f'/api/v3/datasets/{did}/files?role=process&name=interrupted.csv')
    for h, v in {'Cookie': cookie, 'Content-Type': 'application/octet-stream', 'Content-Length': '128',
                 'X-Content-SHA256': '0' * 64, 'Idempotency-Key': 'r16-interrupted-' + marker}.items():
        conn.putheader(h, v)
    conn.endheaders(); conn.send(b'a,b\n1,2\n')
    conn.sock.shutdown(socket.SHUT_WR)
    try:
        conn.getresponse().read()
    except (OSError, http.client.HTTPException):
        pass
    conn.close()
    time.sleep(.2)
    files_after, _ = expect(admin, 'GET', f'/api/v3/datasets/{did}/files', {200})
    require(len(files_after['files']) == count, 'failed upload created catalog row')
    passed('upload_idempotency_hash_limit_and_interruption')

    # Role write denial, including the global viewer ceiling over a stronger ACL.
    expect(viewer, 'GET', f'/api/v3/datasets/{did}', {200})
    expect(viewer, 'GET', f'/api/v3/datasets/{did}/files/{network_file["id"]}/download', {200})
    expect(viewer, 'POST', '/api/v3/datasets', {403}, synthetic)
    expect(viewer, 'POST', f'/api/v3/datasets/{did}/files?role=process&name=no.csv', {403}, b'a', {'X-Content-SHA256': hashlib.sha256(b'a').hexdigest(), 'Idempotency-Key': 'r16-viewer-upload-' + marker})
    expect(viewer, 'POST', f'/api/v3/datasets/{did}/configs', {403}, {'kind': 'dual', 'document': profile})
    expect(viewer, 'POST', f'/api/v3/datasets/{did}/preflight', {403}, {'config_version_id': 'unknown'})
    expect(viewer, 'POST', '/api/v3/runs', {403, 404}, {'dataset_id': did, 'config_version_id': 'unknown', 'mode': 'dual_source'})
    expect(analyst, 'POST', '/api/v3/users', {403}, {'username': 'unauthorized', 'password': 'long-password-123', 'role': 'admin'})
    expect(viewer, 'GET', '/api/v3/audit', {403})
    expect(admin, 'POST', f'/api/v3/datasets/{did}/acl', {200}, {'user_id': viewer_user['id'], 'access': 'analyst'})
    expect(viewer, 'POST', f'/api/v3/datasets/{did}/configs', {403}, {'kind': 'dual', 'document': profile})
    passed('role_matrix_and_global_viewer_ceiling')

    intake = {'dataset_id': did, 'synthetic': True, 'authorization': {'allowed_use': 'synthetic test', 'evidence_ref': 'fixture', 'reviewer': 'local'},
              'time_basis': {'timezone': 'UTC', 'precision': 'fixture ticks', 'synchronization': 'declared', 'evidence_ref': 'fixture'},
              'mapping': {'field_units_ref': 'fixture', 'device_map_ref': 'fixture', 'effective_period_ref': 'fixture'}}
    cfg, _ = expect(analyst, 'POST', f'/api/v3/datasets/{did}/configs', {201}, {'kind': 'intake', 'document': intake})
    intake_id = cfg['config']['id']
    report, _ = expect(analyst, 'POST', f'/api/v3/datasets/{did}/preflight', {200}, {'config_version_id': intake_id})
    require(report['report']['status'] == 'ready_for_manual_review', 'complete synthetic intake not ready for manual review')
    conflict, _ = expect(analyst, 'POST', f'/api/v3/datasets/{did}/configs', {201}, {'kind': 'intake', 'document': {**intake, 'dataset_id': 'wrong-batch'}})
    report, _ = expect(analyst, 'POST', f'/api/v3/datasets/{did}/preflight', {409}, {'config_version_id': conflict['config']['id']})
    require(report['error']['code'] == 'batch_conflict' and 'batch_conflict' in report['report']['errors'], 'batch conflict not rejected and reported')
    passed('batch_conflict_is_explicit_report')

    missing, _ = expect(admin, 'POST', '/api/v3/datasets', {201}, {'name': 'R16 missing material ' + marker, 'source_kind': 'real', 'source': '', 'batch': '', 'authorization_ref': ''})
    real_id = missing['dataset']['id']
    code, _, _ = upload(admin, real_id, 'network', 'network.pcap', network, 'r16-real-only-' + marker)
    require(code == 201, 'real single-source upload failed')
    incomplete = {'dataset_id': real_id, 'synthetic': False}
    cfg, _ = expect(admin, 'POST', f'/api/v3/datasets/{real_id}/configs', {201}, {'kind': 'intake', 'document': incomplete})
    report, _ = expect(admin, 'POST', f'/api/v3/datasets/{real_id}/preflight', {200}, {'config_version_id': cfg['config']['id']})
    require(report['report']['source_scope'] == 'network_only' and report['report']['status'] == 'single_source_review', 'real single-source scope wrong')
    require({'source', 'release', 'authorization'} <= set(report['report']['material_gaps']), 'missing source metadata not reported')
    expect(admin, 'POST', '/api/v3/runs', {422}, {'dataset_id': real_id, 'config_version_id': cfg['config']['id'], 'mode': 'dual_source'})
    passed('real_single_source_missing_metadata_no_analysis')

    c1, _ = expect(analyst, 'POST', f'/api/v3/datasets/{did}/configs', {201}, {'kind': 'dual', 'document': profile})
    old_config = c1['config']['id']
    run1, _ = expect(analyst, 'POST', '/api/v3/runs', {201}, {'dataset_id': did, 'config_version_id': old_config, 'mode': 'dual_source'})
    old_run = run1['run']['id']; poll_run(analyst, old_run)
    updated = copy.deepcopy(profile);updated['config_version'] = 'boundary-v2-' + marker
    c2, _ = expect(analyst, 'POST', f'/api/v3/datasets/{did}/configs', {201}, {'kind': 'dual', 'document': updated})
    new_config = c2['config']['id'];require(new_config != old_config and c2['config']['version'] == c1['config']['version'] + 1, 'new config did not version')
    run2, _ = expect(analyst, 'POST', '/api/v3/runs', {201}, {'dataset_id': did, 'config_version_id': new_config, 'mode': 'dual_source'})
    new_run = run2['run']['id'];poll_run(analyst, new_run)
    r1, _ = expect(analyst, 'GET', f'/api/v3/runs/{old_run}', {200})
    r2, _ = expect(analyst, 'GET', f'/api/v3/runs/{new_run}', {200})
    require(r1['run']['config_version_id'] == old_config and r2['run']['config_version_id'] == new_config, 'run binding did not retain exact version')
    old_result, old_raw = expect(viewer, 'GET', f'/api/v3/runs/{old_run}/result', {200})
    new_result, new_raw = expect(viewer, 'GET', f'/api/v3/runs/{new_run}/result', {200})
    require(old_result['data']['analysis']['config_version'] != new_result['data']['analysis']['config_version'], 'runs used same config')
    expect(viewer, 'GET', f'/api/v3/runs/{old_run}/evidence?operation=first', {200})
    artifacts, _ = expect(viewer, 'GET', f'/api/v3/runs/{old_run}/artifacts', {200})
    first_artifact = artifacts['artifacts'][0]['path']
    artifact_url = f'/api/v3/runs/{old_run}/artifacts/' + '/'.join(urllib.parse.quote(x, safe='') for x in first_artifact.split('/')) + '/download'
    expect(viewer, 'GET', artifact_url, {200})
    expect(viewer, 'POST', f'/api/v3/runs/{old_run}/cancel', {403})
    shadow_network, _, _ = upload(admin, shadow_id, 'network', 'network.pcap', network, 'r16-shadow-network-' + marker)
    shadow_process, _, _ = upload(admin, shadow_id, 'process', 'process.csv', process, 'r16-shadow-process-' + marker)
    require(shadow_network == 201 and shadow_process == 201, 'shadow source creation failed')
    shadow_config, _ = expect(admin, 'POST', f'/api/v3/datasets/{shadow_id}/configs', {201}, {'kind': 'dual', 'document': profile})
    shadow_run_created, _ = expect(admin, 'POST', '/api/v3/runs', {201}, {'dataset_id': shadow_id, 'config_version_id': shadow_config['config']['id'], 'mode': 'dual_source'})
    shadow_run = shadow_run_created['run']['id'];poll_run(admin, shadow_run)
    for client in (analyst, viewer):
        for suffix in ('', '/result', '/evidence?operation=first', '/artifacts', '/artifacts/dataset.json/download'):
            expect(client, 'GET', f'/api/v3/runs/{shadow_run}{suffix}', {403, 404})
    passed('two_executed_versions_viewer_reads_and_cross_run_denial')

    # Tamper only our dataset's original. Restore in finally even if an assertion fails.
    original_path = Path(state['source_root']) / 'inputs' / 'catalog' / did / (network_file['id'] + '.pcap')
    require(original_path.is_file(), 'dedicated original path missing')
    untouched = original_path.read_bytes()
    endpoints = [(f'/api/v3/datasets/{did}/preflight', 'POST', {'config_version_id': intake_id}),
                 (f'/api/v3/runs/{old_run}/result', 'GET', None),
                 (f'/api/v3/runs/{old_run}/evidence?operation=first', 'GET', None),
                 (f'/api/v3/runs/{old_run}/artifacts', 'GET', None),
                 (artifact_url, 'GET', None)]
    try:
        original_path.chmod(0o600);original_path.write_bytes(untouched + b'tamper')
        for path, method, data in endpoints:
            expect(analyst, method, path, {409}, data)
        original_path.unlink()
        for path, method, data in endpoints:
            expect(analyst, method, path, {409}, data)
    finally:
        original_path.write_bytes(untouched);original_path.chmod(0o400)
    expect(analyst, 'POST', f'/api/v3/datasets/{did}/preflight', {200}, {'config_version_id': intake_id})
    expect(analyst, 'GET', f'/api/v3/runs/{old_run}/result', {200})
    expect(analyst, 'GET', f'/api/v3/runs/{old_run}/evidence?operation=first', {200})
    expect(analyst, 'GET', artifact_url, {200})
    passed('original_tamper_missing_blocks_all_trust_then_recovers')

    report = {'status': 'passed', 'checks': checks, 'dedicated_dataset_id': did, 'dedicated_real_dataset_id': real_id,
              'old_run_id': old_run, 'new_run_id': new_run, 'shadow_run_id': shadow_run, 'old_config_id': old_config, 'new_config_id': new_config,
              'result_sha256_old': hashlib.sha256(old_raw).hexdigest(), 'result_sha256_new': hashlib.sha256(new_raw).hexdigest(),
              'real_declared_source_test_material': 'generated synthetic fixture bytes reused solely to exercise real-source metadata intake and rejection; no industrial data was analyzed'}
    out = Path(args.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2,sort_keys=True) + '\n')
    os.chmod(out,0o600)
    print(json.dumps({'status':'passed','checks':len(checks),'report':str(out)},ensure_ascii=False))


if __name__ == '__main__':
    main()
