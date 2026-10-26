#!/usr/bin/env python3
"""Finite, disposable real-Celery synthetic HTTP validation (no eager task calls).

Run from any directory with the repository venv Python. Requires Docker Compose.
Creates its own RabbitMQ/Redis project, uvicorn and prefork worker; always stops them.
Only repository synthetic fixtures are submitted. The default deployment is untouched.
"""
import argparse
import base64
import copy
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / 'deployments/compose.round9-celery-validation.yml'
FIXTURE = ROOT / 'tests/fixtures/synthetic'
PROFILE = ROOT / 'profiles/synthetic-demo.json'
ARTIFACTS = ('dataset.json', 'events.json', 'graph.json', 'quality.json', 'run_manifest.json')
WAIT = 90
STARTUP_WAIT = 180


def require(value, message):
    if not value:
        raise AssertionError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs).stdout.strip()


def http(base, path, body=None, content_type=None):
    headers = {'Content-Type': content_type} if content_type else {}
    request = urllib.request.Request(base + path, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def upload(base, network=None, process=None):
    boundary = 'round9-' + uuid.uuid4().hex
    parts = []
    inputs = (
        ('network_file', 'network.jsonl', network if network is not None else (FIXTURE/'network.normalized.jsonl').read_bytes()),
        ('process_file', 'process.csv', process if process is not None else (FIXTURE/'process.csv').read_bytes()),
        ('profile_file', 'profile.json', PROFILE.read_bytes()),
    )
    for field, name, data in inputs:
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{name}"\r\n'
                      'Content-Type: application/octet-stream\r\n\r\n').encode() + data + b'\r\n')
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="synthetic_confirmed"\r\n\r\ntrue\r\n--{boundary}--\r\n'.encode())
    return http(base, '/cpag/synthetic', b''.join(parts), 'multipart/form-data; boundary=' + boundary)


def poll(base, identifier, expected):
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        code, raw = http(base, '/cpag/status/' + identifier)
        require(code == 200, f'status {identifier}: {code} {raw[:300]!r}')
        value = json.loads(raw)
        if value['status'] in ('completed', 'failed'):
            require(value['status'] == expected, f'{identifier}: {value}')
            return value
        time.sleep(.25)
    raise AssertionError(f'task {identifier} did not reach {expected} within {WAIT}s')


def wait_http(base, process):
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        require(process.poll() is None, 'uvicorn exited before health check')
        try:
            code, _ = http(base, '/health')
            if code == 200:
                return
        except urllib.error.URLError:
            pass
        time.sleep(.25)
    raise AssertionError('uvicorn did not become healthy')


def wait_worker_log(path, needle, process, prior_count=0):
    deadline = time.monotonic() + STARTUP_WAIT
    while time.monotonic() < deadline:
        require(process.poll() is None, f'Celery worker exited; see {path}')
        if path.exists() and path.read_text(errors='replace').count(needle) > prior_count:
            return
        time.sleep(.25)
    raise AssertionError(f'worker log did not contain {needle!r}')


def stop_process(process):
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def json_response(base, path, status=200):
    code, raw = http(base, path)
    require(code == status, f'{path}: expected {status}, got {code}: {raw[:500]!r}')
    return json.loads(raw)


def rabbit_queue(port):
    url = f'http://127.0.0.1:{port}/api/queues/%2F/cpag_generation'
    token = base64.b64encode(b'cpag_round9:disposable-round9-only').decode()
    request = urllib.request.Request(url, headers={'Authorization': 'Basic ' + token})
    with urllib.request.urlopen(request, timeout=12) as response:
        return json.load(response)


def rabbit_overview(port):
    token = base64.b64encode(b'cpag_round9:disposable-round9-only').decode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}/api/overview',
                                     headers={'Authorization': 'Basic ' + token})
    with urllib.request.urlopen(request, timeout=12) as response:
        return json.load(response)


def await_backend(celery_app, identifier, state):
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        meta = celery_app.backend.get_task_meta(identifier)
        if meta['status'] == state:
            result = meta.get('result')
            return {'state': meta['status'], 'result_status': result.get('status') if isinstance(result, dict) else None}
        time.sleep(.25)
    raise AssertionError(f'Celery result backend did not record {state} for {identifier}')


def verify_task(base, output, identifier, compare_core):
    from cpag_core.contracts import validate
    from cpag_core.evidence import EvidenceIndex
    from cpag_core.pipeline import run, fingerprint

    task = output/identifier
    status = json_response(base, '/cpag/status/' + identifier)
    require(status['status'] == 'completed', 'published task status is not completed')
    inventory = json_response(base, '/cpag/artifacts/' + identifier)
    require({item['filename'] for item in inventory['files']} == set(ARTIFACTS), 'published file set differs')
    data = {}
    hashes = {}
    for filename in ARTIFACTS:
        code, raw = http(base, f'/cpag/download/{identifier}/{filename}')
        require(code == 200, f'download {filename}: {code} {raw[:300]!r}')
        require(raw == (task/filename).read_bytes(), f'HTTP/local {filename} mismatch')
        data[filename] = json.loads(raw)
        hashes[filename] = digest(raw)
    manifest = data['run_manifest.json']
    require(manifest['synthetic'] is True and manifest['status'] in ('succeeded', 'succeeded_with_warnings'), 'core manifest invalid')
    require(status['run_manifest_sha256'] == hashes['run_manifest.json'], 'outer manifest hash mismatch')
    for item in manifest['artifacts']:
        name = item['path']
        require(hashes[name] == item['sha256'] and (task/name).stat().st_size == item['size_bytes'], f'core hash/size mismatch: {name}')
    require(manifest['result_hashes'] == {'events': fingerprint(data['events.json']), 'graph': fingerprint(data['graph.json'])}, 'fingerprint mismatch')
    validate('DatasetManifest', data['dataset.json'])
    validate('GraphArtifact', data['graph.json'])
    validate('RunManifest', manifest)
    result = json_response(base, f'/cpag/result/{identifier}/json')
    require(result['status'] == 'completed' and result['synthetic'] is True, 'result route mismatch')
    for name in ('graph', 'events', 'quality', 'run_manifest'):
        require(result['data'][name] == data[name+'.json'], f'result route {name} mismatch')
    code, plain = http(base, f'/cpag/result/{identifier}')
    require(code == 200 and plain == (task/'graph.json').read_bytes(), 'plain result route differs from graph download')
    batch = json_response(base, f'/cpag/status/batch?task_ids={identifier}')
    require(batch[identifier]['status'] == 'completed', 'batch status differs')
    task_list = json_response(base, '/cpag/tasks')
    require(any(item['task_id'] == identifier for item in task_list), 'task is absent from list')

    sources = task/'sources'
    indexes = {}
    for record in status['retained_inputs']:
        path = task/record['path']
        require(path.stat().st_size == record['size_bytes'] and digest(path.read_bytes()) == record['sha256'], 'retained input mismatch')
    for item in data['dataset.json']['files']:
        path = sources/item['name']
        require(digest(path.read_bytes()) == item['sha256'] and path.stat().st_size == item['size_bytes'], 'dataset source mismatch')
        index = EvidenceIndex(path)
        indexes[item['sha256']] = index
    resolved = []
    for event in data['events.json']:
        ref = event['source_ref']
        original = indexes[ref['file_sha256']].resolve(ref)
        resolved.append({'event_id': event['event_id'], 'source_ref': ref, 'original': original})
    for node in data['graph.json']['nodes']:
        for ref in node['evidence_refs']:
            indexes[ref['file_sha256']].resolve(ref)
    for index in indexes.values():
        index.verify()

    if compare_core:
        standalone = output.parent/'standalone'
        comparable = run(sources/'network.jsonl', sources/'process.csv', sources/'profile.json', standalone,
                         synthetic=True, source='user-confirmed synthetic HTTP upload', authorization_ref='synthetic_confirmed=true')
        for name in ARTIFACTS[:-1]:
            require((standalone/name).read_bytes() == (task/name).read_bytes(), f'standalone {name} differs')
        other = copy.deepcopy(comparable)
        current = copy.deepcopy(manifest)
        other.pop('run_id')
        current.pop('run_id')
        require(current == other, 'standalone manifest differs beyond run_id')
    return {'task_id': identifier, 'artifact_sha256': hashes, 'resolved_event_count': len(resolved),
            'resolved_record_sha256': digest(json.dumps(resolved, sort_keys=True, ensure_ascii=False).encode()),
            'standalone_comparison': 'four files byte-identical; run_manifest only run_id differs' if compare_core else None}


def file_hashes(directory):
    return {str(path.relative_to(directory)): digest(path.read_bytes()) for path in directory.rglob('*') if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=ROOT/'docs/refactor/validation-round9/celery-live.json')
    args = parser.parse_args()
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    project = 'cpag-r9-' + uuid.uuid4().hex[:8]
    compose = ['docker', 'compose', '-p', project, '-f', str(COMPOSE)]
    workspace = tempfile.TemporaryDirectory(prefix='cpag-round9-celery-')
    scratch = Path(workspace.name)
    output = scratch/'outputs'
    uploads = scratch/'uploads'
    output.mkdir()
    uploads.mkdir()
    api_log = (args.evidence.parent/'celery-api.log').open('w')
    worker_log = (args.evidence.parent/'celery-worker.log').open('w')
    api = worker = None
    started_infra = False
    evidence = {'synthetic_only': True, 'runtime': 'real uvicorn + Celery prefork + RabbitMQ + Redis',
                'project': project, 'checks': {}, 'artifacts': {}, 'limitations': ['No mid-compute worker kill/recovery claim', 'No real industrial data or production validation']}
    try:
        started_infra = True
        command(compose + ['up', '-d', '--wait', 'rabbitmq', 'redis'])
        rabbit_port = command(compose + ['port', 'rabbitmq', '5672']).rsplit(':', 1)[1]
        rabbit_management_port = command(compose + ['port', 'rabbitmq', '15672']).rsplit(':', 1)[1]
        redis_port = command(compose + ['port', 'redis', '6379']).rsplit(':', 1)[1]
        evidence['versions'] = {'python': sys.version.split()[0],
                                'docker_images': command(compose + ['images']),
                                'celery': __import__('celery').__version__}
        evidence['worker_start_method'] = 'macOS harness forces billiard fork; Linux uses Celery default'
        env = os.environ.copy()
        env.update(PYTHONPATH=os.pathsep.join((str(ROOT/'services/python-cpag-generator'), str(ROOT/'services/analysis/src'))),
                   RABBITMQ_URL=f'amqp://cpag_round9:disposable-round9-only@127.0.0.1:{rabbit_port}//',
                   REDIS_URL=f'redis://127.0.0.1:{redis_port}/0', REDIS_HOST='127.0.0.1', REDIS_PORT=redis_port,
                   OUTPUT_DIR=str(output), UPLOAD_DIR=str(uploads), NEO4J_URI='bolt://127.0.0.1:1',
                   INFLUXDB_URL='http://127.0.0.1:1', PYTHONUNBUFFERED='1')
        os.environ.update({key: env[key] for key in ('PYTHONPATH', 'RABBITMQ_URL', 'REDIS_URL', 'OUTPUT_DIR', 'UPLOAD_DIR')})
        sys.path[:0] = [str(ROOT/'services/python-cpag-generator'), str(ROOT/'services/analysis/src')]
        from infrastructure.celery_app import celery_app

        # Let the OS reserve a free local port before uvicorn binds it.
        import socket
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            api_port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{api_port}'
        api = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'api.v2.app:app', '--host', '127.0.0.1', '--port', str(api_port)],
                               cwd=ROOT, env=env, stdout=api_log, stderr=subprocess.STDOUT, start_new_session=True)
        wait_http(base, api)

        # C1: the broker accepts a task while no worker process exists.
        code, raw = upload(base)
        require(code == 202, f'queued submission: {code} {raw[:300]!r}')
        first = json.loads(raw)['task_id']
        queued = json_response(base, '/cpag/status/' + first)
        require(queued['status'] == 'queued' and worker is None, 'task was not visibly queued without a worker')
        require(queued['files'] == [] and not any((output/first/name).exists() for name in ARTIFACTS),
                'queued task published an artifact before worker execution')
        require(json_response(base, '/cpag/artifacts/' + first)['files'] == [],
                'queued artifact inventory is not empty')
        deadline = time.monotonic() + 20
        queue = {}
        while time.monotonic() < deadline:
            queue = rabbit_queue(rabbit_management_port)
            if queue.get('messages_ready', 0) >= 1:
                break
            time.sleep(.5)
        require(queue.get('messages_ready', 0) >= 1, f'broker did not report queued message: {queue}')
        evidence['checks']['queued_without_worker'] = {'task_id': first, 'http_status': queued['status'],
                                                        'rabbitmq_messages_ready': queue['messages_ready'],
                                                        'published_artifact_count': 0}

        def launch_worker():
            nonlocal worker
            old_ready_count = Path(worker_log.name).read_text(errors='replace').count('ready.')
            if sys.platform == 'darwin':
                # Celery 5.3's macOS spawn child skips fast-trace localization;
                # force the normal prefork method in this validation process only.
                entry = [sys.executable, '-c',
                         "import billiard; billiard.set_start_method('fork', force=True); "
                         "from celery.__main__ import main; main()"]
            else:
                entry = [sys.executable, '-m', 'celery']
            worker = subprocess.Popen(entry + ['-A', 'infrastructure.celery_app', 'worker',
                                       '--pool=prefork', '--concurrency=1', '-Q', 'cpag_generation',
                                       '--loglevel=info', '--hostname', 'round9@%h'], cwd=ROOT, env=env,
                                      stdout=worker_log, stderr=subprocess.STDOUT, start_new_session=True)
            wait_worker_log(Path(worker_log.name), 'ready.', worker, old_ready_count)

        launch_worker()
        poll(base, first, 'completed')
        evidence['checks']['celery_backend_first'] = await_backend(celery_app, first, 'SUCCESS')
        evidence['artifacts']['first'] = verify_task(base, output, first, True)
        evidence['checks']['valid_queue_execution'] = 'HTTP accepted; real prefork worker completed; five downloads, hashes, result and source refs verified'

        # C2: malformed and header-only inputs must never publish a success.
        for label, kwargs in [('malformed', {'network': b'{broken-json\n'}),
                              ('header_only', {'process': b'time,level,pump\n'})]:
            code, raw = upload(base, **kwargs)
            require(code == 202, f'{label} submission: {code} {raw[:300]!r}')
            identifier = json.loads(raw)['task_id']
            failed = poll(base, identifier, 'failed')
            require(json_response(base, f'/cpag/artifacts/{identifier}')['files'] == [], f'{label} published files')
            require(http(base, f'/cpag/result/{identifier}/json')[0] == 409, f'{label} result was exposed')
            require(http(base, f'/cpag/download/{identifier}/graph.json')[0] == 409, f'{label} download was exposed')
            backend = await_backend(celery_app, identifier, 'FAILURE')
            evidence['checks'][label] = {'task_id': identifier, 'status': failed['status'], 'artifact_count': 0,
                                         'backend': backend}

        # C3: duplicate completed delivery returns existing complete publication unchanged.
        before = file_hashes(output/first)
        celery_app.send_task('api.v2.synthetic.execute_synthetic', args=[first], task_id=first,
                             queue='cpag_generation', retry=False)
        wait_worker_log(Path(worker_log.name), f'Task api.v2.synthetic.execute_synthetic[{first}] succeeded', worker)
        # The first success is in the log already; wait for the second occurrence.
        deadline = time.monotonic() + WAIT
        needle = f'Task api.v2.synthetic.execute_synthetic[{first}] succeeded'
        while Path(worker_log.name).read_text(errors='replace').count(needle) < 2 and time.monotonic() < deadline:
            time.sleep(.2)
        require(Path(worker_log.name).read_text(errors='replace').count(needle) >= 2, 'duplicate was not consumed')
        require(file_hashes(output/first) == before, 'duplicate delivery changed completed publication')
        evidence['checks']['duplicate_completed'] = {'task_id': first, 'worker_success_count': 2, 'files_unchanged': True,
                                                      'backend': await_backend(celery_app, first, 'SUCCESS')}

        # C4: restart the worker, then submit and complete a fresh task.
        stop_process(worker)
        require(worker.returncode == 0, f'first worker did not shut down cleanly: {worker.returncode}')
        evidence['checks']['worker_shutdown_exit_code'] = worker.returncode
        worker = None
        launch_worker()
        code, raw = upload(base)
        require(code == 202, f'post-restart submission: {code} {raw[:300]!r}')
        restarted = json.loads(raw)['task_id']
        poll(base, restarted, 'completed')
        evidence['checks']['celery_backend_after_restart'] = await_backend(celery_app, restarted, 'SUCCESS')
        evidence['artifacts']['after_worker_restart'] = verify_task(base, output, restarted, False)
        evidence['checks']['worker_restart'] = {'task_id': restarted, 'status': 'completed'}

        # C5: broker loss has an explicit HTTP failure and never a success manifest.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            idle_queue = rabbit_queue(rabbit_management_port)
            if idle_queue.get('messages_ready', 0) == 0 and idle_queue.get('messages_unacknowledged', 0) == 0:
                break
            time.sleep(.5)
        require(idle_queue.get('messages_ready', 0) == 0 and idle_queue.get('messages_unacknowledged', 0) == 0,
                'broker has an outstanding task before planned stop')
        evidence['checks']['queue_idle_before_broker_stop'] = {
            'messages_ready': idle_queue.get('messages_ready', 0),
            'messages_unacknowledged': idle_queue.get('messages_unacknowledged', 0)}
        stop_process(worker)
        require(worker.returncode == 0, f'second worker did not shut down cleanly: {worker.returncode}')
        worker = None
        command(compose + ['stop', 'rabbitmq'])
        old_dirs = set(output.iterdir())
        code, raw = upload(base)
        require(code == 503, f'broker loss: {code} {raw[:300]!r}')
        new_dirs = set(output.iterdir()) - old_dirs
        require(len(new_dirs) == 1, f'broker loss created {len(new_dirs)} manifests')
        failed = json.loads((next(iter(new_dirs))/'result_manifest.json').read_text())
        require(failed['status'] == 'failed' and failed['files'] == [], 'broker loss falsely published success')
        evidence['checks']['broker_down'] = {'http_code': code, 'manifest_status': failed['status'], 'artifact_count': 0}

        old_rabbit_port = rabbit_port
        command(compose + ['start', 'rabbitmq'])
        # Docker reallocates ephemeral published host ports after stop/start.
        # Restart this disposable API process with the refreshed AMQP URL.
        rabbit_port = command(compose + ['port', 'rabbitmq', '5672']).rsplit(':', 1)[1]
        rabbit_management_port = command(compose + ['port', 'rabbitmq', '15672']).rsplit(':', 1)[1]
        deadline = time.monotonic() + STARTUP_WAIT
        while time.monotonic() < deadline:
            try:
                rabbit_overview(rabbit_management_port)
                break
            except (OSError, HTTPException):
                time.sleep(.5)
        else:
            raise AssertionError('RabbitMQ did not return after restart')
        stop_process(api)
        require(api.returncode == 0, f'disposable API did not shut down cleanly: {api.returncode}')
        env['RABBITMQ_URL'] = f'amqp://cpag_round9:disposable-round9-only@127.0.0.1:{rabbit_port}//'
        api = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'api.v2.app:app', '--host', '127.0.0.1', '--port', str(api_port)],
                               cwd=ROOT, env=env, stdout=api_log, stderr=subprocess.STDOUT, start_new_session=True)
        wait_http(base, api)
        evidence['checks']['broker_restore_ports'] = {'old_amqp_port': old_rabbit_port,
                                                        'new_amqp_port': rabbit_port,
                                                        'disposable_api_restarted': True}
        launch_worker()
        code, raw = upload(base)
        require(code == 202, f'broker recovery submission: {code} {raw[:300]!r}')
        recovered = json.loads(raw)['task_id']
        poll(base, recovered, 'completed')
        evidence['checks']['broker_recovered'] = {'task_id': recovered,
                                                   'backend': await_backend(celery_app, recovered, 'SUCCESS')}
        evidence['artifacts']['after_broker_recovery'] = verify_task(base, output, recovered, False)

        # C6: a corrupt completed artifact must be rejected by all read routes.
        graph = output/first/'graph.json'
        original = graph.read_bytes()
        try:
            graph.write_bytes(original + b' ')  # valid JSON, incorrect SHA and size
            codes = {path: http(base, path)[0] for path in (
                f'/cpag/artifacts/{first}', f'/cpag/result/{first}', f'/cpag/result/{first}/json',
                f'/cpag/download/{first}/graph.json')}
            require(all(code == 409 for code in codes.values()), f'tampered artifact was exposed: {codes}')
            evidence['checks']['tampered_publication'] = {'http_codes': codes, 'corruption': 'valid JSON with changed SHA/size'}
        finally:
            graph.write_bytes(original)
        require(http(base, f'/cpag/download/{first}/graph.json')[0] == 200, 'restored artifact was not downloadable')
        try:
            graph.unlink()
            missing_codes = {path: http(base, path)[0] for path in (
                f'/cpag/artifacts/{first}', f'/cpag/result/{first}', f'/cpag/result/{first}/json',
                f'/cpag/download/{first}/graph.json')}
            require(all(code == 409 for code in missing_codes.values()), f'missing artifact was exposed: {missing_codes}')
            evidence['checks']['missing_publication'] = {'http_codes': missing_codes}
        finally:
            graph.write_bytes(original)
        require(http(base, f'/cpag/download/{first}/graph.json')[0] == 200, 'restored missing artifact was not downloadable')
        evidence['checks']['restored_publication'] = True
        evidence['status'] = 'passed'
    except Exception as exc:
        evidence['status'] = 'failed'
        evidence['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        stop_process(worker)
        stop_process(api)
        api_log.close()
        worker_log.close()
        if started_infra:
            try:
                command(compose + ['down', '--volumes', '--remove-orphans'])
                evidence['cleanup'] = {'compose_down_with_volumes': True,
                                       'status': 'passed',
                                       'api_exit_code': api.returncode if api else None,
                                       'worker_exit_code': worker.returncode if worker else None}
            except Exception as cleanup_error:
                evidence['cleanup_error'] = str(cleanup_error)
                evidence['status'] = 'failed'
        evidence['source_sha256'] = {
            'network': digest((FIXTURE/'network.normalized.jsonl').read_bytes()),
            'process': digest((FIXTURE/'process.csv').read_bytes()),
            'profile': digest(PROFILE.read_bytes()),
        }
        args.evidence.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + '\n')
        workspace.cleanup()
    print(json.dumps({'status': evidence['status'], 'evidence': str(args.evidence), 'checks': list(evidence['checks'])}, ensure_ascii=False))
    require(evidence['status'] == 'passed', 'Validation or disposable infrastructure cleanup failed')


if __name__ == '__main__':
    main()
