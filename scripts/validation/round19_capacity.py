#!/usr/bin/env python3
"""Fail-closed R19 environment probe and formal PG/API/isolated Worker case recorder.

Default is reference-only. --dev-run explicitly permits a non-reference host but
never confers reference acceptance. No JSONL benchmark or R18 pacing is invoked.
Every invocation requires a new output directory; failed attempts are retained.
"""
import argparse
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import time
import traceback
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parents[2]
SCHEMA = 'r19-capacity-measurement-1'
GIB = 1024 ** 3
TARGET = {'network_files': 4, 'network_per_file_bytes': 64 * 1024 ** 2,
          'network_total_bytes': 128 * 1024 ** 2, 'process_bytes': 8 * 1024 ** 2,
          'process_records': 10000, 'process_columns': 16, 'wall_seconds': 1800,
          'evidence_seconds': 10, 'evidence_bytes': 8 * 1024 ** 2, 'evidence_items': 100,
          'active_attempts': 1, 'container_cpus': 4, 'container_memory_bytes': 8 * GIB,
          'container_swap_memory_bytes': 8 * GIB, 'container_pids': 64, 'container_cpu_seconds': 6000,
          'temporary_disk_bytes': 4 * GIB, 'persistent_handoff_bytes': 4 * GIB,
          'output_bytes': GIB, 'frames': 100000, 'operations': 10000,
          'changes': 10000, 'candidates': 100000, 'configuration_bytes': 8 * 1024 ** 2}


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 ** 2), b''):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


class Recorder:
    def __init__(self, root, dev_run=False):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, mode=0o700, exist_ok=False)
        shutil.copyfile(__file__, self.root / 'harness-source.py')
        self.record = {'schema_version': SCHEMA, 'started_at': utc(), 'status': 'running',
                       'dev_run': dev_run, 'reference_accepted': False,
                       'acceptance_scope': 'one case or probe; full R19 matrix remains required',
                       'target': TARGET, 'stages': [], 'failures': [],
                       'measurements': {'phase_breakdown': {'parse_seconds': None, 'association_seconds': None,
                           'write_seconds': None, 'cpu_seconds': None, 'rss_peak_bytes': None,
                           'reason': 'not reached or unavailable; current runtime has no complete phase/CPU/RSS instrumentation'}}}
        self.flush()

    def flush(self):
        write_json(self.root / 'record.json', self.record)

    def event(self, value):
        with (self.root / 'events.jsonl').open('a') as stream:
            stream.write(json.dumps({'at': utc(), **value}, sort_keys=True) + '\n')
            stream.flush(); os.fsync(stream.fileno())

    @contextmanager
    def stage(self, name):
        row = {'name': name, 'started_at': utc(), 'status': 'running'}
        self.record['stages'].append(row); self.event(row); self.flush()
        start = time.monotonic()
        try:
            yield row
        except BaseException as error:
            row.update(status='failed', error_type=type(error).__name__, error=str(error))
            self.record['failures'].append(dict(row))
            with (self.root / 'errors.log').open('a') as stream:
                traceback.print_exc(file=stream)
            raise
        else:
            row['status'] = 'succeeded'
        finally:
            row.update(elapsed_seconds=time.monotonic() - start, finished_at=utc())
            self.event(row); self.flush()

    def command(self, label, argv, timeout=15, check=False):
        """Only pass credential-free commands; persist raw stdout, stderr and exit."""
        start = time.monotonic()
        try:
            result = subprocess.run(argv, cwd=REPO, capture_output=True, timeout=timeout)
            code, out, err = result.returncode, result.stdout, result.stderr
        except (OSError, subprocess.TimeoutExpired) as error:
            code = None
            out = getattr(error, 'stdout', None) or b''
            err = (getattr(error, 'stderr', None) or b'') + str(error).encode()
        (self.root / (label + '.stdout')).write_bytes(out)
        (self.root / (label + '.stderr')).write_bytes(err)
        self.event({'command': argv, 'label': label, 'returncode': code,
                    'elapsed_seconds': time.monotonic() - start})
        if check and code != 0:
            raise RuntimeError(label + ' failed; raw stdout/stderr retained')
        return code, out.decode(errors='replace')


def reference_reasons(environment):
    """Missing, unverified, and mismatched facts all refuse reference qualification."""
    checks = [(environment.get('system') == 'Linux', 'host_not_linux'),
              (environment.get('os_id') == 'ubuntu' and environment.get('os_version') == '24.04', 'host_not_ubuntu_24_04'),
              (environment.get('machine') in ('x86_64', 'amd64'), 'host_not_x86_64'),
              (environment.get('cpu_count') == 8, 'host_not_8_vcpu'),
              (type(environment.get('memory_bytes')) is int and 15 * GIB <= environment['memory_bytes'] <= 17 * GIB, 'host_not_16gib_class'),
              (environment.get('ssd_verified') is True, 'ssd_unverified'),
              (type(environment.get('free_bytes')) is int and environment['free_bytes'] >= 8 * GIB, 'free_disk_below_8gib'),
              (environment.get('docker_ready') is True, 'docker_unavailable'),
              (environment.get('docker', {}).get('architecture') in ('x86_64', 'amd64'), 'docker_not_x86_64'),
              (environment.get('docker', {}).get('cpus', 0) >= 4 and environment.get('docker', {}).get('memory_bytes', 0) >= 8 * GIB, 'docker_resources_below_proposed_profile')]
    return [reason for passed, reason in checks if not passed]


def probe(recorder):
    env = {'system': platform.system(), 'machine': platform.machine(),
           'cpu_count': os.cpu_count(), 'memory_bytes': None,
           'ssd_verified': False, 'free_bytes': shutil.disk_usage(recorder.root).free,
           'docker_ready': False, 'os_id': None, 'os_version': None}
    recorder.command('uname', ['uname', '-a'])
    if env['system'] == 'Linux':
        code, raw = recorder.command('os-release', ['cat', '/etc/os-release'])
        values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line) if code == 0 else {}
        env.update(os_id=values.get('ID', '').strip('"'), os_version=values.get('VERSION_ID', '').strip('"'))
        code, raw = recorder.command('meminfo', ['cat', '/proc/meminfo'])
        for line in raw.splitlines() if code == 0 else []:
            if line.startswith('MemTotal:'): env['memory_bytes'] = int(line.split()[1]) * 1024
        # Match this output directory's actual backing device. Overlay/network/
        # virtual filesystems stay unverified; an arbitrary SSD elsewhere is insufficient.
        code, device = recorder.command('mount-source', ['findmnt', '-no', 'SOURCE', '--target', str(recorder.root)])
        if code == 0 and device.strip().startswith('/dev/'):
            code, raw = recorder.command('storage', ['lsblk', '-s', '-J', '-o', 'NAME,TYPE,ROTA', device.strip()])
            if code == 0:
                try:
                    def leaves(items):
                        for item in items:
                            if item.get('children'): yield from leaves(item['children'])
                            else: yield item
                    devices = list(leaves(json.loads(raw)['blockdevices']))
                    env['ssd_verified'] = bool(devices) and all(d.get('type') == 'disk' and d.get('rota') in (False, 0) for d in devices)
                except (ValueError, KeyError, TypeError): pass
    elif env['system'] == 'Darwin':
        code, raw = recorder.command('hw-memory', ['sysctl', '-n', 'hw.memsize'])
        if code == 0: env['memory_bytes'] = int(raw.strip())
        recorder.command('macos-version', ['sw_vers'])
    template = '{"id":{{json .ID}},"os":{{json .OperatingSystem}},"architecture":{{json .Architecture}},"cpus":{{.NCPU}},"memory_bytes":{{.MemTotal}},"driver":{{json .Driver}},"version":{{json .ServerVersion}}}'
    code, raw = recorder.command('docker-info', ['docker', 'info', '--format', template])
    if code == 0:
        try:
            env['docker'] = json.loads(raw); env['docker_ready'] = bool(env['docker'].get('id'))
        except ValueError: pass
    _, commit = recorder.command('git-commit', ['git', 'rev-parse', 'HEAD'])
    _, status = recorder.command('git-status', ['git', 'status', '--porcelain=v1'])
    _, diff = recorder.command('git-diff', ['git', 'diff', '--binary', 'HEAD'])
    code, names = recorder.command('git-source-paths', ['git', 'ls-files', '--cached', '--others', '--exclude-standard'])
    source_files = []
    if code == 0:
        for name in sorted(set(names.splitlines())):
            path = REPO / name
            if name.startswith(('services/', 'schemas/', 'internal/', 'scripts/validation/')) and path.is_file() and not path.is_symlink() and path.suffix in ('.py', '.go', '.json', '.sh', '.cjs'):
                source_files.append({'path': name, 'sha256': sha(path)})
    write_json(recorder.root / 'source-fingerprints.json', source_files)
    env.update(commit=commit.strip(), dirty=bool(status.strip()), tracked_diff_sha256=hashlib.sha256(diff.encode()).hexdigest(),
               harness_sha256=sha(__file__), source_tree_sha256=sha(recorder.root / 'source-fingerprints.json'))
    env['reference_refusal_reasons'] = reference_reasons(env)
    env['reference_environment_qualified'] = not env['reference_refusal_reasons']
    recorder.record['environment'] = env; recorder.flush()
    return env


def read_case(path):
    """Raw inputs only. No prior analysis/benchmark JSONL can stand in for PCAP/CSV."""
    path = Path(path).resolve(); case = json.loads(path.read_text())
    required = {'schema_version', 'id', 'scale', 'mode', 'networks', 'process', 'profile', 'repetition', 'cache_condition'}
    if not isinstance(case, dict) or set(case) != required or case['schema_version'] != 'r19-capacity-case-1':
        raise ValueError('invalid_capacity_case_manifest')
    if case['scale'] not in ('S', 'M', 'L') or case['mode'] not in ('dual_source', 'dual_source_replay'):
        raise ValueError('invalid_capacity_scale_or_mode')
    if type(case['repetition']) is not int or case['repetition'] not in (1, 2, 3): raise ValueError('invalid_repetition')
    if case['cache_condition'] not in ('unverified_cold', 'verified_cold', 'warm'):
        raise ValueError('explicit_cache_condition_required')
    # This harness does not clear OS caches; cold verification needs external evidence.
    if case['cache_condition'] == 'verified_cold': raise ValueError('cold_cache_evidence_not_supported_by_this_harness')
    if not isinstance(case['networks'], list) or not 1 <= len(case['networks']) <= 4:
        raise ValueError('raw_capture_inputs_required')
    for key in ('networks', 'process', 'profile'):
        values = case[key] if key == 'networks' else [case[key]]
        resolved = []
        for value in values:
            source = path.parent / value
            if source.is_symlink() or not source.is_file(): raise ValueError('regular_original_required')
            if key == 'networks' and source.suffix.lower() not in ('.pcap', '.pcapng'): raise ValueError('raw_capture_inputs_required')
            if key == 'process' and source.suffix.lower() != '.csv': raise ValueError('raw_csv_input_required')
            resolved.append(str(source.resolve()))
        case[key] = resolved if key == 'networks' else resolved[0]
    with Path(case['process']).open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.reader(stream, strict=True); header = next(reader)
        records = sum(1 for _ in reader)
    expected = {'S': 100, 'M': 1000, 'L': 10000}[case['scale']]
    if records != expected: raise ValueError('scale_requires_exact_logical_record_density')
    if not 1 <= len(header) <= TARGET['process_columns']: raise ValueError('process_column_limit')
    case['input_logical_records'] = records
    case['input_fingerprints'] = [{'path': str(p), 'bytes': Path(p).stat().st_size, 'sha256': sha(p)} for p in [*case['networks'], case['process'], case['profile']]]
    case['case_manifest_sha256'] = sha(path)
    return case


def formal_case(recorder, case, image):
    # Existing formal acceptance helpers share the real catalog/auth/preflight,
    # PG migrations, Worker service, and retained-artifact verification path.
    import round16_acceptance as r
    from round16_supplement import intake
    work = recorder.root; source = work / 'source'; source.mkdir()
    control = work / 'control'; control.mkdir()
    container = 'cpag-r19-capacity-' + secrets.token_hex(5)
    pg, public, internal = [r.port() for _ in range(3)]
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(REPO / 'services/worker'), str(REPO / 'services/analysis/src')]),
               GOCACHE=os.environ.get('GOCACHE', '/tmp/cpag-go-build'), GOMODCACHE=os.environ.get('GOMODCACHE', '/tmp/cpag-go-mod'))
    app = worker = None; database_created = False; job = None
    try:
        with recorder.stage('build_formal_binaries'):
            r.build(work, env, skip_image_build=True)
        with recorder.stage('database_start_and_migrations'):
            recorder.command('postgres-start', ['docker', 'run', '--name', container, '-d', '-e', 'POSTGRES_DB=m4_validation', '-e', 'POSTGRES_PASSWORD=m4-disposable-only', '-p', f'127.0.0.1:{pg}:5432', r.PG_IMAGE], timeout=60, check=True)
            database_created = True
            for _ in range(150):
                if subprocess.run(['docker', 'exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'm4_validation'], capture_output=True).returncode == 0: break
                time.sleep(.1)
            else: raise RuntimeError('database_readiness_timeout')
            with (work / 'migrations.log').open('wb') as log:
                for migration in sorted((REPO / 'internal/jobs/migrations').glob('*.sql')):
                    with migration.open('rb') as stream: r.bundle.pg(container, 'm4_validation', 'psql', '-v', 'ON_ERROR_STOP=1', stdin=stream, stdout=log, stderr=subprocess.STDOUT)
        with recorder.stage('application_and_worker_start'):
            password, wt, ct = secrets.token_urlsafe(24), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            config = r.make_config(pg, 'm4_validation', source, control, public, internal, wt, ct, 'r19-capacity', password, REPO / 'webui/out')
            app = r.start_app(work, 'app', work / 'cpagx-v3', config)
            client = r.Client(f'http://127.0.0.1:{public}')
            client.expect('POST', '/api/v3/session', {'username': 'r19-capacity', 'password': password})
            worker_id = container + '-worker'
            worker_cfg = work / 'worker.json'
            r.write_private(worker_cfg, {'api_url': f'http://127.0.0.1:{internal}', 'shared_root': str(source), 'control_root': str(control), 'worker_token': wt, 'coordinator_token': ct, 'worker_id': worker_id, 'image': image, 'poll_seconds': .2, 'recovery_seconds': 2})
            worker = r.start_worker(work, 'worker', worker_cfg, env)
        with recorder.stage('catalog_upload_preflight_config'):
            ds = client.expect('POST', '/api/v3/datasets', {'name': 'R19 capacity ' + str(case['id']), 'source_kind': 'synthetic', 'source': 'generated raw PCAP/CSV capacity fixture', 'batch': 'round19', 'authorization_ref': 'repository generated software fixture'}, code=201)['dataset']['id']
            for number, path in enumerate(case['networks']): r.upload(client, ds, 'network', path, f'r19-network-{number}')
            r.upload(client, ds, 'process', case['process'], 'r19-process-0')
            intake_id = client.expect('POST', f'/api/v3/datasets/{ds}/configs', {'kind': 'intake', 'document': intake(ds)}, code=201)['config']['id']
            preflight = client.expect('POST', f'/api/v3/datasets/{ds}/preflight', {'config_version_id': intake_id})['preflight_id']
            profile = json.loads(Path(case['profile']).read_text())
            if profile.get('synthetic') is not True: raise ValueError('generated_capacity_fixture_required')
            cid = client.expect('POST', f'/api/v3/datasets/{ds}/configs', {'kind': 'dual', 'document': profile}, code=201)['config']['id']
            recorder.record['bindings'] = {'dataset_id': ds, 'preflight_id': preflight, 'configuration_id': cid, 'configuration_sha256': sha(case['profile'])}
        chain_start = time.monotonic()
        with recorder.stage('submit_queue_container_to_terminal'):
            job = client.expect('POST', '/api/v3/runs', {'dataset_id': ds, 'config_version_id': cid, 'preflight_id': preflight, 'mode': case['mode']}, code=201)['run']['id']
            recorder.record['run_id'] = job; recorder.flush()
            # Poll state + raw Docker cgroup stats while the real service executes.
            # Sampling failures are retained and remain missing measurements.
            deadline = chain_start + TARGET['wall_seconds']; seen_containers = set(); sample_number = 0
            while time.monotonic() < deadline:
                status = client.expect('GET', '/api/v3/runs/' + job)['run']
                recorder.event({'run_state': status, 'elapsed_since_submit_seconds': time.monotonic() - chain_start,
                                'disk_free_bytes': {'shared': shutil.disk_usage(source).free, 'control': shutil.disk_usage(control).free}})
                if status['state'] in ('succeeded', 'failed', 'cancelled'): break
                code, raw = recorder.command(f'containers-{sample_number}', ['docker', 'ps', '-aq', '--filter', 'label=cpag.worker=' + worker_id], timeout=5)
                if code == 0:
                    for identity in raw.split():
                        if identity not in seen_containers:
                            # Config includes no session/token environment; select only resources.
                            recorder.command('resources-' + identity[:12], ['docker', 'inspect', '--format', '{{json .HostConfig}}', identity], timeout=5)
                            seen_containers.add(identity)
                        recorder.command(f'stats-{sample_number}-' + identity[:12], ['docker', 'stats', '--no-stream', '--format', '{{json .}}', identity], timeout=5)
                sample_number += 1; time.sleep(.5)
            else:
                # Ask the formal service to cancel; retain its refusal if any.
                recorder.record['cancel_after_deadline'] = client.request('POST', f'/api/v3/runs/{job}/cancel', {})
                raise RuntimeError('whole_chain_1800_second_deadline')
            recorder.record['terminal'] = status
            recorder.record['measurements']['submit_to_terminal_seconds'] = time.monotonic() - chain_start
            if status['state'] != 'succeeded': raise RuntimeError('formal_worker_terminal_' + status['state'])
        output = source / 'jobs' / job / ('attempt-' + str(status['attempt']))
        with recorder.stage('retained_artifact_and_reference_verification'):
            from cpag_core import replay_export, dual_source_export
            verifier = replay_export if case['mode'] == 'dual_source_replay' else dual_source_export
            verifier.verify_task(output)
            result = client.expect('GET', f'/api/v3/runs/{job}/result')
            analysis = json.loads((output / ('analysis.json' if case['mode'] == 'dual_source_replay' else 'dual/analysis.json')).read_text())
            # Count the requested operation density independently of input byte size.
            count = len(analysis['operations']); expected = {'S': 100, 'M': 1000, 'L': 10000}[case['scale']]
            if count != expected: raise ValueError(f'operation_density_mismatch:{count}!={expected}')
            recorder.record['output'] = {'operation_count': count, 'process_event_count': len(analysis['process']), 'bytes': sum(p.stat().st_size for p in output.rglob('*') if p.is_file()), 'files': [{'path': str(p.relative_to(output)), 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(output.rglob('*')) if p.is_file()]}
            recorder.record['measurements']['result_api_verified'] = isinstance(result, dict)
        with recorder.stage('evidence_query') as measurement:
            query_start = time.monotonic()
            answer = client.expect('GET', f'/api/v3/runs/{job}/evidence?' + urlencode({'operation': analysis['operations'][0]['operation_id']}), timeout=10)
            elapsed = time.monotonic() - query_start
            size = len(json.dumps(answer, separators=(',', ':')).encode())
            measurement.update(response_bytes=size, query_seconds=elapsed)
            if not answer.get('verified_original_evidence'): raise ValueError('verified_original_evidence_missing')
            measurement['original_evidence_items'] = len(answer['verified_original_evidence'])
            if elapsed > 10 or size > TARGET['evidence_bytes'] or len(answer['verified_original_evidence']) > TARGET['evidence_items']: raise ValueError('evidence_query_bound_exceeded')
        total = time.monotonic() - chain_start
        recorder.record['measurements']['submit_through_verify_and_evidence_seconds'] = total
        if total > TARGET['wall_seconds']: raise RuntimeError('whole_chain_1800_second_deadline')
        runtime = output / 'runtime_metrics.json'
        if runtime.is_file():
            value = json.loads(runtime.read_text())
            recorder.record['measurements']['replay_runtime_metrics'] = {'path': str(runtime), 'sha256': sha(runtime),
                'elapsed_seconds': value.get('elapsed_seconds'), 'paced': value.get('paced'),
                'arrival_samples': len(value.get('samples', [])), 'core_samples': len(value.get('core_samples', []))}
        metrics = output / 'metrics.json'
        if metrics.is_file():
            value = json.loads(metrics.read_text()); samples = value.get('backlog', {}).get('samples', [])
            recorder.record['measurements']['backlog'] = {'path': str(metrics), 'sha256': sha(metrics),
                'samples': len(samples), 'max_unparsed_records': max((row.get('unparsed_records', 0) for row in samples), default=0),
                'max_waiting_operations': max((row.get('waiting_operations', 0) for row in samples), default=0),
                'max_open_window_operations': max((row.get('open_window_operations', 0) for row in samples), default=0)}
        recorder.record['measurements']['phase_breakdown'] = {'parse_seconds': None, 'association_seconds': None, 'write_seconds': None, 'cpu_seconds': None, 'rss_peak_bytes': None, 'reason': 'current runtime does not expose separate phase/CPU/RSS totals; raw sampled Docker stats retained; cannot satisfy complete R19 measurement gate'}
    finally:
        with recorder.stage('retain_database_and_stop_disposable_services'):
            if job:
                # Preserve all attempts and raw failure receipts. Do not reset/retry.
                recorder.record['retained_attempt_root'] = str(control / 'jobs' / job)
            r.stop(worker); r.stop(app)
            if database_created:
                with (work / 'database.sql').open('wb') as stream:
                    result = subprocess.run(['docker', 'exec', container, 'pg_dump', '-U', 'postgres', 'm4_validation'], stdout=stream, stderr=subprocess.PIPE)
                (work / 'database-dump.stderr').write_bytes(result.stderr)
                recorder.record['database_dump_returncode'] = result.returncode
                # Preserve the stopped DB container if the backup failed.
                recorder.command('postgres-stop', ['docker', 'stop', container], timeout=30)
                if result.returncode == 0: recorder.command('postgres-remove', ['docker', 'rm', container], timeout=15)


def execute(output, *, dev_run=False, probe_only=False, case_manifest=None, image='cpag-isolated:r19-capacity'):
    recorder = Recorder(output, dev_run)
    try:
        with recorder.stage('environment_probe'):
            environment = probe(recorder)
        with recorder.stage('reference_environment_gate') as gate:
            gate.update(reference_environment_qualified=environment['reference_environment_qualified'],
                        explicit_dev_override=dev_run, reasons=environment['reference_refusal_reasons'])
            if not environment['reference_environment_qualified'] and not dev_run:
                raise RuntimeError('reference_environment_refused:' + ','.join(environment['reference_refusal_reasons']))
        if not probe_only:
            if case_manifest is None: raise ValueError('case_manifest_required')
            with recorder.stage('raw_case_validation'):
                case = read_case(case_manifest); recorder.record['case'] = case
            with recorder.stage('worker_image_binding'):
                recorder.command('worker-image', ['docker', 'image', 'inspect', '--format', '{{json .Id}} {{json .RepoDigests}}', image], check=True)
                recorder.record['worker_image'] = image
            with recorder.stage('formal_chain_case'):
                formal_case(recorder, case, image)
        recorder.record['status'] = 'development_probe' if probe_only and dev_run else 'reference_probe' if probe_only else 'development_case_measured_incomplete_gate' if dev_run else 'reference_case_measured_incomplete_gate'
        returncode = 0
    except BaseException as error:
        recorder.record.update(status='failed', error_type=type(error).__name__, error=str(error))
        # Includes errors outside a stage and interrupts; no failure is erased.
        if not recorder.record['failures'] or recorder.record['failures'][-1].get('error') != str(error):
            recorder.record['failures'].append({'error_type': type(error).__name__, 'error': str(error), 'at': utc()})
        returncode = 1
    finally:
        recorder.record.update(finished_at=utc(), reference_accepted=False)
        recorder.flush()
        write_json(recorder.root / 'public-summary.json', public_summary(recorder.root))
    return returncode, recorder.record


def public_summary(root):
    """Allowlisted public facts; private Worker/DB/session credentials stay local."""
    root = Path(root); record = json.loads((root / 'record.json').read_text())
    summary = {key: record.get(key) for key in ('schema_version', 'started_at', 'finished_at', 'status', 'dev_run', 'reference_accepted', 'environment', 'measurements', 'run_id', 'terminal', 'error_type', 'error', 'stages', 'target', 'database_dump_returncode')}
    if 'case' in record:
        summary['case'] = {key: record['case'].get(key) for key in ('id', 'scale', 'mode', 'repetition', 'cache_condition', 'input_logical_records', 'input_fingerprints', 'case_manifest_sha256')}
    summary['private_evidence_root'] = str(root.resolve())
    summary['private_record_sha256'] = sha(root / 'record.json')
    summary['worker_attempts'] = []
    for path in sorted((root / 'control/jobs').glob('*/attempt-*.worker/stopped-inspect.json')):
        inspection = json.loads(path.read_text()); state = inspection.get('State', {}); limits = inspection.get('HostConfig', {})
        item = {'attempt': path.parent.name, 'source_sha256': sha(path), 'image_id': inspection.get('Image'),
                'state': {key: state.get(key) for key in ('ExitCode', 'OOMKilled', 'StartedAt', 'FinishedAt', 'Status')},
                'limits': {key: limits.get(key) for key in ('Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit', 'ReadonlyRootfs', 'NetworkMode', 'Tmpfs')}}
        failure = path.with_name('failure.json')
        if failure.is_file():
            value = json.loads(failure.read_text())
            item['failure'] = {key: value.get(key) for key in ('compute_returncode', 'failure_category', 'error')}
            item['failure_sha256'] = sha(failure)
        summary['worker_attempts'].append(item)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new directory; never reused or cleaned')
    parser.add_argument('--probe-only', action='store_true')
    parser.add_argument('--dev-run', action='store_true', help='explicit local development evidence; never reference accepted')
    parser.add_argument('--case-manifest', type=Path)
    parser.add_argument('--image', default='cpag-isolated:r19-capacity')
    args = parser.parse_args()
    code, record = execute(args.output, dev_run=args.dev_run, probe_only=args.probe_only, case_manifest=args.case_manifest, image=args.image)
    print(json.dumps({'status': record['status'], 'reference_accepted': False, 'record': str(args.output.resolve() / 'record.json')}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
