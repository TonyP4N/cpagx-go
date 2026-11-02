#!/usr/bin/env python3
"""Fixed-version S100 stability: three serial offline/replay formal-service pairs.

--preflight-only freezes/builds once and runs only two tiny fixtures. A later
--group 1, 2, 3 invocation consumes that same lock in order; failed/invalid cells
cannot be retried or skipped. The default --group all performs all six long
cells, never a full S100 warmup. All private evidence and failed outputs remain.
"""
import argparse
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode

import round19_formal_service_acceptance as formal
from round19_core_oracle import canonical, check_raw_evidence
from cpag_core.pipeline import fingerprint

REPO = formal.REPO
VERSION = 's100-fixed-version-three-pairs-1'
POLICY = {
    'groups': 3, 'modes_per_group': ['offline', 'replay'], 'global_long_cell_concurrency': 1,
    'automatic_retry': False, 'cache_condition': 'OS page cache unverified; independent service/control/database per cell',
    'business_comparison': 'exact complete typed logical root descriptors within each mode across independent run IDs',
    'business_fields_removed_or_normalized': [],
    'excluded_roots': {'runtime_metrics.json': 'actual runtime telemetry only; retained in every original manifest'},
    'identity_policy': 'run/attempt identity stays in the publication envelope/context; no business root identity rewrite',
    'offline_expectation': 'frozen declaration/raw geometry: 200 network,100 process,100 operations,99 changes; candidate bounds2594..2596',
    'replay_expectation': 'explicit preregistered synthetic fixture expectation:2596 candidates,310 snapshots,306 revisions',
    'compatibility_repetition': 'ACL/download exercised once per mode in tiny preflight; not repeated in six long cells',
    'scope': 'three fixed-version synthetic development-environment repetitions only; not M/L, reference-environment or industrial acceptance',
}
BASE_ROOTS = {'analysis.json', 'dual/analysis.json', 'events.json', 'graph.json', 'quality.json', 'dataset.json',
              'indices/operations', 'indices/changes', 'indices/candidates_by_operation', 'indices/network_by_frame', 'indices/rule_findings'}
REPLAY_ROOTS = {'metrics.json', 'runtime_metrics.json', 'arrivals.json', 'replay.json', 'history/snapshots', 'history/revisions'}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def fixture_lock(root):
    root = Path(root).resolve()
    files = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'frozen_fixture_symlink')
        if path.is_file():
            files[path.relative_to(root).as_posix()] = {'sha256': formal.sha(path), 'size_bytes': path.stat().st_size}
    declaration = json.loads((root / 'fixture.json').read_text())
    preflight = json.loads((root / 'preflight.json').read_text())
    require(declaration['schema_version'] == 'r19-density-capacity-6' and declaration['scale'] == 'S' and
            declaration['storage_format'] == formal.FORMAT, 'original_frozen_S6_fixture_required')
    require([declaration[key] for key in ('operations', 'request_frames', 'response_frames', 'logical_process_records')] == [100] * 4,
            'frozen_S100_raw_density_changed')
    for name, entry in preflight['raw_inputs'].items():
        require(files[name] == entry, 'frozen_raw_input_preflight_hash_mismatch:' + name)
    configs = {}
    for mode, formal_mode in [('offline', 'dual_source'), ('replay', 'dual_source_replay')]:
        name = mode + '-profile.json'
        config = json.loads((root / name).read_text())
        registered = preflight['modes'][formal_mode]
        require(files[name]['sha256'] == registered['profile_sha256'] and
                fingerprint(config) == registered['config_fingerprint'], 'frozen_profile_registration_mismatch:' + mode)
        require(config['storage_format'] == formal.FORMAT and ('replay' in config) == (mode == 'replay'), 'frozen_mode_mismatch')
        configs[mode] = {'sha256': files[name]['sha256'], 'config_fingerprint': fingerprint(config)}
    geometry = preflight['density_math']
    require(geometry['changes'] == 99 and geometry['candidate_count_lower_bound'] == 2594 and
            geometry['candidate_count_upper_bound'] == 2596, 'registered_offline_geometry_changed')
    return {'files': files, 'declaration': declaration, 'configs': configs,
            'offline_expected': {'network': 200, 'process': 100, 'operations': 100, 'changes': 99,
                                 'candidate_lower_bound': 2594, 'candidate_upper_bound': 2596}}


def business_signature(manifest):
    """No field normalization: every descriptor covers its complete typed root."""
    mode = manifest['mode']
    require(mode in ('offline', 'replay') and manifest['storage_format'] == formal.FORMAT, 'DAG6_mode_required')
    rows = manifest['logical_artifacts']
    names = [row['name'] for row in rows]
    expected = BASE_ROOTS | (REPLAY_ROOTS if mode == 'replay' else set())
    require(len(names) == len(set(names)) and set(names) == expected, 'complete_logical_root_inventory_changed')
    for row in rows:
        require(re.fullmatch('[0-9a-f]{64}', row['digest']) is not None, 'typed_logical_digest_required')
    roots = {row['name']: deepcopy(row) for row in rows if row['name'] not in POLICY['excluded_roots']}
    # These business summary values accompany the complete root inventory;
    # context identities and physical/telemetry hashes are retained separately.
    summary = {key: deepcopy(manifest[key]) for key in ('input_fingerprint', 'config_fingerprint',
        'semantic_config_fingerprint', 'counts', 'result_hashes', 'warnings', 'limitations', 'status')}
    if mode == 'replay':
        summary.update({key: manifest[key] for key in ('final_snapshot_number', 'final_snapshot_id')})
    value = {'mode': mode, 'complete_business_roots': roots, 'business_summary': summary}
    return {'sha256': digest(value), 'value': value,
            'retained_telemetry_descriptors': [deepcopy(row) for row in rows if row['name'] in POLICY['excluded_roots']],
            'original_identity': {'run_id': manifest['run_id'], 'attempt_id': manifest['attempt_id']}}


def expected_counts(manifest, frozen):
    counts = manifest['counts']
    for key, value in frozen['offline_expected'].items():
        if key not in ('candidate_lower_bound', 'candidate_upper_bound'):
            require(counts[key] == value, 'independent_fixture_count_changed:' + key)
    if manifest['mode'] == 'offline':
        require(2594 <= counts['candidates'] <= 2596 and counts['snapshots'] == 0 and counts['revisions'] == 0,
                'offline_registered_geometry_or_history_changed')
    else:
        require((counts['candidates'], counts['snapshots'], counts['revisions']) == (2596, 310, 306),
                'preregistered_replay_counts_changed')


def source_hashes():
    paths = []
    for directory, suffix in [('internal', '.go'), ('cmd', '.go'), ('services/analysis/src/cpag_core', '.py'),
                              ('services/worker/cpag_worker', '.py'), ('schemas', '.json')]:
        paths.extend(path for path in (REPO / directory).rglob('*' + suffix) if path.is_file())
    for name in ('go.mod', 'go.sum', 'internal/jobs/integration/go.mod', 'internal/jobs/integration/go.sum',
                 'deployments/isolated-executor/Dockerfile'):
        if (REPO / name).is_file():
            paths.append(REPO / name)
    for name in ('round19_stability_acceptance.py', 'round19_formal_service_acceptance.py', 'round16_acceptance.py',
                 'round16_supplement.py', 'round19_core_small.py', 'round19_core_oracle.py', 'dual_source_fixtures.py',
                 'round17_profile.py', 'round18_profile.py'):
        paths.append(REPO / 'scripts/validation' / name)
    paths.extend(REPO / 'scripts/backup' / name for name in ('bundle.py', 'dag6.py', 'dag6_evaluation.py', 'terminal_shared.py'))
    paths.extend(path for path in (REPO / 'webui/out').rglob('*') if path.is_file())
    require(all(not path.is_symlink() for path in paths), 'frozen_source_symlink')
    return {path.relative_to(REPO).as_posix(): formal.sha(path) for path in sorted(set(paths))}


def host_hardware():
    value = {'system': platform.system(), 'machine': platform.machine(), 'logical_cpus': os.cpu_count()}
    if platform.system() == 'Darwin':
        for name in ('hw.model', 'machdep.cpu.brand_string', 'hw.physicalcpu', 'hw.logicalcpu', 'hw.memsize'):
            result = subprocess.run(['sysctl', '-n', name], capture_output=True, text=True, timeout=5)
            value[name] = result.stdout.strip() if result.returncode == 0 else None
    else:
        value['physical_memory_bytes'] = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        value['processor'] = platform.processor()
    return value


def host_observation(output):
    disk = shutil.disk_usage(output)
    return {'observed_at_epoch_seconds': time.time(), 'hardware': host_hardware(),
            'load_average_1_5_15_minutes': list(os.getloadavg()),
            'disk_total_bytes': disk.total, 'disk_used_bytes': disk.used, 'disk_free_bytes': disk.free,
            'scope': 'observed host conditions only; no hardware identifiers or serial numbers; not a resource quota'}


def version_lock(image, fixture):
    info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image], text=True, timeout=30))[0]
    image_probe = """import hashlib,json;from pathlib import Path
r=Path('/app');paths=list((r/'services/analysis/src/cpag_core').rglob('*.py'))+list((r/'schemas').glob('*.schema.json'))
v={p.relative_to(r).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths};v['services/worker/cpag_worker/container_entry.py']=hashlib.sha256((r/'entry.py').read_bytes()).hexdigest();print(json.dumps(v,sort_keys=True))"""
    actual = json.loads(subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--cpus', '1', '--memory', '256m', '--pids-limit', '32', '--entrypoint', 'python', image, '-B', '-c', image_probe],
        text=True, timeout=30))
    sources = source_hashes()
    wanted = {name: value for name, value in sources.items() if name.startswith('services/analysis/src/cpag_core/') or
              (name.startswith('schemas/') and name.endswith('.schema.json')) or name == 'services/worker/cpag_worker/container_entry.py'}
    require(actual == wanted, 'immutable_image_core_schema_entry_does_not_match_frozen_checkout')
    dependencies = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'], timeout=30)
    docker_info = json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .}}'], text=True, timeout=30))
    return {'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(),
        'source_sha256': sources, 'resolved_image_id': info['Id'], 'image_runtime_sha256': actual,
        'python_executable_sha256': formal.sha(Path(sys.executable).resolve()), 'python_version': sys.version,
        'pip_freeze_sha256': hashlib.sha256(dependencies).hexdigest(), 'pip_freeze': dependencies.decode('utf-8'),
        'go_version': subprocess.check_output(['go', 'version'], text=True).strip(),
        'go_environment': json.loads(subprocess.check_output(['go', 'env', '-json', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOFLAGS',
                                                             'GOTOOLCHAIN', 'GOEXPERIMENT', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_LDFLAGS'], text=True)),
        'fixture': fixture_lock(fixture), 'host': host_hardware(),
        'docker_host': {key: docker_info.get(key) for key in ('Architecture', 'OSType', 'NCPU', 'MemTotal', 'ServerVersion')},
        'resource_interpretation': 'container8GiB is an upper quota; actual Docker host memory is retained as observed, never increased or silently assumed'}


def power_state():
    if platform.system() != 'Darwin':
        return {'platform': platform.system(), 'status': 'not_applicable_non_Darwin', 'AC_and_lid_not_inferred': True}
    battery = subprocess.check_output(['pmset', '-g', 'batt'], text=True, timeout=5)
    smart = plistlib.loads(subprocess.check_output(['ioreg', '-r', '-c', 'AppleSmartBattery', '-a'], timeout=5))
    lid = subprocess.check_output(['ioreg', '-r', '-k', 'AppleClamshellState', '-d', '4'], text=True, timeout=5)
    states = re.findall(r'"AppleClamshellState"\s*=\s*(Yes|No)', lid)
    pack = smart[0] if isinstance(smart, list) and len(smart) == 1 and isinstance(smart[0], dict) else {}
    # Discard all other hardware properties, especially machine/battery IDs.
    observed = {'platform': 'Darwin', 'pmset_AC': 'AC Power' in battery,
                'ExternalConnected': pack.get('ExternalConnected') if type(pack.get('ExternalConnected')) is bool else None,
                'IsCharging': pack.get('IsCharging') if type(pack.get('IsCharging')) is bool else None,
                'Amperage': pack.get('Amperage') if type(pack.get('Amperage')) is int else None,
                'lid_open': bool(states) and all(value == 'No' for value in states), 'temporary_caffeinate_only': True}
    if not observed['pmset_AC'] or observed['ExternalConnected'] is not True or not observed['lid_open']:
        error = formal.InvalidEnvironment('AC_external_connection_and_open_lid_required_no_settings_changed')
        error.power_observation = observed
        raise error
    return dict(observed, status='AC_power_open_lid_observed')


@contextmanager
def awake(*, long_eligible=True):
    try:
        observation = power_state()
    except formal.InvalidEnvironment as error:
        if long_eligible:
            raise
        observation = dict(error.power_observation, status='tiny_preflight_only_power_not_long_eligible')
    process = None
    try:
        if platform.system() == 'Darwin':
            process = subprocess.Popen(['caffeinate', '-dimsu', '-w', str(os.getpid())], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        yield observation
    finally:
        if process is not None:
            formal.r.stop(process)


@contextmanager
def serial_slot(path=Path('/private/tmp/cpag-r19-stability-global.lock')):
    """Also refuse a second runner targeting a different output directory."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a+') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('another_stability_runner_already_holds_global_serial_slot') from error
        yield


class StabilityHarness(formal.Harness):
    """The existing formal setup/admission/lease/resource/clock implementation."""
    def __init__(self, args, *, build, long_cell):
        super().__init__(args)
        self.frozen_build = Path(build)
        self.long_cell = long_cell
        self.next_power_check = 0

    def setup(self):
        def reuse_build(work, env, skip_image_build=False, **kwargs):
            require(skip_image_build is True and not kwargs.get('build_ui'), 'frozen_build_only')
            for name in ('cpagx-v3', 'cpagctl'):
                shutil.copyfile(self.frozen_build / name, work / name)
                (work / name).chmod(0o700)
                require(formal.sha(work / name) == formal.sha(self.frozen_build / name), 'frozen_binary_copy_changed')
        # Setup is strictly serial and the patch ends before any submission.
        with patch.object(formal.r, 'build', reuse_build):
            super().setup()

    def guard_clock(self, run, row, start, phase, request_measurement=None):
        value = super().guard_clock(run, row, start, phase, request_measurement)
        if not getattr(self, '_clock_cleanup_active', False) and time.monotonic() >= self.next_power_check:
            self.next_power_check = time.monotonic() + 10
            try:
                row['last_power_observation'] = power_state()
            except (formal.InvalidEnvironment, OSError, subprocess.SubprocessError) as error:
                if not self.long_cell:
                    row['last_power_observation'] = {'status': 'tiny_preflight_power_not_long_eligible',
                                                     'observation': getattr(error, 'power_observation', None)}
                    return value
                row['invalid_environment_power'] = {'phase': phase, 'error_type': type(error).__name__,
                                                   'observation': getattr(error, 'power_observation', None)}
                self.report.update(status='invalid_environment', valid=False, reason='AC_or_lid_precondition_lost')
                self.flush()
                self.cancel_cleanup(run, row, 'invalid_environment_cleanup')
                raise formal.InvalidEnvironment('AC_or_lid_precondition_lost') from error
        return value

    def inspect_result(self, run, row, networks, process):
        if not self.long_cell:
            return super().inspect_result(run, row, networks, process)
        # Same authenticated selected-read/resource proof as formal.inspect_result;
        # ACL/download compatibility is explicitly checked in tiny preflight.
        started = formal.clock_start()
        first = len(self.client.timings)
        metadata, tick = self.shared(run, 'metadata')
        ticks = [tick]
        manifest = metadata['manifest']
        physical = json.loads((self.root / 'jobs' / run / 'attempt-1/run_manifest.json').read_text())
        require(canonical(physical) == canonical(manifest) and manifest['run_id'] == run and manifest['attempt_id'] == 1,
                'formal_manifest_or_attempt_binding_changed')
        identities = {}
        for collection, key in [('operations', 'operation_id'), ('changes', 'event_id'), ('candidates', None)]:
            page, tick = self.shared(run, 'page', logical_root='analysis.json', path=[collection], offset=0, limit=1)
            ticks.append(tick)
            require(page['total'] == manifest['counts'][collection], 'selected_page_total_changed')
            if key is not None:
                identities[collection], tick = self.shared(run, 'get', logical_root='analysis.json', path=[collection, 0, key])
                ticks.append(tick)
        for collection in ('nodes', 'edges'):
            _, tick = self.shared(run, 'page', logical_root='graph.json', path=[collection], offset=0, limit=1)
            ticks.append(tick)
        evidence = self.client.expect('GET', f'/api/v3/runs/{run}/evidence?' + urlencode({'operation': identities['operations']}), timeout=11)
        refs = evidence['verified_original_evidence']
        audit = check_raw_evidence(refs, [str(path) for path in networks], str(process))
        kinds = [entry['kind'] for entry in audit['checked_references']]
        require(len({json.dumps(entry['source_ref'], sort_keys=True) for entry in refs}) >= 4 and
                kinds.count('frame') >= 2 and kinds.count('csv') >= 2, 'four_original_raw_references_required')
        changed = self.client.expect('GET', f'/api/v3/runs/{run}/evidence?' + urlencode({'change': identities['changes']}), timeout=11)
        require(changed['verified_original_evidence'], 'original_change_evidence_required')
        if manifest['mode'] == 'replay':
            count = manifest['counts']['snapshots']
            history = []
            for number in sorted({0, count // 2, count - 1}):
                identity, tick = self.shared(run, 'get', logical_root='history/snapshots', path=[number, 'snapshot_id'])
                history.append({'number': number, 'snapshot_id': identity})
                ticks.append(tick)
            final, tick = self.shared(run, 'snapshot', snapshot=count - 1, path=['snapshot_id'])
            require(final == manifest['final_snapshot_id'], 'final_snapshot_identity_changed')
            ticks.append(tick)
            _, tick = self.shared(run, 'revisions', after=0, limit=1)
            ticks.append(tick)
            row['selected_history'] = history
        clock = self.guard_clock(run, row, started, 'selected_queries')
        require(all(item['wall_seconds'] <= 10 and item['response_bytes'] <= 8 * 1024**2 for item in self.client.timings[first:]),
                'selected_HTTP_query_limit_exceeded')
        row.update(selected_http_seconds=clock['wall_seconds'], selected_http_monotonic_seconds=clock['monotonic_seconds'],
            individual_selected_query_seconds=ticks, independent_raw_evidence=audit,
            queried_success_seconds=time.time() - row['submit_wall'],
            queried_success_monotonic_seconds=time.monotonic() - row['submit_monotonic'])
        require(row['queried_success_seconds'] <= 2100, 'formal_service_2100s_deadline')
        self.resource_proof(run, row, clock['wall_seconds'])
        row['compatibility_checks'] = {'status': 'not_repeated_in_long_cell', 'evidence': 'same-freeze tiny preflight per-mode ACL and streamed download'}
        self.flush()
        return metadata


def write_state(root, state):
    formal.write(root / 'suite.json', state)
    public = root / 'public'
    public.mkdir(exist_ok=True)
    formal.write(public / 'report.json', state)


def check_freeze(args, lock):
    require(version_lock(args.image, args.fixture) == lock['version'], 'fixed_version_image_dependencies_or_fixture_changed')
    for name, expected in lock['binary_sha256'].items():
        require(formal.sha(args.output / 'build' / name) == expected, 'frozen_build_binary_changed')


def cell(args, lock, directory, mode, *, small=False):
    check_freeze(args, lock)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    harness = StabilityHarness(SimpleNamespace(output=directory, image=args.image, mode='small' if small else 's100'),
                               build=args.output / 'build', long_cell=not small)
    try:
        harness.setup()
        harness.report['host_observation'] = host_observation(directory)
        require(harness.report['binary_sha256'] == lock['binary_sha256']['cpagx-v3'], 'service_did_not_use_frozen_build')
        if small:
            networks, process, profile, _ = formal.small_inputs(directory / 'fixture', 'success' if mode == 'offline' else 'normal', mode)
        else:
            networks, process, profile = [args.fixture / 'network.pcap'], args.fixture / 'process.csv', args.fixture / (mode + '-profile.json')
        body = harness.admit('stability-' + mode, networks, process, profile)
        run, row = harness.submit_wait(body, ('small-' if small else 's100-') + mode)
        metadata = harness.inspect_result(run, row, networks, process)
        signature = business_signature(metadata['manifest'])
        if not small:
            expected_counts(metadata['manifest'], lock['version']['fixture'])
        check_freeze(args, lock)
        harness.report.update(status='passed', valid=True)
        harness.flush()
        return {'status': 'passed', 'run_id': run, 'attempt': row['attempt'], 'counts': metadata['manifest']['counts'],
                'signature': signature, 'binary_sha256': harness.report['binary_sha256'],
                'core_seconds': row['core_export_verify_selected_seconds'], 'service_seconds': row['queried_success_seconds'],
                'overhead_seconds': row['service_overhead_seconds'], 'selected_query_seconds': row['selected_http_seconds'],
                'host_observation': harness.report['host_observation'],
                'evidence_report_sha256': formal.sha(directory / 'report.json')}
    except BaseException as error:
        harness.report.update(status='invalid_environment' if isinstance(error, formal.InvalidEnvironment) else 'failed',
                              valid=False, error_type=type(error).__name__, reason=str(error))
        harness.flush()
        raise
    finally:
        harness.close()


def run_groups(state, selected, execute, persist):
    """Sequential, fail-closed orchestration; no retry/resume inside any cell."""
    require(state['status'] in ('ready', 'running'), 'failed_or_completed_suite_cannot_resume')
    for number in selected:
        require(number == len(state['groups']) + 1 and 1 <= number <= 3, 'groups_must_run_once_in_order')
        group = {'number': number, 'status': 'running', 'cells': {}}
        state['groups'].append(group)
        state['status'] = 'running'
        persist()
        try:
            for mode in POLICY['modes_per_group']:
                result = execute(number, mode)
                group['cells'][mode] = result
                require(result['status'] == 'passed' and result['attempt'] == 1, 'cell_not_first_attempt_success')
                if number > 1:
                    first = state['groups'][0]['cells'][mode]['signature']
                    require(result['signature']['sha256'] == first['sha256'] and
                            result['signature']['value'] == first['value'], 'complete_business_roots_differ_across_groups:' + mode)
                persist()
            group['status'] = 'passed'
            state['status'] = 'passed' if number == 3 else 'ready'
            persist()
        except BaseException as error:
            group['status'] = state['status'] = 'invalid_environment' if isinstance(error, formal.InvalidEnvironment) else 'failed'
            group.update(error_type=type(error).__name__, reason=str(error))
            persist()
            raise
    return state


def run(args):
    args.output = args.output.resolve()
    args.fixture = args.fixture.resolve()
    require(args.output.is_relative_to(Path('/private/tmp')), 'fresh_private_tmp_suite_required')
    with serial_slot(), awake(long_eligible=not args.preflight_only) as power:
        if not args.output.exists():
            args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
            state = {'version': VERSION, 'status': 'preparing', 'policy': POLICY, 'groups': [], 'power_precondition': power,
                     'scope': POLICY['scope'], 'preflight': {}}
            write_state(args.output, state)
            version = version_lock(args.image, args.fixture)
            build = args.output / 'build'
            build.mkdir(mode=0o700)
            env = formal.Harness(SimpleNamespace(output=build, image=args.image, mode='small')).env
            formal.r.build(build, env, skip_image_build=True)
            require(version_lock(args.image, args.fixture) == version, 'freeze_changed_during_single_build')
            lock = {'version': version, 'binary_sha256': {name: formal.sha(build / name) for name in ('cpagx-v3', 'cpagctl')},
                    'binary_metadata': {name: subprocess.check_output(['go', 'version', '-m', str(build / name)], text=True)
                                        for name in ('cpagx-v3', 'cpagctl')},
                    'policy_sha256': digest(POLICY)}
            formal.write(args.output / 'freeze.json', lock)
            state['freeze_sha256'] = formal.sha(args.output / 'freeze.json')
            try:
                for mode in POLICY['modes_per_group']:
                    state['preflight'][mode] = cell(args, lock, args.output / 'tiny-preflight' / mode, mode, small=True)
                state['status'] = 'ready'
            except BaseException as error:
                state.update(status='invalid_environment' if isinstance(error, formal.InvalidEnvironment) else 'failed', error_type=type(error).__name__, reason=str(error))
                write_state(args.output, state)
                raise
            write_state(args.output, state)
        else:
            state = json.loads((args.output / 'suite.json').read_text())
            lock = json.loads((args.output / 'freeze.json').read_text())
            require(state['freeze_sha256'] == formal.sha(args.output / 'freeze.json') and lock['policy_sha256'] == digest(POLICY), 'suite_freeze_or_policy_changed')
            check_freeze(args, lock)
        if args.preflight_only:
            require(state['status'] == 'ready' and not state['groups'], 'preflight_only_requires_unstarted_groups')
            return state
        selected = range(1, 4) if args.group == 'all' else [int(args.group)]
        return run_groups(state, selected,
            lambda number, mode: cell(args, lock, args.output / f'group-{number}' / mode, mode),
            lambda: write_state(args.output, state))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--fixture', type=Path, default=formal.FROZEN)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--group', choices=('all', '1', '2', '3'), default='all')
    parser.add_argument('--preflight-only', action='store_true')
    args = parser.parse_args()
    if re.fullmatch(r'(?:sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})', args.image) is None:
        parser.error('immutable Docker image ID/digest required')
    value = run(args)
    print(json.dumps({'status': value['status'], 'groups': len(value['groups']), 'report': str(args.output / 'public/report.json')}))


if __name__ == '__main__':
    main()
