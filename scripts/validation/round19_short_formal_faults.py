#!/usr/bin/env python3
"""Two bounded actual DAG6 fault gaps over the ordinary formal service harness.

No task database writes, capacity run, backup/restore, runtime hooks or retries.
Only this harness's fresh jobs, Workers and labelled containers are disturbed.
"""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
import traceback

import round19_formal_service_acceptance as formal

VERSION = 'dag6-short-formal-faults-1'


def lifecycle(events, expected_ids):
    """Require complete actual intervals; paused containers retain their slot."""
    intervals = {}
    for event in events:
        action = event.get('Action', event.get('status'))
        if action not in ('start', 'die'):
            continue
        actor = event.get('Actor', {}); identifier = actor.get('ID')
        labels = actor.get('Attributes', {}); stamp = event.get('timeNano')
        if not identifier or type(stamp) is not int or stamp <= 0:
            raise ValueError('invalid_actual_lifecycle_event')
        item = intervals.setdefault(identifier, {'container_id': identifier,
            'job': labels.get('cpag.job'), 'attempt': labels.get('cpag.attempt'),
            'worker': labels.get('cpag.worker'),
            'role': 'verifier' if labels.get('cpag.role') == 'dag6-source-verifier' else 'compute'})
        if action in item:
            raise ValueError('duplicate_actual_lifecycle_event')
        item[action] = stamp
    if set(intervals) != set(expected_ids) or not intervals:
        raise ValueError('actual_lifecycle_inventory_incomplete')
    ordered = sorted(intervals.values(), key=lambda row: row.get('start', 0))
    previous_end = 0
    for item in ordered:
        if (not item['job'] or not item['attempt'] or not {'start', 'die'} <= set(item)
                or item['die'] <= item['start']):
            raise ValueError('actual_lifecycle_interval_incomplete')
        if item['start'] < previous_end:
            raise ValueError('global_compute_or_verifier_overlap')
        previous_end = max(previous_end, item['die'])
    workers = {row['worker'] for row in ordered if row['role'] == 'compute'}
    if workers != {'short-A', 'short-B'} or not any(row['role'] == 'verifier' for row in ordered):
        raise ValueError('two_real_dag6_workers_and_verifier_not_observed')
    return ordered


def audit_saved(root):
    """Read-only independent aggregation of already retained actual evidence.

    This permits fixing an observer's short/full ID comparison without another
    execution and without rewriting the original failed aggregate report.
    """
    root = Path(root); used = {}
    def read(path):
        used[path.relative_to(root).as_posix()] = formal.sha(path)
        return json.loads(path.read_text())
    report = read(root/'report.json')
    checks = report['public_checks']
    if set(checks) != {'compute_interruption', 'verifier_cancellation', 'post_fault_control'}:
        raise ValueError('saved_fault_checks_incomplete')
    by_label = {row['label']: row for row in report['runs']}
    wanted = {'compute-interruption': ('cancelled', 1), 'compute-competitor-cancelled': ('cancelled', 0),
        'verifier-cancellation': ('cancelled', 1), 'verifier-competitor-cancelled': ('cancelled', 0),
        'post-fault-control': ('succeeded', 1)}
    if set(by_label) != set(wanted):
        raise ValueError('saved_run_inventory_changed')
    exits = []; resources = []; verifier_proofs = []
    image = report['resolved_image_id']
    def resources_ok(host):
        if (host.get('Memory') != 8*1024**3 or host.get('MemorySwap') != 8*1024**3
                or host.get('NanoCpus') != 4*10**9 or host.get('ReadonlyRootfs') is not True
                or host.get('NetworkMode') != 'none'):
            raise ValueError('saved_actual_resource_budget_mismatch')
    for label, (state, attempt) in wanted.items():
        row = by_label[label]
        history = row['attempt_history']
        if row['state'] != state or row['attempt'] != attempt or len(history) != attempt:
            raise ValueError('saved_retry_or_terminal_mismatch')
        if attempt == 0:
            continue
        if not history[0]['exited_at'] or ((history[0]['publication_state'] == 'published') != (state == 'succeeded')):
            raise ValueError('saved_publication_or_exit_mismatch')
        base = root/'control/jobs'/row['id']/'attempt-1.worker'
        execution = read(base/'execution.json'); proof = read(base/'exit.json')
        if (any(proof.get(name) != execution.get(name) for name in ('id','attempt','worker','token','location','container_id'))
                or proof.get('scope') != 'container' or proof.get('exited') is not True
                or proof.get('removed') is not True or proof.get('running') is not False
                or type(proof.get('pid')) is not int or proof['pid'] != 0
                or proof.get('inspected_id') != execution['container_id']
                or any(proof.get('labels', {}).get(name) != value for name, value in (
                    ('cpag.job',row['id']), ('cpag.attempt','1'), ('cpag.worker',execution['worker'])))):
            raise ValueError('saved_bound_compute_exit_invalid')
        exits.append({'run': row['id'], 'state': state, 'attempt': 1, 'exited': True,
                      'removed': True, 'running': False, 'worker': execution['worker']})
        inspection_path = base/'compute-inspect.json'
        if not inspection_path.exists():
            matches = list(root.glob('*-killed-compute-inspect.stdout'))
            if len(matches) != 1: raise ValueError('saved_killed_compute_inspection_missing')
            inspection_path = matches[0]
        inspection = read(inspection_path)
        if isinstance(inspection, list): inspection = inspection[0]
        resources_ok(inspection['HostConfig'])
        if inspection['Id'] != execution['container_id'] or inspection['Image'] != image:
            raise ValueError('saved_actual_compute_image_identity_mismatch')
        resources.append({'run':row['id'], 'role':'compute', 'image':image,
                          'cpus':4, 'memory_bytes':8*1024**3, 'readonly_root':True, 'network':'none'})
    for name in ('compute_interruption', 'verifier_cancellation'):
        check = checks[name]
        if check['attempt'] != 1 or check['terminal_state'] != 'cancelled' or check['trusted_query_status'] != 409 or check['stale_complete_status'] != 409:
            raise ValueError('saved_fault_trust_or_retry_mismatch')
        samples = check['competition_samples']
        if len(samples) != 3 or any(s['state'] != 'queued' or s['attempt'] != 0 or set(s['workers']) != {'A','B'}
            or any(w['alive'] is not True or type(w['pid']) is not int or w['pid'] <= 0 for w in s['workers'].values()) for s in samples):
            raise ValueError('saved_two_live_worker_competition_missing')
    if checks['compute_interruption']['docker_exit_code'] != 137:
        raise ValueError('saved_compute_kill_missing')
    for path in sorted((root/'control').glob('compact-verification-*.json')):
        receipt = read(path); resources_ok(receipt['docker_inspection']['HostConfig'])
        if receipt.get('cleanup_completed') is not True or receipt.get('image') != image:
            raise ValueError('saved_verifier_cleanup_or_image_missing')
        if receipt['run_id'] == by_label['verifier-cancellation']['id']:
            if receipt.get('watcher_cancellation', {}).get('reason') != 'state_changed':
                raise ValueError('saved_actual_verifier_cancellation_missing')
        elif receipt['run_id'] == by_label['post-fault-control']['id']:
            if receipt.get('verification_report', {}).get('status') != 'passed':
                raise ValueError('saved_control_source_verification_missing')
        else:
            raise ValueError('unexpected_saved_verifier')
        verifier_proofs.append({'run':receipt['run_id'], 'cleanup_completed':True,
            'watcher_reason':receipt.get('watcher_cancellation', {}).get('reason'),
            'source_verification_status':receipt.get('verification_report', {}).get('status')})
        resources.append({'run':receipt['run_id'], 'role':'verifier', 'image':image,
                          'cpus':4, 'memory_bytes':8*1024**3, 'readonly_root':True, 'network':'none'})
    if len(verifier_proofs) != 2:
        raise ValueError('saved_verifier_inventory_incomplete')
    inventories = list(root.glob('*-all-actual-container-identities.stdout'))
    if len(inventories) != 1:
        raise ValueError('saved_database_container_inventory_missing')
    expected = read(inventories[0])
    if any(not isinstance(value,str) or re.fullmatch('[a-f0-9]{64}',value) is None for value in expected):
        raise ValueError('saved_full_container_identity_required')
    events_path = root/'owned-docker-events.jsonl'; used[events_path.name] = formal.sha(events_path)
    events = [json.loads(line) for line in events_path.read_text().splitlines() if line.strip()]
    intervals = lifecycle(events, expected)
    return {'version':VERSION, 'status':'passed_saved_evidence_reaudit', 'valid':True,
        'scope':report['scope'], 'git_head':report['git_head'], 'image':image,
        'original_aggregate_status':report['status'], 'original_aggregate_reason':report.get('reason'),
        'correction':'observer container IDs normalized to inspected full ID; runtime, image, inputs, and recorded events unchanged; no third run',
        'public_checks':checks, 'actual_intervals':intervals, 'global_max_active_compute_or_verifier':1,
        'actual_worker_ids':sorted({row['worker'] for row in intervals if row['role']=='compute'}),
        'bound_compute_exits':exits, 'verifier_exit_proofs':verifier_proofs,
        'actual_resource_proofs':resources, 'input_evidence_sha256':used,
        'remaining_boundaries':['No new actual natural-lease-expiry or failed-source-verification scenario was executed; existing separately scoped evidence remains distinct.',
            'The interrupted compute was observed executing before publication; interruption during SQLite writing is not claimed.',
            'No stability, full fault matrix, reference-environment or industrial-data acceptance.']}


class Harness(formal.Harness):
    def __init__(self, args):
        self.workers = {}; self.worker_configs = {}; self.paused_workers = set()
        self.paused_containers = set(); self.command_number = 0; self.event_process = None
        self.known_jobs = set(); self.events = []; self.expected_containers = set()
        super().__init__(args)
        self.report.update(scenario=VERSION, scope='two small actual DAG6 fault gaps; no stability/capacity/reference/industrial acceptance',
            preregistration={'compute': 'hold an actual exporter, record observed phase, Docker-kill before publication, cancel through API without retry; require bound exits and no trusted output',
                'verifier': 'hold actual source verifier while two live Workers compete; queued job stays attempt0; API cancel removes verifier and rejects stale completion',
                'global_gate': 'every owned actual compute/verifier start/die interval complete and nonoverlapping; both distinct Workers must execute',
                'control': 'one ordinary tiny offline task succeeds once after faults',
                'restrictions': 'no manual DB writes, no rerun to replace failure, no S100, no full fault matrix; missed interception fails explicitly'},
            checks={}, public_checks={})
        self.deadline = time.monotonic() + args.seconds

    def flush(self):
        super().flush()
        public = self.work/'public'; public.mkdir(exist_ok=True)
        safe = {key: self.report[key] for key in ('scenario', 'status', 'valid', 'scope',
            'git_head', 'binary_sha256', 'resolved_image_id', 'preregistration', 'public_checks',
            'error_type', 'reason', 'actual_intervals', 'worker_exit_codes') if key in self.report}
        formal.write(public/'report.json', safe)

    def command(self, label, args, *, check=True, timeout=15):
        self.command_number += 1; prefix = self.work/f'{self.command_number:04d}-{label}'
        result = subprocess.run(args, capture_output=True, timeout=timeout)
        prefix.with_suffix('.stdout').write_bytes(result.stdout)
        prefix.with_suffix('.stderr').write_bytes(result.stderr)
        if check and result.returncode:
            raise RuntimeError(label + '_failed_' + str(result.returncode))
        return result

    def start_worker(self):
        key = 'A'
        if key not in self.worker_configs:
            config = json.loads(self.worker_config.read_text()); config['worker_id'] = 'short-A'
            path = self.work/'worker-A.json'; formal.r.write_private(path, config)
            self.worker_configs[key] = path
        self.worker = formal.r.start_worker(self.work, 'worker-A', self.worker_configs[key], self.env)
        self.workers[key] = self.worker

    def launch_b(self):
        config = json.loads(self.worker_config.read_text()); config['worker_id'] = 'short-B'
        path = self.work/'worker-B.json'; formal.r.write_private(path, config); self.worker_configs['B'] = path
        self.workers['B'] = formal.r.start_worker(self.work, 'worker-B', path, self.env)

    def setup(self):
        super().setup()
        self.report['harness_sha256'] = formal.sha(Path(__file__))
        self.event_log = (self.work/'owned-docker-events.jsonl').open('w')
        self.event_process = subprocess.Popen(['docker', 'events', '--filter', 'type=container',
            '--filter', 'event=start', '--filter', 'event=die', '--format', '{{json .}}'],
            stdout=subprocess.PIPE, stderr=(self.work/'events.stderr').open('w'), text=True)
        def consume():
            for line in self.event_process.stdout:
                event = json.loads(line)
                if event.get('Actor', {}).get('Attributes', {}).get('cpag.job') in self.known_jobs:
                    self.events.append(event); self.event_log.write(line); self.event_log.flush()
        self.event_thread = threading.Thread(target=consume, daemon=True); self.event_thread.start()
        time.sleep(.2)
        self.launch_b()
        self.flush()

    def submit(self, body, label):
        start = formal.clock_start()
        run = self.client.expect('POST', '/api/v3/runs', body, code=201)['run']['id']
        self.known_jobs.add(run)
        self.report['runs'].append({'id': run, 'label': label, 'submit_wall': start['wall'],
                                    'submit_monotonic': start['monotonic']})
        self.state['run_ids'].append(run); self.flush()
        return run

    def status(self, run):
        if time.monotonic() >= self.deadline:
            raise TimeoutError('short_fault_harness_deadline')
        status = self.client.expect('GET', f'/api/v3/runs/{run}', timeout=5)['run']
        if status['attempt'] > 1:
            self.client.expect('POST', f'/api/v3/runs/{run}/cancel', {}, timeout=5)
            raise RuntimeError('unexpected_retry_is_failure_not_replacement_measurement')
        return status

    def containers(self, run, role):
        label = 'cpag.role=dag6-source-verifier' if role == 'verifier' else 'cpag.managed=isolated-v1'
        raw = self.command('list-'+role, ['docker', 'ps', '-q', '--filter', 'label=cpag.job='+run,
            '--filter', 'label='+label]).stdout.decode().split()
        return raw

    def hold(self, run, role):
        deadline = min(self.deadline, time.monotonic()+30)
        while time.monotonic() < deadline:
            for identifier in self.containers(run, role):
                # Docker top can block on a paused container. Observe the live
                # process first, then pause; missing the phase is a failed case.
                top = self.command('live-top-'+role, ['docker', 'top', identifier, '-eo', 'pid,ppid,args']).stdout.decode()
                matching = [line for line in top.splitlines() if ('cpag_core.shared_service' if role == 'verifier' else 'cpag_core.shared_cli') in line and 'container_entry' not in line]
                if not matching:
                    time.sleep(.02); continue
                result = self.command('hold-'+role, ['docker', 'pause', identifier], check=False)
                if result.returncode:
                    continue
                self.paused_containers.add(identifier)
                inspection = json.loads(self.command('inspect-'+role, ['docker', 'inspect', identifier]).stdout)[0]
                self.paused_containers.remove(identifier)
                identifier = inspection['Id']
                self.paused_containers.add(identifier)
                host = inspection['HostConfig']
                if (inspection['Image'] != self.args.image or host['Memory'] != 8*1024**3
                        or host['NanoCpus'] != 4*10**9 or not host['ReadonlyRootfs']):
                    raise RuntimeError('actual_resource_or_image_changed')
                self.expected_containers.add(identifier)
                return identifier, inspection
            if self.status(run)['state'] in ('succeeded', 'failed', 'cancelled'):
                raise RuntimeError('actual_'+role+'_interception_missed')
            time.sleep(.02)
        raise TimeoutError('actual_'+role+'_interception_timeout')

    def compete(self, queued):
        samples = []
        for _ in range(3):
            status = self.status(queued)
            if status['state'] != 'queued' or status['attempt'] != 0:
                raise RuntimeError('global_gate_allowed_competing_attempt')
            if self.paused_workers or any(worker.poll() is not None for worker in self.workers.values()):
                raise RuntimeError('two_live_unpaused_workers_not_present')
            samples.append({'state': status['state'], 'attempt': status['attempt'],
                'workers': {key: {'pid': worker.pid, 'alive': worker.poll() is None} for key, worker in self.workers.items()}})
            time.sleep(.15)
        return samples

    def cancel(self, run):
        self.client.expect('POST', f'/api/v3/runs/{run}/cancel', {}, timeout=5)

    def terminal(self, run, expected):
        while time.monotonic() < self.deadline:
            state = self.status(run)
            if state['state'] in ('succeeded', 'failed', 'cancelled'):
                if state['state'] != expected:
                    raise RuntimeError('unexpected_terminal_'+state['state'])
                history = state['attempt_history']
                if any(not row.get('exited_at') for row in history):
                    raise RuntimeError('terminal_without_actual_exit')
                if expected != 'succeeded' and any(row['publication_state'] == 'published' for row in history):
                    raise RuntimeError('interrupted_attempt_published')
                self.run_row(run).update(state=state['state'], attempt=state['attempt'], attempt_history=history)
                self.flush(); return state
            time.sleep(.1)
        raise TimeoutError('short_fault_terminal_timeout')

    def denied(self, run):
        status, _ = self.client.request('GET', f'/api/v3/runs/{run}/shared-query?action=metadata', timeout=5)
        if status == 200:
            raise RuntimeError('interrupted_run_trusted_read_available')
        return status

    def stale_complete(self, run):
        from cpag_worker.worker import APIError
        base = self.control/'jobs'/run/'attempt-1.worker'
        identity = json.loads((base/'execution.json').read_text())
        handoff = json.loads((base/'handoff.json').read_text()) if (base/'handoff.json').exists() else {'manifest_sha256': '0'*64}
        try:
            self.internal.post('/v1/jobs/'+run+'/complete', {
                'attempt': identity['attempt'], 'worker': identity['worker'], 'token': identity['token'],
                'manifest_sha256': handoff['manifest_sha256']})
        except APIError as error:
            if error.status != 409:
                raise RuntimeError('stale_complete_unexpected_status')
            return error.status
        raise RuntimeError('stale_complete_accepted')

    def run_faults(self):
        self.setup()
        networks, process, profile, _ = formal.small_inputs(self.work/'fixture', 'normal', 'replay')
        body = self.admit('short-fault', networks, process, profile)
        os.kill(self.workers['B'].pid, signal.SIGSTOP); self.paused_workers.add('B')
        compute = self.submit(body, 'compute-interruption')
        identifier, inspection = self.hold(compute, 'compute')
        if inspection['Config']['Labels'].get('cpag.worker') != 'short-A':
            raise RuntimeError('first_real_worker_not_A')
        os.kill(self.workers['B'].pid, signal.SIGCONT); self.paused_workers.remove('B')
        queued = self.submit(body, 'compute-competitor-cancelled')
        competition = self.compete(queued)
        # Pausing host Workers avoids an uncontrolled retry between kill and the
        # formal cancellation request; the task database is never edited here.
        for key, worker in self.workers.items():
            os.kill(worker.pid, signal.SIGSTOP); self.paused_workers.add(key)
        self.command('resume-before-kill', ['docker', 'unpause', identifier]); self.paused_containers.remove(identifier)
        self.command('interrupt-actual-compute', ['docker', 'kill', '--signal', 'KILL', identifier])
        stopped = json.loads(self.command('killed-compute-inspect', ['docker', 'inspect', identifier]).stdout)[0]
        self.command('killed-compute-logs', ['docker', 'logs', identifier], check=False)
        if stopped['State']['Running'] or stopped['State']['ExitCode'] != 137:
            raise RuntimeError('actual_compute_kill_not_observed')
        self.cancel(compute); self.cancel(queued)
        for key in list(self.paused_workers):
            os.kill(self.workers[key].pid, signal.SIGCONT); self.paused_workers.remove(key)
        self.terminal(compute, 'cancelled'); self.terminal(queued, 'cancelled')
        self.report['public_checks']['compute_interruption'] = {'run': compute,
            'observed_phase': 'actual exporter process executing before publication; write phase not asserted',
            'docker_exit_code': 137, 'terminal_state': 'cancelled', 'attempt': 1,
            'trusted_query_status': self.denied(compute), 'stale_complete_status': self.stale_complete(compute),
            'competition_samples': competition, 'retry_restriction': 'no retry; API cancellation before resuming host Workers'}
        self.flush()
        formal.r.stop(self.workers['A']); self.worker = None
        verify = self.submit(body, 'verifier-cancellation')
        identifier, _ = self.hold(verify, 'verifier')
        self.start_worker()
        queued = self.submit(body, 'verifier-competitor-cancelled')
        competition = self.compete(queued)
        self.cancel(verify); self.cancel(queued)
        self.terminal(verify, 'cancelled'); self.terminal(queued, 'cancelled')
        self.paused_containers.discard(identifier)
        result = self.command('verifier-after-cancel-inspect', ['docker', 'inspect', identifier], check=False)
        if result.returncode == 0:
            raise RuntimeError('cancelled_verifier_not_removed')
        receipts = list(self.control.glob('compact-verification-'+verify+'-1-*.json'))
        if len(receipts) != 1:
            raise RuntimeError('cancelled_verifier_receipt_missing')
        receipt = json.loads(receipts[0].read_text())
        if receipt.get('cleanup_completed') is not True or receipt.get('watcher_cancellation', {}).get('reason') != 'state_changed':
            raise RuntimeError('verifier_cancellation_cleanup_not_proven')
        self.report['public_checks']['verifier_cancellation'] = {'run': verify,
            'terminal_state': 'cancelled', 'attempt': 1, 'actual_container_removed': True,
            'watcher_reason': 'state_changed', 'cleanup_completed': True,
            'trusted_query_status': self.denied(verify), 'stale_complete_status': self.stale_complete(verify),
            'competition_samples': competition}
        self.flush()
        # One new ordinary tiny success is a control, never a retry of a fault.
        control = self.submit(body, 'post-fault-control')
        state = self.terminal(control, 'succeeded')
        metadata = self.client.expect('GET', f'/api/v3/runs/{control}/shared-query?action=metadata', timeout=11)
        if metadata['manifest']['storage_format'] != formal.FORMAT or state['attempt'] != 1:
            raise RuntimeError('post_fault_control_binding_mismatch')
        self.report['public_checks']['post_fault_control'] = {'run': control, 'state': 'succeeded', 'attempt': 1}
        time.sleep(.25)
        # Every owned start/die event, including containers not paused above,
        # participates in the global actual computation/verifier interval audit.
        query = "SELECT coalesce(json_agg(id),'[]'::json)::text FROM (SELECT container_id AS id FROM m4_job_attempts WHERE container_id<>'' UNION SELECT container_name AS id FROM m4_compact_verifications) owned;"
        expected = self.command('all-actual-container-identities', ['docker', 'exec', self.pg,
            'psql', '-U', 'postgres', '-d', 'm4_validation', '-Atc', query]).stdout
        self.expected_containers.update(json.loads(expected))
        self.report['actual_intervals'] = lifecycle(self.events, self.expected_containers)
        self.report.update(status='passed', valid=True); self.flush()

    def close(self):
        for key in list(self.paused_workers):
            try: os.kill(self.workers[key].pid, signal.SIGCONT)
            except ProcessLookupError: pass
        for identifier in list(self.paused_containers):
            self.command('cleanup-unpause', ['docker', 'unpause', identifier], check=False)
        for worker in self.workers.values():
            formal.r.stop(worker)
        formal.r.stop(self.app); self.app = None; self.worker = None
        # Recovery normally removes all owned containers. Failure cleanup only
        # touches exact owned job labels and preserves raw command evidence.
        for run in self.known_jobs:
            result = self.command('cleanup-owned-list', ['docker', 'ps', '-aq', '--filter', 'label=cpag.job='+run], check=False)
            ids = result.stdout.decode().split()
            if ids: self.command('cleanup-owned-containers', ['docker', 'rm', '-f', *ids], check=False)
        if self.event_process:
            self.event_process.terminate(); self.event_process.wait(timeout=5)
            self.event_thread.join(timeout=5); self.event_log.close()
        self.report['worker_exit_codes'] = {key: worker.returncode for key, worker in self.workers.items()}
        super().close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--seconds', type=int, default=240)
    args = parser.parse_args()
    if re.fullmatch(r'sha256:[a-f0-9]{64}', args.image) is None:
        parser.error('immutable local Docker image ID required')
    args.output = args.output.resolve()
    if not args.output.is_relative_to(Path('/private/tmp')) or not 30 <= args.seconds <= 300:
        parser.error('fresh private/tmp output and 30..300 second short budget required')
    args.mode = 'small'; args.serve = False; args.legacy_evidence = None
    args.output.mkdir(mode=0o700, exist_ok=False)
    harness = Harness(args); harness.flush()
    try:
        harness.run_faults()
    except BaseException as error:
        harness.report.update(status='failed', valid=False, error_type=type(error).__name__, reason=str(error))
        (args.output/'failure.log').write_text(traceback.format_exc()); harness.flush()
    finally:
        try: harness.close()
        except BaseException as error:
            harness.report.update(status='failed', valid=False, cleanup_error_type=type(error).__name__)
            (args.output/'cleanup-failure.log').write_text(traceback.format_exc()); harness.flush()
    print(json.dumps({'status': harness.report['status'], 'public_report': str(args.output/'public/report.json')}))
    return 0 if harness.report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
