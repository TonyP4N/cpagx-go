#!/usr/bin/env python3
"""Bounded real DAG6 terminal PG/files/control backup and fresh restore drill.

This deliberately reuses the formal Go/PostgreSQL/isolated Worker harness. It
creates only small synthetic tasks through the public API. Full responses,
credentials, dumps and logs stay in the private output; public/report.json is an
explicit allowlist. --serve retains the restored ordinary UI for browser review.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
from urllib.parse import urlencode, urlsplit

import round19_formal_service_acceptance as formal
from round19_core_oracle import check_raw_evidence
from round19_shared_backup_mutants import rejection_checks
from round19_shared_evaluation_check import check_saved_evaluation

r = formal.r
REPO = formal.REPO


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


class Harness(formal.Harness):
    def __init__(self, args):
        super().__init__(args)
        self.report['scenario'] = 'terminal-dag6-format7-backup-fresh-restore-1'
        self.report['scope'] = ('small synthetic software recovery only; no stability, '
                                'M/L capacity, reference-environment or industrial acceptance')
        self.fixtures = {}

    def flush(self):
        super().flush()
        public = self.work / 'public'
        public.mkdir(exist_ok=True)
        # Never recursively copy private reports: queries/evidence/configs can
        # contain source locations, credentials and retained original bytes.
        safe = {key: self.report[key] for key in
                ('scenario', 'status', 'valid', 'scope', 'git_head', 'binary_sha256',
                 'resolved_image_id', 'source_files', 'measurements')
                if key in self.report}
        safe['checks'] = deepcopy(self.report.get('public_checks', {}))
        safe['runs'] = [{key: row[key] for key in ('id', 'label', 'state', 'attempt')
                        if key in row} for row in self.report['runs']]
        formal.write(public / 'report.json', safe)

    def setup(self):
        super().setup()
        for relative in ('scripts/backup/bundle.py', 'scripts/backup/dag6.py',
                         'scripts/backup/dag6_evaluation.py', 'scripts/backup/terminal_shared.py',
                         'scripts/validation/round19_shared_backup_acceptance.py',
                         'scripts/validation/round19_shared_backup_mutants.py'):
            self.report['source_files'][relative] = formal.sha(REPO / relative)
        self.flush()

    def query(self, run, action, **values):
        query = {'action': action, **values}
        if 'path' in query:
            query['path'] = json.dumps(query['path'], separators=(',', ':'))
        return self.client.expect('GET', f'/api/v3/runs/{run}/shared-query?' +
                                  urlencode(query), timeout=11)

    def collect(self, run, stage):
        """Read actual authenticated projections; retain complete before/after."""
        prefix = f'/api/v3/runs/{run}'
        result = {'run': self.client.expect('GET', prefix)['run']}
        metadata = result['metadata'] = self.query(run, 'metadata')
        manifest = metadata['manifest']
        require(manifest['run_id'] == run and manifest['storage_format'] == formal.FORMAT,
                'restored_run_manifest_identity_changed')
        result['logical_roots'] = manifest['logical_artifacts']
        result['operation_page'] = self.query(run, 'page', logical_root='analysis.json',
                                              path=['operations'], offset=0, limit=1)
        result['change_page'] = self.query(run, 'page', logical_root='analysis.json',
                                           path=['changes'], offset=0, limit=1)
        result['graph_nodes_page'] = self.query(run, 'page', logical_root='graph.json',
                                                path=['nodes'], offset=0, limit=2)
        result['graph_edges_page'] = self.query(run, 'page', logical_root='graph.json',
                                                path=['edges'], offset=0, limit=2)
        operation = self.query(run, 'get', logical_root='analysis.json',
                               path=['operations', 0, 'operation_id'])
        change = self.query(run, 'get', logical_root='analysis.json',
                            path=['changes', 0, 'event_id'])
        result['operation_evidence'] = self.client.expect('GET', prefix + '/evidence?' +
                                                         urlencode({'operation': operation}), timeout=11)
        result['change_evidence'] = self.client.expect('GET', prefix + '/evidence?' +
                                                      urlencode({'change': change}), timeout=11)
        networks, process = self.fixtures[run]
        refs = result['operation_evidence']['verified_original_evidence']
        audit = check_raw_evidence(refs, [str(path) for path in networks], str(process))
        kinds = [item['kind'] for item in audit['checked_references']]
        require(len({json.dumps(item['source_ref'], sort_keys=True) for item in refs}) >= 4
                and kinds.count('frame') >= 2 and kinds.count('csv') >= 2,
                'four_raw_request_response_before_after_references_required')
        require(result['change_evidence']['verified_original_evidence'],
                'change_original_evidence_missing')
        if manifest['mode'] == 'replay':
            count = manifest['counts']['snapshots']
            result['history'] = {str(number): self.query(run, 'snapshot', snapshot=number,
                                                        path=['snapshot_id'])
                                 for number in sorted({0, count // 2, count - 1})}
            require(result['history'][str(count - 1)] == manifest['final_snapshot_id'],
                    'replay_terminal_snapshot_identity_changed')
            result['revisions'] = self.query(run, 'revisions', after=0, limit=2)
        result['artifacts'] = self.client.expect('GET', prefix + '/artifacts')['artifacts']
        artifact = next(item for item in result['artifacts'] if item['path'] == 'shared/shared.sqlite3')
        raw = self.client.expect('GET', prefix + '/artifacts/shared/shared.sqlite3/download', timeout=120)
        require(isinstance(raw, bytes) and hashlib.sha256(raw).hexdigest() == artifact['sha256'],
                'controlled_download_digest_changed')
        result['download'] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        (self.work / f'{stage}-{run}-shared.sqlite3.download').write_bytes(raw)
        result['evaluation_projection'] = self.client.expect('GET', prefix +
                                                             '/evaluation-input?projection=dual', timeout=11)
        result['evaluations'] = {}
        for check in self.run_row(run).get('saved_evaluation', {}).get('checks', []):
            identity = check['evaluation_id']
            path = prefix + '/evaluations/' + identity
            detail = self.client.expect('GET', path)
            downloaded = self.client.expect('GET', path + '/download')
            document = json.loads(downloaded) if isinstance(downloaded, (bytes, str)) else downloaded
            predicted = result['evaluation_projection']['predictions']['events'][0]['id']
            evidence = self.client.expect('GET', path + '/evidence?' + urlencode({'event': predicted}))
            reference = self.client.expect('GET', path + '/evidence?' +
                                           urlencode({'event': 'manual-transition', 'reference': 'true'}))
            result['evaluations'][identity] = {'detail': detail, 'document': document,
                                               'prediction_evidence': evidence, 'reference': reference}
        denials = {}
        suffixes = ('shared-query?action=metadata', 'evidence?' + urlencode({'operation': operation}),
                    'artifacts/shared/shared.sqlite3/download')
        for label, client in [('anonymous', self.anonymous), ('viewer_without_acl', self.viewer)]:
            for suffix in (*suffixes, *('evaluations/' + identity for identity in result['evaluations'])):
                code, _ = client.request('GET', prefix + '/' + suffix, timeout=11)
                require(code in (401, 403, 404), 'unauthorized_restored_read_allowed')
                denials[label + ':' + suffix.split('?')[0]] = code
        result['acl_denials'] = denials
        formal.write(self.work / f'{stage}-{run}-api.json', result)
        return result

    def terminal_state(self, run):
        state = self.client.expect('GET', f'/api/v3/runs/{run}')['run']
        denied = {}
        for suffix in ('result', 'shared-query?action=metadata', 'artifacts/shared/shared.sqlite3/download'):
            code, _ = self.client.request('GET', f'/api/v3/runs/{run}/' + suffix, timeout=11)
            require(code >= 400, 'cancelled_task_exposed_published_result')
            denied[suffix] = code
        return {'run': state, 'unavailable_results': denied}

    def execute(self):
        self.report['public_checks'] = {}
        self.report['measurements'] = {'version': 'terminal-recovery-wall-and-bytes-1',
                                      'cold_source_reverification': {}}
        self.setup()
        self.legacy_before_compact()
        legacy_run = self.report['checks']['old_format_read']['run_id']
        legacy_before = r.check_evidence(self.client, legacy_run, self.root, 1)
        before = {}
        for mode, case in [('offline', 'success'), ('replay', 'normal')]:
            networks, process, profile, _ = formal.small_inputs(self.work / ('fixture-' + mode), case, mode)
            body = self.admit('backup-' + mode, networks, process, profile)
            run, row = self.submit_wait(body, 'dag6-' + mode)
            self.fixtures[run] = (networks, process)
            if mode == 'replay':
                projection = self.client.expect('GET', f'/api/v3/runs/{run}/evaluation-input?projection=dual', timeout=11)
                row['saved_evaluation'] = check_saved_evaluation(self.client, run, projection,
                    work=self.work / 'evaluation-replay', dataset_id=body['dataset_id'])
                self.state['replay_run_id'] = run
            else:
                self.state['offline_run_id'] = run
            before[run] = self.collect(run, 'original')
            self.flush()
        # Only an ordinary unstarted cancellation is required, no injected rows.
        r.stop(self.worker)
        self.worker = None
        queued = self.client.expect('POST', '/api/v3/runs', body, code=201)['run']['id']
        status = self.client.expect('GET', f'/api/v3/runs/{queued}')['run']
        require(status['state'] == 'queued' and status['attempt'] == 0, 'queued_cancel_already_started')
        self.client.expect('POST', f'/api/v3/runs/{queued}/cancel', {})
        cancelled_before = self.terminal_state(queued)
        require(cancelled_before['run']['state'] == 'cancelled' and cancelled_before['run']['attempt'] == 0,
                'queued_cancel_attempt_changed')
        self.report['runs'].append({'id': queued, 'label': 'queued-cancelled', 'state': 'cancelled', 'attempt': 0})
        self.state.update(cancelled_run_id=queued, legacy_run_id=legacy_run)
        self.state['run_ids'].append(queued)
        # A live service must hold the shared maintenance lock. Rejection is
        # observed before an actual stopped-service terminal snapshot is made.
        rejected = self.work / 'live-backup-rejected'
        try:
            r.bundle.backup(self.pg, 'm4_validation', self.root, rejected,
                            control_root=self.control, maintenance=True)
        except (ValueError, RuntimeError, OSError) as error:
            formal.write(self.work / 'live-backup-rejection.json',
                         {'error_type': type(error).__name__, 'reason': str(error)})
            require('maintenance requires stopped Go service and Worker' in str(error),
                    'live_backup_rejected_for_unrelated_reason')
        else:
            raise RuntimeError('online_service_backup_was_accepted')
        require(not (rejected / 'bundle.json').exists(), 'live_backup_published_success_bundle')
        self.report['public_checks']['online_backup_denied'] = True
        old_client = self.client
        old_cookie = old_client.cookie()
        formal.write(self.work / 'original-http-timings.json', old_client.timings)
        original_root, original_control = self.root, self.control
        r.stop(self.app)
        self.app = None
        self.report['public_checks']['maintenance'] = {'worker_stopped': True, 'go_service_stopped': True}
        self.flush()
        backup_clock = formal.clock_start()
        snapshot = r.bundle.backup(self.pg, 'm4_validation', original_root, self.work / 'bundle',
                                   control_root=original_control, maintenance=True)
        self.report['measurements']['backup'] = formal.clock_elapsed(backup_clock)
        require(snapshot['format_version'] == 7, 'dag6_backup_format7_required')
        self.report['measurements']['backup_bytes'] = {
            'shared_files': sum(item['size_bytes'] for item in snapshot['files'].values()),
            'shared_file_count': len(snapshot['files']),
            'control_files': sum(item['size_bytes'] for item in snapshot['control_files'].values()),
            'control_file_count': len(snapshot['control_files']),
            'database_dump': (self.work / 'bundle/database.dump').stat().st_size,
            'bundle_manifest': (self.work / 'bundle/bundle.json').stat().st_size,
            'complete_bundle': sum(item['size_bytes'] for item in r.bundle.inventory(self.work / 'bundle').values())}
        self.flush()
        # This is a preflight rejection tripwire only. The successful restore
        # below uses real PostgreSQL and unmodified bundle bytes.
        mutants_clock = formal.clock_start()
        mutants = rejection_checks(self.pg, self.work / 'bundle', self.work / 'restore-mutants')
        self.report['measurements']['restore_mutants'] = formal.clock_elapsed(mutants_clock)
        self.report['public_checks']['restore_mutants'] = mutants
        self.root = self.work / 'restored-new-root'
        self.control = self.work / 'restored-new-control'
        restore_clock = formal.clock_start()
        restored = r.bundle.restore(self.pg, self.work / 'bundle', self.root,
                                    control_destination=self.control)
        self.report['measurements']['restore'] = formal.clock_elapsed(restore_clock)
        require(restored.get('valid') and restored.get('catalog_equal') and
                restored.get('attempt_history_equal') and restored.get('file_inventory_equal'),
                'fresh_restore_metadata_or_inventory_mismatch')
        require(restored.get('control_inventory_equal_before_rebase') and
                restored.get('verifier_history_equal') and
                restored.get('restored_authority_credentials') is False,
                'fresh_restore_control_or_source_trust_policy_mismatch')
        formal.write(self.work / 'restore-result.json', restored)
        config = deepcopy(self.config)
        pg_port = urlsplit(config['database_url']).port
        public, internal = r.port(), r.port()
        worker_token, coordinator_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        config.update(database_url=f'postgres://postgres:m4-disposable-only@127.0.0.1:{pg_port}/m4_restore_validation?sslmode=disable',
                      shared_root=str(self.root), control_root=str(self.control), public_addr=f'127.0.0.1:{public}',
                      internal_addr=f'127.0.0.1:{internal}', worker_token=worker_token, coordinator_token=coordinator_token)
        self.app = r.start_app(self.work, 'app-restored', self.work / 'cpagx-v3', config)
        self.origin = f'http://127.0.0.1:{public}'
        self.client = formal.MeasuredClient(self.origin)
        code, _ = self.client.request('GET', '/api/v3/session', headers={'Cookie': 'cpag_session=' + old_cookie})
        require(code == 401, 'restored_session_not_revoked')
        self.client.expect('POST', '/api/v3/session', {'username': self.state['username'], 'password': self.state['password']})
        self.viewer = formal.MeasuredClient(self.origin)
        self.viewer.expect('POST', '/api/v3/session', {'username': self.state['viewer_username'],
                                                    'password': self.state['viewer_password']})
        self.anonymous = formal.MeasuredClient(self.origin)
        self.report['public_checks']['session_revoked_on_restore'] = True
        reverification = {}
        for run, original in before.items():
            path = f'/api/v3/runs/{run}/shared-query?action=metadata'
            old_receipts = set(self.control.glob(f'compact-verification-{run}-1-*.json'))
            verification_clock = formal.clock_start()
            began = time.monotonic()
            code, value = self.client.request('GET', path, timeout=11)
            require(code == 409 and value.get('error', {}).get('code') == 'verification_pending',
                    'first_restore_query_did_not_require_source_reverification')
            polls = [{'status': code, 'response': value}]
            while code != 200 and time.monotonic() - began < 120:
                time.sleep(.25)
                code, value = self.client.request('GET', path, timeout=11)
                polls.append({'status': code, 'response': value})
                require(code in (200, 409), 'restore_source_reverification_unexpected_status')
            require(code == 200, 'restore_source_reverification_timeout')
            self.report['measurements']['cold_source_reverification'][run] = formal.clock_elapsed(verification_clock)
            formal.write(self.work / f'reverification-{run}.json', polls)
            actual = self.collect(run, 'restored')
            require(actual == original, 'restored_authenticated_api_projection_changed')
            new_receipts = set(self.control.glob(f'compact-verification-{run}-1-*.json')) - old_receipts
            require(len(new_receipts) == 1, 'exactly_one_new_background_source_verifier_required')
            receipt = json.loads(next(iter(new_receipts)).read_text())
            require(receipt.get('restart_reverification') is True and
                    receipt.get('cleanup_completed') is True and
                    receipt.get('verification_report', {}).get('status') == 'passed',
                    'restored_real_source_verifier_receipt_missing')
            ledger = json.loads(formal.sql(self.pg,
                "SELECT coalesce(json_agg(row_to_json(v)),'[]') FROM m4_compact_verifications v WHERE job_id=" +
                formal.literal(run), db='m4_restore_validation'))
            require(len(ledger) == 1 and ledger[0]['state'] == 'exited' and ledger[0]['exited_at'] and
                    ledger[0]['container_name'] == receipt['container_id'],
                    'restored_source_verifier_durable_exit_missing')
            formal.write(self.work / f'restored-verifier-{run}.json', {'receipt': receipt, 'ledger': ledger})
            reverification[run] = {'first_status': 409, 'first_error_code': 'verification_pending',
                                   'eventual_status': 200, 'seconds': time.monotonic() - began,
                                   'real_background_source_verifier_exited': True,
                                   'new_background_verification_count': 1,
                                   'complete_saved_api_responses_equal': True}
        require(r.check_evidence(self.client, legacy_run, self.root, 1) == legacy_before,
                'legacy_result_changed_after_restore')
        require(self.terminal_state(queued) == cancelled_before, 'cancelled_task_changed_after_restore')
        self.report['checks']['restored_reverification'] = reverification
        self.report['public_checks'].update(format_version=7, fresh_database='m4_restore_validation',
            new_shared_and_control_roots=True, original_run_and_evaluation_ids_preserved=True,
            complete_api_responses_equal=True, four_raw_references_verified=True,
            graph_pages_history_revisions_equal=True, downloads_equal=True,
            saved_evaluations_and_reference_originals_equal=True, unauthorized_reads_denied=True,
            legacy_result_equal=True, queued_cancelled_attempt_zero_unchanged=True,
            cold_source_reverification={run: {key: value for key, value in proof.items() if key != 'seconds'}
                                        for run, proof in reverification.items()})
        self.worker_config = self.work / 'restored-worker-config.json'
        r.write_private(self.worker_config, {'api_url': f'http://127.0.0.1:{internal}',
            'shared_root': str(self.root), 'control_root': str(self.control), 'worker_token': worker_token,
            'coordinator_token': coordinator_token, 'worker_id': 'r19-restored-worker', 'image': self.args.image,
            'poll_seconds': .2, 'recovery_seconds': 2, 'resource_profile': formal.RESOURCE})
        self.start_worker()
        self.state.update(url=self.origin, restored_url=self.origin, internal_url=f'http://127.0.0.1:{internal}',
                          source_root=str(original_root), original_control_root=str(original_control),
                          restored_root=str(self.root), control_root=str(self.control),
                          restored_run_id=self.state['replay_run_id'], run_id=self.state['replay_run_id'])
        self.report.update(status='passed', valid=True)
        self.flush()
        print(json.dumps({'status': 'passed', 'private_state': str(self.work / 'state.json'),
                          'public_report': str(self.work / 'public/report.json')}), flush=True)
        if self.args.serve:
            halt = False
            def shutdown(*_):
                nonlocal halt
                halt = True
            signal.signal(signal.SIGTERM, shutdown)
            signal.signal(signal.SIGINT, shutdown)
            while not halt:
                require(self.app.poll() is None and self.worker.poll() is None, 'retained_restored_service_exited')
                time.sleep(.5)

    def close(self):
        r.stop(self.worker)
        r.stop(self.app)
        if self.created:
            for database in ('m4_validation', 'm4_restore_validation'):
                with (self.work / (database + '.sql')).open('wb') as dump:
                    subprocess.run(['docker', 'exec', self.pg, 'pg_dump', '-U', 'postgres', database],
                                   stdout=dump, stderr=subprocess.PIPE, check=False)
            with (self.work / 'postgres.log').open('wb') as log:
                subprocess.run(['docker', 'logs', self.pg], stdout=log, stderr=subprocess.STDOUT)
            if self.report.get('status') != 'passed':
                subprocess.run(['docker', 'stop', self.pg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.report['failed_database_preserved'] = {'container': self.pg, 'state': 'stopped_private_database_retained'}
            else:
                subprocess.run(['docker', 'rm', '-f', '-v', self.pg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--serve', action='store_true')
    args = parser.parse_args()
    args.mode = 'small'
    if re.fullmatch(r'(?:sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})', args.image) is None:
        parser.error('immutable Docker image ID/digest required')
    args.output = args.output.resolve()
    if not args.output.is_relative_to(Path('/private/tmp')):
        parser.error('output must be a fresh directory under /private/tmp')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    harness = Harness(args)
    try:
        harness.execute()
    except BaseException as error:
        harness.report.update(status='failed', valid=False, error_type=type(error).__name__, reason=str(error)[:2048])
        harness.flush()
        raise
    finally:
        harness.close()


if __name__ == '__main__':
    main()
