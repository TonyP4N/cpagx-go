#!/usr/bin/env python3
"""Quiescent packaged single-host engineering snapshot; never an online backup.

Bundles contain credentials: keep private and outside Git. Restore only into an
empty independent target with the SAME absolute data path. Historical execution
locations remain historical; they must never authorize new work on another daemon.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import bundle


def docker(*args):
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True).stdout.strip()


def maintenance(project, root):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,48}', project):
        raise ValueError('invalid project')
    # A running API can admit new work; a controller/recovery process can mutate
    # control records. Include all project containers except its database.
    running = docker('ps', '--format', '{{.Names}}').splitlines()
    active = [name for name in running if name.startswith(project+'-') and name != project+'-postgres']
    scope = hashlib.sha256((str(root/'shared')+'|'+str(root/'control')).encode()).hexdigest()[:24]
    compute = docker('ps', '-a', '--filter', 'label=cpag.scope='+scope, '--format', '{{.ID}}')
    if active or compute:
        raise ValueError('maintenance requires stopped application services and no remaining scoped compute containers')


def ledger_check(root, expected_root):
    ledger = json.loads((root/'control/capacity.json').read_text())
    reservations = ledger.get('reservations')
    if ledger.get('root') != str(expected_root/'shared') or not isinstance(reservations, dict):
        raise ValueError('capacity root/reservations mismatch')
    if any(type(value) is not int or value < 0 for value in reservations.values()):
        raise ValueError('invalid reservation')
    used = 0
    for folder in (root/'shared/jobs', root/'control/jobs'):
        if folder.exists():
            used += sum(item['size_bytes'] for item in bundle.inventory(folder).values())
    if sum(reservations.values()) < used:
        raise ValueError('capacity ledger undercounts stored attempt files; rebuild before backup')
    return {'reserved_bytes': sum(reservations.values()), 'attempt_file_bytes': used,
            'reservation_count': len(reservations), 'valid': True}


def control_check(root, attempts):
    history = {(item['job_id'], item['attempt']): item for item in attempts}
    seen = set()
    for path in (root/'control/jobs').glob('*/attempt-*.worker/execution.json'):
        record = json.loads(path.read_text())
        key = (record.get('id'), record.get('attempt'))
        row = history.get(key)
        if row is None or path.parent.parent.name != key[0] or path.parent.name != 'attempt-'+str(key[1])+'.worker':
            raise ValueError('control execution missing or mismatched database identity')
        expected = {'id': row['job_id'], 'attempt': row['attempt'], 'worker': row['worker'],
                    'token': row['attempt_token'], 'container_id': row['container_id'], 'location': row['location']}
        if any(record.get(name) != value for name, value in expected.items()):
            raise ValueError('control execution differs from database history')
        proof = json.loads((path.parent/'exit.json').read_text())
        # Go's shared ExitProof struct serializes these legacy-only zero values
        # even for a container receipt. No other field is stripped or ignored.
        normalized_proof = {'group_exited': False, 'child_pid': 0, 'guardian_pid': 0, **proof}
        if not row.get('exited_at') or normalized_proof != row.get('exit_receipt'):
            raise ValueError('control exit proof differs from database history')
        seen.add(key)
    required = {key for key, row in history.items() if row.get('executor_kind') == 'isolated-v2' and row.get('container_id')}
    if not required.issubset(seen):
        raise ValueError('isolated execution control proof missing; reconcile before checkpoint')
    return {'valid': True, 'matched_execution_count': len(seen)}


def snapshot(project, root, destination, version):
    root, destination = Path(root).absolute(), Path(destination).absolute()
    if root.is_symlink() or destination.exists() or destination.is_relative_to(root):
        raise ValueError('new snapshot outside nonsymlink data root required')
    maintenance(project, root)
    before = bundle.inventory(root)
    capacity = ledger_check(root, root)
    destination.mkdir(mode=0o700, parents=False)
    # Existing snapshot implementation locks both DB tables, validates every
    # source reference/history row, and publishes its marker only after pg_dump.
    data = bundle.backup(project+'-postgres', 'm4_validation', root/'shared', destination/'database-and-shared')
    control = control_check(root, data['attempts'])
    shutil.copytree(root, destination/'host', symlinks=False)
    maintenance(project, root)
    if bundle.inventory(root) != before or bundle.inventory(destination/'host') != before:
        raise ValueError('host state changed during snapshot')
    if bundle.rows_now(project+'-postgres', 'm4_validation') != data['rows'] or bundle.attempts_now(project+'-postgres', 'm4_validation') != data['attempts']:
        raise ValueError('database changed during snapshot')
    result = {'format': 'cpag-engineering-snapshot-v1', 'synthetic_only': True,
              'source_version': version, 'data_root': str(root), 'host_files': before,
              'database_bundle_sha256': bundle.sha(destination/'database-and-shared/bundle.json'),
              'capacity': capacity, 'control': control, 'valid': True}
    bundle.write_report(destination/'snapshot.json', result)
    return result


def verify(source):
    source = Path(source)
    meta = json.loads(bundle.safe(source, 'snapshot.json').read_text())
    if meta.get('format') != 'cpag-engineering-snapshot-v1' or meta.get('synthetic_only') is not True:
        raise ValueError('unsupported snapshot')
    if bundle.inventory(source/'host') != meta['host_files']:
        raise ValueError('host snapshot checksum mismatch')
    data_dir = source/'database-and-shared'
    if bundle.sha(bundle.safe(data_dir, 'bundle.json')) != meta['database_bundle_sha256']:
        raise ValueError('database bundle marker mismatch')
    data = json.loads((data_dir/'bundle.json').read_text())
    if bundle.sha(bundle.safe(data_dir, 'database.dump')) != data['database_sha256']:
        raise ValueError('database dump checksum mismatch')
    if bundle.inventory(data_dir/'files') != data['files'] or bundle.inventory(source/'host/shared') != data['files']:
        raise ValueError('shared snapshots disagree')
    if not bundle.audit(data['rows'], source/'host/shared')['valid'] or not bundle.audit_attempts(data['rows'], data['attempts'])['valid']:
        raise ValueError('snapshot reference/history audit failed')
    if data.get('format_version')==6:
        if set(data.get('catalog',{}))!=set(bundle.CATALOG_TABLES):raise ValueError('snapshot format6 preparation catalog missing')
        if not bundle.audit_catalog(data['catalog'],data['rows'],source/'host/shared')['valid']:
            raise ValueError('snapshot preparation catalog audit failed')
    ledger_check(source/'host', Path(meta['data_root']))
    control_check(source/'host', data['attempts'])
    return meta, data


def restore(project, source, root, confirm):
    source, root = Path(source).absolute(), Path(root).absolute()
    meta, data = verify(source)
    if confirm != bundle.sha(source/'snapshot.json'):
        raise ValueError('confirm must equal verified snapshot.json SHA256')
    if str(root) != meta['data_root'] or root.exists() or root.is_symlink():
        raise ValueError('restore requires absent original absolute data path in independent target')
    maintenance(project, root)
    container = project+'-postgres'
    # Explicitly refuse any existing schema objects before modifying the target.
    count = bundle.pg(container, 'm4_validation', 'psql', '-X', '-qAt', '-c',
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'",
        capture_output=True, text=True).stdout.strip()
    if count != '0':
        raise ValueError('restore database is not empty')
    report = root.parent/(root.name+'-restore-report.json')
    with report.open('x') as stream:
        os.chmod(report, 0o600)
        json.dump({'valid': False, 'phase': 'restoring'}, stream)
    try:
        with (source/'database-and-shared/database.dump').open('rb') as stream:
            bundle.pg(container, 'm4_validation', 'pg_restore', '--exit-on-error', '--no-owner', stdin=stream)
        shutil.copytree(source/'host', root)
        if bundle.rows_now(container, 'm4_validation') != data['rows'] or bundle.attempts_now(container, 'm4_validation') != data['attempts']:
            raise ValueError('restored database differs')
        if bundle.inventory(root) != meta['host_files'] or not bundle.audit(data['rows'], root/'shared')['valid']:
            raise ValueError('restored files/references differ')
        preparation_audit=None;revoked_sessions=None
        if data.get('format_version')==6:
            restored_catalog=bundle.catalog_now(container,'m4_validation',tuple(data['catalog']))
            if restored_catalog!=data['catalog']:raise ValueError('restored preparation catalog differs')
            catalog_audit=bundle.audit_catalog(restored_catalog,data['rows'],root/'shared')
            if not catalog_audit['valid']:raise ValueError('restored preparation catalog invalid')
            preparation_audit=bundle.audit_preparation_documents(container,'m4_validation',restored_catalog,data['rows'],root/'shared')
            # Engineering restore uses m4_validation, so revoke explicitly here.
            bundle.pg(container,'m4_validation','psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c',
                'UPDATE v3_sessions SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL;',capture_output=True,text=True)
            remaining=bundle.pg(container,'m4_validation','psql','-X','-qAt','-c','SELECT count(*) FROM v3_sessions WHERE revoked_at IS NULL;',capture_output=True,text=True).stdout.strip()
            if remaining!='0':raise ValueError('restored preparation login sessions remain active')
            revoked_sessions=True
        capacity = ledger_check(root, root)
        control = control_check(root, data['attempts'])
        result = {'valid': True, 'synthetic_only': True, 'source_version': meta['source_version'],
                  'metadata_equal': True, 'history_equal': True, 'files_equal': True,
                  'evidence_audit': True, 'capacity': capacity, 'control': control}
        if preparation_audit is not None:result.update(preparation_audit=preparation_audit,restored_sessions_revoked=revoked_sessions)
        bundle.write_report(report, result)
        return result
    except Exception as error:
        bundle.write_report(report, {'valid': False, 'phase': 'restore_failed', 'error_type': type(error).__name__,
                                    'policy': 'retain partial target; do not start services'})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['backup', 'verify', 'restore'])
    parser.add_argument('--project', default='cpag-engineering')
    parser.add_argument('--root', default='/cpag')
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--version')
    parser.add_argument('--confirm')
    args = parser.parse_args()
    if args.action == 'backup':
        if not args.version: parser.error('--version required for backup')
        result = snapshot(args.project, args.root, args.bundle, args.version)
        print(json.dumps({'valid': True, 'snapshot_sha256': bundle.sha(Path(args.bundle)/'snapshot.json')}))
    elif args.action == 'verify':
        verify(args.bundle)
        print(json.dumps({'valid': True, 'synthetic_only': True}))
    else:
        print(json.dumps(restore(args.project, args.bundle, args.root, args.confirm)))


if __name__ == '__main__':
    main()
