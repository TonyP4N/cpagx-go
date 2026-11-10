#!/usr/bin/env python3
"""Deployment-scoped terminal bundles; stopped services, new restore targets.

Run inside the Linux deployment host. No database rename, credential transport,
implicit database drops or business/failed-run evidence deletion is performed by this operator.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import time
import secrets
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bundle
import terminal_shared
import retention
from postgres_target import DeploymentDatabases, deployment_databases

FIELDS = {'deployment_id', 'release_root', 'shared_root', 'control_root', 'app_config',
          'worker_config', 'pg_container', 'source_database', 'restore_database',
          'backup_root', 'log_root', 'run_root'}
VERSION = 'deployment-terminal-bundle-1'


def actor():
    return {'uid': os.getuid(), 'effective_uid': os.geteuid(), 'role': 'deployment_root_operator'}


def trusted_backup_root(config):
    root = Path(config['backup_root'])
    if (not root.is_dir() or any(part.is_symlink() for part in (root, *root.parents))
            or root.stat().st_mode & 0o022 or root.stat().st_uid not in (0, os.geteuid())):
        raise ValueError('operator-owned non-writable controlled backup root required')
    return root


def verified_restore_bundle(config, source):
    root = trusted_backup_root(config)
    if source.parent != root or not source.is_dir() or source.is_symlink():
        raise ValueError('restore source must be a direct controlled backup-root bundle')
    receipt = root/(source.name+'-operation.json')
    for path in (source, receipt, source/'operator-owner.json', source/'bundle.json'):
        if (path.is_symlink() or path.stat().st_uid not in (0, os.geteuid())
                or path.stat().st_mode & 0o022):
            raise ValueError('trusted restore receipt and bundle ownership required')
    outside = json.loads(receipt.read_text()); owner = json.loads((source/'operator-owner.json').read_text())
    digest = bundle.sha(source/'bundle.json')
    if (outside.get('version') != VERSION or outside.get('action') != 'backup' or outside.get('valid') is not True
            or outside.get('deployment_id') != config['deployment_id'] or outside.get('database') != config['source_database']
            or outside.get('format_version') != 7 or outside.get('actor', {}).get('effective_uid') != 0
            or outside.get('bundle_sha256') != digest or owner.get('version') != VERSION
            or owner.get('deployment_id') != config['deployment_id'] or owner.get('bundle_sha256') != digest):
        raise ValueError('controlled successful backup receipt, deployment and bundle digest must match')
    return digest


def load_config(path):
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('ordinary owner-private operator configuration required')
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('operator configuration fields do not match deployment contract')
    if not isinstance(value['deployment_id'], str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value['deployment_id']):
        raise ValueError('explicit deployment identity required')
    DeploymentDatabases(value['pg_container'], value['source_database'], value['restore_database'])
    for key in FIELDS - {'deployment_id', 'pg_container', 'source_database', 'restore_database'}:
        if not isinstance(value[key], str) or not Path(value[key]).is_absolute() or '..' in Path(value[key]).parts:
            raise ValueError('operator paths must be explicit absolute paths')
    for key in ('shared_root', 'control_root', 'backup_root', 'log_root', 'run_root'):
        target = Path(value[key])
        if any(part.is_symlink() for part in (target, *target.parents)):
            raise ValueError('persistent operator paths must not contain symlinks')
    roots = [Path(value[key]).resolve() for key in ('shared_root', 'control_root', 'backup_root', 'log_root', 'run_root')]
    for index, left in enumerate(roots):
        for right in roots[index + 1:]:
            separate(left, right)
    return value, path


def separate(left, right):
    if left.is_relative_to(right) or right.is_relative_to(left):
        raise ValueError('separate source, control, bundle and restore paths required')


def owned_postgres(config):
    # Select only nonsecret ownership fields; never read or print container env.
    template = '{{json .Config.Labels}}\n{{.Id}}\n{{.State.Running}}'
    result = subprocess.run(['docker', 'inspect', '--format', template, config['pg_container']],
                            check=True, capture_output=True, text=True, timeout=15)
    if len(result.stdout) > 65536:
        raise ValueError('PostgreSQL ownership response exceeds bound')
    lines = result.stdout.strip().splitlines()
    if len(lines) != 3:
        raise ValueError('PostgreSQL ownership response invalid')
    labels = json.loads(lines[0]); identity = lines[1]
    if (not isinstance(labels, dict) or labels.get('cpag.role') != 'postgres'
            or labels.get('cpag.deployment_id') != config['deployment_id']
            or not re.fullmatch('[a-f0-9]{64}', identity) or lines[2] != 'true'):
        raise ValueError('running PostgreSQL container ownership mismatch')
    return identity


def service_manager(config, config_path, action):
    manager = Path(config['release_root']) / 'deployments/r21/cpag-service'
    if not manager.is_file():
        raise ValueError('installed deployment service manager required')
    # Fixed release-owned entry point and action; no caller-provided shell text.
    subprocess.run([str(manager), action, '--config', str(config_path)], check=True,
                   capture_output=True, text=True, timeout=60)


def reserve_report(path, action, config):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        json.dump({'version': VERSION, 'action': action, 'deployment_id': config['deployment_id'],
                   'valid': False, 'phase': 'reserved', 'actor': actor()}, stream)


def backup(config, config_path, destination, stop_services=False):
    destination = Path(destination).absolute()
    if '..' in destination.parts or destination.parent != Path(config['backup_root']):
        raise ValueError('new bundle must be directly inside configured backup root')
    if destination.exists() or any(part.is_symlink() for part in (destination, *destination.parents)):
        raise ValueError('new ordinary bundle destination required')
    report_path = destination.parent / (destination.name + '-operation.json')
    reserve_report(report_path, 'backup', config)
    try:
        identity = owned_postgres(config)
        if stop_services:
            service_manager(config, config_path, 'stop')
        with deployment_databases(DeploymentDatabases(identity, config['source_database'], config['restore_database'])):
            result = bundle.backup(identity, config['source_database'], Path(config['shared_root']), destination,
                                   control_root=Path(config['control_root']), maintenance=True)
        owner = {'version': VERSION, 'deployment_id': config['deployment_id'],
                 'created_at': datetime.now(timezone.utc).isoformat(), 'bundle_sha256': bundle.sha(destination/'bundle.json')}
        with open(destination/'operator-owner.json', 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
            json.dump(owner, stream); stream.write('\n')
        report = {'version': VERSION, 'action': 'backup', 'valid': True, 'deployment_id': config['deployment_id'],
                  'database': config['source_database'], 'postgres_id': identity, 'format_version': result['format_version'],
                  'bundle_sha256': owner['bundle_sha256'], 'files': len(result['files']),
                  'control_files': len(result.get('control_files', {})), 'source_trust': 'reverify_in_restored_service',
                  'retention': 'retain_source_bundle_controls_and_failed_attempts', 'actor': actor()}
        bundle.write_report(report_path, report)
        return report
    except Exception as error:
        bundle.write_report(report_path, {'version': VERSION, 'action': 'backup', 'valid': False,
            'phase': 'failed', 'error_type': type(error).__name__, 'actor': actor(), 'retention': 'all_source_and_partial_evidence_retained'})
        raise


def restore(config, source, destination, control_destination):
    source, destination, control_destination = (Path(value).absolute() for value in (source, destination, control_destination))
    root = trusted_backup_root(config)
    audit_path = root/('restore-'+str(time.time_ns())+'-'+secrets.token_hex(4)+'-operation.json')
    reserve_report(audit_path, 'restore', config)
    try:
        if any('..' in target.parts for target in (source, destination, control_destination)):
            raise ValueError('canonical restore paths without parent traversal required')
        if any(part.is_symlink() for target in (source, destination, control_destination) for part in (target, *target.parents)):
            raise ValueError('ordinary bundle and new restore paths required')
        if destination.exists() or control_destination.exists():
            raise ValueError('restore shared and control directories must be new')
        for target in (destination, control_destination):
            for protected in (Path(config['shared_root']), Path(config['control_root']), source, Path(config['backup_root'])):
                separate(target, protected)
        separate(destination, control_destination)
        digest = verified_restore_bundle(config, source)
        identity = owned_postgres(config)
        with terminal_shared.maintenance(config['control_root']):
            with deployment_databases(DeploymentDatabases(identity, config['source_database'], config['restore_database'])):
                result = bundle.restore(identity, source, destination, control_destination=control_destination,
                                        database=config['restore_database'])
        report = {'version': VERSION, 'action': 'restore', 'valid': True, 'actor': actor(),
                  'deployment_id': config['deployment_id'], 'database': config['restore_database'],
                  'postgres_id': identity, 'bundle_sha256': digest, 'audit_path': str(audit_path),
                  'source_trust': result.get('source_trust'), 'sessions_revoked': result.get('sessions_revoked'),
                  'worker_observations_cleared': result.get('worker_observations_cleared'),
                  'file_inventory_equal': result.get('file_inventory_equal'),
                  'control_inventory_equal_before_rebase': result.get('control_inventory_equal_before_rebase')}
        bundle.write_report(audit_path, report); return report
    except Exception as error:
        bundle.write_report(audit_path, {'version': VERSION, 'action': 'restore', 'valid': False,
            'phase': 'failed', 'deployment_id': config['deployment_id'], 'actor': actor(),
            'error_type': type(error).__name__, 'reason': str(error),
            'retention': 'source bundle, partial database, directories and failed audit retained'})
        raise


def retention_plan(config, keep):
    if type(keep) is not int or not 1 <= keep <= 10000:
        raise ValueError('retention keep count must be 1..10000')
    root = Path(config['backup_root']); owned = []; retained = []
    for target in sorted(root.iterdir() if root.exists() else []):
        if target.is_symlink() or not target.is_dir():
            retained.append({'name': target.name, 'reason': 'unknown_or_report_never_delete'}); continue
        try:
            owner = json.loads((target/'operator-owner.json').read_text())
            if (owner.get('version') != VERSION or owner.get('deployment_id') != config['deployment_id']
                    or owner.get('bundle_sha256') != bundle.sha(target/'bundle.json')):
                raise ValueError('owner_or_manifest_mismatch')
            manifest = json.loads((target/'bundle.json').read_text())
            if (manifest.get('format_version') != 7 or bundle.sha(target/'database.dump') != manifest['database_sha256']
                    or bundle.inventory(target/'files') != manifest['files']
                    or bundle.inventory(target/'control') != manifest['control_files']):
                raise ValueError('bundle_inventory_mismatch')
            stamp = datetime.fromisoformat(owner['created_at'])
            if stamp.tzinfo is None: raise ValueError('timezone_required')
            owned.append((stamp, target.name))
        except (OSError, ValueError, KeyError, TypeError):
            retained.append({'name': target.name, 'reason': 'incomplete_unknown_or_changed_never_delete'})
    owned.sort(reverse=True)
    return {'version': VERSION, 'action': 'retention-plan', 'deletes_data': False,
            'keep': keep, 'retained_complete': [name for _, name in owned[:keep]],
            'reviewable_old_complete': [name for _, name in owned[keep:]], 'retained_evidence': retained,
            'policy': 'plan_only; no database, container, source, control, failed attempt or bundle deletion'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    sub = parser.add_subparsers(dest='action', required=True)
    backup_parser = sub.add_parser('backup'); backup_parser.add_argument('--destination', required=True, type=Path); backup_parser.add_argument('--stop-services', action='store_true')
    restore_parser = sub.add_parser('restore'); restore_parser.add_argument('--source', required=True, type=Path); restore_parser.add_argument('--destination', required=True, type=Path); restore_parser.add_argument('--control-destination', required=True, type=Path)
    retention = sub.add_parser('retention-plan'); retention.add_argument('--keep', type=int, default=3)
    cleanup = sub.add_parser('cleanup-plan'); cleanup.add_argument('--log-days', type=int, default=14); cleanup.add_argument('--temporary-days', type=int, default=1); cleanup.add_argument('--output', required=True, type=Path)
    apply = sub.add_parser('cleanup-apply'); apply.add_argument('--plan', required=True, type=Path); apply.add_argument('--confirm-deployment', required=True); apply.add_argument('--audit', required=True, type=Path)
    sub.add_parser('status')
    args = parser.parse_args(); config, config_path = load_config(args.config)
    if args.action in ('backup','restore','cleanup-apply') and os.geteuid() != 0:
        raise ValueError('deployment mutation requires the root operator')
    if args.action == 'backup': result = backup(config, config_path, args.destination, args.stop_services)
    elif args.action == 'restore': result = restore(config, args.source, args.destination, args.control_destination)
    elif args.action == 'retention-plan': result = retention_plan(config, args.keep)
    elif args.action == 'cleanup-plan':
        target = args.output.absolute()
        if target.parent != Path(config['backup_root']) or target.exists() or any(part.is_symlink() for part in (target, *target.parents)):
            raise ValueError('new preview file directly inside configured backup root required')
        result = retention.plan(config, args.log_days, args.temporary_days)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with open(target, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream: json.dump(result, stream, indent=2)
    elif args.action == 'cleanup-apply':
        if (args.plan.absolute().parent != Path(config['backup_root']) or args.plan.is_symlink()
                or args.plan.stat().st_mode & 0o022 or args.plan.stat().st_uid != 0 or args.plan.stat().st_size > 8*1024**2):
            raise ValueError('bounded root-owned cleanup preview inside controlled backup root required')
        result = retention.apply(config, json.loads(args.plan.read_text()), args.confirm_deployment, args.audit)
    else: result = {'version': VERSION, 'action': 'status', 'postgres_id': owned_postgres(config), 'deployment_id': config['deployment_id']}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'valid': False, 'error_type': type(error).__name__, 'reason': str(error)}), file=sys.stderr)
        raise SystemExit(1)
