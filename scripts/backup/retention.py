"""Audited removal of closed rotated logs and explicitly closed runtime files.

Business/shared/control/bundle roots are outside this capability. Plans do not
remove data; apply requires an exact deployment confirmation and stopped-service
maintenance lock. Unknown, linked, open or changed files fail closed.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

import bundle
import terminal_shared

VERSION = 'deployment-closed-file-retention-1'
MAX_FILE_BYTES = 256 * 1024**2
MAX_PLAN_BYTES = 1024**3


def config_digest(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def open_file_identities():
    proc = Path('/proc')
    if not proc.is_dir():
        raise ValueError('Linux open-file inspection required for cleanup')
    identities = set()
    for process in proc.iterdir():
        if not process.name.isdigit(): continue
        try:
            descriptors = list((process/'fd').iterdir())
        except (FileNotFoundError, ProcessLookupError): continue
        except PermissionError as error:
            raise ValueError('open-file liveness cannot be established') from error
        for descriptor in descriptors:
            try:
                info = descriptor.stat()
                if stat.S_ISREG(info.st_mode): identities.add((info.st_dev, info.st_ino))
            except (FileNotFoundError, ProcessLookupError): continue
            except PermissionError as error:
                raise ValueError('open-file liveness cannot be established') from error
    return identities


def allowed_name(scope, name):
    if scope == 'logs': return re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.log\.[A-Za-z0-9][A-Za-z0-9_.-]*', name) is not None
    return scope == 'runtime' and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.tmp\.closed', name) is not None


def stamp(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('cleanup requires ordinary single-link files')
    return {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def target(config, item):
    scope = item.get('scope')
    if scope not in ('logs', 'runtime'): raise ValueError('cleanup scope is not allowed')
    root = Path(config['log_root' if scope == 'logs' else 'run_root'])
    relative = item.get('relative')
    if not isinstance(relative, str) or '\\' in relative:
        raise ValueError('cleanup relative path required')
    part = Path(relative)
    if part.is_absolute() or not part.parts or '..' in part.parts or part.as_posix() != relative or not allowed_name(scope, part.name):
        raise ValueError('cleanup name outside rotated-log/closed-runtime policy')
    path = root / part
    if any(value.is_symlink() for value in (path, *path.parents)) or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('cleanup symlink or path escape')
    return path


def plan(config, log_days=14, temporary_days=1):
    for days in (log_days, temporary_days):
        if type(days) is not int or not 1 <= days <= 36500: raise ValueError('cleanup ages must be 1..36500 days')
    now = time.time(); opened = open_file_identities(); candidates = []; retained = []; total = 0
    for scope, root in [('logs', Path(config['log_root'])), ('runtime', Path(config['run_root']))]:
        if not root.is_dir(): continue
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(directory)/name).is_symlink()]
            for name in sorted(files):
                path = Path(directory)/name; item = {'scope': scope, 'relative': path.relative_to(root).as_posix()}
                reason = None
                try:
                    path = target(config, item); current = stamp(path)
                    if (current['device'], current['inode']) in opened: reason = 'open_file_retained'
                    elif current['mtime_ns'] > (now - (log_days if scope == 'logs' else temporary_days) * 86400) * 1e9: reason = 'retention_age_not_reached'
                    elif current['size'] > MAX_FILE_BYTES or total + current['size'] > MAX_PLAN_BYTES or len(candidates) >= 10000: reason = 'bounded_cleanup_limit_retained'
                    else:
                        digest = bundle.sha(path)
                        if stamp(path) != current: raise ValueError('file_changed_during_plan')
                        candidates.append({**item, **current, 'sha256': digest}); total += current['size']
                except (OSError, ValueError): reason = 'unknown_linked_or_protected_file_retained'
                if reason: retained.append({**item, 'reason': reason})
    return {'version': VERSION, 'deployment_id': config['deployment_id'], 'config_sha256': config_digest(config),
            'created_at': now, 'log_days': log_days, 'temporary_days': temporary_days,
            'deletes_data': False, 'candidates': candidates, 'candidate_bytes': total, 'retained': retained,
            'policy': 'closed rotated logs and *.tmp.closed only; current logs, PID files, business and failure evidence excluded'}


def apply(config, planned, confirmation, audit_path):
    if confirmation != config['deployment_id']:
        raise ValueError('exact deployment confirmation required for cleanup apply')
    if (not isinstance(planned, dict) or planned.get('version') != VERSION
            or planned.get('deployment_id') != config['deployment_id'] or planned.get('config_sha256') != config_digest(config)
            or not 0 <= time.time() - planned.get('created_at', 0) <= 86400):
        raise ValueError('current matching cleanup preview required')
    audit_path = Path(audit_path).absolute(); backup_root = Path(config['backup_root'])
    if (not audit_path.is_relative_to(backup_root) or audit_path.parent != backup_root
            or audit_path.exists() or any(part.is_symlink() for part in (audit_path, *audit_path.parents))):
        raise ValueError('new audit file directly inside configured backup root required')
    audit_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    audit = {'version': VERSION, 'deployment_id': config['deployment_id'], 'valid': False,
             'phase': 'reserved', 'actor': {'uid': os.getuid(), 'effective_uid': os.geteuid(), 'role': 'deployment_root_operator'}, 'deleted': [], 'preserved_roots': ['shared_root','control_root','backup_root'],
             'preview_sha256': hashlib.sha256(json.dumps(planned, sort_keys=True).encode()).hexdigest()}
    with open(audit_path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream: json.dump(audit, stream)
    try:
        with terminal_shared.maintenance(config['control_root']):
            opened = open_file_identities(); selected = []
            candidates=planned.get('candidates')
            if not isinstance(candidates,list) or len(candidates)>10000:
                raise ValueError('bounded cleanup candidates required')
            seen=set();total=0
            for item in candidates:
                if not isinstance(item,dict) or (item.get('scope'),item.get('relative')) in seen:
                    raise ValueError('unique cleanup candidates required')
                seen.add((item.get('scope'),item.get('relative')))
                path = target(config, item); current = stamp(path)
                total += current['size']
                if current['size']>MAX_FILE_BYTES or total>MAX_PLAN_BYTES: raise ValueError('cleanup byte bound exceeded')
                if any(current[key] != item.get(key) for key in current) or bundle.sha(path) != item.get('sha256'):
                    raise ValueError('cleanup candidate changed since preview')
                days = planned['log_days' if item['scope'] == 'logs' else 'temporary_days']
                if type(days) is not int or not 1 <= days <= 36500 or current['mtime_ns'] > (planned['created_at'] - days * 86400) * 1e9:
                    raise ValueError('cleanup retention age not satisfied')
                if (current['device'], current['inode']) in opened: raise ValueError('cleanup candidate is currently open')
                selected.append((path, item, current))
            for path, item, current in selected:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    if stamp(path) != current or os.fstat(descriptor).st_ino != current['inode']:
                        raise ValueError('cleanup candidate changed before unlink')
                    path.unlink()
                finally: os.close(descriptor)
                audit['deleted'].append({key: item[key] for key in ('scope','relative','size','sha256')})
                audit['phase'] = 'applying'; bundle.write_report(audit_path, audit)
        audit.update(valid=True, phase='completed', deleted_bytes=sum(row['size'] for row in audit['deleted']))
        bundle.write_report(audit_path, audit); return audit
    except Exception as error:
        audit.update(phase='failed', error_type=type(error).__name__, reason=str(error),
                     orphan_policy='retain all remaining files and audit; never delete business roots')
        bundle.write_report(audit_path, audit); raise
