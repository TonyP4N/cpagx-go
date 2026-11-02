"""Terminal DAG6 bundle checks, without transferring source-read authority.

The restored service must independently rebuild retained sources before issuing
its new in-memory approval. This module verifies the stored publication chain
and every compact node; it never imports old experimental approval credentials.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat

from cpag_core import shared_export as core
from cpag_core import shared_service as service
from cpag_core.dual_source_rules import validate_profile
from cpag_core.pipeline import canonical, file_hash, fingerprint

VERSION = 'dag6-terminal-backup-audit-1'
STATUS = 'storage_only_source_pending'
VERSIONS = {'storage_format': core.FORMAT, 'capacity_profile': service.CAPACITY,
            'resource_profile': service.RESOURCE, 'storage_budget_version': service.BUDGET}
REPLAY = {'replay_version': 'dual-source-replay-1', 'history_format': core.FORMAT}


def detects(payload, profile=None):
    """Route shared and malformed shared markers here rather than to flat readers."""
    for value in (payload, profile):
        if not isinstance(value, dict):
            continue
        if any(name in value for name in ('storage_format', 'storage_budget_version')):
            return True
        if value.get('capacity_profile') in ('engineering-capacity-2', service.CAPACITY):
            return True
        if value.get('resource_profile') in ('engineering-capacity-2', service.CAPACITY, service.RESOURCE):
            return True
        history = value.get('history_format')
        replay = value.get('replay')
        if isinstance(replay, dict):
            history = replay.get('history_format', history)
        if isinstance(history, str) and history.startswith('shared-'):
            return True
    return False


def _digest(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def _safe(root, relative):
    if not isinstance(relative, str) or not relative or '\\' in relative:
        raise ValueError('dag6_unsafe_reference')
    part = Path(relative)
    if part.is_absolute() or '..' in part.parts or part.as_posix() != relative:
        raise ValueError('dag6_unsafe_reference')
    root = Path(root).absolute()
    target = root / part
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError('dag6_reference_escapes_root')
    for path in [target, *target.parents]:
        if path.is_symlink():
            raise ValueError('dag6_symlink_forbidden')
        if path == root:
            break
    return target


def _files(root):
    """Retain failed diagnostics as ordinary bytes, never trusted publications."""
    result = {}
    if root.is_symlink():
        raise ValueError('dag6_symlink_forbidden')
    if not root.exists():
        return result
    if not root.is_dir():
        raise ValueError('dag6_attempt_directory_required')
    def walk(directory):
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                path = Path(entry.path)
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    walk(path)
                elif stat.S_ISREG(mode):
                    result[path.relative_to(root).as_posix()] = {
                        'sha256': file_hash(path), 'size': path.stat().st_size}
                else:
                    raise ValueError('dag6_ordinary_file_required')
    walk(root)
    return result


def _profile_payload(payload, profile):
    if not isinstance(payload, dict) or not isinstance(profile, dict):
        raise ValueError('dag6_payload_profile_objects_required')
    for name, expected in VERSIONS.items():
        if payload.get(name) != expected:
            raise ValueError('dag6_payload_version_mismatch:' + name)
        # Resource limits are operator-owned and normally absent from profiles.
        if name != 'resource_profile' or name in profile:
            if profile.get(name) != expected:
                raise ValueError('dag6_profile_version_mismatch:' + name)
    validate_profile(profile)
    if fingerprint(profile) != payload.get('config_fingerprint'):
        raise ValueError('dag6_profile_config_fingerprint_mismatch')
    kind = payload.get('kind')
    if kind not in ('dual-source', 'dual-source-replay'):
        raise ValueError('dag6_dual_task_required')
    replay = kind == 'dual-source-replay'
    if replay:
        if not isinstance(profile.get('replay'), dict):
            raise ValueError('dag6_replay_profile_required')
        for name, expected in REPLAY.items():
            profile_name = 'version' if name == 'replay_version' else name
            if payload.get(name) != expected or profile['replay'].get(profile_name) != expected:
                raise ValueError('dag6_replay_version_mismatch:' + name)
    elif ('replay' in profile or any(name in payload for name in REPLAY)
          or 'history_format' in profile):
        raise ValueError('dag6_offline_has_replay_fields')
    refs = payload.get('networks', [payload.get('network')])
    if (not isinstance(refs, list) or not 1 <= len(refs) <= 4
            or refs[0] != payload.get('network')):
        raise ValueError('dag6_ordered_network_references_invalid')
    for ref in [*refs, payload.get('process'), payload.get('profile')]:
        if (not isinstance(ref, dict) or set(ref) != {'path', 'sha256'}
                or not _digest(ref['sha256']) or not isinstance(ref['path'], str)):
            raise ValueError('dag6_input_reference_invalid')
    if len({ref['path'] for ref in refs}) != len(refs):
        raise ValueError('dag6_duplicate_network_reference')
    return refs, 'replay' if replay else 'offline'


def _binding(wrapper, publication_sha, payload_sha):
    if not isinstance(wrapper, dict):
        raise ValueError('dag6_publication_object_required')
    for field, expected in VERSIONS.items():
        if wrapper.get(field) != expected:
            raise ValueError('dag6_publication_version_mismatch:' + field)
    if (not isinstance(wrapper.get('run_id'), str) or not 1 <= len(wrapper['run_id']) <= 128
            or type(wrapper.get('attempt_id')) is not int or not 1 <= wrapper['attempt_id'] <= 1000000
            or not _digest(wrapper.get('config_fingerprint'))):
        raise ValueError('dag6_publication_identity_invalid')
    return {**VERSIONS, **{field: wrapper[field] for field in ('run_id', 'attempt_id', 'config_fingerprint')},
            'publication_sha256': publication_sha, 'payload_sha256': payload_sha}


@contextmanager
def open_storage_reader(output):
    """Open verified stored nodes, with no source approval or rebuild authority.

    External job/catalog bindings must be checked with audit first. This helper
    also supports local evaluation-contract comparison over the same byte chain.
    """
    output = Path(output)
    wrapper = core.read_json(output / 'manifest.json', 65536)
    publication_sha = file_hash(output / 'manifest.json')
    # Only the format of this field is needed by _inventory. This local digest
    # is never presented as the database task payload or as a service approval.
    binding = _binding(wrapper, publication_sha, fingerprint(wrapper))
    anchor = output / (publication_sha + '.json')
    if not anchor.is_file() or file_hash(anchor) != publication_sha:
        raise ValueError('dag6_publication_anchor_required')
    root, initial, rows = service._inventory(output, binding)
    # An inherited live-service context cannot bypass compact-node validation.
    token = core._SERVICE_VERIFIED.set(None)
    try:
        with service._envelope(root, rows), core.open_reader(root) as reader:
            reader.backup_verification_status = STATUS
            yield reader
        _, after, final = service._inventory(root, binding)
        if rows != final or canonical(initial) != canonical(after):
            raise ValueError('dag6_changed_during_storage_audit')
    finally:
        core._SERVICE_VERIFIED.reset(token)


def audit(row, root, verify):
    """Validate a terminal row and return explicit storage-only audit evidence."""
    if not isinstance(row, dict) or row.get('state') not in ('succeeded', 'failed', 'cancelled'):
        raise ValueError('dag6_terminal_row_required')
    job = row.get('id')
    if not isinstance(job, str) or not job or len(Path(job).parts) != 1 or job in ('.', '..'):
        raise ValueError('dag6_job_identity_invalid')
    attempt = row.get('attempt')
    if type(attempt) is not int or not 0 <= attempt <= 1000000:
        raise ValueError('dag6_attempt_identity_invalid')
    payload = row.get('payload')
    if not isinstance(payload, dict) or not isinstance(payload.get('profile'), dict):
        raise ValueError('dag6_payload_profile_required')
    profile_ref = payload['profile']
    profile_path = _safe(root, profile_ref.get('path'))
    if not _digest(profile_ref.get('sha256')):
        raise ValueError('dag6_profile_digest_invalid')
    verify(profile_ref['path'], profile_ref['sha256'])
    profile = core.read_json(profile_path)
    networks, mode = _profile_payload(payload, profile)
    refs = list(zip(networks, core.network_names(len(networks))))
    refs += [(payload['process'], 'process.csv'), (profile_ref, 'profile.json')]
    for ref, _ in refs:
        _safe(root, ref['path'])
        verify(ref['path'], ref['sha256'])
    base = Path('jobs') / job / ('attempt-' + str(attempt))
    output = _safe(root, base.as_posix())
    report = {'version': VERSION, 'status': STATUS, 'trusted_result': False,
              'source_verification': 'required_by_restored_service', 'state': row['state'],
              'run_id': job, 'attempt_id': attempt}
    if row['state'] != 'succeeded':
        report.update(status='retained_untrusted_terminal_attempt', files=_files(output))
        return report
    if attempt < 1 or not _digest(row.get('artifact_sha256')):
        raise ValueError('dag6_published_attempt_identity_required')
    digest = row['artifact_sha256']
    if row.get('artifact_path') != (base / (digest + '.json')).as_posix():
        raise ValueError('dag6_published_attempt_path_mismatch')
    verify((base / 'manifest.json').as_posix(), digest)
    verify(row['artifact_path'], digest)
    wrapper = core.read_json(output / 'manifest.json', 65536)
    binding = _binding(wrapper, digest, fingerprint(payload))
    if any(binding[name] != value for name, value in (
            ('run_id', job), ('attempt_id', attempt), ('config_fingerprint', payload['config_fingerprint']))):
        raise ValueError('dag6_publication_job_binding_mismatch')
    if wrapper.get('inputs') != {role: payload[role]['sha256'] for role in ('network', 'process', 'profile')}:
        raise ValueError('dag6_publication_source_mismatch')
    expected_networks = [ref['sha256'] for ref in networks] if 'networks' in payload else None
    if wrapper.get('networks') != expected_networks:
        raise ValueError('dag6_publication_ordered_network_mismatch')
    for name, value in REPLAY.items():
        if (mode == 'replay' and wrapper.get(name) != value) or (mode == 'offline' and name in wrapper):
            raise ValueError('dag6_publication_replay_version_mismatch')
    _, manifest, inventory = service._inventory(output, binding)
    if manifest.get('mode') != mode or manifest.get('network_count') != len(networks):
        raise ValueError('dag6_core_mode_network_count_mismatch')
    for ref, name in refs:
        retained = output / 'sources' / name
        if file_hash(retained) != ref['sha256']:
            raise ValueError('dag6_retained_original_input_mismatch:' + name)
    for entry in inventory:
        verify((base / entry['path']).as_posix(), entry['sha256'], entry['size'])
    with open_storage_reader(output) as reader:
        if canonical(reader.run_manifest) != canonical(manifest):
            raise ValueError('dag6_core_changed_during_audit')
        report.update(storage_integrity_verified=True, logical_roots_sha256=fingerprint(manifest['logical_artifacts']),
                      physical_inventory=inventory, counts=manifest['counts'])
    _, after, final = service._inventory(output, binding)
    if final != inventory or canonical(after) != canonical(manifest):
        raise ValueError('dag6_publication_changed_during_audit')
    for ref, _ in refs:
        verify(ref['path'], ref['sha256'])
    return report
