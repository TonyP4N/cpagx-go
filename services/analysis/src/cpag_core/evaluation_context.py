"""Versioned service-only verification reuse, never an artifact trust anchor.

The Go caller first verifies the current DB publication, attempt, inventory and
all bytes, supplies its checked run-manifest digest, then repeats those checks
before returning. Standalone callers omit this context and retain full semantic
verification. No annotation, HTTP parameter or saved bundle can set this context.
All bytes are rehashed even on a request-local cache hit. Nothing persists across
requests; a restarted service cannot inherit a stale trust decision.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
import re

from .pipeline import file_hash
from .dual_source import strict_json

VERSION = 'service-publication-verification-reuse-1'
_current = ContextVar('evaluation_publication_context', default=None)


@contextmanager
def service_publication(root, digest, *, prepared_adapted=None):
    if digest is None:
        if prepared_adapted is not None:
            raise ValueError('prepared_projection_requires_service_publication')
        yield
        return
    if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
        raise ValueError('invalid_service_publication_digest')
    state = {'root': Path(root).resolve(), 'digest': digest, 'cache': {}, 'prepared_adapted': prepared_adapted}
    token = _current.set(state)
    try:
        checked_manifest(root)
        yield
        checked_manifest(root)
    finally:
        try:
            for close in state['cache'].get('closers', []):
                close()
        finally:
            _current.reset(token)


def checked_manifest(root):
    state = _current.get()
    if state is None:
        return None
    root = Path(root)
    if root.is_symlink() or root.resolve() != state['root']:
        raise ValueError('service_publication_root_mismatch')
    path = root / 'run_manifest.json'
    if path.is_symlink() or file_hash(path) != state['digest']:
        raise ValueError('service_publication_manifest_changed')
    manifest = strict_json(path.read_text(encoding='utf-8'))
    seen = set()
    for item in manifest['artifacts']:
        name = item['path']
        rel = PurePosixPath(name)
        if (not name or rel.is_absolute() or '..' in rel.parts or str(rel) != name
                or name in seen):
            raise ValueError('service_publication_inventory_invalid')
        seen.add(name)
        source = root / name
        if any((root / Path(*rel.parts[:n])).is_symlink() for n in range(1, len(rel.parts)+1)):
            raise ValueError('service_publication_symlink')
        if (not source.is_file() or source.stat().st_size != item['size_bytes']
                or file_hash(source) != item['sha256']):
            raise ValueError('service_publication_bytes_changed: ' + name)
    return manifest


def request_cache(root):
    state = _current.get()
    if state is None:
        return None
    checked_manifest(root)
    return state['cache']


def prepared_projection(root):
    state = _current.get()
    if state is None or state['prepared_adapted'] is None:
        return None
    manifest = checked_manifest(root)
    adapted = state['prepared_adapted']
    binding = adapted['binding']
    hashes = {row['path']: row['sha256'] for row in manifest['artifacts']}
    hashes['run_manifest.json'] = state['digest']
    for key in ('run_id', 'attempt_id', 'mode', 'synthetic', 'input_fingerprint',
                'config_fingerprint', 'tool_versions', 'result_hashes'):
        if binding.get(key) != manifest.get(key):
            raise ValueError('prepared_projection_publication_mismatch: ' + key)
    for key in ('run_id','synthetic','input_fingerprint','config_fingerprint'):
        if adapted['predictions'].get(key) != manifest.get(key):
            raise ValueError('prepared_prediction_identity_mismatch: ' + key)
    if binding.get('artifact_sha256') != hashes:
        raise ValueError('prepared_projection_artifact_binding_mismatch')
    return adapted


def retained_analysis(root):
    cache = request_cache(root)
    if cache is None:
        raise ValueError('service_publication_required')
    if 'analysis' not in cache:
        cache['analysis'] = strict_json((Path(root)/'analysis.json').read_text(encoding='utf-8'))
    return cache['analysis']


def terminal_replay_evidence(root, adapted, **selectors):
    """Read arrived original records for an already verified terminal snapshot.

    This does not evaluate an arrival or synthesize a history state. The normal
    historical snapshot API retains its independent full verification path.
    """
    from .capacity import parser_limits, resolve_capacity_profile
    from .replay_inputs import ReplayInputs
    from .replay_export import network_names, resolve_verified_selection
    root = Path(root); cache = request_cache(root)
    if cache is None or prepared_projection(root) is None:
        raise ValueError('prepared_terminal_replay_required')
    binding = adapted['binding']; final = binding['final_snapshot']
    analysis = retained_analysis(root)
    if analysis.get('replay',{}).get('phase') != 'finished':
        raise ValueError('terminal_replay_required')
    if 'replay_inputs' not in cache:
        manifest = checked_manifest(root)
        profile = strict_json((root/'sources/profile.json').read_text())
        names = [item['path'] for item in manifest['artifacts']
                 if item['path'].startswith('sources/network') and item['path'].endswith('.pcap')]
        names = ['sources/'+name for name in network_names(len(names))]
        extra = {}
        if profile.get('replay',{}).get('history_format') == 'replay-history-checkpoint-delta-2':
            limits=parser_limits(profile); budget=resolve_capacity_profile(profile)
            extra={'packet_limits':limits['packet_limits'],'process_limits':limits['process_limits'],
                   'stream_limits':limits['stream_limits'],'capacity_config':profile,
                   'max_records':budget.frames+budget.process_records+1 if budget.version else 11000}
        inputs=ReplayInputs([root/name for name in names],root/'sources/process.csv',
                            profile['process'],synthetic=profile['synthetic'],**extra)
        cache.setdefault('closers',[]).append(inputs.close)
        for step in profile['replay']['sequence']:
            if step.get('kind') == 'advance':continue
            if step.get('kind') == 'source_eof':inputs.finish_source(step['source_slot'])
            else:inputs.advance(step)
        if not inputs.all_sources_exhausted():raise ValueError('input_not_exhausted')
        cache['replay_inputs']=inputs
    snapshot={'analysis':analysis,'available_at':final['available_at']}
    return resolve_verified_selection(cache['replay_inputs'],snapshot,final['snapshot_number'],**selectors)
