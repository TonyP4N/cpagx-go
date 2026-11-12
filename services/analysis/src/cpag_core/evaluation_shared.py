"""DAG6 evaluation projection over independently verified, bounded logical reads.

Labels never enter this module. Terminal predictions use live plus frozen final
state. Ever-observed counters union stable business identities across *all*
snapshots, including observations subsequently expired or withdrawn. Revisions
and repeated visibility do not add observations. This is an evaluation adapter,
not a second analysis algorithm or a service approval authority.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import hashlib
from pathlib import Path

from .pipeline import canonical, fingerprint

VERSION = 'final-artifact-evaluation-dag6-1'
HISTORY_POLICY = 'terminal-live-frozen-and-ever-observed-distinct-1'
_current = ContextVar('verified_shared_evaluation_reader', default=None)


@contextmanager
def reader_context(output, reader):
    """Only the protected service bridge installs its already approved reader."""
    token = _current.set((Path(output).resolve(), reader))
    try:
        yield reader
    finally:
        _current.reset(token)


def current_reader(output):
    current = _current.get()
    if current is None:
        return None
    if Path(output).resolve() != current[0]:
        raise ValueError('evaluation_service_reader_root_mismatch')
    return current[1]


def _count(reader, root, path):
    # Authenticated node metadata gives exact array cardinality without decoding
    # whole objects; absent/malformed nodes remain an error rather than zero.
    node = reader._node(reader._select(root, path))
    if node[0] not in ('array_leaf', 'array_branch'):
        raise ValueError('evaluation_array_required')
    return node[3]


def _rows(reader, root, base, collection, fields):
    """Page positions, then read only required bounded fields at each position.

    Full observation/candidate records can themselves exceed a query budget.
    Reading selected scalar/object paths avoids expanding evidence arrays.
    """
    total = _count(reader, root, [*base, collection])
    for offset in range(0, total, 100):
        for index in range(offset, min(offset + 100, total)):
            row = {}
            for target, path in fields:
                value = reader.get(root, path=[*base, collection, index, *path])
                cursor = row
                for component in target[:-1]:
                    cursor = cursor.setdefault(component, {})
                cursor[target[-1]] = value
            yield row


def _projection(reader, root='analysis.json', base=()):
    fields = {
        'network': [(('event', 'event_id'), ('event', 'event_id')),
                    (('observation', 'endpoints'), ('observation', 'endpoints'))],
        'process': [(('event', 'event_id'), ('event', 'event_id')), (('time',), ('time',))],
        'operations': [(('operation_id',), ('operation_id',)), (('time',), ('time',))],
        'changes': [(('event_id',), ('event_id',)), (('result',), ('result',)),
                    (('time_range',), ('time_range',))],
        'candidates': [(('candidate_id',), ('candidate_id',)),
                       (('operation_id',), ('operation_id',)), (('change_id',), ('change_id',))],
    }
    result = {name: list(_rows(reader, root, base, name, paths)) for name, paths in fields.items()}
    for name in ('analysis_version', 'config_fingerprint'):
        result[name] = reader.get(root, path=[*base, name])
    return result


def _history(reader, terminal):
    from .evaluation_artifacts import _history_statistics
    manifest = reader.run_manifest
    if manifest['mode'] != 'replay':
        return _history_statistics(())[0], None
    # Keep old candidate first-visible/withdrawal meaning, while adding explicit
    # observation counts; never confuse terminal prediction count with history.
    first = {name: {} for name in ('network', 'process', 'operations', 'changes')}
    snapshots = manifest['counts']['snapshots']
    if _count(reader, 'history/snapshots', []) != snapshots:
        raise ValueError('evaluation_history_count_mismatch')

    def records():
        for number in range(snapshots):
            metadata = {name: reader.get('history/snapshots', path=[number, name])
                        for name in ('snapshot_number', 'snapshot_id', 'available_at',
                                     'state_fingerprint', 'revision_number')}
            if metadata['snapshot_number'] != number:
                raise ValueError('evaluation_history_order_mismatch')
            for name in first:
                path = ('event', 'event_id') if name in ('network', 'process') else (('operation_id',) if name == 'operations' else ('event_id',))
                for row in _rows(reader, 'history/snapshots', [number, 'analysis'], name, [(('id',), path)]):
                    first[name].setdefault(row['id'], number)
            candidates = list(_rows(reader, 'history/snapshots', [number, 'analysis'], 'candidates',
                                    [(('candidate_id',), ('candidate_id',))]))
            yield dict(metadata, analysis={'candidates': candidates})

    statistics, final = _history_statistics(records())
    if (final is None or final['snapshot_number'] != manifest['final_snapshot_number']
            or final['snapshot_id'] != manifest['final_snapshot_id']
            or reader.get('analysis.json', path=['replay', 'phase']) != 'finished'):
        raise ValueError('terminal_snapshot_binding_mismatch')
    for index in range(manifest['counts']['operations']):
        if reader.get('analysis.json', path=['operations', index, 'replay', 'closed']) is not True:
            raise ValueError('terminal_replay_required')
    # Full independent verification bound this snapshot to the final analysis.
    # Retain that exact typed-root equality on every service reader projection.
    if reader._select('history/snapshots', [final['snapshot_number'], 'analysis']) != reader._select('analysis.json', []):
        raise ValueError('evaluation_terminal_analysis_mismatch')
    statistics['observation_policy'] = HISTORY_POLICY
    statistics['terminal_distinct_counts'] = {
        name: len({row['event']['event_id'] if name in ('network', 'process') else row['operation_id'] if name == 'operations' else row['event_id']
                   for row in terminal[name]}) for name in first}
    statistics['ever_observed_distinct_counts'] = {name: len(rows) for name, rows in first.items()}
    statistics['ever_observed_first_snapshot'] = {
        name: [{'id': identity, 'snapshot_number': number} for identity, number in sorted(rows.items())]
        for name, rows in first.items()}
    statistics['observation_definition'] = ('Distinct stable IDs across all snapshots, including expired observations; '
        'terminal live+frozen observations and ever-observed history are separate; revisions are not events.')
    return statistics, final


def adapt_reader(reader, *, batch, sample_sha256, projection='dual', expected_binding=None):
    from .evaluation_artifacts import _adapt_verified, POLICY
    from .shared_export import FORMAT, _bounded
    import re
    if (projection not in ('network', 'process', 'dual') or not isinstance(batch, str) or not batch.strip()
            or not isinstance(sample_sha256, str) or re.fullmatch('[a-f0-9]{64}', sample_sha256) is None):
        raise ValueError('invalid_evaluation_projection_context')
    manifest = reader.run_manifest
    if manifest['storage_format'] != FORMAT:
        raise ValueError('evaluation_explicit_dag6_required')
    analysis = _projection(reader)
    statistics, final = _history(reader, analysis)
    # Only retained configuration versions are needed. Labels are never staged.
    profile = {'config_version': reader.get('analysis.json', path=['config_version']),
               'rule_version': reader.get('analysis.json', path=['rule_version'])}
    hashes = {item['path']: item['sha256'] for item in manifest['artifacts']}
    hashes['run_manifest.json'] = hashlib.sha256(canonical(manifest) + b'\n').hexdigest()
    result = _adapt_verified(manifest, analysis, profile, statistics, final, hashes,
                             batch=batch, sample_sha256=sample_sha256, projection=projection)
    binding = result['binding']
    policy = dict(POLICY, replay='terminal_live_plus_frozen_distinct_stable_ids_only',
                  replay_history=HISTORY_POLICY)
    binding.update(adapter_version=VERSION, policy=policy, policy_sha256=fingerprint(policy),
                   storage_format=FORMAT, logical_artifacts=deepcopy(manifest['logical_artifacts']),
                   logical_roots_sha256=fingerprint(manifest['logical_artifacts']),
                   result_hash_kind=manifest['result_hash_kind'],
                   graph_identity_strategy=manifest['graph_identity_strategy'])
    if manifest['mode'] == 'replay':
        binding.update(history_format=manifest['history_format'],
                       identity_strategy=manifest['identity_strategy'],
                       prefix_digest_strategy=manifest['prefix_digest_strategy'])
        # DAG6 has a shared logical history, not history/manifest.json.
        binding.pop('history_manifest_sha256', None)
    if expected_binding is not None and canonical(expected_binding) != canonical(binding):
        raise ValueError('frozen_artifact_binding_mismatch')
    return _bounded(result)


def adapt_shared(output, **keywords):
    from .shared_export import verify_task, open_reader
    reader = current_reader(output)
    if reader is not None:
        return adapt_reader(reader, **keywords)
    verify_task(output)
    with open_reader(output) as reader:
        return adapt_reader(reader, **keywords)


def query_shared_prediction(output, adapted, **selectors):
    from .shared_export import query_task
    reader = current_reader(output)
    snapshot = adapted['binding']['final_snapshot']
    options = dict(selectors, snapshot=None if snapshot is None else snapshot['snapshot_number'])
    if reader is None:
        return query_task(output, **options)
    from .shared_export import query_reader
    return query_reader(output, reader, **options)
