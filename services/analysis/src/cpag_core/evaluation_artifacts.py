"""R19 final-artifact observation adapter; never accepts annotations.

Frozen policy ``final-observations-upper-bound-1``: network operations use the
configured corrected request interval's upper bound and canonical JSON
``[destination_ip, destination_port]`` as captured endpoint identity. Process
transitions use their retained upper bound and canonical JSON ``[asset_id, tag]``.
These scalar metrics lose interval resolution and do not assert action time.
Candidates remain unlabelled hypothetical relations, never attack predictions.

``network`` and ``process`` are views when applied to dual-source artifacts.
For a distinct ``single_source`` run they must match its actually executed
source mode. Batch and sample digest are supplied by trusted registration
context; the adapter cannot prove them.
Existing verifiers may recompute for integrity. Prediction selection reads only
the retained final artifact, never the recomputed return value or a gold file.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re

from .evaluation_context import checked_manifest, request_cache, service_publication, prepared_projection, retained_analysis, terminal_replay_evidence
from .contracts import validate
from .dual_source import strict_json, utc
from .evaluation import instant
from .pipeline import canonical, file_hash, fingerprint


VERSION = 'final-artifact-evaluation-1'
POLICY = {
    'version': 'final-observations-upper-bound-1',
    'network_kind': 'network_operation',
    'network_asset': 'canonical_json_destination_ip_port_captured_endpoint_only',
    'network_time': 'configured_corrected_request_interval_upper_bound',
    'process_kind': 'process_change',
    'process_asset': 'canonical_json_asset_id_tag',
    'process_time': 'configured_transition_interval_upper_bound',
    'replay': 'verified_terminal_snapshot_distinct_stable_ids_only',
    'relations': 'unlabelled_hypothetical_candidates_no_path_accuracy',
}
LIMITATIONS = [
    'Scalar upper-bound matching loses interval resolution and does not establish action time.',
    'Network/process projections are views, not independent single-source analysis experiments.',
    'Captured endpoints do not establish device, user, attack, causality or physical execution.',
    'Batch and sample digest are declared trusted registration context, not independently verified custody.',
    'Candidate associations are unlabelled relations; path accuracy is unavailable.',
]


def _read(path):
    return strict_json(Path(path).read_text(encoding='utf-8'))


def _unique(rows, key):
    found = {}
    for row in rows:
        identity = row[key]
        if identity in found and canonical(found[identity]) != canonical(row):
            raise ValueError('conflicting_stable_identity: ' + identity)
        found.setdefault(identity, row)
    return list(found.values())


def _interval(value):
    if (not isinstance(value, list) or len(value) != 2
            or any(type(v) not in (int, float) or not math.isfinite(v) for v in value)
            or value[0] > value[1]):
        return None
    return value


def _verified(output):
    """Verify first, then read and bind retained bytes, including replay history."""
    root = Path(output)
    cache = request_cache(root)
    if cache is not None and 'verified' in cache:
        return cache['verified']
    initial = _read(root / 'run_manifest.json')
    if initial.get('mode') == 'replay':
        from .replay_export import verify_task
    elif initial.get('mode') == 'offline':
        from .dual_source_export import verify_task
    elif initial.get('mode') == 'single_source':
        from .single_source_export import verify_task
    else:
        raise ValueError('unsupported_artifact_mode')
    manifest = checked_manifest(root)
    if manifest is None:
        manifest = verify_task(root)
    raw = (root / 'run_manifest.json').read_bytes()
    if raw != canonical(manifest) + b'\n':
        raise ValueError('artifact_changed_after_verification')
    hashes = {'run_manifest.json': hashlib.sha256(raw).hexdigest()}
    entries = {row['path']: row for row in manifest['artifacts']}

    def bound_bytes(name):
        data = (root / name).read_bytes()
        entry = entries[name]
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry['sha256'] or len(data) != entry['size_bytes']:
            raise ValueError('artifact_changed_after_verification: ' + name)
        hashes[name] = digest
        return data

    def bound_rows(name):
        digest = hashlib.sha256(); size = 0
        with (root / name).open('rb') as stream:
            for raw_line in stream:
                digest.update(raw_line); size += len(raw_line)
                yield strict_json(raw_line.decode('utf-8'))
        if digest.hexdigest() != entries[name]['sha256'] or size != entries[name]['size_bytes']:
            raise ValueError('artifact_changed_after_verification: ' + name)

    # Bind every source and projection, even when it is not selected by a view.
    for name, entry in entries.items():
        path = root / name
        if (path.is_symlink() or not path.is_file() or file_hash(path) != entry['sha256']
                or path.stat().st_size != entry['size_bytes']):
            raise ValueError('artifact_changed_after_verification: ' + name)
        hashes[name] = entry['sha256']
    analysis = strict_json(bound_bytes('analysis.json').decode('utf-8'))
    profile_name = 'dual/sources/profile.json' if manifest['mode'] == 'offline' else 'sources/profile.json'
    profile = strict_json(bound_bytes(profile_name).decode('utf-8'))
    statistics, _ = _history_statistics(())
    final = None
    if manifest['mode'] == 'replay':
        replay = strict_json(bound_bytes('replay.json').decode('utf-8'))
        if manifest.get('history_format') is not None:
            from .replay_export import iter_verified_snapshots
            # The versioned outer verifier checks source replay and storage;
            # iterate reconstructed logical states without inventing JSONL files.
            bound_bytes('history/manifest.json')
            statistics, final = _history_statistics(iter_verified_snapshots(root))
        else:
            statistics, final = _history_statistics(bound_rows('snapshots.jsonl'))
        if (final is None or final['snapshot_id'] != replay['final_snapshot_id']
                or statistics['snapshot_count'] != replay['snapshot_count']):
            raise ValueError('terminal_snapshot_binding_mismatch')
        if (final['analysis'].get('replay', {}).get('phase') != 'finished'
                or canonical(final['analysis']) != canonical(analysis)
                or any(op.get('replay', {}).get('closed') is not True for op in analysis['operations'])):
            raise ValueError('terminal_replay_required')
    if (root / 'run_manifest.json').read_bytes() != raw:
        raise ValueError('artifact_changed_after_verification')
    result = (manifest, analysis, profile, statistics, final, hashes)
    if cache is not None:
        cache['verified'] = result
    return result


def _history_statistics(snapshots):
    previous = set()
    first_visible = {}
    withdrawals = []
    count = 0; final = None
    for snapshot in snapshots:
        count += 1; final = snapshot
        current = {row['candidate_id'] for row in snapshot['analysis']['candidates']}
        for identity in sorted(current):
            first_visible.setdefault(identity, {'candidate_id': identity,
                'snapshot_number': snapshot['snapshot_number'], 'snapshot_id': snapshot['snapshot_id'],
                'available_at': snapshot['available_at']})
        withdrawals.extend({'candidate_id': identity, 'snapshot_number': snapshot['snapshot_number'],
            'snapshot_id': snapshot['snapshot_id'], 'available_at': snapshot['available_at']}
            for identity in sorted(previous - current))
        previous = current
    return {'snapshot_count': count, 'candidate_first_visible': list(first_visible.values()),
            'candidate_withdrawals': withdrawals, 'candidate_withdrawal_count': len(withdrawals),
            'definition': 'Ever-visible candidate IDs and visibility withdrawals; separate from terminal predictions and not causality.'}, final


def adapt_artifact(output, *, batch, sample_sha256, projection='dual', expected_binding=None):
    """Project a verified final run, without accepting labels or choosing hits.

    ``expected_binding`` is an optional exact frozen sidecar, including run,
    attempt, versions, hashes and projection context. A mismatch is rejected.
    """
    if projection not in ('network', 'process', 'dual'):
        raise ValueError('unsupported_evaluation_projection')
    if not isinstance(batch, str) or not batch.strip():
        raise ValueError('explicit_registered_batch_required')
    if not isinstance(sample_sha256, str) or re.fullmatch('[a-f0-9]{64}', sample_sha256) is None:
        raise ValueError('explicit_registered_sample_sha256_required')
    prepared = prepared_projection(output)
    if prepared is not None:
        binding = prepared['binding']
        if (binding.get('adapter_version') != VERSION or binding.get('policy') != POLICY
                or binding.get('policy_sha256') != fingerprint(POLICY)
                or binding.get('batch') != batch or binding.get('sample_sha256') != sample_sha256
                or binding.get('projection') != projection
                or binding.get('predictions_sha256') != fingerprint(prepared['predictions'])):
            raise ValueError('prepared_projection_context_mismatch')
        validate('EvaluationPredictions', prepared['predictions'])
        if expected_binding is not None and canonical(expected_binding) != canonical(binding):
            raise ValueError('frozen_artifact_binding_mismatch')
        return prepared
    # DAG6 uses authenticated logical roots rather than nonexistent flat files.
    # A service reader is supplied only inside the protected service bridge;
    # standalone calls retain the complete independent source verification.
    from .evaluation_shared import current_reader, adapt_shared
    shared = current_reader(output)
    if shared is not None or _read(Path(output) / 'run_manifest.json').get('storage_format') == 'shared-observation-dag-6':
        return adapt_shared(output, batch=batch, sample_sha256=sample_sha256,
                            projection=projection, expected_binding=expected_binding)
    manifest, analysis, profile, statistics, final, hashes = _verified(output)
    return _adapt_verified(manifest, analysis, profile, statistics, final, hashes,
                           batch=batch, sample_sha256=sample_sha256,
                           projection=projection, expected_binding=expected_binding)


def _adapt_verified(manifest, analysis, profile, statistics, final, hashes, *,
                    batch, sample_sha256, projection, expected_binding=None):
    if manifest['mode'] == 'single_source' and projection != manifest['source_mode']:
        raise ValueError('single_source_projection_must_match_executed_source_mode')
    events, exclusions, links = [], [], {}
    network = {row['event']['event_id']: row for row in analysis['network']}
    process = {row['event']['event_id']: row for row in analysis['process']}

    def add(identity, kind, asset, timestamp, selector, interval):
        event = {'id': identity, 'batch': batch, 'kind': kind, 'asset': canonical(asset).decode('utf-8'),
                 'time': timestamp, 'sample_sha256': sample_sha256}
        instant(timestamp)
        events.append(event)
        links[identity] = dict(selector, interval=deepcopy(interval))

    if projection in ('network', 'dual'):
        for op in _unique(analysis['operations'], 'operation_id'):
            identity = op['operation_id']
            time = op['time']; interval = _interval(time.get('interval'))
            selector = {'operation_id': identity}
            row = network.get(identity)
            endpoints = row['observation'].get('endpoints') if row else None
            if time.get('status') != 'configured' or interval is None:
                exclusions.append({'id': identity, 'kind': POLICY['network_kind'],
                    'reason': 'trustworthy_configured_request_time_unavailable', 'query': selector})
                continue
            if (not isinstance(endpoints, list) or len(endpoints) != 2
                    or not isinstance(endpoints[1], list) or len(endpoints[1]) != 2
                    or not isinstance(endpoints[1][0], str) or type(endpoints[1][1]) is not int):
                exclusions.append({'id': identity, 'kind': POLICY['network_kind'],
                    'reason': 'captured_destination_endpoint_unavailable', 'query': selector})
                continue
            add(identity, POLICY['network_kind'], endpoints[1], utc(interval[1]), selector, interval)
    if projection in ('process', 'dual'):
        for change in _unique(analysis['changes'], 'event_id'):
            identity = change['event_id']; result = change['result']
            interval = _interval(result.get('interval'))
            after = process.get(result.get('after_event_id'))
            selector = {'change_id': identity}
            if (interval is None or after is None or after['time'].get('status') != 'configured'
                    or change['time_range'].get('end') is None):
                exclusions.append({'id': identity, 'kind': POLICY['process_kind'],
                    'reason': 'trustworthy_configured_transition_time_unavailable', 'query': selector})
                continue
            add(identity, POLICY['process_kind'], [result['asset_id'], result['tag']],
                change['time_range']['end'], selector, interval)
    relations = sorted(row['candidate_id'] for row in _unique(analysis['candidates'], 'candidate_id')) if projection == 'dual' else []
    predictions = {'schema_version': '1.0.0', 'synthetic': manifest['synthetic'],
        'run_id': manifest['run_id'], 'input_fingerprint': manifest['input_fingerprint'],
        'config_fingerprint': manifest['config_fingerprint'],
        'events': sorted(_unique(events, 'id'), key=lambda row: row['id']), 'unlabelled_relations': relations}
    validate('EvaluationPredictions', predictions)
    for candidate in analysis['candidates'] if projection == 'dual' else []:
        links[candidate['candidate_id']] = {'operation_id': candidate['operation_id'],
            'change_id': candidate['change_id'], 'relation_only': True}
    binding = {'adapter_version': VERSION, 'policy': deepcopy(POLICY), 'policy_sha256': fingerprint(POLICY),
        'run_id': manifest['run_id'], 'attempt_id': manifest['attempt_id'], 'mode': manifest['mode'],
        'source_mode': manifest.get('source_mode', 'dual'),
        'source_presence': deepcopy(manifest.get('source_presence', {'network': True, 'process': True})),
        'source_execution_version': manifest.get('single_source_version'),
        'synthetic': manifest['synthetic'], 'input_fingerprint': manifest['input_fingerprint'],
        'config_fingerprint': manifest['config_fingerprint'],
        'semantic_config_fingerprint': manifest.get('semantic_config_fingerprint', analysis['config_fingerprint']),
        'analysis_version': analysis['analysis_version'], 'replay_version': manifest.get('replay_version'),
        'tool_versions': deepcopy(manifest['tool_versions']), 'config_version': profile['config_version'],
        'rule_version': profile['rule_version'], 'artifact_sha256': dict(sorted(hashes.items())),
        'result_hashes': deepcopy(manifest['result_hashes']),
        'projection': projection, 'batch': batch, 'sample_sha256': sample_sha256,
        'context_provenance': 'caller_supplied_trusted_registration_context_not_custody_proof',
        'final_snapshot': None if final is None else {key: final[key] for key in
            ('snapshot_id', 'snapshot_number', 'state_fingerprint', 'available_at', 'revision_number')},
        'predictions_sha256': fingerprint(predictions)}
    if manifest.get('history_format') is not None:
        binding['history_format']=manifest['history_format']
        if 'history_manifest_sha256' in manifest:
            binding['history_manifest_sha256']=manifest['history_manifest_sha256']
    if expected_binding is not None and canonical(expected_binding) != canonical(binding):
        raise ValueError('frozen_artifact_binding_mismatch')
    limitations = list(LIMITATIONS)
    if manifest['mode'] == 'single_source':
        limitations[1] = 'Explicit single-source execution; the absent other source is unavailable and supplies no evidence.'
    return {'predictions': predictions, 'binding': binding, 'exclusions': exclusions,
            'event_links': links, 'process_statistics': statistics,
            'limitations': limitations}


def query_prediction(output, adapted, prediction_id):
    """Resolve a prediction/exclusion/relation through existing verified queries."""
    binding = adapted['binding']
    actual = adapt_artifact(output, batch=binding['batch'], sample_sha256=binding['sample_sha256'],
        projection=binding['projection'], expected_binding=binding)
    if canonical(actual) != canonical(adapted):
        raise ValueError('adapted_payload_mismatch')
    selector = actual['event_links'].get(prediction_id)
    if selector is None:
        excluded = [row for row in actual['exclusions'] if row['id'] == prediction_id]
        if len(excluded) != 1:
            raise KeyError('unknown_prediction')
        selector = excluded[0]['query']
    args = ({'operation_id': selector['operation_id']} if 'operation_id' in selector
            else {'change_id': selector['change_id']})
    if binding.get('storage_format') == 'shared-observation-dag-6':
        from .evaluation_shared import query_shared_prediction
        return {'prediction_id': prediction_id, 'binding': deepcopy(binding),
                'evidence': query_shared_prediction(output, actual, **args)}
    if binding['mode'] == 'replay':
        if prepared_projection(output) is not None:
            evidence = terminal_replay_evidence(output, actual, **args)
        else:
            from .replay_export import query_task
            evidence = query_task(output, binding['final_snapshot']['snapshot_number'], **args)
    elif binding['mode'] == 'single_source':
        from .single_source_export import query_task
        evidence = query_task(output, **args)
    else:
        cache = request_cache(output)
        if cache is None:
            from .dual_source_export import query_task
            evidence = query_task(output, **args)
        else:
            from .dual_source import resolve_verified_selection
            analysis = retained_analysis(output)
            root = Path(output) / 'dual'
            evidence = resolve_verified_selection(root, analysis, _read(root / 'manifest.json'), **args)
    return {'prediction_id': prediction_id, 'binding': deepcopy(binding), 'evidence': evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', required=True)
    parser.add_argument('--batch', required=True)
    parser.add_argument('--sample-sha256', required=True)
    parser.add_argument('--projection', choices=('network', 'process', 'dual'), default='dual')
    parser.add_argument('--service-publication-sha256', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        with service_publication(args.artifact, args.service_publication_sha256):
            result = adapt_artifact(args.artifact, batch=args.batch, sample_sha256=args.sample_sha256,
                                    projection=args.projection)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
