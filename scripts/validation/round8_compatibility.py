"""Read-only inspection of the two explicitly supported synthetic history formats."""
import argparse
import json
from pathlib import Path
import sys

from cpag_core.contracts import ContractError, validate
from cpag_core.evidence import EvidenceIndex
from cpag_core.packet_job import verify_artifacts as verify_packet_artifacts
from cpag_core.pipeline import file_hash, fingerprint, resolve_evidence


CORE_FILES = {'dataset.json', 'events.json', 'graph.json', 'quality.json', 'run_manifest.json'}


def _regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('missing_or_nonregular_file')
    return path


def _read(path):
    return json.loads(_regular(path).read_text(encoding='utf-8'))


def _sources(dataset, network, process, *, index_evidence):
    files = dataset['files']
    if len(files) != 2 or {f['kind'] for f in files} != {'network', 'process'}:
        raise ValueError('unsupported_source_membership')
    paths = {'network': _regular(network), 'process': _regular(process)}
    indexes = {}
    for entry in files:
        path = paths[entry['kind']]
        if file_hash(path) != entry['sha256'] or path.stat().st_size != entry['size_bytes']:
            raise ValueError('original_source_mismatch')
        if index_evidence:
            indexes[entry['kind']] = EvidenceIndex(path, entry['sha256'])
    identity = fingerprint([{k: v for k, v in entry.items() if k != 'name'} for entry in files])
    return indexes, identity


def inspect_history(kind, artifacts, network, process):
    """Verify without writing to artifacts or source files; reject unknown formats."""
    if kind not in {'normalized', 'packet'}:
        raise ValueError('unsupported_history_kind')
    root = Path(artifacts)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('missing_or_nonregular_artifact_directory')
    for name in CORE_FILES | ({'packet_observations.json'} if kind == 'packet' else set()):
        _regular(root / name)
    dataset = _read(root / 'dataset.json')
    manifest = _read(root / 'run_manifest.json')
    validate('DatasetManifest', dataset)
    validate('RunManifest', manifest)
    if dataset['synthetic'] is not True or manifest['synthetic'] is not True:
        raise ValueError('historical_real_data_not_supported')
    indexes, input_fp = _sources(dataset, network, process, index_evidence=kind == 'normalized')
    if input_fp != manifest['input_fingerprint']:
        raise ValueError('history_input_fingerprint_mismatch')
    expected = CORE_FILES - {'run_manifest.json'}
    if kind == 'packet':
        expected.add('packet_observations.json')
    entries = manifest['artifacts']
    if len(entries) != len(expected) or {entry['path'] for entry in entries} != expected:
        raise ValueError('unsupported_artifact_membership')
    for entry in entries:
        path = _regular(root / entry['path'])
        if path.stat().st_size != entry['size_bytes'] or file_hash(path) != entry['sha256']:
            raise ValueError('history_artifact_mismatch')
    if kind == 'packet':
        sidecar = verify_packet_artifacts(root, network)
        if not dataset['synthetic'] or not sidecar['synthetic']:
            raise ValueError('packet_synthetic_mismatch')
        return {'status': 'verified_synthetic_format', 'kind': kind,
                'input_fingerprint': input_fp, 'event_count': len(sidecar['events']),
                'limitations': 'Synthetic packet contract only; historical real instance unverified.'}
    events = _read(root / 'events.json')
    graph = _read(root / 'graph.json')
    _read(root / 'quality.json')
    validate('GraphArtifact', graph)
    if graph['synthetic'] is not True or graph['input_fingerprint'] != input_fp:
        raise ValueError('history_graph_identity_mismatch')
    if manifest['result_hashes'] != {'events': fingerprint(events), 'graph': fingerprint(graph)}:
        raise ValueError('history_result_hash_mismatch')
    if not isinstance(events, list) or len(graph['nodes']) != len(events):
        raise ValueError('history_event_membership_mismatch')
    source_by_digest = {index.digest: index for index in indexes.values()}
    event_ids = []
    event_by_id = {}
    for event in events:
        kind_name = 'process' if 'tag' in event else 'network'
        validate('ProcessObservation' if kind_name == 'process' else 'NetworkEvent', event)
        if event['synthetic'] is not True:
            raise ValueError('history_event_synthetic_mismatch')
        resolve_evidence(event['source_ref'], source_by_digest)
        event_ids.append(event['event_id'])
        event_by_id[event['event_id']] = event
    if len(set(event_ids)) != len(event_ids) or {node['event_id'] for node in graph['nodes']} != set(event_ids):
        raise ValueError('history_graph_event_mismatch')
    for node in graph['nodes']:
        if node['evidence_refs'] != [event_by_id[node['event_id']]['source_ref']]:
            raise ValueError('history_node_evidence_mismatch')
        for ref in node['evidence_refs']:
            resolve_evidence(ref, source_by_digest)
    for index in indexes.values():
        index.verify()
    return {'status': 'verified_synthetic_format', 'kind': kind,
            'input_fingerprint': input_fp, 'event_count': len(events),
            'limitations': 'Synthetic normalized core format only; historical real instance unverified.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', required=True, choices=('normalized', 'packet'))
    parser.add_argument('--artifacts', required=True)
    parser.add_argument('--network', required=True)
    parser.add_argument('--process', required=True)
    args = parser.parse_args(argv)
    try:
        report = inspect_history(args.kind, args.artifacts, args.network, args.process)
    except (ValueError, OSError, ContractError, KeyError, TypeError, UnicodeError) as exc:
        print(json.dumps({'status': 'rejected', 'reason': type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
