"""Explicit versioned offline single-source execution using the shared core.

Only the declared source is opened or retained. The absent source has no input
file, placeholder data or evidence references. Its prepared empty side is marked
unavailable, and cannot establish a cross-source association. Existing dual and
replay execution, publication and historical-version dispatch remain unchanged.
"""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import platform
import shutil
import uuid

from . import __version__
from .contracts import validate
from .dual_source import (_analyze_prepared, references, strict_json, R17_VERSION,
                          network_names)
from .dual_source_export import event_graph
from .dual_source_rules import validate_profile
from .evidence import EvidenceIndex
from .packet_pipeline import analyze_capture, PacketEvidence
from .parsers import parse_process
from .pipeline import canonical, file_hash, fingerprint


VERSION = 'bounded-single-source-1'
STANDARD = frozenset(('dataset.json', 'events.json', 'graph.json', 'quality.json',
                      'analysis.json', 'run_manifest.json'))
NETWORK_BYTES = 16 * 1024 * 1024
PROCESS_BYTES = 2 * 1024 * 1024
PROFILE_BYTES = 65536
OUTPUT_BYTES = 16 * 1024 * 1024


def _read(path):
    return strict_json(Path(path).read_text(encoding='utf-8'))


def _paths(source_mode, source):
    if source_mode not in ('network', 'process'):
        raise ValueError('unsupported_single_source_mode')
    paths = list(source) if isinstance(source, (list, tuple)) else [source]
    if (source_mode == 'network' and not 1 <= len(paths) <= 4) or (source_mode == 'process' and len(paths) != 1):
        raise ValueError('single_source_file_limit')
    paths = [Path(path) for path in paths]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError('invalid_single_source_file')
    limit = NETWORK_BYTES if source_mode == 'network' else PROCESS_BYTES
    if sum(path.stat().st_size for path in paths) > limit:
        raise ValueError('single_source_input_size_limit')
    return paths


def _names(source_mode, count):
    return network_names(count) if source_mode == 'network' else ['process.csv']


def _rows(source_mode, paths):
    return [{'kind': source_mode, 'sha256': file_hash(path), 'size_bytes': path.stat().st_size}
            for path in paths]


def analyze_sources(source_mode, source, config):
    """Read one actual source and invoke unchanged prepared-source operators."""
    paths = _paths(source_mode, source)
    if not validate_profile(config):
        raise ValueError('single_source_requires_explicit_bounded_profile')
    if 'replay' in config:
        raise ValueError('single_source_offline_profile_cannot_declare_replay')
    if not 1 <= len(config['process']['columns']) <= 16 or len(config['mappings']) > 100:
        raise ValueError('profile_size_limit')
    rule_ids = [row['rule_id'] for row in config['mappings']]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError('duplicate_rule_id')
    before = _rows(source_mode, paths)
    presence = {'network': source_mode == 'network', 'process': source_mode == 'process'}
    # This in-memory absent side is explicitly unavailable, never an input file
    # and never an observation. The shared core already handles empty prefixes.
    capture = {'events': [], 'observations': [], 'unsupported': []}
    parsed = {'events': [], 'quality': {'status': 'not_supplied', 'event_count': 0,
                                      'reasons': ['process_source_not_supplied']}}
    packet = None; verify_sources = None
    if source_mode == 'network':
        network = paths if len(paths) > 1 else paths[0]
        capture = analyze_capture(network, synthetic=config['synthetic'], extended=True)
        if not capture['events']:
            raise ValueError('unsupported_or_empty_network')
        packet = PacketEvidence(network, synthetic=config['synthetic'])
    else:
        index = EvidenceIndex(paths[0])
        if sum(1 for _ in csv.reader(io.StringIO(index.text), strict=True)) - 1 > 1000:
            raise ValueError('process_record_limit')
        parsed = parse_process(paths[0], config['process'], synthetic=config['synthetic'],
                               evidence=index, extended=True)
        if parsed['quality']['status'] == 'unsupported' or not parsed['events']:
            raise ValueError('unsupported_or_empty_process')
        if any(reason.startswith(('invalid_csv_record_width', 'invalid_or_truncated_csv'))
               for reason in parsed['quality']['reasons']):
            raise ValueError('malformed_csv_cannot_establish_adjacent_observations')
        verify_sources = index.verify
    result = _analyze_prepared(capture, parsed, packet, config, fingerprint(before),
        allow_empty=True, source_contract='offline', _analysis_version=R17_VERSION,
        verify_sources=verify_sources)
    if before != _rows(source_mode, paths):
        raise ValueError('single_source_changed_during_analysis')
    result.update(analysis_version=VERSION, base_analysis_version=R17_VERSION,
                  single_source_version=VERSION, source_mode=source_mode, source_presence=presence)
    result['quality']['source_presence'] = presence.copy()
    result['quality']['unknown_reasons'] = sorted(set(result['quality']['unknown_reasons'] +
        [('process' if source_mode == 'network' else 'network') + '_source_not_supplied']))
    result['limitations'] = [*result['limitations'], 'explicit_single_source_observation_only',
                             'absent_other_source_not_observed_empty_or_evidence',
                             'cross_source_association_unavailable']
    if result['candidates']:
        raise ValueError('single_source_cannot_publish_cross_source_candidates')
    return result


def _payloads(source_mode, paths, config):
    analysis = analyze_sources(source_mode, paths, config)
    dataset = {'schema_version': '1.0.0', 'synthetic': config['synthetic'],
        'dataset_id': 'single-source-dataset-' + analysis['input_fingerprint'],
        'source': 'explicitly declared retained single-source inputs', 'release': VERSION,
        'files': [dict(row, name=name) for row, name in zip(_rows(source_mode, paths), _names(source_mode, len(paths)))],
        'collection_range': {'start': None, 'end': None},
        'timezone_basis': 'versioned configured clock of provided source only',
        'authorization_ref': 'declared source authorization; not industrial validation'}
    if config['synthetic'] is False:
        dataset.update({key: config['source_provenance'][key] for key in
                        ('source', 'release', 'collection_range', 'timezone_basis', 'authorization_ref')})
    validate('DatasetManifest', dataset)
    return {'dataset.json': dataset, **event_graph(analysis),
            'quality.json': analysis['quality'], 'analysis.json': analysis}


def _warnings(analysis):
    reasons = analysis['quality']['unknown_reasons'] + ['single_source_observation_only']
    if analysis['synthetic'] is False:
        reasons.append('real_source_unvalidated')
    if analysis['quality']['network_unsupported']:
        reasons.append('unsupported_network_records_present')
    reasons += analysis['quality']['process']['reasons']
    if any(finding['state'] == 'unknown' for finding in analysis.get('rule_findings', [])):
        reasons.append('finite_rules_have_unknown_findings')
    return sorted(set(reasons))


def _inventory(root, expected):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('invalid_single_source_root')
    found = set(); directories = set()
    for base, children, files in os.walk(root, followlinks=False):
        for name in children + files:
            if (Path(base) / name).is_symlink():
                raise ValueError('symlink_artifact')
        directories.update((Path(base) / name).relative_to(root).as_posix() for name in children)
        for name in files:
            path = Path(base) / name
            if not path.is_file():
                raise ValueError('nonregular_artifact')
            found.add(path.relative_to(root).as_posix())
    if found != expected or directories != {'sources'}:
        raise ValueError('single_source_inventory_mismatch')


def verify_task(output):
    root = Path(output)
    if root.is_symlink() or not root.is_dir() or (root / 'run_manifest.json').is_symlink():
        raise ValueError('invalid_single_source_root')
    manifest = _read(root / 'run_manifest.json')
    validate('SingleSourceRunManifest', manifest)
    if (root / 'run_manifest.json').read_bytes() != canonical(manifest) + b'\n':
        raise ValueError('run_manifest_encoding_mismatch')
    mode = manifest['source_mode']; source_files = manifest['source_files']
    if (not 1 <= len(source_files) <= (4 if mode == 'network' else 1)
            or source_files != ['sources/' + name for name in _names(mode, len(source_files))]):
        raise ValueError('single_source_input_inventory_mismatch')
    expected = STANDARD | {'sources/profile.json', *source_files}
    _inventory(root, expected)
    entries = manifest['artifacts']
    if len(entries) != len(expected) - 1 or {row['path'] for row in entries} != expected - {'run_manifest.json'}:
        raise ValueError('single_source_manifest_inventory_mismatch')
    for entry in entries:
        path = root / entry['path']
        if file_hash(path) != entry['sha256'] or path.stat().st_size != entry['size_bytes']:
            raise ValueError('single_source_artifact_integrity_mismatch: ' + entry['path'])
    if sum((root / name).stat().st_size for name in expected) > OUTPUT_BYTES:
        raise ValueError('single_source_output_limit')
    if (root / 'sources/profile.json').stat().st_size > PROFILE_BYTES:
        raise ValueError('single_source_profile_size_limit')
    config = _read(root / 'sources/profile.json')
    payloads = _payloads(mode, [root / name for name in source_files], config)
    for name, payload in payloads.items():
        if (root / name).read_bytes() != canonical(payload) + b'\n':
            raise ValueError('single_source_semantic_mismatch: ' + name)
    analysis = payloads['analysis.json']
    if (manifest['input_fingerprint'] != analysis['input_fingerprint']
            or manifest['config_fingerprint'] != analysis['config_fingerprint']
            or manifest['synthetic'] is not analysis['synthetic']
            or manifest['source_presence'] != analysis['source_presence']
            or manifest['analysis_version'] != analysis['analysis_version']
            or manifest['base_analysis_version'] != analysis['base_analysis_version']
            or manifest['limitations'] != analysis['limitations']
            or manifest['warnings'] != _warnings(analysis)
            or manifest['result_hashes'] != {'events': fingerprint(payloads['events.json']),
                                              'graph': fingerprint(payloads['graph.json'])}):
        raise ValueError('single_source_manifest_binding_mismatch')
    return manifest


def export_task(source_mode, source, profile, output, *, run_id=None, attempt_id=1):
    """Publish a new immutable run, retaining no absent-source file."""
    if (run_id is not None and (not isinstance(run_id, str) or not 1 <= len(run_id) <= 128)
            or type(attempt_id) is not int or attempt_id < 1):
        raise ValueError('invalid_execution_identity')
    paths = _paths(source_mode, source); profile = Path(profile); root = Path(output)
    if profile.is_symlink() or not profile.is_file() or profile.stat().st_size > PROFILE_BYTES:
        raise ValueError('invalid_or_oversize_single_source_profile')
    config = _read(profile)
    # Validate mode/config before reserving output or copying sources.
    if not validate_profile(config) or 'replay' in config:
        raise ValueError('explicit_bounded_offline_profile_required')
    before = _rows(source_mode, paths); profile_hash = file_hash(profile)
    if root.exists() or root.is_symlink():
        raise ValueError('output_already_exists')
    root.mkdir(parents=True)
    try:
        source_root = root / 'sources'; source_root.mkdir()
        names = _names(source_mode, len(paths))
        for path, name in zip(paths, names):
            shutil.copyfile(path, source_root / name)
        shutil.copyfile(profile, source_root / 'profile.json')
        retained = [source_root / name for name in names]
        if before != _rows(source_mode, retained) or file_hash(source_root / 'profile.json') != profile_hash:
            raise ValueError('single_source_changed_during_copy')
        payloads = _payloads(source_mode, retained, config)
        for name, payload in payloads.items():
            (root / name).write_bytes(canonical(payload) + b'\n')
        if before != _rows(source_mode, paths) or file_hash(profile) != profile_hash:
            raise ValueError('single_source_changed_during_execution')
        analysis = payloads['analysis.json']
        expected = STANDARD | {'sources/profile.json', *('sources/' + name for name in names)}
        entries = [{'path': name, 'sha256': file_hash(root / name), 'size_bytes': (root / name).stat().st_size}
                   for name in sorted(expected - {'run_manifest.json'})]
        manifest = {'schema_version': '1.0.0', 'synthetic': config['synthetic'],
            'single_source_version': VERSION, 'analysis_version': VERSION,
            'base_analysis_version': R17_VERSION, 'source_mode': source_mode,
            'source_presence': analysis['source_presence'], 'source_files': ['sources/' + name for name in names],
            'run_id': run_id or str(uuid.uuid4()), 'attempt_id': attempt_id,
            'input_fingerprint': analysis['input_fingerprint'], 'config_fingerprint': analysis['config_fingerprint'],
            'tool_versions': {'core': __version__, 'python': platform.python_version()},
            'mode': 'single_source', 'artifacts': entries,
            'result_hashes': {'events': fingerprint(payloads['events.json']), 'graph': fingerprint(payloads['graph.json'])},
            'limitations': analysis['limitations'], 'status': 'succeeded_with_warnings', 'warnings': _warnings(analysis)}
        validate('SingleSourceRunManifest', manifest)
        (root / 'run_manifest.json').write_bytes(canonical(manifest) + b'\n')
        verify_task(root)
        return manifest
    except Exception:
        shutil.rmtree(root)
        raise


def query_task(output, operation_id=None, change_id=None):
    """Verify and resolve only the actual retained source through existing indexes."""
    root = Path(output); manifest = verify_task(root)
    if (operation_id is None) == (change_id is None):
        raise ValueError('select_exactly_one_operation_or_change')
    analysis = _read(root / 'analysis.json')
    mode = manifest['source_mode']
    if operation_id is not None:
        if mode != 'network':
            raise KeyError('network_source_not_supplied')
        matches = analysis['operations'][:1] if operation_id == 'first' else [row for row in analysis['operations'] if row['operation_id'] == operation_id]
        if len(matches) != 1:
            raise KeyError('unknown_operation')
        selected = {'operation': matches[0], 'candidates': [], 'changes': []}
    else:
        if mode != 'process':
            raise KeyError('process_source_not_supplied')
        matches = analysis['changes'][:1] if change_id == 'first' else [row for row in analysis['changes'] if row['event_id'] == change_id]
        findings = [row for row in analysis.get('rule_findings', []) if row['finding_id'] == change_id]
        if len(matches) + len(findings) != 1:
            raise KeyError('unknown_change')
        selected = {'change': matches[0]} if matches else {'rule_finding': findings[0]}
    refs = references(selected); fields = []
    if mode == 'network':
        paths = [root / name for name in manifest['source_files']]
        index = PacketEvidence(paths if len(paths) > 1 else paths[0], synthetic=manifest['synthetic'])
        frames = {(ref['file_sha256'], ref['frame_number']) for ref in refs}
        for row in analysis['network']:
            if any((ref['file_sha256'], ref['frame_number']) in frames for ref in row['observation']['source_refs']):
                fields.append({'event_id': row['event']['event_id'], 'fields': {
                    name: [index.resolve(piece['source_ref'], piece) for piece in field['slices']]
                    for name, field in row['observation']['fields'].items()}})
    else:
        index = EvidenceIndex(root / 'sources/process.csv')
    evidence = [{'source_ref': ref, 'original': index.resolve(ref)} for ref in refs]
    if mode == 'process':
        index.verify()
    return {'synthetic': manifest['synthetic'], 'source_mode': mode,
            'source_presence': manifest['source_presence'], 'selection': selected,
            'verified_original_evidence': evidence, 'verified_network_fields': fields,
            'config_fingerprint': manifest['config_fingerprint'], 'limitations': analysis['limitations']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-mode', choices=('network', 'process'))
    parser.add_argument('--source', action='append')
    parser.add_argument('--profile')
    parser.add_argument('--output', required=True)
    parser.add_argument('--run-id'); parser.add_argument('--attempt-id', type=int, default=1)
    parser.add_argument('--verify', action='store_true')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--operation'); group.add_argument('--change')
    args = parser.parse_args()
    try:
        if args.operation is not None or args.change is not None:
            result = query_task(args.output, operation_id=args.operation, change_id=args.change)
        elif args.verify:
            result = verify_task(args.output)
        else:
            if not all((args.source_mode, args.source, args.profile)):
                raise ValueError('source_mode_source_profile_required')
            result = export_task(args.source_mode, args.source, args.profile, args.output,
                                 run_id=args.run_id, attempt_id=args.attempt_id)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
