"""Small formal publication versus an independent complete DAG6 core export.

This is a bounded acceptance oracle over the same original inputs/configuration,
not a new analysis algorithm. Never call it for S100/M/L. The normal formal
publication remains immutable; the independent export and every failed check
remain under the supplied new diagnostic output directory.
"""
import hashlib
import json
from pathlib import Path
import shutil
import time

from cpag_core import shared_export as core
from cpag_core.pipeline import canonical, file_hash, fingerprint

VERSION = 'small-formal-complete-business-roots-1'
# Fixed before any independent export. Using identical run/attempt removes the
# need to delete/normalize identity-bearing fields anywhere inside business roots.
POLICY = {
    'identity': 'same_explicit_run_id_attempt_id_mode_and_exact_business_configuration',
    'permitted_business_identity_differences': [],
    'business_comparison': 'complete_named_logical_root_inventory_and_exact_typed_merkle_descriptors',
    'volatile_telemetry_roots': ['runtime_metrics.json'],
    'telemetry_reason': 'actual measured wall/CPU/resource samples are retained but not business computation; same exclusion as full source verifier',
    'all_other_roots': 'exact; includes analysis, aliases, standard events/graph, quality, dataset, indices, metrics, arrivals, all snapshots and revisions',
    'small_limits': {'operations': 4, 'snapshots': 64, 'physical_bytes_per_export': 32 * 1024**2,
                     'independent_export_seconds': 60},
    'scope': 'small synthetic software business-equivalence evidence only; no capacity or industrial accuracy claim',
}


def _write(path, value):
    Path(path).write_bytes(canonical(value) + b'\n')


def compare_all_business_roots(artifact, networks, process, profile, output, *, expected_manifest=None):
    """Return exact complete-root evidence, preserving artifacts on every failure.

    ``networks/process/profile`` are the original admitted fixture, not selected
    published business results. The service-provided expected manifest optionally
    binds the local published bytes to the already authenticated HTTP read.
    """
    artifact = Path(artifact).resolve(); output = Path(output).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    began = time.monotonic(); report = {'version': VERSION, 'status': 'in_progress',
        'policy': POLICY, 'formal_artifact': str(artifact), 'output': str(output)}
    _write(output / 'policy.json', POLICY)
    try:
        manifest = core.read_json(artifact / 'run_manifest.json', 65536)
        if expected_manifest is not None and canonical(manifest) != canonical(expected_manifest):
            raise ValueError('formal_service_and_physical_manifest_mismatch')
        if manifest['storage_format'] != core.FORMAT or manifest['counts']['operations'] > POLICY['small_limits']['operations'] or manifest['counts']['snapshots'] > POLICY['small_limits']['snapshots']:
            raise ValueError('small_complete_business_check_only')
        if (artifact / 'run_manifest.json').read_bytes() != canonical(manifest) + b'\n':
            raise ValueError('formal_manifest_canonical_encoding_changed')
        original_config = core.read_json(profile)
        retained_config = core.read_json(artifact / 'sources/profile.json')
        if (canonical(original_config) != canonical(retained_config)
                or fingerprint(original_config) != manifest['config_fingerprint']):
            raise ValueError('formal_and_original_business_configuration_mismatch')
        networks = [Path(path) for path in networks]
        if len(networks) != manifest['network_count']:
            raise ValueError('formal_and_original_network_inventory_mismatch')
        originals = list(zip(networks, ['sources/' + name for name in core.network_names(len(networks))]))
        originals.append((Path(process), 'sources/process.csv'))
        report['original_source_sha256'] = {}
        for original, retained_name in originals:
            digest = file_hash(original)
            if digest != file_hash(artifact / retained_name):
                raise ValueError('formal_retained_original_changed:' + retained_name)
            report['original_source_sha256'][retained_name] = digest
        report['original_config_fingerprint'] = fingerprint(original_config)
        report['identity'] = {name: manifest[name] for name in ('run_id', 'attempt_id', 'mode', 'input_fingerprint', 'config_fingerprint')}
        # Strip only publication *envelopes* from a byte-for-byte diagnostic copy.
        # No logical root, business field or original source is removed/rewritten.
        formal_copy = output / 'formal-core-copy'; formal_copy.mkdir(mode=0o700)
        inventory = {entry['path']: entry for entry in manifest['artifacts']}
        names = core.artifact_files_for_inputs(len(networks), mode=manifest['mode'])
        if set(inventory) != names - {'run_manifest.json'}:
            raise ValueError('formal_complete_physical_inventory_mismatch')
        physical_total = 0
        for name in sorted(names):
            source = artifact / name
            if source.is_symlink() or not source.is_file() or source.stat().st_nlink != 1:
                raise ValueError('ordinary_formal_physical_file_required')
            physical_total += source.stat().st_size
            if physical_total > POLICY['small_limits']['physical_bytes_per_export']:
                raise ValueError('small_complete_business_physical_budget')
            digest = file_hash(source)
            if name in inventory and (digest != inventory[name]['sha256'] or source.stat().st_size != inventory[name]['size_bytes']):
                raise ValueError('formal_physical_bytes_changed:' + name)
            destination = formal_copy / name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if file_hash(destination) != digest or file_hash(source) != digest:
                raise ValueError('formal_bytes_changed_during_diagnostic_copy')
        # Verify all stored nodes and declared root descriptors without running
        # another source computation against the published answer.
        with core.open_reader(formal_copy) as reader:
            published_roots = {item['name']: reader.descriptor(item['name']) for item in manifest['logical_artifacts']}
        reference = output / 'independent-core-export'
        reference_started = time.monotonic()
        rebuilt = core.export_task(networks, process, profile, reference,
            run_id=manifest['run_id'], attempt_id=manifest['attempt_id'], mode=manifest['mode'],
            deadline=reference_started + POLICY['small_limits']['independent_export_seconds'])
        report['independent_export_seconds'] = time.monotonic() - reference_started
        report['independent_core_export'] = str(reference)
        if sum(path.stat().st_size for path in reference.rglob('*') if path.is_file()) > POLICY['small_limits']['physical_bytes_per_export']:
            raise ValueError('small_independent_export_physical_budget')
        actual_roots = {item['name']: item for item in rebuilt['logical_artifacts']}
        if set(published_roots) != set(actual_roots):
            raise ValueError('complete_business_root_inventory_changed')
        comparisons = []; mismatches = []
        for name in sorted(published_roots):
            telemetry = name in POLICY['volatile_telemetry_roots']
            equal = published_roots[name] == actual_roots[name]
            comparisons.append({'name': name, 'business_root': not telemetry, 'exact_descriptor_equal': equal,
                'formal': published_roots[name], 'independent': actual_roots[name]})
            if not equal and not telemetry: mismatches.append(name)
        report.update(complete_named_root_count=len(comparisons),
            complete_business_root_count=sum(row['business_root'] for row in comparisons),
            comparisons=comparisons, unapproved_business_differences=mismatches,
            runtime_telemetry_preserved_in_both_exports=True)
        for name in ('run_id', 'attempt_id', 'mode', 'input_fingerprint', 'config_fingerprint',
                     'semantic_config_fingerprint', 'counts', 'result_hashes', 'warnings', 'limitations', 'status',
                     'final_snapshot_number', 'final_snapshot_id', 'storage_format', 'result_hash_kind',
                     'graph_identity_strategy', 'history_format', 'identity_strategy', 'prefix_digest_strategy'):
            if manifest.get(name) != rebuilt.get(name):
                raise ValueError('formal_and_independent_manifest_business_field_mismatch:' + name)
        # Include the exact raw manifests, all sources, databases and descriptors
        # as inspectable evidence; the comparison never reads a handpicked subset.
        if mismatches: raise ValueError('complete_business_root_mismatch:' + ','.join(mismatches))
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__, reason=str(error))
        raise
    finally:
        report['wall_seconds'] = time.monotonic() - began
        _write(output / 'comparison.json', report)
    return report
