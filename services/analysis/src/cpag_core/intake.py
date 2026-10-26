"""Offline, metadata-only raw batch preflight. This does not invoke analysis."""
import argparse
import json
from pathlib import Path
import sys

from .contracts import ContractError, validate
from .pipeline import canonical, file_hash, fingerprint


FORMAT_BY_KIND = {
    'network': {'.pcap', '.pcapng'},
    'process': {'.csv', '.xls', '.xlsx'},
}
ERROR_EXIT = {
    'missing_file': 11,
    'checksum_mismatch': 12,
    'unsafe_path': 13,
    'batch_conflict': 14,
    'unsupported_format': 15,
    'manifest_invalid': 16,
    'config_invalid': 16,
    'file_changed': 12,
}
ERROR_ORDER = tuple(ERROR_EXIT)
MATERIAL_FIELDS = (
    ('authorization', ('allowed_use', 'evidence_ref', 'reviewer')),
    ('time_basis', ('timezone', 'precision', 'synchronization', 'evidence_ref')),
    ('mapping', ('field_units_ref', 'device_map_ref', 'effective_period_ref')),
)


def _declared(section, fields):
    return isinstance(section, dict) and all(
        isinstance(section.get(field), str) and section[field].strip()
        for field in fields
    )


def _safe_file(root, name):
    """Return a regular file within raw root, never following a symlink."""
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('unsafe_path')
    relative = Path(name)
    if relative.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('unsafe_path')
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('unsafe_path')
    if not current.resolve(strict=False).is_relative_to(root.resolve()):
        raise ValueError('unsafe_path')
    if not current.exists():
        raise ValueError('missing_file')
    if not current.is_file():
        raise ValueError('unsafe_path')
    return current


def _read_object(path):
    def reject_constant(value):
        raise ValueError('nonfinite JSON value')
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'), parse_constant=reject_constant)
    except (OSError, UnicodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def preflight(raw_root, manifest_path, config_path):
    """Return a deterministic report with no local paths or source metadata values."""
    root = Path(raw_root)
    manifest = _read_object(manifest_path)
    config = _read_object(config_path)
    errors = set()
    gaps = set()
    verified = []
    source_kinds = set()
    if manifest is None:
        errors.add('manifest_invalid')
    else:
        try:
            validate('DatasetManifest', manifest)
        except (ContractError, OSError, ValueError):
            errors.add('manifest_invalid')
    if (config is None or not isinstance(config.get('dataset_id'), str) or
            not config['dataset_id'].strip() or type(config.get('synthetic')) is not bool):
        errors.add('config_invalid')
    if manifest is not None and config is not None and 'manifest_invalid' not in errors and 'config_invalid' not in errors:
        if config['dataset_id'] != manifest['dataset_id']:
            errors.add('batch_conflict')
        if config['synthetic'] != manifest['synthetic']:
            errors.add('batch_conflict')
    if root.is_symlink() or not root.is_dir():
        errors.add('unsafe_path')
    if manifest is not None and 'manifest_invalid' not in errors:
        names = set()
        if not manifest['files']:
            errors.add('manifest_invalid')
        for entry in manifest['files']:
            name, kind = entry['name'], entry['kind']
            source_kinds.add(kind)
            if name in names:
                errors.add('batch_conflict')
            names.add(name)
            if 'unsafe_path' in errors and (root.is_symlink() or not root.is_dir()):
                continue
            try:
                path = _safe_file(root, name)
            except ValueError as exc:
                if str(exc) == 'missing_file' and Path(name).suffix.lower() not in FORMAT_BY_KIND[kind]:
                    errors.add('unsupported_format')
                else:
                    errors.add(str(exc))
                continue
            if path.suffix.lower() not in FORMAT_BY_KIND[kind]:
                errors.add('unsupported_format')
                continue
            try:
                before = path.stat()
                actual = file_hash(path)
                after = path.stat()
            except OSError:
                errors.add('file_changed')
                continue
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                errors.add('file_changed')
            elif actual != entry['sha256'] or after.st_size != entry['size_bytes']:
                errors.add('checksum_mismatch')
            else:
                verified.append({'kind': kind, 'sha256': actual, 'size_bytes': after.st_size})
    if manifest is not None and 'manifest_invalid' not in errors and not manifest['authorization_ref'].strip():
        gaps.add('authorization')
    if manifest is not None and 'manifest_invalid' not in errors:
        for field in ('source', 'release'):
            if not manifest[field].strip():
                gaps.add(field)
    for section, fields in MATERIAL_FIELDS:
        if config is None or not _declared(config.get(section), fields):
            gaps.add(section)
    # A declared reference is a lead for manual review, never proof of permission.
    if not errors and len(source_kinds) == 1:
        gaps.add('second_source')
    source_scope = ('network_only' if source_kinds == {'network'} else
                    'process_only' if source_kinds == {'process'} else
                    'dual_source' if source_kinds == {'network', 'process'} else 'unknown')
    input_fp = None
    if not errors and len(verified) == len(manifest['files']):
        input_fp = fingerprint(sorted(verified, key=lambda item: (item['kind'], item['sha256'], item['size_bytes'])))
    # Fingerprint declared config values without reproducing them in either report.
    config_fp = None
    if config is not None:
        safe_config = {'dataset_id': config.get('dataset_id'), 'synthetic': config.get('synthetic'),
                       'declarations': {section: {field: config.get(section, {}).get(field)
                                                  for field in fields}
                                        if isinstance(config.get(section), dict) else None
                                        for section, fields in MATERIAL_FIELDS}}
        config_fp = fingerprint(safe_config)
    status = ('invalid' if errors else 'single_source_review' if source_scope != 'dual_source'
              else 'material_gaps' if gaps else 'ready_for_manual_review')
    exit_code = next((ERROR_EXIT[code] for code in ERROR_ORDER if code in errors),
                     2 if status != 'ready_for_manual_review' else 0)
    return {
        'report_version': '1.0.0', 'synthetic': bool(manifest.get('synthetic')) if manifest else None,
        'status': status, 'exit_code': exit_code, 'source_scope': source_scope,
        'input_fingerprint': input_fp, 'intake_config_fingerprint': config_fp,
        'verified_file_count': len(verified), 'declared_file_count': len(manifest['files']) if manifest and 'files' in manifest and isinstance(manifest['files'], list) else 0,
        'errors': [code for code in ERROR_ORDER if code in errors],
        'material_gaps': sorted(gaps), 'collection_range_status': 'unknown',
        'authorization_status': 'requires_manual_review',
        'alignment_status': 'not_verified',
        'next_step': ('fix_package' if errors else 'review_single_source_only' if source_scope != 'dual_source'
                      else 'supply_materials' if gaps else 'manual_intake_review'),
        'limitations': ['Metadata and file integrity only; no parsing, clock alignment, authorization verification, or industrial validation.'],
    }


def human_report(report):
    lines = [f"P1 intake preflight: {report['status']} (exit {report['exit_code']})",
             f"Source scope: {report['source_scope']}",
             f"Files verified: {report['verified_file_count']}/{report['declared_file_count']}",
             f"Input fingerprint: {report['input_fingerprint'] or 'unavailable'}",
             f"Collection range: {report['collection_range_status']}; alignment: {report['alignment_status']}",
             f"Authorization: {report['authorization_status']}",
             f"Errors: {', '.join(report['errors']) if report['errors'] else 'none'}",
             f"Material gaps: {', '.join(report['material_gaps']) if report['material_gaps'] else 'none'}",
             f"Next step: {report['next_step']}", report['limitations'][0]]
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description='P1 offline raw batch metadata preflight')
    parser.add_argument('--raw-root', required=True)
    parser.add_argument('--manifest', required=True, help='DatasetManifest JSON')
    parser.add_argument('--config', required=True, help='batch config JSON')
    parser.add_argument('--output', required=True, help='new directory outside the raw root')
    parser.add_argument('--json', action='store_true', help='also print machine report to stdout')
    args = parser.parse_args(argv)
    root = Path(args.raw_root).resolve()
    output = Path(args.output).resolve()
    if output == root or output.is_relative_to(root):
        print('output_must_be_outside_raw_root', file=sys.stderr)
        return 17
    if output.exists():
        print('output_already_exists', file=sys.stderr)
        return 17
    report = preflight(args.raw_root, args.manifest, args.config)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'report.json').write_bytes(canonical(report) + b'\n')
    (output / 'report.txt').write_text(human_report(report), encoding='utf-8')
    print((canonical(report).decode() if args.json else human_report(report).rstrip()))
    return report['exit_code']


if __name__ == '__main__':
    sys.exit(main())
