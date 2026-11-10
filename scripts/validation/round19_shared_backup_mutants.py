#!/usr/bin/env python3
"""Six bounded format7 restore rejection checks over separate bundle copies.

No task is computed. The subprocess tripwire proves every mutant is rejected
before any database command, so an existing restored database cannot be touched.
The successful input bundle and every failed mutant remain byte-inspectable.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts/backup'))
import bundle


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def rejection_checks(container, source, output):
    source = Path(source).resolve()
    output = Path(output).resolve()
    if output.exists() or output.is_relative_to(source):
        raise ValueError('new mutant output outside source bundle required')
    snapshot = json.loads((source / 'bundle.json').read_text())
    if snapshot.get('format_version') != 7:
        raise ValueError('successful format7 input bundle required')
    candidates = [row for row in snapshot['rows'] if row['state'] == 'succeeded' and
                  row['payload'].get('storage_format') == 'shared-observation-dag-6']
    if not candidates or not snapshot.get('verifiers'):
        raise ValueError('real successful DAG6 plus exited verifier input required')
    selected = candidates[0]
    base = f"jobs/{selected['id']}/attempt-{selected['attempt']}"
    unchanged = bundle.inventory(source)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []
    for mutant in ('missing_database', 'same_size_source_tamper', 'wrong_run_identity',
                   'unknown_format', 'unexited_verifier', 'unexited_attempt'):
        case = output / mutant
        case.mkdir(mode=0o700)
        copied = case / 'bundle'
        shutil.copytree(source, copied)
        document = deepcopy(snapshot)
        if mutant == 'missing_database':
            target = copied / 'files' / base / 'shared/shared.sqlite3'
            target.parent.chmod(0o700)
            target.unlink()
        elif mutant == 'same_size_source_tamper':
            target = copied / 'files' / base / 'sources/process.csv'
            target.chmod(0o600)
            raw = target.read_bytes()
            if not raw:
                raise AssertionError('nonempty_original_process_required')
            target.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
            if target.stat().st_size != len(raw):
                raise AssertionError('same_size_mutation_failed')
        elif mutant == 'wrong_run_identity':
            next(row for row in document['rows'] if row['id'] == selected['id'])['id'] = 'wrong-run-identity'
        elif mutant == 'unknown_format':
            document['format_version'] = 999
        elif mutant == 'unexited_verifier':
            document['verifiers'][0].update(state='running', exited_at=None)
        else:
            if not document.get('attempts'):
                raise AssertionError('actual_terminal_attempts_required')
            document['attempts'][0]['exited_at'] = None
        write(copied / 'bundle.json', document)
        destination = case / 'restored-root'
        control = case / 'restored-control'
        calls = []
        def no_database_command(*args, **kwargs):
            calls.append(args[0] if args else None)
            raise AssertionError('restore_mutant_reached_database_command')
        try:
            with patch.object(bundle.subprocess, 'run', side_effect=no_database_command):
                bundle.restore(container, copied, destination, control_destination=control)
        except ValueError as error:
            audit = json.loads((case / 'restored-root-audit.json').read_text())
            if audit.get('valid') is not False or audit.get('phase') not in ('bundle_integrity', 'pre_restore_references'):
                raise AssertionError('mutant_not_rejected_in_pre_database_validation') from error
            if calls or destination.exists():
                raise AssertionError('mutant_reached_database_or_restored_files')
            write(case / 'rejection.json', {'mutant': mutant, 'error_type': type(error).__name__,
                                           'reason': str(error), 'audit': audit,
                                           'database_commands': calls})
            checks.append({'mutant': mutant, 'status': 'rejected', 'phase': audit['phase'],
                           'database_command_count': 0, 'restore_files_created': False})
        else:
            raise AssertionError('restore_mutant_was_accepted:' + mutant)
        if bundle.inventory(source) != unchanged:
            raise AssertionError('original_successful_bundle_changed')
    result = {'status': 'passed', 'scope': 'stored format7 restore preflight; no new computation or database writes',
              'original_bundle_inventory_unchanged': True, 'checks': checks}
    write(output / 'report.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = rejection_checks(args.container, args.bundle, args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
