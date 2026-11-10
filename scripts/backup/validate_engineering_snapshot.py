"""Negative checks on a COPY of a real quiescent engineering snapshot."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import engineering

source = Path(sys.argv[1])
meta, data = engineering.verify(source)
packet = next(row for row in data['rows'] if row['payload'].get('kind') == 'packet' and row['state'] == 'succeeded')
cases = {
    'missing_original_capture': 'host/shared/'+packet['payload']['network']['path'],
    'tampered_original_capture': 'host/shared/'+packet['payload']['network']['path'],
    'missing_published_manifest': 'host/shared/'+packet['artifact_path'],
    'tampered_capacity_ledger': 'host/control/capacity.json',
    'tampered_database_dump': 'database-and-shared/database.dump',
}
proofs = sorted((source/'host/control').rglob('exit.json'))
if not proofs:
    raise ValueError('real exit receipt required for control-evidence negative check')
cases['missing_exit_receipt'] = str(proofs[0].relative_to(source))
result = {}
for case, relative in cases.items():
    with tempfile.TemporaryDirectory(prefix='snapshot-negative-', dir=source.parent) as temporary:
        target = Path(temporary)/'copy'
        shutil.copytree(source, target)
        path = target/relative
        if case.startswith('missing_'):
            path.unlink()
        else:
            path.chmod(0o600)
            with path.open('ab') as stream: stream.write(b'corruption')
        try: engineering.verify(target)
        except (ValueError, OSError): result[case] = 'rejected_before_restore'
        else: raise AssertionError('snapshot accepted '+case)
engineering.verify(source)
print(json.dumps({'valid': True, 'synthetic_only': True, 'source_unchanged': True, 'cases': result}, indent=2))
