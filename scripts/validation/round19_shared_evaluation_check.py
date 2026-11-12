"""One-run DAG6 saved-evaluation acceptance; never launches another analysis.

The expected table is handwritten, not inferred from predictions. This helper
freezes the actual service projection before a real local opening time, builds
ordinary versioned sidecars, and exercises their existing service imports. The
server must independently verify the projection and every binding on import.
Local timestamps and handwritten labels are declared provenance, not external
custody or industrial accuracy proof.
"""
import base64
from copy import deepcopy
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
from pathlib import Path
import time
from urllib.parse import urlencode

from cpag_core import evaluation_bundle as eb
from cpag_core.evaluation import digest
from cpag_core.evaluation_details import evaluate_detailed, V2_MATCHING_VERSION, V2_DETAILS_VERSION
from cpag_core.reference_inventory import build_inventory, LOCATOR_VERSION, LOCATED_STATUS

EXPECTED = [('manual-operation', 'network_operation', '["192.0.2.2",44818]', '2026-01-01T00:00:10Z'),
            ('manual-transition', 'process_change', '["synthetic-pump","pump_state"]', '2026-01-01T00:00:12Z')]


def check_saved_evaluation(client, run_id, projection, *, work: Path, dataset_id=None):
    """Use round16_acceptance.Client.expect; return only public check evidence."""
    work = Path(work); work.mkdir(parents=True, exist_ok=False)
    binding = projection['binding']; batch = binding['batch']; sample = binding['sample_sha256']
    if (binding['run_id'] != run_id or binding.get('storage_format') != 'shared-observation-dag-6'
            or len(projection['predictions']['events']) != 2
            or len(projection['predictions']['unlabelled_relations']) != 1):
        raise AssertionError('small_normal_service_projection_required')
    before = deepcopy(binding['logical_artifacts'])
    split = {'schema_version': '1.0.0', 'synthetic': True,
        'rule_windows_seconds': {'association': 5}, 'isolation_seconds': 5, 'blocks': [
        {'partition': 'calibration', 'batch': batch, 'start': '2025-12-01T00:00:00Z',
         'end': '2025-12-01T00:01:00Z', 'sample_sha256': ['a' * 64], 'normal': False},
        {'partition': 'holdout', 'batch': batch, 'start': '2026-01-01T00:00:00Z',
         'end': '2026-01-01T00:01:00Z', 'sample_sha256': [sample], 'normal': False}]}
    # Both independent label variants and originals are fixed before freezing.
    tables = [EXPECTED, [EXPECTED[0], (*EXPECTED[1][:3], '2026-01-01T00:00:14Z')]]
    originals = work / 'reference-originals'; originals.mkdir()
    stream = io.StringIO(newline=''); writer = csv.writer(stream, lineterminator='\r\n')
    writer.writerow(['event_id', 'kind', 'asset', 'time'])
    for rows in tables: writer.writerows(rows)
    raw = stream.getvalue().encode('utf-8'); name = 'handwritten-both-label-variants.csv'
    (originals / name).write_bytes(raw); sha = hashlib.sha256(raw).hexdigest()
    inventory_files = {name: sha}; raw_tables = [raw, raw]; table_hashes = [sha, sha]
    inventory = build_inventory(originals, inventory_files)
    now = datetime.now(timezone.utc); opening = now + timedelta(seconds=2)
    registration = {'schema_version': '1.0.0', 'synthetic': True,
        'registered_at': now.isoformat(), 'holdout_opened_at': opening.isoformat(),
        'input_fingerprint': binding['input_fingerprint'], 'config_fingerprint': binding['config_fingerprint'],
        'split_sha256': digest(split), 'tolerance_seconds': 0, 'thresholds': {}}
    frozen = {'version': eb.V3_VERSION, 'observed_frozen_at': datetime.now(timezone.utc).isoformat(),
        'registration_sha256': digest(registration), 'split_sha256': digest(split),
        'adapted_sha256': digest(projection), 'binding_sha256': digest(binding),
        'matching': V2_MATCHING_VERSION, 'details_version': V2_DETAILS_VERSION, 'custody': eb.CUSTODY,
        'reference_inventory_sha256': digest(inventory), 'reference_locator_version': LOCATOR_VERSION}
    eb.validate_freeze(frozen, registration)
    common = {'registration.json': registration, 'split.json': split, 'adapted.json': projection,
              'freeze.json': frozen, 'reference_inventory.json': inventory}
    eb.publish(work / 'frozen', common)
    if datetime.now(timezone.utc) >= opening:
        raise AssertionError('local_freeze_completion_crossed_opening')
    time.sleep(max(0, (opening - datetime.now(timezone.utc)).total_seconds()) + .01)
    checks = []
    prefix = f'/api/v3/runs/{run_id}/evaluations'
    for number, rows in enumerate(tables):
        labels = {'schema_version': '1.0.0', 'synthetic': True, 'origin': 'independent',
            'source_ref': 'handwritten table fixed before freeze', 'review_ref': 'repository acceptance author',
            'annotation_version': str(number + 1), 'disputed_intervals': [], 'events': [
                {'id': identity, 'kind': kind, 'asset': asset, 'time': at,
                 'batch': batch, 'sample_sha256': sample} for identity, kind, asset, at in rows]}
        refs = {identity: {'source_ref': f'handwritten variant {number}', 'sha256': table_hashes[number],
            'locator': {'version': LOCATOR_VERSION, 'file_sha256': table_hashes[number],
                        'record_number': number * 2 + index + 1, 'columns': ['event_id', 'kind', 'asset', 'time']}}
            for index, (identity, _, _, _) in enumerate(rows)}
        result = evaluate_detailed(projection['predictions'], labels, split, registration,
                                   matching_version=V2_MATCHING_VERSION)
        expected = (2, 0, 0) if number == 0 else (1, 1, 1)
        actual = tuple(result['record']['metrics'][key] for key in ('tp', 'fp', 'fn'))
        if actual != expected:
            raise AssertionError('handwritten_evaluation_counts_changed')
        result['bundle_binding'] = {'version': eb.V3_VERSION, 'freeze_sha256': digest(frozen),
            'artifact_binding_sha256': digest(binding), 'annotations_sha256': digest(labels),
            'references_sha256': digest(refs), 'observed_opened_at': datetime.now(timezone.utc).isoformat(),
            'reference_status': LOCATED_STATUS, 'reference_inventory_sha256': digest(inventory),
            'reference_locator_version': LOCATOR_VERSION}
        values = dict(common, **{'annotations.json': labels, 'references.json': refs, 'result.json': result})
        document = dict(values, **{'manifest.json': {'version': eb.V3_VERSION,
                         'files': {name: digest(value) for name, value in values.items()}}})
        eb.publish(work / f'evaluation-{number}', document)
        if number == 0:
            for mutation in ('late_freeze', 'wrong_attempt', 'wrong_logical_root', 'bad_raw_reference'):
                invalid = deepcopy(document)
                if mutation == 'late_freeze':
                    invalid['freeze.json']['observed_frozen_at'] = opening.isoformat()
                    invalid['result.json']['bundle_binding']['freeze_sha256'] = digest(invalid['freeze.json'])
                elif mutation == 'bad_raw_reference':
                    invalid['references.json']['manual-operation']['locator']['record_number'] = 999999
                    invalid['result.json']['bundle_binding']['references_sha256'] = digest(invalid['references.json'])
                else:
                    b = invalid['adapted.json']['binding']
                    if mutation == 'wrong_attempt': b['attempt_id'] += 1
                    else: b['logical_artifacts'][0]['digest'] = '0' * 64
                    invalid['freeze.json']['adapted_sha256'] = digest(invalid['adapted.json'])
                    invalid['freeze.json']['binding_sha256'] = digest(b)
                    invalid['result.json']['bundle_binding']['artifact_binding_sha256'] = digest(b)
                    invalid['result.json']['bundle_binding']['freeze_sha256'] = digest(invalid['freeze.json'])
                invalid['manifest.json']['files'] = {name: digest(invalid[name]) for name in values}
                client.expect('POST', prefix, invalid, code=409)
        imported = client.expect('POST', prefix, document, code=201)
        evaluation_id = imported['evaluation']['id']; detail_path = f'{prefix}/{evaluation_id}'
        detail = client.expect('GET', detail_path)
        if detail['result'] != result: raise AssertionError('saved_evaluation_result_changed')
        downloaded = client.expect('GET', detail_path + '/download')
        import json
        decoded = json.loads(downloaded) if isinstance(downloaded, (bytes, str)) else downloaded
        if decoded != document: raise AssertionError('saved_evaluation_download_changed')
        errors = result['details']['false_positives']
        identity = errors[0]['event_id'] if errors else projection['predictions']['events'][0]['id']
        raw = client.expect('GET', detail_path + '/evidence?' + urlencode({'event': identity}))['evidence']
        if not raw['evidence']['verified_original_evidence']:
            raise AssertionError('error_prediction_raw_evidence_missing')
        reference = client.expect('GET', detail_path + '/evidence?' + urlencode(
            {'event': 'manual-transition', 'reference': 'true'}))['evidence']
        retained = base64.b64decode(reference['original']['content_base64'], validate=True)
        if retained != raw_tables[number] or reference['status'] != LOCATED_STATUS:
            raise AssertionError('independent_reference_original_changed')
        if reference['resolved_record']['values']['time'] != rows[1][3]:
            raise AssertionError('independent_reference_locator_wrong_record')
        checks.append({'evaluation_id': evaluation_id, 'label_variant': number,
            'expected_tp_fp_fn': list(expected), 'detail_download_verified': True,
            'error_or_prediction_raw_evidence': True, 'reference_original_and_locator_verified': True})
    after = client.expect('GET', f'/api/v3/runs/{run_id}/evaluation-input?projection=dual')
    if after != projection or after['binding']['logical_artifacts'] != before:
        raise AssertionError('label_replacement_changed_analysis_or_projection')
    return {'checks': checks, 'same_run_and_attempt': True, 'same_frozen_projection': True,
            'analysis_logical_roots_unchanged': True,
            'rejected_imports': ['late_freeze', 'wrong_attempt', 'wrong_logical_root', 'bad_raw_reference'],
            'scope': 'synthetic handwritten observation matching; declared local timing and independence, no industrial validation'}
