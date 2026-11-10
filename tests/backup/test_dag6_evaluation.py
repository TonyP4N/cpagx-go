"""Saved DAG6 sidecars: retained-root, original-reference and score integrity."""
import base64
import copy
import csv
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'scripts/backup'), str(ROOT/'services/analysis/src'),
                str(ROOT/'scripts/validation')]
import dag6_evaluation as backup
from round19_core_small import inputs, write
from cpag_core import shared_export as core, evaluation_bundle as eb
from cpag_core.evaluation import digest
from cpag_core.evaluation_details import evaluate_detailed, V2_MATCHING_VERSION, V2_DETAILS_VERSION
from cpag_core.evaluation_shared import current_reader
from cpag_core.pipeline import file_hash
from cpag_core.reference_inventory import build_inventory, LOCATOR_VERSION, LOCATED_STATUS
from cpag_core.shared_artifact_store_compact import SharedArtifactReader


CONTEXT = {'batch': 'backup-handwritten-small', 'sample_sha256': 'b'*64}
EXPECTED = [('manual-operation', 'network_operation', '["192.0.2.2",44818]', '2026-01-01T00:00:10Z'),
            ('manual-transition', 'process_change', '["synthetic-pump","pump_state"]', '2026-01-01T00:00:12Z')]


def publication(output, manifest):
    """Ordinary service publication, including its immutable digest anchor."""
    values = {'run_id': manifest['run_id'], 'attempt_id': manifest['attempt_id'],
        'config_fingerprint': manifest['config_fingerprint'],
        'storage_format': core.FORMAT, 'capacity_profile': 'engineering-core-capacity-3',
        'resource_profile': 'storage-budget-2', 'storage_budget_version': 'shared-storage-budget-2',
        'inputs': {name: file_hash(output/'sources'/filename) for name, filename in
                   [('network', 'network.pcap'), ('process', 'process.csv'), ('profile', 'profile.json')]},
        'artifacts': [{'path': name, 'sha256': file_hash(output/name), 'size': (output/name).stat().st_size}
                      for name in sorted(core.artifact_files(output))]}
    if manifest['network_count'] > 1:
        values['networks'] = [file_hash(output/'sources'/name) for name in core.network_names(manifest['network_count'])]
    if manifest['mode'] == 'replay':
        values.update({name: manifest[name] for name in ('replay_version', 'history_format')})
    write(output/'manifest.json', values)
    (output/(file_hash(output/'manifest.json')+'.json')).write_bytes((output/'manifest.json').read_bytes())


def document_for(root, adapted):
    """Handwritten originals fixed separately from the artifact projection."""
    batch, sample = CONTEXT['batch'], CONTEXT['sample_sha256']
    split = {'schema_version': '1.0.0', 'synthetic': True,
        'rule_windows_seconds': {'association': 5}, 'isolation_seconds': 5,
        'blocks': [{'partition': 'calibration', 'batch': batch, 'start': '2025-12-01T00:00:00Z',
                    'end': '2025-12-01T00:01:00Z', 'sample_sha256': ['a'*64], 'normal': False},
                   {'partition': 'holdout', 'batch': batch, 'start': '2026-01-01T00:00:00Z',
                    'end': '2026-01-01T00:01:00Z', 'sample_sha256': [sample], 'normal': False}]}
    registration = {'schema_version': '1.0.0', 'synthetic': True,
        'registered_at': '2026-01-02T00:00:00Z', 'holdout_opened_at': '2026-01-04T00:00:00Z',
        'input_fingerprint': adapted['binding']['input_fingerprint'],
        'config_fingerprint': adapted['binding']['config_fingerprint'],
        'split_sha256': digest(split), 'tolerance_seconds': 0, 'thresholds': {}}
    originals = root/'originals'; originals.mkdir()
    stream = io.StringIO(newline=''); writer = csv.writer(stream, lineterminator='\r\n')
    writer.writerow(['event_id', 'kind', 'asset', 'time']); writer.writerows(EXPECTED)
    (originals/'manual.csv').write_bytes(stream.getvalue().encode())
    sha = file_hash(originals/'manual.csv'); inventory = build_inventory(originals, {'manual.csv': sha})
    annotations = {'schema_version': '1.0.0', 'synthetic': True, 'origin': 'independent',
        'source_ref': 'handwritten table', 'review_ref': 'backup fixture author',
        'annotation_version': '1', 'disputed_intervals': [], 'events': [
            {'id': identity, 'kind': kind, 'asset': asset, 'time': when, 'batch': batch,
             'sample_sha256': sample} for identity, kind, asset, when in EXPECTED]}
    references = {row[0]: {'source_ref': 'handwritten original CSV', 'sha256': sha,
        'locator': {'version': LOCATOR_VERSION, 'file_sha256': sha,
                    'record_number': number+1, 'columns': ['event_id', 'kind', 'asset', 'time']}}
        for number, row in enumerate(EXPECTED)}
    frozen = {'version': eb.V3_VERSION, 'observed_frozen_at': '2026-01-03T00:00:00Z',
        'registration_sha256': digest(registration), 'split_sha256': digest(split),
        'adapted_sha256': digest(adapted), 'binding_sha256': digest(adapted['binding']),
        'matching': V2_MATCHING_VERSION, 'details_version': V2_DETAILS_VERSION, 'custody': eb.CUSTODY,
        'reference_inventory_sha256': digest(inventory), 'reference_locator_version': LOCATOR_VERSION}
    result = evaluate_detailed(adapted['predictions'], annotations, split, registration,
                               matching_version=V2_MATCHING_VERSION)
    result['bundle_binding'] = {'version': eb.V3_VERSION, 'freeze_sha256': digest(frozen),
        'artifact_binding_sha256': digest(adapted['binding']), 'annotations_sha256': digest(annotations),
        'references_sha256': digest(references), 'observed_opened_at': '2026-01-05T00:00:00Z',
        'reference_status': LOCATED_STATUS, 'reference_inventory_sha256': digest(inventory),
        'reference_locator_version': LOCATOR_VERSION}
    values = {'registration.json': registration, 'split.json': split, 'adapted.json': adapted,
        'freeze.json': frozen, 'reference_inventory.json': inventory, 'annotations.json': annotations,
        'references.json': references, 'result.json': result}
    values['manifest.json'] = {'version': eb.V3_VERSION, 'files': {name: digest(value) for name, value in values.items()}}
    return values


def rehash(document):
    """Re-sign mutable sidecar hashes so corruption reaches independent checks."""
    frozen, result = document['freeze.json'], document['result.json']['bundle_binding']
    for name in ('registration', 'split', 'adapted'):
        frozen[name+'_sha256'] = digest(document[name+'.json'])
    frozen['binding_sha256'] = digest(document['adapted.json']['binding'])
    frozen['reference_inventory_sha256'] = digest(document['reference_inventory.json'])
    for name, key in [('annotations', 'annotations_sha256'), ('references', 'references_sha256'),
                      ('freeze', 'freeze_sha256'), ('reference_inventory', 'reference_inventory_sha256')]:
        result[key] = digest(document[name+'.json'])
    result['artifact_binding_sha256'] = digest(document['adapted.json']['binding'])
    document['manifest.json']['files'] = {name: digest(value) for name, value in document.items() if name != 'manifest.json'}


class DAG6EvaluationBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.output = self.root/'artifact'
        net, process, profile, _ = inputs(self.root/'inputs', 'normal', 'replay')
        manifest = core.export_task(net, process, profile, self.output, mode='replay',
                                    run_id='backup-small', attempt_id=2)
        publication(self.output, manifest)
        self.adapted = backup.adapt_preparation(self.output, **CONTEXT)
        self.document = document_for(self.root, self.adapted)

    def test_real_sidecar_checks_scores_without_source_execution_or_approval(self):
        before = {p.relative_to(self.output).as_posix(): file_hash(p) for p in self.output.rglob('*') if p.is_file()}
        with patch.object(core, 'verify_task', side_effect=AssertionError('source repeated')), \
             patch.object(core, '_build_business_roots', side_effect=AssertionError('analysis repeated')), \
             patch.object(core, 'issue_approval', side_effect=AssertionError('approval issued')):
            result = backup.verify_document(self.document, self.output)
        self.assertEqual([result['result']['record']['metrics'][key] for key in ('tp', 'fp', 'fn')], [2, 0, 0])
        self.assertEqual(result['backup_evaluation_audit']['status'], backup.STATUS)
        self.assertFalse(result['backup_evaluation_audit']['source_approval_issued'])
        self.assertIsNone(current_reader(self.output))
        self.assertEqual(before, {p.relative_to(self.output).as_posix(): file_hash(p) for p in self.output.rglob('*') if p.is_file()})

    def test_rehashed_wrong_attempt_roots_configuration_input_and_prediction_refused(self):
        mutations = [('attempt', lambda b: b.update(attempt_id=3)),
            ('roots', lambda b: b['logical_artifacts'][0].update(digest='0'*64)),
            ('profile', lambda b: b.update(config_fingerprint='0'*64)),
            ('input', lambda b: b.update(input_fingerprint='0'*64))]
        for name, mutate in mutations:
            bad = copy.deepcopy(self.document); mutate(bad['adapted.json']['binding']); rehash(bad)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'frozen_artifact_binding_mismatch'):
                backup.verify_document(bad, self.output)
        bad = copy.deepcopy(self.document); bad['adapted.json']['predictions']['events'][0]['time'] = '2026-01-01T00:00:59Z'
        rehash(bad)
        with self.assertRaisesRegex(ValueError, 'frozen_projection_changed'):
            backup.verify_document(bad, self.output)
        self.assertIsNone(current_reader(self.output))

    def test_rehashed_reference_original_locator_and_scores_refused(self):
        for name in ('original', 'locator', 'score'):
            bad = copy.deepcopy(self.document)
            if name == 'original':
                item = next(iter(bad['reference_inventory.json']['files'].values()))
                raw = base64.b64decode(item['content_base64'])
                item['content_base64'] = base64.b64encode(raw[:-1]+b'X').decode()
            elif name == 'locator': bad['references.json']['manual-transition']['locator']['record_number'] = 999
            else: bad['result.json']['record']['metrics']['tp'] = 99
            rehash(bad)
            with self.subTest(name=name), self.assertRaises(ValueError):
                backup.verify_document(bad, self.output)

    def test_inherited_service_guard_cannot_skip_storage_verification(self):
        token = core._SERVICE_VERIFIED.set((self.output.resolve(), file_hash(self.output/'run_manifest.json')))
        calls = []; original = SharedArtifactReader.verify
        def verify(reader): calls.append(True); return original(reader)
        try:
            with patch.object(SharedArtifactReader, 'verify', verify):
                backup.verify_document(self.document, self.output)
            self.assertEqual(calls, [True])
        finally: core._SERVICE_VERIFIED.reset(token)


if __name__ == '__main__': unittest.main()
