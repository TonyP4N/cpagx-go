import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cpag_core.intake import preflight
from cpag_core.pipeline import fingerprint


ROOT = Path(__file__).resolve().parents[2]


def _write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')


def _batch(tmp_path, *, kinds=('network', 'process')):
    raw = tmp_path / 'raw'
    raw.mkdir()
    files = []
    for kind in kinds:
        name = 'a.pcap' if kind == 'network' else 'b.csv'
        data = b'capture fixture bytes' if kind == 'network' else b'time,value\n0,1\n'
        (raw / name).write_bytes(data)
        files.append({'name': name, 'sha256': hashlib.sha256(data).hexdigest(),
                      'size_bytes': len(data), 'kind': kind})
    manifest = {'schema_version': '1.0.0', 'synthetic': True,
                'dataset_id': 'batch-a', 'source': 'synthetic fixture', 'release': '1',
                'files': files, 'collection_range': {'start': None, 'end': None},
                'timezone_basis': None, 'authorization_ref': 'synthetic permission record'}
    config = {'dataset_id': 'batch-a', 'synthetic': True,
              'authorization': {'allowed_use': 'test', 'evidence_ref': 'auth-1', 'reviewer': 'tester'},
              'time_basis': {'timezone': 'UTC', 'precision': 'seconds',
                             'synchronization': 'fixture clocks', 'evidence_ref': 'clock-1'},
              'mapping': {'field_units_ref': 'units-1', 'device_map_ref': 'map-1',
                          'effective_period_ref': 'period-1'}}
    manifest_path = tmp_path / 'manifest.json'
    config_path = tmp_path / 'config.json'
    _write_json(manifest_path, manifest)
    _write_json(config_path, config)
    return raw, manifest_path, config_path, manifest, config


def _cli(raw, manifest, config, output, *extra):
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'services/analysis/src'))
    return subprocess.run([sys.executable, '-m', 'cpag_core.intake', '--raw-root', str(raw),
                           '--manifest', str(manifest), '--config', str(config), '--output', str(output),
                           *extra], cwd=ROOT, env=env, capture_output=True, text=True)


def check_complete_batch_is_deterministic_and_does_not_mutate_raw(tmp_path):
    raw, manifest_path, config_path, manifest, _ = _batch(tmp_path)
    all_inputs = [*raw.iterdir(), manifest_path, config_path]
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in all_inputs}
    expected_fp = fingerprint([{'kind': f['kind'], 'sha256': f['sha256'],
                                'size_bytes': f['size_bytes']} for f in manifest['files']])
    reports = []
    for number in range(3):
        result = _cli(raw, manifest_path, config_path, tmp_path / f'report-{number}', '--json')
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report == json.loads((tmp_path / f'report-{number}' / 'report.json').read_text())
        assert 'ready_for_manual_review' in (tmp_path / f'report-{number}' / 'report.txt').read_text()
        reports.append(report)
    assert reports[0] == reports[1] == reports[2]
    assert reports[0]['input_fingerprint'] == expected_fp
    assert reports[0]['collection_range_status'] == 'unknown'
    assert reports[0]['alignment_status'] == 'not_verified'
    assert reports[0]['authorization_status'] == 'requires_manual_review'
    assert before == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in all_inputs}


def check_negative_file_cases_have_reason_and_exit_code(tmp_path):
    mutators = {
        'missing_file': lambda raw, manifest: (raw / manifest['files'][0]['name']).unlink(),
        'checksum_mismatch': lambda raw, manifest: (raw / manifest['files'][0]['name']).write_bytes(b'changed'),
        'unsafe_path': lambda raw, manifest: manifest['files'][0].update(name='../outside.pcap'),
        'unsupported_format': lambda raw, manifest: manifest['files'][0].update(name='a.zip'),
        'batch_conflict': lambda raw, manifest: manifest['files'].append(dict(manifest['files'][0])),
    }
    expected = {'missing_file': 11, 'checksum_mismatch': 12, 'unsafe_path': 13,
                'unsupported_format': 15, 'batch_conflict': 14}
    for code, mutate in mutators.items():
        case = tmp_path / code
        case.mkdir()
        raw, manifest_path, config_path, manifest, _ = _batch(case)
        mutate(raw, manifest)
        _write_json(manifest_path, manifest)
        result = _cli(raw, manifest_path, config_path, case / 'report')
        report = json.loads((case / 'report' / 'report.json').read_text())
        assert result.returncode == expected[code], (code, result.stderr)
        assert code in report['errors']
        assert report['status'] == 'invalid'
        assert report['input_fingerprint'] is None


def check_symlink_and_batch_id_conflict(tmp_path):
    raw, manifest_path, config_path, manifest, config = _batch(tmp_path)
    (raw / 'link.pcap').symlink_to(raw / 'a.pcap')
    manifest['files'][0]['name'] = 'link.pcap'
    _write_json(manifest_path, manifest)
    assert preflight(raw, manifest_path, config_path)['exit_code'] == 13
    manifest['files'][0]['name'] = 'a.pcap'
    _write_json(manifest_path, manifest)
    config['dataset_id'] = 'another-batch'
    _write_json(config_path, config)
    report = preflight(raw, manifest_path, config_path)
    assert report['exit_code'] == 14
    assert 'batch_conflict' in report['errors']
    config['dataset_id'] = manifest['dataset_id']
    config['synthetic'] = False
    _write_json(config_path, config)
    assert preflight(raw, manifest_path, config_path)['exit_code'] == 14
    del config['synthetic']
    _write_json(config_path, config)
    assert preflight(raw, manifest_path, config_path)['exit_code'] == 16


def check_material_gaps_and_single_source(tmp_path):
    raw, manifest_path, config_path, manifest, config = _batch(tmp_path, kinds=('network',))
    manifest['authorization_ref'] = ''
    _write_json(manifest_path, manifest)
    config['authorization'] = {}
    config['time_basis'] = {}
    config['mapping'] = {}
    _write_json(config_path, config)
    report = preflight(raw, manifest_path, config_path)
    assert report['exit_code'] == 2
    assert report['source_scope'] == 'network_only'
    assert report['status'] == 'single_source_review'
    assert report['next_step'] == 'review_single_source_only'
    assert report['material_gaps'] == ['authorization', 'mapping', 'second_source', 'time_basis']
    assert report['collection_range_status'] == 'unknown'


def check_input_identity_excludes_paths_and_order_but_config_changes_count(tmp_path):
    raw, manifest_path, config_path, manifest, config = _batch(tmp_path)
    original = preflight(raw, manifest_path, config_path)
    (raw / 'renamed.pcap').write_bytes((raw / 'a.pcap').read_bytes())
    (raw / 'a.pcap').unlink()
    manifest['files'][0]['name'] = 'renamed.pcap'
    manifest['files'].reverse()
    _write_json(manifest_path, manifest)
    renamed = preflight(raw, manifest_path, config_path)
    assert renamed['input_fingerprint'] == original['input_fingerprint']
    config['time_basis']['precision'] = 'milliseconds'
    _write_json(config_path, config)
    changed = preflight(raw, manifest_path, config_path)
    assert changed['intake_config_fingerprint'] != original['intake_config_fingerprint']
    assert changed['input_fingerprint'] == original['input_fingerprint']


def check_report_redacts_credential_and_restricted_url(tmp_path):
    raw, manifest_path, config_path, manifest, config = _batch(tmp_path)
    secret = 'SECRET-TOKEN-987654'
    url = 'https://restricted.example/download?token=' + secret
    manifest['source'] = url
    manifest['authorization_ref'] = url
    config['authorization']['evidence_ref'] = url
    config['extra_secret'] = secret
    _write_json(manifest_path, manifest)
    _write_json(config_path, config)
    result = _cli(raw, manifest_path, config_path, tmp_path / 'report', '--json')
    assert result.returncode == 0
    for text in (result.stdout, (tmp_path / 'report' / 'report.json').read_text(),
                 (tmp_path / 'report' / 'report.txt').read_text()):
        assert secret not in text
        assert url not in text


def check_nonfinite_config_and_missing_source_metadata(tmp_path):
    raw, manifest_path, config_path, manifest, config = _batch(tmp_path)
    config_path.write_text('{"dataset_id":"batch-a","synthetic":true,"time_basis":NaN}')
    result = _cli(raw, manifest_path, config_path, tmp_path / 'bad-report', '--json')
    assert result.returncode == 16
    assert json.loads(result.stdout)['errors'] == ['config_invalid']
    manifest['source'] = ''
    manifest['release'] = ''
    _write_json(manifest_path, manifest)
    _write_json(config_path, config)
    report = preflight(raw, manifest_path, config_path)
    assert report['status'] == 'material_gaps'
    assert report['exit_code'] == 2
    assert report['material_gaps'] == ['release', 'source']


def check_output_cannot_be_inside_raw(tmp_path):
    raw, manifest_path, config_path, _, _ = _batch(tmp_path)
    result = _cli(raw, manifest_path, config_path, raw / 'report')
    assert result.returncode == 17
    assert not (raw / 'report').exists()


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_complete_batch_is_deterministic_and_does_not_mutate_raw(self):
        check_complete_batch_is_deterministic_and_does_not_mutate_raw(self.root)

    def test_negative_file_cases_have_reason_and_exit_code(self):
        check_negative_file_cases_have_reason_and_exit_code(self.root)

    def test_symlink_and_batch_id_conflict(self):
        check_symlink_and_batch_id_conflict(self.root)

    def test_material_gaps_and_single_source(self):
        check_material_gaps_and_single_source(self.root)

    def test_input_identity_excludes_paths_and_order_but_config_changes_count(self):
        check_input_identity_excludes_paths_and_order_but_config_changes_count(self.root)

    def test_report_redacts_credential_and_restricted_url(self):
        check_report_redacts_credential_and_restricted_url(self.root)

    def test_output_cannot_be_inside_raw(self):
        check_output_cannot_be_inside_raw(self.root)

    def test_nonfinite_config_and_missing_source_metadata(self):
        check_nonfinite_config_and_missing_source_metadata(self.root)


if __name__ == '__main__':
    unittest.main()
