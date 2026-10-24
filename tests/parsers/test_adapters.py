import json
import tempfile
import unittest
from pathlib import Path
from cpag_core.parsers import parse_network, parse_process

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / 'tests/fixtures/synthetic'


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((ROOT / 'profiles/synthetic-demo.json').read_text())

    def temp(self, suffix, content):
        tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tmp.write(content.encode())
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return tmp.name

    def test_synthetic_network_and_determinism(self):
        a = parse_network(FIX / 'network.normalized.jsonl')
        self.assertEqual(a, parse_network(FIX / 'network.normalized.jsonl'))
        self.assertEqual(len(a['events']), 2)
        self.assertTrue(all(e['synthetic'] for e in a['events']))
        self.assertIsNone(a['events'][0]['source_ref']['frame_number'])

    def test_no_raw_packets_or_real_network_claim(self):
        for suffix in ('.pcap', '.pcapng', '.txt'):
            self.assertEqual(parse_network(self.temp(suffix, ''))['quality']['status'], 'unsupported')
        self.assertEqual(parse_network(FIX / 'network.normalized.jsonl', synthetic=False)['events'], [])

    def test_bad_json_and_unmarked_records(self):
        result = parse_network(self.temp('.jsonl', '{}\n{"synthetic":true'))
        self.assertEqual(result['events'], [])
        self.assertEqual(result['quality']['status'], 'partial')

    def test_multiline_zero_missing_nonfinite(self):
        events = parse_process(FIX / 'process.csv', self.profile)['events']
        self.assertEqual(len(events), 6)
        self.assertEqual(events[0]['value'], 0)
        self.assertEqual(events[2]['source_ref']['record_number'], 2)
        self.assertIsNone(events[2]['value'])
        self.assertIn('missing_value', events[2]['quality']['reasons'])
        self.assertIn('nonfinite_value', events[4]['quality']['reasons'])
        self.assertEqual(events[1]['value_type'], 'state')

    def test_unknown_timezone_and_asset(self):
        self.profile['columns']['level']['asset_id'] = None
        result = parse_process(self.temp('.csv', 'time,level,pump\n2026-01-01T00:00:00,1,ON\n'), self.profile)
        event = result['events'][0]
        self.assertIsNone(event['event_time'])
        self.assertEqual(event['source_ref']['raw_time'], '2026-01-01T00:00:00')
        self.assertIn('unknown_timezone', event['quality']['reasons'])
        self.assertIn('unresolved_asset', event['quality']['reasons'])

    def test_timezone_requires_evidence(self):
        path = self.temp('.csv', 'time,level,pump\n2026-01-01T08:00:00,1,ON\n')
        self.profile['timezone'] = 'Asia/Shanghai'
        self.assertIsNone(parse_process(path, self.profile)['events'][0]['event_time'])
        self.profile['timezone_evidence'] = 'synthetic fixture specification'
        self.assertEqual(parse_process(path, self.profile)['events'][0]['event_time'], '2026-01-01T00:00:00Z')

    def test_malformed_truncated_and_invalid_values(self):
        for text in ('time,level,pump\n"unterminated', 'time,level,pump\n1,2\n'):
            result = parse_process(self.temp('.csv', text), self.profile)
            self.assertEqual(result['events'], [])
            self.assertEqual(result['quality']['status'], 'partial')
        events = parse_process(self.temp('.csv', 'time,level,pump\nbad,abc,UNKNOWN\n'), self.profile)['events']
        self.assertIn('invalid_numeric_value', events[0]['quality']['reasons'])
        self.assertIn('unknown_state', events[1]['quality']['reasons'])

    def test_network_missing_fields_have_explicit_reasons(self):
        record = {'synthetic': True, 'record_type': 'synthetic_normalized_network'}
        event = parse_network(self.temp('.jsonl', json.dumps(record)))['events'][0]
        for field in ('source', 'destination', 'protocol', 'operation', 'correlation_id', 'response_status'):
            self.assertIn('missing_' + field, event['quality']['reasons'])

    def test_network_rejects_labels_unknown_keys_and_nonstandard_constants(self):
        record = {'synthetic': True, 'record_type': 'synthetic_normalized_network'}
        for field, value in [('label', 'attack'), ('extra', 'ignored'), ('protocol', float('nan'))]:
            result = parse_network(self.temp('.jsonl', json.dumps(dict(record, **{field: value}))))
            self.assertEqual(result['events'], [])
            self.assertEqual(result['quality']['status'], 'partial')

    def test_process_label_separation(self):
        for label in ('Normal/Attack', 'Label', 'Attack_Type', 'ground_truth'):
            path = self.temp('.csv', 'time,level,pump,' + label + '\n2026-01-01T00:00:00Z,1,ON,attack\n')
            result = parse_process(path, self.profile)
            self.assertEqual(result['quality']['status'], 'unsupported')
        self.profile['columns']['label'] = {'tag': 'measurement', 'value_type': 'state'}
        self.assertEqual(parse_process(FIX / 'process.csv', self.profile)['quality']['status'], 'unsupported')

    def test_synthetic_flags_are_explicit_boolean_and_consistent(self):
        for flag in (None, 0, '', 'false'):
            self.profile['synthetic'] = flag
            self.assertEqual(parse_process(FIX / 'process.csv', self.profile)['quality']['status'], 'unsupported')
        self.profile['synthetic'] = False
        self.assertEqual(parse_process(FIX / 'process.csv', self.profile)['quality']['status'], 'unsupported')
        self.assertFalse(parse_process(FIX / 'process.csv', self.profile, synthetic=False)['events'][0]['synthetic'])


    def test_invalid_utf8_is_partial_without_events(self):
        for suffix, parser in [('.jsonl', parse_network), ('.csv', lambda p: parse_process(p, self.profile))]:
            path = Path(self.temp(suffix, ''))
            path.write_bytes(b'\xff')
            result = parser(path)
            self.assertEqual(result['events'], [])
            self.assertEqual(result['quality']['status'], 'partial')

    def test_unsupported_process(self):
        self.assertEqual(parse_process('unknown.xlsx', self.profile)['quality']['status'], 'unsupported')
        self.assertEqual(parse_process(FIX / 'process.csv', {})['quality']['status'], 'unsupported')


if __name__ == '__main__':
    unittest.main()
