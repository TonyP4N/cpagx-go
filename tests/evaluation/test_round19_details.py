"""Handwritten R19 preregistration scenarios; expected labels are never predicted."""
import copy
import unittest

from cpag_core.evaluation import digest, evaluate
from cpag_core.evaluation_details import evaluate_detailed


def event(identity, second, kind='network_operation', normal=False, sample=None):
    # Fixture times and labels are test-author inputs, not pipeline output.
    return {'id': identity, 'batch': 'batch', 'kind': kind, 'asset': 'device',
            'time': f'2026-01-01T0{3 if normal else 2}:00:{second:02d}Z',
            'sample_sha256': sample or ('e' if normal else 'b') * 64}


def fixture():
    split = {'schema_version': '1.0.0', 'synthetic': True,
             'rule_windows_seconds': {'rule': 60}, 'isolation_seconds': 60,
             'blocks': [
                 {'partition': 'calibration', 'batch': 'batch',
                  'start': '2026-01-01T00:00:00Z', 'end': '2026-01-01T01:00:00Z',
                  'sample_sha256': ['a' * 64], 'normal': False},
                 {'partition': 'holdout', 'batch': 'batch',
                  'start': '2026-01-01T02:00:00Z', 'end': '2026-01-01T03:00:00Z',
                  'sample_sha256': ['b' * 64, 'f' * 64], 'normal': False},
                 {'partition': 'holdout', 'batch': 'batch',
                  'start': '2026-01-01T03:00:00Z', 'end': '2026-01-01T04:00:00Z',
                  'sample_sha256': ['e' * 64], 'normal': True}]}
    predictions = {'schema_version': '1.0.0', 'synthetic': True, 'run_id': 'handwritten',
                   'input_fingerprint': 'c' * 64, 'config_fingerprint': 'd' * 64,
                   'events': [event('p1', 1), event('p2', 40)], 'unlabelled_relations': []}
    annotations = {'schema_version': '1.0.0', 'synthetic': True,
                   'origin': 'independent', 'source_ref': 'handwritten-r19-scenarios',
                   'review_ref': 'test-author', 'annotation_version': 'preregistered-P01-P08-P13',
                   'events': [event('g1', 0), event('g2', 20)], 'disputed_intervals': []}
    registration = {'schema_version': '1.0.0', 'synthetic': True,
                    'registered_at': '2025-12-01T00:00:00Z',
                    'holdout_opened_at': '2026-01-02T00:00:00Z',
                    'input_fingerprint': 'c' * 64, 'config_fingerprint': 'd' * 64,
                    'split_sha256': digest(split), 'tolerance_seconds': 1, 'thresholds': {}}
    return predictions, annotations, split, registration


class Round19DetailedTests(unittest.TestCase):
    def details(self, values):
        result = evaluate_detailed(*values)
        # The old contract is checked as a whole, not reconstructed from new code.
        self.assertEqual({key: value for key, value in result.items() if key != 'details'},
                         evaluate(*values))
        return result['details']

    def counts(self, details, expected):
        self.assertEqual(tuple(details['metrics'][key] for key in ('tp', 'fp', 'fn')), expected)
        self.assertEqual(len(details['matches']), expected[0])
        self.assertEqual(len(details['false_positives']), expected[1])
        self.assertEqual(len(details['false_negatives']), expected[2])

    def test_p01_two_references_one_hit_hand_calculated(self):
        details = self.details(fixture())
        self.counts(details, (1, 1, 1))
        self.assertEqual(details['metrics']['precision'],
                         {'value': .5, 'numerator': 1, 'denominator': 2, 'unavailable_reason': None})
        self.assertEqual(details['metrics']['recall']['value'], .5)
        self.assertEqual(details['matches'][0]['prediction']['id'], 'p1')
        self.assertEqual(details['matches'][0]['reference']['id'], 'g1')
        self.assertEqual(details['false_positives'][0]['event']['id'], 'p2')
        self.assertEqual(details['false_negatives'][0]['event']['id'], 'g2')

    def test_p02_exact_tolerance_then_0999(self):
        values = fixture()
        values[0]['events'] = [event('p', 1)]
        values[1]['events'] = [event('g', 0)]
        self.counts(self.details(values), (1, 0, 0))
        values[3]['tolerance_seconds'] = .999
        self.counts(self.details(values), (0, 1, 1))

    def test_p03_duplicate_detections_one_reference(self):
        values = fixture()
        values[0]['events'] = [event('p1', 0), event('p2', 0)]
        values[1]['events'] = [event('g', 0)]
        details = self.details(values)
        self.counts(details, (1, 1, 0))
        self.assertEqual(details['false_positives'][0]['reason'], 'compatible_references_already_assigned')
        self.assertEqual(details['false_positives'][0]['compatible_reference_ids'], ['g'])

    def test_p04_augmenting_path_maximum_matching(self):
        values = fixture()
        values[0]['events'] = [event('flexible', 1), event('restricted', 0)]
        values[1]['events'] = [event('g1', 0), event('g2', 2)]
        details = self.details(values)
        self.counts(details, (2, 0, 0))
        self.assertEqual({row['prediction']['id']: row['reference']['id'] for row in details['matches']},
                         {'flexible': 'g2', 'restricted': 'g1'})
        self.assertEqual(details, self.details(values))

    def test_p05_empty_predictions_preserves_independent_miss(self):
        values = fixture()
        values[0]['events'] = []
        values[1]['events'] = [event('independent-miss', 0)]
        details = self.details(values)
        self.counts(details, (0, 0, 1))
        self.assertEqual(details['metrics']['precision'],
                         {'value': None, 'numerator': 0, 'denominator': 0,
                          'unavailable_reason': 'no_eligible_predictions'})
        self.assertEqual(details['metrics']['recall']['value'], 0)
        self.assertEqual(details['false_negatives'][0]['event']['id'], 'independent-miss')

    def test_p06_empty_both_zero_normal_denominators(self):
        values = fixture()
        values[0]['events'] = []
        values[1]['events'] = []
        values[2]['blocks'][2]['normal'] = False
        values[3]['split_sha256'] = digest(values[2])
        details = self.details(values)
        self.counts(details, (0, 0, 0))
        for name, reason in [('precision', 'no_eligible_predictions'),
                             ('recall', 'no_eligible_reference_events'),
                             ('unmatched_predictions_per_normal_hour', 'no_verified_normal_duration')]:
            self.assertIsNone(details['metrics'][name]['value'])
            self.assertEqual(details['metrics'][name]['denominator'], 0)
            self.assertEqual(details['metrics'][name]['unavailable_reason'], reason)

    def test_p07_dispute_union_left_closed_right_open(self):
        values = fixture()
        values[0]['events'] = []
        values[1]['events'] = []
        for identity, minute in [('before', 9), ('left', 10), ('overlap', 17), ('right', 30)]:
            row = event(identity, 0, normal=True)
            row['time'] = f'2026-01-01T03:{minute:02d}:00Z'
            values[0]['events'].append(row)
        values[1]['disputed_intervals'] = [
            {'batch': 'batch', 'start': '2026-01-01T03:10:00Z', 'end': '2026-01-01T03:20:00Z'},
            {'batch': 'batch', 'start': '2026-01-01T03:15:00Z', 'end': '2026-01-01T03:30:00Z'}]
        details = self.details(values)
        self.counts(details, (0, 2, 0))
        self.assertEqual(details['normal_duration']['declared_seconds'], 3600)
        self.assertEqual(details['normal_duration']['excluded_seconds'], 1200)
        self.assertEqual(details['normal_duration']['counted_seconds'], 2400)
        self.assertEqual(details['metrics']['unmatched_predictions_per_normal_hour']['value'], 3)
        self.assertEqual([row['event']['id'] for row in details['excluded']['predictions']], ['left', 'overlap'])
        self.assertEqual(details['excluded']['predictions'][1]['disputed_interval_indices'], [0, 1])
        self.assertEqual(details['normal_unmatched_prediction_ids'], ['before', 'right'])

    def test_p08_hypothetical_relations_are_unlabelled_only(self):
        values = fixture()
        values[0]['events'] = []
        values[1]['events'] = []
        values[0]['unlabelled_relations'] = ['hypothetical-relation']
        details = self.details(values)
        self.counts(details, (0, 0, 0))
        self.assertEqual(details['unlabelled_relations'], ['hypothetical-relation'])
        self.assertIsNone(details['path_accuracy']['value'])
        self.assertEqual(details['path_accuracy']['unavailable_reason'], 'no_independent_path_reference')
        values[0]['events'] = [event('not-an-observation', 1, kind='hypothetical')]
        with self.assertRaisesRegex(ValueError, 'observation kinds only'):
            evaluate_detailed(*values)

    def test_p13_overlap_cross_split_window_and_frozen_config_rejected(self):
        for mode in ('overlap', 'sample_across_partitions', 'window', 'isolation', 'config', 'split_fingerprint'):
            values = fixture()
            if mode == 'overlap':
                values[2]['blocks'][1]['start'] = '2026-01-01T00:59:00Z'
            elif mode == 'sample_across_partitions':
                values[2]['blocks'][1]['sample_sha256'] = ['a' * 64]
            elif mode == 'window':
                values[2]['rule_windows_seconds'] = {}
            elif mode == 'isolation':
                values[2]['isolation_seconds'] = 59
            elif mode == 'config':
                values[0]['config_fingerprint'] = '0' * 64
            elif mode == 'split_fingerprint':
                values[2]['blocks'][2]['normal'] = False
            if mode not in ('config', 'split_fingerprint'):
                values[3]['split_sha256'] = digest(values[2])
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                evaluate_detailed(*values)

    def test_excluded_reference_and_prediction_do_not_enter_denominators(self):
        values = fixture()
        values[1]['disputed_intervals'] = [{'batch': 'batch', 'start': '2026-01-01T02:00:00Z',
                                          'end': '2026-01-01T02:00:02Z'}]
        details = self.details(values)
        self.counts(details, (0, 1, 1))
        self.assertEqual([row['event']['id'] for row in details['excluded']['reference_events']], ['g1'])
        self.assertEqual(details['metrics']['precision']['denominator'], 1)
        self.assertEqual(details['metrics']['recall']['denominator'], 1)

    def test_kind_separation_and_dimensions(self):
        values = fixture()
        values[0]['events'] = [event('network', 0), event('process', 20, kind='process_change')]
        values[1]['events'] = [event('network-gold', 0), event('process-gold', 20, kind='process_change')]
        details = self.details(values)
        self.counts(details, (2, 0, 0))
        for kind in ('network_operation', 'process_change'):
            self.assertEqual(details['by_kind'][kind]['tp'], 1)
            self.assertEqual(details['by_kind'][kind]['precision']['denominator'], 1)
        for dimension, value in [('asset', 'other'), ('kind', 'process_change')]:
            altered = copy.deepcopy(values)
            altered[0]['events'][0][dimension] = value
            self.counts(self.details(altered), (1, 1, 1))

    def test_same_batch_timeline_matches_distinct_valid_source_samples(self):
        values = fixture()
        values[0]['events'] = [event('p', 0)]
        values[1]['events'] = [event('g', 0, sample='f' * 64)]
        details = self.details(values)
        self.counts(details, (1, 0, 0))
        self.assertIn('declared batch timeline', details['matching_policy']['sample_identity'])

    def test_non_synthetic_inputs_have_no_scored_matches(self):
        values = fixture()
        values[0]['synthetic'] = False
        details = self.details(values)
        self.assertEqual(details['status'], 'not_evaluated')
        self.assertEqual(details['matches'], [])
        self.assertEqual(details['false_positives'], [])
        self.assertIsNone(details['metrics']['tp'])
        self.assertEqual(details['metrics']['precision']['unavailable_reason'],
                         'real_industrial_evaluation_not_performed')
        self.assertEqual(details['unscored']['predictions'], values[0]['events'])

    def test_limit_provenance_and_input_nonmutation(self):
        values = fixture()
        before = copy.deepcopy(values)
        details = self.details(values)
        self.assertEqual(values, before)
        self.assertEqual(details['limits']['events_per_side'], 500)
        self.assertIn('not a cryptographic custody proof', details['provenance_note'])
        self.assertIn('does not prove a prior freeze', details['freeze_note'])
        values[0]['events'] = [event(f'p{index}', 0) for index in range(501)]
        with self.assertRaisesRegex(ValueError, '500 events per side'):
            evaluate_detailed(*values)


if __name__ == '__main__':
    unittest.main()
