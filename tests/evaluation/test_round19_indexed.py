"""Independent oracles for explicit V2; final-artifact throughput is separate."""
import copy
from datetime import datetime, timedelta, timezone
from itertools import combinations_with_replacement
import unittest

from cpag_core.evaluation import digest
from cpag_core.evaluation_details import (evaluate_detailed, validate_matching_version,
    MATCHING_VERSION, DETAILS_VERSION, V2_MATCHING_VERSION, V2_DETAILS_VERSION)
from cpag_core.evaluation_indexed import EVENT_LIMIT, maximum_pairs, _compatible
from test_round19_details import fixture, event


def v2(values):
    return evaluate_detailed(*values, matching_version=V2_MATCHING_VERSION)


def at(milliseconds):
    return (datetime(2026, 1, 1, 2, tzinfo=timezone.utc) + timedelta(milliseconds=milliseconds)).isoformat()


def observation(identity, milliseconds, kind='network_operation'):
    row = event(identity, 0, kind=kind)
    row['time'] = at(milliseconds)
    return row


def exhaustive_size(p_times, g_times, tolerance):
    """Small independent enumeration of all assignments, not greedy matching."""
    def search(index, used):
        if index == len(p_times):
            return 0
        best = search(index + 1, used)
        for target, time in enumerate(g_times):
            if target not in used and abs(p_times[index] - time) <= tolerance:
                best = max(best, 1 + search(index + 1, used | {target}))
        return best
    return search(0, set())


class IndexedEvaluationTests(unittest.TestCase):
    def test_explicit_version_pair_and_legacy_default_unchanged(self):
        values = fixture()
        legacy = evaluate_detailed(*values)
        self.assertEqual(legacy, evaluate_detailed(*values, matching_version=MATCHING_VERSION))
        self.assertEqual(legacy['details']['schema_version'], DETAILS_VERSION)
        modern = v2(values)
        self.assertEqual(modern['record']['metrics'], legacy['record']['metrics'])
        self.assertNotEqual(modern['record']['evaluation_id'], legacy['record']['evaluation_id'])
        self.assertEqual(modern['details']['schema_version'], V2_DETAILS_VERSION)
        for matching, details in ((MATCHING_VERSION, V2_DETAILS_VERSION), (V2_MATCHING_VERSION, DETAILS_VERSION),
                                  ('unknown', None), ([], None)):
            with self.subTest(matching=matching), self.assertRaises(ValueError):
                validate_matching_version(matching, details)

    def test_handwritten_p01_p02_p03_p04_p05_p06(self):
        values = fixture()
        self.assertEqual(v2(values)['record']['metrics']['tp'], 1)
        self.assertEqual(v2(values)['record']['metrics']['fp'], 1)
        self.assertEqual(v2(values)['record']['metrics']['fn'], 1)
        values[0]['events'] = [event('p', 1)]
        values[1]['events'] = [event('g', 0)]
        self.assertEqual(v2(values)['record']['metrics']['tp'], 1)
        values[3]['tolerance_seconds'] = .999
        self.assertEqual(v2(values)['record']['metrics']['tp'], 0)
        values[3]['tolerance_seconds'] = 1
        values[0]['events'] = [event('p1', 0), event('p2', 0)]
        details = v2(values)['details']
        self.assertEqual((details['metrics']['tp'], details['metrics']['fp'], details['metrics']['fn']), (1, 1, 0))
        values[0]['events'] = [event('flexible', 1), event('restricted', 0)]
        values[1]['events'] = [event('g1', 0), event('g2', 2)]
        details = v2(values)['details']
        self.assertEqual({row['prediction_id']: row['reference_id'] for row in details['matches']},
                         {'restricted': 'g1', 'flexible': 'g2'})
        values[0]['events'] = []
        values[1]['events'] = [event('independent-miss', 0)]
        details = v2(values)['details']
        self.assertIsNone(details['metrics']['precision']['value'])
        self.assertEqual(details['metrics']['recall']['value'], 0)
        self.assertEqual(details['false_negatives'][0]['event_id'], 'independent-miss')
        values[1]['events'] = []
        values[2]['blocks'][2]['normal'] = False
        values[3]['split_sha256'] = digest(values[2])
        details = v2(values)['details']
        for name in ('precision', 'recall', 'unmatched_predictions_per_normal_hour'):
            self.assertIsNone(details['metrics'][name]['value'])
            self.assertEqual(details['metrics'][name]['denominator'], 0)

    def test_dispute_union_reference_exclusion_and_half_open_boundaries(self):
        values = fixture()
        values[0]['events'] = [observation('p-excluded', 0)]
        values[1]['events'] = [observation('g-excluded', 0)]
        for identity, minute in [('before', 9), ('left', 10), ('right', 30)]:
            row = event(identity, 0, normal=True)
            row['time'] = f'2026-01-01T03:{minute:02d}:00Z'
            values[0]['events'].append(row)
        values[1]['disputed_intervals'] = [
            {'batch': 'batch', 'start': '2026-01-01T02:00:00Z', 'end': '2026-01-01T02:00:01Z'},
            {'batch': 'batch', 'start': '2026-01-01T03:10:00Z', 'end': '2026-01-01T03:20:00Z'},
            {'batch': 'batch', 'start': '2026-01-01T03:15:00Z', 'end': '2026-01-01T03:30:00Z'}]
        details = v2(values)['details']
        self.assertEqual((details['metrics']['tp'], details['metrics']['fp'], details['metrics']['fn']), (0, 2, 0))
        self.assertEqual(details['normal_duration']['counted_seconds'], 2400)
        self.assertEqual(details['metrics']['unmatched_predictions_per_normal_hour']['value'], 3)
        self.assertEqual(details['normal_unmatched_prediction_ids'], ['before', 'right'])
        self.assertEqual(details['excluded']['reference_events'][0]['event_id'], 'g-excluded')
        self.assertEqual(details['dispute_unions'][1]['source_disputed_interval_indices'], [1, 2])

    def test_exhaustive_independent_maximum_for_small_dense_and_sparse_sets(self):
        arrays = [tuple(values) for length in range(5)
                  for values in combinations_with_replacement((0, 1, 3), length)]
        for p_times in arrays:
            for g_times in arrays:
                pred = [event('p' + str(i), 0) for i in range(len(p_times))]
                gold = [event('g' + str(i), 0) for i in range(len(g_times))]
                pairs, _, _ = maximum_pairs(pred, gold, p_times, g_times, 1)
                self.assertEqual(len(pairs), exhaustive_size(p_times, g_times, 1), (p_times, g_times))
                self.assertEqual(len({i for i, _ in pairs}), len(pairs))
                self.assertEqual(len({j for _, j in pairs}), len(pairs))

    def test_20000_two_kinds_with_independent_duplicate_and_missed_reference(self):
        values = fixture()
        # Source table: 10000 operations and 10000 changes. The last source row
        # has no gold; a distinct gold at20min has no prediction; row0 repeats.
        values[0]['events'] = [observation(f'p{i:05d}', i * 10,
                                'network_operation' if i < 10000 else 'process_change') for i in range(20000)]
        values[0]['events'].append(observation('p-duplicate', 0))
        values[1]['events'] = [observation(f'g{i:05d}', i * 10,
                                'network_operation' if i < 10000 else 'process_change') for i in range(19999)]
        values[1]['events'].append(observation('g-independent-miss', 1200000, kind='process_change'))
        values[3]['tolerance_seconds'] = 0
        result = v2(values)
        self.assertEqual(tuple(result['record']['metrics'][key] for key in ('tp', 'fp', 'fn')), (19999, 2, 1))
        self.assertEqual(result['details']['by_kind']['network_operation']['tp'], 10000)
        self.assertEqual(result['details']['by_kind']['process_change']['tp'], 9999)
        self.assertEqual(result['details']['metrics']['precision']['denominator'], 20001)
        self.assertEqual(result['details']['metrics']['recall']['denominator'], 20000)
        self.assertEqual(result['details']['false_negatives'][0]['event_id'], 'g-independent-miss')

    def test_22000_dense_same_time_one_to_one_and_bounded_compatibility_examples(self):
        values = fixture()
        values[0]['events'] = [event(f'p{i:05d}', 0) for i in range(EVENT_LIMIT)]
        values[1]['events'] = [event(f'g{i:05d}', 0) for i in range(EVENT_LIMIT)]
        values[3]['tolerance_seconds'] = 0
        result = v2(values)
        self.assertEqual(tuple(result['record']['metrics'][key] for key in ('tp', 'fp', 'fn')), (22000, 0, 0))
        self.assertEqual(len({row['prediction_id'] for row in result['details']['matches']}), 22000)
        self.assertEqual(len({row['reference_id'] for row in result['details']['matches']}), 22000)
        values[1]['events'].pop()
        details = v2(values)['details']
        error = details['false_positives'][0]
        self.assertEqual(error['compatible_reference_count'], 21999)
        self.assertEqual(len(error['compatible_reference_ids']), 20)
        self.assertTrue(error['compatible_ids_truncated'])
        self.assertEqual((details['metrics']['tp'], details['metrics']['fp'], details['metrics']['fn']), (21999, 1, 0))
        values[0]['events'].append(event('over-capacity', 0))
        with self.assertRaisesRegex(ValueError, '22000 events per side'):
            v2(values)
        with self.assertRaisesRegex(ValueError, '500 events per side'):
            evaluate_detailed(*values)

    def test_permutation_invariant_assignment_and_unicode_ids(self):
        values = fixture()
        values[0]['events'] = [event('p-z', 0), event('p-a', 0)]
        values[1]['events'] = [event('\U0010ffff' * 4, 0)]
        first = v2(values)['details']
        values[0]['events'].reverse()
        values[1]['events'].reverse()
        second = v2(values)['details']
        self.assertEqual(first['matches'], second['matches'])
        self.assertEqual(first['false_positives'], second['false_positives'])
        self.assertEqual(first['false_positives'][0]['compatible_reference_count'], 1)

    def test_compatibility_range_never_relaxes_absolute_tolerance(self):
        pred = event('p', 0)
        for tolerance in (0, .00000001, .9999999, 1, 1.0000001, 1e100):
            times = [1767225600 + delta for delta in (-2, -1, -.0000002384185791, 0, .0000002384185791, 1, 2)]
            other = [event('g' + str(i), 0) for i in range(len(times))]
            groups = {('batch', 'network_operation', 'device'): [(time, row['id'], i) for i, (time, row) in enumerate(zip(times, other))]}
            count, examples = _compatible(pred, 1767225600, other, groups, tolerance)
            expected = [row['id'] for time, row in zip(times, other) if abs(time - 1767225600) <= tolerance]
            self.assertEqual(count, len(expected))
            self.assertEqual(examples, expected)

    def test_v2_rejects_same_provenance_and_split_failures_and_keeps_no_real_scores(self):
        for mode in ('overlap', 'duplicate_sample', 'isolation', 'config', 'duplicate_event', 'normal_gold', 'attack'):
            values = fixture()
            if mode == 'overlap':
                values[2]['blocks'][1]['start'] = '2026-01-01T00:59:00Z'
            if mode == 'duplicate_sample':
                values[2]['blocks'][1]['sample_sha256'] = ['a' * 64]
            if mode == 'isolation':
                values[2]['isolation_seconds'] = 59
            if mode == 'config':
                values[0]['config_fingerprint'] = '0' * 64
            if mode == 'duplicate_event':
                values[0]['events'].append(copy.deepcopy(values[0]['events'][0]))
            if mode == 'normal_gold':
                values[2]['blocks'][1]['normal'] = True
            if mode == 'attack':
                values[0]['events'][0]['kind'] = 'hypothetical_attack'
            values[3]['split_sha256'] = digest(values[2])
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                v2(values)
        values = fixture()
        values[0]['synthetic'] = False
        result = v2(values)
        self.assertTrue(all(value is None for value in result['record']['metrics'].values()))
        self.assertEqual(result['details']['matches'], [])
        self.assertEqual(result['details']['unscored']['prediction_ids'], ['p1', 'p2'])
        self.assertIsNone(result['path_accuracy'])


if __name__ == '__main__':
    unittest.main()
