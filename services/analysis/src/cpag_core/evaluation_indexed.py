"""Opt-in V2 synthetic observation matching with bounded, indexed storage.

This module never predicts or reads artifacts. Labels remain caller-supplied.
For equal time tolerances, pairing the earliest compatible prediction/reference
within each batch/kind/asset group yields a maximum-cardinality matching: an
optimal assignment can exchange its first crossed pair for the two earliest
points without decreasing cardinality. It does not minimize time distance.
"""
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from math import inf, nextafter
from operator import itemgetter

from .contracts import validate
from .evaluation import check_schema, digest, instant, number
from .evaluation_details import (_interval, _metrics, SUPPORTED_KINDS,
                                 V2_MATCHING_VERSION, V2_DETAILS_VERSION)

EVENT_LIMIT = 22000
COMPATIBILITY_EXAMPLES_LIMIT = 20
PROVENANCE = 'Independence and opening times are declared provenance, not a cryptographic custody proof.'


class HoldoutIndex:
    def __init__(self, split):
        check_schema('EvaluationSplit', split)
        windows = split['rule_windows_seconds']
        if not windows:
            raise ValueError('rule windows must be declared, use explicit zero for no window')
        largest = max(number(w, 'rule window') for w in windows.values())
        gap = number(split['isolation_seconds'], 'isolation')
        if gap < largest:
            raise ValueError('isolation smaller than maximum rule window')
        all_batches = defaultdict(list)
        self.batches = defaultdict(list)
        self.blocks = []
        seen = set()
        for index, block in enumerate(split['blocks']):
            if not block['sample_sha256']:
                raise ValueError('empty sample identity')
            start, end = instant(block['start']), instant(block['end'])
            if end <= start:
                raise ValueError('invalid split interval')
            for sample in block['sample_sha256']:
                if sample in seen:
                    raise ValueError('duplicate sample across blocks')
                seen.add(sample)
            row = (start, end, index, block, set(block['sample_sha256']))
            all_batches[block['batch']].append(row)
            self.blocks.append(row)
            if block['partition'] == 'holdout':
                self.batches[block['batch']].append(row)
        if {row[3]['partition'] for row in self.blocks} != {'calibration', 'holdout'}:
            raise ValueError('both calibration and holdout required')
        for rows in all_batches.values():
            rows.sort(key=lambda row: (row[0], row[1], row[2]))
            for left, right in zip(rows, rows[1:]):
                separation = right[0] - left[1]
                if separation < 0:
                    raise ValueError('overlapping split blocks')
                if left[3]['partition'] != right[3]['partition'] and separation < gap:
                    raise ValueError('insufficient boundary isolation')
        self.starts = {}
        for batch, rows in self.batches.items():
            rows.sort(key=lambda row: (row[0], row[1], row[2]))
            self.starts[batch] = [row[0] for row in rows]

    def at(self, batch, at):
        rows = self.batches.get(batch, ())
        index = bisect_right(self.starts.get(batch, ()), at) - 1
        return rows[index] if index >= 0 and at < rows[index][1] else None

    def normal(self, batch, at):
        row = self.at(batch, at)
        return row is not None and row[3]['normal']


class DisputeIndex:
    def __init__(self, annotations, holdout):
        grouped = defaultdict(list)
        for index, item in enumerate(annotations['disputed_intervals']):
            start, end = instant(item['start']), instant(item['end'])
            block = holdout.at(item['batch'], start)
            if end <= start or block is None or end > block[1]:
                raise ValueError('dispute outside holdout')
            grouped[item['batch']].append((start, end, index))
        self.batches = {}
        self.starts = {}
        self.ends = {}
        self.rows = []
        for batch in sorted(grouped):
            merged = []
            for start, end, index in sorted(grouped[batch]):
                if merged and start <= merged[-1][1]:
                    merged[-1][1] = max(end, merged[-1][1])
                    merged[-1][2].append(index)
                else:
                    merged.append([start, end, [index]])
            rows = []
            for start, end, indices in merged:
                identity = len(self.rows)
                self.rows.append(dict(_interval(start, end), union_index=identity,
                                      batch=batch, source_disputed_interval_indices=sorted(indices)))
                rows.append((start, end, identity))
            self.batches[batch] = rows
            self.starts[batch] = [row[0] for row in rows]
            self.ends[batch] = [row[1] for row in rows]

    def at(self, batch, at):
        rows = self.batches.get(batch, ())
        index = bisect_right(self.starts.get(batch, ()), at) - 1
        return rows[index][2] if index >= 0 and at < rows[index][1] else None

    def normal_duration(self, holdout):
        rows = []
        for start, end, index, block, _ in holdout.blocks:
            if block['partition'] != 'holdout' or not block['normal']:
                continue
            cursor = start
            counted, excluded = [], []
            overlaps = self.batches.get(block['batch'], ())
            left = bisect_right(self.ends.get(block['batch'], ()), start)
            for overlap_index in range(left, len(overlaps)):
                s, e, union = overlaps[overlap_index]
                if s >= end:
                    break
                s, e = max(start, s), min(end, e)
                if s > cursor:
                    counted.append(_interval(cursor, s))
                excluded.append(dict(_interval(s, e), union_index=union))
                cursor = max(cursor, e)
            if cursor < end:
                counted.append(_interval(cursor, end))
            rows.append({'block_index': index, 'batch': block['batch'],
                         'declared': _interval(start, end), 'excluded_disputed_union': excluded,
                         'counted': counted, 'counted_seconds': sum(item['seconds'] for item in counted)})
        return rows


def _group(event):
    return event['batch'], event['kind'], event['asset']


def _ordered_groups(events, times):
    grouped = defaultdict(list)
    for index, (event, at) in enumerate(zip(events, times)):
        grouped[_group(event)].append((at, event['id'], index))
    for rows in grouped.values():
        rows.sort()
    return dict(grouped)


def maximum_pairs(pred, gold, pred_times, gold_times, tolerance):
    """O(n log n) storage/time for dense and sparse equal-tolerance groups."""
    p_groups, g_groups = _ordered_groups(pred, pred_times), _ordered_groups(gold, gold_times)
    pairs = []
    for key in sorted(p_groups):
        p_rows, g_rows = p_groups[key], g_groups.get(key, ())
        i = j = 0
        while i < len(p_rows) and j < len(g_rows):
            p_at, _, p_index = p_rows[i]
            g_at, _, g_index = g_rows[j]
            if abs(p_at - g_at) <= tolerance:
                pairs.append((p_index, g_index))
                i += 1
                j += 1
            elif p_at < g_at:
                i += 1
            else:
                j += 1
    return pairs, p_groups, g_groups


def _compatible(event, at, other, groups, tolerance):
    rows = groups.get(_group(event), ())
    # The key avoids assumptions about event ID alphabets. Expand floating
    # search bounds, then apply the frozen absolute-difference comparison to
    # boundary time groups so range arithmetic cannot widen the tolerance.
    key = itemgetter(0)
    left = bisect_left(rows, nextafter(at - tolerance, -inf), key=key)
    right = bisect_right(rows, nextafter(at + tolerance, inf), key=key)
    while left < right and abs(rows[left][0] - at) > tolerance:
        left = bisect_right(rows, rows[left][0], lo=left, hi=right, key=key)
    while left < right and abs(rows[right - 1][0] - at) > tolerance:
        right = bisect_left(rows, rows[right - 1][0], lo=left, hi=right, key=key)
    count = right - left
    examples = [other[rows[i][2]]['id'] for i in range(left, min(right, left + COMPATIBILITY_EXAMPLES_LIMIT))]
    return count, examples


def evaluate_indexed(predictions, annotations, split, registration):
    for dataset in (predictions, annotations):
        if isinstance(dataset, dict) and isinstance(dataset.get('events'), list) and len(dataset['events']) > EVENT_LIMIT:
            raise ValueError('indexed evaluator limit: 22000 events per side')
    for name, value in (('EvaluationPredictions', predictions), ('EvaluationAnnotations', annotations),
                        ('EvaluationRegistration', registration)):
        check_schema(name, value)
    if max(len(predictions['events']), len(annotations['events'])) > EVENT_LIMIT:
        raise ValueError('indexed evaluator limit: 22000 events per side')
    holdout = HoldoutIndex(split)
    if registration['split_sha256'] != digest(split):
        raise ValueError('split changed after registration')
    if any(registration[key] != predictions[key] for key in ('input_fingerprint', 'config_fingerprint')):
        raise ValueError('prediction identity differs from frozen registration')
    if instant(registration['registered_at']) >= instant(registration['holdout_opened_at']):
        raise ValueError('registration must precede holdout opening')
    if annotations['origin'] != 'independent' or not all(annotations[key].strip() for key in ('review_ref', 'source_ref', 'annotation_version')):
        raise ValueError('independent reviewed annotations required')
    tolerance = number(registration['tolerance_seconds'], 'tolerance')
    for value in registration['thresholds'].values():
        number(value, 'threshold')
    all_times = []
    for dataset in (predictions, annotations):
        seen, times = set(), []
        for event in dataset['events']:
            if event['id'] in seen:
                raise ValueError('duplicate event identity')
            seen.add(event['id'])
            if event['kind'] not in SUPPORTED_KINDS:
                raise ValueError('detailed evaluation supports observation kinds only; relations are unlabelled')
            at = instant(event['time'])
            block = holdout.at(event['batch'], at)
            if block is None or event['sample_sha256'] not in block[4]:
                raise ValueError('event outside holdout')
            times.append(at)
        all_times.append(times)
    for event, at in zip(annotations['events'], all_times[1]):
        if holdout.normal(event['batch'], at):
            raise ValueError('positive gold inside declared normal interval')
    disputes = DisputeIndex(annotations, holdout)
    eligible, eligible_times, excluded = [], [], {}
    for name, dataset, times in zip(('predictions', 'reference_events'), (predictions, annotations), all_times):
        events, ats, omissions = [], [], []
        for event, at in zip(dataset['events'], times):
            union = disputes.at(event['batch'], at)
            if union is None:
                events.append(event)
                ats.append(at)
            else:
                omissions.append({'event_id': event['id'], 'reason': 'disputed_interval', 'dispute_union_index': union})
        eligible.append(events)
        eligible_times.append(ats)
        excluded[name] = omissions
    pred, gold = eligible
    pred_times, gold_times = eligible_times
    enabled = all(value['synthetic'] for value in (predictions, annotations, split, registration))
    pairs, p_groups, g_groups = maximum_pairs(pred, gold, pred_times, gold_times, tolerance) if enabled else ([], {}, {})
    matched_pred = {i for i, _ in pairs}
    matched_gold = {j for _, j in pairs}
    matches = [{'prediction_id': pred[i]['id'], 'reference_id': gold[j]['id'], 'kind': pred[i]['kind'],
                'absolute_time_difference_seconds': abs(pred_times[i] - gold_times[j])}
               for i, j in pairs]
    false_positives, false_negatives = [], []
    if enabled:
        for own, times, matched, other, groups, rows, key in (
                (pred, pred_times, matched_pred, gold, g_groups, false_positives, 'reference'),
                (gold, gold_times, matched_gold, pred, p_groups, false_negatives, 'prediction')):
            for index, (event, at) in enumerate(zip(own, times)):
                if index in matched:
                    continue
                count, examples = _compatible(event, at, other, groups, tolerance)
                rows.append({'event_id': event['id'], 'reason': 'compatible_' + key + 's_already_assigned' if count
                             else 'no_compatible_' + key + '_within_tolerance',
                             'compatible_' + key + '_count': count,
                             'compatible_' + key + '_ids': examples,
                             'compatible_ids_truncated': count > len(examples)})
    normal_rows = disputes.normal_duration(holdout)
    seconds = sum(row['counted_seconds'] for row in normal_rows)
    normal_unmatched = [event for i, event in enumerate(pred) if enabled and i not in matched_pred
                        and holdout.normal(event['batch'], pred_times[i])]
    metrics = _metrics(len(pairs), len(pred) - len(pairs), len(gold) - len(pairs), len(normal_unmatched), seconds, enabled)
    p_counts, g_counts = Counter(event['kind'] for event in pred), Counter(event['kind'] for event in gold)
    tp_counts = Counter(row['kind'] for row in matches)
    normal_counts = Counter(event['kind'] for event in normal_unmatched)
    by_kind = {kind: _metrics(tp_counts[kind], p_counts[kind] - tp_counts[kind], g_counts[kind] - tp_counts[kind],
                              normal_counts[kind], seconds, enabled)
               for kind in sorted(set(p_counts) | set(g_counts) | {'network_operation', 'process_change'})}
    record_metrics = {'tp': metrics['tp'], 'fp': metrics['fp'], 'fn': metrics['fn'],
                      'precision': metrics['precision']['value'], 'recall': metrics['recall']['value'],
                      'normal_hours': metrics['normal_hours'],
                      'false_alarms_per_normal_hour': metrics['unmatched_predictions_per_normal_hour']['value']}
    if not enabled:
        record_metrics = {key: None for key in record_metrics}
    policy = {'version': V2_MATCHING_VERSION, 'dimensions': ['batch', 'kind', 'asset'],
              'tolerance_seconds': tolerance, 'time_boundary': 'absolute_difference <= tolerance',
              'interval_boundary': 'start <= time < end', 'objective': 'maximum_cardinality_one_to_one',
              'tie_break': 'ascending_time_then_event_id_in_each_batch_kind_asset_group',
              'sample_identity': 'validated holdout membership; matching uses the declared batch timeline',
              'distance_optimization': False}
    record = {'schema_version': '1.0.0', 'synthetic': enabled,
              'evaluation_id': 'evaluation-' + digest([V2_MATCHING_VERSION, predictions, annotations, split, registration]),
              'run_id': predictions['run_id'], 'data_split': digest(split), 'label_source': annotations['source_ref'],
              'annotation_version': annotations['annotation_version'],
              'matching_strategy': 'indexed temporal maximum-cardinality one-to-one; explicit batch/kind/asset, inclusive time tolerance',
              'metrics': record_metrics, 'error_analysis': [
                  'Synthetic calculation only; real industrial evaluation not performed.',
                  'Unlabelled relations excluded; no path gold or path accuracy.'], 'independent_labels': True}
    validate('EvaluationRecord', record)
    details = {'schema_version': V2_DETAILS_VERSION, 'status': 'synthetic_software_test' if enabled else 'not_evaluated',
               'scope': 'synthetic observation matching only; no attack, path, or industrial alarm accuracy',
               'matching_policy': policy, 'matching_policy_sha256': digest(policy),
               'limits': {'events_per_side': EVENT_LIMIT, 'compatibility_examples_per_error': COMPATIBILITY_EXAMPLES_LIMIT,
                          'capacity_acceptance': 'evaluator_only; analysis_worker_and_real_material_acceptance_separate',
                          'event_basis': 'final observed operations and changes, not CSV cell observations; no truncation'},
               'metrics': metrics, 'by_kind': by_kind, 'matches': matches,
               'false_positives': false_positives, 'false_negatives': false_negatives, 'excluded': excluded,
               'unscored': {'prediction_ids': [event['id'] for event in pred], 'reference_ids': [event['id'] for event in gold]}
               if not enabled else {'prediction_ids': [], 'reference_ids': []},
               'normal_duration': {'declared_seconds': sum(row['declared']['seconds'] for row in normal_rows),
                                   'excluded_seconds': sum(sum(x['seconds'] for x in row['excluded_disputed_union']) for row in normal_rows),
                                   'counted_seconds': seconds, 'blocks': normal_rows,
                                   'basis': 'common declared normal holdout intervals for observation kinds'},
               'dispute_unions': disputes.rows,
               'normal_unmatched_prediction_ids': [event['id'] for event in normal_unmatched],
               'unlabelled_relations': list(predictions['unlabelled_relations']),
               'path_accuracy': {'value': None, 'numerator': None, 'denominator': None, 'unavailable_reason': 'no_independent_path_reference'},
               'legacy_metric_aliases': {'false_alarms_per_normal_hour':
                                        'unmatched_predictions_per_normal_hour; observation metric, not validated industrial alarms'},
               'input_sha256': {name: digest(value) for name, value in zip(
                   ('predictions', 'annotations', 'split', 'registration'), (predictions, annotations, split, registration))},
               'provenance_note': PROVENANCE,
               'freeze_note': 'The caller must verify the preregistered version and artifact binding; this sidecar alone does not prove a prior freeze.'}
    return {'record': record, 'status': details['status'], 'input_fingerprint': predictions['input_fingerprint'],
            'config_fingerprint': predictions['config_fingerprint'], 'annotation_sha256': digest(annotations),
            'registration_sha256': digest(registration), 'excluded_disputed_predictions': len(excluded['predictions']),
            'unlabelled_relations': len(predictions['unlabelled_relations']), 'path_accuracy': None,
            'provenance_note': PROVENANCE, 'details': details}
