"""Versioned observation details around the unchanged synthetic evaluator.

No predictor, label synthesis, or artifact loading occurs here. The caller must
supply independently authored labels and validate the final artifact separately.
A registration's declarations do not prove custody or label independence.
"""
from copy import deepcopy
from datetime import datetime, timezone

from .evaluation import contains, digest, evaluate, instant, validate_splits


DETAILS_VERSION = '1.0.0'
MATCHING_VERSION = 'legacy-ordered-augmenting-path-v1'
SUPPORTED_KINDS = ('network_operation', 'process_change', 'operation', 'change')
EVENT_LIMIT = 500


def _interval(start, end):
    def stamp(value):
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')
    return {'start': stamp(start), 'end': stamp(end), 'seconds': end - start}


def _normal_duration(blocks, disputes):
    """Return auditable interval union, counting each normal second only once."""
    rows = []
    for index, (block, start, end) in enumerate(blocks):
        if block['partition'] != 'holdout' or not block['normal']:
            continue
        overlaps = sorted((max(start, s), min(end, e)) for batch, s, e in disputes
                          if batch == block['batch'] and s < end and e > start)
        merged = []
        for left, right in overlaps:
            if merged and left <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(right, merged[-1][1]))
            else:
                merged.append((left, right))
        counted = []
        cursor = start
        for left, right in merged:
            if left > cursor:
                counted.append(_interval(cursor, left))
            cursor = right
        if cursor < end:
            counted.append(_interval(cursor, end))
        rows.append({'block_index': index, 'batch': block['batch'],
                     'declared': _interval(start, end),
                     'excluded_disputed_union': [_interval(s, e) for s, e in merged],
                     'counted': counted,
                     'counted_seconds': sum(item['seconds'] for item in counted)})
    return rows


def _metrics(tp, fp, fn, normal_fp, seconds, enabled):
    def metric(numerator, denominator, zero_reason):
        reason = None
        if not enabled:
            reason = 'real_industrial_evaluation_not_performed'
        elif denominator == 0:
            reason = zero_reason
        return {'value': numerator / denominator if reason is None else None,
                'numerator': numerator if enabled else None,
                'denominator': denominator,
                'unavailable_reason': reason}
    return {'tp': tp if enabled else None, 'fp': fp if enabled else None,
            'fn': fn if enabled else None,
            'precision': metric(tp, tp + fp, 'no_eligible_predictions'),
            'recall': metric(tp, tp + fn, 'no_eligible_reference_events'),
            'unmatched_predictions_per_normal_hour': metric(
                normal_fp, seconds / 3600, 'no_verified_normal_duration'),
            'normal_seconds': seconds,
            'normal_hours': seconds / 3600 if seconds else None}


def evaluate_detailed(predictions, annotations, split, registration):
    """Evaluate at most 500 events per side and explain the legacy calculation.

    The legacy return keys and values remain identical. ``details`` is a new,
    separately versioned sidecar. A maximum-cardinality tie is resolved using
    supplied prediction/reference order, exactly as in the legacy evaluator;
    there is no claim of minimum distance or permutation-invariant assignment.
    The caller's frozen bundle must bind these ordered inputs and this policy.
    """
    legacy = evaluate(predictions, annotations, split, registration)
    for dataset in (predictions, annotations):
        if any(event['kind'] not in SUPPORTED_KINDS for event in dataset['events']):
            raise ValueError('detailed evaluation supports observation kinds only; relations are unlabelled')
    blocks = validate_splits(split)
    disputes = [(item['batch'], instant(item['start']), instant(item['end']))
                for item in annotations['disputed_intervals']]

    def disputed_by(event):
        at = instant(event['time'])
        return [index for index, (batch, start, end) in enumerate(disputes)
                if batch == event['batch'] and start <= at < end]

    pred = [event for event in predictions['events'] if not disputed_by(event)]
    gold = [event for event in annotations['events'] if not disputed_by(event)]
    excluded = {}
    for name, dataset in (('predictions', predictions), ('reference_events', annotations)):
        excluded[name] = [dict(event=deepcopy(event), reason='disputed_interval',
                               disputed_interval_indices=disputed_by(event))
                          for event in dataset['events'] if disputed_by(event)]
    tolerance = registration['tolerance_seconds']
    edges = [[j for j, reference in enumerate(gold)
              if event['batch'] == reference['batch'] and event['kind'] == reference['kind']
              and event['asset'] == reference['asset']
              and abs(instant(event['time']) - instant(reference['time'])) <= tolerance]
             for event in pred]
    assigned = {}

    def augment(index, seen):
        for target in edges[index]:
            if target in seen:
                continue
            seen.add(target)
            if target not in assigned or augment(assigned[target], seen):
                assigned[target] = index
                return True
        return False

    enabled = legacy['status'] == 'synthetic_software_test'
    if enabled:
        for index in range(len(pred)):
            augment(index, set())
    matched = set(assigned.values())
    matches = [{'prediction': deepcopy(pred[i]), 'reference': deepcopy(gold[j]),
                'absolute_time_difference_seconds': abs(instant(pred[i]['time']) - instant(gold[j]['time']))}
               for j, i in sorted(assigned.items())]
    false_positive = [dict(event=deepcopy(event),
                           reason='compatible_references_already_assigned' if edges[i]
                           else 'no_compatible_reference_within_tolerance',
                           compatible_reference_ids=[gold[j]['id'] for j in edges[i]])
                      for i, event in enumerate(pred) if i not in matched] if enabled else []
    false_negative = [dict(event=deepcopy(event),
                           reason='compatible_predictions_already_assigned' if any(j in e for e in edges)
                           else 'no_compatible_prediction_within_tolerance',
                           compatible_prediction_ids=[pred[i]['id'] for i, e in enumerate(edges) if j in e])
                      for j, event in enumerate(gold) if j not in assigned] if enabled else []
    normal_rows = _normal_duration(blocks, disputes)
    seconds = sum(row['counted_seconds'] for row in normal_rows)
    normal_unmatched = [event for i, event in enumerate(pred)
                        if enabled and i not in matched
                        and contains(blocks, event['batch'], instant(event['time']), True)]
    metrics = _metrics(len(assigned), len(pred) - len(assigned), len(gold) - len(assigned),
                       len(normal_unmatched), seconds, enabled)
    by_kind = {}
    for kind in sorted(set(event['kind'] for event in pred + gold)
                       | {'network_operation', 'process_change'}):
        tp = sum(row['prediction']['kind'] == kind for row in matches)
        by_kind[kind] = _metrics(tp, sum(event['kind'] == kind for event in pred) - tp,
                                sum(event['kind'] == kind for event in gold) - tp,
                                sum(event['kind'] == kind for event in normal_unmatched), seconds, enabled)
    # Fail closed if future legacy changes invalidate the detailed explanation.
    if enabled:
        old = legacy['record']['metrics']
        actual = {name: metrics[name] for name in ('tp', 'fp', 'fn')}
        actual.update(precision=metrics['precision']['value'], recall=metrics['recall']['value'],
                      normal_hours=metrics['normal_hours'],
                      false_alarms_per_normal_hour=metrics['unmatched_predictions_per_normal_hour']['value'])
        if actual != old:
            raise ValueError('detailed matching no longer agrees with legacy evaluator')
    policy = {'version': MATCHING_VERSION,
              'dimensions': ['batch', 'kind', 'asset'],
              'tolerance_seconds': tolerance, 'time_boundary': 'absolute_difference <= tolerance',
              'interval_boundary': 'start <= time < end',
              'objective': 'maximum_cardinality_one_to_one',
              'tie_break': 'supplied_prediction_order_then_supplied_reference_order_augmenting_paths',
              'sample_identity': 'validated holdout membership; matching uses the declared batch timeline',
              'distance_optimization': False}
    details = {'schema_version': DETAILS_VERSION, 'status': legacy['status'],
               'scope': 'synthetic observation matching only; no attack, path, or industrial alarm accuracy',
               'matching_policy': policy, 'matching_policy_sha256': digest(policy),
               'limits': {'events_per_side': EVENT_LIMIT, 'capacity_acceptance': 'not_demonstrated'},
               'metrics': metrics, 'by_kind': by_kind,
               'matches': matches, 'false_positives': false_positive, 'false_negatives': false_negative,
               'excluded': excluded,
               'unscored': {'predictions': deepcopy(pred), 'reference_events': deepcopy(gold)}
               if not enabled else {'predictions': [], 'reference_events': []},
               'normal_duration': {'declared_seconds': sum(row['declared']['seconds'] for row in normal_rows),
                                   'excluded_seconds': sum(sum(x['seconds'] for x in row['excluded_disputed_union'])
                                                           for row in normal_rows),
                                   'counted_seconds': seconds, 'blocks': normal_rows,
                                   'basis': 'common declared normal holdout intervals for observation kinds'},
               'normal_unmatched_prediction_ids': [event['id'] for event in normal_unmatched],
               'unlabelled_relations': deepcopy(predictions['unlabelled_relations']),
               'path_accuracy': {'value': None, 'numerator': None, 'denominator': None,
                                 'unavailable_reason': 'no_independent_path_reference'},
               'legacy_metric_aliases': {'false_alarms_per_normal_hour':
                   'unmatched_predictions_per_normal_hour; observation metric, not validated industrial alarms'},
               'input_sha256': {'predictions': digest(predictions), 'annotations': digest(annotations),
                                'split': digest(split), 'registration': digest(registration)},
               'provenance_note': legacy['provenance_note'],
               'freeze_note': 'The caller must verify the preregistered version and artifact binding; this sidecar alone does not prove a prior freeze.'}
    return dict(legacy, details=details)
