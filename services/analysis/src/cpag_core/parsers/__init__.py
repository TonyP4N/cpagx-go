"""Explicit adapters; no raw packet decoding or cross-source alignment."""
from ..measurement import phase
import csv
import io
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from dataclasses import dataclass
from collections import defaultdict
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _label_column(name):
    normalized = re.sub(r'[^a-z0-9]', '', str(name).lower())
    return normalized in {'label', 'labels', 'attack', 'attacklabel', 'attacktype', 'attackid', 'isattack', 'normalattack', 'groundtruth', 'gold', 'annotation', 'class', 'targetlabel'} or normalized.startswith(('attack', 'groundtruth'))


def _strict_constant(value):
    raise ValueError('nonstandard JSON constant: ' + value)


def _quality(reasons, count=None):
    result = {'status': 'partial' if reasons else 'valid', 'reasons': sorted(set(reasons))}
    if count is not None:
        result['event_count'] = count
    return result


def _time(raw, profile, *, extended=False):
    if not raw:
        return None, ['missing_time']
    try:
        # datetime only represents microseconds. Do not silently truncate finer
        # CSV time precision and then claim a narrower aligned interval.
        fraction = re.search(r'[T ]\d{2}:\d{2}:\d{2}[.,](\d+)', raw)
        if extended and fraction and len(fraction.group(1)) > 6:
            return None, ['timestamp_precision_unsupported']
        dt = datetime.strptime(raw, profile['timestamp_format']) if profile.get('timestamp_format') else datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            if not profile.get('timezone') or not profile.get('timezone_evidence'):
                return None, ['unknown_timezone']
            dt = dt.replace(tzinfo=ZoneInfo(profile['timezone']))
            # Reject ambiguous/nonexistent local times rather than silently choosing a fold.
            other = dt.replace(fold=1)
            if dt.utcoffset() != other.utcoffset() or dt.astimezone(timezone.utc).astimezone(dt.tzinfo).replace(tzinfo=None) != dt.replace(tzinfo=None):
                return None, ['ambiguous_or_nonexistent_local_time']
        return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'), []
    except (ValueError, TypeError, ZoneInfoNotFoundError):
        return None, ['invalid_time']


def _base(digest, number, column, raw, synthetic, kind):
    identity = f'{kind}:{digest}:{number}:{column}'
    return {'schema_version': '1.0.0', 'synthetic': synthetic,
            'event_id': hashlib.sha256(identity.encode()).hexdigest(), 'ingest_time': None,
            'source_ref': {'file_sha256': digest, 'record_number': number, 'frame_number': None, 'column': column, 'raw_time': raw}}


def _unsupported(reason):
    return {'events': [], 'quality': {'status': 'unsupported', 'reasons': [reason], 'event_count': 0}}


def parse_network(path, *, synthetic=True, evidence=None):
    """Read explicitly synthetic normalized JSONL adapter records, never PCAP bytes."""
    path = Path(path)
    if path.suffix.lower() in {'.pcap', '.pcapng', '.cap'}:
        return _unsupported('raw_packet_adapter_pending_independent_validation')
    if path.suffix.lower() != '.jsonl' or synthetic is not True:
        return _unsupported('only_synthetic_normalized_jsonl_supported')
    digest = evidence.digest if evidence is not None else _file_hash(path)
    events, errors = [], []
    try:
        with (io.StringIO(evidence.text) if evidence is not None else path.open(encoding='utf-8')) as stream:
            for number, line in enumerate(stream, 1):
                try:
                    obj = json.loads(line, parse_constant=_strict_constant)
                    if not isinstance(obj, dict) or obj.get('synthetic') is not True or obj.get('record_type') != 'synthetic_normalized_network':
                        raise ValueError('not explicitly synthetic normalized adapter record')
                    fields = ('source', 'destination', 'protocol', 'operation', 'correlation_id', 'response_status', 'raw_time')
                    if set(obj) - set(fields) - {'synthetic', 'record_type'}:
                        raise ValueError('unknown_or_label_fields')
                    if any(obj.get(key) is not None and not isinstance(obj[key], str) for key in fields):
                        raise ValueError('fields must be strings or null')
                    raw = obj.get('raw_time')
                    when, reasons = _time(raw, {})
                    reasons.extend('missing_' + key for key in fields[:-1] if not obj.get(key))
                    event = _base(digest, number, None, raw, True, 'network')
                    event.update(event_time=when, endpoints={'source': obj.get('source'), 'destination': obj.get('destination')},
                                 **{key: obj.get(key) for key in fields[2:6]})
                    event['quality'] = _quality(reasons)
                    events.append(event)
                    errors.extend(reasons)
                except (ValueError, TypeError) as exc:
                    errors.append(f'invalid_jsonl_record:{number}:{exc}')
    except UnicodeError:
        errors.append('invalid_utf8')
    return {'events': events, 'quality': _quality(errors, len(events))}


@dataclass(frozen=True)
class ProcessLimits:
    max_bytes: int = 2 * 1024 * 1024
    max_records: int = 1000
    max_columns: int = 16

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError('process limits must be positive integers')


@phase('process_parse')
def parse_process(path, profile, *, synthetic=True, evidence=None, limits=None, extended=False):
    """CSV logical records with explicit per-column definitions; no interpolation."""
    path = Path(path)
    if path.suffix.lower() != '.csv':
        return _unsupported('only_csv_process_adapter_supported')
    if not isinstance(profile, dict) or not profile.get('timestamp_column') or not profile.get('columns'):
        return _unsupported('explicit_timestamp_and_column_profile_required')
    if type(synthetic) is not bool or ('synthetic' in profile and (type(profile['synthetic']) is not bool or profile['synthetic'] != synthetic)):
        return _unsupported('synthetic_profile_mismatch')
    columns = profile['columns']
    if not isinstance(columns, dict) or any(not isinstance(v, dict) or not v.get('tag') or v.get('value_type') not in ('analog', 'state') or ('state_map' in v and not isinstance(v['state_map'], dict)) for v in columns.values()):
        return _unsupported('invalid_column_profile')
    if any(_label_column(c) or _label_column(v.get('tag')) for c, v in columns.items()) or _label_column(profile['timestamp_column']):
        return _unsupported('label_fields_forbidden_in_analysis_input')
    if type(extended) is not bool:
        raise ValueError('extended must be boolean')
    limits = limits or (ProcessLimits() if extended else None)
    if limits is not None and (getattr(evidence, 'size_bytes', len(evidence.text.encode('utf-8'))) if evidence is not None else path.stat().st_size) > limits.max_bytes:
        return _unsupported('process_byte_limit')
    digest = evidence.digest if evidence is not None else _file_hash(path)
    events, errors = [], []
    record_groups = defaultdict(list)
    try:
        with (io.StringIO(evidence.text.lstrip('\ufeff'), newline='') if evidence is not None else path.open(encoding='utf-8-sig', newline='')) as stream:
            reader = csv.reader(stream, strict=True)
            header = next(reader, [])
            if limits is not None and len(header) > limits.max_columns:
                return _unsupported('process_column_limit')
            if any(_label_column(c) for c in header):
                return _unsupported('label_fields_forbidden_in_analysis_input')
            if len(header) != len(set(header)) or profile['timestamp_column'] not in header or any(c not in header for c in columns):
                return _unsupported('missing_or_duplicate_profile_columns')
            for number, values in enumerate(reader, 1):
                if limits is not None and number > limits.max_records:
                    return _unsupported('process_record_limit')
                if len(values) != len(header):
                    errors.append(f'invalid_csv_record_width:{number}')
                    continue
                record_groups[tuple(values)].append(number)
                row = dict(zip(header, values))
                raw_time = row[profile['timestamp_column']]
                when, time_reasons = _time(raw_time, profile, extended=extended)
                for column, definition in columns.items():
                    raw = row[column]
                    reasons = list(time_reasons)
                    value = None
                    if raw.strip() in profile.get('missing_values', ['', 'NA', 'N/A', 'null']):
                        reasons.append('missing_value')
                    elif definition['value_type'] == 'analog':
                        try:
                            value = float(raw)
                            if not math.isfinite(value):
                                value = None
                                reasons.append('nonfinite_value')
                        except ValueError:
                            reasons.append('invalid_numeric_value')
                    else:
                        state_map = definition.get('state_map')
                        if state_map is None:
                            value = raw
                        elif raw in state_map and isinstance(state_map[raw], (str, int, float, bool)) and (not isinstance(state_map[raw], float) or math.isfinite(state_map[raw])):
                            value = state_map[raw]
                        else:
                            reasons.append('unknown_state')
                    if not definition.get('asset_id'):
                        reasons.append('unresolved_asset')
                    event = _base(digest, number, column, raw_time, synthetic, 'process')
                    event.update(event_time=when, tag=definition['tag'], value=value, value_type=definition['value_type'],
                                 unit=definition.get('unit'), asset_id=definition.get('asset_id'), quality=_quality(reasons))
                    events.append(event)
                    errors.extend(reasons)
    except (csv.Error, UnicodeError) as exc:
        errors.append(f'invalid_or_truncated_csv:{exc}')
    if not extended:
        return {'events': events, 'quality': _quality(errors, len(events))}
    duplicate_records = {number for members in record_groups.values() if len(members) > 1 for number in members}
    time_groups = defaultdict(list)
    for event in events:
        if event['event_time'] is not None:
            time_groups[(event['source_ref']['column'], event['event_time'])].append(event)
        if event['source_ref']['record_number'] in duplicate_records:
            event['quality'] = _quality(event['quality']['reasons'] + ['duplicate_process_record'])
            errors.append('duplicate_process_record')
    for members in time_groups.values():
        if len(members) > 1:
            errors.append('duplicate_process_time')
            for event in members:
                event['quality'] = _quality(event['quality']['reasons'] + ['duplicate_process_time'])
    return {'events': events, 'quality': _quality(errors, len(events))}
