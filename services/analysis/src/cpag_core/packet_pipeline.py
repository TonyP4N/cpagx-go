"""Explicit-source bounded packet -> NetworkEvent -> observed graph adapter.

Never imported by the default pipeline. CLI also resolves raw frame/field evidence.
"""
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
from .contracts import validate
from .parsers.packet_envelope import CaptureError, Limits, inspect_capture
from .parsers.packet_protocol import decode_payload
from .pipeline import fingerprint


@dataclass(frozen=True)
class StreamLimits:
    max_streams: int = 128
    max_segments: int = 2048
    max_stream_bytes: int = 262144
    max_pdus: int = 2048
    max_capture_seconds: int = 300
    max_processing_seconds: int = 10

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError('stream limits must be positive integers')


def checksum_evidence(raw):
    """Check captured bytes only; offload and endpoint acceptance remain unknown."""
    def residual(data):
        if len(data) % 2:
            data += b'\0'
        total = sum(int.from_bytes(data[i:i+2], 'big') for i in range(0,len(data),2))
        while total >> 16:
            total = (total & 65535) + (total >> 16)
        return (~total) & 65535
    t = {'basis':'captured_bytes_only_offload_unknown'}
    if len(raw) < 34 or raw[12:14] != b'\x08\x00':
        return {**t, 'status':'unsupported'}
    ip = raw[14:]
    ihl, length = (ip[0] & 15)*4, int.from_bytes(ip[2:4],'big')
    if ihl < 20 or length < ihl or len(ip) < length:
        return {**t, 'status':'truncated_or_invalid'}
    value = residual(ip[:ihl])
    t['ipv4'] = {'stored_hex':ip[10:12].hex(), 'residual':value, 'valid_for_captured_bytes':value == 0}
    if ip[9] == 6 and not int.from_bytes(ip[6:8],'big') & 0x3fff and length-ihl >= 20:
        tcp = ip[ihl:length]
        pseudo = ip[12:20] + b'\0\x06' + len(tcp).to_bytes(2,'big')
        value = residual(pseudo+tcp)
        t['tcp'] = {'stored_hex':tcp[16:18].hex(), 'residual':value, 'valid_for_captured_bytes':value == 0}
    return t


@dataclass(frozen=True)
class CaptureSetLimits:
    """Current execution bounds; R19 candidate capacity is not implied."""
    max_files: int = 4
    max_total_bytes: int = 16 * 1024 * 1024
    max_total_frames: int = 10000

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError('capture set limits must be positive integers')


class PacketEvidence:
    """Immutable original-file index, bounded across an ordered capture set.

    A single path retains integer .frames keys; a capture list uses (hash, frame)
    keys. Use frame(ref) for either form. Only one bounded file is read at once.
    """
    def __init__(self, path, *, synthetic=None, limits=None, capture_limits=None):
        if type(synthetic) is not bool:
            raise CaptureError('synthetic_opt_in_required')
        paths = list(path) if isinstance(path, (list, tuple)) else [path]
        self.limits = limits or Limits()
        self.capture_limits = capture_limits or (CaptureSetLimits() if isinstance(path, (list, tuple))
                                                  else CaptureSetLimits(max_total_bytes=self.limits.max_bytes,
                                                                        max_total_frames=self.limits.max_frames))
        if not 1 <= len(paths) <= self.capture_limits.max_files:
            raise CaptureError('capture_file_count_limit')
        self.paths = [Path(p) for p in paths]
        if sum(p.stat().st_size for p in self.paths) > self.capture_limits.max_total_bytes:
            raise CaptureError('aggregate_byte_limit')
        self.files = {}
        frames = []
        for original in self.paths:
            envelope = inspect_capture(original, synthetic=synthetic, limits=self.limits)
            digest = envelope['file_sha256']
            if digest in self.files:
                raise CaptureError('duplicate_capture_file')
            self.files[digest] = {'path': original, 'envelope': envelope}
            frames.extend(envelope['frames'])
            if len(frames) > self.capture_limits.max_total_frames:
                raise CaptureError('aggregate_frame_limit')
        self.file_sha256s = list(self.files)
        self.digest = self.file_sha256s[0] if len(paths) == 1 else fingerprint(self.file_sha256s)
        self.path = self.paths[0] if len(paths) == 1 else None
        self.envelope = {**next(iter(self.files.values()))['envelope'], 'frames': frames,
                         'file_sha256': self.digest, 'file_sha256s': self.file_sha256s}
        self._frames = {(f['file_sha256'], f['frame_number']): f for f in frames}
        self.frames = ({f['frame_number']: f for f in frames} if len(paths) == 1 else dict(self._frames))
        self._verified()

    def _verified(self, digest=None):
        selected = self.file_sha256s if digest is None else [digest]
        data = None
        total_bytes = 0
        for key in selected:
            with self.files[key]['path'].open('rb') as source:
                data = source.read(self.limits.max_bytes + 1)
            if len(data) > self.limits.max_bytes or hashlib.sha256(data).hexdigest() != key:
                raise CaptureError('evidence_file_hash_mismatch')
            total_bytes += len(data)
            if total_bytes > self.capture_limits.max_total_bytes:
                raise CaptureError('aggregate_byte_limit')
        return data

    @property
    def data(self):
        if self.path is None:
            raise CaptureError('multi_capture_requires_original_file_reference')
        return self._verified(self.file_sha256s[0])

    def frame(self, ref):
        n = ref.get('frame_number')
        key = (ref.get('file_sha256'), n)
        if type(n) is not int or key not in self._frames:
            raise CaptureError('invalid_frame_reference')
        return self._frames[key]

    def raw_frame(self, frame):
        # Parsing iterates files in declared order, retaining at most one file.
        digest = frame['file_sha256']
        if getattr(self, '_cached_digest', None) != digest:
            self._cached_data = self._verified(digest)
            self._cached_digest = digest
        start = frame['byte_offset']
        return self._cached_data[start:start + frame['captured_length']]

    def resolve(self, ref, field=None):
        f = self.frame(ref)
        data = self._verified(ref['file_sha256'])
        if ref.get('raw_time') != str(f['raw_timestamp']):
            raise CaptureError('evidence_raw_time_mismatch')
        for key in ('byte_offset', 'captured_length', 'original_length', 'frame_sha256'):
            if key in ref and ref[key] != f[key]:
                raise CaptureError('evidence_reference_metadata_mismatch')
        raw = data[f['byte_offset']:f['byte_offset'] + f['captured_length']]
        result = {**f, 'raw_hex': raw.hex(), 'integrity': 'file_and_frame_sha256_verified',
                  'network_checksums': checksum_evidence(raw)}
        if field is not None:
            start, length = field['frame_byte_offset'], field['length']
            if type(start) is not int or type(length) is not int or start < 0 or length < 1 or start + length > len(raw):
                raise CaptureError('field_outside_frame')
            value = raw[start:start+length]
            if value.hex() != field['hex'] or hashlib.sha256(value).hexdigest() != field['sha256']:
                raise CaptureError('field_evidence_hash_mismatch')
            result['field'] = {**field, 'absolute_byte_offset': f['byte_offset'] + start}
        return result


def standard_ref(frame):
    if 'source_ref' in frame:
        return dict(frame['source_ref'])
    return {'file_sha256': frame['file_sha256'], 'frame_number': frame['frame_number'],
            'record_number': None, 'column': None, 'raw_time': str(frame['raw_timestamp'])}


def analyze_capture(path, *, synthetic=None, limits=None, stream_limits=None, capture_limits=None, extended=None):
    if extended is None:
        extended = synthetic is False or isinstance(path, (list, tuple))
    if type(extended) is not bool:
        raise ValueError('extended must be boolean')
    started = time.monotonic()
    bounds = stream_limits or StreamLimits()
    index = PacketEvidence(path, synthetic=synthetic, limits=limits, capture_limits=capture_limits)
    return _analyze_packet_index(index, synthetic=synthetic, bounds=bounds, started=started, extended=extended, multiple=isinstance(path, (list, tuple)))


def _ref_key(ref):
    return (ref.get('file_sha256', ref.get('source_slot')), ref['frame_number'])


def analyze_prepared_frames(index, *, synthetic, final=False, stream_limits=None):
    """Analyze only the bounded arrived frames supplied by an in-memory index."""
    return _analyze_packet_index(index, synthetic=synthetic, bounds=stream_limits or StreamLimits(),
                                 started=time.monotonic(), extended=True, replay=True, final=final)


def _analyze_packet_index(index, *, synthetic, bounds, started, extended, multiple=False, replay=False, final=True):
    frames = index.envelope['frames']
    streams, connections = {}, {}
    controls = []
    rejected_epochs = set()
    rejected, observations = [], []
    incomplete = []
    pdu_count = 0
    def check_time():
        if time.monotonic() - started > bounds.max_processing_seconds:
            raise CaptureError('processing_deadline')
    def reject(reason, refs):
        item = {'reason': reason, 'source_refs': refs}
        waiting = reason in ('stream_gap', 'incomplete_encapsulation', 'segmentation_or_coalescing_unsupported')
        (incomplete if replay and not final and waiting else rejected).append(item)
    for f in frames:
        check_time()
        t, ref = f['transport'], standard_ref(f)
        if 'source_port' not in t:
            reject(t['reason'], [ref]); continue
        if 44818 not in (t['source_port'], t['destination_port']):
            continue
        endpoints = ((t['source_ip'], t['source_port']), (t['destination_ip'], t['destination_port']))
        flow = tuple(sorted(endpoints))
        flags = t['tcp_flags']
        if flow not in connections and len(connections) >= bounds.max_streams:
            raise CaptureError('connection_cache_limit')
        connection = connections.setdefault(flow, {'epoch':0,'syns':{},'fin':{},'reset':False,'data':False})
        if flags & 2:
            seq = t['sequence_number']
            same_syn = connection['syns'].get(endpoints) == seq
            peer_syn = connection['syns'].get(endpoints[::-1])
            handshake_reply = bool(flags & 16) and peer_syn is not None and t['acknowledgment_number'] == (peer_syn+1) % 2**32
            if not ((same_syn or handshake_reply) and not connection['data'] and not connection['reset'] and not connection['fin']):
                connection = {'epoch':connection['epoch']+1,'syns':{},'fin':{},'reset':False,'data':False}
                connections[flow] = connection
            connection['syns'][endpoints] = seq
        epoch = connection['epoch']
        if flags & 7:
            controls.append({'source_ref':ref,'epoch':epoch,'tcp_flags':flags,'endpoints':endpoints})
        # Control-only ACK/FIN/RST frames never invalidate previously observed bytes.
        # FIN closes just its sender; a peer can still send the response (half-close).
        invalid = None
        if t['tcp_payload_length']:
            if flags & 7:
                invalid = 'control_packet_payload_unsupported'
            elif connection['reset'] or endpoints in connection['fin']:
                invalid = 'payload_after_connection_close'
            elif flags & 0x20:
                invalid = 'tcp_urgent_unsupported'
        if flags & 1:
            previous_fin = connection['fin'].get(endpoints)
            if previous_fin is not None and previous_fin != t['sequence_number']:
                reject('conflicting_fin_sequence', [ref])
            connection['fin'][endpoints] = t['sequence_number']
        if flags & 4:
            connection['reset'] = True
        if invalid:
            reject(invalid,[ref])
            rejected_epochs.add((flow,epoch))
            continue
        if not t['tcp_payload_length']:
            continue
        connection['data'] = True
        key = (flow, epoch, endpoints)
        if key not in streams:
            if len(streams) >= bounds.max_streams:
                raise CaptureError('stream_cache_limit')
            streams[key] = {'segments': [], 'errors': set(), 'first_time': f['raw_timestamp'] / f['ticks_per_second'], 'control_refs': [], 'all_refs': []}
        s = streams[key]
        s['all_refs'].append(ref)
        timestamp = f['raw_timestamp'] / f['ticks_per_second']
        if abs(timestamp-s['first_time']) > bounds.max_capture_seconds:
            s['errors'].add('capture_time_limit')
        if f['captured_length'] != f['original_length']:
            s['errors'].add('capture_truncated'); continue
        raw = index.raw_frame(f)
        tcp_start = 14 + (raw[14] & 15) * 4
        payload_start = tcp_start + (raw[tcp_start+12] >> 4) * 4
        payload = raw[payload_start:14 + int.from_bytes(raw[16:18], 'big')]
        seq = t['sequence_number']
        if seq + len(payload) > 2**32:
            s['errors'].add('sequence_wrap_unsupported')
        if len(s['segments']) >= bounds.max_segments:
            raise CaptureError('segment_cache_limit')
        s['segments'].append((seq, payload, ref, payload_start))
    for (flow, epoch, endpoints), s in streams.items():
        check_time()
        segments = s['segments']
        refs = s['all_refs']
        if not segments:
            if s['errors']:
                reject(','.join(sorted(s['errors'])), refs)
            continue
        low = min(v[0] for v in segments)
        high = max(v[0] + len(v[1]) for v in segments)
        if high-low > bounds.max_stream_bytes:
            reject('stream_span_limit', refs); continue
        sparse = {}
        for seq, payload, _, _ in segments:
            check_time()
            for offset, value in enumerate(payload, seq):
                if offset in sparse and sparse[offset] != value:
                    s['errors'].add('conflicting_overlap')
                sparse[offset] = value
        if len(sparse) != high-low:
            s['errors'].add('stream_gap')
        if s['errors']:
            reject(','.join(sorted(s['errors'])), refs); continue
        stream = bytes(sparse[n] for n in range(low, high))
        cursor, pending = 0, []
        try:
            while cursor < len(stream):
                check_time()
                if pdu_count >= bounds.max_pdus:
                    raise CaptureError('pdu_count_limit')
                pdu_count += 1
                if len(stream)-cursor < 24:
                    raise CaptureError('incomplete_encapsulation')
                size = 24 + int.from_bytes(stream[cursor+2:cursor+4], 'little')
                pdu = stream[cursor:cursor+size]
                if len(pdu) != size:
                    raise CaptureError('segmentation_or_coalescing_unsupported')
                try:
                    decoded = decode_payload(pdu)
                    expected = endpoints[1][1] if decoded['direction'] == 'request' else endpoints[0][1]
                    if expected != 44818 or endpoints[0][1] == endpoints[1][1]:
                        raise CaptureError('direction_port_mismatch')
                except CaptureError as error:
                    if not extended:
                        raise
                    # A length-delimited unsupported PDU does not erase other
                    # observed PDUs. Its epoch is still barred from association.
                    reject(str(error), [ref for seq, payload, ref, _ in segments
                                        if seq < low+cursor+size and seq+len(payload) > low+cursor])
                    cursor += size
                    continue
                contributing, fields = [], []
                # Every intersecting segment, including identical retransmissions, retained.
                for seq, payload, ref, frame_start in segments:
                    a, b = max(seq, low+cursor), min(seq+len(payload), low+cursor+size)
                    if a < b:
                        contributing.append(ref)
                        value = payload[a-seq:b-seq]
                        fields.append({'source_ref': ref, 'frame_byte_offset': frame_start+a-seq,
                                       'pdu_byte_offset': a-low-cursor, 'length': b-a,
                                       'hex': value.hex(), 'sha256': hashlib.sha256(value).hexdigest()})
                named_ranges = {'encapsulation.command': (0,2), 'encapsulation.length': (2,2),
                                'encapsulation.session': (4,4), 'encapsulation.status': (8,4),
                                'encapsulation.context': (12,8), 'cip.service': (40,1)}
                if decoded['direction'] == 'request':
                    named_ranges['cip.path'] = (42,6)
                    data_start = 48
                else:
                    named_ranges['cip.general_status'] = (42,1)
                    data_start = 44 + 2 * len(decoded['additional_status'])
                if data_start < size:
                    named_ranges['cip.data'] = (data_start, size-data_start)
                named_fields = {}
                for name, (start, length) in named_ranges.items():
                    pieces = []
                    for part in fields:
                        a = max(start, part['pdu_byte_offset'])
                        b = min(start+length, part['pdu_byte_offset']+part['length'])
                        if a < b:
                            value = pdu[a:b]
                            pieces.append({'source_ref':part['source_ref'],
                                           'frame_byte_offset':part['frame_byte_offset']+a-part['pdu_byte_offset'],
                                           'pdu_byte_offset':a, 'length':b-a, 'hex':value.hex(),
                                           'sha256':hashlib.sha256(value).hexdigest()})
                    named_fields[name] = {'pdu_byte_offset':start, 'length':length,
                                          'hex':pdu[start:start+length].hex(), 'slices':pieces}
                pending.append({**decoded, **({'stream_sequence':low+cursor} if replay else {}), 'source_refs': contributing, 'field_slices': fields,
                                'fields': named_fields,
                                'pdu_sha256': hashlib.sha256(pdu).hexdigest(), 'pdu_hex': pdu.hex(),
                                'endpoints': endpoints, 'epoch': epoch,
                                'quality': [('synthetic_only' if synthetic else 'real_source_unvalidated'), 'bounded_stream_subset', 'connection_epoch_unverified', 'network_checksums_not_validated']})
                cursor += size
            observations.extend(pending)
        except CaptureError as error:
            if extended and str(error) != 'pdu_count_limit':
                observations.extend(pending)
            reject(str(error), refs)
    # Invalid direction of an epoch blocks association in both directions.
    bad_frames = {_ref_key(r) for item in rejected for r in item['source_refs']}
    blocked = {(tuple(sorted(v['endpoints'])), v['epoch']) for v in observations
               if any(_ref_key(r) in bad_frames for r in v['source_refs'])}
    blocked.update(rejected_epochs)
    # Rejects can belong to the opposite direction, so derive blocked epochs explicitly.
    for control in controls:
        if _ref_key(control['source_ref']) in bad_frames:
            blocked.add((tuple(sorted(control['endpoints'])), control['epoch']))
    for (flow, epoch, _), s in streams.items():
        if any(_ref_key(r) in bad_frames for r in s['all_refs']):
            blocked.add((flow, epoch))
    groups = defaultdict(list)
    unknown_transport = any('source_port' not in f['transport'] for f in frames)
    events = []
    def association(i, status, reason):
        observations[i]['association_status'] = status
        observations[i]['association_reason'] = reason
        events[i]['quality']['reasons'].append('association_'+status+':'+reason)
    for i, obs in enumerate(observations):
        endpoints = obs['endpoints']
        key = (endpoints if obs['direction']=='request' else endpoints[::-1], obs['epoch'],
               obs['session_handle'], obs['sender_context'], obs['service'])
        if not unknown_transport and (tuple(sorted(endpoints)), obs['epoch']) not in blocked and obs['sender_context'] != '0000000000000000':
            groups[key].append(i)
        event = {'schema_version':'1.0.0', 'synthetic':synthetic, 'event_id':'packet-'+fingerprint([obs['endpoints'],obs['epoch'],obs['stream_sequence'],obs['pdu_sha256']] if replay else obs),
                 'source_ref':obs['source_refs'][0], 'event_time':None, 'ingest_time':None,
                 'quality':{'status':'partial', 'reasons':list(obs['quality'])},
                 'endpoints':dict(zip(('source','destination'), (f'{ip}:{port}' for ip,port in endpoints))),
                 'protocol':'ENIP/CPF/CIP', 'operation':obs['operation'], 'correlation_id':None,
                 'response_status':str(obs['general_status']) if 'general_status' in obs else None}
        events.append(event)
        # Add annotations after event identity is computed: raw observation hash
        # semantics remain unchanged by this association explanation layer.
        if unknown_transport:
            association(i, 'unsupported', 'unknown_transport_in_capture')
        elif (tuple(sorted(endpoints)), obs['epoch']) in blocked:
            association(i, 'unsupported', 'rejected_stream_in_connection_epoch')
        elif obs['sender_context'] == '0000000000000000':
            association(i, 'unsupported', 'zero_sender_context')
    claims, edges = [], []
    for members in groups.values():
        req = [i for i in members if observations[i]['direction']=='request']
        res = [i for i in members if observations[i]['direction']=='response']
        if len(req) > 1 or len(res) > 1:
            reason = ('duplicate_requests_and_responses' if len(req)>1 and len(res)>1
                      else 'duplicate_requests' if len(req)>1 else 'duplicate_responses')
            for i in members:
                association(i, 'ambiguous', reason)
        elif not req or not res:
            for i in members:
                association(i, 'missing', 'request_missing' if not req else 'response_missing')
        if len(req) == len(res) == 1:
            a,b = req[0],res[0]
            association(a, 'matched', 'unique_request_response')
            association(b, 'matched', 'unique_request_response')
            claim_id = 'association-'+fingerprint([events[a]['event_id'], events[b]['event_id']])
            claims.append({'schema_version':'1.0.0', 'synthetic':synthetic, 'claim_id':claim_id,
                           'relation_type':'protocol_request_response_association', 'status':'observed',
                           'evidence_refs':observations[a]['source_refs']+observations[b]['source_refs'],
                           'assumptions':['capture_scope_unique_endpoints_epoch_session_context_service',
                                          'connection_epoch_unverified', 'no_attack_causality_or_physical_effect_asserted'],
                           'counterevidence':[], 'rule_id':('enip-association-2' if extended else 'synthetic-enip-association-1')})
            edges.append({'id':claim_id, 'source':events[a]['event_id'], 'target':events[b]['event_id'], 'claim_id':claim_id})
            events[a]['correlation_id'] = events[b]['correlation_id'] = claim_id
    for e in events:
        if not replay:
            validate('NetworkEvent', e)
    graph = {'schema_version':'1.0.0', 'synthetic':synthetic, 'graph_id':'packet-graph-'+index.digest,
             'nodes':[{'id':e['event_id'], 'event_id':e['event_id'], 'kind':'network', 'evidence_refs':o['source_refs']}
                      for e,o in zip(events,observations)], 'edges':edges, 'claims':claims,
             'input_fingerprint':index.digest, 'core_version':('bounded-packet-2' if extended else 'synthetic-packet-1'),
             'statistics':{'nodes':len(events), 'edges':len(edges)}, 'truncation':{'truncated':False,'reason':None}}
    if not replay:
        validate('GraphArtifact', graph)
    index._verified()
    if replay:
        return {'events':events, 'observations':observations, 'unsupported':rejected, 'pending':incomplete,
                'connection_controls':controls, 'quality':{'status':'partial','reasons':['arrived_prefix_only','bounded_subset']}}
    return {'adapter_version':('bounded-packet-2' if extended else 'synthetic-packet-1'), 'synthetic':synthetic, 'file_sha256':index.digest,
            **({'file_sha256s':index.file_sha256s, 'capture_order':'declared_file_then_original_frame'}
               if multiple else {}),
            'events':events, 'graph':graph, 'observations':observations, 'unsupported':rejected,
            'connection_controls':controls,
            'quality':{'status':'partial', 'reasons':[('synthetic_only' if synthetic else 'real_source_unvalidated'),'real_data_unvalidated','bounded_subset']}}


def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture')
    source = p.add_mutually_exclusive_group()
    source.add_argument('--synthetic', action='store_true', default=None)
    source.add_argument('--real', dest='synthetic', action='store_false', help='parse the bounded subset; source remains unvalidated')
    p.add_argument('--frame', type=int)
    p.add_argument('--event-id')
    p.add_argument('--field', help='named decoded field, e.g. cip.service')
    args = p.parse_args()
    try:
        if args.frame is None:
            result = analyze_capture(args.capture, synthetic=args.synthetic)
            if args.event_id:
                matches = [i for i,e in enumerate(result['events']) if e['event_id'] == args.event_id]
                if len(matches) != 1:
                    raise CaptureError('unknown_event_id')
                i = matches[0]
                observation = result['observations'][i]
                evidence = PacketEvidence(args.capture, synthetic=args.synthetic)
                selected = observation['fields']
                if args.field:
                    if args.field not in selected:
                        raise CaptureError('unknown_field')
                    selected = {args.field:selected[args.field]}
                result = {'event':result['events'][i], 'node':result['graph']['nodes'][i],
                          'observation':observation,
                          'verified_fields':{name:[evidence.resolve(piece['source_ref'], piece)
                                                  for piece in field['slices']]
                                             for name,field in selected.items()}}
        else:
            index = PacketEvidence(args.capture, synthetic=args.synthetic)
            if args.frame not in index.frames:
                raise CaptureError('invalid_frame_reference')
            result = index.resolve(standard_ref(index.frames[args.frame]))
    except (ValueError, OSError) as e:
        p.exit(2,str(e)+'\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
