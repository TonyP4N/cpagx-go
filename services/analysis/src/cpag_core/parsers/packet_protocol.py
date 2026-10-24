"""Opt-in synthetic ENIP/CIP observations; no NetworkEvents or stream reassembly."""
from collections import defaultdict
import hashlib
from pathlib import Path
import struct
from .packet_envelope import CaptureError, Limits, inspect_capture


def decode_payload(payload):
    """Decode exactly one SendRRData PDU; reject all unimplemented variants."""
    def need(condition, reason):
        if not condition:
            raise CaptureError(reason)
    need(len(payload) >= 24, 'segmentation_or_short_encapsulation')
    command, length, session, status, context, options = struct.unpack_from('<HHII8sI', payload)
    need(len(payload) == 24 + length, 'segmentation_or_coalescing_unsupported')
    need(command == 0x6f, 'encapsulation_command_unsupported')
    need(options == 0 and status == 0 and session != 0, 'encapsulation_status_options_or_session_unsupported')
    body = payload[24:]
    need(len(body) >= 16, 'short_cpf')
    interface, timeout, count, address, address_length, item, size = struct.unpack_from('<IHHHHHH', body)
    need(interface == 0 and count == 2 and address == 0 and address_length == 0 and item == 0xb2,
         'cpf_layout_unsupported')
    need(len(body) == 16 + size, 'cpf_length_mismatch')
    cip = body[16:]
    need(len(cip) >= 2, 'short_cip')
    service = cip[0] & 0x7f
    need(service in (0x0e, 0x10), 'cip_service_unsupported')
    result = {'session_handle': session, 'sender_context': context.hex(), 'service': service,
              'operation': 'read_attribute' if service == 0x0e else 'write_attribute',
              'direction': 'response' if cip[0] & 0x80 else 'request', 'timeout_raw': timeout}
    if cip[0] & 0x80:
        need(len(cip) >= 4 and cip[1] == 0, 'invalid_cip_response_header')
        end = 4 + 2 * cip[3]
        need(len(cip) >= end, 'truncated_additional_status')
        result.update(general_status=cip[2], additional_status=list(struct.unpack('<' + 'H' * cip[3], cip[4:end])),
                      data_hex=cip[end:].hex())
    else:
        end = 2 + cip[1] * 2
        need(end <= len(cip), 'truncated_cip_path')
        # Deliberately only canonical 8-bit class/instance/attribute logical segments.
        path = cip[2:end]
        need(len(path) == 6 and path[::2] == b'\x20\x24\x30', 'cip_path_unsupported')
        need(service != 0x0e or end == len(cip), 'get_request_data_unsupported')
        result.update(path={'class': path[1], 'instance': path[3], 'attribute': path[5]}, data_hex=cip[end:].hex())
    return result


def inspect_protocol(path, *, synthetic=False, limits=None):
    """Inspect bounded capture; full PDU per TCP payload is an explicit subset.

    Pair only a unique request and response with reversed endpoints, identical
    nonzero sender context/session/service and no unsupported payload in that flow.
    Capture order does not establish causality. No TCP stream validity is asserted.
    """
    limits = limits or Limits()
    envelope = inspect_capture(path, synthetic=synthetic, limits=limits)
    with Path(path).open('rb') as stream:
        data = stream.read(limits.max_bytes + 1)
    if hashlib.sha256(data).hexdigest() != envelope['file_sha256']:
        raise CaptureError('capture_changed_during_inspection')
    observations, unsupported = [], []
    blocked_flows = set()
    intervals = defaultdict(list)
    for frame in envelope['frames']:
        transport = frame['transport']
        ref = {k: frame[k] for k in ('file_sha256', 'frame_number', 'byte_offset', 'captured_length', 'original_length', 'frame_sha256')}
        flow = None
        try:
            if 'source_port' not in transport:
                raise CaptureError(transport['reason'])
            endpoints = ((transport['source_ip'], transport['source_port']), (transport['destination_ip'], transport['destination_port']))
            flow = tuple(sorted(endpoints))
            if transport['source_port'] != 44818 and transport['destination_port'] != 44818:
                raise CaptureError('non_target_port')
            # No connection epoch reconstruction: any observed SYN/FIN/RST
            # makes same-tuple capture matching unsafe, including empty control frames.
            if transport['tcp_flags'] & 0x07:
                blocked_flows.add(flow)
            if not transport['tcp_payload_length']:
                continue
            if frame['captured_length'] != frame['original_length']:
                raise CaptureError('capture_truncated')
            raw = data[frame['byte_offset']:frame['byte_offset'] + frame['captured_length']]
            ip = raw[14:]
            tcp_offset = 14 + (ip[0] & 15) * 4
            start = tcp_offset + (raw[tcp_offset + 12] >> 4) * 4
            payload = raw[start:14 + int.from_bytes(ip[2:4], 'big')]
            seq = transport['sequence_number']
            intervals[(flow, endpoints)].append((seq, seq + len(payload)))
            if seq + len(payload) > 2**32:
                raise CaptureError('tcp_sequence_wrap_unsupported')
            decoded = decode_payload(payload)
            expected_port = transport['destination_port'] if decoded['direction'] == 'request' else transport['source_port']
            if expected_port != 44818 or transport['source_port'] == transport['destination_port']:
                raise CaptureError('direction_port_mismatch')
            observations.append(dict(decoded, endpoints=endpoints, source_refs=[ref], quality=['single_payload_only_stream_unverified']))
        except CaptureError as exc:
            unsupported.append({'source_refs': [ref], 'reason': str(exc)})
            if flow is not None and str(exc) != 'non_target_port':
                blocked_flows.add(flow)
    for (flow, _), spans in intervals.items():
        spans.sort()
        if any(right[0] < left[1] for left, right in zip(spans, spans[1:])):
            blocked_flows.add(flow)
    groups = defaultdict(list)
    for index, item in enumerate(observations):
        endpoints = item['endpoints']
        flow = tuple(sorted(endpoints))
        if flow in blocked_flows:
            item['quality'].append('flow_ambiguity_pairing_disabled')
            item['correlation_status'] = 'ambiguous'
        elif item['sender_context'] == '0000000000000000':
            item['correlation_status'] = 'zero_context_pairing_disabled'
        else:
            client_server = endpoints if item['direction'] == 'request' else endpoints[::-1]
            groups[(client_server, item['session_handle'], item['sender_context'], item['service'])].append(index)
    pairs = []
    for indices in groups.values():
        requests = [i for i in indices if observations[i]['direction'] == 'request']
        responses = [i for i in indices if observations[i]['direction'] == 'response']
        if len(requests) == len(responses) == 1:
            a, b = requests[0], responses[0]
            pairs.append({'request_index': a, 'response_index': b,
                          'source_refs': observations[a]['source_refs'] + observations[b]['source_refs'],
                          'basis': 'unique_reversed_endpoints_session_context_service',
                          'quality': ['capture_scope_only_connection_epoch_unverified']})
            for i in indices:
                observations[i]['correlation_status'] = 'unique_capture_match'
        else:
            for i in indices:
                observations[i]['correlation_status'] = ('no_matching_response_observed' if requests and not responses else
                                                        'no_matching_request_observed' if responses and not requests else 'ambiguous')
    return {'adapter_version': 'synthetic-protocol-1', 'synthetic': True, 'file_sha256': envelope['file_sha256'],
            'frames': envelope['frames'], 'observations': observations, 'pairs': pairs, 'unsupported': unsupported,
            'events': [], 'quality': {'status': 'partial', 'reasons': ['synthetic_only', 'tcp_reassembly_unsupported', 'real_data_unvalidated']}}


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('--synthetic', action='store_true')
    parser.add_argument('--max-bytes', type=int, default=Limits().max_bytes)
    parser.add_argument('--max-frames', type=int, default=Limits().max_frames)
    parser.add_argument('--max-frame-bytes', type=int, default=Limits().max_frame_bytes)
    args = parser.parse_args()
    try:
        result = inspect_protocol(args.capture, synthetic=args.synthetic,
                                  limits=Limits(args.max_bytes, args.max_frames, args.max_frame_bytes))
    except (ValueError, OSError) as exc:
        parser.exit(2, str(exc) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
