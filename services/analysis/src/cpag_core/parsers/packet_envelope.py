"""Bounded explicitly classified capture envelope inspection; deliberately no protocol decoding.

This API is separate from the default parser and never emits NetworkEvents.
Offsets refer to immutable input bytes, not reconstructed packets.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct


class CaptureError(ValueError):
    """Malformed, unsupported or resource-exceeding capture (no partial result)."""


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 16 * 1024 * 1024
    max_frames: int = 10000
    max_frame_bytes: int = 262144

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in (self.max_bytes, self.max_frames, self.max_frame_bytes)):
            raise ValueError('limits must be positive integers')


def inspect_capture(path, *, synthetic=None, limits=None):
    """Index classic PCAP and a strict PCAPNG SHB/IDB/EPB subset.

    Caller must explicitly classify synthetic versus real input; real semantics remain unvalidated. Timestamp integers are raw;
    no timezone, clock alignment, device identity or request pairing is inferred.
    Unsupported linktypes, blocks and interface options fail closed.
    """
    if type(synthetic) is not bool:
        raise CaptureError('synthetic_opt_in_required')
    limits = limits or Limits()
    if not isinstance(limits, Limits):
        raise ValueError('limits must be Limits')
    with Path(path).open('rb') as stream:
        data = stream.read(limits.max_bytes + 1)
    if len(data) > limits.max_bytes:
        raise CaptureError('byte_limit')
    digest = hashlib.sha256(data).hexdigest()
    frames = []

    def add(offset, captured, original, raw_time, resolution):
        if len(frames) >= limits.max_frames:
            raise CaptureError('frame_limit')
        if captured > limits.max_frame_bytes:
            raise CaptureError('frame_byte_limit')
        if captured > original:
            raise CaptureError('captured_length_exceeds_original')
        if offset + captured > len(data):
            raise CaptureError('truncated_frame')
        frames.append({'transport': _transport(data[offset:offset + captured]), 'file_sha256': digest, 'frame_number': len(frames) + 1,
                       'byte_offset': offset, 'captured_length': captured,
                       'original_length': original, 'raw_timestamp': raw_time,
                       'ticks_per_second': resolution,
                       'frame_sha256': hashlib.sha256(data[offset:offset + captured]).hexdigest(),
                       'quality': ['protocol_semantics_unsupported'] + (['capture_truncated'] if captured < original else [])})

    magics = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
              b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
    if data[:4] in magics:
        endian, resolution = magics[data[:4]]
        if len(data) < 24:
            raise CaptureError('truncated_pcap_header')
        major, minor, zone, accuracy, snaplen, link = struct.unpack_from(endian + 'HHiiII', data, 4)
        if (major, minor) != (2, 4) or link != 1 or not snaplen or zone or accuracy:
            raise CaptureError('unsupported_pcap_header_or_linktype')
        pos = 24
        while pos < len(data):
            if pos + 16 > len(data):
                raise CaptureError('truncated_record_header')
            seconds, fraction, captured, original = struct.unpack_from(endian + 'IIII', data, pos)
            if fraction >= resolution or captured > snaplen:
                raise CaptureError('invalid_record_header')
            add(pos + 16, captured, original, seconds * resolution + fraction, resolution)
            pos += 16 + captured
        container = 'pcap'
    elif data[:4] == b'\x0a\x0d\x0d\x0a':
        pos, endian, interfaces = 0, None, []
        while pos < len(data):
            if pos + 12 > len(data):
                raise CaptureError('truncated_block')
            if data[pos:pos + 4] == b'\x0a\x0d\x0d\x0a':
                if endian is not None:
                    raise CaptureError('multiple_sections_unsupported')
                bom = data[pos + 8:pos + 12]
                endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(bom)
                if endian is None:
                    raise CaptureError('invalid_byte_order')
            kind, length = struct.unpack_from(endian + 'II', data, pos)
            if length < 12 or length % 4 or pos + length > len(data):
                raise CaptureError('invalid_block_length')
            if struct.unpack_from(endian + 'I', data, pos + length - 4)[0] != length:
                raise CaptureError('block_length_mismatch')
            body = pos + 8
            if kind == 0x0A0D0D0A:
                if length != 28 or struct.unpack_from(endian + 'HHq', data, body + 4) != (1, 0, -1):
                    raise CaptureError('unsupported_section_header')
            elif kind == 1:
                if interfaces:
                    raise CaptureError('multiple_interfaces_unsupported')
                if length != 20:
                    raise CaptureError('interface_options_unsupported')
                link, reserved, snaplen = struct.unpack_from(endian + 'HHI', data, body)
                if link != 1 or reserved or not snaplen:
                    raise CaptureError('unsupported_interface_or_linktype')
                interfaces.append(snaplen)
            elif kind == 6:
                if length < 32:
                    raise CaptureError('short_packet_block')
                interface, high, low, captured, original = struct.unpack_from(endian + 'IIIII', data, body)
                if interface >= len(interfaces) or captured > interfaces[interface]:
                    raise CaptureError('invalid_packet_interface_or_snaplen')
                padded = (captured + 3) & ~3
                if length != 32 + padded:
                    raise CaptureError('packet_options_or_invalid_length')
                add(body + 20, captured, original, (high << 32) | low, 1000000)
            else:
                raise CaptureError('unsupported_block_type')
            pos += length
        container = 'pcapng'
    else:
        raise CaptureError('unsupported_capture_magic')
    return {'adapter_version': 'synthetic-envelope-1', 'synthetic': synthetic, 'container': container,
            'file_sha256': digest, 'frames': frames, 'events': [],
            'quality': {'status': 'unsupported', 'reasons': ['protocol_semantics_unsupported'],
                        'frame_count': len(frames), 'event_count': 0}}


def _transport(frame):
    """Observe fixed header fields only; no checksums, reassembly or semantics."""
    import ipaddress
    if len(frame) < 14:
        return {'status': 'unsupported', 'reason': 'short_ethernet_header'}
    ethertype = int.from_bytes(frame[12:14], 'big')
    if ethertype != 0x0800:
        return {'status': 'unsupported', 'reason': 'non_ipv4_or_vlan', 'ethertype': ethertype}
    packet = frame[14:]
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return {'status': 'unsupported', 'reason': 'short_or_invalid_ipv4'}
    ihl = (packet[0] & 15) * 4
    total = int.from_bytes(packet[2:4], 'big')
    if ihl < 20 or total < ihl or len(packet) < total:
        return {'status': 'unsupported', 'reason': 'invalid_or_truncated_ipv4'}
    result = {'status': 'partial', 'source_ip': str(ipaddress.IPv4Address(packet[12:16])),
              'destination_ip': str(ipaddress.IPv4Address(packet[16:20])),
              'ip_protocol': packet[9], 'reason': 'application_semantics_unsupported'}
    if int.from_bytes(packet[6:8], 'big') & 0x3fff:
        result['reason'] = 'ip_fragment_reassembly_unsupported'
    elif packet[9] == 6:
        tcp = packet[ihl:total]
        if len(tcp) < 20 or (tcp[12] >> 4) * 4 < 20 or (tcp[12] >> 4) * 4 > len(tcp):
            result['reason'] = 'invalid_or_truncated_tcp'
        else:
            result.update(source_port=int.from_bytes(tcp[:2], 'big'), destination_port=int.from_bytes(tcp[2:4], 'big'),
                          sequence_number=int.from_bytes(tcp[4:8], 'big'), acknowledgment_number=int.from_bytes(tcp[8:12], 'big'),
                          tcp_flags=tcp[13], tcp_payload_length=len(tcp) - (tcp[12] >> 4) * 4)
    else:
        result['reason'] = 'non_tcp_protocol_unsupported'
    return result


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--synthetic', action='store_true', default=None, help='explicitly attest generated input')
    source.add_argument('--real', dest='synthetic', action='store_false', help='inspect bytes; real data remains unvalidated')
    parser.add_argument('--max-bytes', type=int, default=Limits().max_bytes)
    parser.add_argument('--max-frames', type=int, default=Limits().max_frames)
    parser.add_argument('--max-frame-bytes', type=int, default=Limits().max_frame_bytes)
    args = parser.parse_args()
    try:
        result = inspect_capture(args.capture, synthetic=args.synthetic,
                                 limits=Limits(args.max_bytes, args.max_frames, args.max_frame_bytes))
    except (CaptureError, ValueError, OSError) as exc:
        parser.exit(2, str(exc) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
