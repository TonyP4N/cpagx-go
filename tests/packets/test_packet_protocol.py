"""Synthetic structural wire fixtures, no industrial or attack coverage claim."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from test_packet_envelope import pcap, pcapng
from cpag_core.parsers.packet_envelope import CaptureError, Limits
from cpag_core.parsers.packet_protocol import decode_payload, inspect_protocol

# Independent literal ENIP/CPF/CIP bytes: session 1/context 0102030405060708.
GET = bytes.fromhex('6f0018000100000000000000010203040506070800000000'
                    '000000000000020000000000b20008000e03200124013001')
REPLY = bytes.fromhex('6f0016000100000000000000010203040506070800000000'
                      '000000000000020000000000b20006008e0000003412')


def message(cip, context=b'\x01\x02\x03\x04\x05\x06\x07\x08', session=1):
    body = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0xb2, len(cip)) + cip
    return struct.pack('<HHII8sI', 0x6f, len(body), session, 0, context, 0) + body


def frame(payload, seq=100, reverse=False):
    src, dst = (bytes([192,0,2,1]), bytes([192,0,2,2]))
    ports = (1234, 44818)
    if reverse:
        src, dst, ports = dst, src, ports[::-1]
    tcp = struct.pack('!HHIIBBHHH', *ports, seq, 0, 80, 24, 4096, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 20+len(tcp), 1, 0, 64, 6, 0, src, dst)
    return b'\0'*12 + b'\x08\x00' + ip + tcp


class ProtocolTests(unittest.TestCase):
    def run_frames(self, frames, container=pcap):
        data = container(list(enumerate(frames, 1)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'synthetic.pcap'
            path.write_bytes(data)
            result = inspect_protocol(path, synthetic=True)
        for observation in result['observations']:
            for ref in observation['source_refs']:
                raw = data[ref['byte_offset']:ref['byte_offset']+ref['captured_length']]
                self.assertEqual(hashlib.sha256(raw).hexdigest(), ref['frame_sha256'])
        return result

    def test_golden_fields_pairs_and_reordered_containers(self):
        self.assertEqual(decode_payload(GET)['path'], {'class':1,'instance':1,'attribute':1})
        self.assertEqual(decode_payload(REPLY)['data_hex'], '3412')
        for container in (pcap, pcapng):
            result = self.run_frames([frame(REPLY, reverse=True), frame(GET)], container)
            self.assertEqual(len(result['pairs']), 1)
            self.assertEqual([r['frame_number'] for r in result['pairs'][0]['source_refs']], [2,1])
            self.assertEqual(result['events'], [])

    def test_set_and_response_status(self):
        decoded = decode_payload(message(bytes.fromhex('10032001240130013412')))
        self.assertEqual(decoded['operation'], 'write_attribute')
        self.assertEqual(decoded['data_hex'], '3412')
        decoded = decode_payload(message(bytes.fromhex('900005013412')))
        self.assertEqual(decoded['general_status'], 5)
        self.assertEqual(decoded['additional_status'], [0x1234])

    def test_duplicates_overlap_disable_pairs(self):
        for seq in (100,101):
            result = self.run_frames([frame(GET), frame(GET, seq), frame(REPLY, reverse=True)])
            self.assertEqual(result['pairs'], [])
            self.assertTrue(all(x['correlation_status']=='ambiguous' for x in result['observations']))

    def test_partial_coalesced_and_truncated(self):
        for payload in (GET[:12], GET[:-1], GET+GET):
            result = self.run_frames([frame(payload), frame(REPLY, reverse=True)])
            self.assertEqual(result['pairs'], [])
            self.assertEqual(len(result['unsupported']), 1)
        result = self.run_frames([frame(GET[:20]), frame(GET[20:],120), frame(REPLY,reverse=True)])
        self.assertEqual(result['pairs'], [])
        self.assertEqual(len(result['unsupported']), 2)

    def test_mismatch_unanswered_and_zero_context(self):
        for reply in (message(bytes.fromhex('90000000')), message(bytes.fromhex('8e000000'),session=2),
                      message(bytes.fromhex('8e000000'),context=b'abcdefgh')):
            self.assertEqual(self.run_frames([frame(GET),frame(reply,reverse=True)])['pairs'], [])
        result = self.run_frames([frame(GET)])
        self.assertEqual(result['observations'][0]['correlation_status'], 'no_matching_response_observed')
        result = self.run_frames([frame(message(bytes.fromhex('0e03200124013001'),context=b'\0'*8))])
        self.assertEqual(result['observations'][0]['correlation_status'], 'zero_context_pairing_disabled')

    def test_unsupported_service_path_and_bad_lengths(self):
        for cip in ('5203200124013001','0e0220012401','8e00000212'):
            with self.assertRaises(CaptureError):
                decode_payload(message(bytes.fromhex(cip)))
        bad = bytearray(GET)
        bad[38:40] = b'\x09\x00'
        with self.assertRaisesRegex(CaptureError,'cpf_length'):
            decode_payload(bad)

    def test_connection_boundaries_disable_pairing(self):
        for flags in (0x02, 0x01, 0x04):
            for payload in (b'', GET):
                boundary = bytearray(frame(payload,seq=300))
                boundary[47] = flags
                result = self.run_frames([frame(GET), bytes(boundary), frame(REPLY,reverse=True)])
                self.assertEqual(result['pairs'], [])
                self.assertTrue(all(item['correlation_status'] == 'ambiguous'
                                    for item in result['observations']))

    def test_transport_and_header_boundaries(self):
        raw = frame(GET)
        truncated = pcap([(1, raw)])
        truncated = bytearray(truncated)
        struct.pack_into('<I', truncated, 36, len(raw)+1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'truncated'
            path.write_bytes(truncated)
            result = inspect_protocol(path,synthetic=True)
            self.assertEqual(result['unsupported'][0]['reason'],'capture_truncated')
        self.assertEqual(self.run_frames([frame(GET, reverse=True)])['unsupported'][0]['reason'],
                         'direction_port_mismatch')
        for offset, value, reason in ((0,0x70,'command'), (8,1,'status_options'), (20,1,'status_options')):
            mutated = bytearray(GET)
            mutated[offset] = value
            with self.assertRaisesRegex(CaptureError, reason):
                decode_payload(mutated)
        fragmented = bytearray(raw)
        fragmented[20:22] = b'\x20\x00'
        result = self.run_frames([bytes(fragmented)])
        self.assertEqual(result['unsupported'][0]['reason'],'ip_fragment_reassembly_unsupported')

    def test_gate_limits_and_mutation_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'capture'
            original = pcap([(1,frame(GET))])
            path.write_bytes(original)
            with self.assertRaisesRegex(CaptureError,'synthetic_opt'):
                inspect_protocol(path)
            with self.assertRaisesRegex(CaptureError,'byte_limit'):
                inspect_protocol(path,synthetic=True,limits=Limits(max_bytes=10))
            before = inspect_protocol(path,synthetic=True)
            path.write_bytes(pcap([(1,frame(message(bytes.fromhex('1003200124013001ff'))))]))
            after = inspect_protocol(path,synthetic=True)
            self.assertNotEqual(before['file_sha256'],after['file_sha256'])
            self.assertNotEqual(before['observations'][0]['source_refs'],after['observations'][0]['source_refs'])
            from cpag_core.parsers.packet_protocol import inspect_capture as index
            def changed(*args,**kwargs):
                result = index(*args,**kwargs)
                path.write_bytes(original)
                return result
            with patch('cpag_core.parsers.packet_protocol.inspect_capture',side_effect=changed):
                with self.assertRaisesRegex(CaptureError,'capture_changed'):
                    inspect_protocol(path,synthetic=True)


if __name__ == '__main__':
    unittest.main()
