"""Independent byte references: no production/legacy fixture encoder imports."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from cpag_core.packet_pipeline import analyze_capture, PacketEvidence, CaptureSetLimits
from cpag_core.parsers.packet_envelope import CaptureError, Limits

# Canonical read request: class1 instance1 attribute1; opaque returned 0102.
REQUEST = bytes.fromhex('6f0018004433221100000000010203040506070800000000'
                        '000000000000020000000000b20008000e03200124013001')
RESPONSE = bytes.fromhex('6f0016004433221100000000010203040506070800000000'
                         '000000000000020000000000b20006008e0000000102')


def tcp(payload=b'', seq=100, reverse=False, flags=24, ack=0):
    source, target = (44818, 12000) if reverse else (12000, 44818)
    ips = bytes.fromhex('0a0000020a000001' if reverse else '0a0000010a000002')
    ethernet = b'\x11'*6 + b'\x22'*6 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH', 0x45, 0, 40+len(payload), 1, 0, 64, 6, 0) + ips
    header = struct.pack('!HHIIBBHHH', source, target, seq, ack, 0x50, flags, 1024, 0, 0)
    return ethernet+ip+header+payload


def classic(frames, endian='<', nano=False, start=1, link=1):
    magic = (0xa1b23c4d if nano else 0xa1b2c3d4)
    data = struct.pack(endian+'IHHIIII', magic, 2, 4, 0, 0, 65535, link)
    for n, raw in enumerate(frames, start):
        data += struct.pack(endian+'IIII', n, 0, len(raw), len(raw))+raw
    return data


def nextgen(frames, start=1):
    def block(kind, body):
        size=12+len(body)
        return struct.pack('<II',kind,size)+body+struct.pack('<I',size)
    data=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    data+=block(1,struct.pack('<HHI',1,0,65535))
    for n,raw in enumerate(frames,start):
        data+=block(6,struct.pack('<IIIII',0,0,n*1000000,len(raw),len(raw))+raw+b'\0'*((-len(raw))%4))
    return data


class Round17ParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.number=0

    def save(self, frames, container=classic, **kwargs):
        self.number+=1
        path=Path(self.tmp.name)/f'{self.number}.pcap'
        path.write_bytes(container(frames,**kwargs));return path

    def test_preregistered_four_file_reassembly_and_exact_original_evidence(self):
        paths=[self.save([tcp(REQUEST[:20])]),
               self.save([tcp(REQUEST[20:],120)],nextgen,start=2),
               self.save([tcp(REQUEST[:20])],start=3),
               self.save([tcp(RESPONSE,reverse=True)],endian='>',nano=True,start=4)]
        result=analyze_capture(paths,synthetic=True)
        self.assertEqual(len(result['events']),2)
        self.assertEqual(len(result['graph']['edges']),1)
        obs=result['observations'][0]
        self.assertEqual(obs['pdu_hex'],REQUEST.hex())
        self.assertEqual(obs['path'],{'class':1,'instance':1,'attribute':1})
        self.assertEqual(len(obs['source_refs']),3)
        self.assertEqual({r['frame_number'] for r in obs['source_refs']},{1})
        self.assertEqual({r['file_sha256'] for r in obs['source_refs']},
                         {hashlib.sha256(p.read_bytes()).hexdigest() for p in paths[:3]})
        index=PacketEvidence(paths,synthetic=True)
        self.assertEqual(index.file_sha256s,result['file_sha256s'])
        for original in result['observations']:
            rebuilt=bytearray(len(bytes.fromhex(original['pdu_hex'])))
            for part in original['field_slices']:
                raw=index.resolve(part['source_ref'],part)
                self.assertEqual(raw['frame_number'],1)
                a=part['pdu_byte_offset'];rebuilt[a:a+part['length']]=bytes.fromhex(part['hex'])
            self.assertEqual(rebuilt.hex(),original['pdu_hex'])
        self.assertEqual(result,analyze_capture(paths,synthetic=True))
        paths[1].write_bytes(paths[1].read_bytes()[:-1]+b'X')
        with self.assertRaisesRegex(CaptureError,'hash_mismatch'):
            index.resolve(obs['source_refs'][1])

    def test_out_of_order_retransmission_and_duplicate_pdu_distinction(self):
        paths=[self.save([tcp(REQUEST[20:],120)]),self.save([tcp(REQUEST[:20]),tcp(REQUEST[:20])],start=2),
               self.save([tcp(RESPONSE,reverse=True)],start=4)]
        result=analyze_capture(paths,synthetic=True)
        self.assertEqual((len(result['events']),len(result['graph']['edges'])),(2,1))
        path=self.save([tcp(REQUEST+REQUEST),tcp(RESPONSE,reverse=True)])
        result=analyze_capture(path,synthetic=True)
        self.assertEqual((len(result['events']),len(result['graph']['edges'])),(3,0))
        self.assertTrue(all(o['association_reason']=='duplicate_requests' for o in result['observations']))

    def test_original_frame_collision_does_not_block_unrelated_connection(self):
        invalid=self.save([tcp(REQUEST[:-1])])
        req=bytearray(tcp(REQUEST));req[34:36]=(12001).to_bytes(2,'big')
        res=bytearray(tcp(RESPONSE,reverse=True));res[36:38]=(12001).to_bytes(2,'big')
        valid=self.save([bytes(req),bytes(res)],start=2)
        result=analyze_capture([invalid,valid],synthetic=True)
        self.assertEqual(len(result['graph']['edges']),1)

    def test_unsupported_suffix_keeps_observed_prefix_and_blocks_pairing(self):
        unknown=REQUEST[:40]+b'\x4c'+REQUEST[41:]
        path=self.save([tcp(REQUEST+unknown+REQUEST),tcp(RESPONSE,reverse=True)])
        result=analyze_capture(path,synthetic=True,extended=True)
        self.assertEqual(len(result['events']),3)
        self.assertEqual(result['observations'][0]['pdu_hex'],REQUEST.hex())
        self.assertEqual(result['observations'][1]['pdu_hex'],REQUEST.hex())
        self.assertEqual(result['unsupported'][0]['reason'],'cip_service_unsupported')
        self.assertEqual(result['graph']['edges'],[])

    def test_legacy_scalar_unsupported_semantics_are_explicitly_preserved(self):
        unknown=REQUEST[:40]+b'\x4c'+REQUEST[41:]
        path=self.save([tcp(REQUEST+unknown+REQUEST),tcp(RESPONSE,reverse=True)])
        legacy=analyze_capture(path,synthetic=True)
        current=analyze_capture(path,synthetic=True,extended=True)
        self.assertEqual(len(legacy['events']),1)
        self.assertEqual(legacy['adapter_version'],'synthetic-packet-1')
        self.assertEqual(len(current['events']),3)
        self.assertEqual(current['adapter_version'],'bounded-packet-2')

    def test_gap_overlap_and_missing_response_independent_answers(self):
        for parts,reason in [([tcp(REQUEST[:20]),tcp(REQUEST[21:],121)],'stream_gap'),
                             ([tcp(REQUEST),tcp(b'X',110)],'conflicting_overlap'),
                             ([tcp(REQUEST[:-1])],'segmentation')]:
            paths=[self.save(parts),self.save([tcp(RESPONSE,reverse=True)],start=4)]
            result=analyze_capture(paths,synthetic=True)
            self.assertEqual(len(result['events']),1)
            self.assertEqual(result['graph']['edges'],[])
            self.assertIn(reason,result['unsupported'][0]['reason'])
        result=analyze_capture(self.save([tcp(REQUEST)]),synthetic=True)
        self.assertEqual(result['observations'][0]['association_reason'],'response_missing')

    def test_cross_file_control_boundaries(self):
        req=self.save([tcp(REQUEST),tcp(flags=17,seq=148)])
        res=self.save([tcp(RESPONSE,reverse=True)],start=4)
        self.assertEqual(len(analyze_capture([req,res],synthetic=True)['graph']['edges']),1)
        reset=self.save([tcp(REQUEST),tcp(flags=4,seq=148)])
        result=analyze_capture([reset,res],synthetic=True)
        self.assertEqual(len(result['events']),1)
        self.assertEqual(result['unsupported'][0]['reason'],'payload_after_connection_close')
        reuse=self.save([tcp(REQUEST),tcp(flags=2,seq=900)])
        result=analyze_capture([reuse,res],synthetic=True)
        self.assertEqual(len(result['events']),2)
        self.assertEqual(result['graph']['edges'],[])

    def test_capture_truncation_preserves_peer_and_reports_original_evidence(self):
        path=self.save([tcp(REQUEST),tcp(RESPONSE,reverse=True)])
        data=bytearray(path.read_bytes())
        # Complete captured frame, but wire length declares one missing byte.
        captured=int.from_bytes(data[32:36],'little')
        data[36:40]=(captured+1).to_bytes(4,'little');path.write_bytes(data)
        result=analyze_capture(path,synthetic=True)
        self.assertEqual(len(result['events']),1)
        self.assertEqual(result['observations'][0]['direction'],'response')
        self.assertEqual(result['unsupported'][0]['reason'],'capture_truncated')
        self.assertEqual(result['unsupported'][0]['source_refs'][0]['frame_number'],1)
        self.assertEqual(result['graph']['edges'],[])

    def test_declared_order_duplicate_input_and_actual_aggregate_bounds(self):
        a=self.save([tcp(REQUEST)]);b=self.save([tcp(RESPONSE,reverse=True)],start=2)
        with self.assertRaisesRegex(CaptureError,'duplicate_capture'):
            analyze_capture([a,a],synthetic=True)
        with self.assertRaisesRegex(CaptureError,'file_count'):
            analyze_capture([a,b,a,b,a],synthetic=True)
        with self.assertRaisesRegex(CaptureError,'aggregate_byte'):
            analyze_capture([a,b],synthetic=True,capture_limits=CaptureSetLimits(max_total_bytes=a.stat().st_size))
        with self.assertRaisesRegex(CaptureError,'aggregate_frame'):
            analyze_capture([a,b],synthetic=True,capture_limits=CaptureSetLimits(max_total_frames=1))
        result=analyze_capture([a,b],synthetic=True)
        reversed_result=analyze_capture([b,a],synthetic=True)
        self.assertNotEqual(result['file_sha256'],reversed_result['file_sha256'])
        self.assertEqual(result['file_sha256s'],list(reversed(reversed_result['file_sha256s'])))
        self.assertNotIn('capture_order',analyze_capture(a,synthetic=True))

    def test_real_source_is_explicit_and_not_validated(self):
        path=self.save([tcp(REQUEST),tcp(RESPONSE,reverse=True)])
        with self.assertRaisesRegex(CaptureError,'opt_in'):
            analyze_capture(path)
        result=analyze_capture(path,synthetic=False)
        self.assertFalse(result['synthetic']);self.assertFalse(result['graph']['synthetic'])
        self.assertTrue(all(not e['synthetic'] for e in result['events']))
        self.assertIn('real_source_unvalidated',result['quality']['reasons'])
        self.assertEqual(len(result['graph']['edges']),1)

    def test_unknown_link_and_container_damage_fail_without_result(self):
        bad=self.save([tcp(REQUEST)],link=101)
        with self.assertRaisesRegex(CaptureError,'linktype'):
            analyze_capture(bad,synthetic=True)
        bad=self.save([tcp(REQUEST)],nextgen)
        bad.write_bytes(bad.read_bytes()[:-1])
        with self.assertRaises(CaptureError):
            analyze_capture(bad,synthetic=True)
        bad=self.save([tcp(REQUEST)])
        bad.write_bytes(bad.read_bytes()[:-1])
        with self.assertRaisesRegex(CaptureError,'truncated'):
            analyze_capture(bad,synthetic=True)
