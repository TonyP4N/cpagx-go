"""End-to-end synthetic packet adapter, provenance and bounded stream negatives."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_packet_envelope import pcap, pcapng
from test_packet_protocol import GET, REPLY, frame
from cpag_core.packet_pipeline import analyze_capture, PacketEvidence, StreamLimits
from cpag_core.parsers.packet_envelope import CaptureError
from cpag_core.contracts import validate


class PacketPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'synthetic.pcap'

    def run_frames(self, frames, container=pcap, **kwargs):
        self.path.write_bytes(container(list(enumerate(frames,1))))
        return analyze_capture(self.path, synthetic=True, **kwargs)

    def test_end_to_end_segmented_out_of_order_retransmitted_evidence(self):
        for container in (pcap, pcapng):
            result = self.run_frames([frame(GET[20:],120), frame(GET[:20]), frame(GET[:20]),
                                      frame(REPLY,reverse=True)],container)
            self.assertEqual(len(result['events']),2)
            self.assertEqual(len(result['graph']['edges']),1)
            self.assertEqual(len(result['graph']['nodes'][0]['evidence_refs']),3)
            self.assertEqual(result['graph']['claims'][0]['status'],'observed')
            for e in result['events']:
                validate('NetworkEvent',e)
            validate('GraphArtifact',result['graph'])
            evidence = PacketEvidence(self.path,synthetic=True)
            for obs in result['observations']:
                pdu = bytearray(len(bytes.fromhex(obs['pdu_hex'])))
                for field in obs['field_slices']:
                    raw = evidence.resolve(field['source_ref'],field)
                    self.assertEqual(raw['integrity'],'file_and_frame_sha256_verified')
                    start = field['pdu_byte_offset']
                    pdu[start:start+field['length']] = bytes.fromhex(field['hex'])
                self.assertEqual(pdu.hex(),obs['pdu_hex'])

    def test_coalescing_and_ambiguous_context(self):
        result=self.run_frames([frame(GET+GET),frame(REPLY,reverse=True)])
        self.assertEqual(len(result['events']),3)
        self.assertEqual(result['graph']['edges'],[])

    def test_gap_conflict_incomplete_wrap(self):
        for pieces,reason in [([frame(GET[:20]),frame(GET[21:],121)],'stream_gap'),
                              ([frame(GET),frame(b'x',110)],'conflicting_overlap'),
                              ([frame(GET[:-1])],'segmentation'),
                              ([frame(GET,2**32-4)],'sequence_wrap')]:
            result=self.run_frames(pieces+[frame(REPLY,reverse=True)])
            self.assertEqual(result['graph']['edges'],[])
            self.assertTrue(any(reason in e['reason'] for e in result['unsupported']),result)

    def test_boundaries_no_cross_epoch(self):
        for flag in (1,2,4):
            control=bytearray(frame(b'',200)); control[47]=flag
            result=self.run_frames([frame(GET),bytes(control),frame(REPLY,reverse=True)])
            self.assertEqual(result['graph']['edges'],[])

    def test_limits_and_optin(self):
        self.run_frames([frame(GET)])
        with self.assertRaises(CaptureError):
            analyze_capture(self.path)
        with self.assertRaisesRegex(CaptureError,'segment_cache'):
            self.run_frames([frame(GET),frame(GET)],stream_limits=StreamLimits(max_segments=1))
        with self.assertRaisesRegex(CaptureError,'stream_cache'):
            self.run_frames([frame(GET),frame(REPLY,reverse=True)],stream_limits=StreamLimits(max_streams=1))
        result=self.run_frames([frame(GET)],stream_limits=StreamLimits(max_stream_bytes=1))
        self.assertEqual(result['events'],[])

    def test_tamper_file_frame_and_field(self):
        result=self.run_frames([frame(GET)])
        index=PacketEvidence(self.path,synthetic=True)
        field=result['observations'][0]['field_slices'][0]
        with self.assertRaisesRegex(CaptureError,'field_evidence'):
            index.resolve(field['source_ref'],dict(field,hex='00'))
        with self.assertRaisesRegex(CaptureError,'metadata'):
            index.resolve(dict(field['source_ref'],frame_sha256='0'*64))
        with self.assertRaisesRegex(CaptureError,'raw_time'):
            index.resolve(dict(field['source_ref'],raw_time='9'))
        data=bytearray(self.path.read_bytes()); data[-1]^=1; self.path.write_bytes(data)
        with self.assertRaisesRegex(CaptureError,'file_hash'):
            index.resolve(field['source_ref'])

    def test_named_fields_split_between_frames_and_tamper(self):
        result=self.run_frames([frame(GET[:41]),frame(GET[41:],141)])
        obs=result['observations'][0]
        self.assertEqual(obs['fields']['cip.path']['hex'],'200124013001')
        index=PacketEvidence(self.path,synthetic=True)
        for field in obs['fields'].values():
            for part in field['slices']:
                index.resolve(part['source_ref'],part)
        part=obs['fields']['cip.path']['slices'][0]
        with self.assertRaisesRegex(CaptureError,'outside_frame'):
            index.resolve(part['source_ref'],dict(part,frame_byte_offset=99999))

    def test_time_pdu_and_processing_bounds(self):
        result=self.run_frames([frame(GET[:10]),frame(GET[10:20],110),frame(GET[20:],120)],
                               stream_limits=StreamLimits(max_capture_seconds=1))
        self.assertEqual(result['events'],[])
        self.assertIn('capture_time_limit',result['unsupported'][0]['reason'])
        result=self.run_frames([frame(GET+GET)],stream_limits=StreamLimits(max_pdus=1))
        self.assertEqual(result['events'],[])
        self.assertEqual(result['unsupported'][0]['reason'],'pdu_count_limit')
        with patch('cpag_core.packet_pipeline.time.monotonic',side_effect=[0,11]):
            with self.assertRaisesRegex(CaptureError,'processing_deadline'):
                analyze_capture(self.path,synthetic=True)

    def test_unknown_transport_disables_association_and_close_payload_rejected(self):
        unknown=bytearray(frame(b'')); unknown[12:14]=b'\x86\xdd'
        result=self.run_frames([frame(GET),bytes(unknown),frame(REPLY,reverse=True)])
        self.assertEqual(result['graph']['edges'],[])
        control=bytearray(frame(GET)); control[47]=1
        result=self.run_frames([bytes(control),frame(REPLY,reverse=True)])
        self.assertEqual(result['graph']['edges'],[])
        self.assertTrue(any('control_packet_payload' in x['reason'] for x in result['unsupported']))

    def test_checksum_query_reports_captured_bytes_only(self):
        from cpag_core.packet_pipeline import checksum_evidence
        # Published IPv4 checksum example header, total length 0x73 / checksum b861.
        raw=b'\0'*12+b'\x08\x00'+bytes.fromhex('45000073000040004011b861c0a80001c0a800c7')+b'\0'*95
        self.assertTrue(checksum_evidence(raw)['ipv4']['valid_for_captured_bytes'])
        result=self.run_frames([frame(GET)])
        evidence=PacketEvidence(self.path,synthetic=True)
        checks=evidence.resolve(result['events'][0]['source_ref'])['network_checksums']
        self.assertFalse(checks['ipv4']['valid_for_captured_bytes'])
        self.assertFalse(checks['tcp']['valid_for_captured_bytes'])
        self.assertEqual(checks['tcp']['stored_hex'],'0000')
