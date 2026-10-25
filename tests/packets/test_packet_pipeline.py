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
from cpag_core.pipeline import fingerprint


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
        self.assert_associations(result,'ambiguous','duplicate_requests')

    def assert_associations(self, result, status, reason):
        for obs,event in zip(result['observations'],result['events']):
            self.assertEqual(obs['association_status'],status)
            self.assertEqual(obs['association_reason'],reason)
            self.assertIn('association_'+status+':'+reason,event['quality']['reasons'])
            original={k:v for k,v in obs.items() if k not in ('association_status','association_reason')}
            self.assertEqual(event['event_id'],'packet-'+fingerprint(original))

    def test_explicit_association_states(self):
        for frames,status,reason in [
            ([frame(GET),frame(REPLY,reverse=True)],'matched','unique_request_response'),
            ([frame(GET)],'missing','response_missing'),
            ([frame(REPLY,reverse=True)],'missing','request_missing'),
            ([frame(GET),frame(REPLY+REPLY,reverse=True)],'ambiguous','duplicate_responses'),
            ([frame(GET+GET),frame(REPLY+REPLY,reverse=True)],'ambiguous','duplicate_requests_and_responses'),
            ([frame(GET+GET)],'ambiguous','duplicate_requests'),
        ]:
            with self.subTest(reason=reason):
                self.assert_associations(self.run_frames(frames),status,reason)
        zero_get=bytearray(GET); zero_get[12:20]=b'\0'*8
        zero_reply=bytearray(REPLY); zero_reply[12:20]=b'\0'*8
        result=self.run_frames([frame(bytes(zero_get)),frame(bytes(zero_reply),reverse=True)])
        self.assert_associations(result,'unsupported','zero_sender_context')
        self.assertEqual(result['graph']['edges'],[])

    def test_gap_conflict_incomplete_wrap(self):
        for pieces,reason in [([frame(GET[:20]),frame(GET[21:],121)],'stream_gap'),
                              ([frame(GET),frame(b'x',110)],'conflicting_overlap'),
                              ([frame(GET[:-1])],'segmentation'),
                              ([frame(GET,2**32-4)],'sequence_wrap')]:
            result=self.run_frames(pieces+[frame(REPLY,reverse=True)])
            self.assertEqual(result['graph']['edges'],[])
            self.assertTrue(any(reason in e['reason'] for e in result['unsupported']),result)
            self.assert_associations(result,'unsupported','rejected_stream_in_connection_epoch')

    def test_boundaries_no_cross_epoch(self):
        for flag in (2,4):
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
        self.assert_associations(result,'unsupported','unknown_transport_in_capture')
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

    def test_fin_ack_half_close_duplicate_fin_and_full_close_keep_observations(self):
        def control(flags,seq,reverse=False):
            raw=bytearray(frame(b'',seq,reverse));raw[47]=flags;return bytes(raw)
        for frames in ([frame(GET),frame(REPLY,reverse=True),control(17,148),control(16,146,True)],
                       [frame(GET),control(17,148),frame(REPLY,reverse=True)],
                       [frame(GET),control(17,148),control(17,148),control(16,146,True),frame(REPLY,reverse=True)],
                       [frame(GET),frame(REPLY,reverse=True),control(17,148),control(17,146,True),control(16,149)]):
            result=self.run_frames(frames)
            self.assertEqual(len(result['events']),2)
            self.assertEqual(len(result['graph']['edges']),1)
            self.assertEqual(result['unsupported'],[])

    def test_reset_late_data_and_tuple_reuse_no_cross_connection_pair(self):
        def control(flags,seq,reverse=False,ack=0):
            raw=bytearray(frame(b'',seq,reverse));raw[47]=flags;raw[42:46]=ack.to_bytes(4,'big');return bytes(raw)
        result=self.run_frames([frame(GET),control(4,148),frame(REPLY,reverse=True)])
        self.assertEqual(len(result['events']),1)
        self.assertEqual(result['graph']['edges'],[])
        self.assertIn('payload_after_connection_close',result['unsupported'][0]['reason'])
        # Same tuple/context/service in a new SYN epoch must not match old request.
        result=self.run_frames([frame(GET),control(17,148),control(17,146,True),
                                control(2,900),control(18,1900,True,901),frame(REPLY,1901,True)])
        self.assertEqual(len(result['events']),2)
        self.assertEqual(result['graph']['edges'],[])
        # Two complete epochs each associate within their own boundary.
        result=self.run_frames([frame(GET),frame(REPLY,reverse=True),control(4,148),
                                control(2,900),control(2,900),control(18,1900,True,901),
                                frame(GET,901),frame(REPLY,1901,True)])
        self.assertEqual(len(result['events']),4)
        self.assertEqual(len(result['graph']['edges']),2)
        epochs=[o['epoch'] for o in result['observations']]
        self.assertEqual(epochs,[0,0,1,1])

    def test_sender_payload_after_fin_rejected_without_erasing_prior_request(self):
        fin=bytearray(frame(b'',148));fin[47]=17
        result=self.run_frames([frame(GET),bytes(fin),frame(GET,149),frame(REPLY,reverse=True)])
        self.assertEqual(len(result['events']),2)
        self.assertEqual(result['graph']['edges'],[])
        self.assertTrue(any(x['reason']=='payload_after_connection_close' for x in result['unsupported']))

    def test_complete_handshake_close_and_same_sequence_reuse(self):
        def control(flags,seq,reverse=False,ack=0):
            raw=bytearray(frame(b'',seq,reverse));raw[47]=flags;raw[42:46]=ack.to_bytes(4,'big');return bytes(raw)
        handshake=[control(2,99),control(2,99),control(18,99,True,100),control(16,100,False,100)]
        close=[control(17,148),control(16,146,True,149),control(17,146,True,149),control(16,149,False,147)]
        result=self.run_frames(handshake+[frame(GET),frame(REPLY,reverse=True)]+close)
        self.assertEqual(len(result['events']),2)
        self.assertEqual(len(result['graph']['edges']),1)
        self.assertEqual({o['epoch'] for o in result['observations']},{1})
        # Reusing the exact same SYN sequence numbers/context still opens epoch 2.
        result=self.run_frames(handshake+[frame(GET)]+close+handshake+[frame(REPLY,reverse=True)])
        self.assertEqual(len(result['events']),2)
        self.assertEqual(result['graph']['edges'],[])
        self.assertEqual([o['epoch'] for o in result['observations']],[1,2])
        result=self.run_frames(handshake+[frame(GET),frame(REPLY,reverse=True)]+close+[frame(GET,149)])
        self.assertEqual(len(result['events']),2)
        self.assertTrue(any(x['reason']=='payload_after_connection_close' for x in result['unsupported']))
