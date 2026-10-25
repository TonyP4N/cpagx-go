import json
from pathlib import Path
import tempfile
import unittest
from test_packet_envelope import pcap
from test_packet_protocol import GET,REPLY,frame
from cpag_core.packet_job import run,verify_artifacts,query_evidence,ARTIFACTS
from cpag_core.contracts import validate

class PacketJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.capture=self.root/'synthetic.pcap'
        self.capture.write_bytes(pcap(list(enumerate([frame(GET[20:],120),frame(GET[:20]),frame(GET[:20]),frame(REPLY,reverse=True)],1))))
        self.process=self.root/'unused.txt';self.process.write_text('compatibility placeholder; unused')
        self.profile=self.root/'profile.json';self.profile.write_text(json.dumps({'synthetic':True,'adapter':'synthetic-packet-1'}))
        self.output=self.root/'output'
    def test_contract_query_and_retransmission_refs(self):
        manifest=run(self.capture,self.process,self.profile,self.output,synthetic=True)
        self.assertEqual({p.name for p in self.output.iterdir()},ARTIFACTS)
        validate('RunManifest',manifest)
        result=verify_artifacts(self.output,self.capture)
        self.assertEqual(len(result['graph']['nodes'][0]['evidence_refs']),3)
        query=query_evidence(self.output,self.capture,result['events'][0]['event_id'],'cip.path')
        self.assertEqual(query['observation']['fields']['cip.path']['hex'],'200124013001')
        self.assertTrue(query['verified_fields']['cip.path'])
        for piece in query['verified_fields']['cip.path']:
            self.assertEqual(piece['integrity'],'file_and_frame_sha256_verified')
    def test_forged_decoded_field_and_missing_sidecar_rejected(self):
        run(self.capture,self.process,self.profile,self.output,synthetic=True)
        side=self.output/'packet_observations.json';original=side.read_bytes();result=json.loads(original)
        result['observations'][0]['path']['class']=99;side.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError,'artifact hash/size'):verify_artifacts(self.output,self.capture)
        side.write_bytes(original);side.unlink()
        with self.assertRaises(OSError):verify_artifacts(self.output,self.capture)
    def test_gating(self):
        with self.assertRaisesRegex(ValueError,'opt_in'):run(self.capture,self.process,self.profile,self.output)
        self.profile.write_text('{"synthetic":true}')
        with self.assertRaisesRegex(ValueError,'profile'):run(self.capture,self.process,self.profile,self.output,synthetic=True)
