from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from cpag_core.packet_pipeline import PacketEvidence,standard_ref,CaptureError

ROOT=Path(__file__).resolve().parents[2]

class BatchEvidenceTests(unittest.TestCase):
    def test_one_verification_each_boundary_and_same_original(self):
        index=PacketEvidence(ROOT/'examples/round18-replay/network.pcap',synthetic=True)
        ref=standard_ref(next(iter(index.frames.values())))
        expected=index.resolve(ref)
        with patch.object(index,'_verified',wraps=index._verified) as check:
            with index.verified_batch():
                for _ in range(100):self.assertEqual(index.resolve(ref),expected)
            self.assertEqual(check.call_count,2)
    def test_changed_bytes_at_exit_reject_whole_batch_and_clear_cache(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'network.pcap';shutil.copyfile(ROOT/'examples/round18-replay/network.pcap',source)
            index=PacketEvidence(source,synthetic=True);ref=standard_ref(next(iter(index.frames.values())))
            with self.assertRaisesRegex(CaptureError,'evidence_file_hash_mismatch'):
                with index.verified_batch():
                    index.resolve(ref)
                    data=source.read_bytes();source.write_bytes(data[:-1]+bytes([data[-1]^1]))
            self.assertIsNone(index._batch_data)
            with self.assertRaises(CaptureError):index.resolve(ref)
    def test_nested_batch_rejected(self):
        index=PacketEvidence(ROOT/'examples/round18-replay/network.pcap',synthetic=True)
        with index.verified_batch():
            with self.assertRaisesRegex(CaptureError,'nested_evidence_batch'):
                with index.verified_batch():pass
