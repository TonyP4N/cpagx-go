"""Raw density fixture controls independent of analysis output and labels."""
import csv
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/validation'), str(ROOT / 'services/analysis/src')]
from round19_scale_fixture import generate
from round19_capacity import read_case
from cpag_core.dual_source_rules import validate_profile


class ScaleFixtureTests(unittest.TestCase):
    def test_all_scales_preserve_raw_request_response_and_csv_density(self):
        with tempfile.TemporaryDirectory() as directory:
            for scale, count in [('S', 100), ('M', 1000), ('L', 10000)]:
                with self.subTest(scale=scale):
                    root = Path(directory) / scale; report = generate(root, scale)
                    data = (root / 'network.pcap').read_bytes(); position = 24; frames = []
                    while position < len(data):
                        _, _, captured, original = struct.unpack_from('<IIII', data, position)
                        self.assertEqual(captured, original)
                        frames.append(data[position + 16:position + 16 + captured]); position += 16 + captured
                    self.assertEqual(position, len(data)); self.assertEqual(len(frames), 2 * count)
                    # CIP service literal starts after Ethernet/IP/TCP + ENIP/CPF.
                    self.assertEqual(sum(frame[94] == 0x10 for frame in frames), count)
                    self.assertEqual(sum(frame[94] == 0x90 for frame in frames), count)
                    with (root / 'process.csv').open(newline='') as stream:
                        self.assertEqual(sum(1 for _ in csv.reader(stream)) - 1, count)
                    config = json.loads((root / 'replay-profile.json').read_text())
                    validate_profile(config)
                    sequence = config['replay']['sequence']
                    self.assertEqual(len(sequence), 3 * count + 4)
                    for slot, expected in [('network-0', 2 * count), ('process', count + 1)]:
                        records = [row['record_number'] for row in sequence if row.get('source_slot') == slot and 'record_number' in row]
                        self.assertEqual(records, list(range(1, expected + 1)))
                    self.assertEqual(read_case(root / 'dual_source-1.json')['input_logical_records'], count)
                    self.assertEqual(report['arrival_steps'], 3 * count + 4)
                    self.assertFalse(config['replay']['realtime'])

    def test_existing_fixture_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fixture'; generate(root, 'S')
            original = (root / 'network.pcap').read_bytes()
            with self.assertRaises(FileExistsError): generate(root, 'S')
            self.assertEqual((root / 'network.pcap').read_bytes(), original)


if __name__ == '__main__': unittest.main()
