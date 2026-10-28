import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
import round19_density_reference as oracle

class DensityReferenceTests(unittest.TestCase):
    def test_hand_fixed_endpoints_and_counts(self):
        expected={'S':(100,'2026-01-01T00:00:14.950000Z','2026-01-01T00:00:16.920000Z'),
                  'M':(1000,'2026-01-01T00:00:59.950000Z','2026-01-01T00:01:28.920000Z'),
                  'L':(10000,'2026-01-01T00:08:29.950000Z','2026-01-01T00:13:28.920000Z')}
        for scale,(count,last_network,last_process) in expected.items():
            with self.subTest(scale=scale):
                rows=oracle.expected_rows(scale)
                self.assertEqual(len(rows),2*count-1)
                self.assertEqual(rows[0]['time'],'2026-01-01T00:00:10.000000Z')
                self.assertEqual(rows[count-1]['time'],last_network)
                self.assertEqual(rows[count]['time'],'2026-01-01T00:00:09.080000Z')
                self.assertEqual(rows[-1]['time'],last_process)
                self.assertEqual(len({row['id'] for row in rows}),2*count-1)

    def test_reference_records_match_independently_declared_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'new'
            report=oracle.generate(root,'S',batch='fixed',sample_sha256='b'*64)
            self.assertEqual(report['expected_events'],199)
            with (root/'independent-reference.csv').open(newline='') as stream:rows=list(csv.DictReader(stream))
            refs=json.loads((root/'references.json').read_text())
            for number in (1,100,101,199):
                row=rows[number-1];ref=refs[row['id']]
                self.assertEqual(ref['locator']['record_number'],number)
                self.assertEqual(ref['sha256'],report['source_sha256'])
                self.assertEqual(ref['locator']['columns'],['id','kind','asset','time','basis'])
            with self.assertRaises(FileExistsError):oracle.generate(root,'S',batch='fixed',sample_sha256='b'*64)

if __name__=='__main__':unittest.main()
