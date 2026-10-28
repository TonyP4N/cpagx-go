"""Exact raw-byte software boundaries, not dense/target-host performance."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from round19_byte_fixture import generate
from cpag_core.dual_source import analyze, run_dual

class ByteBoundaryTests(unittest.TestCase):
    def test_exact_boundaries_and_plus_one_never_publish_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); inputs=root/'inputs'; generate(inputs)
            networks=[inputs/f'network-{i}.pcap' for i in range(4)]
            process=inputs/'process.csv'; profile=inputs/'profile.json'
            result=analyze(networks,process,json.loads(profile.read_text()))
            self.assertEqual((len(result['network']),len(result['process']),len(result['operations']),len(result['changes'])),(2,10000,1,1))
            self.assertEqual(len(result['candidates']),1)
            self.assertEqual(result['candidates'][0]['state'],'unknown')
            self.assertIn('unsupported_network_records_present',result['candidates'][0]['unknown_reasons'])
            # Independent byte oracle: 64 MiB per item, 128 MiB total, 8 MiB CSV.
            for index,(paths,target) in enumerate(((networks[:1],networks[0]),(networks,networks[1]),(networks,process))):
                size=target.stat().st_size
                with target.open('ab') as stream:stream.write(b'!')
                output=root/f'rejected-{index}'
                try:
                    with self.assertRaisesRegex(ValueError,'input_size_limit'):
                        run_dual(paths,process,profile,output)
                    self.assertFalse(output.exists())
                finally:
                    with target.open('r+b') as stream:stream.truncate(size)
            with self.assertRaisesRegex(ValueError,'network_file_limit'):
                run_dual(networks+[networks[0]],process,profile,root/'fifth')
            self.assertFalse((root/'fifth').exists())
            # Sixteen columns are already exercised above; seventeen must fail.
            process.write_text('time,pump,'+','.join(f'x{i}' for i in range(15))+'\n2026-01-01T00:00:10Z,0,'+','*14+'\n')
            with self.assertRaisesRegex(ValueError,'unsupported_or_empty_process'):
                run_dual(networks,process,profile,root/'columns')
            self.assertFalse((root/'columns').exists())

if __name__=='__main__':unittest.main()
