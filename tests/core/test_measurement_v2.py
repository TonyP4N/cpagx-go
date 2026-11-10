import json
from pathlib import Path
import tempfile
import unittest
from cpag_core import measurement_v2 as m


class PhaseV2Tests(unittest.TestCase):
    def test_all_calls_survive_raw_limit_without_invented_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/'metrics.jsonl')
            for number in range(300):
                m.record(path, 'parse', 'failed' if number==299 else 'returned', .5, .25, 1024+number)
            m.record(path, 'export', 'returned', 200, 80, 2048)
            m.flush_summaries()
            rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
            self.assertEqual(len(rows), 257)
            summary = rows[-1]
            self.assertEqual(summary['all_observed_calls'], 301)
            self.assertEqual(summary['raw_rows_not_retained'], 45)
            self.assertEqual(summary['phases']['parse'], {'calls':300,'returned':299,'failed':1,
                'wall_seconds':150,'cpu_seconds':75,'rss_high_water_bytes':1323})
            self.assertNotIn('total_seconds', summary)
            self.assertNotIn('allocation_bytes', summary)
            m.flush_summaries()
            self.assertEqual(len(Path(path).read_text().splitlines()),257)

    def test_summary_absent_before_normal_flush(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/'metrics.jsonl')
            m.record(path,'parse','returned',1,0,100)
            self.assertEqual(json.loads(Path(path).read_text())['kind'],'sample')
            m.flush_summaries()

if __name__ == '__main__': unittest.main()
