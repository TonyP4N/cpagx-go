import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cpag_core.measurement import phase

class PhaseTests(unittest.TestCase):
    def test_opt_in_does_not_change_value_and_reports_failure(self):
        @phase('probe')
        def work(value):
            if value is None:raise ValueError('original failure')
            return value
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'phases.jsonl'
            with patch.dict(os.environ,{'CPAG_PHASE_METRICS':str(p)}):
                self.assertEqual(work({'value':0}),{'value':0})
                with self.assertRaisesRegex(ValueError,'original failure'):work(None)
            rows=[json.loads(line) for line in p.read_text().splitlines()]
            self.assertEqual([r['status'] for r in rows],['returned','failed'])
            self.assertTrue(all(r['rss_high_water_bytes']>0 and r['wall_seconds']>=0 for r in rows))
    def test_disabled_requires_no_output(self):
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(phase('disabled')(lambda:7)(),7)
