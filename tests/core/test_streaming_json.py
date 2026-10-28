import hashlib
import math
from pathlib import Path
import random
import tempfile
import unittest
from cpag_core.pipeline import canonical, stable_value, fingerprint, json_chunks, write_canonical, canonical_file_matches


class StreamingJSONTests(unittest.TestCase):
    def test_independent_legacy_bytes_and_hashes(self):
        ref={'file_sha256':'a'*64,'frame_number':1,'raw_time':'时间', 'column':None}
        values=[None,False,0,-0.0,1e-8,'\\\n中文😀',[],{},[ref]*40,
                {'run_id':'a','items':[{'ingest_time':None,'x':0}], 'tuple':({'run_id':'keep'},)},
                {1:'one',2:'two'}]
        rng=random.Random(42)
        for _ in range(100):
            values.append({'z':[rng.random(),rng.randrange(-100,100),ref], 'a': {'run_id':str(rng.random()),'v':rng.choice(values[:8])}})
        for value in values:
            self.assertEqual(b''.join(json_chunks(value)),canonical(value))
            self.assertEqual(fingerprint(value),hashlib.sha256(canonical(stable_value(value))).hexdigest())

    def test_file_bytes_and_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'x.json';value={'nested':[{'a':1}]*20}
            write_canonical(path,value)
            self.assertEqual(path.read_bytes(),canonical(value)+b'\n')
            self.assertTrue(canonical_file_matches(path,value))
            path.write_bytes(path.read_bytes().replace(b'1',b'2',1))
            self.assertFalse(canonical_file_matches(path,value))

    def test_mutation_between_calls_not_cached(self):
        value={'a':1};one=fingerprint(value);value['a']=2
        self.assertNotEqual(one,fingerprint(value))

    def test_nonfinite_rejected(self):
        for value in (math.inf,-math.inf,math.nan):
            with self.assertRaises(ValueError):b''.join(json_chunks({'x':value}))
