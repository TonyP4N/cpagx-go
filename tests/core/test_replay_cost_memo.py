from copy import deepcopy
import unittest
from cpag_core.shared_artifact_store_compact import _hash,_uncached_hash,_small_hash
from cpag_core.dual_source import references

class ReplayCostMemoTests(unittest.TestCase):
    def test_pure_hash_all_arguments_and_bounded_cache(self):
        for i in range(5000):
            args=('scalar',str(i).encode(),len(str(i)),i%3,i%4)
            self.assertEqual(_hash(*args),_uncached_hash(*args))
        self.assertLessEqual(_small_hash.cache_info().currsize,4096)
        args=('dict',b'x'*2048,4096,8,2)
        self.assertEqual(_hash(*args),_uncached_hash(*args))

    def test_shared_reference_subtrees_are_complete_and_call_scoped(self):
        a={'file_sha256':'a'*64,'frame_number':1,'record_number':None,'column':None,'raw_time':'a'}
        b=dict(a,frame_number=2)
        shared={'evidence_refs':[a,b]}
        obj=[shared,{'claim':shared,'other':deepcopy(shared)},[a]]
        self.assertEqual(references(obj),[a,b])
        b['frame_number']=3
        self.assertEqual(references(obj),[a,dict(a,frame_number=2),b])
        shared['evidence_refs'].append(dict(a,frame_number=4))
        self.assertEqual(len(references(obj)),4)
