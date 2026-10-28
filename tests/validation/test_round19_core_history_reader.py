"""Actual replay reader consumes bounded paths/pages, not full snapshots."""
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/validation'),str(ROOT/'services/analysis/src')]
from round19_core_small import inputs
from round19_core_cell import sample_history
from cpag_core import shared_export as core


class CoreHistoryReaderTests(unittest.TestCase):
    def test_actual_first_middle_last_and_original_page_use_only_bounded_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();networks,process,profile,_=inputs(root/'inputs','normal','replay')
            output=root/'artifact';core.export_task(networks,process,profile,output,run_id='history-reader',mode='replay',deadline=time.monotonic()+30)
            key=os.urandom(32);approval=core.issue_approval(output,key,deadline=time.monotonic()+30)
            metadata=core.metadata_task(output,approval=approval,authority_key=key);calls=[]
            class PathsOnly:
                def __init__(self,reader):self.reader=reader
                def get(self,name,*,path=(),max_bytes=8*1024**2):
                    if name in ('history/snapshots','history/revisions') and len(path)<2:raise AssertionError('whole_history_record_materialized')
                    calls.append(('get',name,list(path)));return self.reader.get(name,path=path,max_bytes=max_bytes)
                def page(self,name,*,path=(),offset=0,limit=100,max_bytes=8*1024**2):
                    if not path or not 1<=limit<=100 or max_bytes>8*1024**2:raise AssertionError('unbounded_history_page')
                    calls.append(('page',name,list(path)));return self.reader.page(name,path=path,offset=offset,limit=limit,max_bytes=max_bytes)
            @contextmanager
            def audited(*args,**kwargs):
                with core.open_reader(*args,**kwargs) as reader:yield PathsOnly(reader)
            adapter=types.SimpleNamespace(open_reader=audited,query_task=core.query_task,read_json=core.read_json)
            result,timings=sample_history(adapter,output,metadata,approval,key,time.monotonic()+30,networks,process,profile)
            self.assertEqual(len(result['snapshots']),3);self.assertEqual(len(result['revisions']),3)
            self.assertEqual(len(timings),7);self.assertTrue(calls)
            self.assertTrue(result['historical_operation']['independent_arrival_prefix_checked'])
            self.assertGreater(result['historical_operation']['evidence_page']['returned'],0)
            self.assertTrue(all(row['seconds']<10 and row['complete_response_bytes']<=8*1024**2 for row in timings))


if __name__=='__main__':unittest.main()
