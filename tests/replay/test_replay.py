import copy
import unittest
from cpag_core.replay import ReplayWindow

def event(n,time):
    return {'schema_version':'1.0.0','synthetic':True,'event_id':str(n),'source_ref':{'file_sha256':'a'*64,'frame_number':1,'record_number':None,'column':None,'raw_time':None},'event_time':time,'ingest_time':None,'quality':{'status':'partial','reasons':['synthetic']},'endpoints':{'source':'a','destination':'b'},'protocol':'synthetic','operation':'observe','correlation_id':None,'response_status':None}

def at(n):return '2026-10-26T00:00:%02dZ'%n

class ReplayTests(unittest.TestCase):
    def test_prefix_never_reads_future_or_changes_prior_output(self):
        w=ReplayWindow();first=w.push(event(1,at(1)),available_at=at(1));saved=copy.deepcopy(first)
        # There is no iterable input that could inspect a future suffix.
        w.push(event(2,at(2)),available_at=at(2))
        self.assertEqual(first,saved);self.assertEqual(len(first['events']),1)
        other=ReplayWindow();self.assertEqual(other.push(event(1,at(1)),available_at=at(1)),first)
        w.snapshot()['events'][0]['operation']='tamper'
        self.assertEqual(w.snapshot()['events'][0]['operation'],'observe')
    def test_late_revision_expiry_and_future_timestamp(self):
        w=ReplayWindow(window_seconds=5)
        self.assertEqual(w.push(event(1,at(5)),available_at=at(7))['status'],'late_revision')
        self.assertEqual(w.push(event(2,at(1)),available_at=at(7))['status'],'outside_window')
        self.assertEqual(w.push(event(3,at(8)),available_at=at(7))['status'],'future_timestamp_rejected')
        self.assertEqual(w.advance(at(11))['events'],[])
        with self.assertRaisesRegex(ValueError,'backwards'):w.advance(at(10))
    def test_null_time_capacity_and_conflicting_identity(self):
        w=ReplayWindow(max_events=1)
        self.assertEqual(w.push(event(0,None),available_at=at(1))['status'],'timestamp_unavailable')
        e=event(1,at(1));w.push(e,available_at=at(1))
        self.assertEqual(w.push(e,available_at=at(1))['status'],'duplicate')
        self.assertEqual(w.push(event(2,at(1)),available_at=at(1))['status'],'capacity_rejected')
        e['operation']='conflict'
        self.assertEqual(w.push(e,available_at=at(1))['status'],'conflicting_duplicate')
        self.assertEqual(w.snapshot()['events'][0]['operation'],'observe')
    def test_byte_limit_and_real_data_gating(self):
        w=ReplayWindow(max_bytes=1)
        self.assertEqual(w.push(event(1,at(1)),available_at=at(1))['status'],'capacity_rejected')
        e=event(1,at(1));e['synthetic']=False
        with self.assertRaisesRegex(ValueError,'synthetic'):w.push(e,available_at=at(1))

    def test_invalid_contract_does_not_advance(self):
        w=ReplayWindow()
        with self.assertRaises(ValueError):w.push({},available_at=at(1))
        self.assertIsNone(w.clock)
        with self.assertRaises(ValueError):w.advance('2026-10-26T00:00:01')
