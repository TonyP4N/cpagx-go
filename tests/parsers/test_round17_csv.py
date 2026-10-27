"""Handwritten CSV answers, independent of packet fixtures/production encoder."""
from pathlib import Path
import tempfile
import unittest

from cpag_core.parsers import parse_process, ProcessLimits


class Round17CSVTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'process.csv'
        self.profile={'timestamp_column':'time','columns':{
            'level':{'tag':'level','value_type':'analog','unit':'m','asset_id':'tank'},
            'pump':{'tag':'pump','value_type':'state','asset_id':'pump','state_map':{'ON':1,'OFF':0}}}}

    def parse(self,text,**kwargs):
        self.path.write_text(text,encoding='utf-8')
        return parse_process(self.path,self.profile,synthetic=False,extended=True,**kwargs)

    def test_missing_zero_invalid_nonfinite_state_and_original_record(self):
        result=self.parse('time,level,pump\n2026-01-01T00:00:00Z,0,OFF\n'
                          '2026-01-01T00:00:01Z,,ON\n'
                          'bad,abc,UNKNOWN\n2026-01-01T00:00:03Z,NaN,ON\n')
        events=result['events']
        self.assertEqual([e['value'] for e in events[::2]],[0.0,None,None,None])
        self.assertEqual(events[1]['value'],0)
        self.assertEqual(events[2]['quality']['reasons'],['missing_value'])
        self.assertEqual(events[4]['quality']['reasons'],['invalid_numeric_value','invalid_time'])
        self.assertEqual(events[5]['quality']['reasons'],['invalid_time','unknown_state'])
        self.assertEqual(events[6]['quality']['reasons'],['nonfinite_value'])
        self.assertFalse(any(e['synthetic'] for e in events))
        self.assertEqual(events[4]['source_ref']['record_number'],3)
        self.assertEqual(events[4]['source_ref']['raw_time'],'bad')

    def test_time_precision_and_timezone_never_silently_default(self):
        result=self.parse('time,level,pump\n2026-01-01T00:00:00.123456789Z,1,ON\n'
                          '2026-01-01T00:00:00.123456,2,OFF\n')
        first,second=result['events'][0],result['events'][2]
        self.assertIsNone(first['event_time'])
        self.assertEqual(first['source_ref']['raw_time'],'2026-01-01T00:00:00.123456789Z')
        self.assertIn('timestamp_precision_unsupported',first['quality']['reasons'])
        self.assertIsNone(second['event_time'])
        self.assertIn('unknown_timezone',second['quality']['reasons'])

    def test_duplicates_retain_all_records_and_mark_all_members(self):
        result=self.parse('time,level,pump\n2026-01-01T00:00:00Z,0,OFF\n'
                          '2026-01-01T00:00:00Z,0,OFF\n'
                          '2026-01-01T08:00:00+08:00,2,ON\n')
        self.assertEqual(len(result['events']),6)
        self.assertEqual({e['source_ref']['record_number'] for e in result['events']},{1,2,3})
        self.assertEqual(len({e['event_id'] for e in result['events']}),6)
        for event in result['events']:
            self.assertIn('duplicate_process_time',event['quality']['reasons'])
            self.assertEqual('duplicate_process_record' in event['quality']['reasons'],event['source_ref']['record_number']<3)

    def test_legacy_csv_duplicate_and_precision_semantics_are_preserved(self):
        text='time,level,pump\n2026-01-01T00:00:00.123456789Z,1,ON\n2026-01-01T00:00:00.123456789Z,1,ON\n'
        current=self.parse(text)
        legacy=parse_process(self.path,self.profile,synthetic=False)
        self.assertEqual(len(legacy['events']),4)
        self.assertTrue(all(e['quality']['status']=='valid' for e in legacy['events']))
        self.assertEqual(legacy['events'][0]['event_time'],'2026-01-01T00:00:00.123456Z')
        self.assertTrue(all(e['event_time'] is None for e in current['events']))
        self.assertTrue(all('duplicate_process_record' in e['quality']['reasons'] for e in current['events']))

    def test_multiline_bom_utf8_logical_records_and_invalid_bytes(self):
        self.profile['columns']['pump'].pop('state_map')
        result=self.parse('\ufefftime,level,pump\n2026-01-01T00:00:00Z,1,"a\nb"\n2026-01-01T00:00:01Z,2,关闭\n')
        self.assertEqual(len(result['events']),4)
        self.assertEqual(result['events'][1]['value'],'a\nb')
        self.assertEqual(result['events'][3]['source_ref']['record_number'],2)
        self.path.write_bytes(b'time,level,pump\n\xff')
        self.assertEqual(parse_process(self.path,self.profile,synthetic=False)['events'],[])

    def test_bad_structure_and_limits_no_trusted_partial_output(self):
        for text in ('time,level,level,pump\n', 'time,level\n',
                     'time,level,pump\n2026-01-01T00:00:00Z,1\n',
                     'time,level,pump\n"unfinished'):
            result=self.parse(text)
            self.assertEqual(result['events'],[])
            self.assertNotEqual(result['quality']['status'],'valid')
        text='time,level,pump\n2026-01-01T00:00:00Z,1,ON\n2026-01-01T00:00:01Z,2,ON\n'
        for limits,reason in [(ProcessLimits(max_bytes=1),'process_byte_limit'),
                              (ProcessLimits(max_records=1),'process_record_limit'),
                              (ProcessLimits(max_columns=2),'process_column_limit')]:
            result=self.parse(text,limits=limits)
            self.assertEqual(result['events'],[])
            self.assertEqual(result['quality']['reasons'],[reason])
