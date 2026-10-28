"""Independent guard controls: no analyzer produces the expected answers."""
import copy
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from round19_core_oracle import compare_values,IdentityBijection,check_raw_evidence,pcap_records,csv_records


class CoreIndependentOracleTests(unittest.TestCase):
    def test_all_business_values_order_and_scalar_types_are_compared(self):
        old={'analysis':{'counterevidence':['kept'],'alternatives':['c3','c1'],'response':False,'sample':1.0},'graph':{'claims':[{'status':'hypothetical'}]}}
        changes=[lambda v:v['analysis']['counterevidence'].clear(),lambda v:v['analysis']['alternatives'].reverse(),
                 lambda v:v['analysis'].update(response=0),lambda v:v['analysis'].update(sample=1),
                 lambda v:v['graph']['claims'][0].update(status='confirmed')]
        for change in changes:
            new=copy.deepcopy(old);change(new);result=compare_values(old,new)
            self.assertFalse(result['equal']);self.assertTrue(result['differences'])
        self.assertTrue(compare_values(old,copy.deepcopy(old))['equal'])

    def test_only_exact_predeclared_scalar_path_changes_can_pass(self):
        old={'graph':{'graph_id':'old','claims':['all']}};new={'graph':{'graph_id':'new','claims':['all']}}
        rule={'path':'/graph/graph_id','old_present':True,'old':'old','new_present':True,'new':'new','reason':'explicit container hash version'}
        self.assertTrue(compare_values(old,new,allowed=[rule])['equal'])
        bad=copy.deepcopy(new);bad['graph']['claims'].clear();self.assertFalse(compare_values(old,bad,allowed=[rule])['equal'])
        bad=copy.deepcopy(rule);bad['new']='unregistered';self.assertFalse(compare_values(old,new,allowed=[bad])['equal'])
        bad=copy.deepcopy(rule);bad['path']='/missing';self.assertFalse(compare_values(old,new,allowed=[bad])['equal'])
        bad=copy.deepcopy(rule);bad['old']={'claims':'cannot hide objects'}
        with self.assertRaises(ValueError):compare_values(old,new,allowed=[bad])

    def test_missing_fields_and_truncated_examples_never_become_equal(self):
        result=compare_values({'a':[1,2,3]},{'a':[]},max_examples=1)
        self.assertFalse(result['equal']);self.assertEqual(result['unapproved_difference_count'],3);self.assertTrue(result['examples_truncated'])
        rule={'path':'/identity_strategy','old_present':False,'old':None,'new_present':True,'new':'merkle-json-dag-1','reason':'new explicit container identity'}
        self.assertTrue(compare_values({}, {'identity_strategy':'merkle-json-dag-1'},allowed=[rule])['equal'])

    def test_container_identity_mapping_must_be_bijective_and_linked(self):
        mapping=IdentityBijection();mapping.bind('s1','m1');mapping.bind('s2','m2');mapping.bind('s1','m1')
        self.assertEqual(mapping.mapped('s2'),'m2');self.assertIsNone(mapping.mapped(None))
        for a,b in [('s1','m2'),('s3','m1')]:
            with self.assertRaises(ValueError):mapping.bind(a,b)
        with self.assertRaises(ValueError):mapping.mapped('unregistered')

    def raw_fixture(self,root):
        frame=b'\x01\x02\x03\x04\xaa\xbb';record=struct.pack('<IIII',1767225610,500000,len(frame),len(frame))+frame
        network=root/'network.pcap';network.write_bytes(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiiII',2,4,0,0,65535,1)+record)
        header=b'time,pump,note\r\n';row=b'2026-01-01T00:00:10Z,1,"line1\r\nline2"\r\n'
        process=root/'process.csv';process.write_bytes(header+row)
        original={'raw_hex':frame.hex(),'frame_sha256':hashlib.sha256(frame).hexdigest(),'captured_length':6,'original_length':6,'byte_offset':40}
        return network,process,record,header,row,original

    def test_original_packet_and_quoted_logical_csv_records_are_located_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);network,process,record,header,row,original=self.raw_fixture(root)
            offline={'file_sha256':hashlib.sha256(network.read_bytes()).hexdigest(),'frame_number':1,'record_number':None,'column':None,'raw_time':'1767225610500000'}
            replay={'source_slot':'network-0','record_sha256':hashlib.sha256(record).hexdigest(),'frame_number':1,'record_number':None,'column':None,'raw_time':'1767225610500000'}
            for ref in (offline,replay):self.assertTrue(check_raw_evidence([{'source_ref':ref,'original':original}],[network],process)['all_returned_references_match_independent_originals'])
            expected={'time':'2026-01-01T00:00:10Z','pump':'1','note':'line1\r\nline2'}
            for ref in ({'file_sha256':hashlib.sha256(process.read_bytes()).hexdigest(),'frame_number':None,'record_number':1,'column':'pump','raw_time':expected['time']},
                        {'source_slot':'process','record_sha256':hashlib.sha256(row).hexdigest(),'frame_number':None,'record_number':2,'column':'pump','raw_time':expected['time']}):
                result=check_raw_evidence([{'source_ref':ref,'original':expected}],[network],process)
                self.assertEqual(result['checked_references'][0]['byte_offset'],len(header))
            self.assertEqual(len(csv_records(process)['records']),2);self.assertEqual(pcap_records(network)['records'][0]['byte_offset'],40)

    def test_changed_raw_hex_hash_offset_missing_frame_and_csv_column_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);network,process,record,header,row,original=self.raw_fixture(root)
            ref={'source_slot':'network-0','record_sha256':hashlib.sha256(record).hexdigest(),'frame_number':1,'record_number':None,'column':None,'raw_time':'1767225610500000'}
            for key,value in [('raw_hex','0000'),('frame_sha256','0'*64),('byte_offset',41)]:
                bad=dict(original);bad[key]=value
                with self.assertRaises(ValueError):check_raw_evidence([{'source_ref':ref,'original':bad}],[network],process)
            for key,value in [('frame_number',2),('frame_number',True),('record_sha256','0'*64),('source_slot','network-9')]:
                bad=dict(ref);bad[key]=value
                with self.assertRaises(ValueError):check_raw_evidence([{'source_ref':bad,'original':original}],[network],process)
            bad={'source_slot':'process','record_sha256':hashlib.sha256(row).hexdigest(),'frame_number':None,'record_number':2,'column':'absent','raw_time':'2026-01-01T00:00:10Z'}
            with self.assertRaises(ValueError):check_raw_evidence([{'source_ref':bad,'original':{}}],[network],process)
            network.write_bytes(network.read_bytes()[:-1])
            with self.assertRaises(ValueError):pcap_records(network)

if __name__=='__main__':unittest.main()
