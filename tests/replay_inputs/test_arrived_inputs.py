"""Independent raw bytes/CSV prefix answers; guard rejects any future read."""
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from cpag_core.replay_inputs import ReplayInputs
from cpag_core.pipeline import canonical
from cpag_core.parsers.packet_envelope import CaptureError, Limits

REQUEST=bytes.fromhex('6f0018004433221100000000010203040506070800000000'
                      '000000000000020000000000b20008000e03200124013001')
REPLY=bytes.fromhex('6f0016004433221100000000010203040506070800000000'
                    '000000000000020000000000b20006008e0000000102')
PROFILE={'timestamp_column':'time','columns':{'level':{'tag':'level','asset_id':'tank','value_type':'analog','unit':'m'}}}


def frame(payload,seq=100,reverse=False,flags=24):
    ports=(44818,12000) if reverse else (12000,44818)
    ips=bytes.fromhex('0a0000020a000001' if reverse else '0a0000010a000002')
    ip=struct.pack('!BBHHHBBH',0x45,0,40+len(payload),1,0,64,6,0)+ips
    tcp=struct.pack('!HHIIBBHHH',*ports,seq,0,0x50,flags,1024,0,0)
    return b'\x11'*6+b'\x22'*6+b'\x08\x00'+ip+tcp+payload


def pcap(frames,endian='<',nano=False):
    data=struct.pack(endian+'IHHIIII',0xa1b23c4d if nano else 0xa1b2c3d4,2,4,0,0,65535,1)
    cuts=[]
    for n,raw in enumerate(frames,1):
        data+=struct.pack(endian+'IIII',n,0,len(raw),len(raw))+raw;cuts.append(len(data))
    return data,cuts


def pcapng(frames,endian='<'):
    def block(kind,body):
        size=12+len(body);return struct.pack(endian+'II',kind,size)+body+struct.pack(endian+'I',size)
    data=block(0x0a0d0d0a,struct.pack(endian+'IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack(endian+'HHI',1,0,65535));cuts=[]
    for n,raw in enumerate(frames,1):
        data+=block(6,struct.pack(endian+'IIIII',0,0,n*1000000,len(raw),len(raw))+raw+b'\0'*((-len(raw))%4));cuts.append(len(data))
    return data,cuts


def visible(inputs,final=False):
    return {k:v for k,v in inputs.snapshot(final=final).items() if k!='frames'}


class Guard(io.BytesIO):
    def __init__(self,data,limit):super().__init__(data);self.limit=limit;self.calls=[]
    def read(self,n=-1):
        self.calls.append((self.tell(),n))
        if n<0 or self.tell()+n>self.limit:raise AssertionError('future byte read')
        return super().read(n)


class ArrivalInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.serial=0
    def source(self,data,suffix='.pcap'):
        self.serial+=1;p=self.base/f'{self.serial}{suffix}';p.write_bytes(data);return p
    def inputs(self,network,process=None):
        if process is None:process=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n','.csv')
        result=ReplayInputs(network,process,PROFILE,synthetic=True);self.addCleanup(result.close);return result
    def advance(self,inputs,slot,n,**extra):
        return inputs.advance(dict(source_slot=slot,record_number=n,available_at='2026-01-01T00:00:20Z',**extra))

    def test_constructor_and_complete_frame_never_read_future_byte_all_containers(self):
        for container in (pcap,pcapng):
            for endian in ('<','>'):
                data,cuts=container([frame(REQUEST),frame(REPLY,reverse=True)],endian=endian)
                path=self.source(data);csvpath=self.source(b'time,level\n0,1\n','.csv');guard=Guard(data,cuts[0])
                with patch.object(Path,'open',return_value=guard) as opened:
                    inputs=self.inputs(path,csvpath);opened.assert_not_called()
                    self.advance(inputs,'network-0',1)
                    first=visible(inputs);self.assertEqual(len(first['capture']['events']),1)
                    self.assertEqual(first['capture']['observations'][0]['association_reason'],'response_missing')
                    consumed=guard.tell();self.advance(inputs,'network-0',1)
                    self.assertEqual(guard.tell(),consumed)
                    self.assertEqual(canonical(first),canonical(visible(inputs)))

    def test_mutated_and_appended_future_capture_csv_prefix_bytes_identical(self):
        before=[frame(REQUEST[:20])]
        a,_=pcap(before+[frame(REQUEST[20:],120),frame(REPLY,reverse=True)])
        b,_=pcap(before+[frame(b'future DIFFERENT',120),frame(b'another future',reverse=True)])
        c1=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n2026-01-01T00:00:01Z,1\n','.csv')
        c2=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n"future changed\nrow",99\nextra,3\n','.csv')
        left=self.inputs(self.source(a),c1);right=self.inputs(self.source(b),c2)
        for source,number in [('network-0',1),('process',1),('process',2)]:
            self.advance(left,source,number);self.advance(right,source,number)
            self.assertEqual(canonical(visible(left)),canonical(visible(right)))
        current=visible(left)
        self.assertEqual(current['capture']['events'],[])
        self.assertTrue(current['capture']['pending'])
        self.assertEqual(current['parsed']['events'][0]['value'],0)
        self.assertNotIn('file_sha256',canonical(current).decode())
        self.assertNotEqual(hashlib.sha256(a).hexdigest(),hashlib.sha256(b).hexdigest())

    def test_cross_file_out_of_order_segments_retransmission_and_original_slices(self):
        a,_=pcap([frame(REQUEST[20:],120),frame(REQUEST[:20])])
        b,_=pcapng([frame(REQUEST[:20]),frame(REPLY,reverse=True)])
        inputs=self.inputs([self.source(a),self.source(b)])
        self.advance(inputs,'network-0',1);self.assertEqual(visible(inputs)['capture']['events'],[])
        self.advance(inputs,'network-1',1)
        self.assertEqual(len(visible(inputs)['capture']['events']),1)
        self.advance(inputs,'network-0',2);self.advance(inputs,'network-1',2)
        result=visible(inputs)['capture'];self.assertEqual(len(result['events']),2)
        self.assertTrue(all(obs['association_status']=='matched' for obs in result['observations']))
        request=result['observations'][0];self.assertEqual(request['pdu_hex'],REQUEST.hex())
        self.assertEqual(len(request['source_refs']),3)
        for field in request['field_slices']:
            resolved=inputs.resolve(field['source_ref'],field)
            self.assertEqual(resolved['integrity'],'arrived_record_sha256_verified')
        with self.assertRaisesRegex(ValueError,'not_arrived'):
            inputs.frame(dict(request['source_refs'][0],frame_number=99))

    def test_tcp_conflicting_arrived_bytes_keep_two_real_refs_and_csv_conflicting_values(self):
        data,_=pcap([frame(REQUEST),frame(b'X',110),frame(REPLY,reverse=True)])
        inputs=self.inputs(self.source(data))
        first=self.advance(inputs,'network-0',1)['source_ref'];second=self.advance(inputs,'network-0',2)['source_ref']
        self.advance(inputs,'network-0',3);result=visible(inputs)['capture']
        conflict=next(item for item in result['unsupported'] if 'conflicting_overlap' in item['reason'])
        self.assertEqual(conflict['source_refs'],[first,second])
        for ref in conflict['source_refs']:inputs.resolve(ref)
        self.assertEqual(len(result['events']),1)
        csvpath=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n2026-01-01T00:00:00Z,1\n','.csv')
        inputs=self.inputs(self.source(pcap([])[0]),csvpath)
        for number in range(1,4):self.advance(inputs,'process',number)
        events=visible(inputs)['parsed']['events'];self.assertEqual([e['value'] for e in events],[0,1])
        self.assertTrue(all('duplicate_process_time' in e['quality']['reasons'] for e in events))
        self.assertEqual({e['source_ref']['record_number'] for e in events},{2,3})
        for event in events:inputs.resolve(event['source_ref'])

    def test_unverified_duplicate_claim_cannot_fabricate_second_original(self):
        data,_=pcap([frame(REQUEST)]);inputs=self.inputs(self.source(data))
        accepted=self.advance(inputs,'network-0',1);first=canonical(visible(inputs))
        conflict=self.advance(inputs,'network-0',1,record_sha256='f'*64)
        self.assertEqual(conflict['status'],'conflicting_reference')
        self.assertEqual(conflict['original_ref'],accepted['source_ref'])
        self.assertEqual(conflict['source_ref'],accepted['source_ref'])
        self.assertEqual(conflict['claimed_record_sha256'],'f'*64)
        self.assertEqual(canonical(visible(inputs)),first)
        with self.assertRaisesRegex(ValueError,'hash_mismatch'):
            inputs.resolve(dict(accepted['source_ref'],record_sha256='f'*64))

    def test_csv_bom_quoted_multiline_crlf_and_no_read_ahead(self):
        raw=b'\xef\xbb\xbf"time",level,note\r\n2026-01-01T00:00:00Z,0,"one\r\ntwo"\r\nFUTURE,999,tail\r\n'
        path=self.source(raw,'.csv');guard=Guard(raw,raw.index(b'FUTURE'))
        network=self.source(pcap([])[0])
        with patch.object(Path,'open',return_value=guard):
            inputs=self.inputs(network,path)
            self.advance(inputs,'process',1);self.advance(inputs,'process',2)
            result=visible(inputs)['parsed'];self.assertEqual(len(result['events']),1)
            self.assertEqual(result['events'][0]['value'],0)
            self.assertEqual(result['events'][0]['source_ref']['record_number'],2)
            self.assertEqual(inputs.resolve(result['events'][0]['source_ref'])['note'],'one\r\ntwo')
            self.assertEqual(guard.tell(),raw.index(b'FUTURE'))

    def test_explicit_eof_and_final_gap_source_close_does_not_flush_other_file(self):
        a,_=pcap([frame(REQUEST[:20])]);b,_=pcap([frame(REQUEST[21:],121)])
        inputs=self.inputs([self.source(a),self.source(b)])
        self.advance(inputs,'network-0',1);inputs.finish_source('network-0')
        self.assertTrue(visible(inputs)['capture']['pending'])
        self.advance(inputs,'network-1',1)
        self.assertTrue(any('stream_gap' in item['reason'] for item in visible(inputs)['capture']['pending']))
        self.assertTrue(any('stream_gap' in item['reason'] for item in visible(inputs,final=True)['capture']['unsupported']))
        with self.assertRaisesRegex(ValueError,'source_record_not_next'):self.advance(inputs,'process',2)

    def test_finish_is_pure_prefix_and_explicit_eof_gate_requires_every_source(self):
        data,cuts=pcap([frame(REQUEST),frame(REPLY,reverse=True)])
        path=self.source(data);guard=Guard(data,cuts[0]);process=self.source(b'time,level\n','.csv')
        with patch.object(Path,'open',return_value=guard):
            inputs=self.inputs(path,process)
            self.advance(inputs,'network-0',1)
            cursor=guard.tell();inputs.finish()
            self.assertEqual(guard.tell(),cursor)
            self.assertFalse(inputs.all_sources_exhausted())
        data,_=pcap([frame(REQUEST)])
        inputs=self.inputs(self.source(data),self.source(b'time,level\n','.csv'))
        self.advance(inputs,'network-0',1);inputs.finish_source('network-0')
        self.assertFalse(inputs.all_sources_exhausted())
        self.advance(inputs,'process',1);inputs.finish_source('process')
        self.assertTrue(inputs.all_sources_exhausted())
        with self.assertRaisesRegex(ValueError,'already_exhausted'):self.advance(inputs,'network-0',2)

    def test_retransmission_expands_evidence_without_changing_pdu_identity(self):
        raw,_=pcap([frame(REQUEST),frame(REQUEST)])
        inputs=self.inputs(self.source(raw))
        self.advance(inputs,'network-0',1);first=visible(inputs)['capture']
        self.advance(inputs,'network-0',2);second=visible(inputs)['capture']
        self.assertEqual(first['events'][0]['event_id'],second['events'][0]['event_id'])
        self.assertEqual(len(first['observations'][0]['source_refs']),1)
        self.assertEqual(len(second['observations'][0]['source_refs']),2)

    def test_admission_filter_never_uses_rejected_tcp_segment_or_compresses_csv_ordinals(self):
        raw,_=pcap([frame(REQUEST[:20]),frame(REQUEST[20:],120),frame(REPLY,reverse=True)])
        inputs=self.inputs(self.source(raw))
        refs=[self.advance(inputs,'network-0',number)['source_ref'] for number in range(1,4)]
        self.assertEqual(len(visible(inputs)['capture']['events']),2)
        filtered=inputs.snapshot(allowed_record_refs=[refs[0],refs[2]])
        self.assertEqual(len(filtered['capture']['events']),1)
        self.assertEqual(filtered['capture']['observations'][0]['direction'],'response')
        csvpath=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n2026-01-01T00:00:01Z,99\n2026-01-01T00:00:02Z,1\n','.csv')
        inputs=self.inputs(self.source(pcap([])[0]),csvpath)
        refs=[self.advance(inputs,'process',number)['source_ref'] for number in range(1,5)]
        filtered=inputs.snapshot(allowed_record_refs=[refs[0],refs[1],refs[3]])
        self.assertEqual([event['source_ref']['record_number'] for event in filtered['parsed']['events']],[2,4])
        self.assertEqual([event['value'] for event in filtered['parsed']['events']],[0,1])
        self.assertEqual(filtered['parsed']['filtered_record_numbers'],[3])

    def test_offline_full_scan_is_a_real_future_read_negative_control(self):
        from cpag_core.packet_pipeline import analyze_capture
        raw,cuts=pcap([frame(REQUEST),frame(REPLY,reverse=True)])
        path=self.source(raw)
        with patch.object(Path,'open',return_value=Guard(raw,cuts[0])):
            with self.assertRaisesRegex(AssertionError,'future byte read'):
                analyze_capture(path,synthetic=True)

    def test_fin_reset_and_current_record_resource_failures(self):
        for flags,expected in [(17,2),(4,1)]:
            a,_=pcap([frame(REQUEST),frame(b'',148,flags=flags)]);b,_=pcap([frame(REPLY,reverse=True)])
            inputs=self.inputs([self.source(a),self.source(b)])
            for slot,num in [('network-0',1),('network-0',2),('network-1',1)]:self.advance(inputs,slot,num)
            self.assertEqual(len(visible(inputs)['capture']['events']),expected)
        data,_=pcap([frame(REQUEST)]);inputs=ReplayInputs(self.source(data),self.source(b'time,level\n','.csv'),PROFILE,synthetic=True,packet_limits=Limits(max_frames=1,max_frame_bytes=2))
        self.addCleanup(inputs.close)
        with self.assertRaisesRegex(CaptureError,'frame_byte_limit'):self.advance(inputs,'network-0',1)
