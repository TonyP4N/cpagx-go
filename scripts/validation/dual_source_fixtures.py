"""Hand-built synthetic scenarios; does not invoke decoding or read analysis/expected outputs."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/packets'))
from test_packet_protocol import message, frame
from test_packet_envelope import block
BASE=1767225600


def make_case(directory, name='success', capture_format='pcap'):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    config=json.loads((ROOT/'profiles/dual-source-synthetic.json').read_text())
    requests=[] if name=='orphan_change' else [10]
    if name=='ambiguous':requests=[10,10.2]
    records=[];request_seq=100;response_seq=100
    for i,when in enumerate(requests):
        context=(i+1).to_bytes(8,'little')
        request=message(bytes.fromhex('10032001240130010100'),context=context)
        records.append((when,frame(request,seq=request_seq)));request_seq+=len(request)
        if name!='missing_response':
            status='05' if name=='error' else '00'
            response=message(bytes.fromhex('9000'+status+'00'),context=context)
            records.append((when+1,frame(response,seq=response_seq,reverse=True)));response_seq+=len(response)
    if not records:
        records=[(11,frame(message(bytes.fromhex('90000000')),reverse=True))]
    rows=[(9,'0'),(10.5,'0'),(12,'1'),(15,'1'),(16,'1')]
    if name=='no_change':rows=[(t,'0') for t,_ in rows]
    if name=='missing_value':rows[1]=(10.5,'')
    if name=='sampling_gap':rows=[(9,'0'),(16,'1')]
    if name in ('offset','disjoint'):rows=[(t+100,v) for t,v in rows]
    if name=='offset':config['clocks']['process']['offset_seconds']=-100
    if name=='clock_unknown':config['clocks']['process']['basis']=None
    if name=='uncertain_time':config['clocks']['network']['uncertainty_seconds']=2
    if name=='mapping_missing':config['mappings']=[]
    if name=='mapping_conflict':config['mappings'].append({**config['mappings'][0],'rule_id':'conflicting-map'})
    if name=='out_of_order':rows=rows[::-1];records=records[::-1]
    capture=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiiII',2,4,0,0,65535,1)
    for when,raw in records:
        seconds=int(when);micros=round((when-seconds)*1000000)
        capture+=struct.pack('<IIII',BASE+seconds,micros,len(raw),len(raw))+raw
    if capture_format=='pcapng':
        capture=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
        for when,raw in records:
            ticks=(BASE+int(when))*1000000+round((when-int(when))*1000000)
            capture+=block(6,struct.pack('<IIIII',0,ticks>>32,ticks & 0xffffffff,len(raw),len(raw))+raw+b'\0'*(-len(raw)%4))
    (directory/'network.pcap').write_bytes(capture)
    (directory/'process.csv').write_text('time,pump\n'+''.join(
        f'{datetime.fromtimestamp(BASE+t,timezone.utc).isoformat().replace("+00:00","Z")},{value}\n' for t,value in rows))
    (directory/'profile.json').write_text(json.dumps(config,indent=2)+'\n')
    return directory/'network.pcap',directory/'process.csv',directory/'profile.json'
