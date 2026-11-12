#!/usr/bin/env python3
"""Independent exact byte/record boundaries, not a density/throughput benchmark.

One real supported synthetic CIP exchange plus explicitly unsupported Ethernet
frames used as byte occupancy. Unknown frames must remain quality evidence and
must never become replacement protocol events. CSV extra columns are unprofiled.
"""
import argparse
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import struct
from round19_scale_fixture import message,frame,at
from round17_profile import profile

MIB=1024**2

def capture(path,size,ordinal,payload):
    with path.open('xb') as f:
        f.write(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiiII',2,4,0,0,262144,1))
        count=0
        def record(raw,micros):
            nonlocal count
            sec,frac=divmod(micros,1000000)
            f.write(struct.pack('<IIII',1767225600+sec,frac,len(raw),len(raw))+raw);count+=1
        if payload:record(payload,10000000+ordinal*10000)
        while f.tell()<size:
            remaining=size-f.tell()
            take=min(262144,remaining-16)
            if remaining-(take+16) in range(1,30):take-=30
            if take<14:raise ValueError('cannot represent exact byte boundary')
            raw=bytes([ordinal])*12+b'\x88\xb5'+bytes([ordinal])*(take-14)
            record(raw,12000000+count)
    assert path.stat().st_size==size
    return count

def generate(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=False)
    context=(1).to_bytes(8,'little')
    request=frame(message(bytes.fromhex('10032001240130010100'),context),100)
    response=frame(message(bytes.fromhex('90000000'),context),100,True)
    sizes=[64*MIB,32*MIB,16*MIB,16*MIB];counts=[]
    for i,size in enumerate(sizes):counts.append(capture(root/f'network-{i}.pcap',size,i,[request,response,None,None][i]))
    header='time,pump,'+','.join('unused'+str(i) for i in range(14))+'\n'
    rows=[]
    for i in range(10000):rows.append(at(9000000+i*1000)+','+str(int(i>=1100))+','+','*13+'\n')
    remaining=8*MIB-len(header.encode())-sum(len(x.encode()) for x in rows)
    base,extra=divmod(remaining,10000)
    with (root/'process.csv').open('x') as f:
        f.write(header)
        for i,row in enumerate(rows):
            cut=row.index(',',row.index(',')+1)+1
            f.write(row[:cut]+'x'*(base+int(i<extra))+row[cut:])
    assert (root/'process.csv').stat().st_size==8*MIB
    config=profile();config['capacity_profile']='engineering-capacity-1'
    for clock in config['clocks'].values():clock['valid_to']=at(86399000000)
    for mapping in config['mappings']:mapping['valid_to']=at(86399000000)
    (root/'profile.json').write_text(json.dumps(config,separators=(',',':'))+'\n')
    case={'schema_version':'r19-byte-boundary-case-1','id':'four-captures-128MiB-csv8MiB-10000rows-16cols',
          'scale':'byte-boundary','mode':'dual_source','networks':[f'network-{i}.pcap' for i in range(4)],
          'process':'process.csv','profile':'profile.json','repetition':1,'cache_condition':'unverified_cold'}
    (root/'case.json').write_text(json.dumps(case,indent=2)+'\n')
    oracle={'network_bytes':sizes,'network_total_bytes':128*MIB,'frames':counts,'csv_bytes':8*MIB,
        'csv_logical_records':10000,'csv_columns':16,'expected_network_events':2,'expected_operations':1,
        'expected_changes':1,'expected_candidates':1,'expected_candidate_state':'unknown','required_unknown_reason':'unsupported_network_records_present','quality':'unsupported Ethernet records explicitly retained',
        'forbidden_conclusion':'no protocol coverage or capacity throughput claim from padding; no replacement events'}
    (root/'oracle.json').write_text(json.dumps(oracle,indent=2)+'\n');return oracle

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True)
    print(json.dumps(generate(p.parse_args().output)))
