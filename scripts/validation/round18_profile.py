"""Independent raw synthetic inputs and a hand-written arrival schedule for R18."""
from pathlib import Path
import json
import struct
from dual_source_fixtures import make_case
from round17_profile import profile


def at(seconds):return '2026-01-01T00:00:%09.6fZ'%seconds


def fixture(root,*,case='normal',split=True,speed=1,realtime=False):
    root=Path(root)
    network,process,config_path=make_case(root,'missing_response' if case=='missing_response' else 'success')
    config=profile()
    if case=='response_expired':config['clocks']['network']['valid_to']=at(10.5)
    config['replay']={'version':'dual-source-replay-1','simulation_start':at(8),
        'arrival_time_basis':'independently declared generated fixture UTC arrival sequence',
        'warmup_seconds':2,'allowed_lateness_seconds':2,'buffer_seconds':60,
        'max_buffer_records':11000,'max_snapshots':4096,'max_revisions':8192,
        'max_output_bytes':16777216,'speed':speed,'realtime':realtime,'finish_at':at(18)}
    networks=[network]
    if split and case!='missing_response':
        raw=network.read_bytes();end=24+16+struct.unpack_from('<I',raw,32)[0]
        other=root/'response.pcap';other.write_bytes(raw[:24]+raw[end:]);network.write_bytes(raw[:end]);networks.append(other)
    rows=[('process',1,8),('process',2,9),('network-0',1,10),('process',3,10.5)]
    if case!='missing_response':rows.append(('network-1' if split else 'network-0',1 if split else 2,11))
    rows.extend([('process',4,13 if case=='allowed_late' else 12),('process',5,15),('process',6,16)])
    config['replay']['sequence']=[{'source_slot':slot,'record_number':number,'available_at':at(when)} for slot,number,when in rows]
    for slot in [*('network-%d'%i for i in range(len(networks))),'process']:
        config['replay']['sequence'].append({'kind':'source_eof','source_slot':slot,'available_at':at(16)})
    config['replay']['sequence'].append({'kind':'advance','available_at':at(18)})
    config_path.write_text(json.dumps(config,indent=2)+'\n')
    return networks,process,config_path,config


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();n,p,c,_=fixture(args.output)
    print(json.dumps({'network':[str(x) for x in n],'process':str(p),'profile':str(c)}))
