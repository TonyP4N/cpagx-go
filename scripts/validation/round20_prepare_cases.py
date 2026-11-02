#!/usr/bin/env python3
"""Prepare bounded new synthetic UI cases through actual public service APIs.

Only tiny fixtures run. Existing offline/replay/restored/S100 results are reused;
raw inputs, credentials and complete responses remain in external private output.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import struct
import time
import round19_formal_service_acceptance as formal
from dual_source_fixtures import make_case, frame, message, BASE
r = formal.r


def multi_device(root):
    networks, process, profile, config = formal.small_inputs(root,'success','offline')
    config['process']['columns']['valve'] = dict(config['process']['columns']['pump'], tag='valve_state',asset_id='synthetic-valve')
    config['mappings'].append(dict(config['mappings'][0],rule_id='set-valve-one',destination_ip='192.0.2.3',tag='valve_state',asset_id='synthetic-valve'))
    process.write_text('time,pump,valve\n2026-01-01T00:00:09Z,0,0\n2026-01-01T00:00:10.5Z,0,0\n2026-01-01T00:00:12Z,1,1\n2026-01-01T00:00:15Z,1,1\n2026-01-01T00:00:16Z,1,1\n')
    records=[]
    for number,address in enumerate((bytes([192,0,2,2]),bytes([192,0,2,3]))):
        context=(number+1).to_bytes(8,'little')
        for when,reverse,payload in [(10+number*.1,False,bytes.fromhex('10032001240130010100')),(11+number*.1,True,bytes.fromhex('90000000'))]:
            wire=bytearray(frame(message(payload,context=context),reverse=reverse))
            wire[26 if reverse else 30:30 if reverse else 34]=address
            records.append((when,bytes(wire)))
    raw=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiiII',2,4,0,0,65535,1)
    for when,wire in sorted(records):
        raw+=struct.pack('<IIII',BASE+int(when),round((when-int(when))*1e6),len(wire),len(wire))+wire
    networks[0].write_bytes(raw);profile.write_text(json.dumps(config,indent=2)+'\n')
    return networks,process,profile,config


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cases',default='multi-device,out_of_order,no_change,empty-process,replay-limit,too_late')
    args=parser.parse_args();state=json.loads(args.state.read_text());work=args.output.resolve()
    work.mkdir(parents=True,exist_ok=False,mode=0o700)
    client=formal.MeasuredClient(state['url']);client.expect('POST','/api/v3/session',{'username':state['username'],'password':state['password']})
    report={'status':'running','scope':'tiny synthetic UI fixtures only','checks':{},'cases':{}}
    def save():formal.write(work/'report.json',report)
    for case in args.cases.split(','):
        mode='replay' if case in ('replay-limit','too_late') else 'offline'
        if case=='multi-device':networks,process,profile,config=multi_device(work/case)
        else:networks,process,profile,config=formal.small_inputs(work/case,case if case in ('out_of_order','no_change','too_late','ambiguous','error','missing_response') else 'normal' if mode=='replay' else 'success',mode)
        if case=='empty-process':process.write_text('time,pump\n')
        if case=='replay-limit':
            config['replay']['max_snapshots']=1;profile.write_text(json.dumps(config,indent=2)+'\n')
        dataset=client.expect('POST','/api/v3/datasets',{'name':'R20 UI '+case,'source_kind':'synthetic','source':'tiny generated acceptance fixture','batch':'r20-ui','authorization_ref':'repository synthetic fixture only'},code=201)['dataset']['id']
        for number,network in enumerate(networks):r.upload(client,dataset,'network',network,case+'-network-'+str(number))
        r.upload(client,dataset,'process',process,case+'-process')
        intake=client.expect('POST',f'/api/v3/datasets/{dataset}/configs',{'kind':'intake','document':formal.intake(dataset)},code=201)['config']['id']
        preflight=client.expect('POST',f'/api/v3/datasets/{dataset}/preflight',{'config_version_id':intake})
        dual=client.expect('POST',f'/api/v3/datasets/{dataset}/configs',{'kind':'dual','document':config},code=201)['config']['id']
        run=client.expect('POST','/api/v3/runs',{'dataset_id':dataset,'config_version_id':dual,'preflight_id':preflight['preflight_id'],'mode':'dual_source_replay' if mode=='replay' else 'dual_source'},code=201)['run']['id']
        began=time.monotonic()
        while time.monotonic()-began<180:
            status=client.expect('GET',f'/api/v3/runs/{run}')['run']
            if status['state'] in ('succeeded','failed','cancelled'):break
            time.sleep(.3)
        else:raise RuntimeError('tiny_case_timeout:'+case)
        expected='failed' if case in ('empty-process','replay-limit') else 'succeeded'
        report['cases'][case]={'run_id':run,'dataset_id':dataset,'state':status['state'],'expected':expected,'attempt':status['attempt']}
        formal.write(work/(case+'-run.json'),status);save()
        if status['state']!=expected:raise RuntimeError('tiny_case_state_mismatch:'+case)
    report['status']='passed';save()
    state.setdefault('ui_cases',{}).update(report['cases'])
    args.state.write_text(json.dumps(state,indent=2)+'\n');args.state.chmod(0o600)
    print(json.dumps(report))
if __name__=='__main__':main()
