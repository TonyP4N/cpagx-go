"""Independent ledger negatives plus a real expiry/history equivalence case."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/validation'),str(ROOT/'services/analysis/src')]
from round19_core_history_coverage import Ledger,Auditor,raw_expectations,audit_coverage
from round19_core_oracle import canonical,compare_values
from round19_core_small import inputs,legacy_replay,compare_replay,wire,write,rule
from round18_profile import at
from cpag_core import shared_export as core


class TreeReader:
    """Tiny in-memory shape fixture for audit logic, not a core verifier."""
    def __init__(self,snapshots,metrics):
        self.nodes={};self.roots={'history/snapshots':self.encode(snapshots),'metrics.json':self.encode(metrics)}
        self.run_manifest={'counts':{'snapshots':len(snapshots)}}
    def encode(self,value):
        ref=hashlib.sha256(canonical(value)).hexdigest()
        if isinstance(value,dict):kind='dict';body={k:self.encode(v) for k,v in value.items()};items=len(value)
        elif isinstance(value,list):kind='array_leaf';body=[self.encode(v) for v in value];items=len(value)
        else:kind='scalar';body=value;items=0
        self.nodes[ref]=(kind,body,len(canonical(value)),items,b'',0);return ref
    def _node(self,ref):return self.nodes[ref]
    def _select(self,name,path):
        ref=self.roots[name]
        for component in path:ref=self.nodes[ref][1][component]
        return ref
    def page(self,name,*,path,offset,limit,max_bytes):
        body=self.nodes[self._select(name,path)][1]
        return {'total':len(body),'returned':min(limit,max(0,len(body)-offset))}


class CoverageLedgerTests(unittest.TestCase):
    def fixture(self,root):
        record=struct.pack('<IIII',1767225610,0,6,6)+b'abcdef'
        network=root/'network.pcap';network.write_bytes(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiiII',2,4,0,0,65535,1)+record)
        header=b'time,pump\n';row=b'2026-01-01T00:00:09Z,1\n';process=root/'process.csv';process.write_bytes(header+row)
        def ref(slot,number,digest,frame=False):return {'source_slot':slot,'record_sha256':digest,'frame_number':number if frame else None,'record_number':None if frame else number,'column':None,'raw_time':'1767225610000000' if frame else None}
        h=ref('process',1,hashlib.sha256(header).hexdigest());p=ref('process',2,hashlib.sha256(row).hexdigest());n=ref('network-0',1,hashlib.sha256(record).hexdigest(),True)
        observed=copy.deepcopy(p);observed.update(column='pump',raw_time='2026-01-01T00:00:09Z')
        pe={'event_id':'process-event','source_ref':observed};ne={'event_id':'network-event','source_ref':n}
        snapshots=[{'snapshot_number':i,'available_at':at(8+i),'arrival_seq':i+1,'events':events,
            'analysis':{'replay':{'available_record_refs':[h,p,n],'expired_record_refs':[]}}} for i,events in enumerate(([],[pe],[pe,ne]))]
        metrics={'event_latency':{'denominator_total_events':2,'samples':[
            {'event_id':'process-event','first_available_at':at(9),'evidence_refs':[observed]},
            {'event_id':'network-event','first_available_at':at(10),'evidence_refs':[n]}]}}
        profile={'process':{'timestamp_column':'time'},'replay':{'sequence':[
            {'source_slot':'process','record_number':1,'available_at':at(8)},
            {'source_slot':'process','record_number':2,'available_at':at(9)},
            {'source_slot':'network-0','record_number':1,'available_at':at(10)}]}}
        return network,process,profile,snapshots,metrics
    def run_model(self,root,change=None,limit=128*1024**2):
        network,process,profile,snapshots,metrics=self.fixture(root)
        if change:change(snapshots,metrics)
        ledger=Ledger(limit);expected,sequence,_=raw_expectations([network],process,profile,ledger)
        return Auditor(TreeReader(snapshots,metrics),expected,sequence,ledger,time.monotonic()+10).run()
    def test_every_original_is_admitted_and_present_in_actual_history(self):
        with tempfile.TemporaryDirectory() as directory:
            result=self.run_model(Path(directory));self.assertEqual(result['admitted_units'],3)
            self.assertEqual(result['actual_history_events_proven'],2);self.assertEqual(result['csv_headers_admitted_not_observations'],1)
    def test_missing_admit_observation_wrong_hash_future_latency_and_duplicates_refuse(self):
        changes=[
            lambda s,m:s[-1]['analysis']['replay']['available_record_refs'].pop(),
            lambda s,m:s[-1]['events'].pop(),
            lambda s,m:m['event_latency']['samples'][0]['evidence_refs'][0].update(record_sha256='0'*64),
            lambda s,m:s[-1].update(arrival_seq=1),
            lambda s,m:m['event_latency']['samples'][0].update(first_available_at=at(8)),
            lambda s,m:m['event_latency']['samples'][0].update(first_available_at=at(9.5)),
            lambda s,m:m['event_latency']['samples'].append(copy.deepcopy(m['event_latency']['samples'][0])),
            lambda s,m:m['event_latency'].update(denominator_total_events=3)]
        for index,change in enumerate(changes):
            with self.subTest(index=index),tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):self.run_model(Path(directory),change)
    def test_ledger_budget_is_an_explicit_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError,'ledger_byte_limit'):self.run_model(Path(directory),limit=64)
    def test_real_expiry_preserves_old_new_full_history_and_original_coverage(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();networks,process,profile,config=inputs(root/'inputs','normal','replay')
            process.write_bytes(process.read_bytes()+(at(30)+',1\n').encode())
            steps=[s for s in config['replay']['sequence'] if s.get('kind') not in ('source_eof','advance')]
            steps.append({'source_slot':'process','record_number':7,'available_at':at(30.1)})
            steps.extend({'kind':'source_eof','source_slot':slot,'available_at':at(31)} for slot in ('network-0','network-1','process'))
            steps.append({'kind':'advance','available_at':at(59)});config['replay'].update(sequence=steps,finish_at=at(59),buffer_seconds=20);write(profile,config)
            legacy=legacy_replay(networks,process,config);output=root/'artifact'
            core.export_task(networks,process,profile,output,run_id='expiry-coverage',mode='replay',deadline=time.monotonic()+30)
            key=os.urandom(32);approval=core.issue_approval(output,key,deadline=time.monotonic()+30)
            with core.open_reader(output,approval=approval,authority_key=key) as reader:
                self.assertTrue(compare_values(legacy['analysis'],reader.get('analysis.json'))['equal'])
                comparison=compare_replay(legacy,reader.get('history/snapshots'),reader.get('history/revisions'))
                self.assertTrue(all(row['equal'] for row in comparison['path_comparisons']))
                self.assertEqual(len(reader.get('analysis.json',path=['process'])),2)
                self.assertTrue(compare_values(legacy['metrics'],reader.get('metrics.json'))['equal'])
                from cpag_core.dual_source_export import event_graph
                projection=wire(event_graph(legacy['analysis'],replay=True));graph=reader.get('graph.json')
                self.assertTrue(compare_values(projection['events.json'],reader.get('events.json'))['equal'])
                self.assertTrue(compare_values(projection['graph.json'],graph,allowed=[rule('/graph_id',projection['graph.json']['graph_id'],graph['graph_id'],'registered complete container identity')])['equal'])
            result=audit_coverage(core,output,networks,process,profile,approval,key,time.monotonic()+30)
            self.assertEqual(result['admitted_units'],9);self.assertEqual(result['actual_history_events_proven'],8)
            self.assertEqual(result['expired_units'],8)


if __name__=='__main__':unittest.main()
