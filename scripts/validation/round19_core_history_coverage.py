"""Independent complete L replay coverage audit over authenticated DAG reads.

This is verification work inside the1800s chain, not an interactive query.
No predictor/ReplayCore/reference collector supplies the expected raw identities.
"""
import hashlib
import json
from pathlib import Path
import resource
import sys
import time
from datetime import datetime,timezone

from round19_core_oracle import canonical,pcap_records,csv_records

VERSION='core-ever-observed-coverage-1'
MAX_LEDGER_BYTES=128*1024**2
MAX_NODE_READS=8_000_000
MAX_DEPTH=64
MAX_RECORD_BYTES=8*1024**2


def instant(value):
    if not isinstance(value,str):raise ValueError('coverage_UTC_time_required')
    parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:raise ValueError('coverage_UTC_time_required')
    return parsed.astimezone(timezone.utc)


def owned(value):
    total=sys.getsizeof(value)
    if isinstance(value,(tuple,list)):total+=sum(owned(child) for child in value)
    elif isinstance(value,dict):total+=sum(owned(k)+owned(v) for k,v in value.items())
    return total


class Ledger:
    def __init__(self,limit=MAX_LEDGER_BYTES):self.limit=limit;self.bytes=0;self.peak=0
    def add(self,collection,key,value=None):
        if key in collection:return False
        before=sys.getsizeof(collection)
        if isinstance(collection,set):collection.add(key)
        else:collection[key]=value
        self.bytes+=sys.getsizeof(collection)-before+owned(key)+(0 if isinstance(collection,set) else owned(value))+64
        self.peak=max(self.peak,self.bytes)
        if self.bytes>self.limit:raise ValueError('coverage_ledger_byte_limit')
        return True


def raw_expectations(networks,process,profile,ledger):
    result={};files={}
    for slot,path in enumerate(networks):
        parsed=pcap_records(path);files['network-'+str(slot)]=parsed['file_sha256']
        for number,row in enumerate(parsed['records'],1):
            ledger.add(result,('network-'+str(slot),number,row['record_sha256']),('network',row['raw_time'],None,False))
    parsed=csv_records(process);files['process']=parsed['file_sha256'];time_column=profile['process']['timestamp_column']
    columns=[name for name in parsed['header'] if name!=time_column]
    if len(columns)!=1:raise ValueError('coverage_fixed_one_signal_fixture_required')
    for number,row in enumerate(parsed['records'],1):
        values=dict(zip(parsed['header'],row['values']))
        ledger.add(result,('process',number,row['record_sha256']),('process',None if number==1 else values[time_column],columns[0],number==1))
    sequence={}
    for index,step in enumerate(profile['replay']['sequence'],1):
        if 'record_number' not in step:continue
        key=(step['source_slot'],step['record_number'])
        if key in sequence:raise ValueError('coverage_fixed_unique_arrival_fixture_required')
        ledger.add(sequence,key,(index,step['available_at']))
    if {(slot,number) for slot,number,digest in result}!=set(sequence):raise ValueError('coverage_arrival_inventory_not_complete')
    return result,sequence,files


class Auditor:
    def __init__(self,reader,expected,sequence,ledger,deadline):
        self.reader=reader;self.expected=expected;self.sequence=sequence;self.ledger=ledger;self.deadline=deadline
        self.reads=0;self.references={};self.array_nodes=set();self.metrics={};self.metric_units={};self.admitted=set();self.present={}
    def node(self,ref):
        self.reads+=1
        if self.reads>MAX_NODE_READS:raise ValueError('coverage_node_read_limit')
        if time.monotonic()>self.deadline:raise TimeoutError('coverage_chain_deadline')
        node=self.reader._node(ref)
        if node[0]=='scalar' and node[2]>MAX_RECORD_BYTES:raise ValueError('coverage_scalar_byte_limit')
        return node
    def obj(self,ref,maximum=None):
        node=self.node(ref)
        if node[0]!='dict':raise ValueError('coverage_dictionary_required')
        if maximum is not None and node[2]>maximum:raise ValueError('coverage_record_byte_limit')
        return node[1]
    def scalar(self,ref):
        node=self.node(ref)
        if node[0]!='scalar':raise ValueError('coverage_scalar_required')
        return node[1]
    def array(self,ref,*,dedup=False):
        stack=[(ref,0)]
        while stack:
            current,depth=stack.pop()
            if depth>MAX_DEPTH:raise ValueError('coverage_depth_limit')
            if dedup and not self.ledger.add(self.array_nodes,current):continue
            node=self.node(current)
            if node[0]=='array_branch':stack.extend((child,depth+1) for child in reversed(node[1]))
            elif node[0]=='array_leaf':yield from node[1]
            else:raise ValueError('coverage_array_required')
    def reference(self,ref,*,observed):
        if ref not in self.references:
            value={name:self.scalar(child) for name,child in self.obj(ref,MAX_RECORD_BYTES).items()}
            if set(value)!={'source_slot','record_sha256','frame_number','record_number','column','raw_time'}:raise ValueError('coverage_reference_shape')
            frame=value['frame_number'];record=value['record_number'];number=frame if frame is not None else record
            if type(number) is not int or number<1 or (frame is None)==(record is None):raise ValueError('coverage_reference_ordinal')
            key=(value['source_slot'],number,value['record_sha256'])
            if key not in self.expected:raise ValueError('coverage_reference_not_in_originals')
            self.ledger.add(self.references,ref,(key,value['column'],value['raw_time']))
        key,column,raw_time=self.references[ref];kind,expected_time,signal,header=self.expected[key]
        if kind=='network':
            if column is not None or raw_time!=expected_time:raise ValueError('coverage_network_original_metadata_mismatch')
        elif observed:
            if header or column!=signal or raw_time!=expected_time:raise ValueError('coverage_process_original_metadata_mismatch')
        elif column is not None or raw_time is not None:raise ValueError('coverage_raw_admission_metadata_mismatch')
        return key
    def run(self):
        last=self.reader.run_manifest['counts']['snapshots']-1
        seen=self.reader._select('history/snapshots',[last,'analysis','replay','available_record_refs'])
        for ref in self.array(seen):
            key=self.reference(ref,observed=False)
            if not self.ledger.add(self.admitted,key):raise ValueError('coverage_duplicate_admitted_original')
        if self.admitted!=set(self.expected):raise ValueError('coverage_missing_admitted_original')
        samples=self.reader._select('metrics.json',['event_latency','samples'])
        for ref in self.array(samples):
            value=self.obj(ref,MAX_RECORD_BYTES);identity=self.scalar(value['event_id']);available=self.scalar(value['first_available_at'])
            refs=list(self.array(value['evidence_refs']))
            if len(refs)!=1:raise ValueError('coverage_fixed_one_event_per_record_required')
            key=self.reference(refs[0],observed=True);sequence,expected_time=self.sequence[key[:2]]
            if instant(available)<instant(expected_time):raise ValueError('coverage_latency_before_original_arrival')
            if not self.ledger.add(self.metrics,identity,(key,available,sequence)):raise ValueError('coverage_duplicate_latency_event')
            if not self.ledger.add(self.metric_units,key,identity):raise ValueError('coverage_duplicate_observed_original')
        data={key for key,value in self.expected.items() if not value[3]}
        if set(self.metric_units)!=data:raise ValueError('coverage_missing_ever_observed_metric')
        denominator=self.scalar(self.reader._select('metrics.json',['event_latency','denominator_total_events']))
        if type(denominator) is not int or denominator!=len(data):raise ValueError('coverage_event_denominator_mismatch')
        snapshots=self.reader._select('history/snapshots',[])
        position=0
        for ref in self.array(snapshots):
            snapshot=self.obj(ref);number=self.scalar(snapshot['snapshot_number']);available=self.scalar(snapshot['available_at']);arrival=self.scalar(snapshot['arrival_seq'])
            if type(number) is not int or number!=position or type(arrival) is not int:raise ValueError('coverage_snapshot_position')
            for event_ref in self.array(snapshot['events'],dedup=True):
                event=self.obj(event_ref,MAX_RECORD_BYTES);identity=self.scalar(event['event_id'])
                if identity not in self.metrics:continue
                key=self.reference(event['source_ref'],observed=True);expected_key,first,sequence=self.metrics[identity]
                if key!=expected_key:raise ValueError('coverage_history_event_original_mismatch')
                if arrival<sequence:raise ValueError('coverage_future_observation')
                if identity not in self.present:
                    if instant(available)!=instant(first):raise ValueError('coverage_latency_not_actual_first_history_presence')
                    self.ledger.add(self.present,identity,(number,available,arrival))
            position+=1
        if position!=last+1:raise ValueError('coverage_history_snapshot_count')
        if set(self.present)!=set(self.metrics):raise ValueError('coverage_missing_actual_history_observation')
        expired=self.reader.page('history/snapshots',path=[last,'analysis','replay','expired_record_refs'],offset=0,limit=1,max_bytes=MAX_RECORD_BYTES)['total']
        return {'version':VERSION,'status':'passed','raw_original_units':len(self.expected),'csv_headers_admitted_not_observations':sum(v[3] for v in self.expected.values()),
            'admitted_units':len(self.admitted),'ever_observed_data_units':len(data),'actual_history_events_proven':len(self.present),
            'expired_units':expired,'snapshot_count':position,'missing_or_extra_units':0,
            'membership_sha256':hashlib.sha256(canonical(sorted(self.admitted))).hexdigest(),
            'event_membership_sha256':hashlib.sha256(canonical(sorted((key,self.metric_units[key]) for key in data))).hexdigest(),
            'node_reads':self.reads,'unique_shared_event_array_nodes':len(self.array_nodes),
            'ledger_peak_owned_bytes':self.ledger.peak,'ledger_byte_limit':self.ledger.limit,'node_read_limit':MAX_NODE_READS,
            'scope':'complete independent original/admission/history-presence audit; not an interactive query or substitute for full source verification'}


def audit_coverage(core,root,networks,process,profile_path,approval,key,deadline,*,ledger_limit=MAX_LEDGER_BYTES,report=None):
    began=time.monotonic();cpu=time.process_time();ledger=Ledger(ledger_limit)
    report={} if report is None else report;report.update(version=VERSION,status='in_progress');auditor=None
    try:
        profile=json.loads(Path(profile_path).read_text());expected,sequence,files=raw_expectations(networks,process,profile,ledger)
        with core.open_reader(root,deadline=deadline,approval=approval,authority_key=key) as reader:
            auditor=Auditor(reader,expected,sequence,ledger,deadline);result=auditor.run()
        # Close the audit against a fresh complete physical inventory/permit check.
        core.check_approval(root,approval,key)
        result.update(raw_file_sha256=files);report.update(result)
        return report
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__,reason=str(error),
            node_reads=auditor.reads if auditor else None,admitted_units=len(auditor.admitted) if auditor else None,
            actual_history_events_proven=len(auditor.present) if auditor else None,
            ledger_peak_owned_bytes=ledger.peak,ledger_byte_limit=ledger.limit)
        raise
    finally:report.update(wall_seconds=time.monotonic()-began,cpu_seconds=time.process_time()-cpu)
