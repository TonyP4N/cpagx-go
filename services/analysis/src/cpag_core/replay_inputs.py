"""Arrival-only raw adapters. No constructor scan, prefetch, or full-file digest.

Snapshots recompute only bounded already-arrived buffers through the shared R17
packet/CSV adapters. This deliberately trades throughput for inspectability;
R19 capacity/performance is not claimed. Full-original integrity belongs to the
outer run binding and is never a prefix reference or prefix fingerprint.
"""
from copy import deepcopy
import csv
import hashlib
import io
from pathlib import Path
import struct
from types import SimpleNamespace

from .packet_pipeline import analyze_prepared_frames, checksum_evidence, StreamLimits
from .parsers import parse_process, ProcessLimits
from .parsers.packet_envelope import CaptureError, Limits, _transport
from .pipeline import canonical, fingerprint


def sha(data):
    return hashlib.sha256(data).hexdigest()


class _Cursor:
    def __init__(self, path, slot, kind, owner):
        self.path, self.slot, self.kind, self.owner = Path(path), slot, kind, owner
        self.stream = None
        self.offset = 0
        self.number = 0
        self.endian = None
        self.container = None
        self.headers = b''
        self.interfaces = []
        self.snaplen = None
        self.resolution = None
        self.eof = False

    def read(self, count):
        if self.stream is None:
            self.stream = self.path.open('rb', buffering=0)
        data = self.stream.read(count)
        self.offset += len(data)
        self.owner._account(self.kind, len(data))
        return data

    def exact(self, count, reason):
        if count < 0 or count > self.owner.packet_limits.max_frame_bytes + 64:
            raise CaptureError('record_byte_limit')
        data = self.read(count)
        if len(data) != count:
            raise CaptureError(reason)
        return data

    def block(self, first=None):
        start = self.offset - len(first or b'')
        prefix = (first or b'') + self.exact(8-len(first or b''), 'truncated_block')
        if prefix[:4] == b'\x0a\x0d\x0d\x0a':
            if self.endian is not None:
                raise CaptureError('multiple_sections_unsupported')
            bom = self.exact(4, 'truncated_block')
            self.endian = {b'\x4d\x3c\x2b\x1a':'<', b'\x1a\x2b\x3c\x4d':'>'}.get(bom)
            if self.endian is None:
                raise CaptureError('invalid_byte_order')
            prefix += bom
        kind, length = struct.unpack_from(self.endian+'II', prefix)
        if length < 12 or length % 4 or length < len(prefix):
            raise CaptureError('invalid_block_length')
        raw = prefix+self.exact(length-len(prefix), 'truncated_block')
        if struct.unpack_from(self.endian+'I', raw, length-4)[0] != length:
            raise CaptureError('block_length_mismatch')
        return start, kind, raw

    def packet(self):
        if self.container is None:
            magic = self.exact(4, 'truncated_capture_header')
            magics = {b'\xd4\xc3\xb2\xa1':('<',1000000), b'\xa1\xb2\xc3\xd4':('>',1000000),
                      b'\x4d\x3c\xb2\xa1':('<',1000000000), b'\xa1\xb2\x3c\x4d':('>',1000000000)}
            if magic in magics:
                self.container = 'pcap';self.endian,self.resolution = magics[magic]
                header = magic+self.exact(20, 'truncated_pcap_header')
                major,minor,zone,accuracy,snaplen,link = struct.unpack_from(self.endian+'HHiiII',header,4)
                if (major,minor)!=(2,4) or link!=1 or not snaplen or zone or accuracy:
                    raise CaptureError('unsupported_pcap_header_or_linktype')
                self.snaplen=snaplen;self.headers=header
            elif magic == b'\x0a\x0d\x0d\x0a':
                self.container='pcapng'
                _,kind,raw=self.block(magic)
                if len(raw)!=28 or struct.unpack_from(self.endian+'HHq',raw,12)!=(1,0,-1):
                    raise CaptureError('unsupported_section_header')
                self.headers=raw
            else:
                raise CaptureError('unsupported_capture_magic')
        if self.container=='pcap':
            start=self.offset;header=self.read(16)
            if not header:
                self.eof=True;return None
            if len(header)!=16:raise CaptureError('truncated_record_header')
            seconds,fraction,captured,original=struct.unpack(self.endian+'IIII',header)
            if fraction>=self.resolution or captured>self.snaplen:
                raise CaptureError('invalid_record_header')
            if captured>self.owner.packet_limits.max_frame_bytes:raise CaptureError('frame_byte_limit')
            if captured>original:raise CaptureError('captured_length_exceeds_original')
            raw=self.exact(captured,'truncated_frame');record=header+raw
            timestamp=seconds*self.resolution+fraction;offset=start+16
        else:
            while True:
                first=self.read(4)
                if not first:self.eof=True;return None
                if len(first)!=4:raise CaptureError('truncated_block')
                start,kind,record=self.block(first)
                if kind==1:
                    if self.interfaces:raise CaptureError('multiple_interfaces_unsupported')
                    if len(record)!=20:raise CaptureError('interface_options_unsupported')
                    link,reserved,snaplen=struct.unpack_from(self.endian+'HHI',record,8)
                    if link!=1 or reserved or not snaplen:raise CaptureError('unsupported_interface_or_linktype')
                    self.interfaces.append(snaplen);self.headers+=record;continue
                if kind!=6:raise CaptureError('unsupported_block_type')
                if len(record)<32:raise CaptureError('short_packet_block')
                interface,high,low,captured,original=struct.unpack_from(self.endian+'IIIII',record,8)
                if interface>=len(self.interfaces) or captured>self.interfaces[interface]:
                    raise CaptureError('invalid_packet_interface_or_snaplen')
                if captured>self.owner.packet_limits.max_frame_bytes:raise CaptureError('frame_byte_limit')
                if captured>original:raise CaptureError('captured_length_exceeds_original')
                if len(record)!=32+((captured+3)&~3):raise CaptureError('packet_options_or_invalid_length')
                raw=record[28:28+captured];timestamp=(high<<32)|low
                self.resolution=1000000;offset=start+28;break
        self.number+=1
        ref={'source_slot':self.slot,'record_sha256':sha(record),'frame_number':self.number,
             'record_number':None,'column':None,'raw_time':str(timestamp)}
        frame={'transport':_transport(raw),'source_ref':ref,'frame_number':self.number,
               'byte_offset':offset,'captured_length':captured,'original_length':original,
               'raw_timestamp':timestamp,'ticks_per_second':self.resolution,'frame_sha256':sha(raw),
               'quality':['protocol_semantics_unsupported']+(['capture_truncated'] if captured<original else [])}
        return {'source_ref':ref,'raw':record,'frame_raw':raw,'frame':frame,'byte_offset':start,
                'length':len(record),'header_sha256':sha(self.headers),'kind':'network'}

    def csv_record(self):
        start=self.offset;raw=bytearray();quoted=False;quote_pending=False;field_start=True
        while True:
            value=self.read(1)
            if not value:
                self.eof=True
                if not raw:return None
                if quoted and not quote_pending:raise ValueError('invalid_or_truncated_csv:unterminated_quote')
                break
            if self.number==0 and not raw and value==b'\xef':
                leading=value+self.exact(2,'invalid_utf8')
                raw+=leading
                field_start=leading==b'\xef\xbb\xbf'
                continue
            raw+=value
            if len(raw)>self.owner.process_limits.max_bytes:raise ValueError('process_byte_limit')
            if quoted:
                if quote_pending:
                    if value==b'"':quote_pending=False;continue
                    quoted=False;quote_pending=False
                    if value not in (b',',b'\n',b'\r'):raise ValueError('invalid_or_truncated_csv:after_quote')
                else:
                    if value==b'"':quote_pending=True
                    continue
            if field_start and value==b'"':quoted=True;field_start=False
            elif value==b',':field_start=True
            elif value==b'\n':break
            elif value==b'\r':
                # Supported LF/CRLF terminators; the LF belongs to this record.
                if self.read(1)!=b'\n':raise ValueError('csv_lone_cr_unsupported')
                raw+=b'\n';break
            else:field_start=False
        self.number+=1
        data=bytes(raw)
        try:
            text=data.decode('utf-8-sig' if self.number==1 else 'utf-8')
            values=list(csv.reader(io.StringIO(text,newline=''),strict=True))
        except (UnicodeError,csv.Error) as error:
            raise ValueError('invalid_or_truncated_csv:'+str(error)) from error
        if len(values)!=1:raise ValueError('invalid_csv_logical_record')
        ref={'source_slot':self.slot,'record_sha256':sha(data),'frame_number':None,
             'record_number':self.number,'column':None,'raw_time':None}
        return {'source_ref':ref,'raw':data,'values':values[0],'byte_offset':start,'length':len(data),
                'kind':'header' if self.number==1 else 'process'}

    def close(self):
        if self.stream is not None:self.stream.close()


class ReplayInputs:
    """Each advance reads exactly the next physical frame/logical CSV record.

    CSV source ordinals include its header (1); first data record is 2. Repeating
    a seen ordinal is a cache lookup and never reads another original byte.
    """
    def __init__(self, networks, process, process_profile, *, synthetic, packet_limits=None,
                 process_limits=None, stream_limits=None, max_records=11000, capacity_config=None):
        if type(synthetic) is not bool:raise ValueError('explicit_synthetic_boolean_required')
        paths=list(networks) if isinstance(networks,(tuple,list)) else [networks]
        if not 1<=len(paths)<=4:raise ValueError('network_file_limit')
        self.synthetic=synthetic;self.profile=deepcopy(process_profile)
        self.packet_limits=packet_limits or Limits();self.process_limits=process_limits or ProcessLimits()
        self.stream_limits=stream_limits or StreamLimits();self.max_records=max_records
        capacity=None
        if capacity_config is not None:
            from .capacity import resolve_capacity_profile,parser_limits
            from .dual_source_rules import validate_profile
            validate_profile(capacity_config)
            if capacity_config.get('replay',{}).get('history_format')!='replay-history-checkpoint-delta-2':raise ValueError('capacity_replay_history_required')
            capacity=resolve_capacity_profile(capacity_config);ceilings=parser_limits(capacity_config)
        else:ceilings={'packet_limits':Limits(),'process_limits':ProcessLimits(),'stream_limits':StreamLimits()}
        ceiling_records=capacity.frames+capacity.process_records+1 if capacity is not None and capacity.version else 11000
        self.network_total_limit=capacity.network_total_bytes if capacity is not None else self.packet_limits.max_bytes
        if type(max_records) is not int or not 1<=max_records<=ceiling_records:
            raise ValueError('arrived_record_limit_configuration')
        for selected, ceiling in ((self.packet_limits,ceilings['packet_limits']),(self.process_limits,ceilings['process_limits']),(self.stream_limits,ceilings['stream_limits'])):
            if any(value>getattr(ceiling,key) for key,value in vars(selected).items()):
                raise ValueError('replay_hard_limit_exceeded')
        self.sources={f'network-{i}':_Cursor(path,f'network-{i}','network',self) for i,path in enumerate(paths)}
        self.sources['process']=_Cursor(process,'process','process',self)
        self.seen={};self.ordered=[];self.finished_sources=set();self.network_bytes=0;self.process_bytes=0;self.frame_count=0
        self.envelope={'frames':[]};self.file_sha256s=[];self.digest=fingerprint([])

    def _account(self, kind, count):
        if kind=='network':
            self.network_bytes+=count
            if self.network_bytes>self.network_total_limit:raise CaptureError('aggregate_byte_limit')
        else:
            self.process_bytes+=count
            if self.process_bytes>self.process_limits.max_bytes:raise ValueError('process_byte_limit')

    def advance(self, step):
        slot=step['source_slot'];number=step['record_number']
        if slot not in self.sources or type(number) is not int or number<1:raise ValueError('invalid_replay_source_record')
        source=self.sources[slot];key=(slot,number)
        if key in self.seen:
            unit=self.seen[key]
            expected=step.get('record_sha256',unit['source_ref']['record_sha256'])
            result={'status':'duplicate' if expected==unit['source_ref']['record_sha256'] else 'conflicting_reference',
                    'source_ref':deepcopy(unit['source_ref']),'kind':unit['kind'],'available_at':step['available_at']}
            if result['status']=='conflicting_reference':
                result.update(original_ref=deepcopy(unit['source_ref']),claimed_record_sha256=expected,
                              reason='unverified_digest_claim_not_second_original')
            return result
        if slot in self.finished_sources:raise ValueError('source_already_exhausted')
        if number!=source.number+1:raise ValueError('source_record_not_next')
        if len(self.seen)>=self.max_records:raise ValueError('arrived_record_limit')
        unit=source.packet() if source.kind=='network' else source.csv_record()
        if unit is None:
            return {'status':'eof','source_slot':slot,'record_number':number,'available_at':step['available_at']}
        if 'record_sha256' in step and step['record_sha256']!=unit['source_ref']['record_sha256']:
            raise ValueError('arrival_record_hash_mismatch')
        if source.kind=='network':
            self.frame_count+=1
            if self.frame_count>self.packet_limits.max_frames:raise CaptureError('aggregate_frame_limit')
            self.envelope['frames'].append(unit['frame'])
        elif number>self.process_limits.max_records+1:raise ValueError('process_record_limit')
        self.seen[key]=unit;self.ordered.append(key)
        self.digest=fingerprint([{'source_ref':self.seen[k]['source_ref'],
            'header_sha256':self.seen[k].get('header_sha256')} for k in self.ordered])
        return {'status':'accepted','source_ref':deepcopy(unit['source_ref']),'kind':unit['kind'],'available_at':step['available_at']}

    def frame(self, ref):
        unit=self._unit(ref)
        if unit['kind']!='network':raise ValueError('replay_frame_required')
        return deepcopy(unit['frame'])

    def _unit(self, ref):
        number=ref.get('frame_number') if ref.get('frame_number') is not None else ref.get('record_number')
        if type(number) is not int or number<1:raise ValueError('invalid_replay_reference')
        key=(ref.get('source_slot'),number)
        if key not in self.seen:raise ValueError('record_not_arrived')
        unit=self.seen[key]
        original=unit['source_ref']
        if set(ref)!=set(original) or any(ref.get(k)!=original[k] for k in ('source_slot','frame_number','record_number')):
            raise ValueError('invalid_replay_reference')
        if unit['kind']=='network' and any(ref.get(k)!=original[k] for k in ('column','raw_time')):
            raise ValueError('evidence_raw_time_or_column_mismatch')
        if ref.get('record_sha256')!=unit['source_ref']['record_sha256']:raise ValueError('replay_record_hash_mismatch')
        if sha(unit['raw'])!=ref['record_sha256']:raise ValueError('replay_record_hash_mismatch')
        return unit

    def record(self, ref):
        return deepcopy(self._unit(ref))

    def raw_frame(self, frame):
        return self._unit(frame['source_ref'])['frame_raw']

    def _verified(self):
        for unit in self.seen.values():
            if sha(unit['raw'])!=unit['source_ref']['record_sha256']:raise ValueError('replay_record_hash_mismatch')

    def resolve(self, ref, field=None):
        unit=self._unit(ref)
        if unit['kind']=='network':
            if ref.get('raw_time')!=unit['source_ref']['raw_time']:raise ValueError('evidence_raw_time_mismatch')
            raw=unit['frame_raw'];result={**unit['frame'],'raw_hex':raw.hex(),
                'integrity':'arrived_record_sha256_verified','network_checksums':checksum_evidence(raw)}
            if field is not None:
                start,length=field['frame_byte_offset'],field['length']
                if type(start) is not int or type(length) is not int or start<0 or length<1 or start+length>len(raw):raise ValueError('field_outside_frame')
                value=raw[start:start+length]
                if value.hex()!=field['hex'] or sha(value)!=field['sha256']:raise ValueError('field_evidence_hash_mismatch')
                result['field']={**field,'absolute_byte_offset':unit['frame']['byte_offset']+start}
            return result
        header=self.seen.get(('process',1))
        if not header:raise ValueError('csv_header_not_arrived')
        row=dict(zip(header['values'],unit['values']))
        if ref.get('column') is not None and ref['column'] not in row:raise ValueError('evidence_column_missing')
        if ref.get('raw_time') is not None and ref['raw_time']!=row.get(self.profile['timestamp_column']):raise ValueError('evidence_raw_time_mismatch')
        return row

    def snapshot(self, *, final=False, allowed_record_refs=None):
        allowed=None if allowed_record_refs is None else {(r['source_slot'],r.get('frame_number') or r.get('record_number'),r['record_sha256']) for r in allowed_record_refs}
        def included(unit):
            ref=unit['source_ref']
            return allowed is None or unit['kind']=='header' or (ref['source_slot'],ref.get('frame_number') or ref.get('record_number'),ref['record_sha256']) in allowed
        selected=[self.seen[k] for k in self.ordered if included(self.seen[k])]
        selected_fingerprint=fingerprint([{'source_ref':unit['source_ref'],'header_sha256':unit.get('header_sha256')} for unit in selected])
        prepared=SimpleNamespace(envelope={'frames':[unit['frame'] for unit in selected if unit['kind']=='network']},
            digest=selected_fingerprint,raw_frame=self.raw_frame,_verified=self._verified)
        capture=analyze_prepared_frames(prepared,synthetic=self.synthetic,final=final,stream_limits=self.stream_limits)
        csv_units=[unit for unit in selected if unit['source_ref']['source_slot']=='process']
        parsed={'events':[],'quality':{'status':'partial','reasons':['process_not_arrived'],'event_count':0}}
        if csv_units:
            text=b''.join(unit['raw'] for unit in csv_units).decode('utf-8-sig')
            index=SimpleNamespace(text=text,digest=sha(text.encode()),size_bytes=sum(len(u['raw']) for u in csv_units))
            parsed=parse_process(self.sources['process'].path,self.profile,synthetic=self.synthetic,evidence=index,extended=True,limits=self.process_limits)
            if parsed['quality']['status']=='unsupported':raise ValueError('unsupported_process:'+','.join(parsed['quality']['reasons']))
            for event in parsed['events']:
                old=event['source_ref'];unit=csv_units[old['record_number']]
                ref={**unit['source_ref'],'column':old['column'],'raw_time':old['raw_time']}
                event['source_ref']=ref;event['event_id']='replay-process-'+fingerprint(ref)
        parsed['filtered_record_numbers']=[self.seen[k]['source_ref']['record_number'] for k in self.ordered
            if self.seen[k]['kind']=='process' and not included(self.seen[k])]
        return {'capture':deepcopy(capture),'parsed':deepcopy(parsed),'frames':self,
                'prefix_fingerprint':selected_fingerprint,'available_record_refs':[deepcopy(unit['source_ref']) for unit in selected]}

    def finish_source(self, slot):
        source=self.sources[slot]
        if not source.eof:
            # Explicit EOF is an arrival action; it must not consume another unit.
            if source.read(1):raise ValueError('source_not_exhausted')
            source.eof=True
        self.finished_sources.add(slot)
        source.close()

    def all_sources_exhausted(self):
        return set(self.sources)==self.finished_sources

    def finish(self):
        # Logical arrival-sequence finalization never inspects an original suffix.
        # Trusted complete export separately requires explicit source_eof actions.
        return self.snapshot(final=True)

    def close(self):
        for source in self.sources.values():source.close()
