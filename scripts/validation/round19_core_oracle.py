"""Independent small-value, identity and raw-record checks; no predictor imports."""
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

VERSION='r19-independent-core-oracle-1'
MISSING=object()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def sha(value):return hashlib.sha256(value).hexdigest()


def pointer(path):return ''.join('/'+str(part).replace('~','~0').replace('/','~1') for part in path)


def exact(left,right):
    return left is right if left is MISSING or right is MISSING else type(left) is type(right) and canonical(left)==canonical(right)


def compare_values(old,new,*,allowed=(),max_examples=1000):
    """Every difference is counted; only exact predeclared scalar leaves pass."""
    if type(max_examples) is not int or not 1<=max_examples<=1000000:raise ValueError('difference_example_budget_invalid')
    rules={};used=set();examples=[];permitted=[];count=0
    for rule in allowed:
        if (not isinstance(rule,dict) or set(rule)!={'path','old_present','old','new_present','new','reason'}
                or not isinstance(rule['path'],str) or not rule['path'].startswith('/')
                or type(rule['old_present']) is not bool or type(rule['new_present']) is not bool
                or not isinstance(rule['reason'],str) or not rule['reason'].strip()
                or any(isinstance(rule[key],(dict,list)) for key in ('old','new'))
                or rule['path'] in rules):raise ValueError('exact_scalar_difference_policy_required')
        canonical(rule);rules[rule['path']]=rule
    def walk(a,b,path):
        nonlocal count
        location=pointer(path)
        if location in rules:
            rule=rules[location];used.add(location)
            expected_a=rule['old'] if rule['old_present'] else MISSING
            expected_b=rule['new'] if rule['new_present'] else MISSING
            if exact(a,expected_a) and exact(b,expected_b):
                permitted.append(rule);return
        if type(a) is dict and type(b) is dict:
            if any(type(key) is not str for key in (*a,*b)):raise ValueError('JSON_string_keys_required')
            for key in sorted(set(a)|set(b)):walk(a.get(key,MISSING),b.get(key,MISSING),(*path,key))
            return
        if type(a) is list and type(b) is list:
            for index in range(max(len(a),len(b))):walk(a[index] if index<len(a) else MISSING,b[index] if index<len(b) else MISSING,(*path,index))
            return
        if exact(a,b):return
        count+=1
        if len(examples)<max_examples:
            examples.append({'path':location,'old_present':a is not MISSING,'old':None if a is MISSING else a,
                'new_present':b is not MISSING,'new':None if b is MISSING else b})
    walk(old,new,())
    unused=sorted(set(rules)-used)
    return {'version':VERSION,'equal':count==0 and not unused,'unapproved_difference_count':count,
        'differences':examples,'examples_truncated':count>len(examples),'allowed_observed':permitted,'unused_policy_paths':unused}


class IdentityBijection:
    """Container identity map only; caller must select exact identity paths."""
    def __init__(self):self.forward={};self.backward={}
    def bind(self,old,new):
        if not isinstance(old,str) or not old or not isinstance(new,str) or not new:raise ValueError('explicit_identity_strings_required')
        if self.forward.get(old,new)!=new or self.backward.get(new,old)!=old:raise ValueError('identity_mapping_not_bijective')
        self.forward[old]=new;self.backward[new]=old
    def mapped(self,old):
        if old is None:return None
        if old not in self.forward:raise ValueError('unregistered_identity_reference')
        return self.forward[old]
    def record(self):return dict(sorted(self.forward.items()))


def pcap_records(path):
    """Independent PCAP envelope scan; no transport or judgment implementation."""
    data=Path(path).read_bytes()
    magic={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000),
           b'\x4d\x3c\xb2\xa1':('<',1000000000),b'\xa1\xb2\x3c\x4d':('>',1000000000)}
    if len(data)<24 or data[:4] not in magic:raise ValueError('independent_pcap_envelope_required')
    endian,resolution=magic[data[:4]];major,minor,zone,accuracy,snaplen,link=struct.unpack_from(endian+'HHiiII',data,4)
    if (major,minor,zone,accuracy,link)!=(2,4,0,0,1) or snaplen<=0:raise ValueError('independent_pcap_header_invalid')
    rows=[];offset=24
    while offset<len(data):
        if offset+16>len(data):raise ValueError('independent_pcap_truncated_record')
        seconds,fraction,captured,original=struct.unpack_from(endian+'IIII',data,offset)
        end=offset+16+captured
        if fraction>=resolution or captured>original or captured>snaplen or end>len(data):raise ValueError('independent_pcap_record_invalid')
        raw=data[offset+16:end];record=data[offset:end]
        rows.append({'raw':raw,'record_raw':record,'byte_offset':offset+16,'record_byte_offset':offset,
            'raw_time':str(seconds*resolution+fraction),'captured_length':captured,'original_length':original,
            'frame_sha256':sha(raw),'record_sha256':sha(record)})
        offset=end
    return {'file_sha256':sha(data),'records':rows}


class _CSVLines:
    def __init__(self,raw):self.stream=io.BytesIO(raw);self.offset=0
    def __iter__(self):return self
    def __next__(self):
        raw=self.stream.readline()
        if not raw:raise StopIteration
        first=self.offset==0;self.offset+=len(raw)
        return (raw.removeprefix(b'\xef\xbb\xbf') if first else raw).decode('utf-8')


def csv_records(path):
    raw=Path(path).read_bytes();lines=_CSVLines(raw);reader=csv.reader(lines,strict=True);start=0;rows=[]
    for values in reader:
        fragment=raw[start:lines.offset];rows.append({'values':values,'raw':fragment,'byte_offset':start,'record_sha256':sha(fragment)})
        start=lines.offset
    if not rows or not rows[0]['values'] or len(set(rows[0]['values']))!=len(rows[0]['values']):raise ValueError('independent_csv_header_invalid')
    header=rows[0]['values']
    if any(len(row['values'])!=len(header) for row in rows):raise ValueError('independent_csv_record_width_invalid')
    return {'file_sha256':sha(raw),'header':header,'records':rows}


def check_raw_evidence(evidence,networks,process):
    """Resolve every returned raw reference against independently indexed bytes."""
    if not isinstance(evidence,list) or not evidence:raise ValueError('nonempty_raw_evidence_required')
    captures=[pcap_records(path) for path in networks];csv_input=csv_records(process);checked=[]
    for item in evidence:
        ref=item['source_ref'];original=item['original'];replay='source_slot' in ref
        if ref.get('frame_number') is not None:
            number=ref['frame_number']
            if type(number) is not int or number<1:raise ValueError('independent_frame_number_invalid')
            if replay:
                slot=ref['source_slot']
                if not isinstance(slot,str) or not slot.startswith('network-') or not slot[8:].isdigit():raise ValueError('independent_network_slot_invalid')
                index=int(slot[8:])
                if not 0<=index<len(captures):raise ValueError('independent_network_slot_invalid')
                capture=captures[index]
            else:
                matches=[value for value in captures if value['file_sha256']==ref.get('file_sha256')]
                if len(matches)!=1:raise ValueError('independent_capture_identity_invalid')
                capture=matches[0]
            if number>len(capture['records']):raise ValueError('independent_frame_missing')
            row=capture['records'][number-1]
            if replay and ref.get('record_sha256')!=row['record_sha256']:raise ValueError('independent_record_sha_mismatch')
            if ref.get('raw_time')!=row['raw_time']:raise ValueError('independent_raw_time_mismatch')
            for key in ('raw_hex','frame_sha256','captured_length','original_length','byte_offset'):
                expected=row['raw'].hex() if key=='raw_hex' else row[key]
                if not exact(original.get(key),expected):raise ValueError('independent_frame_bytes_or_metadata_mismatch:'+key)
            checked.append({'kind':'frame','number':number,'frame_sha256':row['frame_sha256'],'record_sha256':row['record_sha256']})
        else:
            number=ref.get('record_number')
            if type(number) is not int or number<1:raise ValueError('independent_csv_number_invalid')
            if replay and ref.get('source_slot')!='process':raise ValueError('independent_process_slot_invalid')
            if not replay and ref.get('file_sha256')!=csv_input['file_sha256']:raise ValueError('independent_csv_file_identity_invalid')
            index=number-1 if replay else number
            if index>=len(csv_input['records']):raise ValueError('independent_csv_record_missing')
            row=csv_input['records'][index];expected=dict(zip(csv_input['header'],row['values']))
            if replay and ref.get('record_sha256')!=row['record_sha256']:raise ValueError('independent_record_sha_mismatch')
            if ref.get('column') is not None and ref['column'] not in expected:raise ValueError('independent_csv_column_missing')
            if ref.get('raw_time') is not None and ref['raw_time']!=expected.get('time'):raise ValueError('independent_raw_time_mismatch')
            if not exact(original,expected):raise ValueError('independent_csv_value_mismatch')
            checked.append({'kind':'csv','number':number,'record_sha256':row['record_sha256'],'byte_offset':row['byte_offset']})
    return {'version':VERSION,'checked_references':checked,'all_returned_references_match_independent_originals':True}
