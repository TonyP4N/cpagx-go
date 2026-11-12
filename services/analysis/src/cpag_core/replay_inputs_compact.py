"""DAG6-only arrived-record parsing reuse; no original prefetch or future scan.

TCP reconstruction remains the unchanged bounded packet adapter. Its complete
answer is reusable only for exactly the same selected, arrived frame identities
and final flag. CSV row parsing is local; duplicate/time quality is recomputed
from the selected set on every snapshot, so excluded/late records cannot leak.
"""
from collections import Counter, OrderedDict
from copy import deepcopy
import sys
from types import SimpleNamespace

from . import replay_inputs as original
from .capacity import COMPACT, COMPACT_FORMAT, resolve_capacity_profile
from .parsers import _quality
from .measurement import phase
from .pipeline import canonical, fingerprint

VERSION = 'arrived-parser-cache-1'
CACHE_BYTES = 16 * 1024**2


def _bounded_size(value, limit):
    """Conservative retained Python-object size; shared identities counted once.

    Stop at the fixed cache ceiling. This is cache accounting, not process RSS.
    """
    stack=[value];seen=set();total=0
    while stack:
        item=stack.pop();identity=id(item)
        if identity in seen:continue
        seen.add(identity);total+=sys.getsizeof(item)
        if total>limit:return None
        if isinstance(item,dict):
            stack.extend(item.keys());stack.extend(item.values())
        elif isinstance(item,(list,tuple,set,frozenset)):
            stack.extend(item)
    return total


class _Cache:
    def __init__(self):
        self.rows=OrderedDict();self.bytes=0
        self.stats={'version':VERSION,'cache_limit_bytes':CACHE_BYTES,'cache_bytes':0,'cache_peak_bytes':0,
            'cache_accounting':'per-entry Python object traversal plus 512 bytes LRU overhead; not process RSS',
            'network_parse_calls':0,'network_frames_parsed':0,'capture_cache_hits':0,
            'process_parse_calls':0,'process_records_parsed':0,'row_cache_hits':0,
            'evictions':0,'oversized_uncached':0}

    def get(self,key):
        row=self.rows.get(key)
        if row is None:return None
        self.rows.move_to_end(key)
        return row[0]

    def put(self,key,value):
        size=_bounded_size((key,value),max(0,CACHE_BYTES-512))
        if size is not None:size+=512
        if size is None:
            self.stats['oversized_uncached']+=1
            return
        old=self.rows.pop(key,None)
        if old is not None:self.bytes-=old[1]
        # Two exact frame sets cover outer/all-arrived and inner/admitted views.
        if key[0]=='capture':
            peers=[k for k in self.rows if k[0]=='capture']
            while len(peers)>=2:
                self.bytes-=self.rows.pop(peers.pop(0))[1];self.stats['evictions']+=1
        while self.rows and (self.bytes+size>CACHE_BYTES or len(self.rows)>=32768):
            _,(_,removed)=self.rows.popitem(last=False);self.bytes-=removed;self.stats['evictions']+=1
        self.rows[key]=(value,size);self.bytes+=size;self.stats['cache_bytes']=self.bytes
        self.stats['cache_peak_bytes']=max(self.stats['cache_peak_bytes'],self.bytes)


class CompactReplayInputs(original.ReplayInputs):
    """Explicit core-capacity-3 input adapter; old constructors stay unchanged."""
    def __init__(self,*args,capacity_config=None,digest_strategy='incremental-prefix-digest-2',**kwargs):
        if (not isinstance(capacity_config,dict) or
                resolve_capacity_profile(capacity_config).version!=COMPACT or
                capacity_config.get('storage_format')!=COMPACT_FORMAT or
                capacity_config.get('replay',{}).get('history_format')!=COMPACT_FORMAT or
                digest_strategy!='incremental-prefix-digest-2'):
            raise ValueError('explicit_compact_replay_input_strategy_required')
        super().__init__(*args,capacity_config=capacity_config,digest_strategy=digest_strategy,**kwargs)
        self._parse_cache=_Cache()

    @property
    def parse_statistics(self):
        return dict(self._parse_cache.stats)

    @phase('replay_network_prefix')
    def _capture(self,selected,final):
        frames=[unit for unit in selected if unit['kind']=='network']
        key=('capture',self.synthetic,bool(final),tuple(vars(self.stream_limits).items()),
            tuple((u['source_ref']['source_slot'],u['source_ref']['frame_number'],u['source_ref']['record_sha256']) for u in frames))
        capture=self._parse_cache.get(key)
        if capture is not None:
            # A cache hit is never evidence that the arrived bytes stayed intact.
            self._verified();self._parse_cache.stats['capture_cache_hits']+=1
            return capture
        prepared=SimpleNamespace(envelope={'frames':[unit['frame'] for unit in frames]},
            digest=self.digest,raw_frame=self.raw_frame,_verified=self._verified)
        capture=self._parse_capture(prepared,final)
        self._parse_cache.stats['network_parse_calls']+=1
        self._parse_cache.stats['network_frames_parsed']+=len(frames)
        self._parse_cache.put(key,capture)
        return capture

    @phase('network_parse')
    def _parse_capture(self,prepared,final):
        return original.analyze_prepared_frames(prepared,synthetic=self.synthetic,
            final=final,stream_limits=self.stream_limits)

    def _process_piece(self,header,unit,profile_digest):
        key=('process',profile_digest,self.synthetic,str(self.sources['process'].path),
            header['source_ref']['record_sha256'],None if unit is None else
            (unit['source_ref']['record_number'],unit['source_ref']['record_sha256']))
        parsed=self._parse_cache.get(key)
        if parsed is not None:
            self._parse_cache.stats['row_cache_hits']+=1
            return parsed
        raw=header['raw']+(b'' if unit is None else unit['raw'])
        text=raw.decode('utf-8-sig')
        index=SimpleNamespace(text=text,digest=original.sha(text.encode()),size_bytes=len(raw))
        parsed=original.parse_process(self.sources['process'].path,self.profile,synthetic=self.synthetic,
            evidence=index,extended=True,limits=self.process_limits)
        self._parse_cache.stats['process_parse_calls']+=1
        self._parse_cache.stats['process_records_parsed']+=int(unit is not None)
        if parsed['quality']['status']=='unsupported':
            raise ValueError('unsupported_process:'+','.join(parsed['quality']['reasons']))
        if unit is not None:
            for event in parsed['events']:
                old=event['source_ref']
                ref={**unit['source_ref'],'column':old['column'],'raw_time':old['raw_time']}
                event['source_ref']=ref;event['event_id']='replay-process-'+fingerprint(ref)
        self._parse_cache.put(key,parsed)
        return parsed

    @phase('replay_process_prefix')
    def _process(self,selected):
        units=[unit for unit in selected if unit['source_ref']['source_slot']=='process']
        if not units:
            return {'events':[],'quality':{'status':'partial','reasons':['process_not_arrived'],'event_count':0}}
        header=units[0];profile_digest=original.sha(canonical(self.profile))
        self._process_piece(header,None,profile_digest)
        parsed=[];errors=[];record_counts=Counter();time_counts=Counter()
        for number,unit in enumerate(units[1:],1):
            piece=self._process_piece(header,unit,profile_digest)
            for reason in piece['quality']['reasons']:
                errors.append('invalid_csv_record_width:'+str(number) if reason=='invalid_csv_record_width:1' else reason)
            valid=len(unit['values'])==len(header['values'])
            if valid:record_counts[tuple(unit['values'])]+=1
            for event in piece['events']:
                if event['event_time'] is not None:
                    time_counts[(event['source_ref']['column'],event['event_time'])]+=1
                parsed.append((unit,event))
        events=[]
        for unit,event in parsed:
            reasons=[]
            if record_counts[tuple(unit['values'])]>1:reasons.append('duplicate_process_record')
            if event['event_time'] is not None and time_counts[(event['source_ref']['column'],event['event_time'])]>1:
                reasons.append('duplicate_process_time')
            if reasons:
                event=dict(event);event['quality']=_quality(event['quality']['reasons']+reasons);errors.extend(reasons)
            events.append(event)
        return {'events':events,'quality':_quality(errors,len(events))}

    @phase('replay_input_snapshot')
    def snapshot(self,*,final=False,allowed_record_refs=None):
        allowed=None if allowed_record_refs is None else {(r['source_slot'],r.get('frame_number') or r.get('record_number'),r['record_sha256']) for r in allowed_record_refs}
        def included(unit):
            ref=unit['source_ref']
            return allowed is None or unit['kind']=='header' or (ref['source_slot'],ref.get('frame_number') or ref.get('record_number'),ref['record_sha256']) in allowed
        selected=[self.seen[key] for key in self.ordered if included(self.seen[key])]
        # Incremental digest has exactly the old canonical digest bytes, also
        # when an explicit admission set selects every already-arrived record.
        digest=(self.digest if len(selected)==len(self.ordered) else fingerprint([
            {'source_ref':unit['source_ref'],'header_sha256':unit.get('header_sha256')} for unit in selected]))
        capture=self._capture(selected,final);parsed=self._process(selected)
        parsed['filtered_record_numbers']=[self.seen[key]['source_ref']['record_number'] for key in self.ordered
            if self.seen[key]['kind']=='process' and not included(self.seen[key])]
        return {'capture':deepcopy(capture),'parsed':deepcopy(parsed),'frames':self,
            'prefix_fingerprint':digest,'available_record_refs':[deepcopy(unit['source_ref']) for unit in selected]}

    def close(self):
        super().close()
        cache=getattr(self,'_parse_cache',None)
        if cache is not None:
            cache.rows.clear();cache.bytes=0;cache.stats['cache_bytes']=0
