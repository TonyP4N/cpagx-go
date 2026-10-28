"""Deterministic arrived-prefix replay; wall-clock observations are separate.

This module never opens source files or reads an arrival iterator. Its only
material input is an adapter snapshot containing records already received.
"""
from copy import deepcopy
from datetime import datetime, timezone
from fractions import Fraction
import time
import re

from .contracts import validate
from .dual_source import _analyze_prepared, corrected, references, utc, R17_VERSION
from .dual_source_rules import clock_time, validate_profile, outward
from .pipeline import canonical, fingerprint

VERSION='dual-source-replay-1'
TRANSPORT_FIELDS={'sequence','finish_at','speed','realtime','realtime_pacing','history_format'}


def instant(value):
    if not isinstance(value,str):raise ValueError('explicit_replay_utc_time_required')
    if re.search(r':\d{2}\.\d{7,}',value):raise ValueError('replay_timestamp_precision_unsupported')
    when=datetime.fromisoformat(value.replace('Z','+00:00'))
    if when.tzinfo is None:raise ValueError('explicit_replay_utc_time_required')
    return when.astimezone(timezone.utc).timestamp()


def exact_instant(value):
    instant(value)
    delta=datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
    return Fraction(delta.days*86400+delta.seconds)+Fraction(delta.microseconds,1000000)


def semantic_profile(profile):
    result=deepcopy(profile)
    result['replay']={key:value for key,value in result['replay'].items() if key not in TRANSPORT_FIELDS}
    return result


def record_key(ref):
    return (ref['source_slot'],ref.get('frame_number'),ref.get('record_number'))


class ReplayIncomplete(ValueError):
    def __init__(self, reason, summary):
        self.reason=reason;self.summary=summary
        super().__init__('replay_incomplete:'+reason+':'+canonical(summary).decode())


class _EmptyFrames:
    def frame(self, ref):raise ValueError('record_not_arrived')


class ReplayCore:
    """consume/advance only use declared simulation time, never a wall clock."""
    def __init__(self, profile, *, history_sink=None):
        self.profile=deepcopy(profile)
        self.parameters=deepcopy(profile['replay']);validate('ReplayCompactProfile' if getattr(self,'compact_history',False) else 'ReplaySpoolProfile' if self.parameters.get('history_format')=='replay-history-checkpoint-delta-2' else 'ReplayProfile',self.parameters)
        self.analysis_profile=deepcopy(profile);self.analysis_profile.pop('replay')
        if not validate_profile(self.analysis_profile):raise ValueError('replay_requires_bounded_profile')
        self.identity_profile=semantic_profile(profile)
        self.config_fingerprint=fingerprint(self.identity_profile)
        if self.parameters.get('history_format')=='replay-history-checkpoint-delta-2' and history_sink is None:raise ValueError('spool_history_sink_required')
        self._history_sink=history_sink
        if history_sink is not None:
            from .replay_history import HistorySink
            if not isinstance(history_sink, HistorySink):raise ValueError('explicit_v2_history_sink_required')
            history_sink.bind(self.config_fingerprint, VERSION)
        self._snapshot_count=0;self._history_count=0
        self.now=instant(self.parameters['simulation_start']);self.start=self.now
        self.now_exact=exact_instant(self.parameters['simulation_start']);self.start_exact=self.now_exact
        self.arrival_seq=0;self.phase='running';self.closed={};self.first_operation_at={};self.first_operation_exact={}
        self.seen={};self.admitted={};self.record_available={};self.expired=[];self.conflicts=[];self.discarded=[]
        self.network={};self.process={};self.frozen_network={};self.frozen_process={};self.capture_unsupported=[];self.capture_pending=[]
        self.process_quality={'status':'valid','reasons':[],'event_count':0};self.filtered_record_numbers=[]
        self.frame_accessor=_EmptyFrames();self.prefix_fingerprint=fingerprint([])
        self._history=[];self._snapshots=[];self._runtime=[];self._trace=[]
        self._latencies={};self._confirmations={};self._backlog=[]
        self._counts={'arrival_attempts':0,'accepted':0,'duplicate':0,'conflict':0,'late':0,'too_late':0,'discarded':0,'expired':0}
        self._output_bytes=0;self._revision_number=0
        self._analysis=self._judge()
        self._last_state_fingerprint=None;self._latest=None
        self._publish('initial',{'kind':'initial','arrival_seq':0,'available_at':utc(self.now),'evidence_refs':[]},initial=True)

    def _failure(self, reason, evidence_refs=None):
        self.phase='incomplete'
        raise ReplayIncomplete(reason,{'status':'incomplete','reason':reason,'arrival_seq':self.arrival_seq,
            'available_at':utc(self.now),'snapshots':self._snapshot_count,'revisions':self._history_count,
            'arrived_records':len(self.seen),'last_state_fingerprint':self._last_state_fingerprint,
            'evidence_refs':deepcopy((evidence_refs or [])[:4])})

    def _check_clock(self, available_at, arrival_seq=None):
        now=instant(available_at);now_exact=exact_instant(available_at)
        if now_exact<self.now_exact:raise ValueError('arrival_clock_cannot_go_backwards')
        if arrival_seq is not None:
            if type(arrival_seq) is not int or arrival_seq<=self.arrival_seq:raise ValueError('arrival_sequence_not_increasing')
            self.arrival_seq=arrival_seq
        self.now=now;self.now_exact=exact_instant(available_at)

    def _allowed(self, refs):
        return all(record_key(ref) in self.admitted and self.admitted[record_key(ref)]['record_sha256']==ref['record_sha256'] for ref in refs)

    def _collect(self, prefix, *, final=False):
        self.frame_accessor=prefix.get('frame_accessor',prefix.get('frames'))
        if self.frame_accessor is None:raise ValueError('arrived_frame_accessor_required')
        if hasattr(self.frame_accessor,'snapshot'):
            prefix=self.frame_accessor.snapshot(final=final,allowed_record_refs=list(self.admitted.values()))
        capture,parsed=prefix['capture'],prefix['parsed']
        self.filtered_record_numbers=parsed.get('filtered_record_numbers',[])
        current_network={}
        for event,observation in zip(capture['events'],capture['observations']):
            if self._allowed(observation['source_refs']):
                current_network[event['event_id']]={'event':deepcopy(event),'observation':deepcopy(observation)}
            else:
                # A discarded late retransmission can add provenance to a PDU
                # already admitted. Keep its earlier verified version, not the
                # newly excluded contributor. Accepted parse retractions below
                # remain authoritative and never accumulate stale operations.
                current_refs={canonical(ref) for ref in observation['source_refs']}
                for identity,prior in self.network.items():
                    if all(canonical(ref) in current_refs for ref in prior['observation']['source_refs']):
                        current_network[identity]=deepcopy(prior)
        self.network=current_network
        self.process={event['event_id']:deepcopy(event) for event in parsed['events'] if self._allowed([event['source_ref']])}
        self.capture_unsupported=[deepcopy(item) for item in capture.get('unsupported',[]) if self._allowed(item.get('source_refs',[]))]
        self.capture_pending=deepcopy(capture.get('pending',[]))
        # Malformed logical rows cannot establish adjacency, including at EOF.
        reasons=parsed['quality']['reasons']
        if any(reason.startswith(('invalid_csv_record_width','invalid_or_truncated_csv')) for reason in reasons):
            self._failure('malformed_process_input')
        self.process_quality=deepcopy(parsed['quality'])
        self.process_quality['event_count']=len(self.process)
        self.prefix_fingerprint=prefix['prefix_fingerprint']

    def _judge(self):
        capture={'events':[item['event'] for item in self.network.values()],
                 'observations':[item['observation'] for item in self.network.values()],
                 'unsupported':deepcopy(self.capture_unsupported)}
        parsed={'events':list(self.process.values()),'quality':deepcopy(self.process_quality),
                'filtered_record_numbers':list(self.filtered_record_numbers)}
        result=_analyze_prepared(capture,parsed,self.frame_accessor,self.analysis_profile,self.prefix_fingerprint,
            allow_empty=True,source_contract='replay',identity_config=self.identity_profile)
        result['semantic_config_fingerprint']=self.config_fingerprint
        result['replay_version']=VERSION
        result['quality']['network_pending']=deepcopy(self.capture_pending)
        groups=None
        if getattr(self,'compact_history',False):
            groups={}
            for candidate in result['candidates']:groups.setdefault(candidate['operation_id'],[]).append(candidate)
        for operation in result['operations']:
            identity=operation['operation_id']
            self.first_operation_at.setdefault(identity,self.now)
            self.first_operation_exact.setdefault(identity,self.now_exact)
            interval=operation['time']['interval']
            deadline=outward((Fraction.from_float(float(interval[1])) if interval else self.first_operation_exact[identity])+
                Fraction(str(self.analysis_profile['window_seconds']))+Fraction(str(self.parameters['allowed_lateness_seconds'])),True)
            hard_unknown=operation['mapping']['status']!='matched' or any(
                reason.startswith(('request_','response_','mapping_','process_mapping_conflict','process_order_uncertain','duplicate_process_time','unsupported_network'))
                for reason in operation['unknown_reasons'])
            own_candidates=groups.get(identity,[]) if groups is not None else [candidate for candidate in result['candidates'] if candidate['operation_id']==identity]
            if self.now_exact<self.start_exact+Fraction(str(self.parameters['warmup_seconds'])):status='warming_up'
            elif operation['response']['state'] not in ('success','error'):status='pending_response'
            elif operation['response']['state']=='error' or operation['counterevidence']:status='counterevidence_present'
            elif hard_unknown:status='unknown'
            elif any(candidate['state']=='ambiguous' for candidate in own_candidates):status='ambiguous'
            elif any(candidate['state']!='supported_candidate' for candidate in own_candidates):status='unknown'
            elif operation['assessment']=='unknown':status='wait_process'
            else:status='normal'
            operation['replay']={'status':status,'provisional':True,'closed':False,'deadline':utc(deadline),'deadline_epoch_seconds':deadline,
                'deadline_basis':'corrected_request_upper' if interval else 'arrival_timeout_unknown',
                'first_available_at':utc(self.first_operation_at[identity]),
                'waiting_for':(['response'] if operation['response']['state'] not in ('success','error') else [])+
                              (['process_window'] if operation['assessment']=='unknown' else [])}
            if self.conflicts:
                operation['unknown_reasons']=sorted(set(operation['unknown_reasons']+['conflicting_record_identity']))
                operation['assessment']='unknown';operation['replay']['status']='unknown'
        # Replay does not publish speculative associations before the response or
        # during warmup. All remaining judgements use the shared R17 rule result.
        pending={op['operation_id'] for op in result['operations'] if op['replay']['status'] in ('warming_up','pending_response')}
        if self.conflicts:pending.update(op['operation_id'] for op in result['operations'])
        result['candidates']=[c for c in result['candidates'] if c['operation_id'] not in pending]
        if groups is not None:
            groups={}
            for candidate in result['candidates']:groups.setdefault(candidate['operation_id'],[]).append(candidate)
        for operation in result['operations']:
            operation['candidates']=[c['candidate_id'] for c in (groups.get(operation['operation_id'],[]) if groups is not None else result['candidates']) if c['operation_id']==operation['operation_id']]
        # Frozen operations and their claim evidence are immutable even if later
        # adapter observations would associate a further response or alternative.
        if getattr(self,'compact_history',False):
            self._merge_frozen(result)
        else:
            for identity,frozen in self.closed.items():
                result['operations']=[op for op in result['operations'] if op['operation_id']!=identity]+[deepcopy(frozen['operation'])]
                result['candidates']=[c for c in result['candidates'] if c['operation_id']!=identity]+deepcopy(frozen['candidates'])
                by_id={change['event_id']:change for change in result['changes']}
                for change in frozen['changes']:by_id.setdefault(change['event_id'],deepcopy(change))
                result['changes']=list(by_id.values())
        for name,archive in (('network',self.frozen_network),('process',self.frozen_process)):
            existing={row['event']['event_id'] for row in result[name]}
            result[name]+=[deepcopy(row) for identity,row in archive.items() if identity not in existing]
        # Stable first-observation operation order, including frozen entries.
        result['operations'].sort(key=lambda op:(self.first_operation_at[op['operation_id']],op['operation_id']))
        linked={candidate['change_id'] for candidate in result['candidates']}
        result['orphan_change_ids']=[change['event_id'] for change in result['changes'] if change['event_id'] not in linked]
        result['replay']={'version':VERSION,'phase':self.phase,'warmup_complete':self.now_exact>=self.start_exact+Fraction(str(self.parameters['warmup_seconds'])),
            'conflicts':deepcopy(self.conflicts),'closed_operation_ids':sorted(self.closed),
            'available_record_refs':deepcopy(list(self.seen.values())),
            'active_record_refs':deepcopy(list(self.admitted.values())),
            'buffer_scope':'active observations; historical originals and frozen decisions remain queryable',
            'expired_record_refs':deepcopy(self.expired),
            'limitations':['arrived_prefix_only','hypothetical_associations_only','input_exhausted_does_not_prove_effect',
                           'bounded_prefix_recomputation_not_a_throughput_claim']}
        return result

    def _raw_interval(self, prefix, ref):
        frames=prefix.get('frame_accessor',prefix.get('frames'))
        if ref.get('frame_number') is not None:
            frame=frames.frame(ref);exact=Fraction(frame['raw_timestamp'],frame['ticks_per_second'])
            return clock_time(ref['raw_time'],outward(exact),outward(exact,True),self.analysis_profile['clocks']['network'],corrected,True)['interval']
        matches=[event for event in prefix['parsed']['events'] if record_key(event['source_ref'])==record_key(ref) and event['event_time']]
        if not matches:return None
        dt=datetime.fromisoformat(matches[0]['event_time'].replace('Z','+00:00'))
        delta=dt-datetime(1970,1,1,tzinfo=timezone.utc)
        exact=Fraction(delta.days*86400+delta.seconds)+Fraction(delta.microseconds,1000000)
        return clock_time(ref['raw_time'],outward(exact),outward(exact,True),self.analysis_profile['clocks']['process'],corrected,True)['interval']

    def _affects_closed(self, prefix, ref, interval):
        if interval is None:return []
        key=record_key(ref);affected=[]
        process=[event for event in prefix['parsed']['events'] if record_key(event['source_ref'])==key]
        for identity,frozen in self.closed.items():
            operation=frozen['operation'];window=operation.get('window')
            if window is None and operation['time']['interval'] is not None:
                start,end=operation['time']['interval'];window=[start,end+self.analysis_profile['window_seconds']]
            if window is None:continue
            gap=self.analysis_profile['max_sample_gap_seconds']
            if interval[1]<window[0]-gap or interval[0]>window[1]+gap:continue
            if process:
                mapping=operation['mapping']
                if any(event['asset_id']==mapping.get('asset_id') and event['tag']==mapping.get('tag') for event in process):affected.append(identity)
            elif ref.get('frame_number') is not None:
                frame=prefix.get('frame_accessor',prefix.get('frames')).frame(ref)
                transport=frame['transport']
                endpoints={str(transport.get('source_ip'))+':'+str(transport.get('source_port')),
                           str(transport.get('destination_ip'))+':'+str(transport.get('destination_port'))}
                if endpoints=={operation['source_endpoint'],operation['destination_endpoint']}:affected.append(identity)
        return affected

    def _expire(self):
        cutoff=self.now_exact-Fraction(str(self.parameters['buffer_seconds']))
        removed=[]
        open_ids={operation['operation_id'] for operation in self._analysis['operations'] if not operation['replay']['closed']}
        protected={record_key(ref) for ref in references([
            [operation for operation in self._analysis['operations'] if operation['operation_id'] in open_ids],
            [candidate for candidate in self._analysis['candidates'] if candidate['operation_id'] in open_ids],
            self.capture_pending])}
        for key in list(self.admitted):
            ref=self.admitted[key]
            if ref['source_slot']=='process' and ref.get('record_number')==1:continue
            if self.record_available.get(key,self.now_exact)<cutoff:
                if key in protected:self._failure('buffer_time_limit',[ref])
                removed.append(self.admitted.pop(key));self._counts['expired']+=1
        if not removed:return
        self.expired.extend(deepcopy(removed))
        self.network={identity:item for identity,item in self.network.items() if self._allowed(item['observation']['source_refs'])}
        self.process={identity:event for identity,event in self.process.items() if self._allowed([event['source_ref']])}
        self.capture_unsupported=[item for item in self.capture_unsupported if self._allowed(item.get('source_refs',[]))]

    def consume(self, prefix, *, available_at, arrival_seq, trigger_ref=None, status='accepted', original_ref=None, claimed_record_sha256=None):
        started=time.monotonic()
        if self.phase in ('incomplete','finished'):raise ValueError('replay_is_not_running')
        if status not in ('accepted','duplicate','conflict','conflicting_reference','input_exhausted','source_eof','eof'):raise ValueError('invalid_arrival_status')
        if trigger_ref is not None:validate('ReplaySourceRef',trigger_ref)
        self._check_clock(available_at,arrival_seq)
        # Settle the previous admitted prefix before considering this record. A
        # future arriving response/change cannot make its overdue window true.
        if self._settle_due():
            self._record_metrics()
            self._publish('clock_before_arrival',{'kind':'clock_advance','arrival_seq':arrival_seq,
                'available_at':utc(self.now),'evidence_refs':[]})
        trigger={'kind':status,'arrival_seq':arrival_seq,'available_at':utc(self.now),'evidence_refs':[] if trigger_ref is None else [deepcopy(trigger_ref)]}
        classification=status;reason=None
        if status not in ('input_exhausted','source_eof','eof'):
            self._counts['arrival_attempts']+=1
            key=record_key(trigger_ref) if trigger_ref else None
            if status=='conflicting_reference':
                classification='conflicting_reference';reason='unverified_digest_claim_not_second_original'
                self._counts['conflict']+=1
            elif key in self.seen:
                if self.seen[key]['record_sha256']==trigger_ref['record_sha256'] and status!='conflict':classification='duplicate'
                else:classification='conflict'
            if classification=='conflicting_reference':pass
            elif classification=='duplicate':self._counts['duplicate']+=1
            elif classification=='conflict':
                self._counts['conflict']+=1
                old=deepcopy(original_ref or self.seen.get(key) or trigger_ref)
                self.conflicts.append({'reason':'conflicting_record_identity','original_ref':old,'conflicting_ref':deepcopy(trigger_ref),'available_at':utc(self.now)})
                trigger['evidence_refs']=references([old,trigger_ref]);reason='conflicting_record_identity'
            else:
                if trigger_ref is not None:
                    self.seen[key]=deepcopy(trigger_ref)
                    interval=self._raw_interval(prefix,trigger_ref)
                    if interval and Fraction.from_float(float(interval[1]))<self.now_exact:
                        self._counts['late']+=1;classification='late'
                    affected=self._affects_closed(prefix,trigger_ref,interval)
                    if interval and Fraction.from_float(float(interval[1]))<self.now_exact-Fraction(str(self.parameters['allowed_lateness_seconds'])) and affected:
                        classification='too_late';reason='closed_window_lateness_limit'
                        self._counts['too_late']+=1;self._counts['discarded']+=1
                        self.discarded.append({'source_ref':deepcopy(trigger_ref),'reason':reason,'available_at':utc(self.now)})
                    else:
                        self.admitted[key]=deepcopy(trigger_ref);self.record_available[key]=self.now_exact;self._counts['accepted']+=1
                # External callers may pass an already admitted prefix delta.
                for ref in prefix.get('available_record_refs',[]):
                    key=record_key(ref)
                    if key not in self.seen:self.seen[key]=deepcopy(ref);self.admitted[key]=deepcopy(ref);self.record_available[key]=self.now_exact
                if classification!='too_late':self._collect(prefix)
        elif status in ('input_exhausted','source_eof'):
            self._collect(prefix,final=status=='input_exhausted')
            if status=='input_exhausted':self.phase='input_exhausted'
        if classification not in ('duplicate','conflicting_reference'):self._analysis=self._judge()
        self._record_metrics()
        self._trace.append({'arrival_seq':arrival_seq,'available_at':utc(self.now),'classification':classification,
            'reason':reason,'sample_kind':'control' if status in ('input_exhausted','source_eof','eof') else 'record',
            'evidence_refs':deepcopy(trigger['evidence_refs']),
            **({'claimed_record_sha256':claimed_record_sha256} if claimed_record_sha256 is not None else {})})
        snapshot=self._publish(classification,trigger)
        self._runtime.append({'arrival_seq':arrival_seq,'operation':'consume','wall_seconds':time.monotonic()-started})
        return snapshot

    def _settle_due(self):
        before=(len(self.closed),self._counts['expired'])
        self._analysis=self._judge()
        for operation in self._analysis['operations']:
            identity=operation['operation_id']
            if identity in self.closed or self.now_exact<=Fraction.from_float(float(operation['replay']['deadline_epoch_seconds'])):continue
            operation['replay'].update(closed=True,provisional=False,status='closed')
            if operation['time']['interval'] is None:
                operation['unknown_reasons']=sorted(set(operation['unknown_reasons']+['arrival_timeout_unknown']))
            elif operation['response']['state'] not in ('success','error'):
                operation['unknown_reasons']=sorted(set(operation['unknown_reasons']+['response_missing_at_window_close']))
            elif operation['assessment']=='unknown':
                operation['unknown_reasons']=sorted(set(operation['unknown_reasons']+['incomplete_process_window_at_close']))
            candidates=[c for c in self._analysis['candidates'] if c['operation_id']==identity]
            change_ids={candidate['change_id'] for candidate in candidates}
            frozen_refs=references([operation,candidates])
            frozen_keys={record_key(ref) for ref in frozen_refs}
            for name,archive in (('network',self.frozen_network),('process',self.frozen_process)):
                for row in self._analysis[name]:
                    if any(record_key(ref) in frozen_keys for ref in references(row)):
                        archive.setdefault(row['event']['event_id'],deepcopy(row))
            self.closed[identity]={'operation':deepcopy(operation),'candidates':deepcopy(candidates),
                'changes':deepcopy([change for change in self._analysis['changes'] if change['event_id'] in change_ids])}
        self._expire()
        self._analysis=self._judge()
        return before!=(len(self.closed),self._counts['expired'])

    def advance(self, available_at, arrival_seq=None):
        started=time.monotonic()
        if self.phase in ('incomplete','finished'):raise ValueError('replay_is_not_running')
        self._check_clock(available_at,arrival_seq)
        self._settle_due();self._record_metrics()
        snapshot=self._publish('clock_advanced',{'kind':'clock_advance','arrival_seq':self.arrival_seq,'available_at':utc(self.now),'evidence_refs':[]})
        self._runtime.append({'arrival_seq':self.arrival_seq,'operation':'advance','wall_seconds':time.monotonic()-started})
        return snapshot

    def finish(self, available_at):
        self.advance(available_at)
        if any(not operation['replay']['closed'] for operation in self._analysis['operations']):
            self._failure('open_windows_at_finish')
        self.phase='finished';self._analysis=self._judge()
        return self._publish('input_exhausted',{'kind':'input_exhausted','arrival_seq':self.arrival_seq,'available_at':utc(self.now),'evidence_refs':[]})

    def _record_metrics(self):
        for row in self._analysis['network']+self._analysis['process']:
            event=row['event'];identity=event['event_id']
            if identity in self._latencies:continue
            interval=row['time']['interval']
            self._latencies[identity]={'event_id':identity,'first_available_at':utc(self.now),
                'event_interval':deepcopy(interval),'latency_seconds':None if interval is None else [self.now-interval[1],self.now-interval[0]],
                'status':'unknown_time' if interval is None else 'computed','evidence_refs':references(event)}
        for candidate in self._analysis['candidates']:
            if candidate['candidate_id'] in self._confirmations:continue
            operation=next(op for op in self._analysis['operations'] if op['operation_id']==candidate['operation_id'])
            interval=operation['time']['interval']
            self._confirmations[candidate['candidate_id']]={'candidate_id':candidate['candidate_id'],'operation_id':operation['operation_id'],
                'first_available_at':utc(self.now),'request_interval':deepcopy(interval),
                'latency_seconds':None if interval is None else [self.now-interval[1],self.now-interval[0]],
                'status':'software_candidate_available_not_causal_confirmation','candidate_state':candidate['state']}
        pending=sum(not op['replay']['closed'] and bool(op['replay']['waiting_for']) for op in self._analysis['operations'])
        self._backlog.append({'arrival_seq':self.arrival_seq,'available_at':utc(self.now),'unit':'records_and_operations',
            'unparsed_records':len({record_key(ref) for item in self.capture_pending for ref in references(item)}),
            'waiting_operations':pending,'prerequisite_waiting_operations':pending,
            'open_window_operations':sum(not operation['replay']['closed'] for operation in self._analysis['operations'])})

    def _publish(self, status, trigger, initial=False):
        if len(self.admitted)>self.parameters['max_buffer_records']:self._failure('buffer_record_limit')
        if self._snapshot_count>=self.parameters['max_snapshots']:self._failure('snapshot_limit')
        state_fingerprint=fingerprint(self._analysis)
        changed=state_fingerprint!=self._last_state_fingerprint and not initial
        revision_number=self._revision_number+(1 if changed else 0)
        snapshot={'schema_version':'1.0.0','synthetic':self.analysis_profile['synthetic'],'replay_version':VERSION,'snapshot_number':self._snapshot_count,
            'available_at':utc(self.now),'arrival_seq':self.arrival_seq,'status':status,'revision_number':revision_number,
            'config_version':self.analysis_profile['config_version'],'config_fingerprint':self.config_fingerprint,
            'semantic_config_fingerprint':self.config_fingerprint,'state_fingerprint':state_fingerprint,
            'trigger':deepcopy(trigger),'analysis':deepcopy(self._analysis)}
        snapshot['snapshot_id']='snapshot-'+fingerprint(snapshot)
        revision=None
        if changed:
            if self._history_count>=self.parameters['max_revisions']:self._failure('revision_limit')
            revision={'schema_version':'1.0.0','synthetic':self.analysis_profile['synthetic'],'replay_version':VERSION,'revision_number':revision_number,
                'old_snapshot_id':self._latest['snapshot_id'] if self._latest else None,'new_snapshot_id':snapshot['snapshot_id'],
                'old_snapshot_number':self._latest['snapshot_number'] if self._latest else None,'new_snapshot_number':snapshot['snapshot_number'],
                'old_state_fingerprint':self._last_state_fingerprint,'new_state_fingerprint':state_fingerprint,
                'available_at':utc(self.now),'trigger':deepcopy(trigger),'config_version':self.analysis_profile['config_version'],
                'config_fingerprint':self.config_fingerprint,'semantic_config_fingerprint':self.config_fingerprint,
                'rule_version':self.analysis_profile['rule_version'],'reason':status,
                'evidence_refs':references([trigger['evidence_refs'],self._analysis])}
            revision['revision_id']='revision-'+fingerprint(revision);validate('ReplayRevision',revision)
        compact=self._history_sink is not None and self.parameters.get('history_format')=='replay-history-checkpoint-delta-2'
        added=0 if compact else len(canonical(snapshot))+1+(len(canonical(revision))+1 if revision else 0)
        if self._output_bytes+added>self.parameters['max_output_bytes']:self._failure('output_byte_limit')
        self._output_bytes+=added;self._revision_number=revision_number
        if self._history_sink is None:
            if revision:self._history.append(revision)
            self._snapshots.append(snapshot)
        else:
            self._history_sink.append(snapshot,revision)
        self._snapshot_count+=1;self._history_count+=revision is not None
        self._latest=snapshot;self._last_state_fingerprint=state_fingerprint
        return deepcopy(snapshot)

    def snapshot(self):return deepcopy(self._latest)
    def snapshots(self):
        if self._history_sink is not None:raise ValueError('spooled_history_requires_indexed_reader')
        return deepcopy(self._snapshots)
    def history(self):
        if self._history_sink is not None:raise ValueError('spooled_history_requires_indexed_reader')
        return deepcopy(self._history)
    def final_result(self):return deepcopy(self._analysis)
    def runtime_metrics(self):return {'unit':'seconds','samples':deepcopy(self._runtime),'excluded_from_semantic_hashes':True}
    def metrics(self):
        values=list(self._latencies.values())
        return {'replay_version':VERSION,'time_basis':self.parameters['arrival_time_basis'],'unit':'seconds',
            'counts':deepcopy(self._counts),'arrival_samples':deepcopy(self._trace),
            'event_latency':{'denominator_definition':'distinct ever-visible network/process event ids, including later retracted observations',
                'denominator_total_events':len(values),'denominator_computable_events':sum(item['status']=='computed' for item in values),'samples':deepcopy(values)},
            'confirmation_latency':{'denominator_candidates':len(self._confirmations),'samples':deepcopy(list(self._confirmations.values()))},
            'backlog':{'samples':deepcopy(self._backlog),'definition':'arrived unparsed records, unmet response/process prerequisites, and all still-open operation windows; excludes future scheduled arrivals',
                'waiting_operations_alias':'prerequisite_waiting_operations',
                'field_units':{'unparsed_records':'records','waiting_operations':'operations','prerequisite_waiting_operations':'operations','open_window_operations':'operations'}},
            'discarded':deepcopy(self.discarded)}
