"""Opt-in DAG6 replay storage using the unchanged arrived-prefix rule engine.

Logical state/snapshot identities use the complete typed Merkle value. They are
not legacy canonical-JSON hashes. Every snapshot and revision remains indexed.
"""
from copy import deepcopy

from .capacity import COMPACT, COMPACT_FORMAT, resolve_capacity_profile
from .contracts import validate
from .measurement import phase
from .dual_source import references, utc
from .replay_core import ReplayCore, VERSION
from .replay_history import HistorySink


class CompactHistorySink(HistorySink):
    def __init__(self, writer):
        self.writer=writer
        self.snapshots=[]
        self.revisions=[]
        self.last=None

    def bind(self, semantic_config_fingerprint, replay_version):
        self.config_fingerprint=semantic_config_fingerprint
        self.replay_version=replay_version

    def append_descriptors(self, snapshot, revision, metadata):
        self.snapshots.append(snapshot['digest'])
        if revision is not None:self.revisions.append(revision['digest'])
        self.last=metadata

    def seal(self):
        self.writer.sequence('history/snapshots',self.snapshots)
        self.writer.sequence('history/revisions',self.revisions)
        return {'history_format':COMPACT_FORMAT,'identity_strategy':'merkle-json-dag-1',
            'replay_version':self.replay_version,'snapshot_count':len(self.snapshots),
            'revision_count':len(self.revisions),'last_snapshot_id':self.last['snapshot_id'],
            'config_fingerprint':self.config_fingerprint}

    def abort(self):
        # The owning publisher retains failed storage; it never seals it.
        pass


class CompactReplayCore(ReplayCore):
    compact_history=True

    def __init__(self, profile, *, history_sink):
        if resolve_capacity_profile(profile).version!=COMPACT or not isinstance(history_sink,CompactHistorySink):
            raise ValueError('compact_replay_context_required')
        super().__init__(profile,history_sink=history_sink)

    def _collect(self,prefix,*,final=False):
        super()._collect(prefix,final=final)
        self._collection_generation=getattr(self,'_collection_generation',0)+1

    def _judge(self):
        key=(self.now_exact,self.phase,getattr(self,'_collection_generation',0),len(self.closed),
            len(self.admitted),len(self.expired),len(self.conflicts),len(self.seen))
        if getattr(self,'_judgement_key',None)==key:return self._judgement_value
        result=super()._judge()
        self._judgement_key=key;self._judgement_value=result
        return result

    def _merge_frozen(self,result):
        # Match legacy insertion order: live values followed by closed insertion
        # order; change definitions use first occurrence, never overwrite.
        result['operations']=[op for op in result['operations'] if op['operation_id'] not in self.closed]
        result['candidates']=[c for c in result['candidates'] if c['operation_id'] not in self.closed]
        changes={change['event_id']:change for change in result['changes']}
        for frozen in self.closed.values():
            result['operations'].append(frozen['operation'])
            result['candidates'].extend(frozen['candidates'])
            for change in frozen['changes']:changes.setdefault(change['event_id'],change)
        result['changes']=list(changes.values())

    @phase('history_generation')
    def _publish(self,status,trigger,initial=False):
        if len(self.admitted)>self.parameters['max_buffer_records']:self._failure('buffer_record_limit')
        if self._snapshot_count>=self.parameters['max_snapshots']:self._failure('snapshot_limit')
        writer=self._history_sink.writer
        state=writer.intern(self._analysis)
        state_fingerprint=state['digest']
        changed=state_fingerprint!=self._last_state_fingerprint and not initial
        revision_number=self._revision_number+int(changed)
        snapshot={'schema_version':'1.0.0','synthetic':self.analysis_profile['synthetic'],'replay_version':VERSION,
            'snapshot_number':self._snapshot_count,'available_at':utc(self.now),'arrival_seq':self.arrival_seq,
            'status':status,'revision_number':revision_number,'config_version':self.analysis_profile['config_version'],
            'config_fingerprint':self.config_fingerprint,'semantic_config_fingerprint':self.config_fingerprint,
            'state_fingerprint':state_fingerprint,'trigger':deepcopy(trigger)}
        fields={'analysis':state['digest']}
        if self.parameters.get('standard_projection')=='standard-graph-events-1':
            from .dual_source_export import event_graph
            projection=event_graph(self._analysis,replay=True,identity_strategy='merkle-json-dag-1')
            fields['graph']=writer.intern(projection['graph.json'])['digest']
            fields['events']=writer.intern(projection['events.json'])['digest']
        identity=writer.compose(None,snapshot,fields)
        snapshot['snapshot_id']='snapshot-'+identity['digest']
        snapshot_ref=writer.compose(None,snapshot,fields)
        revision_ref=None
        if changed:
            if self._history_count>=self.parameters['max_revisions']:self._failure('revision_limit')
            revision={'schema_version':'1.0.0','synthetic':self.analysis_profile['synthetic'],'replay_version':VERSION,
                'revision_number':revision_number,'old_snapshot_id':self._latest['snapshot_id'] if self._latest else None,
                'new_snapshot_id':snapshot['snapshot_id'],'old_snapshot_number':self._latest['snapshot_number'] if self._latest else None,
                'new_snapshot_number':snapshot['snapshot_number'],'old_state_fingerprint':self._last_state_fingerprint,
                'new_state_fingerprint':state_fingerprint,'available_at':utc(self.now),'trigger':deepcopy(trigger),
                'config_version':self.analysis_profile['config_version'],'config_fingerprint':self.config_fingerprint,
                'semantic_config_fingerprint':self.config_fingerprint,'rule_version':self.analysis_profile['rule_version'],
                'reason':status,'evidence_refs':references([trigger['evidence_refs'],self._analysis])}
            revision['revision_id']='revision-'+writer.intern(revision)['digest']
            validate('ReplayRevision',revision)
            revision_ref=writer.intern(revision)
        self._history_sink.append_descriptors(snapshot_ref,revision_ref,snapshot)
        self._revision_number=revision_number
        self._snapshot_count+=1;self._history_count+=int(changed)
        self._latest=snapshot;self._last_state_fingerprint=state_fingerprint
        return deepcopy(snapshot)

    def final_result(self):
        # Export consumes immutable final values before the engine is discarded.
        return self._analysis


def execute_compact(networks,process,config,writer,deadline=None):
    from .replay_export import execute
    sink=CompactHistorySink(writer)
    run=execute(networks,process,config,history_sink=sink,_core_class=CompactReplayCore)
    run['history']=run.pop('history_spool')
    return run
