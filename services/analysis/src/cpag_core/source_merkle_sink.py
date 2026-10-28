"""Versioned, source-computed DAG6 roots without a second physical database.

This is not a reader and never accepts an expected artifact root as an answer.
Every typed value is supplied by the complete source execution. It shares the
producer's hashing/chunking rules, while retaining only digest/extent metadata.
Original inventory/byte/schema checks remain the verifier's responsibility.
"""
from collections import OrderedDict
from contextlib import contextmanager
import hashlib
import struct
import sys

from . import shared_artifact_store as base
from . import shared_artifact_store_compressed as previous
from .shared_artifact_store_compact import FORMAT,LogicalHasher,KINDS
from .pipeline import canonical
from .replay_history import _digest
from .measurement import phase

STRATEGY_VERSION='dag6-full-source-merkle-sink-1'
_METADATA=struct.Struct('>QIBB')
# An exact audit index, not a value cache. The published node ceiling remains
# unchanged; its RAM also stays inside the existing process/cgroup quota.
MAX_INDEX_BYTES=2*1024**3


class TypedMerkleSourceSink(LogicalHasher):
    def __init__(self,*,context=None,version=STRATEGY_VERSION,max_bytes=1024**3,
                 max_nodes=8000000,max_roots=160000,max_node_bytes=8*1024**2,
                 max_array_items=500000,max_depth=64,cache_entries=4096,
                 max_logical_root_bytes=512*1024**3,deadline=None):
        if version!=STRATEGY_VERSION:raise ValueError('explicit_source_merkle_strategy_required')
        if context is not None:base._context(context)
        self.context=None if context is None else dict(context)
        self.version=FORMAT;self.verification_strategy=STRATEGY_VERSION
        self.limits=dict(max_bytes=max_bytes,max_nodes=max_nodes,max_roots=max_roots,
            max_node_bytes=max_node_bytes,max_array_items=max_array_items,max_depth=max_depth,
            cache_entries=cache_entries,max_dict_items=4096,
            max_logical_root_bytes=max_logical_root_bytes,cache_bytes=16*1024**2)
        previous._limits(self.limits,max_logical_bytes=4*1024**5)
        base._deadline(deadline)
        self.deadline=deadline;self.stable=False
        self._memo=OrderedDict();self._nodes={};self._roots={}
        self.node_count=0;self.root_count=0
        self._index_entry_bytes=0;self._index_peak_bytes=sys.getsizeof(self._nodes)
        self.failed=False;self.sealed=False;self.closed=False
        self._terminal_report=None

    @contextmanager
    def _operation(self):
        if self.failed or self.sealed or self.closed:raise ValueError('source_sink_not_writable')
        base._deadline(self.deadline)
        self._memo.clear()
        try:yield
        except BaseException:
            self.failed=True
            raise
        finally:self._memo.clear()

    def _put(self,kind,value,size,items,height):
        node=super()._put(kind,value,size,items,height)
        digest=bytes.fromhex(node[0])
        packed=_METADATA.pack(size,items,KINDS.index(kind),height)
        existing=self._nodes.get(digest)
        if existing is not None:
            if existing!=packed:raise ValueError('source_sink_digest_metadata_conflict')
            return node
        if self.node_count>=self.limits['max_nodes']:raise ValueError('shared_node_limit')
        estimate=self._index_entry_bytes+sys.getsizeof(digest)+sys.getsizeof(packed)+sys.getsizeof(self._nodes)
        if estimate>MAX_INDEX_BYTES:raise ValueError('source_sink_audit_index_memory_limit')
        self._nodes[digest]=packed;self.node_count+=1
        self._index_entry_bytes+=sys.getsizeof(digest)+sys.getsizeof(packed)
        self._index_peak_bytes=max(self._index_peak_bytes,self._index_entry_bytes+sys.getsizeof(self._nodes))
        if self._index_peak_bytes>MAX_INDEX_BYTES:raise ValueError('source_sink_audit_index_memory_limit')
        return node

    def _node(self,ref):
        if not _digest(ref):raise ValueError('shared_reference_invalid')
        packed=self._nodes.get(bytes.fromhex(ref))
        if packed is None:raise ValueError('source_sink_reference_not_computed')
        size,items,kind,height=_METADATA.unpack(packed)
        return ref,size,items,KINDS[kind],height

    def _name_available(self,name):
        base._name(name)
        if name in self._roots:raise ValueError('shared_root_already_exists')
        if self.root_count>=self.limits['max_roots']:raise ValueError('shared_root_limit')

    def _root(self,name,node):
        self._roots[name]=node[0];self.root_count+=1
        return self._descriptor(node,name)

    @staticmethod
    def _descriptor(node,name=None):
        result={'digest':node[0],'logical_bytes':node[1],'items':node[2],'kind':node[3]}
        if name is not None:result['name']=name
        return result

    @phase('source_merkle_root_rebuild')
    def intern(self,value):
        with self._operation():return self._descriptor(self._encode(value,0,set()))

    @phase('source_merkle_root_rebuild')
    def add(self,name,value):
        with self._operation():
            self._name_available(name)
            return self._root(name,self._encode(value,0,set()))

    @phase('source_merkle_root_rebuild')
    def compose(self,name,values,references):
        with self._operation():
            if name is not None:self._name_available(name)
            if type(values) is not dict or type(references) is not dict or set(values)&set(references) or len(values)+len(references)>self.limits['max_dict_items']:
                raise ValueError('shared_composition_invalid')
            children={}
            for key,value in values.items():
                if type(key) is not str:raise ValueError('shared_composition_invalid')
                children[key]=self._encode(value,1,set())
            for key,ref in references.items():
                if type(key) is not str:raise ValueError('shared_composition_invalid')
                children[key]=self._node(ref)
            size=2+sum(len(canonical(key))+1+child[1] for key,child in children.items())+max(0,len(children)-1)
            node=self._put('dict',{key:child[0] for key,child in children.items()},size,len(children),1+max((child[4] for child in children.values()),default=0))
            return self._descriptor(node) if name is None else self._root(name,node)

    @phase('source_merkle_root_rebuild')
    def sequence(self,name,references):
        with self._operation():
            if name is not None:self._name_available(name)
            if not isinstance(references,(list,tuple)) or len(references)>self.limits['max_array_items']:
                raise ValueError('shared_array_item_limit')
            nodes=[self._node(ref) for ref in references]
            class ExistingValues:
                def __len__(self):return len(nodes)
                def __iter__(self):return iter(nodes)
            encode=self._encode
            try:
                # Reuse the identical DAG6 ordered chunker on independently
                # computed descriptors. No original-store descriptor is read.
                self._encode=lambda child,depth,active:child
                node=self._array(ExistingValues(),0,set())
            finally:self._encode=encode
            return self._descriptor(node) if name is None else self._root(name,node)

    def alias(self,name,target):
        with self._operation():
            self._name_available(name);base._name(target)
            if target not in self._roots:raise ValueError('shared_alias_target_missing')
            return self._root(name,self._node(self._roots[target]))

    def descriptor(self,name):
        base._deadline(self.deadline);base._name(name)
        if self.closed:raise ValueError('source_sink_closed')
        if name not in self._roots:raise ValueError('shared_root_missing')
        return self._descriptor(self._node(self._roots[name]),name)

    def report(self):
        if self.closed:return dict(self._terminal_report)
        index=hashlib.sha256()
        for name,ref in sorted(self._roots.items()):index.update(canonical([name,ref])+b'\n')
        return {'verification_strategy':STRATEGY_VERSION,'storage_format':FORMAT,
            'status':'failed_source_rebuild' if self.failed else 'source_computed_roots_only_not_publication_or_approval',
            'failed':self.failed,'sealed':self.sealed,
            'node_count':self.node_count,'root_count':self.root_count,
            'roots_index_sha256':index.hexdigest(),'audit_index_owned_bytes':self._index_entry_bytes+sys.getsizeof(self._nodes),
            'audit_index_peak_owned_bytes':self._index_peak_bytes,'audit_index_byte_limit':MAX_INDEX_BYTES,
            'flat_value_cache_owned_bytes':getattr(self,'_flat_value_bytes',0),'limits':dict(self.limits),
            'physical_artifacts_created':0,'physical_quota_check':'retained_original_inventory_must_be_verified_by_caller'}

    def seal(self):
        if self.failed or self.sealed or self.closed or not self.root_count:raise ValueError('source_sink_failed_empty_or_sealed')
        self.sealed=True
        result=self.report();result['logical_artifacts']=[self.descriptor(name) for name in sorted(self._roots)]
        return result

    def close(self):
        if self.closed:return
        self._terminal_report=self.report()
        self._memo.clear();self._nodes.clear();self._roots.clear()
        if hasattr(self,'_flat_values'):self._flat_values.clear();self._flat_value_bytes=0
        self.closed=True
