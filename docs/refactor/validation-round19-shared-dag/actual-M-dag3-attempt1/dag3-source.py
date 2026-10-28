"""Isolated shared-observation-dag-3 prototype, not a core/service publisher.

Recursive typed nodes share nested evidence/counterevidence across offline,
replay, graph and history roots. Existing storage/readers remain untouched.
Canonical hashes walk the complete logical JSON without materializing it.
No source independence, prefix semantics or publication/ACL authority is proved
by this storage codec; future integration must supply those existing gates.
"""
from collections import OrderedDict
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import quote

from .dual_source import strict_json
from .pipeline import canonical, file_hash
from .replay_history import _ordinary, _digest

FORMAT = 'shared-observation-dag-3'
STATUS = 'sealed_store_source_unverified'
BRANCH = 64
MAX_PHYSICAL_BYTES = 1024**3
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')


def _name(value):
    if not isinstance(value,str) or not NAME.fullmatch(value) or any(part in ('','..','.') for part in value.split('/')):
        raise ValueError('shared_logical_name_invalid')
    return value


def _int(value,low,high):
    return type(value) is int and low<=value<=high


def _context(value):
    if not isinstance(value,dict) or set(value)!={'run_id','attempt_id','input_fingerprint','config_fingerprint'}:
        raise ValueError('shared_context_invalid')
    if not isinstance(value['run_id'],str) or not 1<=len(value['run_id'])<=128 or not _int(value['attempt_id'],1,1000000):
        raise ValueError('shared_context_invalid')
    if any(not _digest(value[key]) for key in ('input_fingerprint','config_fingerprint')):raise ValueError('shared_context_invalid')


def _hash(kind,payload,size,items,height):
    # Paging extents and heights are authenticated, not untrusted SQLite hints.
    return hashlib.sha256((FORMAT+'\0'+kind+'\0').encode()+canonical([size,items,height])+b'\0'+payload).hexdigest()


def _deadline(deadline):
    if deadline is not None and time.monotonic()>=deadline:raise ValueError('shared_store_deadline_exceeded')


def _limits(value):
    bounds={'max_bytes':(256*1024,MAX_PHYSICAL_BYTES),'max_nodes':(1,2000000),
            'max_roots':(1,160000),'max_node_bytes':(1,8*1024**2),'max_array_items':(1,500000),
            'max_depth':(1,64),'cache_entries':(1,4096)}
    if not isinstance(value,dict) or set(value)!=set(bounds) or any(not _int(value[key],*bounds[key]) for key in bounds):
        raise ValueError('shared_limits_invalid')


class SharedArtifactWriter:
    def __init__(self,root,*,context,version,max_bytes=MAX_PHYSICAL_BYTES,max_nodes=2000000,
                 max_roots=160000,max_node_bytes=8*1024**2,max_array_items=500000,
                 max_depth=64,cache_entries=4096,deadline=None):
        if version!=FORMAT:raise ValueError('explicit_shared_format_required')
        _context(context)
        self.limits=dict(max_bytes=max_bytes,max_nodes=max_nodes,max_roots=max_roots,max_node_bytes=max_node_bytes,
                         max_array_items=max_array_items,max_depth=max_depth,cache_entries=cache_entries)
        _limits(self.limits);_deadline(deadline)
        self.root=Path(root).absolute()
        if self.root.exists() or self.root.is_symlink():raise ValueError('shared_output_must_be_new')
        self.root.mkdir(mode=0o700,parents=True)
        self.context=dict(context);self.deadline=deadline
        self.connection=sqlite3.connect(self.root/'shared.sqlite3')
        self.connection.execute('PRAGMA page_size=4096')
        self.connection.execute('PRAGMA max_page_count='+str((max_bytes-65536)//4096))
        self.connection.execute('PRAGMA journal_mode=DELETE')
        self.connection.execute('PRAGMA synchronous=FULL')
        self.connection.execute('PRAGMA cache_size=-2048')
        self.connection.execute('CREATE TABLE nodes(digest TEXT PRIMARY KEY,kind TEXT NOT NULL,payload BLOB NOT NULL,logical_bytes INTEGER NOT NULL,items INTEGER NOT NULL,height INTEGER NOT NULL) WITHOUT ROWID')
        self.connection.execute('CREATE TABLE roots(name TEXT PRIMARY KEY,digest TEXT NOT NULL) WITHOUT ROWID')
        self.connection.commit()
        self.node_count=self.root_count=0
        self.failed=self.sealed=False
        self._recent=OrderedDict();self._memo=OrderedDict()

    def close(self):
        if self.connection is not None:self.connection.close();self.connection=None

    def _put(self,kind,value,size,items,height):
        _deadline(self.deadline)
        if not _int(size,1,2**63-1) or not _int(items,0,500000) or not _int(height,0,self.limits['max_depth']+8):raise ValueError('shared_logical_extent_invalid')
        payload=canonical(value)
        if len(payload)>self.limits['max_node_bytes']:raise ValueError('shared_node_byte_limit')
        digest=_hash(kind,payload,size,items,height)
        if digest not in self._recent:
            cursor=self.connection.execute('INSERT OR IGNORE INTO nodes VALUES(?,?,?,?,?,?)',(digest,kind,payload,size,items,height))
            if cursor.rowcount:
                self.node_count+=1
                if self.node_count>self.limits['max_nodes']:raise ValueError('shared_node_limit')
            self._recent[digest]=None
            if len(self._recent)>self.limits['cache_entries']:self._recent.popitem(last=False)
        else:self._recent.move_to_end(digest)
        return digest,size,items,kind,height

    def _array(self,values,depth,active):
        if len(values)>self.limits['max_array_items']:raise ValueError('shared_array_item_limit')
        nodes=[];refs=[];size=2;height=0
        for value in values:
            child=self._encode(value,depth+1,active)
            if refs:size+=1
            refs.append(child[0]);size+=child[1];height=max(height,child[4])
            if len(refs)==BRANCH:nodes.append(self._put('array_leaf',refs,size,len(refs),height+1));refs=[];size=2;height=0
        if refs or not nodes:nodes.append(self._put('array_leaf',refs,size,len(refs),height+1))
        while len(nodes)>1:
            level=[]
            for index in range(0,len(nodes),BRANCH):
                children=nodes[index:index+BRANCH]
                if len(children)==1:level.append(children[0]);continue
                total=sum(child[2] for child in children)
                logical=2+sum(child[1]-2 for child in children)+len(children)-1
                level.append(self._put('array_branch',[child[0] for child in children],logical,total,1+max(child[4] for child in children)))
            nodes=level
        return nodes[0]

    def _encode(self,value,depth,active):
        if depth>self.limits['max_depth']:raise ValueError('shared_depth_limit')
        if value is None or type(value) in (str,int,float,bool):
            if type(value) is float and not math.isfinite(value):raise ValueError('shared_nonfinite_number')
            payload=canonical(value)
            return self._put('scalar',value,len(payload),0,0)
        if type(value) not in (dict,list,tuple):raise ValueError('shared_json_type_invalid')
        identity=id(value)
        if identity in active:raise ValueError('shared_cycle_forbidden')
        # Scoped to one synchronous root write; discarded before a later write
        # so object mutation or Python id reuse cannot turn into a stale root.
        cached=self._memo.get(identity)
        if cached is not None and cached[0] is value:
            self._memo.move_to_end(identity);return cached[1]
        active.add(identity)
        try:
            if type(value) in (list,tuple):node=self._array(value,depth,active)
            else:
                if any(type(key) is not str for key in value):raise ValueError('shared_json_key_invalid')
                refs={};size=2;height=0
                for key in sorted(value):
                    child=self._encode(value[key],depth+1,active)
                    if refs:size+=1
                    refs[key]=child[0];size+=len(canonical(key))+1+child[1];height=max(height,child[4])
                node=self._put('dict',refs,size,len(refs),height+1)
        finally:active.remove(identity)
        self._memo[identity]=(value,node)
        if len(self._memo)>self.limits['cache_entries']:self._memo.popitem(last=False)
        return node

    def add(self,name,value):
        _name(name)
        if self.failed or self.sealed:raise ValueError('shared_writer_not_writable')
        try:
            if self.root_count>=self.limits['max_roots']:raise ValueError('shared_root_limit')
            if self.connection.execute('SELECT 1 FROM roots WHERE name=?',(name,)).fetchone():raise ValueError('shared_root_already_exists')
            self._memo.clear()
            node=self._encode(value,0,set())
            self.connection.execute('INSERT INTO roots VALUES(?,?)',(name,node[0]))
            self.connection.commit();self.root_count+=1
            return {'name':name,'digest':node[0],'logical_bytes':node[1],'items':node[2],'kind':node[3]}
        except BaseException as error:
            self.failed=True
            try:self.connection.rollback()
            finally:self.close()
            if isinstance(error,sqlite3.Error):raise ValueError('shared_storage_failed:'+getattr(error,'sqlite_errorname','SQLITE_ERROR')) from error
            raise
        finally:self._memo.clear()

    def seal(self):
        if self.failed or self.sealed or not self.root_count:raise ValueError('shared_failed_empty_or_sealed')
        digest=hashlib.sha256()
        for name,ref in self.connection.execute('SELECT name,digest FROM roots ORDER BY name'):
            digest.update(canonical([name,ref])+b'\n')
        self.close()
        database=self.root/'shared.sqlite3'
        manifest={'version':FORMAT,'status':STATUS,'context':self.context,'limits':self.limits,
                  'database':{'path':'shared.sqlite3','sha256':file_hash(database),'size_bytes':database.stat().st_size},
                  'root_count':self.root_count,'node_count':self.node_count,'roots_index_sha256':digest.hexdigest()}
        raw=canonical(manifest)+b'\n'
        if len(raw)>65536 or database.stat().st_size+len(raw)>self.limits['max_bytes']:
            self.failed=True;raise ValueError('shared_physical_byte_limit')
        with (self.root/'manifest.json').open('xb') as stream:stream.write(raw)
        self.sealed=True
        return {'manifest':manifest,'manifest_sha256':hashlib.sha256(raw).hexdigest()}


class SharedArtifactReader:
    def __init__(self,root,*,expected_manifest_sha256,expected_context=None,deadline=None):
        self.root=Path(root).absolute();self.deadline=deadline
        _deadline(deadline)
        if self.root.is_symlink() or not self.root.is_dir() or {p.name for p in self.root.iterdir()}!={'manifest.json','shared.sqlite3'}:
            raise ValueError('shared_inventory_invalid')
        for name in ('manifest.json','shared.sqlite3'):_ordinary(self.root/name)
        path=self.root/'manifest.json'
        if path.stat().st_size>65536 or not _digest(expected_manifest_sha256) or file_hash(path)!=expected_manifest_sha256:
            raise ValueError('shared_manifest_binding_invalid')
        raw=path.read_bytes();manifest=strict_json(raw.decode())
        if not isinstance(manifest,dict) or set(manifest)!={'version','status','context','limits','database','root_count','node_count','roots_index_sha256'}:
            raise ValueError('shared_manifest_contract_invalid')
        if manifest['version']!=FORMAT or manifest['status']!=STATUS or raw!=canonical(manifest)+b'\n':raise ValueError('shared_manifest_version_or_encoding_invalid')
        _context(manifest['context']);_limits(manifest['limits'])
        if expected_context is not None and manifest['context']!=expected_context:raise ValueError('shared_context_changed')
        db=manifest['database']
        if not isinstance(db,dict) or set(db)!={'path','sha256','size_bytes'} or db['path']!='shared.sqlite3' or not _digest(db['sha256']) or not _int(db['size_bytes'],1,MAX_PHYSICAL_BYTES):raise ValueError('shared_database_contract_invalid')
        if not _int(manifest['root_count'],1,manifest['limits']['max_roots']) or not _int(manifest['node_count'],1,manifest['limits']['max_nodes']) or not _digest(manifest['roots_index_sha256']):raise ValueError('shared_counts_invalid')
        database=self.root/db['path']
        if database.stat().st_size!=db['size_bytes'] or file_hash(database)!=db['sha256'] or database.stat().st_size+len(raw)>manifest['limits']['max_bytes']:
            raise ValueError('shared_database_binding_invalid')
        self.manifest=manifest;self._cache=OrderedDict()
        self.connection=sqlite3.connect('file:'+quote(str(database))+'?mode=ro&immutable=1',uri=True)
        self.connection.execute('PRAGMA query_only=ON');self.connection.execute('PRAGMA trusted_schema=OFF');self.connection.execute('PRAGMA cache_size=-2048')
        try:self.verify()
        except BaseException:self.close();raise

    def close(self):
        if self.connection is not None:self.connection.close();self.connection=None

    def _node(self,ref):
        _deadline(self.deadline)
        if not _digest(ref):raise ValueError('shared_reference_invalid')
        if ref in self._cache:self._cache.move_to_end(ref);return self._cache[ref]
        row=self.connection.execute('SELECT kind,payload,logical_bytes,items,height FROM nodes WHERE digest=?',(ref,)).fetchone()
        if row is None:raise ValueError('shared_node_missing')
        kind,payload,size,items,height=row
        if kind not in ('scalar','dict','array_leaf','array_branch') or not isinstance(payload,bytes) or len(payload)>self.manifest['limits']['max_node_bytes'] or _hash(kind,payload,size,items,height)!=ref or not _int(size,1,2**63-1) or not _int(items,0,500000) or not _int(height,0,self.manifest['limits']['max_depth']+8):raise ValueError('shared_node_invalid')
        value=strict_json(payload.decode())
        if payload!=canonical(value):raise ValueError('shared_node_encoding_invalid')
        if kind=='scalar':
            if type(value) not in (str,int,float,bool,type(None)) or size!=len(payload) or items!=0 or height!=0:raise ValueError('shared_scalar_invalid')
        elif kind=='dict':
            if not isinstance(value,dict) or len(value)!=items or any(not _digest(v) for v in value.values()):raise ValueError('shared_dict_invalid')
        elif not isinstance(value,list) or len(value)>BRANCH or (len(value)<2 and kind=='array_branch') or any(not _digest(v) for v in value):raise ValueError('shared_array_invalid')
        self._cache[ref]=(kind,value,size,items,payload,height)
        if len(self._cache)>self.manifest['limits']['cache_entries']:self._cache.popitem(last=False)
        return self._cache[ref]

    def _extent(self,ref):
        # Local child metadata equations plus strictly decreasing byte extents
        # and heights prove an acyclic DAG without expanding shared subtrees.
        kind,value,size,items,_,height=self._node(ref)
        if kind=='scalar':return
        pairs=list(value.items()) if kind=='dict' else list(enumerate(value))
        children=[(key,self._node(child)) for key,child in pairs]
        if any(child[2]>=size or child[5]>=height for _,child in children):raise ValueError('shared_cycle_or_extent_invalid')
        if kind=='dict':expected=2+sum(len(canonical(key))+1+child[2] for key,child in children)+max(0,len(children)-1);count=len(children)
        elif kind=='array_leaf':expected=2+sum(child[2] for _,child in children)+max(0,len(children)-1);count=len(children)
        else:
            if any(child[0] not in ('array_leaf','array_branch') or child[3]<1 for _,child in children):raise ValueError('shared_branch_kind_invalid')
            expected=2+sum(child[2]-2 for _,child in children)+len(children)-1;count=sum(child[3] for _,child in children)
        if size!=expected or items!=count or height!=1+max((child[5] for _,child in children),default=0) or (kind.startswith('array') and count>self.manifest['limits']['max_array_items']):raise ValueError('shared_extent_invalid')

    def verify(self):
        catalog=set(self.connection.execute('SELECT type,name,tbl_name FROM sqlite_master'))
        if catalog!={('table','nodes','nodes'),('table','roots','roots')}:raise ValueError('shared_database_schema_invalid')
        if self.connection.execute('PRAGMA integrity_check').fetchone()!=('ok',):raise ValueError('shared_database_integrity_invalid')
        for table,key in (('nodes','node_count'),('roots','root_count')):
            if self.connection.execute('SELECT count(*) FROM '+table).fetchone()[0]!=self.manifest[key]:raise ValueError('shared_record_count_invalid')
        for (ref,) in self.connection.execute('SELECT digest FROM nodes'):self._extent(ref)
        digest=hashlib.sha256()
        for name,ref in self.connection.execute('SELECT name,digest FROM roots ORDER BY name'):
            _name(name);self._node(ref);digest.update(canonical([name,ref])+b'\n')
        if digest.hexdigest()!=self.manifest['roots_index_sha256']:raise ValueError('shared_root_index_changed')
        return {'version':FORMAT,'status':'store_integrity_only_source_unverified','root_count':self.manifest['root_count']}

    def descriptor(self,name):
        _name(name);row=self.connection.execute('SELECT digest FROM roots WHERE name=?',(name,)).fetchone()
        if row is None:raise ValueError('shared_root_missing')
        kind,_,size,items,_,_=self._node(row[0])
        return {'name':name,'digest':row[0],'kind':kind,'logical_bytes':size,'items':items}

    def roots(self,*,after='',limit=100):
        if not _int(limit,1,100) or not isinstance(after,str):raise ValueError('shared_root_page_invalid')
        return [self.descriptor(name) for (name,) in self.connection.execute('SELECT name FROM roots WHERE name>? ORDER BY name LIMIT ?',(after,limit))]

    def _array_ref(self,ref,index):
        kind,value,_,items,_,_=self._node(ref)
        if kind not in ('array_leaf','array_branch') or not _int(index,0,items-1):raise ValueError('shared_array_index_invalid')
        if kind=='array_leaf':return value[index]
        for child in value:
            count=self._node(child)[3]
            if index<count:return self._array_ref(child,index)
            index-=count
        raise ValueError('shared_array_extent_invalid')

    def _select(self,name,path):
        if not isinstance(path,(list,tuple)) or len(path)>self.manifest['limits']['max_depth']:raise ValueError('shared_selection_path_invalid')
        ref=self.descriptor(name)['digest']
        for part in path:
            kind,value,_,_,_,_=self._node(ref)
            if kind=='dict' and type(part) is str and part in value:ref=value[part]
            elif kind in ('array_leaf','array_branch') and type(part) is int:ref=self._array_ref(ref,part)
            else:raise ValueError('shared_selection_missing')
        return ref

    def _items(self,ref):
        kind,value,_,_,_,_=self._node(ref)
        if kind=='array_leaf':yield from value
        elif kind=='array_branch':
            for child in value:yield from self._items(child)
        else:raise ValueError('shared_not_array')

    def _chunks(self,ref):
        kind,value,_,_,payload,_=self._node(ref)
        if kind=='scalar':yield payload
        elif kind=='dict':
            yield b'{'
            for index,(key,child) in enumerate(sorted(value.items())):
                if index:yield b','
                yield canonical(key);yield b':';yield from self._chunks(child)
            yield b'}'
        else:
            yield b'['
            for index,child in enumerate(self._items(ref)):
                if index:yield b','
                yield from self._chunks(child)
            yield b']'

    def iter_canonical(self,name,*,path=(),max_bytes):
        if not _int(max_bytes,0,2**63-1):raise ValueError('shared_scan_budget_invalid')
        ref=self._select(name,path);size=self._node(ref)[2]
        if size>max_bytes:raise ValueError('shared_logical_byte_limit')
        seen=0
        for chunk in self._chunks(ref):
            seen+=len(chunk)
            if seen>max_bytes:raise ValueError('shared_logical_byte_limit')
            yield chunk
        if seen!=size:raise ValueError('shared_stream_extent_invalid')

    def canonical_sha256(self,name,*,path=(),max_bytes):
        digest=hashlib.sha256()
        for chunk in self.iter_canonical(name,path=path,max_bytes=max_bytes):digest.update(chunk)
        return digest.hexdigest()

    def get(self,name,*,path=(),max_bytes=8*1024**2):
        return strict_json(b''.join(self.iter_canonical(name,path=path,max_bytes=max_bytes)).decode())

    def page(self,name,*,path=(),offset=0,limit=100,max_bytes=8*1024**2):
        if not _int(offset,0,2**63-1) or not _int(limit,1,100) or not _int(max_bytes,0,8*1024**2):raise ValueError('shared_page_budget_invalid')
        ref=self._select(name,path);kind,_,_,total,_,_=self._node(ref)
        if kind not in ('array_leaf','array_branch'):raise ValueError('shared_page_requires_array')
        items=[];size=2
        for index in range(offset,min(offset+limit,total)):
            child=self._array_ref(ref,index);extent=self._node(child)[2]
            size+=extent+(1 if items else 0)
            if size>max_bytes:raise ValueError('shared_page_byte_limit')
            items.append(strict_json(b''.join(self._chunks(child)).decode()))
        result={'version':FORMAT,'root_digest':self.descriptor(name)['digest'],'path':list(path),'offset':offset,'limit':limit,
                'total':total,'returned':len(items),'has_more':offset+len(items)<total,'items':items}
        if len(canonical(result))>max_bytes:raise ValueError('shared_page_byte_limit')
        return result
