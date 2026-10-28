"""DAG6 core storage: authenticated logical values, compact physical references.

Physical integer IDs have no authority. Each decoded node reconstructs all child
SHA256 references before checking its complete typed Merkle digest. Old prototype
formats/readers are unchanged. Storage integrity alone is never source approval.
"""
from collections import OrderedDict
import hashlib
from pathlib import Path
import sqlite3
from urllib.parse import quote

from . import shared_artifact_store as base
from . import shared_artifact_store_compressed as previous
from .dual_source import strict_json
from .pipeline import canonical, file_hash
from .measurement import phase
from .replay_history import _ordinary, _digest

FORMAT = 'shared-observation-dag-6'
CODEC = 'local-varint-references-1'
SEMANTIC_VERSION = 'merkle-semantic-1'
_APPROVED_READ = object()
VOLATILE = frozenset(('run_id','ingest_time'))
KINDS = ('scalar','dict','array_leaf','array_branch')


def _hash(kind, raw, size, items, height):
    return hashlib.sha256((FORMAT+'\0'+CODEC+'\0'+kind+'\0').encode()+canonical([size,items,height])+b'\0'+raw).hexdigest()


def _varint(value):
    if type(value) is not int or not 0 <= value <= 2**63-1:
        raise ValueError('compact_integer_invalid')
    result = bytearray()
    while value >= 128:
        result.append((value&127)|128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _integer(raw, position):
    start = position
    value = 0
    for offset in range(9):
        if position >= len(raw):
            raise ValueError('compact_integer_truncated')
        current = raw[position]
        position += 1
        value |= (current&127) << (offset*7)
        if current < 128:
            if raw[start:position] != _varint(value):
                raise ValueError('compact_integer_noncanonical')
            return value,position
    raise ValueError('compact_integer_invalid')


def _physical(kind, value, ids):
    if kind == 'scalar':
        return canonical(value)
    parts = [_varint(len(value))]
    if kind == 'dict':
        for key,ref in sorted(value.items()):
            raw = key.encode('utf-8')
            parts.extend((_varint(len(raw)),raw,_varint(ids[ref])))
    else:
        parts.extend(_varint(ids[ref]) for ref in value)
    return b''.join(parts)


def _physical_decode(kind, raw):
    if kind == 'scalar':
        value = strict_json(raw.decode())
        if canonical(value) != raw or type(value) not in (str,int,float,bool,type(None)):
            raise ValueError('compact_scalar_encoding_invalid')
        return value,[]
    count,position = _integer(raw,0)
    if count > (previous.MAX_DICT_ITEMS if kind=='dict' else base.BRANCH):
        raise ValueError('compact_collection_limit')
    rows = []
    ids = []
    last = None
    for _ in range(count):
        if kind == 'dict':
            length,position = _integer(raw,position)
            if position+length > len(raw):
                raise ValueError('compact_key_truncated')
            key = raw[position:position+length].decode()
            position += length
            if last is not None and key <= last:
                raise ValueError('compact_key_order_invalid')
            last = key
        identity,position = _integer(raw,position)
        if identity < 1:
            raise ValueError('compact_child_identity_invalid')
        ids.append(identity)
        rows.append((key,identity) if kind=='dict' else identity)
    if position != len(raw):
        raise ValueError('compact_node_trailing_bytes')
    return (dict(rows) if kind=='dict' else rows),ids


class LogicalHasher(previous.SharedArtifactWriter):
    """Complete typed-value digest without a database or logical serialization."""
    def __init__(self, *, limits=None, deadline=None, stable=False):
        self.version = FORMAT
        self.limits = limits or dict(max_bytes=1024**3,max_nodes=8000000,max_roots=160000,
            max_node_bytes=8*1024**2,max_array_items=500000,max_depth=64,cache_entries=4096,
            max_dict_items=4096,max_logical_root_bytes=512*1024**3,cache_bytes=16*1024**2)
        previous._limits(self.limits)
        self.deadline = deadline
        self.stable = stable
        self._memo = OrderedDict()

    def _put(self,kind,value,size,items,height):
        base._deadline(self.deadline)
        if not base._int(size,1,self.limits['max_logical_root_bytes']) or not base._int(items,0,self.limits['max_array_items']) or not base._int(height,0,self.limits['max_depth']+8):
            raise ValueError('shared_logical_extent_invalid')
        raw = previous._pack(kind,value)
        if len(raw)>self.limits['max_node_bytes']:
            raise ValueError('shared_node_byte_limit')
        return _hash(kind,raw,size,items,height),size,items,kind,height

    def _encode(self,value,depth,active):
        if self.stable and isinstance(value,dict) and set(value)&VOLATILE:
            value = {key:child for key,child in value.items() if key not in VOLATILE}
        return super()._encode(value,depth,active)

    def digest(self,value):
        self._memo.clear()
        try:
            node = self._encode(value,0,set())
            return {'digest':node[0],'logical_bytes':node[1],'items':node[2],'kind':node[3]}
        finally:
            self._memo.clear()


class SharedArtifactWriter(previous.SharedArtifactWriter):
    def __init__(self,root,*,context,version,**kwargs):
        if version != FORMAT:
            raise ValueError('explicit_compact_format_required')
        super().__init__(root,context=context,version=previous.CONTENT_FORMAT,**kwargs)
        self.version = FORMAT
        self.connection.execute('DROP TABLE nodes')
        self.connection.execute('DROP TABLE roots')
        # Integer primary table avoids 32-byte references in every nested array.
        self.connection.execute('CREATE TABLE nodes(id INTEGER PRIMARY KEY,digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32),kind TEXT NOT NULL,payload BLOB NOT NULL,logical_bytes INTEGER NOT NULL,items INTEGER NOT NULL,height INTEGER NOT NULL)')
        self.connection.execute('CREATE TABLE roots(name TEXT PRIMARY KEY,digest BLOB NOT NULL CHECK(length(digest)=32)) WITHOUT ROWID')
        self.connection.commit()
        self._ids = OrderedDict()

    @phase('compact_store_write')
    def add(self,*args,**kwargs):return super().add(*args,**kwargs)

    @phase('compact_store_write')
    def intern(self,*args,**kwargs):return super().intern(*args,**kwargs)

    @phase('compact_store_write')
    def compose(self,*args,**kwargs):return super().compose(*args,**kwargs)

    def _identity(self,ref):
        if ref in self._ids:
            self._ids.move_to_end(ref)
            return self._ids[ref]
        row = self.connection.execute('SELECT id FROM nodes WHERE digest=?',(bytes.fromhex(ref),)).fetchone()
        if row is None:
            raise ValueError('compact_child_missing')
        self._ids[ref] = row[0]
        if len(self._ids)>self.limits['cache_entries']:
            self._ids.popitem(last=False)
        return row[0]

    def _put(self,kind,value,size,items,height):
        base._deadline(self.deadline)
        if not base._int(size,1,self.limits['max_logical_root_bytes']) or not base._int(items,0,self.limits['max_array_items']) or not base._int(height,0,self.limits['max_depth']+8):
            raise ValueError('shared_logical_extent_invalid')
        raw = previous._pack(kind,value)
        if len(raw)>self.limits['max_node_bytes']:
            raise ValueError('shared_node_byte_limit')
        ref = _hash(kind,raw,size,items,height)
        if ref not in self._recent:
            found = self.connection.execute('SELECT id FROM nodes WHERE digest=?',(bytes.fromhex(ref),)).fetchone()
            if found is None:
                refs = value.values() if kind=='dict' else value if kind!='scalar' else ()
                ids = {child:self._identity(child) for child in refs}
                payload = previous._store(_physical(kind,value,ids))
                cursor = self.connection.execute('INSERT INTO nodes(digest,kind,payload,logical_bytes,items,height) VALUES(?,?,?,?,?,?)',
                    (bytes.fromhex(ref),kind,payload,size,items,height))
                identity = cursor.lastrowid
                self.node_count += 1
                if self.node_count>self.limits['max_nodes']:
                    raise ValueError('shared_node_limit')
            else:
                identity = found[0]
            self._ids[ref] = identity
            self._ids.move_to_end(ref)
            if len(self._ids)>self.limits['cache_entries']:
                self._ids.popitem(last=False)
            self._recent[ref] = None
            if len(self._recent)>self.limits['cache_entries']:
                self._recent.popitem(last=False)
        else:
            self._recent.move_to_end(ref)
        return ref,size,items,kind,height

    def descriptor(self,name):
        base._name(name)
        row=self.connection.execute('SELECT n.digest,n.logical_bytes,n.items,n.kind FROM roots r JOIN nodes n ON n.digest=r.digest WHERE r.name=?',(name,)).fetchone()
        if row is None:raise ValueError('shared_root_missing')
        return {'name':name,'digest':row[0].hex(),'logical_bytes':row[1],'items':row[2],'kind':row[3]}

    @phase('compact_store_write')
    def sequence(self,name,references):
        if self.failed or self.sealed:raise ValueError('shared_writer_not_writable')
        try:return self._sequence(name,references)
        except BaseException as error:
            self.failed=True
            if self.connection is not None:
                self.connection.rollback();self.close()
            if isinstance(error,sqlite3.Error):raise ValueError('shared_storage_failed:'+getattr(error,'sqlite_errorname','SQLITE_ERROR')) from error
            raise

    def _sequence(self,name,references):
        """Complete ordered array of committed nodes, without decoding values."""
        if len(references)>self.limits['max_array_items']:
            raise ValueError('shared_array_item_limit')
        nodes=[]
        for ref in references:
            if not _digest(ref):
                raise ValueError('shared_reference_invalid')
            row=self.connection.execute('SELECT logical_bytes,items,kind,height FROM nodes WHERE digest=?',(bytes.fromhex(ref),)).fetchone()
            if row is None:
                raise ValueError('compact_child_missing')
            nodes.append((ref,*row))
        class ExistingValues:
            def __len__(self):return len(nodes)
            def __iter__(self):return iter(nodes)
        # Run the same ordered chunker; values here are already authenticated
        # committed descriptors, not user JSON and not an external trust switch.
        original=self._encode
        try:
            self._encode=lambda child,depth,active:child
            node=self._array(ExistingValues(),0,set())
        finally:
            self._encode=original
        if name is None:
            self.connection.commit()
            return {'digest':node[0],'logical_bytes':node[1],'items':node[2],'kind':node[3]}
        # Compose a temporary dictionary is unnecessary; root the array directly.
        base._name(name)
        if self.root_count>=self.limits['max_roots']:
            raise ValueError('shared_root_limit')
        try:
            self.connection.execute('INSERT INTO roots VALUES(?,?)',(name,bytes.fromhex(node[0])))
            self.connection.commit()
            self.root_count+=1
        except sqlite3.Error as error:
            self.failed=True;self.connection.rollback();self.close()
            raise ValueError('shared_sequence_root_failed') from error
        return {'name':name,'digest':node[0],'logical_bytes':node[1],'items':node[2],'kind':node[3]}

    def seal(self):
        if self.failed or self.sealed or not self.root_count:
            raise ValueError('shared_failed_empty_or_sealed')
        index=hashlib.sha256()
        for name,ref in self.connection.execute('SELECT name,digest FROM roots ORDER BY name'):
            index.update(canonical([name,ref.hex()])+b'\n')
        self.close()
        database=self.root/'shared.sqlite3'
        manifest={'version':FORMAT,'codec':CODEC,'status':base.STATUS,'context':self.context,'limits':self.limits,
            'database':{'path':'shared.sqlite3','sha256':file_hash(database),'size_bytes':database.stat().st_size},
            'root_count':self.root_count,'node_count':self.node_count,'roots_index_sha256':index.hexdigest()}
        raw=canonical(manifest)+b'\n'
        if len(raw)>65536 or database.stat().st_size+len(raw)>self.limits['max_bytes']:
            self.failed=True;raise ValueError('shared_physical_byte_limit')
        with (self.root/'manifest.json').open('xb') as stream:stream.write(raw)
        self.sealed=True
        return {'manifest':manifest,'manifest_sha256':hashlib.sha256(raw).hexdigest()}


class SharedArtifactReader(previous.SharedArtifactReader):
    def __init__(self,root,*,expected_manifest_sha256,expected_context=None,deadline=None,_approval_token=None):
        self.root=Path(root).absolute();self.deadline=deadline
        base._deadline(deadline)
        if self.root.is_symlink() or not self.root.is_dir() or {p.name for p in self.root.iterdir()}!={'manifest.json','shared.sqlite3'}:
            raise ValueError('shared_inventory_invalid')
        for name in ('manifest.json','shared.sqlite3'):_ordinary(self.root/name)
        path=self.root/'manifest.json'
        if path.stat().st_size>65536 or not _digest(expected_manifest_sha256) or file_hash(path)!=expected_manifest_sha256:
            raise ValueError('shared_manifest_binding_invalid')
        raw=path.read_bytes();manifest=strict_json(raw.decode())
        if not isinstance(manifest,dict) or set(manifest)!={'version','codec','status','context','limits','database','root_count','node_count','roots_index_sha256'}:
            raise ValueError('shared_manifest_contract_invalid')
        if manifest['version']!=FORMAT or manifest['codec']!=CODEC or manifest['status']!=base.STATUS or raw!=canonical(manifest)+b'\n':
            raise ValueError('shared_manifest_version_or_encoding_invalid')
        base._context(manifest['context']);previous._limits(manifest['limits'])
        if expected_context is not None and manifest['context']!=expected_context:
            raise ValueError('shared_context_changed')
        db=manifest['database']
        if not isinstance(db,dict) or set(db)!={'path','sha256','size_bytes'} or db['path']!='shared.sqlite3' or not _digest(db['sha256']) or not base._int(db['size_bytes'],1,base.MAX_PHYSICAL_BYTES):
            raise ValueError('shared_database_contract_invalid')
        if not base._int(manifest['root_count'],1,manifest['limits']['max_roots']) or not base._int(manifest['node_count'],1,manifest['limits']['max_nodes']) or not _digest(manifest['roots_index_sha256']):
            raise ValueError('shared_counts_invalid')
        database=self.root/db['path']
        if database.stat().st_size!=db['size_bytes'] or file_hash(database)!=db['sha256'] or database.stat().st_size+len(raw)>manifest['limits']['max_bytes']:
            raise ValueError('shared_database_binding_invalid')
        self.version=FORMAT;self.manifest=manifest;self._cache=OrderedDict();self._cache_sizes={};self._cache_bytes=0
        self.connection=sqlite3.connect('file:'+quote(str(database))+'?mode=ro&immutable=1',uri=True)
        self.connection.execute('PRAGMA query_only=ON');self.connection.execute('PRAGMA trusted_schema=OFF');self.connection.execute('PRAGMA cache_size=-2048')
        try:
            if _approval_token is not _APPROVED_READ:self.verify()
        except BaseException:self.close();raise

    def _decode(self,row):
        identity,ref,kind,stored,size,items,height=row
        if type(identity) is not int or identity<1 or not isinstance(ref,bytes) or len(ref)!=32 or kind not in KINDS or not base._int(size,1,self.manifest['limits']['max_logical_root_bytes']) or not base._int(items,0,self.manifest['limits']['max_array_items']) or not base._int(height,0,self.manifest['limits']['max_depth']+8):
            raise ValueError('compact_node_invalid')
        physical=previous._load(stored,self.manifest['limits']['max_node_bytes'])
        value,ids=_physical_decode(kind,physical)
        children={}
        if ids:
            unique=list(set(ids))
            if any(child>=identity for child in unique):
                raise ValueError('compact_child_not_preceding_parent')
            placeholders=','.join('?' for _ in unique)
            children={child[0]:child for child in self.connection.execute('SELECT id,digest,logical_bytes,items,kind,height FROM nodes WHERE id IN ('+placeholders+')',unique)}
            if len(children)!=len(unique):
                raise ValueError('compact_child_missing')
            if any(not isinstance(child[1],bytes) or len(child[1])!=32 for child in children.values()):
                raise ValueError('compact_child_digest_invalid')
            value={key:children[child][1].hex() for key,child in value.items()} if kind=='dict' else [children[child][1].hex() for child in value]
        logical=previous._pack(kind,value)
        if len(logical)>self.manifest['limits']['max_node_bytes'] or _hash(kind,logical,size,items,height)!=ref.hex():
            raise ValueError('compact_node_authentication_failed')
        if kind=='scalar':
            if size!=len(logical) or items!=0 or height!=0:
                raise ValueError('shared_scalar_invalid')
        else:
            if kind=='dict':
                expected=2+sum(len(canonical(key))+1+children[child][2] for key,child in _physical_decode(kind,physical)[0].items())+max(0,len(ids)-1)
                count=len(ids)
            elif kind=='array_leaf':
                expected=2+sum(children[child][2] for child in ids)+max(0,len(ids)-1);count=len(ids)
            else:
                if len(ids)<2 or any(children[child][4] not in ('array_leaf','array_branch') or children[child][3]<1 for child in ids):
                    raise ValueError('shared_branch_kind_invalid')
                expected=2+sum(children[child][2]-2 for child in ids)+len(ids)-1;count=sum(children[child][3] for child in ids)
            if expected!=size or items!=count or height!=1+max((child[5] for child in children.values()),default=0) or any(child[2]>=size or child[5]>=height for child in children.values()):
                raise ValueError('shared_extent_invalid')
        return kind,value,size,items,(logical if kind=='scalar' else b''),height

    def _node(self,ref):
        base._deadline(self.deadline)
        if isinstance(ref,bytes) and len(ref)==32:ref=ref.hex()
        if not _digest(ref):raise ValueError('shared_reference_invalid')
        if ref in self._cache:
            self._cache.move_to_end(ref);return self._cache[ref]
        row=self.connection.execute('SELECT id,digest,kind,payload,logical_bytes,items,height FROM nodes WHERE digest=?',(bytes.fromhex(ref),)).fetchone()
        if row is None:raise ValueError('shared_node_missing')
        node=self._decode(row)
        weight=previous._memory(node)+previous._memory(ref)+256
        if weight<=previous.CACHE_BYTES:
            while self._cache and (self._cache_bytes+weight>previous.CACHE_BYTES or len(self._cache)>=self.manifest['limits']['cache_entries']):
                old,_=self._cache.popitem(last=False);self._cache_bytes-=self._cache_sizes.pop(old)
            self._cache[ref]=node;self._cache_sizes[ref]=weight;self._cache_bytes+=weight
        return node

    @phase('compact_node_verification')
    def verify(self):
        expected={('table','nodes','nodes'),('table','roots','roots'),('index','sqlite_autoindex_nodes_1','nodes')}
        if set(self.connection.execute('SELECT type,name,tbl_name FROM sqlite_master'))!=expected:
            raise ValueError('shared_database_schema_invalid')
        if self.connection.execute('PRAGMA integrity_check').fetchone()!=('ok',):
            raise ValueError('shared_database_integrity_invalid')
        for table,key in (('nodes','node_count'),('roots','root_count')):
            if self.connection.execute('SELECT count(*) FROM '+table).fetchone()[0]!=self.manifest[key]:
                raise ValueError('shared_record_count_invalid')
        for row in self.connection.execute('SELECT id,digest,kind,payload,logical_bytes,items,height FROM nodes ORDER BY id'):
            base._deadline(self.deadline);self._decode(row)
        index=hashlib.sha256()
        for name,ref in self.connection.execute('SELECT name,digest FROM roots ORDER BY name'):
            base._name(name);self._node(ref);index.update(canonical([name,ref.hex()])+b'\n')
        if index.hexdigest()!=self.manifest['roots_index_sha256']:
            raise ValueError('shared_root_index_changed')
        return {'version':FORMAT,'status':'store_integrity_only_source_unverified','root_count':self.manifest['root_count']}
