"""Isolated BLOB32/compressed DAG prototypes; no production reader dispatch.

DAG4 changes only the physical codec; DAG5 also uses content-defined ordered
array chunks. DAG3 remains in shared_artifact_store unchanged. Neither format
establishes source authenticity or replaces publication/prefix validation.
"""
from collections import OrderedDict
import hashlib
import sqlite3
import struct
import sys
import zlib
from pathlib import Path
from urllib.parse import quote

from . import shared_artifact_store as legacy
from .dual_source import strict_json
from .pipeline import canonical, file_hash
from .replay_history import _ordinary, _digest

BINARY_FORMAT = 'shared-observation-dag-4'
CONTENT_FORMAT = 'shared-observation-dag-5'
FORMATS = (BINARY_FORMAT, CONTENT_FORMAT)
CODEC = 'blob32-zlib-or-raw-1'
CACHE_BYTES = 16*1024**2
MAX_DICT_ITEMS = 4096
MAX_LOGICAL_BYTES = 512*1024**3
_U32 = struct.Struct('>I')


def _limits(value):
    if not isinstance(value,dict) or set(value) != {'max_bytes','max_nodes','max_roots','max_node_bytes','max_array_items','max_depth','cache_entries','max_dict_items','max_logical_root_bytes','cache_bytes'}:
        raise ValueError('shared_limits_invalid')
    ordinary = {key:item for key,item in value.items() if key not in ('max_dict_items','max_logical_root_bytes','cache_bytes')}
    if not legacy._int(ordinary['max_nodes'],1,8000000):
        raise ValueError('shared_limits_invalid')
    ordinary['max_nodes'] = min(ordinary['max_nodes'],2000000)
    legacy._limits(ordinary)
    if value['max_dict_items'] != MAX_DICT_ITEMS or value['cache_bytes'] != CACHE_BYTES or not legacy._int(value['max_logical_root_bytes'],1,MAX_LOGICAL_BYTES):
        raise ValueError('shared_limits_invalid')


def _pack(kind, value):
    if kind == 'scalar':
        return canonical(value)
    if kind == 'dict':
        if len(value) > MAX_DICT_ITEMS:
            raise ValueError('shared_dict_item_limit')
        parts = [_U32.pack(len(value))]
        for key, ref in sorted(value.items()):
            raw = key.encode('utf-8')
            parts.extend((_U32.pack(len(raw)), raw, bytes.fromhex(ref)))
        return b''.join(parts)
    return _U32.pack(len(value)) + b''.join(bytes.fromhex(ref) for ref in value)


def _unpack(kind, raw):
    if kind == 'scalar':
        value = strict_json(raw.decode('utf-8'))
        if raw != canonical(value):
            raise ValueError('shared_node_encoding_invalid')
        return value
    if len(raw) < 4:
        raise ValueError('shared_binary_node_invalid')
    count = _U32.unpack_from(raw)[0]
    if kind != 'dict':
        if count > legacy.BRANCH or len(raw) != 4+32*count:
            raise ValueError('shared_binary_node_invalid')
        return [raw[i:i+32].hex() for i in range(4, len(raw), 32)]
    # Each dictionary entry consumes at least 36 bytes; reject a forged count
    # before any loop or allocation, and require sorted distinct UTF-8 keys.
    if count > MAX_DICT_ITEMS or count > (len(raw)-4)//36:
        raise ValueError('shared_binary_node_invalid')
    offset = 4
    result = {}
    previous = None
    for _ in range(count):
        if offset+4 > len(raw):
            raise ValueError('shared_binary_node_invalid')
        length = _U32.unpack_from(raw, offset)[0]
        offset += 4
        if offset+length+32 > len(raw):
            raise ValueError('shared_binary_node_invalid')
        key = raw[offset:offset+length].decode('utf-8')
        offset += length
        if previous is not None and key <= previous:
            raise ValueError('shared_binary_node_invalid')
        previous = key
        result[key] = raw[offset:offset+32].hex()
        offset += 32
    if offset != len(raw):
        raise ValueError('shared_binary_node_invalid')
    return result


def _store(raw):
    compressed = zlib.compress(raw, level=1)
    return b'Z'+compressed if len(compressed) < len(raw) else b'R'+raw


def _load(stored, maximum):
    if not isinstance(stored, bytes) or not stored or len(stored) > maximum+1:
        raise ValueError('shared_compressed_node_invalid')
    if stored[:1] == b'R':
        return stored[1:]
    if stored[:1] != b'Z':
        raise ValueError('shared_compressed_node_invalid')
    stream = zlib.decompressobj()
    try:
        raw = stream.decompress(stored[1:], maximum+1)
    except zlib.error as error:
        raise ValueError('shared_compressed_node_invalid') from error
    # max_length stops allocation before a compressed bomb can expand further.
    # Requiring EOF rejects truncation; unused_data rejects concatenated streams.
    if len(raw) > maximum or not stream.eof or stream.unused_data or stream.unconsumed_tail:
        raise ValueError('shared_compressed_node_limit_or_encoding')
    return raw


def _hash(version, kind, raw, size, items, height):
    return hashlib.sha256((version+'\0'+CODEC+'\0'+kind+'\0').encode()+canonical([size,items,height])+b'\0'+raw).hexdigest()


def _memory(value):
    """Conservative per-entry decoded-object accounting, counting duplicates."""
    total = sys.getsizeof(value)
    if isinstance(value, dict):
        total += sum(_memory(key)+_memory(child) for key,child in value.items())
    elif isinstance(value, (list,tuple)):
        total += sum(_memory(child) for child in value)
    return total


class SharedArtifactWriter(legacy.SharedArtifactWriter):
    def __init__(self, root, *, context, version, max_nodes=2000000, max_logical_root_bytes=MAX_LOGICAL_BYTES, **kwargs):
        if version not in FORMATS:
            raise ValueError('explicit_shared_compressed_format_required')
        # Reuse the established bounds/inventory creation, then replace the empty
        # prototype schema. No global format state or legacy reader is changed.
        if not legacy._int(max_nodes,1,8000000) or not legacy._int(max_logical_root_bytes,1,MAX_LOGICAL_BYTES):
            raise ValueError('shared_limits_invalid')
        super().__init__(root, context=context, version=legacy.FORMAT, max_nodes=min(max_nodes,2000000), **kwargs)
        self.limits.update(max_nodes=max_nodes,max_dict_items=MAX_DICT_ITEMS,max_logical_root_bytes=max_logical_root_bytes,cache_bytes=CACHE_BYTES)
        _limits(self.limits)
        self.version = version
        self.connection.execute('DROP TABLE nodes')
        self.connection.execute('DROP TABLE roots')
        self.connection.execute('CREATE TABLE nodes(digest BLOB PRIMARY KEY CHECK(length(digest)=32),kind TEXT NOT NULL,payload BLOB NOT NULL,logical_bytes INTEGER NOT NULL,items INTEGER NOT NULL,height INTEGER NOT NULL) WITHOUT ROWID')
        self.connection.execute('CREATE TABLE roots(name TEXT PRIMARY KEY,digest BLOB NOT NULL CHECK(length(digest)=32)) WITHOUT ROWID')
        self.connection.commit()

    def _put(self, kind, value, size, items, height):
        legacy._deadline(self.deadline)
        if not legacy._int(size,1,self.limits['max_logical_root_bytes']) or not legacy._int(items,0,500000) or not legacy._int(height,0,self.limits['max_depth']+8):
            raise ValueError('shared_logical_extent_invalid')
        raw = _pack(kind, value)
        if len(raw) > self.limits['max_node_bytes']:
            raise ValueError('shared_node_byte_limit')
        ref = _hash(self.version,kind,raw,size,items,height)
        if ref not in self._recent:
            payload = _store(raw)
            cursor = self.connection.execute('INSERT OR IGNORE INTO nodes VALUES(?,?,?,?,?,?)',
                (bytes.fromhex(ref),kind,payload,size,items,height))
            if cursor.rowcount:
                self.node_count += 1
                if self.node_count > self.limits['max_nodes']:
                    raise ValueError('shared_node_limit')
            self._recent[ref] = None
            if len(self._recent) > self.limits['cache_entries']:
                self._recent.popitem(last=False)
        else:
            self._recent.move_to_end(ref)
        return ref,size,items,kind,height

    def _array(self, values, depth, active):
        if self.version == BINARY_FORMAT:
            return super()._array(values,depth,active)
        if len(values) > self.limits['max_array_items']:
            raise ValueError('shared_array_item_limit')
        # Content-defined cuts resynchronize after a deletion. Each value and its
        # original position remain in the ordered tree; nothing is sorted away.
        # All levels cap at 64 children and cut only after at least 16 children.
        def chunks(nodes):
            pending = []
            for child in nodes:
                pending.append(child)
                if len(pending) == legacy.BRANCH or (len(pending) >= 16 and int(child[0][:2],16)&31 == 0):
                    yield pending
                    pending = []
            if pending:
                yield pending
        nodes = []
        for children in chunks(self._encode(value,depth+1,active) for value in values):
            size = 2+sum(child[1] for child in children)+len(children)-1
            nodes.append(self._put('array_leaf',[child[0] for child in children],size,len(children),1+max(child[4] for child in children)))
        if not nodes:
            return self._put('array_leaf',[],2,0,1)
        while len(nodes) > 1:
            level = []
            for children in chunks(nodes):
                if len(children) == 1:
                    level.append(children[0])
                else:
                    level.append(self._put('array_branch',[child[0] for child in children],
                        2+sum(child[1]-2 for child in children)+len(children)-1,
                        sum(child[2] for child in children),1+max(child[4] for child in children)))
            nodes = level
        return nodes[0]

    def add(self, name, value):
        # Legacy traversal returns textual refs; SQLite storage is binary only.
        # Convert the root at insertion via a temporary connection adapter is
        # unnecessary: this small method keeps failure/transaction behavior clear.
        legacy._name(name)
        if self.failed or self.sealed:
            raise ValueError('shared_writer_not_writable')
        try:
            if self.root_count >= self.limits['max_roots']:
                raise ValueError('shared_root_limit')
            if self.connection.execute('SELECT 1 FROM roots WHERE name=?',(name,)).fetchone():
                raise ValueError('shared_root_already_exists')
            self._memo.clear()
            node = self._encode(value,0,set())
            self.connection.execute('INSERT INTO roots VALUES(?,?)',(name,bytes.fromhex(node[0])))
            self.connection.commit()
            self.root_count += 1
            return {'name':name,'digest':node[0],'logical_bytes':node[1],'items':node[2],'kind':node[3]}
        except BaseException as error:
            self.failed = True
            try:
                self.connection.rollback()
            finally:
                self.close()
            if isinstance(error,sqlite3.Error):
                raise ValueError('shared_storage_failed:'+getattr(error,'sqlite_errorname','SQLITE_ERROR')) from error
            raise
        finally:
            self._memo.clear()

    def intern(self, value):
        """Commit a typed value without adding a root name (for composed roots)."""
        if self.failed or self.sealed:
            raise ValueError('shared_writer_not_writable')
        try:
            self._memo.clear()
            node = self._encode(value,0,set())
            self.connection.commit()
            return {'digest':node[0],'logical_bytes':node[1],'items':node[2],'kind':node[3]}
        except BaseException as error:
            self.failed = True
            try:
                self.connection.rollback()
            finally:
                self.close()
            if isinstance(error,sqlite3.Error):
                raise ValueError('shared_storage_failed:'+getattr(error,'sqlite_errorname','SQLITE_ERROR')) from error
            raise
        finally:
            self._memo.clear()

    def compose(self, name, values, references):
        """Commit a dictionary referencing already interned complete values.

        name=None interns without naming; no unregistered external child is used.
        This is a physical optimization, not a partial logical object.
        """
        if self.failed or self.sealed:
            raise ValueError('shared_writer_not_writable')
        if name is not None:
            legacy._name(name)
        try:
            if not isinstance(values,dict) or not isinstance(references,dict) or set(values)&set(references) or len(values)+len(references)>MAX_DICT_ITEMS:
                raise ValueError('shared_composition_invalid')
            if name is not None:
                if self.root_count>=self.limits['max_roots']:
                    raise ValueError('shared_root_limit')
                if self.connection.execute('SELECT 1 FROM roots WHERE name=?',(name,)).fetchone():
                    raise ValueError('shared_root_already_exists')
            children={}
            self._memo.clear()
            for key,value in values.items():
                if type(key) is not str:
                    raise ValueError('shared_composition_invalid')
                children[key]=self._encode(value,1,set())
            for key,ref in references.items():
                if type(key) is not str or not _digest(ref):
                    raise ValueError('shared_composition_invalid')
                row=self.connection.execute('SELECT logical_bytes,items,kind,height FROM nodes WHERE digest=?',(bytes.fromhex(ref),)).fetchone()
                if row is None:
                    raise ValueError('shared_composition_reference_missing')
                children[key]=(ref,*row)
            logical=2+sum(len(canonical(key))+1+child[1] for key,child in children.items())+max(0,len(children)-1)
            node=self._put('dict',{key:child[0] for key,child in children.items()},logical,len(children),1+max((child[4] for child in children.values()),default=0))
            if name is not None:
                self.connection.execute('INSERT INTO roots VALUES(?,?)',(name,bytes.fromhex(node[0])))
                self.root_count+=1
            self.connection.commit()
            result={'digest':node[0],'logical_bytes':node[1],'items':node[2],'kind':node[3]}
            if name is not None:
                result['name']=name
            return result
        except BaseException as error:
            self.failed=True
            try:
                self.connection.rollback()
            finally:
                self.close()
            if isinstance(error,sqlite3.Error):
                raise ValueError('shared_storage_failed:'+getattr(error,'sqlite_errorname','SQLITE_ERROR')) from error
            raise
        finally:
            self._memo.clear()

    def alias(self, name, target):
        """Explicit second name for an already committed immutable logical root."""
        legacy._name(name)
        legacy._name(target)
        if self.failed or self.sealed:
            raise ValueError('shared_writer_not_writable')
        try:
            legacy._deadline(self.deadline)
            if self.root_count >= self.limits['max_roots']:
                raise ValueError('shared_root_limit')
            if self.connection.execute('SELECT 1 FROM roots WHERE name=?',(name,)).fetchone():
                raise ValueError('shared_root_already_exists')
            row = self.connection.execute('SELECT digest FROM roots WHERE name=?',(target,)).fetchone()
            if row is None:
                raise ValueError('shared_alias_target_missing')
            ref = row[0]
            kind,size,items = self.connection.execute('SELECT kind,logical_bytes,items FROM nodes WHERE digest=?',(ref,)).fetchone()
            self.connection.execute('INSERT INTO roots VALUES(?,?)',(name,ref))
            self.connection.commit()
            self.root_count += 1
            return {'name':name,'digest':ref.hex(),'logical_bytes':size,'items':items,'kind':kind}
        except BaseException as error:
            self.failed = True
            try:
                self.connection.rollback()
            finally:
                self.close()
            if isinstance(error,sqlite3.Error):
                raise ValueError('shared_storage_failed:'+getattr(error,'sqlite_errorname','SQLITE_ERROR')) from error
            raise

    def seal(self):
        if self.failed or self.sealed or not self.root_count:
            raise ValueError('shared_failed_empty_or_sealed')
        index = hashlib.sha256()
        for name,ref in self.connection.execute('SELECT name,digest FROM roots ORDER BY name'):
            index.update(canonical([name,ref.hex()])+b'\n')
        self.close()
        database = self.root/'shared.sqlite3'
        manifest = {'version':self.version,'codec':CODEC,'status':legacy.STATUS,'context':self.context,'limits':self.limits,
            'database':{'path':'shared.sqlite3','sha256':file_hash(database),'size_bytes':database.stat().st_size},
            'root_count':self.root_count,'node_count':self.node_count,'roots_index_sha256':index.hexdigest()}
        raw = canonical(manifest)+b'\n'
        if len(raw)>65536 or database.stat().st_size+len(raw)>self.limits['max_bytes']:
            self.failed = True
            raise ValueError('shared_physical_byte_limit')
        with (self.root/'manifest.json').open('xb') as stream:
            stream.write(raw)
        self.sealed = True
        return {'manifest':manifest,'manifest_sha256':hashlib.sha256(raw).hexdigest()}


class SharedArtifactReader(legacy.SharedArtifactReader):
    def __init__(self, root, *, expected_manifest_sha256, expected_context=None, deadline=None):
        self.root = Path(root).absolute()
        self.deadline = deadline
        legacy._deadline(deadline)
        if self.root.is_symlink() or not self.root.is_dir() or {p.name for p in self.root.iterdir()} != {'manifest.json','shared.sqlite3'}:
            raise ValueError('shared_inventory_invalid')
        for name in ('manifest.json','shared.sqlite3'):
            _ordinary(self.root/name)
        path = self.root/'manifest.json'
        if path.stat().st_size>65536 or not _digest(expected_manifest_sha256) or file_hash(path)!=expected_manifest_sha256:
            raise ValueError('shared_manifest_binding_invalid')
        raw = path.read_bytes()
        manifest = strict_json(raw.decode())
        if not isinstance(manifest,dict) or set(manifest)!={'version','codec','status','context','limits','database','root_count','node_count','roots_index_sha256'}:
            raise ValueError('shared_manifest_contract_invalid')
        if manifest['version'] not in FORMATS or manifest['codec'] != CODEC or manifest['status'] != legacy.STATUS or raw != canonical(manifest)+b'\n':
            raise ValueError('shared_manifest_version_or_encoding_invalid')
        legacy._context(manifest['context'])
        _limits(manifest['limits'])
        if expected_context is not None and manifest['context'] != expected_context:
            raise ValueError('shared_context_changed')
        db = manifest['database']
        if not isinstance(db,dict) or set(db)!={'path','sha256','size_bytes'} or db['path']!='shared.sqlite3' or not _digest(db['sha256']) or not legacy._int(db['size_bytes'],1,legacy.MAX_PHYSICAL_BYTES):
            raise ValueError('shared_database_contract_invalid')
        if not legacy._int(manifest['root_count'],1,manifest['limits']['max_roots']) or not legacy._int(manifest['node_count'],1,manifest['limits']['max_nodes']) or not _digest(manifest['roots_index_sha256']):
            raise ValueError('shared_counts_invalid')
        database = self.root/db['path']
        if database.stat().st_size != db['size_bytes'] or file_hash(database)!=db['sha256'] or database.stat().st_size+len(raw)>manifest['limits']['max_bytes']:
            raise ValueError('shared_database_binding_invalid')
        self.version = manifest['version']
        self.manifest = manifest
        self._cache = OrderedDict()
        self._cache_sizes = {}
        self._cache_bytes = 0
        self.connection = sqlite3.connect('file:'+quote(str(database))+'?mode=ro&immutable=1',uri=True)
        self.connection.execute('PRAGMA query_only=ON')
        self.connection.execute('PRAGMA trusted_schema=OFF')
        self.connection.execute('PRAGMA cache_size=-2048')
        try:
            self.verify()
        except BaseException:
            self.close()
            raise

    def _node(self, ref):
        legacy._deadline(self.deadline)
        if isinstance(ref,bytes) and len(ref)==32:
            ref = ref.hex()
        if not _digest(ref):
            raise ValueError('shared_reference_invalid')
        if ref in self._cache:
            self._cache.move_to_end(ref)
            return self._cache[ref]
        row = self.connection.execute('SELECT kind,payload,logical_bytes,items,height FROM nodes WHERE digest=?',(bytes.fromhex(ref),)).fetchone()
        if row is None:
            raise ValueError('shared_node_missing')
        kind,stored,size,items,height = row
        if kind not in ('scalar','dict','array_leaf','array_branch') or not legacy._int(size,1,self.manifest['limits']['max_logical_root_bytes']) or not legacy._int(items,0,500000) or not legacy._int(height,0,self.manifest['limits']['max_depth']+8):
            raise ValueError('shared_node_invalid')
        raw = _load(stored,self.manifest['limits']['max_node_bytes'])
        if _hash(self.version,kind,raw,size,items,height)!=ref:
            raise ValueError('shared_node_invalid')
        value = _unpack(kind,raw)
        payload = raw if kind == 'scalar' else b''
        if kind == 'scalar':
            if type(value) not in (str,int,float,bool,type(None)) or size!=len(raw) or items!=0 or height!=0:
                raise ValueError('shared_scalar_invalid')
        elif kind == 'dict':
            if len(value)!=items:
                raise ValueError('shared_dict_invalid')
        elif len(value)<2 and kind=='array_branch':
            raise ValueError('shared_array_invalid')
        node = (kind,value,size,items,payload,height)
        weight = _memory(node)+_memory(ref)+256
        # Count limit alone would permit 4096 * 8MiB decompressed nodes. Account
        # decoded objects and payload and never cache an entry larger than cap.
        if weight <= CACHE_BYTES:
            while self._cache and (self._cache_bytes+weight>CACHE_BYTES or len(self._cache)>=self.manifest['limits']['cache_entries']):
                old,_ = self._cache.popitem(last=False)
                self._cache_bytes -= self._cache_sizes.pop(old)
            self._cache[ref] = node
            self._cache_sizes[ref] = weight
            self._cache_bytes += weight
        return node

    def _extent(self, ref):
        # Do not hold all decoded children: a small compressed parent may refer
        # to many large children and bypass an otherwise bounded LRU cache.
        kind,value,size,items,_,height=self._node(ref)
        if kind=='scalar':
            return
        pairs=value.items() if kind=='dict' else enumerate(value)
        total=0
        count=0
        maximum=0
        children=0
        for key,child_ref in pairs:
            child=self._node(child_ref)
            child_kind,_,child_size,child_items,_,child_height=child
            if child_size>=size or child_height>=height:
                raise ValueError('shared_cycle_or_extent_invalid')
            if kind=='dict':
                total+=len(canonical(key))+1+child_size
                count+=1
            elif kind=='array_leaf':
                total+=child_size
                count+=1
            else:
                if child_kind not in ('array_leaf','array_branch') or child_items<1:
                    raise ValueError('shared_branch_kind_invalid')
                total+=child_size-2
                count+=child_items
            maximum=max(maximum,child_height)
            children+=1
        expected=2+total+max(0,children-1)
        if size!=expected or items!=count or height!=maximum+1 or (kind.startswith('array') and count>self.manifest['limits']['max_array_items']):
            raise ValueError('shared_extent_invalid')

    def verify(self):
        catalog = set(self.connection.execute('SELECT type,name,tbl_name FROM sqlite_master'))
        if catalog != {('table','nodes','nodes'),('table','roots','roots')}:
            raise ValueError('shared_database_schema_invalid')
        if self.connection.execute('PRAGMA integrity_check').fetchone()!=('ok',):
            raise ValueError('shared_database_integrity_invalid')
        for table,key in (('nodes','node_count'),('roots','root_count')):
            if self.connection.execute('SELECT count(*) FROM '+table).fetchone()[0] != self.manifest[key]:
                raise ValueError('shared_record_count_invalid')
        for (ref,) in self.connection.execute('SELECT digest FROM nodes'):
            self._extent(ref)
        index = hashlib.sha256()
        for name,ref in self.connection.execute('SELECT name,digest FROM roots ORDER BY name'):
            legacy._name(name)
            self._node(ref)
            index.update(canonical([name,ref.hex()])+b'\n')
        if index.hexdigest()!=self.manifest['roots_index_sha256']:
            raise ValueError('shared_root_index_changed')
        return {'version':self.version,'status':'store_integrity_only_source_unverified','root_count':self.manifest['root_count']}

    def descriptor(self, name):
        legacy._name(name)
        row = self.connection.execute('SELECT digest FROM roots WHERE name=?',(name,)).fetchone()
        if row is None:
            raise ValueError('shared_root_missing')
        kind,_,size,items,_,_ = self._node(row[0])
        return {'name':name,'digest':row[0].hex(),'kind':kind,'logical_bytes':size,'items':items}

    def page(self, *args, **kwargs):
        result = super().page(*args,**kwargs)
        result['version'] = self.version
        return result
