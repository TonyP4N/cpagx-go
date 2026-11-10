"""Explicit V2 disk history store; not a task publisher or source verifier.

Only already-arrived logical snapshots enter this sink. Immutable row objects
and 64-way list chunks are shared across states; checkpoint/delta records keep
all fields and array ordering. SQLite is a bounded disk index, not an authority.
Restore requires the externally retained manifest digest. Original source,
arrival-prefix, publication/attempt, ACL and backup checks remain caller gates.
"""
from collections import OrderedDict
import hashlib
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote

from .contracts import validate
from .dual_source import strict_json, references
from .pipeline import canonical, file_hash, fingerprint

VERSION = 'replay-history-checkpoint-delta-2'
SEMANTIC_VERSION = 'dual-source-replay-1'
BRANCH = 64
CHECKPOINT_INTERVAL = 128
SNAPSHOT_FIELDS = {'schema_version', 'synthetic', 'replay_version', 'snapshot_number', 'available_at',
                   'arrival_seq', 'status', 'revision_number', 'config_version', 'config_fingerprint',
                   'semantic_config_fingerprint', 'state_fingerprint', 'trigger', 'analysis', 'snapshot_id'}


def _hash(kind, payload):
    return hashlib.sha256(kind.encode() + b'\0' + payload).hexdigest()


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _ordinary(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('history_ordinary_unlinked_file_required')


class HistorySink:
    """Bounded disk spool. Failed or unsealed stores cannot be restored."""
    def __init__(self, root, *, run_id, attempt_id, version, max_bytes=64 * 1024 * 1024,
                 checkpoint_interval=CHECKPOINT_INTERVAL, max_objects=1000000,
                 max_snapshots=22000, max_revisions=44000, max_object_bytes=8 * 1024 * 1024):
        if version != VERSION:
            raise ValueError('explicit_supported_history_version_required')
        if not isinstance(run_id, str) or not run_id or type(attempt_id) is not int or not 1 <= attempt_id <= 1000000:
            raise ValueError('history_run_attempt_required')
        for name, value, low, high in (
                ('max_bytes', max_bytes, 256 * 1024, 1024 * 1024 * 1024),
                ('checkpoint_interval', checkpoint_interval, 1, 128),
                ('max_objects', max_objects, 1, 1000000), ('max_snapshots', max_snapshots, 1, 45000),
                ('max_revisions', max_revisions, 1, 90000), ('max_object_bytes', max_object_bytes, 1, 32 * 1024 * 1024)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError('history_budget_invalid:' + name)
        self.root = Path(root).absolute()
        if self.root.exists() or self.root.is_symlink():
            raise ValueError('history_output_must_be_new')
        self.root.mkdir(mode=0o700, parents=True)
        self.limits = dict(max_bytes=max_bytes, max_working_bytes=3*max_bytes, checkpoint_interval=checkpoint_interval,
                           max_objects=max_objects, max_snapshots=max_snapshots,
                           max_revisions=max_revisions, max_object_bytes=max_object_bytes)
        self.context = {'run_id': run_id, 'attempt_id': attempt_id}
        self.connection = sqlite3.connect(self.root / 'history.sqlite3')
        # Persistent pages use the declared final budget; rollback journals
        # have a separate explicit 3x working ceiling, not a smaller output cap.
        self.connection.execute('PRAGMA page_size=4096')
        self.connection.execute('PRAGMA max_page_count=' + str((max_bytes - 65536) // 4096))
        self.connection.execute('PRAGMA journal_mode=DELETE')
        self.connection.execute('PRAGMA synchronous=FULL')
        self.connection.execute('PRAGMA cache_size=-2048')
        self.connection.execute('CREATE TABLE objects(digest TEXT PRIMARY KEY,kind TEXT NOT NULL,payload BLOB NOT NULL)')
        self.connection.execute('CREATE TABLE snapshots(number INTEGER PRIMARY KEY,checkpoint INTEGER NOT NULL,payload BLOB NOT NULL)')
        self.connection.execute('CREATE TABLE revisions(number INTEGER PRIMARY KEY,payload BLOB NOT NULL)')
        self.connection.commit()
        self.snapshot_count = self.revision_count = self.object_count = 0
        self.synthetic = None
        self.last_snapshot_id = None
        self.last_fields = {}
        self.failed = self.sealed = False
        self._recent = OrderedDict()

    def bind(self, semantic_config_fingerprint, replay_version):
        if self.snapshot_count or not _digest(semantic_config_fingerprint) or replay_version != SEMANTIC_VERSION:
            raise ValueError('history_semantic_binding_invalid')
        self.context.update(semantic_config_fingerprint=semantic_config_fingerprint, replay_version=replay_version)

    def _put(self, kind, value):
        payload = canonical(value)
        if len(payload) > self.limits['max_object_bytes']:
            raise ValueError('history_object_byte_limit')
        digest = _hash(kind, payload)
        if digest in self._recent:
            self._recent.move_to_end(digest)
            return digest
        cursor = self.connection.execute('INSERT OR IGNORE INTO objects VALUES(?,?,?)', (digest, kind, payload))
        if cursor.rowcount:
            self.object_count += 1
            if self.object_count > self.limits['max_objects']:
                raise ValueError('history_object_limit')
        self._recent[digest] = None
        if len(self._recent) > 4096:
            self._recent.popitem(last=False)
        return digest

    def _array(self, values):
        refs = []
        chunk = []
        for value in values:
            chunk.append(self._put('value', value))
            if len(chunk) == BRANCH:
                refs.append(self._put('leaf', chunk))
                chunk = []
        if chunk or not refs:
            refs.append(self._put('leaf', chunk))
        while len(refs) > 1:
            refs = [self._put('branch', refs[i:i + BRANCH]) for i in range(0, len(refs), BRANCH)]
        return refs[0]

    def _fields(self, value):
        return {key: self._array(item) if isinstance(item, list) else self._put('value', item)
                for key, item in sorted(value.items())}

    def append(self, snapshot, revision):
        if self.failed or self.sealed or 'semantic_config_fingerprint' not in self.context:
            raise ValueError('history_sink_not_writable_or_bound')
        try:
            if set(snapshot) != SNAPSHOT_FIELDS or snapshot['snapshot_number'] != self.snapshot_count:
                raise ValueError('history_snapshot_sequence_invalid')
            if snapshot['config_fingerprint'] != self.context['semantic_config_fingerprint'] or snapshot['replay_version'] != SEMANTIC_VERSION:
                raise ValueError('history_snapshot_binding_invalid')
            if self.snapshot_count >= self.limits['max_snapshots']:
                raise ValueError('history_snapshot_limit')
            if revision is not None and self.revision_count >= self.limits['max_revisions']:
                raise ValueError('history_revision_limit')
            if self.synthetic is not None and self.synthetic != snapshot['synthetic']:raise ValueError('history_source_category_changed')
            self.synthetic = snapshot['synthetic']
            fields = self._fields(snapshot['analysis'])
            interval = self.limits['checkpoint_interval']
            checkpoint = self.snapshot_count - self.snapshot_count % interval
            full = self.snapshot_count == checkpoint
            record = {'metadata': self._put('value', {key: value for key, value in snapshot.items() if key != 'analysis'}),
                      'previous_snapshot_id': self.last_snapshot_id,
                      'fields': fields if full else None,
                      'delta': None if full else {'set': {key: value for key, value in fields.items()
                                                         if self.last_fields.get(key) != value},
                                                  'remove': sorted(set(self.last_fields) - set(fields))},
                      'revision': None}
            if revision is not None:
                validate('ReplayRevision', revision)
                if revision['revision_number'] != self.revision_count + 1:
                    raise ValueError('history_revision_sequence_invalid')
                record['revision'] = revision['revision_number']
                revision_record = self._fields(revision)
                self.connection.execute('INSERT INTO revisions VALUES(?,?)', (revision['revision_number'], canonical(revision_record)))
            self.connection.execute('INSERT INTO snapshots VALUES(?,?,?)',
                                    (self.snapshot_count, checkpoint, canonical(record)))
            self.connection.commit()
            if sum(path.stat().st_size for path in self.root.iterdir()) > self.limits['max_working_bytes']:
                raise ValueError('history_working_byte_limit')
            self.snapshot_count += 1
            self.revision_count += revision is not None
            self.last_snapshot_id = snapshot['snapshot_id']
            self.last_fields = fields
        except Exception:
            self.failed = True
            try:
                self.connection.rollback()
            finally:
                self.close()
            raise

    def abort(self):
        self.failed = True
        self.close()

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def seal(self):
        if self.failed or self.sealed or not self.snapshot_count:
            raise ValueError('history_failed_empty_or_already_sealed')
        self.close()
        database = self.root / 'history.sqlite3'
        manifest = {'schema_version':'1.0.0','synthetic':self.synthetic,'version': VERSION, 'context': self.context, 'limits': self.limits,
                    'database': {'path': 'history.sqlite3', 'sha256': file_hash(database), 'size_bytes': database.stat().st_size},
                    'snapshot_count': self.snapshot_count, 'revision_count': self.revision_count,
                    'object_count': self.object_count, 'last_snapshot_id': self.last_snapshot_id,
                    'status': 'sealed_storage_not_source_verified'}
        validate('ReplayHistorySpoolManifest', manifest)
        raw = canonical(manifest) + b'\n'
        if database.stat().st_size + len(raw) > self.limits['max_bytes']:
            self.failed = True
            raise ValueError('history_disk_byte_limit')
        with (self.root / 'manifest.json').open('xb') as stream:
            stream.write(raw)
        self.sealed = True
        return {'manifest': manifest, 'manifest_sha256': hashlib.sha256(raw).hexdigest()}


class HistoryReader:
    """Restore indexed history against an external manifest hash, bounded RAM.

    Verification proves storage/logical hash consistency only. It neither
    replays source bytes nor establishes an authorized published attempt.
    """
    def __init__(self, root, *, expected_manifest_sha256, expected_context=None):
        self.root = Path(root).absolute()
        if self.root.is_symlink() or not self.root.is_dir() or {p.name for p in self.root.iterdir()} != {'manifest.json', 'history.sqlite3'}:
            raise ValueError('history_inventory_invalid')
        for name in ('manifest.json', 'history.sqlite3'):
            _ordinary(self.root / name)
        if not _digest(expected_manifest_sha256) or file_hash(self.root / 'manifest.json') != expected_manifest_sha256:
            raise ValueError('history_manifest_binding_invalid')
        raw = (self.root / 'manifest.json').read_bytes()
        if len(raw) > 65536:
            raise ValueError('history_manifest_byte_limit')
        self.manifest = strict_json(raw.decode())
        validate('ReplayHistorySpoolManifest', self.manifest)
        if raw != canonical(self.manifest) + b'\n':
            raise ValueError('history_manifest_encoding_invalid')
        if expected_context is not None and self.manifest['context'] != expected_context:
            raise ValueError('history_context_changed')
        if self.manifest['limits']['max_working_bytes']!=3*self.manifest['limits']['max_bytes']:
            raise ValueError('history_working_budget_invalid')
        item = self.manifest['database']
        database = self.root / 'history.sqlite3'
        if database.stat().st_size != item['size_bytes'] or file_hash(database) != item['sha256']:
            raise ValueError('history_database_binding_invalid')
        if database.stat().st_size + len(raw) > self.manifest['limits']['max_bytes']:
            raise ValueError('history_disk_byte_limit')
        self.connection = sqlite3.connect('file:' + quote(str(database)) + '?mode=ro&immutable=1', uri=True)
        self.connection.execute('PRAGMA trusted_schema=OFF')
        self.connection.execute('PRAGMA query_only=ON')
        try:
            self.verify()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def _node(self, digest, depth=0, budget=None):
        if budget is None:budget={'nodes':0,'bytes':0}
        budget['nodes']+=1
        if budget['nodes']>self.manifest['limits']['max_objects']:raise ValueError('history_decode_node_limit')
        if not _digest(digest) or depth > 16:
            raise ValueError('history_object_reference_invalid')
        row = self.connection.execute('SELECT kind,payload FROM objects WHERE digest=?', (digest,)).fetchone()
        if row is None:
            raise ValueError('history_object_missing')
        kind, payload = row
        if not isinstance(payload, bytes) or len(payload) > self.manifest['limits']['max_object_bytes'] or _hash(kind, payload) != digest:
            raise ValueError('history_object_changed')
        value = strict_json(payload.decode())
        if payload != canonical(value):
            raise ValueError('history_object_encoding_invalid')
        if kind == 'value':
            budget['bytes']+=len(payload)
            if budget['bytes']>self.manifest['limits']['max_bytes']:raise ValueError('history_decode_byte_limit')
            return value
        if kind not in ('leaf', 'branch') or not isinstance(value, list) or len(value) > BRANCH:
            raise ValueError('history_object_kind_invalid')
        rows = [self._node(ref, depth + 1, budget) for ref in value]
        if kind == 'leaf':
            return rows
        if any(not isinstance(row, list) for row in rows):
            raise ValueError('history_branch_kind_invalid')
        return [item for row in rows for item in row]

    def _record(self, number):
        row = self.connection.execute('SELECT checkpoint,payload FROM snapshots WHERE number=?', (number,)).fetchone()
        if row is None or not isinstance(row[1], bytes):
            raise ValueError('history_snapshot_missing')
        record = strict_json(row[1].decode())
        if row[1] != canonical(record) or not isinstance(record, dict) or set(record) != {'metadata', 'previous_snapshot_id', 'fields', 'delta', 'revision'}:
            raise ValueError('history_snapshot_record_invalid')
        return row[0], record

    def _apply(self, fields, number, checkpoint, record):
        interval = self.manifest['limits']['checkpoint_interval']
        if checkpoint != number - number % interval:
            raise ValueError('history_checkpoint_index_invalid')
        if checkpoint == number:
            if not isinstance(record['fields'], dict) or record['delta'] is not None:
                raise ValueError('history_checkpoint_invalid')
            fields = dict(record['fields'])
        else:
            delta = record['delta']
            if record['fields'] is not None or not isinstance(delta, dict) or set(delta) != {'set', 'remove'} or not isinstance(delta['set'], dict) or not isinstance(delta['remove'], list):
                raise ValueError('history_delta_invalid')
            fields = dict(fields)
            for key in delta['remove']:
                if key not in fields:
                    raise ValueError('history_delta_removal_invalid')
                del fields[key]
            fields.update(delta['set'])
        return fields

    def _snapshot(self, number, fields, record):
        budget={'nodes':0,'bytes':0}
        metadata = self._node(record['metadata'],budget=budget)
        if not isinstance(metadata, dict) or 'analysis' in metadata:
            raise ValueError('history_snapshot_metadata_invalid')
        snapshot = dict(metadata, analysis={key: self._node(ref,budget=budget) for key, ref in fields.items()})
        if set(snapshot) != SNAPSHOT_FIELDS or snapshot['snapshot_number'] != number or snapshot['replay_version'] != SEMANTIC_VERSION:
            raise ValueError('history_snapshot_identity_invalid')
        if snapshot['schema_version']!='1.0.0' or type(snapshot['synthetic']) is not bool or snapshot['synthetic']!=self.manifest['synthetic'] or any(type(snapshot[key]) is not int or snapshot[key]<0 for key in ('snapshot_number','arrival_seq','revision_number')):
            raise ValueError('history_snapshot_scalar_contract_invalid')
        context = self.manifest['context']
        if snapshot['config_fingerprint'] != context['semantic_config_fingerprint'] or snapshot['semantic_config_fingerprint'] != context['semantic_config_fingerprint']:
            raise ValueError('history_snapshot_config_invalid')
        if fingerprint(snapshot['analysis']) != snapshot['state_fingerprint']:
            raise ValueError('history_state_fingerprint_invalid')
        if 'snapshot-' + fingerprint({key: value for key, value in snapshot.items() if key != 'snapshot_id'}) != snapshot['snapshot_id']:
            raise ValueError('history_snapshot_fingerprint_invalid')
        return snapshot

    def snapshot(self, number, *, projection=False):
        if type(number) is not int or not 0 <= number < self.manifest['snapshot_count']:
            raise ValueError('history_snapshot_number_invalid')
        checkpoint, _ = self._record(number)
        fields = {}
        for index in range(checkpoint, number + 1):
            base, record = self._record(index)
            fields = self._apply(fields, index, base, record)
        snapshot = self._snapshot(number, fields, record)
        if projection:
            from .dual_source_export import event_graph
            projected = event_graph(snapshot['analysis'], replay=True)
            snapshot.update(graph=projected['graph.json'], events=projected['events.json'])
        return snapshot

    def revisions(self, after=0, limit=100):
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('history_revision_page_invalid')
        rows = self.connection.execute('SELECT payload FROM revisions ORDER BY number LIMIT ? OFFSET ?', (limit, after))
        return [self._revision(row[0]) for row in rows]

    def _revision(self, payload):
        fields = strict_json(payload.decode())
        if payload != canonical(fields) or not isinstance(fields, dict):
            raise ValueError('history_revision_encoding_invalid')
        budget={'nodes':0,'bytes':0}
        revision = {key: self._node(ref,budget=budget) for key, ref in fields.items()}
        validate('ReplayRevision', revision)
        if revision['revision_id'] != 'revision-' + fingerprint({key: value for key, value in revision.items() if key != 'revision_id'}):
            raise ValueError('history_revision_fingerprint_invalid')
        return revision

    def verify(self):
        manifest = self.manifest
        limits = manifest['limits']
        catalog=set(self.connection.execute('SELECT type,name,tbl_name FROM sqlite_master'))
        expected={('table','objects','objects'),('table','snapshots','snapshots'),('table','revisions','revisions'),('index','sqlite_autoindex_objects_1','objects')}
        if catalog!=expected:raise ValueError('history_database_schema_invalid')
        if self.connection.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise ValueError('history_database_integrity_invalid')
        for table, expected, maximum in (('objects', manifest['object_count'], limits['max_objects']),
                                         ('snapshots', manifest['snapshot_count'], limits['max_snapshots']),
                                         ('revisions', manifest['revision_count'], limits['max_revisions'])):
            if expected > maximum or self.connection.execute('SELECT count(*) FROM ' + table).fetchone()[0] != expected:
                raise ValueError('history_record_count_invalid')
        for digest, kind, payload in self.connection.execute('SELECT digest,kind,payload FROM objects'):
            if not _digest(digest) or kind not in ('value', 'leaf', 'branch') or not isinstance(payload, bytes) or len(payload) > limits['max_object_bytes'] or _hash(kind, payload) != digest:
                raise ValueError('history_object_changed')
        fields, previous, revisions = {}, None, 0
        for number in range(manifest['snapshot_count']):
            checkpoint, record = self._record(number)
            fields = self._apply(fields, number, checkpoint, record)
            snapshot = self._snapshot(number, fields, record)
            if record['previous_snapshot_id'] != (previous['snapshot_id'] if previous else None):
                raise ValueError('history_snapshot_chain_invalid')
            changed = previous is not None and previous['state_fingerprint'] != snapshot['state_fingerprint']
            if snapshot['revision_number'] != revisions + changed:
                raise ValueError('history_revision_counter_invalid')
            if changed:
                revisions += 1
                if record['revision'] != revisions:
                    raise ValueError('history_revision_link_invalid')
                row = self.connection.execute('SELECT payload FROM revisions WHERE number=?', (revisions,)).fetchone()
                if row is None:
                    raise ValueError('history_revision_missing')
                revision = self._revision(row[0])
                for key, expected in (('old_snapshot_id', previous['snapshot_id']), ('new_snapshot_id', snapshot['snapshot_id']),
                                      ('old_snapshot_number', number - 1), ('new_snapshot_number', number),
                                      ('old_state_fingerprint', previous['state_fingerprint']), ('new_state_fingerprint', snapshot['state_fingerprint']),
                                      ('available_at', snapshot['available_at']), ('trigger', snapshot['trigger']), ('revision_number', revisions),
                                      ('config_fingerprint', snapshot['config_fingerprint']),
                                      ('semantic_config_fingerprint', snapshot['semantic_config_fingerprint']),
                                      ('config_version', snapshot['config_version']), ('synthetic', snapshot['synthetic']),
                                      ('evidence_refs', references([snapshot['trigger']['evidence_refs'], snapshot['analysis']]))):
                    if revision[key] != expected:
                        raise ValueError('history_revision_link_invalid')
            elif record['revision'] is not None:
                raise ValueError('history_unexpected_revision')
            previous = snapshot
        if previous is None or previous['snapshot_id'] != manifest['last_snapshot_id'] or revisions != manifest['revision_count']:
            raise ValueError('history_terminal_binding_invalid')
        return {'status': 'storage_and_logical_hashes_verified; original_sources_and_publication_not_verified',
                'snapshot_count': manifest['snapshot_count'], 'revision_count': revisions}
