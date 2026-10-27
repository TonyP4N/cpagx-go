#!/usr/bin/env python3
"""Offline M4 validation bundles. Local directories + docker pg_dump, no archive extraction.
Only explicitly named disposable databases are accepted by this validation utility.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import stat
import tempfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'services/analysis/src'))
from cpag_core.contracts import validate
from cpag_core.evidence import EvidenceIndex
from cpag_core.packet_pipeline import PacketEvidence
from cpag_core.packet_job import verify_artifacts as verify_packet_artifacts
from cpag_core.pipeline import fingerprint, canonical
from cpag_core.dual_source import strict_json
from cpag_core.dual_source_export import FILES as DUAL_FILES, verify_task as verify_dual_task
from cpag_core.intake import preflight as verify_intake_preflight

TERMINAL = {'succeeded', 'failed', 'cancelled'}
CATALOG_TABLES = (
    'v3_users', 'v3_sessions', 'v3_datasets', 'v3_dataset_acl',
    'v3_source_files', 'v3_dataset_files', 'v3_config_versions',
    'v3_run_bindings', 'v3_preflights', 'v3_audit_events',
)
CATALOG_ORDER = {
    'v3_dataset_acl': 'dataset_id,user_id',
    'v3_run_bindings': 'job_id',
}
CATALOG_REDACT = {
    # The database dump is private operational material. The human-readable
    # manifest must not duplicate authentication verifiers or session tokens.
    'v3_users': " - 'password_hash'",
    'v3_sessions': " - 'token_hash' - 'revoked_at'",
}


def catalog_query(table, prefix=False):
    """Fixed SQL for nonsecret directory projections; table names are constants."""
    if table not in CATALOG_TABLES:
        raise ValueError('unsupported catalog table')
    order = CATALOG_ORDER.get(table, 'id')
    projection = 'to_jsonb(t)' + CATALOG_REDACT.get(table, '')
    result = f"coalesce(jsonb_agg({projection} ORDER BY {order}),'[]'::jsonb)::text"
    marker = "'CATALOG:" + table + ":'||" if prefix else ''
    return f'SELECT {marker}{result} FROM {table} t;'


def catalog_now(container, db):
    catalog = {}
    for table in CATALOG_TABLES:
        result = pg(container, db, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                    '-c', catalog_query(table), capture_output=True, text=True)
        catalog[table] = json.loads(result.stdout)
    return catalog


def revoke_restored_sessions(container):
    """Invalidate every restored login before a restored service can be started."""
    result = pg(container, 'm4_restore_validation', 'psql', '-X', '-qAt',
                '-v', 'ON_ERROR_STOP=1', '-c',
                "WITH revoked AS (UPDATE v3_sessions SET revoked_at=clock_timestamp() "
                "WHERE revoked_at IS NULL RETURNING id) SELECT count(*) FROM revoked;",
                capture_output=True, text=True)
    count = int(result.stdout.strip())
    remaining = pg(container, 'm4_restore_validation', 'psql', '-X', '-qAt',
                   '-v', 'ON_ERROR_STOP=1', '-c',
                   'SELECT count(*) FROM v3_sessions WHERE revoked_at IS NULL;',
                   capture_output=True, text=True)
    if int(remaining.stdout.strip()) != 0:
        raise ValueError('restored login sessions remain active')
    return count


def audit_dual(row, root, verify):
    """Bind the database publication to the original, reverified dual run."""
    payload=row['payload']
    profile=strict_json(safe(root,payload['profile']['path']).read_text(encoding='utf-8'))
    if fingerprint(profile)!=payload['config_fingerprint']:
        raise ValueError('dual profile config fingerprint mismatch')
    if row['state']!='succeeded':
        return
    attempt=row.get('attempt')
    if type(attempt) is not int or attempt<1:
        raise ValueError('dual published attempt identity missing')
    base=Path('jobs')/row['id']/('attempt-'+str(attempt))
    manifest=verify((base/'manifest.json').as_posix(),row['artifact_sha256'])
    published=verify(row['artifact_path'],row['artifact_sha256'])
    if published.read_bytes()!=manifest.read_bytes():
        raise ValueError('dual content-addressed publication mismatch')
    expected_key=base/(row['artifact_sha256']+'.json')
    if row['artifact_path']!=expected_key.as_posix():
        raise ValueError('dual published attempt path mismatch')
    wrapper=strict_json(manifest.read_text(encoding='utf-8'))
    if wrapper['config_fingerprint']!=payload['config_fingerprint']:
        raise ValueError('dual wrapper config fingerprint mismatch')
    if wrapper['inputs']!={role:payload[role]['sha256'] for role in ('network','process','profile')}:
        raise ValueError('dual wrapper source mismatch')
    entries=wrapper['artifacts']
    if (not isinstance(entries,list) or len(entries)!=len(DUAL_FILES)
            or {entry['path'] for entry in entries}!=DUAL_FILES):
        raise ValueError('unexpected dual artifact set')
    for entry in entries:
        verify((base/entry['path']).as_posix(),entry['sha256'],entry['size'])
    output=safe(root,base.as_posix())
    expected_files=DUAL_FILES|{'manifest.json',row['artifact_sha256']+'.json'}
    if set(inventory(output))!=expected_files:
        raise ValueError('unexpected dual publication file inventory')
    # The core verifier requires its exact eleven-file export tree. The
    # task publication adds two wrappers, so verify an isolated byte copy.
    with tempfile.TemporaryDirectory(prefix='cpag-dual-audit-') as temporary:
        export=Path(temporary)/'export'
        export.mkdir()
        for name in DUAL_FILES:
            target=export/name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(output/name,target)
        core=verify_dual_task(export)
    if core['run_id']!=row['id'] or core['attempt_id']!=attempt:
        raise ValueError('dual core run/attempt identity mismatch')
    for role,name in (('network','network.pcap'),('process','process.csv'),('profile','profile.json')):
        if safe(root,payload[role]['path']).read_bytes()!=(output/'dual/sources'/name).read_bytes():
            raise ValueError('dual retained original input differs: '+role)


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024), b''): h.update(block)
    return h.hexdigest()


def safe(root, rel):
    p=Path(rel)
    if p.is_absolute() or not p.parts or '..' in p.parts or '\\' in str(rel):
        raise ValueError('unsafe relative reference')
    target=root/p
    if not target.resolve().is_relative_to(root.resolve()): raise ValueError('reference escapes root')
    for part in [target,*target.parents]:
        if part==root.parent: break
        if part.is_symlink(): raise ValueError('symlink forbidden')
    return target


def inventory(root):
    """Inventory every entry or fail; never treat a missing/unreadable tree as empty."""
    root=Path(root)
    if root.is_symlink() or not root.is_dir():raise ValueError('file tree root missing, not a directory or symlink')
    result={}
    def walk(directory):
        # scandir raises on inaccessible/disappeared directories. Path.rglob can
        # suppress traversal errors, which cannot establish a complete backup.
        with os.scandir(directory) as entries:
            for entry in sorted(entries,key=lambda item:item.name):
                path=Path(entry.path);mode=entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):raise ValueError('symlink in file tree')
                if stat.S_ISDIR(mode):walk(path)
                elif stat.S_ISREG(mode):
                    result[path.relative_to(root).as_posix()]={'sha256':sha(path),'size_bytes':path.stat().st_size}
                else:raise ValueError('non-regular source')
    walk(root)
    return result


def audit(rows, root):
    """Verify all database-referenced inputs and successful publication chains."""
    used=set(); errors=[];jobs=[];seen_jobs=set()
    def verify(rel, digest, size=None):
        if not isinstance(rel,str) or not rel:raise ValueError('invalid file reference path')
        p=safe(root,rel)
        used.add(rel)
        if not p.is_file(): raise ValueError('missing file: '+rel)
        if sha(p)!=digest or (size is not None and p.stat().st_size!=size): raise ValueError('checksum/size mismatch: '+rel)
        return p
    if not isinstance(rows,list):
        rows=[];errors.append({'scope':'jobs','reason':'job snapshot must be an array'})
    for position,row in enumerate(rows):
        job_id=row.get('id') if isinstance(row,dict) and isinstance(row.get('id'),str) else None
        try:
            if not isinstance(row,dict) or not job_id:raise ValueError('job must be an object with nonempty id')
            if job_id in seen_jobs:raise ValueError('duplicate job identity')
            seen_jobs.add(job_id)
            if row['state'] not in TERMINAL: raise ValueError('active/nonterminal task: '+row['id'])
            payload=row.get('payload')
            if not isinstance(payload,dict):raise ValueError('job payload must be an object')
            packet=payload.get('kind')=='packet'
            dual=payload.get('kind')=='dual-source'
            if payload.get('kind') not in (None,'','packet','dual-source'):raise ValueError('unknown task kind')
            for role in ('network','process','profile'):
                ref=payload.get(role)
                if not isinstance(ref,dict):raise ValueError('missing or invalid input reference: '+role)
                verify(ref['path'],ref['sha256'])
            if dual:
                audit_dual(row,root,verify)
            if row['state']=='succeeded' and not dual:
                manifest=verify(row['artifact_path'],row['artifact_sha256'])
                wrapper=json.loads(manifest.read_text())
                base=Path(row['artifact_path']).parent
                seen=set()
                for a in wrapper['artifacts']:
                    if Path(a['path']).name!=a['path'] or a['path'] in seen: raise ValueError('invalid or duplicate artifact')
                    seen.add(a['path']);verify((base/a['path']).as_posix(),a['sha256'],a['size'])
                expected_set={'dataset.json','events.json','graph.json','quality.json','run_manifest.json'} | ({'packet_observations.json'} if packet else set())
                if seen!=expected_set: raise ValueError('unexpected core artifact set')
                for role in ('network','process','profile'):
                    if wrapper['inputs'][role]!=payload[role]['sha256']: raise ValueError('wrapper source mismatch')
                if wrapper['config_fingerprint']!=payload['config_fingerprint']: raise ValueError('config mismatch')
                core=json.loads(safe(root,(base/'run_manifest.json').as_posix()).read_text())
                if core['status'] not in ('succeeded','succeeded_with_warnings') or core['synthetic'] is not True: raise ValueError('core success mismatch')
                if core['config_fingerprint']!=wrapper['config_fingerprint']: raise ValueError('core config mismatch')
                for a in core['artifacts']:
                    verify((base/a['path']).as_posix(),a['sha256'],a['size_bytes'])
                dataset=json.loads(safe(root,(base/'dataset.json').as_posix()).read_text())
                expected={payload[k]['sha256'] for k in ('network','process')}
                if {f['sha256'] for f in dataset['files']}!=expected: raise ValueError('dataset source mismatch')
                validate('RunManifest',core);validate('DatasetManifest',dataset)
                if {a['path'] for a in core['artifacts']} != expected_set-{'run_manifest.json'} or len(core['artifacts'])!=len(expected_set)-1:
                    raise ValueError('unexpected core artifact set')
                indexes = {payload[k]['sha256']:(PacketEvidence(safe(root,payload[k]['path']),synthetic=True) if packet and k=='network' else EvidenceIndex(safe(root,payload[k]['path']),payload[k]['sha256'])) for k in ('network','process')}
                packet_sidecar=verify_packet_artifacts(safe(root,base.as_posix()),safe(root,payload['network']['path'])) if packet else None
                profile=json.loads(safe(root,payload['profile']['path']).read_text())
                if hashlib.sha256(canonical(profile)).hexdigest()!=payload['config_fingerprint']:
                    raise ValueError('profile config fingerprint mismatch')
                if len(dataset['files'])!=2 or {f['kind'] for f in dataset['files']}!={'network','process'}:
                    raise ValueError('dataset role coverage mismatch')
                for entry in dataset['files']:
                    role=entry['kind'];source=safe(root,payload[role]['path'])
                    if entry['sha256']!=payload[role]['sha256'] or entry['size_bytes']!=source.stat().st_size:
                        raise ValueError('dataset file metadata mismatch')
                expected_input=fingerprint([{k:v for k,v in f.items() if k!='name'} for f in dataset['files']])
                if core['input_fingerprint']!=expected_input:raise ValueError('input fingerprint mismatch')
                def resolve(ref):
                    if ref['file_sha256'] not in indexes: raise ValueError('unresolved evidence source')
                    source=indexes[ref['file_sha256']]
                    original=source.resolve(ref)
                    if isinstance(source,EvidenceIndex) and source.path.suffix.lower()=='.csv' and original.get(profile['timestamp_column'])!=ref['raw_time']:
                        raise ValueError('evidence raw time differs from original record')
                    return original
                events=json.loads(safe(root,(base/'events.json').as_posix()).read_text())
                event_map={}
                for e in events:
                    if e['event_id'] in event_map: raise ValueError('duplicate event id')
                    kind='NetworkEvent' if e['source_ref']['file_sha256']==payload['network']['sha256'] else 'ProcessObservation'
                    validate(kind,e);resolve(e['source_ref']);event_map[e['event_id']]=e
                graph=json.loads(safe(root,(base/'graph.json').as_posix()).read_text())
                validate('GraphArtifact',graph)
                if graph['input_fingerprint']!=core['input_fingerprint']:raise ValueError('graph input fingerprint mismatch')
                if core['result_hashes']!={'events':fingerprint(events),'graph':fingerprint(graph)}:
                    raise ValueError('core result fingerprint mismatch')
                nodes={}
                for node in graph['nodes']:
                    if node['id'] in nodes or node['event_id'] not in event_map: raise ValueError('invalid graph event node')
                    event=event_map[node['event_id']]
                    expected_refs=next((o['source_refs'] for e,o in zip(packet_sidecar['events'],packet_sidecar['observations']) if e['event_id']==event['event_id']),[]) if packet else [event['source_ref']]
                    if node['evidence_refs']!=expected_refs: raise ValueError('graph node evidence differs from event')
                    expected_kind='network' if event['source_ref']['file_sha256']==payload['network']['sha256'] else 'process'
                    if node['kind']!=expected_kind: raise ValueError('graph node kind differs')
                    for ref in node['evidence_refs']:resolve(ref)
                    nodes[node['id']]=node
                if {n['event_id'] for n in nodes.values()}!=set(event_map) or len(nodes)!=len(event_map):
                    raise ValueError('graph event coverage mismatch')
                claims={}
                for claim in graph['claims']:
                    if claim['claim_id'] in claims: raise ValueError('duplicate claim')
                    for ref in claim['evidence_refs']+claim['counterevidence']:resolve(ref)
                    claims[claim['claim_id']]=claim
                edge_ids=set()
                for edge in graph['edges']:
                    if edge['id'] in edge_ids or edge['source'] not in nodes or edge['target'] not in nodes or edge['claim_id'] not in claims:
                        raise ValueError('unresolved graph edge')
                    edge_ids.add(edge['id'])
                if graph['statistics']!={'nodes':len(nodes),'edges':len(edge_ids)}:raise ValueError('graph statistics mismatch')
                for source in indexes.values():
                    source._verified() if isinstance(source,PacketEvidence) else source.verify()
            jobs.append({'row_index':position,'job_id':job_id,'valid':True})
        except (OSError,ValueError,KeyError,TypeError,AttributeError,IndexError) as exc:
            errors.append({'row_index':position,'job_id':job_id,'reason':str(exc)})
            jobs.append({'row_index':position,'job_id':job_id,'valid':False})
    inventory_complete=True
    try:files=inventory(root)
    except (OSError,ValueError) as exc:
        files={};inventory_complete=False;errors.append({'scope':'file_tree','reason':str(exc)})
    return {'valid':not errors,'errors':errors,'jobs':jobs,'inventory_complete':inventory_complete,'referenced_files':sorted(used),
            'unreferenced_files':sorted(set(files)-used),
            'orphan_policy':'retain_and_report; unreferenced may be prior attempts or diagnostics, never delete automatically'}


def audit_attempts(rows, attempts):
    """Check all history entries independently without exposing execution tokens."""
    jobs={};seen={};errors=[]
    if not isinstance(rows,list):rows=[];errors.append({'scope':'jobs','reason':'job snapshot must be an array'})
    if not isinstance(attempts,list):attempts=[];errors.append({'scope':'attempts','reason':'attempt snapshot must be an array'})
    for position,row in enumerate(rows):
        try:
            if not isinstance(row,dict) or not isinstance(row.get('id'),str) or not row['id']:
                raise ValueError('invalid history job identity')
            if row['id'] in jobs:raise ValueError('duplicate history job identity')
            current=row.get('attempt',0)
            if type(current) is not int or not 0<=current<=100:raise ValueError('invalid job attempt count')
            jobs[row['id']]=row
        except (ValueError,KeyError,TypeError) as error:errors.append({'row_index':position,'reason':str(error)})
    for position,attempt in enumerate(attempts):
        job_id=attempt.get('job_id') if isinstance(attempt,dict) else None
        number=attempt.get('attempt') if isinstance(attempt,dict) else None
        try:
            if not isinstance(attempt,dict) or not isinstance(job_id,str) or job_id not in jobs or type(number) is not int or number<1:
                raise ValueError('invalid history job/attempt')
            if (job_id,number) in seen:raise ValueError('duplicate attempt history')
            row=jobs[job_id]
            if number>row.get('attempt',0):raise ValueError('history beyond current attempt')
            if not attempt.get('worker') or not attempt.get('attempt_token'):raise ValueError('history execution identity missing')
            if number==row['attempt'] and (attempt['worker']!=row['worker'] or attempt['attempt_token']!=row['attempt_token']):
                raise ValueError('latest attempt identity mismatch')
            receipt=attempt.get('exit_receipt')
            revoked=attempt.get('start_revoked_at')
            not_started=isinstance(receipt,dict) and (receipt.get('scope')=='not-started' or receipt.get('start_revoked') is True)
            if not_started:
                if (attempt.get('executor_kind')!='isolated-v2' or not isinstance(revoked,str) or not revoked
                    or attempt.get('container_id')!='' or receipt.get('scope')!='not-started'
                    or receipt.get('start_revoked') is not True or not isinstance(attempt.get('location'),str)
                    or not attempt['location'] or receipt.get('location')!=attempt['location']):
                    raise ValueError('invalid not-started revocation evidence')
            if revoked is not None:
                if attempt.get('executor_kind') not in ('legacy','isolated-v2') or not isinstance(revoked,str) or not revoked:
                    raise ValueError('invalid revoked execution metadata')
                if attempt.get('publication_state')=='published':raise ValueError('revoked attempt cannot publish')
                if not not_started:
                    # A later genuine removal receipt may replace not-started
                    # proof while the start gate remains permanently revoked.
                    if (not isinstance(receipt,dict) or receipt.get('scope')!='container'
                        or not attempt.get('container_id') or receipt.get('container_id')!=attempt['container_id']
                        or receipt.get('location')!=attempt.get('location') or receipt.get('removed') is not True
                        or receipt.get('exited') is not True or receipt.get('inspected_id')!=attempt['container_id']
                        or receipt.get('running') is not False or type(receipt.get('pid')) is not int or receipt['pid']!=0
                        or receipt.get('labels',{}).get('cpag.job')!=job_id
                        or receipt.get('labels',{}).get('cpag.attempt')!=str(number)
                        or receipt.get('labels',{}).get('cpag.worker')!=attempt['worker']):
                        raise ValueError('revoked execution requires bound removal evidence')
            if receipt is not None:
                if not isinstance(receipt,dict) or receipt.get('id')!=job_id or receipt.get('attempt')!=number or receipt.get('worker')!=attempt['worker'] or receipt.get('token')!=attempt['attempt_token']:
                    raise ValueError('history exit receipt identity mismatch')
                if attempt.get('exited_at') is None:raise ValueError('history exit receipt lacks exited_at')
            if attempt.get('publication_state')=='published':
                if number!=row['attempt'] or row['state']!='succeeded' or attempt.get('artifact_path')!=row['artifact_path'] or attempt.get('artifact_sha256')!=row['artifact_sha256']:
                    raise ValueError('history publication mismatch')
            elif number==row['attempt'] and row['state']=='succeeded':raise ValueError('success lacks published attempt history')
            seen[(job_id,number)]=attempt
        except (KeyError,TypeError,ValueError,AttributeError) as error:errors.append({'row_index':position,'job_id':job_id,'attempt':number,'reason':str(error)})
    for row in jobs.values():
        if {n for j,n in seen if j==row['id']}!=set(range(1,row.get('attempt',0)+1)):
            errors.append({'job_id':row['id'],'reason':'incomplete attempt history'})
    return {'valid':not errors,'errors':errors,'attempt_count':len(attempts),'verified_attempt_count':len(seen)}


def audit_catalog(catalog, rows, root):
    """Verify V3 directory ownership and original bytes, including unused uploads.

    PostgreSQL foreign keys remain the primary write barrier. This independent
    audit rejects a missing, mixed, or tampered bundle before database mutation
    and checks restored data against the immutable M4 input/publication chain.
    No credential verifiers or session tokens are accepted in this projection.
    """
    errors=[]; referenced=set(); counts={}; tables={}
    if not isinstance(catalog,dict) or set(catalog)!=set(CATALOG_TABLES):
        return {'valid':False,'errors':[{'scope':'catalog','reason':'incomplete catalog table set'}]}
    for table in CATALOG_TABLES:
        value=catalog[table]
        if not isinstance(value,list) or any(not isinstance(row,dict) for row in value):
            errors.append({'scope':table,'reason':'catalog table must be an array of objects'})
            tables[table]=[]
        else:
            tables[table]=value
        counts[table]=len(tables[table])
    if errors:return {'valid':False,'errors':errors,'counts':counts}
    if any('password_hash' in row for row in tables['v3_users']) or any(
            'token_hash' in row or 'revoked_at' in row for row in tables['v3_sessions']):
        return {'valid':False,'errors':[{'scope':'catalog','reason':'credential field in catalog projection'}],
                'counts':counts}

    def identity(table, key='id'):
        indexed={}
        for row in tables[table]:
            value=row.get(key)
            if not isinstance(value,(str,int)) or value=='':
                errors.append({'scope':table,'reason':'invalid row identity'});continue
            if value in indexed:errors.append({'scope':table,'reason':'duplicate row identity'})
            indexed[value]=row
        return indexed

    users=identity('v3_users');datasets=identity('v3_datasets')
    source_files=identity('v3_source_files');dataset_files=identity('v3_dataset_files')
    configs=identity('v3_config_versions');jobs={}
    for row in rows:
        if isinstance(row,dict) and isinstance(row.get('id'),str):jobs[row['id']]=row
    identity('v3_sessions');identity('v3_run_bindings','job_id')
    identity('v3_preflights');identity('v3_audit_events')
    acl_keys=set();versions=set();source_owners=set();run_jobs=set();verified_preflights={}

    def unique_json(raw):
        def no_duplicates(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('duplicate snapshot JSON key')
                result[key]=value
            return result
        def no_nonfinite(_):raise ValueError('nonfinite snapshot JSON')
        return json.loads(raw,object_pairs_hook=no_duplicates,parse_constant=no_nonfinite)

    def recorded_time(value):
        if not isinstance(value,str):raise ValueError('catalog timestamp missing')
        stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
        if stamp.tzinfo is None:raise ValueError('catalog timestamp lacks timezone')
        return stamp

    def user_exists(value):return value in users
    def valid_digest(value):
        return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
    def verify_file(path,digest,size=None):
        if not isinstance(path,str) or not path:raise ValueError('invalid catalog file path')
        file=safe(root,path);referenced.add(path)
        if not file.is_file():raise ValueError('missing catalog file: '+path)
        if not valid_digest(digest) or sha(file)!=digest:
            raise ValueError('catalog file checksum mismatch: '+path)
        if size is not None and (type(size) is not int or size<0 or file.stat().st_size!=size):
            raise ValueError('catalog file size mismatch: '+path)
        return file

    def belongs_to_dataset(path,dataset_id,profile=False):
        if not isinstance(path,str) or not isinstance(dataset_id,str):return False
        parts=Path(path).parts
        prefix=('inputs','catalog',dataset_id)+(('profiles',) if profile else ())
        return len(parts)>len(prefix) and parts[:len(prefix)]==prefix

    for row in tables['v3_sessions']:
        if not user_exists(row.get('user_id')):
            errors.append({'scope':'v3_sessions','reason':'session owner missing'})
    for row in tables['v3_datasets']:
        if not user_exists(row.get('created_by')):
            errors.append({'scope':'v3_datasets','reason':'dataset creator missing'})
        if row.get('source_kind') not in ('synthetic','real'):
            errors.append({'scope':'v3_datasets','reason':'invalid source kind'})
        if row.get('verification_status') not in ('accepted_unvalidated','metadata_checked','rejected'):
            errors.append({'scope':'v3_datasets','reason':'invalid verification status'})
    for row in tables['v3_dataset_acl']:
        key=(row.get('dataset_id'),row.get('user_id'))
        if key in acl_keys:errors.append({'scope':'v3_dataset_acl','reason':'duplicate dataset access'})
        acl_keys.add(key)
        if key[0] not in datasets or not user_exists(key[1]):
            errors.append({'scope':'v3_dataset_acl','reason':'dangling access ownership'})
        if row.get('access') not in ('viewer','analyst','owner'):
            errors.append({'scope':'v3_dataset_acl','reason':'invalid access role'})
    for row in tables['v3_source_files']:
        try:verify_file(row.get('storage_path'),row.get('sha256'),row.get('size_bytes'))
        except (OSError,ValueError,TypeError) as exc:
            errors.append({'scope':'v3_source_files','id':row.get('id'),'reason':str(exc)})
    for row in tables['v3_dataset_files']:
        source=source_files.get(row.get('source_file_id'))
        if row.get('dataset_id') not in datasets or source is None or not user_exists(row.get('created_by')):
            errors.append({'scope':'v3_dataset_files','id':row.get('id'),'reason':'dangling dataset/file/user ownership'})
        if row.get('role') not in ('network','process'):
            errors.append({'scope':'v3_dataset_files','id':row.get('id'),'reason':'invalid input role'})
        if source is not None:
            source_owners.add(source['id'])
            if not belongs_to_dataset(source.get('storage_path'),row.get('dataset_id')):
                errors.append({'scope':'v3_dataset_files','id':row.get('id'),'reason':'source path outside owning dataset'})
    for source_id in source_files:
        if source_id not in source_owners:
            errors.append({'scope':'v3_source_files','id':source_id,'reason':'source file has no dataset owner'})
    for row in tables['v3_config_versions']:
        if row.get('dataset_id') not in datasets or not user_exists(row.get('created_by')):
            errors.append({'scope':'v3_config_versions','id':row.get('id'),'reason':'dangling config ownership'})
        if row.get('kind') not in ('intake','dual') or type(row.get('version')) is not int or row['version']<1:
            errors.append({'scope':'v3_config_versions','id':row.get('id'),'reason':'invalid config kind/version'})
        key=(row.get('dataset_id'),row.get('kind'),row.get('version'))
        if key in versions:errors.append({'scope':'v3_config_versions','id':row.get('id'),'reason':'duplicate config version'})
        versions.add(key)
        if not belongs_to_dataset(row.get('profile_storage_path'),row.get('dataset_id'),profile=True):
            errors.append({'scope':'v3_config_versions','id':row.get('id'),'reason':'profile path outside owning dataset'})
        try:
            profile=verify_file(row.get('profile_storage_path'),row.get('profile_sha256'))
            document=strict_json(profile.read_text(encoding='utf-8'))
            if (document!=row.get('profile_json') or
                    hashlib.sha256(canonical(document)).hexdigest()!=row.get('config_fingerprint')):
                raise ValueError('config source/document/fingerprint mismatch')
        except (OSError,ValueError,TypeError,UnicodeError) as exc:
            errors.append({'scope':'v3_config_versions','id':row.get('id'),'reason':str(exc)})
    for row in tables['v3_run_bindings']:
        job_id=row.get('job_id');job=jobs.get(job_id)
        dataset_id=row.get('dataset_id');config=configs.get(row.get('config_version_id'))
        network=dataset_files.get(row.get('network_file_id'))
        process=dataset_files.get(row.get('process_file_id'))
        if job_id in run_jobs:errors.append({'scope':'v3_run_bindings','job_id':job_id,'reason':'duplicate run binding'})
        run_jobs.add(job_id)
        if (job is None or dataset_id not in datasets or config is None or network is None or
                process is None or not user_exists(row.get('created_by'))):
            errors.append({'scope':'v3_run_bindings','job_id':job_id,'reason':'dangling run ownership'});continue
        if (config.get('dataset_id')!=dataset_id or network.get('dataset_id')!=dataset_id or
                process.get('dataset_id')!=dataset_id or network.get('role')!='network' or
                process.get('role')!='process'):
            errors.append({'scope':'v3_run_bindings','job_id':job_id,'reason':'run input ownership/role mismatch'});continue
        network_source=source_files.get(network.get('source_file_id'))
        process_source=source_files.get(process.get('source_file_id'))
        if network_source is None or process_source is None:continue
        payload=job.get('payload')
        try:
            if not isinstance(payload,dict):raise ValueError('invalid run payload')
            for role,source in (('network',network_source),('process',process_source)):
                if payload.get(role)!={'path':source['storage_path'],'sha256':source['sha256']}:
                    raise ValueError('run '+role+' differs from catalog source')
            if payload.get('profile')!={'path':config['profile_storage_path'],'sha256':config['profile_sha256']}:
                raise ValueError('run profile differs from catalog version')
            if payload.get('config_fingerprint')!=config['config_fingerprint']:
                raise ValueError('run config fingerprint differs from catalog version')
            if (row.get('mode')!='dual_source' or config['kind']!='dual' or
                    payload.get('kind')!='dual-source'):
                raise ValueError('run mode/config/task kind mismatch')
        except (KeyError,ValueError,TypeError) as exc:
            errors.append({'scope':'v3_run_bindings','job_id':job_id,'reason':str(exc)})
    for job_id,job in jobs.items():
        payload=job.get('payload')
        if not isinstance(payload,dict):continue
        catalog_input=any(isinstance(payload.get(role),dict) and
                          str(payload[role].get('path','')).startswith('inputs/catalog/')
                          for role in ('network','process','profile'))
        if catalog_input and job_id not in run_jobs:
            errors.append({'scope':'v3_run_bindings','job_id':job_id,
                           'reason':'catalog-backed job lacks run ownership binding'})
    for row in tables['v3_preflights']:
        preflight_id=row.get('id');config=configs.get(row.get('config_version_id'))
        if (row.get('dataset_id') not in datasets or config is None or
                config.get('dataset_id')!=row.get('dataset_id') or not user_exists(row.get('created_by'))):
            errors.append({'scope':'v3_preflights','id':preflight_id,'reason':'dangling preflight ownership'});continue
        if config.get('kind')!='intake' or not isinstance(row.get('report'),dict):
            errors.append({'scope':'v3_preflights','id':preflight_id,'reason':'invalid preflight config/report'});continue
        status=row.get('snapshot_status');raw=row.get('snapshot_json');digest=row.get('snapshot_sha256')
        if status not in ('native','reconstructed'):
            errors.append({'scope':'v3_preflights','id':preflight_id,
                           'reason':'unverified legacy preflight snapshot: '+str(status)});continue
        if (not isinstance(raw,str) or not isinstance(digest,str) or
                hashlib.sha256(raw.encode('utf-8')).hexdigest()!=digest or row.get('snapshot_reason') is not None):
            errors.append({'scope':'v3_preflights','id':preflight_id,'reason':'snapshot bytes/hash/status mismatch'});continue
        try:
            snapshot=unique_json(raw)
            if not isinstance(snapshot,dict) or set(snapshot)!={'schema_version','origin','dataset','files','config','manifest'}:
                raise ValueError('preflight snapshot shape invalid')
            if snapshot['schema_version']!='v3-preflight-snapshot-1' or snapshot['origin']!=status:
                raise ValueError('preflight snapshot version/origin mismatch')
            dataset=datasets[row['dataset_id']]
            expected_dataset={key:dataset[key] for key in
                ('id','source_kind','source','batch','authorization_ref')}
            if snapshot['dataset']!=expected_dataset:
                raise ValueError('preflight snapshot dataset metadata mismatch')
            expected_config={'id':config['id'],'kind':'intake','version':config['version'],
                             'path':config['profile_storage_path'],'sha256':config['profile_sha256'],
                             'fingerprint':config['config_fingerprint'],'document':config['profile_json']}
            if snapshot['config']!=expected_config or row['config_version_id']!=config['id']:
                raise ValueError('preflight snapshot config/version mismatch')
            preflight_time=recorded_time(row.get('created_at'))
            if recorded_time(config.get('created_at'))>preflight_time:
                raise ValueError('preflight references later config version')
            files=snapshot['files']
            if not isinstance(files,list) or not files:
                raise ValueError('preflight snapshot files missing')
            seen=set();manifest_files=[]
            for entry in files:
                if not isinstance(entry,dict):raise ValueError('preflight snapshot file invalid')
                file_id=entry.get('dataset_file_id')
                if file_id in seen:raise ValueError('duplicate preflight snapshot file')
                seen.add(file_id)
                link=dataset_files.get(file_id)
                source=source_files.get(entry.get('source_file_id'))
                if link is None or source is None or link.get('source_file_id')!=source.get('id'):
                    raise ValueError('preflight snapshot file reference missing')
                expected_file={'dataset_file_id':link['id'],'source_file_id':source['id'],
                    'role':link['role'],'filename':link['filename'],
                    'path':source['storage_path'],'sha256':source['sha256'],
                    'size_bytes':source['size_bytes']}
                if entry!=expected_file or link['dataset_id']!=row['dataset_id']:
                    raise ValueError('preflight snapshot file identity/hash/size mismatch')
                if (recorded_time(link.get('created_at'))>preflight_time or
                        recorded_time(source.get('created_at'))>preflight_time):
                    raise ValueError('preflight references later source file')
                verify_file(source['storage_path'],source['sha256'],source['size_bytes'])
                manifest_files.append({'name':source['storage_path'],'sha256':source['sha256'],
                                       'size_bytes':source['size_bytes'],'kind':link['role']})
            if [entry['dataset_file_id'] for entry in files]!=sorted(seen):
                raise ValueError('preflight snapshot file order mismatch')
            manifest={'schema_version':'1.0.0','synthetic':dataset['source_kind']=='synthetic',
                'dataset_id':row['dataset_id'],'source':dataset['source'],'release':dataset['batch'],
                'files':manifest_files,'collection_range':{'start':None,'end':None},
                'timezone_basis':None,'authorization_ref':dataset['authorization_ref']}
            if snapshot['manifest']!=manifest:
                raise ValueError('preflight snapshot manifest differs from fixed inputs')
            with tempfile.TemporaryDirectory(prefix='cpag-intake-backup-') as temporary:
                manifest_path=Path(temporary)/'manifest.json'
                manifest_path.write_bytes(canonical(manifest)+b'\n')
                expected=verify_intake_preflight(root,manifest_path,
                    safe(root,config['profile_storage_path']))
            if expected!=row['report']:
                raise ValueError('preflight report differs from retained snapshot sources/config')
            verified_preflights[preflight_id]=snapshot
        except (OSError,ValueError,KeyError,TypeError,UnicodeError) as exc:
            errors.append({'scope':'v3_preflights','id':preflight_id,'reason':str(exc)})
    for row in tables['v3_run_bindings']:
        job_id=row.get('job_id');preflight_id=row.get('preflight_id')
        link_origin=row.get('preflight_link_origin')
        if (link_origin not in ('native_gate','reconstructed_match') or
                not isinstance(preflight_id,str) or preflight_id not in verified_preflights or
                row.get('preflight_link_reason') is not None):
            errors.append({'scope':'v3_run_bindings','job_id':job_id,
                           'reason':'run preflight gate unbound or unverified'});continue
        snapshot=verified_preflights[preflight_id]
        preflight=next(item for item in tables['v3_preflights'] if item.get('id')==preflight_id)
        if (preflight.get('dataset_id')!=row.get('dataset_id') or
                preflight.get('report',{}).get('status')!='ready_for_manual_review' or
                snapshot['dataset']['source_kind']!='synthetic' or
                {entry['dataset_file_id'] for entry in snapshot['files']}!=
                    {row.get('network_file_id'),row.get('process_file_id')} or
                len(snapshot['files'])!=2 or
                (link_origin=='native_gate' and preflight.get('snapshot_status')!='native') or
                (link_origin=='reconstructed_match' and preflight.get('snapshot_status')!='reconstructed')):
            errors.append({'scope':'v3_run_bindings','job_id':job_id,
                           'reason':'run preflight snapshot/status/input binding mismatch'})
        try:
            if recorded_time(preflight.get('created_at'))>recorded_time(row.get('created_at')):
                raise ValueError('run linked to later preflight')
        except ValueError as exc:
            errors.append({'scope':'v3_run_bindings','job_id':job_id,'reason':str(exc)})
    for row in tables['v3_audit_events']:
        if ((row.get('user_id') is not None and row['user_id'] not in users) or
                (row.get('dataset_id') is not None and row['dataset_id'] not in datasets) or
                (row.get('job_id') is not None and row['job_id'] not in jobs)):
            errors.append({'scope':'v3_audit_events','id':row.get('id'),'reason':'dangling audit reference'})
        if not isinstance(row.get('details'),dict):
            errors.append({'scope':'v3_audit_events','id':row.get('id'),'reason':'invalid audit detail'})
        else:
            def secret_key(value):
                if isinstance(value,dict):
                    forbidden={'authorization','cookie','password','password_hash','secret',
                               'token','token_hash','worker_token','coordinator_token',
                               'session_token','bearer'}
                    return any(str(key).lower() in forbidden or secret_key(item)
                               for key,item in value.items())
                if isinstance(value,list):return any(secret_key(item) for item in value)
                return False
            if secret_key(row['details']):
                errors.append({'scope':'v3_audit_events','id':row.get('id'),
                               'reason':'credential field in audit detail'})
    return {'valid':not errors,'errors':errors,'counts':counts,'referenced_files':sorted(referenced),
            'session_restore_policy':'revoke_all_sessions_before_restored_service_start'}


def include_catalog_references(task_audit, catalog_audit):
    """Unused catalog uploads/configs are live references, not file orphans."""
    extra=set(catalog_audit['referenced_files'])
    task_audit['referenced_files']=sorted(set(task_audit['referenced_files'])|extra)
    task_audit['unreferenced_files']=sorted(set(task_audit['unreferenced_files'])-extra)
    return task_audit


def pg(container, db, command, *args, **kwargs):
    if db not in ('m4_validation','m4_restore_validation'): raise ValueError('only disposable validation databases allowed')
    return subprocess.run(['docker','exec','-i',container,command,'-U','postgres','-d',db,*args],check=True,**kwargs)


def rows_now(container,db):
    result=pg(container,db,'psql','-X','-qAt','-c',"SELECT coalesce(json_agg(row_to_json(j) ORDER BY id),'[]'::json) FROM m4_jobs j",capture_output=True,text=True)
    return json.loads(result.stdout)


def attempts_now(container,db):
    result=pg(container,db,'psql','-X','-qAt','-c',"SELECT coalesce(json_agg(row_to_json(a) ORDER BY job_id,attempt),'[]'::json) FROM m4_job_attempts a",capture_output=True,text=True)
    return json.loads(result.stdout)


def backup(container, db, root, destination):
    root=Path(root).resolve();destination=Path(destination).resolve()
    if not root.is_dir(): raise ValueError('source root must exist')
    if destination.exists() or destination.is_relative_to(root): raise ValueError('new bundle outside shared root required')
    if db!='m4_validation': raise ValueError('backup source must be disposable m4_validation')
    # Hold SHARE locks across dump and copy. Writers cannot change the M4 task
    # history or V3 directory metadata while the exported snapshot is in use.
    created_destination=False;phase='database_snapshot'
    conn=subprocess.Popen(['docker','exec','-i',container,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',db],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        conn.stdin.write("BEGIN; SET LOCAL lock_timeout='5s'; "
                         "LOCK TABLE m4_jobs, m4_job_attempts IN SHARE MODE; "
                         "SELECT 'CATALOG_PRESENT:'||(to_regclass('public.v3_datasets') IS NOT NULL)::text;\n")
        conn.stdin.flush()
        first=conn.stdout.readline().strip()
        # Older unit fixtures predate the catalog-presence exchange. A real
        # database emits CATALOG_PRESENT; preserve format-2 backup support.
        legacy_fixture=first.startswith('SNAPSHOT:')
        if not legacy_fixture and first not in ('CATALOG_PRESENT:true','CATALOG_PRESENT:false'):
            raise ValueError('could not establish catalog schema state')
        has_catalog=first=='CATALOG_PRESENT:true'
        if has_catalog:
            conn.stdin.write('LOCK TABLE '+', '.join(CATALOG_TABLES)+' IN SHARE MODE;\n')
        conn.stdin.write("SELECT 'SNAPSHOT:'||pg_export_snapshot(); "
                         "SELECT 'ROWS:'||coalesce(json_agg(row_to_json(j) ORDER BY id),'[]'::json)::text FROM m4_jobs j; "
                         "SELECT 'ATTEMPTS:'||coalesce(json_agg(row_to_json(a) ORDER BY job_id,attempt),'[]'::json)::text FROM m4_job_attempts a;\n")
        if has_catalog:
            for table in CATALOG_TABLES:
                conn.stdin.write(catalog_query(table, prefix=True)+'\n')
        conn.stdin.flush()
        snapshot=first if legacy_fixture else conn.stdout.readline().strip()
        raw_rows=conn.stdout.readline().strip();raw_attempts=conn.stdout.readline().strip()
        if not snapshot.startswith('SNAPSHOT:') or not raw_rows.startswith('ROWS:') or not raw_attempts.startswith('ATTEMPTS:'): raise ValueError('could not establish database snapshot')
        rows=json.loads(raw_rows[5:]);attempts=json.loads(raw_attempts[9:]);catalog=None
        if has_catalog:
            catalog={}
            for table in CATALOG_TABLES:
                raw=conn.stdout.readline().strip();prefix='CATALOG:'+table+':'
                if not raw.startswith(prefix):raise ValueError('could not establish catalog snapshot: '+table)
                catalog[table]=json.loads(raw[len(prefix):])
        phase='source_audit';before=audit(rows,root)
        if not before['valid']: raise ValueError('source reference audit failed: '+json.dumps(before['errors']))
        history=audit_attempts(rows,attempts)
        if not history['valid']:raise ValueError('source attempt history invalid: '+json.dumps(history['errors']))
        directory=None
        if catalog is not None:
            directory=audit_catalog(catalog,rows,root)
            if not directory['valid']:
                raise ValueError('source catalog invalid: '+json.dumps(directory['errors']))
            include_catalog_references(before,directory)
        destination.mkdir(mode=0o700);created_destination=True
        phase='copy_files';files=inventory(root)
        shutil.copytree(root,destination/'files',symlinks=False)
        if inventory(destination/'files')!=files or inventory(root)!=files: raise ValueError('source changed during backup')
        # The source may have changed between the first reference audit and the
        # inventory captured for copying. Hash agreement between two copies alone
        # cannot establish agreement with the exported database snapshot.
        phase='copied_reference_audit';copied=audit(rows,destination/'files')
        if not copied['valid']:raise ValueError('copied reference audit failed: '+json.dumps(copied['errors']))
        copied_directory=None
        if catalog is not None:
            copied_directory=audit_catalog(catalog,rows,destination/'files')
            if not copied_directory['valid']:
                raise ValueError('copied catalog invalid: '+json.dumps(copied_directory['errors']))
            include_catalog_references(copied,copied_directory)
        phase='database_dump'
        with (destination/'database.dump').open('xb') as dump:
            pg(container,db,'pg_dump','-Fc','--snapshot='+snapshot[9:],stdout=dump)
        phase='final_integrity'
        if inventory(destination/'files')!=files or inventory(root)!=files:raise ValueError('files changed during database dump')
        phase='bundle_publication'
        bundle={'format_version':4 if catalog is not None else 2,'synthetic_validation_only':True,'rows':rows,'attempts':attempts,'files':files,
                'database_sha256':sha(destination/'database.dump'),'source_audit':before,'copied_audit':copied,'attempt_audit':history,
                'consistency':'exported PostgreSQL snapshot + SHARE lock; terminal tasks only; file pre/post hashes'}
        if catalog is not None:
            bundle.update(catalog=catalog,catalog_audit=directory,copied_catalog_audit=copied_directory,
                          session_restore_policy='revoke_all_sessions_before_restored_service_start')
        write_report(destination/'bundle.json',bundle)
        return bundle
    except (OSError,ValueError,KeyError,TypeError,AttributeError,IndexError,subprocess.SubprocessError) as error:
        if created_destination:
            try:write_report(destination/'backup-failure.json',{'valid':False,'phase':phase,'reason':str(error),
                'orphan_policy':'retain_and_report; incomplete bundle retained, no valid bundle published'})
            except OSError:pass
        raise
    finally:
        if conn.poll() is None:
            try: conn.stdin.write('ROLLBACK;\n\\q\n');conn.stdin.flush();conn.communicate(timeout=5)
            except (BrokenPipeError,subprocess.TimeoutExpired): conn.kill();conn.wait()


def write_report(path, value):
    """Replace only a reserved report, atomically; partial JSON never means success."""
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,
                                         prefix=path.name+'.pending-',delete=False) as stream:
            temporary=Path(stream.name)
            json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()


def restore(container, bundle_dir, destination):
    bundle_dir=Path(bundle_dir).resolve();destination=Path(destination).resolve()
    report=destination.parent/(destination.name+'-audit.json')
    if destination.exists() or report.exists() or destination.is_relative_to(bundle_dir):
        raise ValueError('restore destination and report must be new and outside bundle')
    # Atomic reservation prevents a concurrent/repeated invocation from replacing
    # another invocation's successful or failed terminal audit.
    report.parent.mkdir(parents=True,exist_ok=True)
    with open(report,'x',opener=lambda path,flags:os.open(path,flags,0o600)) as stream:
        json.dump({'valid':False,'phase':'reserved','status':'in_progress'},stream);stream.write('\n')
    phase='bundle_integrity'
    try:
        bundle=json.loads(safe(bundle_dir,'bundle.json').read_text())
        if bundle['format_version']==3:
            raise ValueError('legacy v3 catalog bundle lacks verified preflight snapshots; restore with b208bc9 in an isolated maintenance environment, apply migration 007, run cpagx-v3 --backfill-legacy, then create a format-4 backup')
        if bundle['format_version'] not in (2,4) or bundle['synthetic_validation_only'] is not True: raise ValueError('unsupported bundle')
        if sha(safe(bundle_dir,'database.dump'))!=bundle['database_sha256'] or inventory(bundle_dir/'files')!=bundle['files']:
            raise ValueError('bundle integrity mismatch')
        phase='pre_restore_references'
        before=audit(bundle['rows'],bundle_dir/'files')
        if not before['valid']: raise ValueError('bundle references invalid: '+json.dumps(before['errors']))
        history=audit_attempts(bundle['rows'],bundle.get('attempts',[]))
        if not history['valid']:raise ValueError('bundle attempt history invalid: '+json.dumps(history['errors']))
        has_catalog=bundle['format_version']==4
        if has_catalog:
            directory=audit_catalog(bundle['catalog'],bundle['rows'],bundle_dir/'files')
            if not directory['valid']:
                raise ValueError('bundle catalog invalid: '+json.dumps(directory['errors']))
        phase='create_new_database'
        # createdb refuses an existing target: never overwrite a current database.
        subprocess.run(['docker','exec',container,'createdb','-U','postgres','m4_restore_validation'],check=True)
        phase='restore_database'
        with (bundle_dir/'database.dump').open('rb') as dump:
            pg(container,'m4_restore_validation','pg_restore','--exit-on-error','--no-owner',stdin=dump)
        revoked_sessions=0
        if has_catalog:
            phase='revoke_restored_sessions'
            revoked_sessions=revoke_restored_sessions(container)
        phase='restore_files'
        shutil.copytree(bundle_dir/'files',destination)
        rows=rows_now(container,'m4_restore_validation')
        if rows!=bundle['rows']: raise ValueError('restored task metadata differs from snapshot')
        if attempts_now(container,'m4_restore_validation')!=bundle.get('attempts',[]):raise ValueError('restored attempt history differs from snapshot')
        if has_catalog:
            restored_catalog=catalog_now(container,'m4_restore_validation')
            if restored_catalog!=bundle['catalog']:
                raise ValueError('restored catalog metadata differs from snapshot')
        result=audit(rows,destination)
        if not result['valid']: raise ValueError('restored references invalid: '+json.dumps(result['errors']))
        if has_catalog:
            directory=audit_catalog(restored_catalog,rows,destination)
            if not directory['valid']:
                raise ValueError('restored catalog invalid: '+json.dumps(directory['errors']))
            include_catalog_references(result,directory)
        if inventory(destination)!=bundle['files']:raise ValueError('restored file inventory differs from bundle')
        result.update(phase='completed',database='m4_restore_validation',metadata_equal=True,
                      file_inventory_equal=True,attempt_history_equal=True)
        if has_catalog:
            result.update(catalog_equal=True,catalog_audit=directory,sessions_revoked=revoked_sessions,
                          session_restore_policy='revoke_all_sessions_before_restored_service_start')
        write_report(report,result)
        return result
    except (OSError,ValueError,KeyError,TypeError,AttributeError,IndexError,subprocess.SubprocessError) as error:
        try:
            write_report(report,{'valid':False,'phase':phase,'reason':str(error),
                'orphan_policy':'retain_and_report; partial restore retained for inspection'})
        except OSError:
            # The pre-reserved report remains invalid if capacity prevents the
            # failure update too. Preserve the original operation error.
            pass
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    for action in ('backup','restore'):
        q=sub.add_parser(action);q.add_argument('--container',required=True);q.add_argument('--destination',required=True)
        q.add_argument('--source',required=True)
    args=p.parse_args()
    result=backup(args.container,'m4_validation',args.source,args.destination) if args.action=='backup' else restore(args.container,args.source,args.destination)
    print(json.dumps({'action':args.action,'valid':True,'orphan_policy':result.get('orphan_policy',result.get('source_audit',{}).get('orphan_policy'))}))

if __name__=='__main__': main()
