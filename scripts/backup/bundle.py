#!/usr/bin/env python3
"""Offline M4 validation bundles. Local directories + docker pg_dump, no archive extraction.
Only explicitly named disposable databases are accepted by this validation utility.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'services/analysis/src'))
from cpag_core.contracts import validate
from cpag_core.evidence import EvidenceIndex
from cpag_core.pipeline import fingerprint, canonical

TERMINAL = {'succeeded', 'failed', 'cancelled'}


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
    result={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink(): raise ValueError('symlink in file tree')
        if p.is_dir(): continue
        if not p.is_file(): raise ValueError('non-regular source')
        result[p.relative_to(root).as_posix()]={'sha256':sha(p),'size_bytes':p.stat().st_size}
    return result


def audit(rows, root):
    """Verify all database-referenced inputs and successful publication chains."""
    used=set(); errors=[]
    def verify(rel, digest, size=None):
        used.add(rel)
        p=safe(root,rel)
        if not p.is_file(): raise ValueError('missing file: '+rel)
        if sha(p)!=digest or (size is not None and p.stat().st_size!=size): raise ValueError('checksum/size mismatch: '+rel)
        return p
    for row in rows:
        try:
            if row['state'] not in TERMINAL: raise ValueError('active/nonterminal task: '+row['id'])
            payload=row.get('payload') or {}
            for role in ('network','process','profile'):
                ref=payload.get(role)
                if ref: verify(ref['path'],ref['sha256'])
            if row['state']=='succeeded':
                manifest=verify(row['artifact_path'],row['artifact_sha256'])
                wrapper=json.loads(manifest.read_text())
                base=Path(row['artifact_path']).parent
                seen=set()
                for a in wrapper['artifacts']:
                    if Path(a['path']).name!=a['path'] or a['path'] in seen: raise ValueError('invalid or duplicate artifact')
                    seen.add(a['path']);verify((base/a['path']).as_posix(),a['sha256'],a['size'])
                if seen!={'dataset.json','events.json','graph.json','quality.json','run_manifest.json'}: raise ValueError('unexpected core artifact set')
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
                if {a['path'] for a in core['artifacts']} != {'dataset.json','events.json','graph.json','quality.json'} or len(core['artifacts'])!=4:
                    raise ValueError('unexpected core artifact set')
                indexes = {payload[k]['sha256']:EvidenceIndex(safe(root,payload[k]['path']),payload[k]['sha256']) for k in ('network','process')}
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
                    if source.path.suffix.lower()=='.csv' and original.get(profile['timestamp_column'])!=ref['raw_time']:
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
                    if node['evidence_refs']!=[event['source_ref']]: raise ValueError('graph node evidence differs from event')
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
                for source in indexes.values():source.verify()
        except (OSError,ValueError,KeyError,TypeError) as exc:
            errors.append({'job_id':row.get('id'),'reason':str(exc)})
    files=inventory(root)
    return {'valid':not errors,'errors':errors,'referenced_files':sorted(used),
            'unreferenced_files':sorted(set(files)-used),
            'orphan_policy':'retain_and_report; unreferenced may be prior attempts or diagnostics, never delete automatically'}


def pg(container, db, command, *args, **kwargs):
    if db not in ('m4_validation','m4_restore_validation'): raise ValueError('only disposable validation databases allowed')
    return subprocess.run(['docker','exec','-i',container,command,'-U','postgres','-d',db,*args],check=True,**kwargs)


def rows_now(container,db):
    result=pg(container,db,'psql','-X','-qAt','-c',"SELECT coalesce(json_agg(row_to_json(j) ORDER BY id),'[]'::json) FROM m4_jobs j",capture_output=True,text=True)
    return json.loads(result.stdout)


def backup(container, db, root, destination):
    root=Path(root).resolve();destination=Path(destination).resolve()
    if not root.is_dir(): raise ValueError('source root must exist')
    if destination.exists() or destination.is_relative_to(root): raise ValueError('new bundle outside shared root required')
    if db!='m4_validation': raise ValueError('backup source must be disposable m4_validation')
    # Hold SHARE lock across dump and copy. Writers cannot change jobs while the exported snapshot is in use.
    conn=subprocess.Popen(['docker','exec','-i',container,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',db],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        query="BEGIN; SET LOCAL lock_timeout='5s'; LOCK TABLE m4_jobs IN SHARE MODE; SELECT 'SNAPSHOT:'||pg_export_snapshot(); SELECT 'ROWS:'||coalesce(json_agg(row_to_json(j) ORDER BY id),'[]'::json)::text FROM m4_jobs j;\n"
        conn.stdin.write(query);conn.stdin.flush()
        snapshot=conn.stdout.readline().strip();raw_rows=conn.stdout.readline().strip()
        if not snapshot.startswith('SNAPSHOT:') or not raw_rows.startswith('ROWS:'): raise ValueError('could not establish database snapshot')
        rows=json.loads(raw_rows[5:]);before=audit(rows,root)
        if not before['valid']: raise ValueError('source reference audit failed: '+json.dumps(before['errors']))
        destination.mkdir(mode=0o700)
        files=inventory(root)
        shutil.copytree(root,destination/'files',symlinks=False)
        if inventory(destination/'files')!=files or inventory(root)!=files: raise ValueError('source changed during backup')
        with (destination/'database.dump').open('xb') as dump:
            pg(container,db,'pg_dump','-Fc','--snapshot='+snapshot[9:],stdout=dump)
        bundle={'format_version':1,'synthetic_validation_only':True,'rows':rows,'files':files,
                'database_sha256':sha(destination/'database.dump'),'source_audit':before,
                'consistency':'exported PostgreSQL snapshot + SHARE lock; terminal tasks only; file pre/post hashes'}
        (destination/'bundle.json').write_text(json.dumps(bundle,sort_keys=True,indent=2)+'\n')
        return bundle
    finally:
        if conn.poll() is None:
            try: conn.stdin.write('ROLLBACK;\n\\q\n');conn.stdin.flush();conn.communicate(timeout=5)
            except (BrokenPipeError,subprocess.TimeoutExpired): conn.kill();conn.wait()


def restore(container, bundle_dir, destination):
    bundle_dir=Path(bundle_dir).resolve();destination=Path(destination).resolve()
    report=destination.parent/(destination.name+'-audit.json')
    if destination.exists() or report.exists() or destination.is_relative_to(bundle_dir):
        raise ValueError('restore destination and report must be new and outside bundle')
    phase='bundle_integrity'
    try:
        bundle=json.loads(safe(bundle_dir,'bundle.json').read_text())
        if bundle['format_version']!=1 or bundle['synthetic_validation_only'] is not True: raise ValueError('unsupported bundle')
        if sha(safe(bundle_dir,'database.dump'))!=bundle['database_sha256'] or inventory(bundle_dir/'files')!=bundle['files']:
            raise ValueError('bundle integrity mismatch')
        phase='pre_restore_references'
        before=audit(bundle['rows'],bundle_dir/'files')
        if not before['valid']: raise ValueError('bundle references invalid: '+json.dumps(before['errors']))
        phase='create_new_database'
        # createdb refuses an existing target: never overwrite a current database.
        subprocess.run(['docker','exec',container,'createdb','-U','postgres','m4_restore_validation'],check=True)
        phase='restore_database'
        with (bundle_dir/'database.dump').open('rb') as dump:
            pg(container,'m4_restore_validation','pg_restore','--exit-on-error','--no-owner',stdin=dump)
        phase='restore_files'
        shutil.copytree(bundle_dir/'files',destination)
        rows=rows_now(container,'m4_restore_validation')
        if rows!=bundle['rows']: raise ValueError('restored task metadata differs from snapshot')
        result=audit(rows,destination)
        if not result['valid']: raise ValueError('restored references invalid: '+json.dumps(result['errors']))
        if inventory(destination)!=bundle['files']:raise ValueError('restored file inventory differs from bundle')
        result.update(phase='completed',database='m4_restore_validation',metadata_equal=True,
                      file_inventory_equal=True)
        report.write_text(json.dumps(result,indent=2)+'\n')
        return result
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        report.parent.mkdir(parents=True,exist_ok=True)
        report.write_text(json.dumps({'valid':False,'phase':phase,'reason':str(error),
            'orphan_policy':'retain_and_report; partial restore retained for inspection'},indent=2)+'\n')
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
