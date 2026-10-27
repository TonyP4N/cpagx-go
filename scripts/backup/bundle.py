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

TERMINAL = {'succeeded', 'failed', 'cancelled'}


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
    # Hold SHARE lock across dump and copy. Writers cannot change jobs while the exported snapshot is in use.
    created_destination=False;phase='database_snapshot'
    conn=subprocess.Popen(['docker','exec','-i',container,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',db],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        query="BEGIN; SET LOCAL lock_timeout='5s'; LOCK TABLE m4_jobs, m4_job_attempts IN SHARE MODE; SELECT 'SNAPSHOT:'||pg_export_snapshot(); SELECT 'ROWS:'||coalesce(json_agg(row_to_json(j) ORDER BY id),'[]'::json)::text FROM m4_jobs j; SELECT 'ATTEMPTS:'||coalesce(json_agg(row_to_json(a) ORDER BY job_id,attempt),'[]'::json)::text FROM m4_job_attempts a;\n"
        conn.stdin.write(query);conn.stdin.flush()
        snapshot=conn.stdout.readline().strip();raw_rows=conn.stdout.readline().strip();raw_attempts=conn.stdout.readline().strip()
        if not snapshot.startswith('SNAPSHOT:') or not raw_rows.startswith('ROWS:') or not raw_attempts.startswith('ATTEMPTS:'): raise ValueError('could not establish database snapshot')
        rows=json.loads(raw_rows[5:]);attempts=json.loads(raw_attempts[9:]);phase='source_audit';before=audit(rows,root)
        if not before['valid']: raise ValueError('source reference audit failed: '+json.dumps(before['errors']))
        history=audit_attempts(rows,attempts)
        if not history['valid']:raise ValueError('source attempt history invalid: '+json.dumps(history['errors']))
        destination.mkdir(mode=0o700);created_destination=True
        phase='copy_files';files=inventory(root)
        shutil.copytree(root,destination/'files',symlinks=False)
        if inventory(destination/'files')!=files or inventory(root)!=files: raise ValueError('source changed during backup')
        # The source may have changed between the first reference audit and the
        # inventory captured for copying. Hash agreement between two copies alone
        # cannot establish agreement with the exported database snapshot.
        phase='copied_reference_audit';copied=audit(rows,destination/'files')
        if not copied['valid']:raise ValueError('copied reference audit failed: '+json.dumps(copied['errors']))
        phase='database_dump'
        with (destination/'database.dump').open('xb') as dump:
            pg(container,db,'pg_dump','-Fc','--snapshot='+snapshot[9:],stdout=dump)
        phase='final_integrity'
        if inventory(destination/'files')!=files or inventory(root)!=files:raise ValueError('files changed during database dump')
        phase='bundle_publication'
        bundle={'format_version':2,'synthetic_validation_only':True,'rows':rows,'attempts':attempts,'files':files,
                'database_sha256':sha(destination/'database.dump'),'source_audit':before,'copied_audit':copied,'attempt_audit':history,
                'consistency':'exported PostgreSQL snapshot + SHARE lock; terminal tasks only; file pre/post hashes'}
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
        if bundle['format_version']!=2 or bundle['synthetic_validation_only'] is not True: raise ValueError('unsupported bundle')
        if sha(safe(bundle_dir,'database.dump'))!=bundle['database_sha256'] or inventory(bundle_dir/'files')!=bundle['files']:
            raise ValueError('bundle integrity mismatch')
        phase='pre_restore_references'
        before=audit(bundle['rows'],bundle_dir/'files')
        if not before['valid']: raise ValueError('bundle references invalid: '+json.dumps(before['errors']))
        history=audit_attempts(bundle['rows'],bundle.get('attempts',[]))
        if not history['valid']:raise ValueError('bundle attempt history invalid: '+json.dumps(history['errors']))
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
        if attempts_now(container,'m4_restore_validation')!=bundle.get('attempts',[]):raise ValueError('restored attempt history differs from snapshot')
        result=audit(rows,destination)
        if not result['valid']: raise ValueError('restored references invalid: '+json.dumps(result['errors']))
        if inventory(destination)!=bundle['files']:raise ValueError('restored file inventory differs from bundle')
        result.update(phase='completed',database='m4_restore_validation',metadata_equal=True,
                      file_inventory_equal=True,attempt_history_equal=True)
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
