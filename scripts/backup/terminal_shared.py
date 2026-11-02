"""Format7 stop-writes control inventory; no reusable source approvals."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re

@contextmanager
def maintenance(control):
    root=Path(control).resolve()
    if not root.is_dir():raise ValueError('existing private control directory required')
    path=root/'.maintenance.lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a+') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('maintenance requires stopped Go service and Worker')
        yield root

def verifier_rows(pg,container,db):
    return json.loads(pg(container,db,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c',
        "SELECT coalesce(json_agg(row_to_json(v) ORDER BY job_id,attempt),'[]'::json)::text FROM m4_compact_verifications v;",
        capture_output=True,text=True).stdout)

def _attempt_exit(attempt):
    proof=attempt.get('exit_receipt')
    if not attempt.get('exited_at') or not isinstance(proof,dict):
        raise ValueError('attempt exit proof missing')
    if (not isinstance(attempt.get('job_id'),str) or not attempt['job_id']
            or type(attempt.get('attempt')) is not int or attempt['attempt']<1
            or any(not isinstance(attempt.get(name),str) or not attempt[name] for name in ('worker','attempt_token'))
            or any(proof.get(key)!=attempt.get(field) for key,field in
                   (('id','job_id'),('attempt','attempt'),('worker','worker'),('token','attempt_token')))):
        raise ValueError('attempt exit identity mismatch')
    scope=proof.get('scope')
    location=attempt.get('location')
    if scope=='container':
        container=attempt.get('container_id')
        if (not isinstance(container,str) or re.fullmatch('[a-f0-9]{64}',container) is None
                or not isinstance(location,str) or not location.startswith('docker:')
                or proof.get('location')!=location or proof.get('container_id')!=container
                or proof.get('inspected_id')!=container or proof.get('exited') is not True
                or proof.get('removed') is not True or proof.get('running') is not False
                or type(proof.get('pid')) is not int or proof['pid']!=0
                or not isinstance(proof.get('labels'),dict)
                or any(proof['labels'].get(key)!=value for key,value in (
                    ('cpag.job',attempt['job_id']),('cpag.attempt',str(attempt['attempt'])),('cpag.worker',attempt['worker'])))):
            raise ValueError('attempt exit container evidence mismatch')
    elif scope=='not-started':
        if (attempt.get('executor_kind')!='isolated-v2' or not attempt.get('start_revoked_at')
                or attempt.get('container_id')!='' or proof.get('start_revoked') is not True
                or not isinstance(location,str) or not location.startswith('docker:')
                or proof.get('location')!=location or attempt.get('publication_state')=='published'):
            raise ValueError('attempt exit not-started evidence mismatch')
    elif scope in (None,'') and location=='legacy-process-group':
        if (proof.get('group_exited') is not True
                or any(type(proof.get(name)) is not int or proof[name]<=0 for name in ('child_pid','guardian_pid'))):
            raise ValueError('attempt exit process evidence mismatch')
    else:
        raise ValueError('attempt exit scope mismatch')

def audit_exits(rows,attempts,verifiers,control,safe):
    jobs={r['id']:r for r in rows}; seen=set()
    for a in attempts:
        _attempt_exit(a)
    for v in verifiers:
        key=(v['job_id'],v['attempt'])
        if key in seen or v['job_id'] not in jobs or not 1<=v['attempt']<=jobs[v['job_id']]['attempt']:
            raise ValueError('verifier history identity mismatch')
        seen.add(key)
        if v['state']!='exited' or not v.get('exited_at'):raise ValueError('active or unconfirmed source verifier')
        receipt=safe(control,f"compact-verification-{v['job_id']}-{v['attempt']}-{v['container_name'][:12]}.json")
        r=json.loads(receipt.read_text())
        if (not isinstance(r,dict) or r.get('version')!='service-compact-verification-execution-1'
                or r.get('run_id')!=v['job_id'] or r.get('attempt_id')!=v['attempt']
                or r.get('container_id')!=v['container_name'] or r.get('cleanup_completed') is not True):
            raise ValueError('source verifier exit receipt mismatch')
        job=jobs[v['job_id']]
        if job['state']=='succeeded' and job['attempt']==v['attempt'] and job['payload'].get('storage_format')=='shared-observation-dag-6':
            digest=job.get('artifact_sha256')
            if not isinstance(digest,str) or re.fullmatch('[a-f0-9]{64}',digest) is None or r.get('publication_sha256')!=digest:
                raise ValueError('source verifier publication binding mismatch')
    for row in rows:
        if row['state'] not in ('succeeded','failed','cancelled'):raise ValueError('active task in terminal backup')
        if row['state']=='succeeded' and row['payload'].get('storage_format')=='shared-observation-dag-6' and (row['id'],row['attempt']) not in seen:
            raise ValueError('successful shared task lacks verifier exit history')
    return {'valid':True,'attempts':len(attempts),'verifiers':len(verifiers),'source_trust':'must_reverify_in_restored_service'}

def rebase_capacity(control,old_root,new_root):
    p=Path(control)/'capacity.json'
    if not p.exists():return None
    value=json.loads(p.read_text())
    if value.get('root')!=str(old_root) or not isinstance(value.get('reservations'),dict):raise ValueError('capacity ledger root or reservations mismatch')
    if any(type(v) is not int or v<0 for v in value['reservations'].values()):raise ValueError('invalid capacity reservation')
    value['root']=str(new_root)
    temporary=p.with_suffix('.restore-tmp')
    with temporary.open('x') as f:
        os.chmod(temporary,0o600);json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
    os.replace(temporary,p)
    return {'field':'capacity.json.root','old':str(old_root),'new':str(new_root),'reservations_preserved':True}
