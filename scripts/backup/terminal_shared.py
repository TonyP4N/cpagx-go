"""Format7 stop-writes control inventory; no reusable source approvals."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
from datetime import datetime


def _kube_exit(attempt, proof):
    k=proof.get('kubernetes')
    uuid=r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
    location=attempt.get('location','')
    if (not isinstance(k,dict) or attempt.get('executor_kind')!='kubernetes-job-v1'
            or re.fullmatch('kubernetes:'+uuid,location) is None
            or proof.get('location')!=location or proof.get('exited') is not True
            or proof.get('container_id')!=attempt.get('container_id')
            or re.fullmatch(uuid,str(k.get('job_uid',''))) is None
            or k['job_uid']!=attempt.get('container_id') or k.get('namespace')!='cpag'
            or k.get('run_id')!=attempt['job_id'] or k.get('attempt')!=attempt['attempt']
            or k.get('worker')!=attempt['worker']):
        raise ValueError('attempt exit Kubernetes identity mismatch')
    try:
        when=datetime.fromisoformat(k['finished_at'].replace('Z','+00:00'))
        if when.tzinfo is None:raise ValueError()
    except (KeyError,TypeError,ValueError,AttributeError):
        raise ValueError('attempt exit Kubernetes timestamp missing')
    if k.get('version')=='kubernetes-not-started-1':
        if (k.get('removed') is not True or k.get('suspended') is not True or k.get('pod_uid')
                or k.get('container_id') or k.get('exit_code') is not None or attempt.get('publication_state')=='published'):
            raise ValueError('attempt exit Kubernetes non-start mismatch')
    elif (k.get('version')!='kubernetes-termination-1'
          or re.fullmatch(uuid,str(k.get('pod_uid',''))) is None or k['pod_uid']==k['job_uid']
          or re.fullmatch('containerd://[a-f0-9]{64}',str(k.get('container_id',''))) is None
          or type(k.get('exit_code')) is not int or k.get('removed') or k.get('suspended')
          or (attempt.get('publication_state')=='published' and k['exit_code']!=0)):
        raise ValueError('attempt exit Kubernetes termination mismatch')

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
    if scope=='kubernetes-job':
        _kube_exit(attempt,proof)
    elif scope=='container':
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
        kube=attempt.get('executor_kind')=='kubernetes-job-v1'
        valid_location=isinstance(location,str) and (re.fullmatch(r'kubernetes:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',location) is not None if kube else location.startswith('docker:'))
        if (attempt.get('executor_kind') not in ('isolated-v2','kubernetes-job-v1') or not attempt.get('start_revoked_at')
                or attempt.get('container_id')!='' or proof.get('start_revoked') is not True
                or not valid_location
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
        if (not isinstance(r,dict) or r.get('run_id')!=v['job_id'] or r.get('attempt_id')!=v['attempt']
                or r.get('cleanup_completed') is not True):
            raise ValueError('source verifier exit receipt mismatch')
        version=r.get('version')
        if version=='service-compact-verification-execution-1':
            if r.get('container_id')!=v['container_name']:raise ValueError('source verifier exit receipt mismatch')
        elif version in ('service-sidecar-verification-1','service-sidecar-verification-2'):
            # v1 deployed receipts predate the explicit nonce field. They remain
            # bound by their private control path, persisted row, run, attempt and digest.
            if (re.fullmatch('[a-f0-9]{64}',v['container_name']) is None
                    or (version.endswith('-2') and r.get('verification_id')!=v['container_name'])
                    or type(r.get('status')) is not int or r['status'] not in (200,422,500)
                    or not isinstance(r.get('ended_at'),str)):
                raise ValueError('source verifier exit receipt mismatch')
            try:
                if datetime.fromisoformat(r['ended_at'].replace('Z','+00:00')).tzinfo is None:raise ValueError()
            except ValueError:raise ValueError('source verifier exit receipt timestamp mismatch')
        else:raise ValueError('source verifier exit receipt mismatch')
        job=jobs[v['job_id']]
        if job['state']=='succeeded' and job['attempt']==v['attempt'] and job['payload'].get('storage_format')=='shared-observation-dag-6':
            if version.startswith('service-sidecar-') and r['status']!=200:raise ValueError('successful run has failed source verification')
            digest=job.get('artifact_sha256')
            if not isinstance(digest,str) or re.fullmatch('[a-f0-9]{64}',digest) is None or r.get('publication_sha256')!=digest:
                raise ValueError('source verifier publication binding mismatch')
    for row in rows:
        if row['state'] not in ('succeeded','failed','cancelled'):raise ValueError('active task in terminal backup')
        if row['state']=='succeeded' and row['payload'].get('storage_format')=='shared-observation-dag-6' and (row['id'],row['attempt']) not in seen:
            raise ValueError('successful shared task lacks verifier exit history')
    return {'valid':True,'attempts':len(attempts),'verifiers':len(verifiers),'source_trust':'must_reverify_in_restored_service'}

def capacity_source_root(control,physical_root,explicit_runtime_mapping=False):
    """Read only after the immutable bundle's complete control inventory was checked."""
    p=Path(control)/'capacity.json'
    if not p.exists():return physical_root
    value=json.loads(p.read_text());root=value.get('root')
    if not isinstance(root,str) or not Path(root).is_absolute() or '..' in Path(root).parts:
        raise ValueError('invalid captured capacity root')
    if root!=physical_root and not explicit_runtime_mapping:
        raise ValueError('explicit container runtime mapping required')
    return root


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
