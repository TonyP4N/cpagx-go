#!/usr/bin/env python3
"""Native Linux UID permissions regression; no analysis or source recomputation.

Default uses tiny synthetic marker files. --artifact reads an existing completed
artifact only for post-run inventory/permission impact validation. The image is
reused unchanged and Worker helpers are mounted read-only from this checkout.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid

_SCRIPT=Path(__file__).resolve()
REPO=_SCRIPT.parents[2] if len(_SCRIPT.parents)>2 else Path('/')


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(65536),b''):h.update(chunk)
    return h.hexdigest()


def inventory(root):
    result={}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise ValueError('symlink_not_allowed')
        if path.is_file():result[path.relative_to(root).as_posix()]={'sha256':digest(path),'size':path.stat().st_size}
    return result


def synthetic(root):
    (root/'shared').mkdir(parents=True);(root/'sources').mkdir()
    for name,value in {'run_manifest.json':b'{"scope":"permissions-only-marker"}\n','shared/shared.sqlite3':b'unchanged-native-permission-marker',
                       'shared/manifest.json':b'{}\n','sources/network.pcap':b'not-a-capture-marker','sources/process.csv':b'time,value\n0,1\n','sources/profile.json':b'{}\n'}.items():
        path=root/name;path.write_bytes(value);path.chmod(0o444)
    entries=inventory(root)
    (root/'manifest.json').write_text(json.dumps({'artifacts':[{'path':name,**row} for name,row in entries.items()]},sort_keys=True)+'\n')
    anchor=digest(root/'manifest.json')+'.json';(root/anchor).write_bytes((root/'manifest.json').read_bytes());(root/anchor).chmod(0o400)
    root.chmod(0o700)
    return root


def inside():
    """Root is confined to native tmpfs; children execute with real distinct UIDs."""
    import shutil
    metadata=json.loads(sys.stdin.buffer.readline());root=Path('/probe/attempt');root.mkdir(mode=0o700)
    with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
        for member in archive:
            name=member.name
            if not member.isfile() or name not in metadata['inventory'] or Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('unsafe_probe_archive')
            path=root/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open('xb') as stream:shutil.copyfileobj(archive.extractfile(member),stream)
            path.chmod(member.mode & 0o777)
    expected=metadata['inventory'];anchor=metadata['anchor'];anchor_raw=(root/anchor).read_bytes()
    if hashlib.sha256(anchor_raw).hexdigest()!=expected[anchor]['sha256']:raise ValueError('anchor_transfer_changed')
    (root/anchor).unlink()
    # Change children first: root without DAC override cannot traverse a directory
    # after it has been transferred to the private owner.
    for path in sorted(root.rglob('*'),key=lambda p:len(p.parts),reverse=True):os.chown(path,1001,1001)
    os.chown(root,1001,1001)
    def child(uid,code):
        result=subprocess.run([sys.executable,'-c',code],preexec_fn=lambda:os.setuid(uid),text=True,capture_output=True)
        return {'returncode':result.returncode,'stdout':result.stdout.strip(),'stderr':result.stderr.strip()}
    def owner(code):
        value=child(1001,code)
        if value['returncode']:raise RuntimeError('owner_probe_failed:'+value['stderr'])
        return value
    reader="import json,os,hashlib;from pathlib import Path\np=Path('/probe/attempt');expected="+repr(expected)+";out={'uid':os.getuid(),'hashes':{},'errors':{}}\nfor name in expected:\n try:out['hashes'][name]=hashlib.sha256((p/name).read_bytes()).hexdigest()\n except OSError as error:out['errors'][name]=type(error).__name__\nfor key,operation in [('root_write',lambda:(p/'untrusted-probe').write_bytes(b'x')),('payload_write',lambda:(p/'shared/shared.sqlite3').write_bytes(b'x'))]:\n try:operation();out[key]='allowed'\n except OSError as error:out[key]=type(error).__name__\nprint(json.dumps(out))"
    def probe():
        value=child(65532,reader)
        if value['returncode']:raise RuntimeError(value['stderr'])
        return json.loads(value['stdout'])
    before=probe()
    if not before['errors'] or any(v!='PermissionError' for v in before['errors'].values()):raise AssertionError('private_root_must_deny_other_uid')
    owner("from pathlib import Path;from cpag_worker.isolated import seal_handoff;seal_handoff(Path('/probe/attempt'),compact=True)")
    # Actual service owner may create the anchor while verifier UID has no write.
    owner("import os;from pathlib import Path;p=Path('/probe/attempt');f=p/"+repr(anchor)+";fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o444);os.write(fd,"+repr(anchor_raw)+");os.fsync(fd);os.close(fd)")
    fresh=probe()
    def require_readonly_hashes(value):
        if value['errors'] or value['hashes']!={n:v['sha256'] for n,v in expected.items()}:raise AssertionError('inventory_hash_readback_failed')
        if value['root_write']!='PermissionError' or value['payload_write']!='PermissionError':raise AssertionError('verifier_uid_must_not_write')
    require_readonly_hashes(fresh)
    # Recover a retained root from the former 0700/0400 layout. The Worker helper
    # fixes root traversal; the service must migrate its own checked anchor.
    owner("import os;from pathlib import Path;p=Path('/probe/attempt');os.chmod(p,0o700);os.chmod(p/"+repr(anchor)+",0o400);from cpag_worker.isolated import prepare_compact_publication_root;prepare_compact_publication_root(p)")
    old_anchor=probe()
    if old_anchor['errors']!={anchor:'PermissionError'}:raise AssertionError('old_private_anchor_must_be_distinguished')
    owner("import os,hashlib;from pathlib import Path;from cpag_worker.isolated import sync_dir;p=Path('/probe/attempt');a=p/"+repr(anchor)+";assert hashlib.sha256(a.read_bytes()).hexdigest()=="+repr(expected[anchor]['sha256'])+";os.chmod(a,0o444);os.chmod(p,0o555);sync_dir(p)")
    final=probe();require_readonly_hashes(final)
    owner_write=child(1001,"from pathlib import Path;Path('/probe/attempt/owner-after-complete').write_bytes(b'x')")
    if owner_write['returncode']==0:raise AssertionError('completed_root_must_deny_owner_new_file')
    print(json.dumps({'status':'passed','valid':True,'filesystem':'native Linux container tmpfs; no host bind for artifact data','owner_uid':1001,'verifier_uid':65532,
        'private0700_other_uid_read':'denied','prepared_root_mode':'0755','verifier_read_and_full_hash_inventory':'passed','verifier_root_and_payload_write':'denied',
        'owner_anchor_create':'passed','legacy0400_anchor_other_uid_read':'denied','migrated0444_anchor_other_uid_read':'passed','completed_root_mode':'0555','completed_owner_new_file':'denied',
        'files':len(expected),'bytes':sum(v['size'] for v in expected.values()),'inventory':expected,'business_bytes_unchanged':True},sort_keys=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--image');parser.add_argument('--output',type=Path);parser.add_argument('--artifact',type=Path)
    args=parser.parse_args()
    if args.inside:return inside()
    if args.output is None or not args.image:parser.error('--image and --output required')
    if re.fullmatch(r'(?:sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})',args.image) is None:parser.error('immutable image required')
    args.output=args.output.resolve();args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    source=args.artifact.resolve() if args.artifact else synthetic(args.output/'synthetic-artifact')
    before=inventory(source);wrapper=digest(source/'manifest.json');anchor=wrapper+'.json'
    if anchor not in before or before[anchor]['sha256']!=wrapper:raise ValueError('exact_existing_anchor_required')
    declared=json.loads((source/'manifest.json').read_text())
    names={row['path'] for row in declared['artifacts']}|{'manifest.json',anchor}
    if set(before)!=names:raise ValueError('source_inventory_mismatch')
    for row in declared['artifacts']:
        if before[row['path']]!={'sha256':row['sha256'],'size':row['size']}:raise ValueError('source_publication_digest_mismatch')
    identity={}
    if args.artifact:
        manifest=json.loads((source/'run_manifest.json').read_text())
        identity={k:manifest.get(k) for k in ('run_id','attempt_id','config_fingerprint','input_fingerprint','source_fingerprint','storage_format','result_hashes')}
    # Stage exact code bytes in the controlled temporary directory. This avoids
    # Docker Desktop/cloud-file bind hydration failures; it changes no image.
    runtime=args.output/'worker-code';runtime.mkdir(mode=0o755)
    shutil.copytree(REPO/'services/worker/cpag_worker',runtime/'cpag_worker',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for path in runtime.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    probe_script=args.output/'probe-script.py';shutil.copyfile(Path(__file__).resolve(),probe_script);probe_script.chmod(0o644)
    if digest(runtime/'cpag_worker/isolated.py')!=digest(REPO/'services/worker/cpag_worker/isolated.py'):raise ValueError('worker_snapshot_changed')
    name='cpag-r19-permissions-'+uuid.uuid4().hex
    command=['docker','run','--name',name,'--rm','--interactive','--network','none','--read-only','--user','0:0','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','SETUID',
        '--cpus','1','--memory','512m','--pids-limit','32','--tmpfs','/probe:rw,nosuid,nodev,size=256m,mode=1777',
        '--mount','type=bind,src='+str(runtime)+',dst=/worker,readonly','--mount','type=bind,src='+str(probe_script)+',dst=/probe-script.py,readonly',
        '-e','PYTHONPATH=/worker','--entrypoint','python',args.image,'/probe-script.py','--inside']
    report={'scope':'post-run permissions and retained-byte inventory impact only; no analysis, no performance acceptance','artifact_source':str(source) if args.artifact else None,'original_artifact_identity':identity,'image':args.image,'worker_helper_sha256':digest(REPO/'services/worker/cpag_worker/isolated.py')}
    with tempfile.TemporaryFile(dir=args.output) as request:
        request.write((json.dumps({'inventory':before,'anchor':anchor})+'\n').encode())
        with tarfile.open(fileobj=request,mode='w|') as archive:
            for entry in before:archive.add(source/entry,arcname=entry,recursive=False)
        request.seek(0)
        try:
            result=subprocess.run(command,stdin=request,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        except subprocess.TimeoutExpired:
            subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            report.update(status='failed',valid=False,reason='native_uid_probe_timeout');(args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');raise
    (args.output/'native-stdout.json').write_bytes(result.stdout);(args.output/'native-stderr.log').write_bytes(result.stderr)
    if result.returncode:
        report.update(status='failed',valid=False,returncode=result.returncode);(args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');raise RuntimeError('native_uid_probe_failed; see retained stderr')
    report.update(json.loads(result.stdout));report['source_inventory_unchanged']=inventory(source)==before
    if not report['source_inventory_unchanged']:raise AssertionError('original_artifact_changed')
    (args.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':report['status'],'files':report['files'],'bytes':report['bytes'],'source_inventory_unchanged':True,'report':str(args.output/'report.json')},sort_keys=True))


if __name__=='__main__':main()
