#!/usr/bin/env python3
"""Actual Linux closed-file cleanup drill; touches only uniquely owned fixtures.

Use --phase live before stopping the deployment, then --phase stopped after
services exit. No source/control evidence, database or unknown file is removed.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/backup'))
import deployment_ops as ops
import retention


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--phase',choices=('live','stopped'),required=True);args=parser.parse_args()
    config,_=ops.load_config(args.config);args.output.mkdir(parents=True,exist_ok=True)
    state_path=args.output/'retention-fixture.json';report_path=args.output/'retention-report.json'
    report=json.loads(report_path.read_text()) if report_path.exists() else {'version':'actual-linux-closed-file-retention-1','checks':{},'scope':'unique synthetic log/runtime fixtures only; no business inventory reclamation'}
    report.setdefault('validation_scripts', {})[args.phase]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    manifest=Path(ops.__file__).resolve().parents[2]/'ops-manifest.json'
    if manifest.is_file():
        package=json.loads(manifest.read_text());report['production_ops_package_sha256']=package['package_sha256']
        if args.phase=='stopped' and report['checks'].get('live_cleanup_refused_without_file_deletion'):
            report['validation_scripts'].setdefault('live',package['files']['scripts/validation/round21_retention_drill.py'])
    if os.geteuid()!=0:raise ValueError('run on the isolated deployment as root')
    if args.phase=='live':
        if state_path.exists():raise ValueError('new retention drill output required')
        prefix='r21-retention-'+secrets.token_hex(6)
        files={
            'rotated':Path(config['log_root'])/(prefix+'.log.1'),
            'temporary':Path(config['run_root'])/(prefix+'.tmp.closed'),
            'current':Path(config['log_root'])/(prefix+'.log'),
            'unknown':Path(config['run_root'])/(prefix+'.txt'),
            'protected':Path(config['control_root'])/(prefix+'-retained-proof.json'),
        }
        for name,path in files.items():
            with path.open('xb') as stream:stream.write(('synthetic retention fixture '+name+'\n').encode())
            os.utime(path,(time.time()-40*86400,time.time()-40*86400))
        state={'prefix':prefix,'paths':{name:str(path) for name,path in files.items()},'sha256':{name:ops.bundle.sha(path) for name,path in files.items()}}
        write(state_path,state)
        planned=retention.plan(config)
        # Never allow an experiment to delete pre-existing deployment log data.
        assert all(row['relative'].startswith(prefix) for row in planned['candidates'])
        write(args.output/'live-cleanup-preview.json',planned)
        audit=Path(config['backup_root'])/(prefix+'-live-cleanup-audit.json')
        try:retention.apply(config,planned,config['deployment_id'],audit)
        except ValueError as error:
            assert 'stopped Go service and Worker' in str(error)
        else:raise AssertionError('running deployment allowed cleanup apply')
        assert all(Path(value).is_file() for value in state['paths'].values())
        report['checks']['live_cleanup_refused_without_file_deletion']=True
    else:
        state=json.loads(state_path.read_text());prefix=state['prefix'];files={name:Path(value) for name,value in state['paths'].items()}
        opened=Path(config['log_root'])/(prefix+'-opened.log.1');opened.write_bytes(b'actual open descriptor fixture\n')
        os.utime(opened,(time.time()-40*86400,time.time()-40*86400))
        linked=Path(config['log_root'])/(prefix+'-linked.log.1');os.link(files['current'],linked)
        cross=Path(config['log_root'])/(prefix+'-cross-volume.log.1');cross_created=False
        try:
            os.link(files['protected'],cross);cross_created=True
            report['cross_volume_guard']='same device; protected evidence link retained until explicit drill teardown'
        except OSError as error:
            if error.errno!=errno.EXDEV:raise
            report['checks']['cross_volume_control_link_rejected_by_os']=True
        try:
            with opened.open('rb'):
                planned=retention.plan(config)
                assert all(row['relative']!=opened.name for row in planned['candidates'])
                assert any(row['relative']==opened.name and row['reason']=='open_file_retained' for row in planned['retained'])
            report['checks']['actual_open_descriptor_prevents_cleanup']=True
            planned=retention.plan(config)
            assert all(row['relative'].startswith(prefix) for row in planned['candidates'])
            assert not any(row['relative']==linked.name for row in planned['candidates'])
            assert {row['relative'] for row in planned['candidates']}=={files['rotated'].name,files['temporary'].name,opened.name}
            write(args.output/'stopped-cleanup-preview.json',planned)
            audit=Path(config['backup_root'])/(prefix+'-stopped-cleanup-audit.json')
            result=retention.apply(config,planned,config['deployment_id'],audit)
            assert result['valid'] and len(result['deleted'])==3
            assert all(not path.exists() for path in (files['rotated'],files['temporary'],opened))
            for name in ('current','unknown','protected'):
                assert files[name].is_file() and ops.bundle.sha(files[name])==state['sha256'][name]
            assert linked.is_file() and ops.bundle.sha(linked)==state['sha256']['current']
            report['checks'].update(closed_preview_only_deleted_with_root_audit=True,current_log_unknown_runtime_and_control_evidence_preserved=True,hard_link_to_current_log_preserved=True)
            report['audit']=str(audit);report['deleted_count']=3
        finally:
            # Remove only the exact hard link introduced by this drill; preserve
            # its original control evidence and all recorded failed/success audits.
            if linked.exists() and linked.stat().st_ino==files['current'].stat().st_ino:linked.unlink()
            if cross_created and cross.exists() and cross.stat().st_ino==files['protected'].stat().st_ino:cross.unlink()
        report['status']='passed'
    write(report_path,report);print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
