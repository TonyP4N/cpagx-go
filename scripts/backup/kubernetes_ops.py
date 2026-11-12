#!/usr/bin/env python3
"""Explicit k3s host operator for existing format7 bundles; source data is never replaced."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import time

import bundle
from postgres_target import DeploymentDatabases, KubernetesPostgres, deployment_databases

VERSION='kubernetes-terminal-bundle-1'
FIELDS={'context','namespace','namespace_uid','app_deployment','app_uid','postgres_pod','postgres_uid',
        'postgres_container','source_database','restore_database','shared_root','control_root','backup_root','restore_root','runtime_shared_root'}


def plain_path(value):
    p=Path(value)
    if not p.is_absolute() or '..' in p.parts or any(x.is_symlink() for x in (p,*p.parents)):
        raise ValueError('explicit ordinary absolute paths required')
    return p


def load(path):
    p=plain_path(path);st=p.stat()
    if not p.is_file() or st.st_mode&0o077 or st.st_uid!=os.geteuid():raise ValueError('owner-private operator config required')
    c=json.loads(p.read_text())
    if set(c)!=FIELDS:raise ValueError('Kubernetes backup configuration fields invalid')
    for k in ('namespace_uid','app_uid'):
        if not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',c[k]):raise ValueError('immutable deployment identity required')
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,62}',c['app_deployment']):raise ValueError('explicit deployment required')
    endpoint=KubernetesPostgres(c['context'],c['namespace'],c['postgres_pod'],c['postgres_uid'],c['postgres_container'])
    plain_path(c['runtime_shared_root'])
    policy=DeploymentDatabases(c['postgres_pod'],c['source_database'],c['restore_database'],endpoint)
    paths=[plain_path(c[k]) for k in ('shared_root','control_root','backup_root','restore_root')]
    for i,p in enumerate(paths):
        if not p.is_dir():raise ValueError('configured persistent directories must exist')
        for q in paths[i+1:]:
            if p.is_relative_to(q) or q.is_relative_to(p):raise ValueError('separate source, bundle and recovery roots required')
    for p in paths[2:]:
        if p.stat().st_uid!=os.geteuid() or p.stat().st_mode&0o077:raise ValueError('owner-private backup and recovery roots required')
    return c,policy


def kubectl(c,*args):
    r=subprocess.run(['kubectl','--context',c['context'],'-n',c['namespace'],'--request-timeout=15s',*args],
                     check=True,capture_output=True,text=True,timeout=20)
    return json.loads(r.stdout) if r.stdout.strip() else None


def deployment(c):
    ns=kubectl(c,'get','namespace',c['namespace'],'-o','json')
    app=kubectl(c,'get','deployment',c['app_deployment'],'-o','json')
    if ns['metadata']['uid']!=c['namespace_uid'] or app['metadata']['uid']!=c['app_uid']:
        raise ValueError('deployment identity changed')
    return app


def replicas(c,app,count):
    patch=[{'op':'test','path':'/metadata/uid','value':c['app_uid']},
           {'op':'test','path':'/metadata/resourceVersion','value':app['metadata']['resourceVersion']},
           {'op':'replace','path':'/spec/replicas','value':count}]
    return kubectl(c,'patch','deployment',c['app_deployment'],'--type=json','-p',json.dumps(patch),'-o','json')


@contextmanager
def stopped(c,allow_stop):
    app=deployment(c);original=app['spec']['replicas'];changed=False
    try:
        if original:
            if not allow_stop:raise ValueError('running deployment: explicitly stop services for terminal backup')
            replicas(c,app,0);changed=True
        deadline=time.monotonic()+90
        while True:
            app=deployment(c)
            if app['spec']['replicas']!=0:raise ValueError('deployment resumed during maintenance')
            labels=app['spec']['selector']['matchLabels'];selector=','.join(k+'='+v for k,v in sorted(labels.items()))
            pods=kubectl(c,'get','pods','-l',selector,'-o','json')
            if not pods['items']:break
            if time.monotonic()>deadline:raise TimeoutError('deployment has not stopped')
            time.sleep(1)
        yield
    finally:
        # Resume only the same deployment still at zero; never overwrite a concurrent change.
        if changed:
            current=deployment(c)
            if current['spec']['replicas']==0:replicas(c,current,original)


def reserve(path,action,c):
    with path.open('x') as f:
        os.chmod(path,0o600)
        json.dump({'version':VERSION,'valid':False,'action':action,'namespace_uid':c['namespace_uid'],'app_uid':c['app_uid']},f)


def backup(c,policy,name,stop_services=False):
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',name):raise ValueError('simple new bundle name required')
    dest=Path(c['backup_root'])/name;receipt=dest.with_name(name+'-operation.json')
    if dest.exists():raise ValueError('backup destination already exists')
    reserve(receipt,'backup',c)
    try:
        with stopped(c,stop_services),deployment_databases(policy):
            result=bundle.backup(policy.container,policy.source,Path(c['shared_root']),dest,
                                 control_root=Path(c['control_root']),maintenance=True)
        report={'version':VERSION,'valid':True,'action':'backup','namespace_uid':c['namespace_uid'],
                'app_uid':c['app_uid'],'source_database':policy.source,'bundle_sha256':bundle.sha(dest/'bundle.json'),
                'format_version':result['format_version'],'files':len(result['files']),'control_files':len(result['control_files']),
                'source_preserved':True,'restore_requires_source_reverification':True}
        bundle.write_report(receipt,report);return report
    except Exception as e:
        bundle.write_report(receipt,{'version':VERSION,'valid':False,'action':'backup','error_type':type(e).__name__,
                                    'reason':str(e),'partial_evidence_retained':True})
        raise


def restore(c,policy,name,target):
    for v in (name,target):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',v):raise ValueError('simple bundle and target names required')
    src=plain_path(str(Path(c['backup_root'])/name));base=plain_path(str(Path(c['restore_root'])/target))
    receipt=src.with_name(name+'-operation.json')
    for p in (src,receipt,src/'bundle.json'):
        if p.is_symlink() or p.stat().st_uid!=os.geteuid() or p.stat().st_mode&0o022:raise ValueError('trusted private bundle required')
    r=json.loads(receipt.read_text())
    if (r.get('version')!=VERSION or r.get('valid') is not True or r.get('action')!='backup'
            or r.get('namespace_uid')!=c['namespace_uid'] or r.get('app_uid')!=c['app_uid']
            or r.get('source_database')!=policy.source or r.get('bundle_sha256')!=bundle.sha(src/'bundle.json')):
        raise ValueError('backup identity or manifest changed')
    deployment(c)
    base.mkdir(mode=0o700) # An existing target is never reused or overwritten.
    audit=base/'operation.json';reserve(audit,'restore',c)
    try:
        with deployment_databases(policy):
            result=bundle.restore(policy.container,src,base/'shared',control_destination=base/'control',database=policy.restore,runtime_root=c['runtime_shared_root'])
        report={'version':VERSION,'valid':True,'action':'restore','database':policy.restore,'source_preserved':True,
                'source_trust':result['source_trust'],'sessions_revoked':result['sessions_revoked'],
                'file_inventory_equal':result['file_inventory_equal'],
                'control_inventory_equal_before_rebase':result['control_inventory_equal_before_rebase']}
        bundle.write_report(audit,report);return report
    except Exception as e:
        bundle.write_report(audit,{'version':VERSION,'valid':False,'action':'restore','error_type':type(e).__name__,
                                  'reason':str(e),'partial_evidence_retained':True})
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True)
    sub=p.add_subparsers(dest='action',required=True)
    b=sub.add_parser('backup');b.add_argument('--name',required=True);b.add_argument('--stop-services',action='store_true')
    r=sub.add_parser('restore');r.add_argument('--name',required=True);r.add_argument('--target',required=True)
    a=p.parse_args()
    if os.geteuid()!=0:p.error('run as the authorized Linux host root operator')
    c,policy=load(a.config)
    result=backup(c,policy,a.name,a.stop_services) if a.action=='backup' else restore(c,policy,a.name,a.target)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
