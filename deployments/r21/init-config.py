#!/usr/bin/env python3
"""Create fresh private deployment configuration; prints paths, never credentials."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sys
from urllib.parse import quote,urlsplit

def private(path,value):
 with open(path,'x',opener=lambda p,f:os.open(p,f,0o600)) as stream:stream.write(value if isinstance(value,str) else json.dumps(value,indent=2)+'\n')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config-root',type=Path,default=Path('/etc/cpag'));p.add_argument('--state-root',type=Path,default=Path('/var/lib/cpag'));p.add_argument('--release-root',type=Path,default=Path('/opt/cpag/current'));p.add_argument('--log-root',type=Path,default=Path('/var/log/cpag'));p.add_argument('--run-root',type=Path,default=Path('/run/cpag'));p.add_argument('--backup-root',type=Path,default=Path('/var/backups/cpag'));p.add_argument('--external-origin',required=True);p.add_argument('--executor-image',required=True);p.add_argument('--deployment-id',required=True);p.add_argument('--pg-container',default='cpag-r21-postgres');p.add_argument('--pg-port',type=int,default=15432);a=p.parse_args()
 origin=urlsplit(a.external_origin)
 if origin.scheme!='https' or not origin.hostname or origin.path or origin.query or origin.fragment or origin.username:p.error('external-origin must be an exact https origin without path or userinfo')
 if not re.fullmatch(r'[a-z0-9][a-z0-9-]{2,50}',a.deployment_id):p.error('invalid deployment-id')
 if not re.fullmatch(r'(sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})',a.executor_image):p.error('immutable executor image ID/digest required')
 paths=[a.config_root,a.state_root,a.release_root,a.log_root,a.run_root,a.backup_root]
 if any(not x.is_absolute() for x in paths):p.error('absolute paths required')
 if a.config_root.exists() and any(a.config_root.iterdir()):p.error('configuration root must be new or empty')
 if os.geteuid()!=0:p.error('deployment bootstrap must run as root to reserve the trusted backup root')
 for root in [a.config_root,a.state_root,a.log_root,a.run_root,a.backup_root,a.state_root/'shared',a.state_root/'control']:root.mkdir(parents=True,exist_ok=True,mode=0o700)
 if a.backup_root.is_symlink() or a.backup_root.stat().st_uid!=0 or a.backup_root.stat().st_mode&0o077:p.error('backup-root must remain root-owned 0700; do not recursively chown it to the service account')
 password=secrets.token_urlsafe(32);admin_password=secrets.token_urlsafe(32);worker=secrets.token_urlsafe(32);coordinator=secrets.token_urlsafe(32)
 app={'database_url':f'postgres://postgres:{quote(password,safe="")}@127.0.0.1:{a.pg_port}/cpag_app?sslmode=disable','shared_root':str(a.state_root/'shared'),'control_root':str(a.state_root/'control'),'public_addr':'127.0.0.1:8095','internal_addr':'127.0.0.1:8094','external_origin':a.external_origin,'worker_token':worker,'coordinator_token':coordinator,'bootstrap_admin_username':'cpag-admin','bootstrap_admin_password':admin_password,'static_root':str(a.release_root/'webui/out'),'python_bin':sys.executable,'python_path':str(a.release_root/'services/analysis/src'),'resource_profile':'storage-budget-2','capacity_policy':'engineering-core-capacity-3','compact_verifier_image':a.executor_image}
 op={'deployment_id':a.deployment_id,'release_root':str(a.release_root),'app_config':str(a.config_root/'app.json'),'worker_config':str(a.config_root/'worker.json'),'shared_root':app['shared_root'],'control_root':app['control_root'],'pg_container':a.pg_container,'source_database':'cpag_app','restore_database':'cpag_restore','backup_root':str(a.backup_root),'log_root':str(a.log_root),'run_root':str(a.run_root)}
 private(a.config_root/'app.json',app);private(a.config_root/'worker.json',{'api_url':'http://127.0.0.1:8094','shared_root':app['shared_root'],'control_root':app['control_root'],'worker_token':worker,'coordinator_token':coordinator,'worker_id':'r21-worker','image':a.executor_image,'poll_seconds':.2,'recovery_seconds':2,'resource_profile':'storage-budget-2'})
 private(a.config_root/'operator.json',op);private(a.config_root/'postgres.env','POSTGRES_DB=cpag_app\nPOSTGRES_USER=postgres\nPOSTGRES_PASSWORD='+password+'\n');private(a.config_root/'credentials.json',{'username':'cpag-admin','password':admin_password})
 print(json.dumps({'status':'created','config_root':str(a.config_root),'operator':str(a.config_root/'operator.json')}))
if __name__=='__main__':main()
