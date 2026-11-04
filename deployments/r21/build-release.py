#!/usr/bin/env python3
"""Build an opt-in Linux unified-Go release; no credentials or installed-state data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPO=Path(__file__).resolve().parents[2]
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def tracked_copy(source,target,extra=()):
 paths=subprocess.check_output(['git','ls-files','--',str(source.relative_to(REPO))],cwd=REPO,text=True).splitlines()
 paths.extend(extra)
 for name in sorted(set(paths)):
  path=REPO/name
  if not path.is_file() or path.is_symlink():raise ValueError('runtime source must be an ordinary file: '+name)
  destination=target/path.relative_to(source);destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,destination)
def go_inputs(cwd,target,env):
 raw=subprocess.check_output(['go','list','-deps','-json',target],cwd=cwd,env=env,text=True);decoder=json.JSONDecoder();files={};modules={}
 while raw.strip():
  row,end=decoder.raw_decode(raw.lstrip());raw=raw.lstrip()[end:];directory=Path(row['Dir'])
  if directory.is_relative_to(REPO):
   for name in row.get('GoFiles',[])+row.get('CgoFiles',[])+row.get('EmbedFiles',[]):
    path=directory/name;files[str(path.relative_to(REPO))]=digest(path)
  elif row.get('Module'):modules[row['Module']['Path']]=row['Module'].get('Version','local')
 for relative in ['go.mod','go.sum','internal/jobs/integration/go.mod','internal/jobs/integration/go.sum']:files[relative]=digest(REPO/relative)
 return {'files':dict(sorted(files.items())),'sha256':hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'module_versions':dict(sorted(modules.items()))}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--arch',choices=['arm64','amd64'],default='arm64');p.add_argument('--static-root',type=Path,default=REPO/'webui/out');p.add_argument('--include-smoke-fixture',action='store_true');a=p.parse_args()
 out=a.output.resolve();static=a.static_root.resolve()
 if out.is_relative_to(REPO):p.error('release output must be outside the checkout')
 if not (static/'workbench/index.html').is_file():p.error('a completed static workbench export is required')
 out.mkdir(parents=True,exist_ok=False,mode=0o755)
 ignore=shutil.ignore_patterns('__pycache__','*.pyc','.DS_Store')
 for source,target,extra in [(REPO/'services/analysis/src',out/'services/analysis/src',()),(REPO/'services/worker/cpag_worker',out/'services/worker/cpag_worker',()),(REPO/'schemas',out/'schemas',()),(REPO/'internal/jobs/migrations',out/'migrations',('internal/jobs/migrations/017_worker_observability.sql',)),(REPO/'scripts/backup',out/'scripts/backup',('scripts/backup/deployment_ops.py','scripts/backup/postgres_target.py','scripts/backup/retention.py'))]:
  tracked_copy(source,target,extra)
 for name in ['round19_core_oracle.py','round21_retention_drill.py']:
  destination=out/'scripts/validation'/name;destination.parent.mkdir(parents=True,exist_ok=True)
  shutil.copy2(REPO/'scripts/validation'/name,destination)
 shutil.copytree(REPO/'deployments/r21',out/'deployments/r21',ignore=ignore);shutil.copytree(static,out/'webui/out',ignore=ignore)
 if a.include_smoke_fixture:
  sys.path.insert(0,str(REPO/'scripts/validation'))
  from round19_core_small import inputs
  for mode,case in [('offline','success'),('replay','normal')]:inputs(out/'samples'/mode,case,mode)
  (out/'samples/expected.json').write_text(json.dumps({'synthetic_only':True,'operations':1,'changes':1,'candidates':1})+'\n')
 (out/'bin').mkdir();env=dict(os.environ,GOOS='linux',GOARCH=a.arch,CGO_ENABLED='0')
 builds={}
 for name,cwd,target in [('cpagx-v3',REPO/'internal/jobs/integration','./cmd/cpagx-v3'),('cpagctl',REPO,'./cmd/cpagctl')]:
  before=go_inputs(cwd,target,env)
  subprocess.run(['go','build','-trimpath','-o',str(out/'bin'/name),target],cwd=cwd,env=env,check=True)
  if before!=go_inputs(cwd,target,env):raise RuntimeError('Go build inputs changed during build; discard this release')
  builds[name]=before
 manifest={'format':'cpag-r21-linux-release-1','target':'linux/'+a.arch,'source_reference_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'go_build_inputs':builds,'go':subprocess.check_output(['go','version'],text=True).strip(),'files':{str(x.relative_to(out)):{'sha256':digest(x),'size_bytes':x.stat().st_size} for x in sorted(out.rglob('*')) if x.is_file()}}
 (out/'release.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'release':str(out),'target':manifest['target'],'files':len(manifest['files'])}))
if __name__=='__main__':main()
