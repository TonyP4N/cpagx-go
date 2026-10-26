#!/usr/bin/env python3
"""Online preparation only; output is a self-contained Linux/arm64 image bundle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--version',default='rc1');p.add_argument('--compute-version',default='round7');p.add_argument('--output',type=Path,required=True);p.add_argument('--include-baseline',action='store_true');p.add_argument('--require-clean',action='store_true');a=p.parse_args()
SOURCE=a.source.resolve();TEMPLATES=Path(__file__).resolve().parents[2]/'deployments/engineering';OUT=a.output.resolve();OUT.mkdir(parents=True,exist_ok=True)
def call(*args,**kw):return subprocess.check_output(args,**kw).decode().strip()
def image_meta(tag):return json.loads(call('docker','image','inspect',tag))[0]
release_paths=['services','schemas','internal','scripts','deployments','profiles','tests/fixtures','go.mod','go.sum','docs/refactor/validation-round4/protocol-synthetic.pcap']
def check_clean():
    if call('git','-C',str(SOURCE),'diff','--name-only','HEAD','--',*release_paths) or call('git','-C',str(SOURCE),'ls-files','--others','--exclude-standard','--',*release_paths):raise SystemExit('release source has uncommitted/untracked build inputs')
if a.require_clean:check_clean()
freeze_commit=call('git','-C',str(SOURCE),'rev-parse','HEAD')
if 'go1.26.5' not in call('go','version'):raise SystemExit('release build requires Go 1.26.5')
def build(source,version,compute_version,commit_override=None):
    with tempfile.TemporaryDirectory(prefix='cpag-release-build-') as temporary:
        stage=Path(temporary)
        for src,dest in [(source/'services/analysis/src',stage/'services/analysis/src'),(source/'services/worker/cpag_worker',stage/'services/worker/cpag_worker'),(source/'schemas',stage/'schemas'),(source/'internal/jobs/migrations',stage/'migrations'),(source/'scripts/backup',stage/'scripts/backup'),(TEMPLATES,stage/'engineering')]:
            shutil.copytree(src,dest,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        (stage/'bin').mkdir();(stage/'samples').mkdir()
        for source_file in [source/'tests/fixtures/synthetic/network.normalized.jsonl',source/'tests/fixtures/synthetic/process.csv',source/'profiles/synthetic-demo.json',source/'docs/refactor/validation-round4/protocol-synthetic.pcap']:
            shutil.copyfile(source_file,stage/'samples'/source_file.name)
        (stage/'samples/packet-profile.json').write_text(json.dumps({'synthetic':True,'adapter':'synthetic-packet-1'}))
        env={**os.environ,'GOOS':'linux','GOARCH':'arm64','CGO_ENABLED':'0'}
        for name,command in [('job-api','m4-job-api'),('recovery','m4-recovery')]:
            subprocess.run(['go','build','-trimpath','-o',str(stage/'bin'/name),'./cmd/'+command],cwd=source/'internal/jobs/integration',env=env,check=True)
        try:commit=commit_override or call('git','-C',str(source),'rev-parse','HEAD')
        except subprocess.CalledProcessError:commit='archive-1386a4f'
        hashes={str(path.relative_to(stage)):hashlib.sha256(path.read_bytes()).hexdigest() for path in stage.rglob('*') if path.is_file()}
        release={'version':'cpag-engineering-synthetic-'+version,'source_commit':commit,'wrapper_source_commit':call('git','-C',str(TEMPLATES.parent.parent),'rev-parse','HEAD'),'wrapper_source':'engineering templates from preparation working tree; separate from archived core','target':'linux/arm64','go':'1.26.5','python':'3.12.12','docker':'29.1.3','postgres':'17.6-alpine','source_files_sha256':hashes}
        (stage/'release.json').write_text(json.dumps(release,indent=2))
        app='cpag-engineering:'+version;compute='cpag-isolated:'+compute_version
        subprocess.run(['docker','build','--platform','linux/arm64','-t',app,'-f',str(TEMPLATES/'Dockerfile.app'),str(stage)],check=True)
        subprocess.run(['docker','build','--platform','linux/arm64','-t',compute,'-f',str(TEMPLATES/'Dockerfile.compute'),str(stage)],check=True)
        return app,compute,release
images=[];app,compute,release=build(SOURCE,a.version,a.compute_version);images += [app,compute]
if a.include_baseline:
    with tempfile.TemporaryDirectory(prefix='cpag-baseline-') as temporary:
        archive=subprocess.check_output(['git','-C',str(SOURCE),'archive','1386a4f'])
        subprocess.run(['tar','-xf','-','-C',temporary],input=archive,check=True)
        old_app,old_compute,old_release=build(Path(temporary),'baseline-1386a4f','baseline-1386a4f',call('git','-C',str(SOURCE),'rev-parse','1386a4f'));images += [old_app,old_compute]
        (OUT/'baseline-release.json').write_text(json.dumps(old_release,indent=2))
images += ['mirror.gcr.io/library/postgres:17.6-alpine']
subprocess.run(['docker','save','-o',str(OUT/'images.tar'),*images],check=True)
# The separate lab engine is provided only to reproduce the explicitly containerized target.
subprocess.run(['docker','save','-o',str(OUT/'lab-engine.tar'),'mirror.gcr.io/library/docker:29.1.3-dind'],check=True)
with tarfile.open(OUT/'images.tar') as archive:
    archive_manifest=json.load(archive.extractfile('manifest.json'))
configs={tag:'sha256:'+entry['Config'].split('/')[-1].removesuffix('.json') for entry in archive_manifest for tag in entry.get('RepoTags',[])}
release['images']=[{'tag':tag,'id':configs[tag],'source_daemon_image_id':image_meta(tag)['Id'],'architecture':image_meta(tag)['Architecture'],'os':image_meta(tag)['Os']} for tag in images]
(OUT/'release.json').write_text(json.dumps(release,indent=2));shutil.copyfile(TEMPLATES/'cpag.sh',OUT/'cpag.sh');cli=(OUT/'cpag.sh').read_text().replace(':-cpag-engineering:rc1}',':-'+app+'}').replace(':-cpag-isolated:round7}',':-'+compute+'}');(OUT/'cpag.sh').write_text(cli);(OUT/'cpag.sh').chmod(0o755)
(OUT/'INSTALL.txt').write_text('Target: Linux/arm64 with Docker Engine 29.1.3 already installed. Containerized DinD acceptance only; not bare-metal/VM OS installation.\nCreate /cpag-root/data first; ./cpag.sh install; ./cpag.sh start; ./cpag.sh demo; ./cpag.sh check.\nStop preserves /cpag-root/data and database volume. Maintenance retains PostgreSQL. All tasks synthetic.\n')
for name in ('config.env.example','OPERATIONS.zh-CN.md'):
    shutil.copyfile(TEMPLATES/name,OUT/name)
(OUT/'dependencies.lock.json').write_text(json.dumps({'target':'linux/arm64','python':{'version':'3.12.12-alpine3.22','image':'mirror.gcr.io/library/python@sha256:848ba4413eb897e225159b8fc1b02094576cbae4aa73fc13142608ae2c8c0e32'},'docker_cli':{'version':'29.1.3','image':'mirror.gcr.io/library/docker@sha256:4fa0ee1f3a7e4354c4ea34558b6d4ee32859baf4973d4c8ccc8e7fe3dd730c04'},'lab_engine':{'version':'29.1.3-dind','image':'mirror.gcr.io/library/docker@sha256:173f284a4299164772a90f52b373e73e087583c0963f1334c9995f190ef6f3f5'},'postgres':{'version':'17.6-alpine','image':'mirror.gcr.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94'},'go_build':'1.26.5','python_packages':'stdlib only; no pip install','go_modules':{'go.mod_sha256':hashlib.sha256((SOURCE/'internal/jobs/integration/go.mod').read_bytes()).hexdigest(),'go.sum_sha256':hashlib.sha256((SOURCE/'internal/jobs/integration/go.sum').read_bytes()).hexdigest()}},indent=2))
drill=TEMPLATES.parent.parent/'scripts/release/validate-upgrade-rollback.sh'
if drill.exists():shutil.copyfile(drill,OUT/drill.name)
files=sorted(path for path in OUT.iterdir() if path.is_file() and path.name!='SHA256SUMS')
(OUT/'SHA256SUMS').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n' for path in files))
if a.require_clean:
    check_clean()
    if call('git','-C',str(SOURCE),'rev-parse','HEAD')!=freeze_commit:raise SystemExit('source HEAD changed during release build')
print(json.dumps({'package':str(OUT),'images':images,'bytes':sum(path.stat().st_size for path in OUT.iterdir())}))
