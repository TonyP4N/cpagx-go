#!/usr/bin/env python3
"""Clean containerized Linux target; a new daemon/cache, physically no public route."""
import argparse
import json
from pathlib import Path
import subprocess
import time
p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);p.add_argument('--keep',action='store_true');p.add_argument('--run-upgrade-drill',action='store_true');a=p.parse_args()
a.evidence.mkdir(parents=True,exist_ok=True);name='cpag-offline-rc1';network=name+'-airgap';engine=name+'-engine';state=name+'-state';snapshots=name+'-snapshots'
def host(*args,check=True):return subprocess.run(['docker',*args],check=check,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def inside(*args,check=True):return host('exec',name,*args,check=check)
def record(key,value):
    (a.evidence/(key+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def cpag(command):
    result=inside('sh','/package/cpag.sh',command,check=False)
    (a.evidence/(command+'.log')).write_text(result.stdout+'\n'+result.stderr)
    if result.returncode:raise RuntimeError('offline '+command+' failed; see '+command+'.log')
    print('PASS offline',command,flush=True)
# Lab-engine bootstrap occurs before creation of the clean target. All application
# images are installed only after the daemon-empty and airgap checks.
host('load','-i',str(a.package.resolve()/'lab-engine.tar'))
for volume in (engine,state,snapshots):
    if host('volume','inspect',volume,check=False).returncode==0:raise SystemExit('fresh volume required: '+volume)
    host('volume','create',volume)
host('network','create','--internal',network)
host('run','-d','--privileged','--name',name,'--network',network,'-e','DOCKER_TLS_CERTDIR=','-v',engine+':/var/lib/docker','-v',state+':/cpag-root','-v',snapshots+':/snapshots','--mount','type=bind,src='+str(a.package.resolve())+',dst=/package,readonly','mirror.gcr.io/library/docker:29.1.3-dind','--storage-driver=vfs')
try:
    for _ in range(120):
        if inside('docker','info',check=False).returncode==0:break
        time.sleep(.5)
    else:raise RuntimeError('clean daemon did not start')
    initial=inside('docker','images','--format','{{.ID}}').stdout.strip();assert not initial,initial
    record('target-platform',{'os_release':inside('cat','/etc/os-release').stdout,'uname':inside('uname','-a').stdout,'docker_version':json.loads(inside('docker','version','--format','{{json .}}').stdout)})
    record('clean-target',{'images_before_install':[],'docker_info':json.loads(inside('docker','info','--format','{{json .}}').stdout),'target':'Linux/arm64 containerized privileged DinD; not a bare-metal or VM OS installation'})
    routes=inside('ip','route').stdout;assert not any(line.startswith('default ') for line in routes.splitlines()),routes
    blocked=inside('wget','-T','3','-q','-O','-','https://example.com',check=False);assert blocked.returncode!=0
    record('airgap',{'outer_network':json.loads(host('network','inspect',network).stdout)[0],'routes':routes,'public_https_exit':blocked.returncode,'public_https_error':blocked.stderr,'images_before_install':initial})
    cpag('install')
    release=json.loads((a.package/'release.json').read_text())
    for image in release['images']:
        installed=inside('docker','image','inspect',image['tag'],'--format','{{.Id}}').stdout.strip();assert installed in (image['id'],image['source_daemon_image_id']),(image,installed)
    tool=inside('docker','run','--rm','--pull=never','--network','none','cpag-engineering:rc1','python','-m','cpag_worker.capacity_rebuild','--help')
    (a.evidence/'packaged-capacity-help.log').write_text(tool.stdout)
    cpag('start');cpag('demo');cpag('check')
    before=json.loads(inside('cat','/cpag-root/data/demo-results.json').stdout)
    cpag('restart');cpag('check')
    after=json.loads(inside('cat','/cpag-root/data/demo-results.json').stdout);assert before==after
    record('service-restart',{'before':before,'after':after,'same_persisted_jobs':True})
    record('offline-check',json.loads(inside('cat','/cpag-root/data/offline-check.json').stdout))
    record('target-images',[json.loads(line) for line in inside('docker','image','ls','--format','{{json .}}').stdout.splitlines()])
    # Prove completed attempts used real isolated containers recorded by PostgreSQL,
    # rather than calculating samples directly in the controller/API process.
    c=json.loads(inside('cat','/cpag-root/data/config.json').stdout)
    rows=inside('docker','exec','cpag-engineering-postgres','psql','-At','-U','postgres','-d','m4_validation','-c',"SELECT job_id,attempt,location,container_id,exited_at IS NOT NULL,publication_state FROM m4_job_attempts ORDER BY job_id,attempt;").stdout
    assert 'docker:' in rows and '|published' in rows;record('actual-isolated-attempts',{'rows':rows})
    final_routes=inside('ip','route').stdout;assert not any(line.startswith('default ') for line in final_routes.splitlines())
    final_blocked=inside('wget','-T','3','-q','-O','-','https://example.com',check=False);assert final_blocked.returncode!=0
    record('airgap-after-services',{'routes':final_routes,'public_https_exit':final_blocked.returncode})
    cpag('stop')
    if a.run_upgrade_drill:
        result=inside('env','CPAG_ENGINEERING_DISPOSABLE=1','sh','/package/validate-upgrade-rollback.sh','/package')
        (a.evidence/'upgrade-rollback.log').write_text(result.stdout+'\n'+result.stderr)
        record('upgrade-rollback-result',json.loads(inside('cat','/round7-drill/upgrade-rollback-result.json').stdout))
    inside('docker','info')
    print('PASS clean offline installation/task/evidence/download/restart',flush=True)
finally:
    (a.evidence/'target-engine.log').write_text(host('logs',name,check=False).stdout)
    if not a.keep:
        host('rm','-f',name,check=False)
        host('network','rm',network,check=False)
        for volume in (engine,state,snapshots):host('volume','rm',volume,check=False)
    else:print('Preserved target: '+name,flush=True)
