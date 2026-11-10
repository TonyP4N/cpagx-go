#!/usr/bin/env python3
"""Two actual tiny Linux filesystem faults; no PostgreSQL or analysis execution."""
import argparse, hashlib, json, os, re, secrets, subprocess, tempfile
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
def run(args,**kwargs):return subprocess.run(args,capture_output=True,check=True,**kwargs)
def allowed_output(path):
    target=Path(path).resolve(); roots={Path(tempfile.gettempdir()).resolve(),Path('/tmp').resolve()}
    return any(target != root and target.is_relative_to(root) for root in roots)

def main(output,image):
 output=output.resolve();output.mkdir(parents=True,exist_ok=False,mode=0o700)
 resolved=json.loads(run(['docker','image','inspect',image]).stdout)[0]
 architecture=resolved['Architecture'];require_arch={'arm64':'arm64','amd64':'amd64'}
 if architecture not in require_arch:raise ValueError('unsupported probe architecture')
 env=dict(os.environ,GOOS='linux',GOARCH=require_arch[architecture],CGO_ENABLED='0',GOCACHE=os.environ.get('GOCACHE') or str(Path(tempfile.gettempdir())/'cpag-r21-go-cache'))
 binary=output/'catalog-storage.test'
 result=run(['go','test','-c','-o',str(binary),'./internal/catalog'],cwd=REPO,env=env,timeout=180)
 (output/'build.log').write_bytes(result.stdout+result.stderr);binary.chmod(0o755)
 fixture=output/'readonly';fixture.mkdir(mode=0o755)
 report={'scope':'actual Linux container filesystem checks only; not complete parser/write-publication or reference-environment acceptance','image':resolved['Id'],'architecture':architecture,'cases':[],'status':'running'}
 target=output/'report.json'
 for kind in ('readonly','small-full'):
  name='cpag-r21-storage-'+secrets.token_hex(4)
  args=['docker','create','--name',name,'--label','cpag.r21.storage-probe=true','--user','65532:65532','--network','none','--read-only','--memory','128m','--memory-swap','128m','--cpus','.5','--pids-limit','32','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,nosuid,size=32m,mode=1777','-e','CPAG_R21_MOUNT_PROBE='+kind,'-v',str(binary)+':/catalog-storage.test:ro']
  if kind=='readonly':args+=['-v',str(fixture)+':/probe:ro']
  else:args+=['--tmpfs','/probe:rw,nosuid,size=8m,mode=0700,uid=65532,gid=65532']
  args+=['--entrypoint','/catalog-storage.test',resolved['Id'],'-test.run=^TestR21ActualReadOnlyAndSmallFilesystem$','-test.v']
  try:
   run(args,timeout=20);result=subprocess.run(['docker','start','-a',name],capture_output=True,timeout=30)
   (output/(kind+'.log')).write_bytes(result.stdout+result.stderr)
   info=json.loads(run(['docker','inspect',name],timeout=10).stdout)[0];(output/(kind+'-inspect.json')).write_text(json.dumps(info,indent=2)+'\n')
   matches=re.findall(rb'R21_STORAGE_PROBE (\{.*\})',result.stdout)
   record={'probe':kind,'exit_code':info['State']['ExitCode'],'running':info['State']['Running'],'readonly_root':info['HostConfig']['ReadonlyRootfs'],'network':info['HostConfig']['NetworkMode'],'memory_bytes':info['HostConfig']['Memory'],'pids_limit':info['HostConfig']['PidsLimit'],'tmpfs':info['HostConfig']['Tmpfs'],'probe_mount_readonly':any(row['Destination']=='/probe' and row['RW'] is False for row in info.get('Mounts',[])),'result':json.loads(matches[-1]) if matches else None}
   report['cases'].append(record)
   if result.returncode or record['exit_code'] or record['running'] or not matches:raise RuntimeError('actual_'+kind+'_probe_failed')
  finally:
   run(['docker','rm','-f',name],timeout=15)
   target.write_text(json.dumps(report,indent=2)+'\n')
 report['status']='passed';report['cleanup_completed']=True;report['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();report['health_source_sha256']=hashlib.sha256((REPO/'internal/catalog/health.go').read_bytes()).hexdigest();target.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':'passed','report':str(target)}))
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--image',required=True);args=parser.parse_args()
 if not allowed_output(args.output) or re.fullmatch(r'(sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})',args.image) is None:parser.error('fresh system-temporary output and existing immutable image required')
 main(args.output,args.image)
