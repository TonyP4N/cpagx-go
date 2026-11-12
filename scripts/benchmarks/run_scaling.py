"""Run only the registered synthetic benchmark in a bounded disposable Linux container."""
import argparse
import json
from pathlib import Path
import subprocess
import uuid

ROOT=Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    name='cpag-benchmark-'+uuid.uuid4().hex[:10]
    image='cpag-synthetic-scaling:round11'
    report={'status':'failed','synthetic':True}
    try:
        subprocess.run(['docker','build','-t',image,'-f',str(ROOT/'deployments/benchmarks/Dockerfile'),str(ROOT)],check=True,timeout=180)
        report['image_id']=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',image],text=True,timeout=15).strip()
        command=['docker','run','--name',name,'--network','none','--read-only','--cap-drop','ALL',
                 '--security-opt','no-new-privileges','--cpus','2','--memory','512m','--memory-swap','512m',
                 '--pids-limit','64','--tmpfs','/tmp:rw,nosuid,nodev,size=256m,mode=1777',report['image_id']]
        child=subprocess.run(command,text=True,capture_output=True,timeout=600)
        report['container_exit_code']=child.returncode
        report['stderr']=child.stderr[-8000:]
        try: report['benchmark']=json.loads(child.stdout)
        except ValueError: report['measurement_error']='missing_or_invalid_container_report'
        report['state']=json.loads(subprocess.check_output(['docker','inspect','--format','{{json .State}}',name],text=True,timeout=15))
        report['limits']=json.loads(subprocess.check_output(['docker','inspect','--format','{{json .HostConfig}}',name],text=True,timeout=15))
        benchmark=report.get('benchmark',{})
        if (child.returncode==0 and benchmark.get('status')=='passed' and report['state']['Running'] is False
            and report['state']['Pid']==0 and not report['state']['OOMKilled']):
            # Confirm actual cgroup limits, not merely CLI flags.
            env=benchmark['environment']
            assert env['memory_max']=='536870912' and env['memory_swap_max']=='0' and env['pids_max']=='64'
            quota,period=map(int,env['cpu_max'].split());assert quota/period==2
            report['status']='passed'
    except (subprocess.SubprocessError,OSError,ValueError,KeyError,AssertionError) as exc:
        report['error']=type(exc).__name__+': '+str(exc)
    finally:
        # Safe after partial startup as well; only this UUID-named container.
        try:
            cleanup=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=20)
            report['cleanup']='passed' if cleanup.returncode==0 or 'No such container' in cleanup.stderr else 'failed'
        except (OSError,subprocess.SubprocessError) as exc:
            report['cleanup']='failed'
            report['cleanup_error']=type(exc).__name__
        if report['cleanup']=='failed': report['status']='failed'
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'output':str(args.output)}))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
