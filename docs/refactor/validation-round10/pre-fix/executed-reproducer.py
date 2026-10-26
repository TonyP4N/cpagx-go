"""Run opt-in Docker/cgroup probes and save inspectable JSON evidence."""
import json
from pathlib import Path
import subprocess
import time

ROOT = Path('/Users/nbtechx-pyf/Documents/ChatGPT/FYP/cpagx-go')
OUT = ROOT/'docs/refactor/validation-round10/pre-fix'
OUT.mkdir(parents=True,exist_ok=True)
def docker(*args):
    return subprocess.check_output(['docker',*args],text=True).strip()
docker('build','-t','cpag-linux-isolation:round4','-f',str(ROOT/'deployments/linux-isolation/Dockerfile'),str(ROOT))
results = []
for mode in ('timeout',):
    name = 'cpag-r4-'+mode
    args = ['run','-d','--name',name,'--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--memory','128m','--memory-swap','128m',
            '--cpus','.25','--pids-limit','32','--tmpfs','/runtime:rw,nosuid,nodev,size=16m,mode=1777',
            '--tmpfs','/output:rw,nosuid,nodev,size=8m,mode=1777',
            '-e','CPAG_CONTAINER_SECONDS=20']
    if mode == 'timeout': args += ['-e','PROBE_TIMEOUT=1']
    args += ['cpag-linux-isolation:round4','python','/app/isolation/probe.py',
             'worker' if mode in ('timeout','doublekill') else mode]
    record = {'probe':mode}
    try:
        docker(*args)
        time.sleep(10)  # deterministic slow host observer
        if mode in ('doublekill','timeout'):
            for _ in range(100):
                try:
                    evidence = docker('exec',name,'python','-c',
                        "from pathlib import Path; import json; p=Path('/runtime/shared/output.worker/child.pid'); print(json.dumps({'child':int(p.read_text()),'escaped':int(Path('/runtime/escaped.pid').read_text()),'worker':int(Path('/runtime/worker.pid').read_text())}))")
                    record['before'] = json.loads(evidence); break
                except subprocess.CalledProcessError:
                    if docker('inspect','--format','{{.State.Running}}',name) == 'false':
                        raise AssertionError(docker('logs',name))
                    time.sleep(.05)
            else:
                record['startup_logs']=docker('logs',name)
                raise AssertionError('child did not start: '+record['startup_logs'])
        if mode == 'doublekill':
            record['kill'] = docker('exec',name,'python','-c',
                "from pathlib import Path; import os,signal,json; child=int(Path('/runtime/shared/output.worker/child.pid').read_text()); fields=Path('/proc/'+str(child)+'/stat').read_text().rsplit(')',1)[1].split(); guardian=int(fields[1]); worker=int(Path('/runtime/worker.pid').read_text()); print(json.dumps({'guardian':guardian,'worker':worker}),flush=True); os.kill(guardian,signal.SIGKILL); os.kill(worker,signal.SIGKILL)")
        if mode == 'cpu':
            time.sleep(1)
            record['cpu_before'] = docker('exec',name,'cat','/sys/fs/cgroup/cpu.stat')
            start=time.monotonic(); time.sleep(3)
            record['cpu_after'] = docker('exec',name,'cat','/sys/fs/cgroup/cpu.stat')
            record['interval_seconds']=time.monotonic()-start
            def usage(value): return int(dict(line.split() for line in value.splitlines())['usage_usec'])
            record['cpu_cores']=(usage(record['cpu_after'])-usage(record['cpu_before']))/1e6/record['interval_seconds']
            assert .10 < record['cpu_cores'] < .40, record
        record['exit'] = int(docker('wait',name))
        record['state']=json.loads(docker('inspect','--format','{{json .State}}',name))
        record['limits']=json.loads(docker('inspect','--format','{{json .HostConfig}}',name))
        record['logs']=docker('logs',name)
        record['top']=subprocess.run(['docker','top',name],text=True,capture_output=True).__dict__['stderr'].strip()
        assert record['state']['Running'] is False and record['state']['Pid'] == 0
        if mode == 'memory': assert record['state']['OOMKilled'] or record['exit']==137
        if mode in ('disk','output'): assert '"errno": 28' in record['logs']
        if mode == 'pids': assert '"errno": 11' in record['logs']
        if mode == 'cpu': assert record['exit']==124
        if mode == 'timeout':
            assert record['exit']==0 and '"reason": "timeout"' in record['logs'], record
        if mode == 'doublekill': assert record['exit']==137
        record['pass']=True
    finally:
        results.append(record)
        (OUT/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL)
    print('PASS',mode,flush=True)
