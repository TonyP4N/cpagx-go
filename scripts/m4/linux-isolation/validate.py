"""Real Docker/cgroup probes with bounded observation and durable final evidence."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid
from evidence import timeout_proof, doublekill_proof

ROOT = Path(__file__).resolve().parents[3]


def docker(*args, timeout=45):
    return subprocess.check_output(['docker', *args], text=True, stderr=subprocess.PIPE, timeout=timeout).strip()


def run_probe(mode, iteration, image, observer_delay):
    name = 'cpag-r10-' + uuid.uuid4().hex[:10]
    record = {'probe': mode, 'iteration': iteration, 'container': name, 'pass': False}
    args = ['run','-d','--name',name,'--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--memory','128m','--memory-swap','128m',
            '--cpus','.25','--pids-limit','32','--tmpfs','/runtime:rw,nosuid,nodev,size=16m,mode=1777',
            '--tmpfs','/output:rw,nosuid,nodev,size=8m,mode=1777',
            '-e','CPAG_CONTAINER_SECONDS=20']
    is_timeout = mode in ('timeout','late-observer','slow-start')
    if is_timeout:
        args += ['-e','PROBE_TIMEOUT=1']
    if mode == 'slow-start':
        args += ['-e','PROBE_STARTUP_DELAY=4']
    args += [image,'python','/app/isolation/probe.py',
             'worker' if is_timeout or mode == 'doublekill' else mode]
    created = False
    try:
        docker(*args)
        created = True
        if mode == 'late-observer':
            # Wait for real termination first: observation happens strictly after exit.
            docker('wait', name)
            time.sleep(observer_delay)
            record['observed_after_exit'] = True
        if mode == 'doublekill':
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                try:
                    record['before'] = json.loads(docker('exec',name,'cat','/runtime/started.json', timeout=max(.1, deadline-time.monotonic())))
                    break
                except (subprocess.CalledProcessError, ValueError) as exc:
                    record['last_startup_observation_error'] = str(exc)
                    assert docker('inspect','--format','{{.State.Running}}',name) == 'true', 'container exited before readiness'
                    time.sleep(.1)
            else:
                raise AssertionError('startup evidence deadline exceeded (12s)')
            assert all(type(record['before'].get(k)) is int and record['before'][k] > 1
                       for k in ('child','guardian','worker','escaped'))
            # PID 1 tears down the exec process too. Preserve its flushed action
            # acknowledgement and inspect final state rather than require exec=0.
            injection = subprocess.run(['docker','exec',name,'python','-c',
                "from pathlib import Path; import os,signal,json,time; s=json.loads(Path('/runtime/started.json').read_text()); "
                "fields=Path('/proc/'+str(s['child'])+'/stat').read_text().rsplit(')',1)[1].split(); "
                "assert int(fields[1])==s['guardian']; os.kill(s['guardian'],signal.SIGKILL); "
                "print(json.dumps({'identity':s,'guardian_sigkill_sent':True}),flush=True); "
                "os.kill(s['worker'],signal.SIGKILL); time.sleep(2)"],
                text=True, capture_output=True, timeout=15)
            record['injector_returncode'] = injection.returncode
            record['injector_stdout'] = injection.stdout
            record['injector_stderr'] = injection.stderr
        if mode == 'cpu':
            time.sleep(1)
            record['cpu_before'] = docker('exec',name,'cat','/sys/fs/cgroup/cpu.stat')
            start = time.monotonic(); time.sleep(3)
            record['cpu_after'] = docker('exec',name,'cat','/sys/fs/cgroup/cpu.stat')
            record['interval_seconds'] = time.monotonic()-start
            def usage(value): return int(dict(line.split() for line in value.splitlines())['usage_usec'])
            record['cpu_cores'] = (usage(record['cpu_after'])-usage(record['cpu_before']))/1e6/record['interval_seconds']
            assert .10 < record['cpu_cores'] < .40, record
        record['exit'] = int(docker('wait',name))
        record['state'] = json.loads(docker('inspect','--format','{{json .State}}',name))
        record['limits'] = json.loads(docker('inspect','--format','{{json .HostConfig}}',name))
        record['logs'] = docker('logs',name)
        assert record['state']['Running'] is False and record['state']['Pid'] == 0
        if mode == 'memory': assert record['state']['OOMKilled'] or record['exit'] == 137
        if mode in ('disk','output'): assert '"errno": 28' in record['logs']
        if mode == 'pids': assert '"errno": 11' in record['logs']
        if mode == 'cpu': assert record['exit'] == 124
        if is_timeout:
            record['proof'] = timeout_proof(record, require_startup=mode != 'slow-start')
        if mode == 'doublekill': record['kill'] = doublekill_proof(record)
        record['pass'] = True
    except Exception as exc:
        record['error'] = f'{type(exc).__name__}: {exc}'
        if created:
            for key, command in [('failure_state',('inspect','--format','{{json .State}}',name)),
                                 ('failure_logs',('logs',name))]:
                try: record[key] = docker(*command)
                except Exception as diagnostic: record[key] = 'unavailable: ' + str(diagnostic)
    finally:
        if created:
            try:
                docker('rm','-f',name)
                record['cleanup'] = 'passed'
            except Exception as exc:
                record['cleanup'] = str(exc)
                record['pass'] = False
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'docs/refactor/validation-round10/linux-results.json')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--modes', nargs='+', choices=['memory','disk','output','pids','cpu','timeout','late-observer','slow-start','doublekill'])
    parser.add_argument('--observer-delay', type=float, default=.2)
    args = parser.parse_args()
    assert 1 <= args.repeats <= 10 and 0 <= args.observer_delay <= 10
    image = 'cpag-linux-isolation:round10'
    subprocess.run(['docker','build','-t',image,'-f',str(ROOT/'deployments/linux-isolation/Dockerfile'),str(ROOT)], check=True, timeout=180)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    results = []
    modes = args.modes or ['memory','disk','output','pids','cpu','timeout','late-observer','slow-start','doublekill']
    for mode in modes:
        for iteration in range(args.repeats if mode in ('timeout','late-observer','slow-start','doublekill') else 1):
            record = run_probe(mode, iteration+1, image, args.observer_delay)
            results.append(record)
            args.output.write_text(json.dumps(results, indent=2)+'\n')
            print('PASS' if record['pass'] else 'FAIL', mode, iteration+1, flush=True)
    assert all(r['pass'] for r in results), 'Probe failure: inspect ' + str(args.output)


if __name__ == '__main__':
    main()
