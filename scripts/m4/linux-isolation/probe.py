"""Synthetic fault probes; no industrial data or external API."""
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time

mode = sys.argv[1]
if mode == 'memory':
    blocks = []
    while True: blocks.append(bytearray(8*1024*1024))
elif mode == 'cpu':
    while True: pass
elif mode in ('disk', 'output'):
    target = '/runtime' if mode == 'disk' else '/output'
    try:
        with open(target+'/fill', 'wb', buffering=0) as stream:
            while True: stream.write(b'x'*1048576)
    except OSError as exc:
        print(json.dumps({'errno':exc.errno,'target':target}), flush=True)
        sys.exit(0 if exc.errno == 28 else 1)
elif mode == 'pids':
    children = []
    try:
        while True:
            pid = os.fork()
            if pid == 0:
                time.sleep(60)
                sys.exit()
            children.append(pid)
    except OSError as exc:
        print(json.dumps({'errno':exc.errno,'children':len(children)}), flush=True)
        sys.exit(0 if exc.errno == 11 else 1)
elif mode == 'core':
    # Delay is an explicit synthetic startup fault, not a Worker timeout change.
    if '--startup-delay' in sys.argv:
        time.sleep(float(sys.argv[sys.argv.index('--startup-delay') + 1]))
    child_pid, guardian_pid = os.getpid(), os.getppid()
    # Escapes the process group deliberately. Container teardown must catch it.
    if os.fork() == 0:
        os.setsid()
        snapshot = {'child': child_pid, 'guardian': guardian_pid, 'escaped': os.getpid(),
                    'worker': int(Path('/runtime/worker.pid').read_text())}
        temporary = Path('/runtime/started.tmp')
        temporary.write_text(json.dumps(snapshot))
        temporary.replace('/runtime/started.json')
        while True: time.sleep(.1)
    while True: time.sleep(.1)
elif mode == 'worker':
    from cpag_worker.worker import Worker
    root = Path('/runtime/shared'); root.mkdir()
    payload = {'config_fingerprint':'synthetic'}
    for name in ('network','process','profile'):
        (root/name).write_text('synthetic')
        payload[name] = {'path':name,'sha256':hashlib.sha256(b'synthetic').hexdigest()}
    class API:
        def post(self, path, body): return {}
    Path('/runtime/worker.pid').write_text(str(os.getpid()))
    worker = Worker(API(),root,'linux-probe',timeout=2 if os.environ.get('PROBE_TIMEOUT') else 60,
                    command=[sys.executable,__file__,'core','--startup-delay',os.environ.get('PROBE_STARTUP_DELAY','0')])
    started = time.monotonic()
    result=worker.attempt({'id':'probe','attempt':1,'token':'synthetic','payload':payload,'output_dir':'output'})
    receipt=root/'output.worker'/'exit.json'
    print(json.dumps({'probe_result': True, 'worker_result':result,
                      'elapsed_seconds': time.monotonic()-started,
                      'startup': json.loads(Path('/runtime/started.json').read_text()) if Path('/runtime/started.json').exists() else None,
                      'receipt':json.loads(receipt.read_text()) if receipt.exists() else None}),flush=True)
else:
    raise SystemExit('unknown probe')
