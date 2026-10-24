"""Attempt supervisor. Parent pipe EOF kills the entire core process group."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


def supervise(config):
    stop = threading.Event()
    def parent_pipe():
        while os.read(0, 1):
            pass
        stop.set()
    def limits():
        import resource
        for name, value in [('RLIMIT_CPU', config['cpu_seconds']), ('RLIMIT_AS', config['memory_bytes']), ('RLIMIT_FSIZE', config['file_bytes']), ('RLIMIT_NOFILE', 128)]:
            if name == 'RLIMIT_AS' and sys.platform == 'darwin':
                continue  # macOS rejects effective address-space caps; use Linux for this limit.
            if hasattr(resource, name) and value:
                resource.setrlimit(getattr(resource, name), (value, value))
    child = subprocess.Popen(config['command'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, preexec_fn=limits if os.name == 'posix' else None,
                             env=config['env'])
    threading.Thread(target=parent_pipe, daemon=True).start()
    Path(config['pid_file']).write_text(str(child.pid))
    def drain(stream, filename):
        remaining = config['log_bytes']
        with open(filename, 'wb') as out:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                out.write(chunk[:remaining])
                remaining = max(0, remaining-len(chunk))
    threads = [threading.Thread(target=drain, args=(stream, config[name]), daemon=True) for stream, name in [(child.stdout, 'stdout'), (child.stderr, 'stderr')]]
    for thread in threads:
        thread.start()
    deadline = time.monotonic()+config['timeout']
    reason = 'exited'
    while child.poll() is None:
        if stop.is_set() or time.monotonic() >= deadline:
            reason = 'parent_disconnected' if stop.is_set() else 'timeout'
            break
        time.sleep(.05)
    # Always kill the group, including descendants surviving a clean core exit.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=config['kill_grace'])
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait()
    for thread in threads:
        thread.join(timeout=2)
    Path(config['exit_file']).write_text(json.dumps({'returncode':child.returncode,'reason':reason}))

if __name__ == '__main__':
    supervise(json.loads(Path(sys.argv[1]).read_text()))
