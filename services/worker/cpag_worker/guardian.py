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
        if config.get('resident_sandbox'):
            from .resident_sandbox import enter
            enter(config['resident_sandbox'])
    child = subprocess.Popen(config['command'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
        if config.get('output_root'):
            try:
                used = sum(p.stat().st_size for p in Path(config['output_root']).rglob('*') if p.is_file() and not p.is_symlink())
                if used > config['file_bytes']:
                    reason = 'output_limit'
                    break
            except OSError:
                reason = 'output_unreadable'
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
    # A PID alone is never exit evidence (PID reuse and remote workers). The
    # guardian checks its own group after wait; zombies cannot compute.
    def group_exited():
        if sys.platform.startswith('linux'):
            for item in Path('/proc').iterdir():
                if not item.name.isdigit(): continue
                try:
                    fields = (item/'stat').read_text().rsplit(')', 1)[1].split()
                    if int(fields[2]) == child.pid and fields[0] != 'Z': return False
                except (FileNotFoundError, ProcessLookupError): pass
            return True
        try: os.killpg(child.pid, 0)
        except ProcessLookupError: return True
        return False
    for _ in range(100):
        if group_exited(): break
        time.sleep(.05)
    else: return  # No proof: recovery must retain cancelling.
    proof = {**config['identity'], 'returncode':child.returncode,'reason':reason,
             'group_exited':True,'child_pid':child.pid,'guardian_pid':os.getpid()}
    if config.get('resident_receipt'):
        resident = {**config['resident_receipt'], 'version': 'resident-guardian-1',
                    **{k: proof[k] for k in ('returncode', 'reason', 'group_exited', 'child_pid', 'guardian_pid')}}
        proof = {**config['identity'], 'location': config['location'],
                 'container_id': resident['container_id'], 'scope': 'resident-process-group',
                 'exited': True, 'resident': resident}
    target = Path(config['exit_file'])
    temporary = target.with_suffix('.tmp')
    with temporary.open('x') as stream:
        json.dump(proof, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)

if __name__ == '__main__':
    supervise(json.loads(Path(sys.argv[1]).read_text()))
