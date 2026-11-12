"""Container PID 1: worker exit or wall deadline ends the entire PID namespace.

Run exactly one worker attempt per container. Never reuse a container for a lease.
"""
import os
import signal
import subprocess
import sys
import time

child = subprocess.Popen(sys.argv[1:])
deadline = time.monotonic() + float(os.environ.get('CPAG_CONTAINER_SECONDS', '180'))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
while child.poll() is None:
    if time.monotonic() >= deadline:
        print('container wall deadline', flush=True)
        sys.exit(124)
    time.sleep(.05)
sys.exit(child.returncode if child.returncode >= 0 else 128-child.returncode)
