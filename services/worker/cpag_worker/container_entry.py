"""Compute-only PID1. Host owns credentials, container lifecycle and publication."""
import json
from pathlib import Path
import subprocess
import sys
import time

child=subprocess.Popen(sys.argv[1:])
deadline=time.monotonic()+float(__import__('os').environ.get('CPAG_CONTAINER_SECONDS','120'))
while child.poll() is None:
    if time.monotonic()>deadline:
        raise SystemExit(124)
    time.sleep(.05)
Path('/runtime/result.json').write_text(json.dumps({'returncode':child.returncode}))
# Keep bounded tmpfs available for host-side copy. PID1 deadline also bounds
# detached descendants and orphaned containers if the host controller dies.
while time.monotonic()<deadline:
    time.sleep(.05)
raise SystemExit(124)
