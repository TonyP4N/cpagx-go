"""Compute-only PID1. Host owns credentials, container lifecycle and publication."""
import json
import resource
from pathlib import Path
import subprocess
import sys
import time

started=time.monotonic()
child=subprocess.Popen(sys.argv[1:])
deadline=time.monotonic()+float(__import__('os').environ.get('CPAG_CONTAINER_SECONDS','120'))
while child.poll() is None:
    if time.monotonic()>deadline:
        raise SystemExit(124)
    time.sleep(.05)
usage=resource.getrusage(resource.RUSAGE_CHILDREN)
Path('/runtime/result.json').write_text(json.dumps({'returncode':child.returncode,
    'measurement_version':'compute-process-resources-1',
    'wall_seconds':time.monotonic()-started,
    'cpu_user_seconds':usage.ru_utime,'cpu_system_seconds':usage.ru_stime,
    'rss_peak_bytes':usage.ru_maxrss*1024,
    'scope':'Linux waited compute process and waited descendants; excludes host transfer/verification and tmpfs pages; not exit proof'}))
# Keep bounded tmpfs available for host-side copy. PID1 deadline also bounds
# detached descendants and orphaned containers if the host controller dies.
while time.monotonic()<deadline:
    time.sleep(.05)
raise SystemExit(124)
