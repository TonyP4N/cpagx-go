"""Private PID1 identity for a singleton Compose worker, without daemon access.

The descriptor deliberately has no close/unlock method. Only process termination
releases it. A replacement PID1 publishes its own generation while holding the
singleton owner lock. API recovery requires both that replacement and release of
the exact old generation; an unlocked file on its own never attests termination.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from .isolated import atomic_json, sync_dir


class ComposeGeneration:
    def __init__(self, control, deployment, supervisor):
        if sys.platform != 'linux' or os.geteuid() != 0 or os.getpid() != 1:
            raise ValueError('Compose resident generation requires trusted Linux root PID1')
        if not re.fullmatch(r'[0-9a-f]{32}', deployment) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', supervisor):
            raise ValueError('invalid Compose deployment or singleton supervisor identity')
        control = Path(control)
        directory = control/'resident-generations'
        directory.mkdir(mode=0o700, exist_ok=True)
        for path in (control, directory):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise ValueError('private root-owned generation directory required')
        generation = secrets.token_hex(16)
        self.fd = os.open(directory/(generation+'.lock'), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        os.set_inheritable(self.fd, False)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record = {'version': 'resident-compose-generation-1', 'deployment_id': deployment,
                  'generation': generation, 'supervisor_id': supervisor, 'pid': 1}
        raw = json.dumps(record, sort_keys=True).encode()
        remaining = memoryview(raw)
        while remaining:
            remaining = remaining[os.write(self.fd, remaining):]
        os.fsync(self.fd)
        sync_dir(directory)
        atomic_json(control/'resident-current.json', record)
        self.identity = {'version': 'resident-registration-1', 'backend': 'compose-pid1-v1',
                         'deployment_id': deployment, 'generation': generation,
                         'supervisor_id': supervisor, 'container_id': 'pid1://'+generation}
