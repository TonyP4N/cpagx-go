"""Bounded, peer-authenticated local requests; never returns execution authority."""
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
import time

CONSUMER_UID = 65531
PARTITION = 'rabbit-v3'
LIMIT = 1024


def dispatch_request(value):
    if not isinstance(value, dict) or set(value) != {'job_id', 'dispatch_id'}:
        raise ValueError('dispatch identity fields required')
    if any(not isinstance(value[k], str) or re.fullmatch('[0-9a-f]{32}', value[k]) is None for k in value):
        raise ValueError('invalid dispatch identity')
    return {**value, 'partition': PARTITION}


def read_line(stream):
    data = bytearray()
    while not data.endswith(b'\n'):
        chunk = stream.recv(min(256, LIMIT + 1 - len(data)))
        if not chunk:
            raise ValueError('incomplete local request')
        data.extend(chunk)
        if len(data) > LIMIT:
            raise ValueError('local request limit')
    return json.loads(data)


def request(path, value, timeout=7200):
    dispatch_request(value)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(path))
        client.sendall(json.dumps(value, separators=(',', ':')).encode()+b'\n')
        response = read_line(client)
        if not isinstance(response, dict) or set(response) != {'status'} or response['status'] not in ('done', 'stale', 'retry'):
            raise ValueError('invalid supervisor response')
        return response['status']


class DispatchServer:
    def __init__(self, path, owner, lock, fatal, consumer_uid=CONSUMER_UID):
        self.path, self.owner, self.lock, self.fatal = Path(path), owner, lock, fatal
        self.consumer_uid = consumer_uid
        self.stopped = threading.Event()
        self.listener = None
        self.thread = None
        self.pending_until = 0

    def start(self):
        if not hasattr(socket, 'SO_PEERCRED') or os.geteuid() != 0:
            raise ValueError('Linux root peer-authenticated supervisor required')
        parent = self.path.parent
        parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        if parent.is_symlink() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o027:
            raise ValueError('dispatch directory must be root-owned and protected')
        os.chown(parent, 0, self.consumer_uid); parent.chmod(0o750)
        if self.path.exists():
            info = self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                raise ValueError('foreign dispatch socket')
            self.path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path)); os.chown(self.path, 0, self.consumer_uid); self.path.chmod(0o660)
        listener.listen(8); listener.settimeout(.5)
        self.listener = listener
        self.thread = threading.Thread(target=self.serve, daemon=True); self.thread.start()

    def handle(self, client):
        _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != self.consumer_uid:
            raise PermissionError('foreign local peer')
        client.settimeout(2)
        dispatch = dispatch_request(read_line(client))
        if not self.lock.acquire(blocking=False):
            self.pending_until = time.monotonic()+6
            return 'retry'
        self.pending_until = 0
        try:
            result = self.owner.once(dispatch=dispatch)
            if result == 'recovery_required':
                self.fatal.set(); self.owner.helper.stop()
            return 'done' if result == 'settled' else 'stale' if result == 'idle' else 'retry'
        except Exception:
            if self.owner.journal.exists():
                self.fatal.set(); self.owner.helper.stop()
            # API409 means exact dispatch still queued but temporarily busy.
            return 'retry'
        finally:
            self.lock.release()

    def queue_pending(self):
        return time.monotonic() < self.pending_until

    def serve(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with client:
                try:
                    status = self.handle(client)
                    client.sendall(json.dumps({'status': status}).encode()+b'\n')
                except (ValueError, PermissionError, OSError):
                    pass  # No authority or exception bodies cross the socket.

    def close(self):
        self.stopped.set()
        if self.listener: self.listener.close()
        if self.thread: self.thread.join(timeout=5)
