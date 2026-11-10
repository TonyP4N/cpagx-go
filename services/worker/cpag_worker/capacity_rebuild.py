"""Preview and explicitly apply a conservative isolated-executor capacity rebuild.

No files/artifacts or API task states are deleted or modified. Same owner->capacity
lock ordering as DockerExecutor; unknown evidence blocks apply.
"""
import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.parse
import time
import urllib.request
import uuid

JOB = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
ATTEMPT = re.compile(r'^attempt-([1-9][0-9]*)\.worker$')
OUTPUT = re.compile(r'^attempt-([1-9][0-9]*)(?:\.publish-lock)?$')
KEY = re.compile(r'^([A-Za-z0-9][A-Za-z0-9_.-]{0,127}):([1-9][0-9]*)$')
MAX_LEDGER = 4 * 1024 * 1024


class RebuildRefused(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def atomic(path, data):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if temporary.exists(): temporary.unlink()


def write_report(path, value, roots):
    path = Path(path).absolute()
    parent = path.parent.resolve(strict=True)
    path = parent / path.name
    if any(path == root or path.is_relative_to(root) for root in roots):
        raise RebuildRefused('report must be outside managed roots')
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical(value) + b'\n'); stream.flush(); os.fsync(stream.fileno())
    sync_directory(parent)


class CapacityRebuilder:
    def __init__(self, root, control, api_url='', token='', *, output_bytes=16777216, status_reader=None, discovery_reader=None, coordinator_token=''):
        self.root, self.control = Path(root).resolve(strict=True), Path(control).resolve(strict=True)
        if self.root == self.control or self.root.is_relative_to(self.control) or self.control.is_relative_to(self.root):
            raise RebuildRefused('shared and control roots must be separate')
        if type(output_bytes) is not int or not 1 <= output_bytes <= 1073741824:
            raise RebuildRefused('invalid executor output limit')
        self.output_bytes, self.api_url, self.token = output_bytes, api_url.rstrip('/'), token
        self.status_reader = status_reader or self._status
        self.coordinator_token=coordinator_token
        self.discovery_reader=discovery_reader
        self.path = self.control / 'capacity.json'

    def _status(self, job):
        request = urllib.request.Request(self.api_url + '/v1/jobs/' + job,
            headers={'Authorization': 'Bearer ' + self.token})
        with urllib.request.urlopen(request, timeout=3) as response:
            data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024: raise RebuildRefused('API status too large')
        return json.loads(data)

    def _discover(self):
        if self.discovery_reader is not None:return self.discovery_reader()
        daemon=subprocess.run(['docker','info','--format','{{.ID}}'],check=True,capture_output=True,text=True,timeout=10).stdout.strip()
        if not daemon or not self.coordinator_token:raise RebuildRefused('Docker identity and coordinator credential required')
        scope=digest((str(self.root)+'|'+str(self.control)).encode())[:24]
        location='docker:'+daemon+':'+scope
        records=[]
        # Unscoped earlier executions cannot safely be assigned to a control root.
        for queried in (location,'docker:'+daemon):
            request=urllib.request.Request(self.api_url+'/v1/executions?location='+urllib.parse.quote(queried,safe=''),headers={'Authorization':'Bearer '+self.coordinator_token})
            with urllib.request.urlopen(request,timeout=3) as response:data=response.read(4*1024*1024+1)
            if len(data)>4*1024*1024:raise RebuildRefused('execution discovery too large')
            items=json.loads(data)
            if not isinstance(items,list):raise RebuildRefused('invalid execution discovery')
            for item in items:
                if not isinstance(item,dict) or item.get('location')!=queried or not JOB.fullmatch(str(item.get('id',''))) or type(item.get('attempt')) is not int or item['attempt']<1:raise RebuildRefused('invalid execution discovery item')
                value={key:item.get(key) for key in ('id','attempt','location','container_id','executor','exited_at','state','current_attempt','lease_valid','start_revoked_at')}
                value['unscoped']=queried!=location
                records.append(value)
        return records

    def _attempts(self):
        result = set()
        jobs = self.control / 'jobs'
        if jobs.is_symlink(): raise RebuildRefused('symlinked control jobs directory')
        if not jobs.exists(): return result
        for job in jobs.iterdir():
            if job.is_symlink() or not job.is_dir() or not JOB.fullmatch(job.name):
                raise RebuildRefused('unsafe control job directory')
            for item in job.iterdir():
                if item.is_symlink(): raise RebuildRefused('symlinked attempt directory')
                match = ATTEMPT.fullmatch(item.name)
                if not match or not item.is_dir(): raise RebuildRefused('unrecognized control attempt directory')
                result.add((job.name, int(match[1])))
        if len(result) > 10000: raise RebuildRefused('attempt limit exceeded')
        return result

    @contextmanager
    def locked(self):
        # Never take capacity.lock and then wait for owner.lock: workers acquire
        # them in the reverse order. All acquisitions fail immediately on contention.
        with ExitStack() as stack:
            before = self._attempts()
            for job, attempt in sorted(before):
                path = self.control / 'jobs' / job / ('attempt-' + str(attempt) + '.worker') / 'owner.lock'
                fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                stream = stack.enter_context(os.fdopen(fd, 'a+'))
                try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: raise RebuildRefused('attempt owner active: ' + job + ':' + str(attempt))
            fd = os.open(self.control / 'capacity.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            stream = stack.enter_context(os.fdopen(fd, 'a+'))
            try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise RebuildRefused('capacity lock busy')
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.fstat(stream.fileno()).st_nlink != 1: raise RebuildRefused('unsafe capacity lock')
            if before != self._attempts(): raise RebuildRefused('attempt namespace changed while locking')
            yield

    def _ledger(self):
        try:
            info = self.path.lstat()
        except FileNotFoundError: return {'state': 'missing', 'sha256': None}, None, {}
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_LEDGER:
            raise RebuildRefused('unsafe or oversized capacity ledger')
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            initial=os.fstat(stream.fileno());raw=stream.read(MAX_LEDGER+1);final=os.fstat(stream.fileno())
        identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if len(raw)>MAX_LEDGER or len(raw)!=final.st_size or identity(initial)!=identity(final) or identity(final)!=identity(self.path.lstat()):raise RebuildRefused('ledger changed during inspection')
        marker = {'sha256': digest(raw), 'size': len(raw), 'state': 'invalid'}
        try:
            value = json.loads(raw)
            if isinstance(value, dict) and 'root' in value and value['root'] != str(self.root):
                raise RebuildRefused('capacity ledger belongs to another root')
            if not isinstance(value, dict) or not isinstance(value.get('reservations'), dict): raise ValueError()
            reservations = value['reservations']
            if any(not isinstance(key, str) or (key != '__existing__' and not KEY.fullmatch(key)) or type(size) is not int or size < 0 for key, size in reservations.items()): raise ValueError()
            marker['state'] = 'valid'
            return marker, raw, reservations
        except RebuildRefused: raise
        except (ValueError, TypeError): return marker, raw, {}

    def _scan(self):
        entries = []
        def walk_error(error):raise error
        for label, root in (('shared', self.root), ('control', self.control)):
            for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
                base = Path(directory)
                for name in dirs:
                    path = base / name
                    if path.is_symlink(): raise RebuildRefused('symlinked managed directory: ' + str(path))
                for name in names:
                    path = base / name; relative = str(path.relative_to(root))
                    if label == 'control' and relative in ('capacity.json', 'capacity.lock'): continue
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise RebuildRefused('symlink, hardlink or special managed file: ' + str(path))
                    if name == 'owner.lock':
                        if info.st_size: raise RebuildRefused('nonempty owner lock')
                        continue
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, 'rb') as stream:
                        initial = os.fstat(stream.fileno()); h = hashlib.sha256()
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''): h.update(chunk)
                        final = os.fstat(stream.fileno())
                    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                    if identity(initial) != identity(final) or identity(final) != identity(path.lstat()):
                        raise RebuildRefused('file changed during inspection')
                    entries.append({'root': label, 'path': relative, 'size': final.st_size,
                        'sha256': h.hexdigest(), 'identity': list(identity(final))})
        return sorted(entries, key=lambda item: (item['root'], item['path']))

    def _snapshot(self):
        old, raw, reservations = self._ledger()
        entries = self._scan()
        try:
            discovered=self._discover();discovery_unknown=None
            if not isinstance(discovered,list):raise RebuildRefused('invalid execution discovery')
        except Exception as error:discovered=[];discovery_unknown=type(error).__name__
        attempts = set(self._attempts())
        usage = {}; unassigned = 0; outside = 0
        for item in discovered:
            if not isinstance(item,dict) or not JOB.fullmatch(str(item.get('id',''))) or type(item.get('attempt')) is not int or item['attempt']<1:
                discovery_unknown='InvalidExecutionDiscovery';continue
            attempts.add((item['id'],item['attempt']))
        protected=False
        for key in reservations:
            if key != '__existing__': match = KEY.fullmatch(key); attempts.add((match[1], int(match[2])))
        # Include outputs whose control directory was lost; API remains authoritative.
        for entry in entries:
            parts = Path(entry['path']).parts
            assigned = None
            if len(parts) >= 3 and parts[0] == 'jobs' and JOB.fullmatch(parts[1]):
                match = (ATTEMPT if entry['root'] == 'control' else OUTPUT).fullmatch(parts[2])
                if match: assigned = (parts[1], int(match[1])); attempts.add(assigned)
            if assigned: usage[assigned] = usage.get(assigned, 0) + entry['size']
            elif parts and parts[0] == 'jobs': unassigned += entry['size']
            else: outside += entry['size']
        states = {}; unknown = []; proposed = {}; decisions = []
        for job, attempt in sorted(attempts):
            if job not in states:
                try:
                    status = self.status_reader(job)
                    if not isinstance(status, dict) or status.get('id') != job or not isinstance(status.get('attempt_history'), list): raise ValueError('invalid API job status')
                    if status.get('state') not in ('queued','running','cancelling','cancelled','failed','succeeded') or type(status.get('attempt')) is not int or status['attempt']<0 or type(status.get('lease_valid')) is not bool: raise ValueError('invalid API job state')
                    history=status['attempt_history']
                    if any(not isinstance(item,dict) or type(item.get('attempt')) is not int or item['attempt']<1 or (item.get('exited_at') is not None and (not isinstance(item['exited_at'],str) or not item['exited_at'])) for item in history) or len({item['attempt'] for item in history})!=len(history):raise ValueError('invalid API attempt history')
                    states[job] = {'state': status['state'], 'attempt': status['attempt'], 'lease_valid': status.get('lease_valid'),
                        'payload': json.loads(json.dumps(status.get('payload'))), 'attempt_history': [
                            {key: value for key, value in item.items() if key in ('attempt', 'exited_at', 'executor', 'start_revoked_at', 'publication_state', 'container_id', 'location')}
                            for item in status['attempt_history']]}
                except Exception as error:
                    states[job] = {'unknown': type(error).__name__}
            state = states[job]; key = job + ':' + str(attempt); used = usage.get((job, attempt), 0)
            history = [item for item in state.get('attempt_history', []) if item.get('attempt') == attempt]
            known = len(history) == 1 and 'unknown' not in state and history[0].get('executor') in ('legacy','isolated-v2') and history[0].get('publication_state') in ('unpublished','fenced','published') and attempt<=state['attempt']
            if not known: unknown.append(key)
            terminal = known and state.get('state') in ('succeeded', 'failed', 'cancelled') and history[0].get('exited_at') is not None
            inputs = 48 * 1024 * 1024
            if known:
                try:
                    sizes = []
                    for role in ('network', 'process', 'profile'):
                        ref = state['payload'][role]; path = Path(ref['path'])
                        if path.is_absolute() or '..' in path.parts or not path.parts or str(path)=='.': raise ValueError()
                        matches = [item for item in entries if item['root'] == 'shared' and item['path'] == str(path) and item['sha256'] == ref['sha256']]
                        if len(matches) != 1 or matches[0]['size'] > 16 * 1024 * 1024: raise ValueError()
                        sizes.append(matches[0]['size'])
                    inputs = sum(sizes)
                except (KeyError, TypeError, ValueError):
                    if not terminal: unknown.append(key)
            if terminal:
                amount, reason = used + 65536, 'terminal_with_attempt_exit_proof'
            else:
                protected=True
                if old['state'] != 'valid': unknown.append(key)
                amount = max(reservations.get(key, 0), used + inputs + 2 * self.output_bytes + 2097152)
                reason = 'retain_active_or_unproven_reservation'
            proposed[key] = amount
            decisions.append({'key': key, 'previous': reservations.get(key), 'proposed': amount,
                'observed_bytes': used, 'reason': reason})
        # Unattributed transient/stage files are never silently omitted. Preserve
        # the previous catch-all floor while such bytes cannot be attributed.
        catchall = max(unassigned, reservations.get('__existing__', 0)) if unassigned or protected or discovery_unknown else 0
        proposed['__existing__'] = catchall
        value = {'version': 1, 'root': str(self.root), 'control': str(self.control),
            'output_bytes': self.output_bytes, 'ledger_before': old, 'files': entries,
            'api_states': states, 'execution_discovery':discovered,'discovery_unknown':discovery_unknown, 'decisions': decisions, 'unknown_attempts': sorted(set(unknown)),
            'outside_job_bytes': outside, 'unattributed_job_bytes': unassigned,
            'proposed_ledger': {'root': str(self.root), 'reservations': proposed},
            'applicable': not unknown and not discovery_unknown and not any(item.get('unscoped') for item in discovered)}
        value['plan_id'] = digest(canonical(value))
        return value, raw

    def preview(self):
        with self.locked():
            plan, _ = self._snapshot()
            # Detect namespace/files/API changes even during the preview itself.
            verified, _ = self._snapshot()
            if plan != verified: raise RebuildRefused('evidence changed during preview; retry after quiescing')
            return plan

    def apply(self, plan, confirmation):
        claimed = dict(plan); plan_id = claimed.pop('plan_id', None)
        if not plan_id or digest(canonical(claimed)) != plan_id or confirmation != plan_id:
            raise RebuildRefused('explicit matching plan confirmation required')
        with self.locked():
            current, original = self._snapshot()
            if current != plan: raise RebuildRefused('preview is stale; regenerate and review')
            if not current['applicable']: raise RebuildRefused('unknown task/attempt evidence; retain pending reservations')
            verified, _ = self._snapshot()
            if verified != current: raise RebuildRefused('evidence changed before apply')
            backup_root = self.control / 'capacity-backups'
            if backup_root.is_symlink(): raise RebuildRefused('symlinked backup directory')
            backup_root.mkdir(mode=0o700, exist_ok=True)
            backup = backup_root / (time.strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex)
            backup.mkdir(mode=0o700)
            if original is not None: atomic(backup / 'capacity.original', original)
            atomic(backup / 'preview.json', canonical(plan) + b'\n')
            atomic(backup / 'manifest.json', canonical({'original': current['ledger_before'],
                'plan_id': plan_id, 'root': str(self.root), 'control': str(self.control)}) + b'\n')
            sync_directory(backup_root);sync_directory(self.control)
            atomic(self.path, canonical(current['proposed_ledger']) + b'\n')
            return {'applied': True, 'plan_id': plan_id, 'backup': str(backup),
                'ledger_sha256': digest(self.path.read_bytes()), 'reservations': current['proposed_ledger']['reservations']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default=os.environ.get('CPAG_SHARED_ROOT'))
    parser.add_argument('--control', default=os.environ.get('CPAG_CONTROL_ROOT'))
    parser.add_argument('--api-url', default=os.environ.get('CPAG_API_URL'))
    parser.add_argument('--output-bytes', type=int, default=16777216)
    parser.add_argument('--report', required=True, help='new report path outside managed roots')
    parser.add_argument('--apply-plan', help='previous preview report; absence means preview only')
    parser.add_argument('--confirm', help='exact reviewed plan_id; mandatory for apply')
    args = parser.parse_args()
    if not all((args.root, args.control, args.api_url, os.environ.get('CPAG_WORKER_TOKEN'),os.environ.get('CPAG_COORDINATOR_TOKEN'))):
        parser.error('root/control/API URL and worker/coordinator credentials are required')
    tool = CapacityRebuilder(args.root, args.control, args.api_url, os.environ['CPAG_WORKER_TOKEN'], output_bytes=args.output_bytes,coordinator_token=os.environ['CPAG_COORDINATOR_TOKEN'])
    report_path=Path(args.report).absolute(); report_parent=report_path.parent.resolve(strict=True); report_path=report_parent/report_path.name
    if report_path.exists() or report_path.is_symlink() or any(report_path==r or report_path.is_relative_to(r) for r in (tool.root,tool.control)): raise RebuildRefused('unsafe or existing report destination')
    result = tool.apply(json.loads(Path(args.apply_plan).read_text()), args.confirm) if args.apply_plan else tool.preview()
    write_report(args.report, result, (tool.root, tool.control))
    print(json.dumps({'applied': result.get('applied', False), 'plan_id': result.get('plan_id'), 'report': str(Path(args.report).absolute())}))


if __name__ == '__main__':
    main()
