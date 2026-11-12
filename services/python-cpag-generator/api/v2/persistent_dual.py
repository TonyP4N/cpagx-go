"""Explicit local-only bridge to the persistent dual-source queue.

Credentials remain server-side. Enable only alongside the opt-in M4 API and
shared storage; no Celery route or default is replaced.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response

FILES = ('graph.json', 'events.json', 'dataset.json', 'quality.json', 'analysis.json', 'run_manifest.json')
IDENTITY = re.compile(r'^[A-Za-z0-9_-]{1,100}$')


def _core():
    source = Path(__file__).resolve().parents[3] / "analysis" / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    from cpag_core import dual_source_export
    return dual_source_export


def settings():
    if os.getenv('CPAG_PERSISTENT_ENABLED') != '1':
        raise HTTPException(503, 'Persistent dual-source entry is not enabled')
    base = os.environ.get('CPAG_PERSISTENT_API_URL', '')
    root = Path(os.environ.get('CPAG_PERSISTENT_ROOT', '/nonexistent')).resolve()
    token = os.environ.get('CPAG_PERSISTENT_TOKEN', '')
    try:
        parsed = urlsplit(base)
        local = (parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
                 and parsed.port is not None and parsed.username is None and parsed.password is None
                 and parsed.path in ('', '/') and not parsed.query and not parsed.fragment)
    except ValueError:
        local = False
    if not local or not root.is_dir() or len(token) < 24:
        raise HTTPException(503, 'Persistent local API/storage configuration is incomplete')
    return base.rstrip('/'), root, token


def call(path, body=None):
    base, _, token = settings()
    req = Request(base + path, data=None if body is None else json.dumps(body).encode(),
                  headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with urlopen(req, timeout=30) as response:
            return json.load(response)
    except HTTPError as exc:
        raw = exc.read().decode(errors='replace')
        raise HTTPException(exc.code, raw) from exc
    except (URLError, TimeoutError) as exc:
        raise HTTPException(503, 'Persistent API unavailable; retry without changing task identity') from exc


def job(task_id):
    if not IDENTITY.fullmatch(task_id):
        raise HTTPException(400, 'Invalid task identity')
    value = call('/v1/jobs/' + task_id)
    if value.get('payload', {}).get('kind') != 'dual-source':
        raise HTTPException(409, 'Not a persistent dual-source task')
    return value


def state(value):
    return {**value, 'task_id': value['id'], 'status': 'completed' if value['state'] == 'succeeded' else value['state'],
            'task_kind': 'synthetic_dual_source', 'executor': 'persistent',
            'error': value.get('last_error') or value.get('recovery_reason')}


def published(task_id):
    value = job(task_id)
    if value['state'] != 'succeeded':
        raise HTTPException(409, 'Task has no trusted completed publication')
    # The authoritative API validates DB publication identity and every file.
    output = call('/v1/jobs/' + task_id + '/dual-result')
    _, root, _ = settings()
    rel = value.get('artifact_path')
    if not isinstance(rel, str):
        raise HTTPException(409, 'Publication path missing')
    path = root / rel
    if path.resolve() != path or not path.is_relative_to(root):
        raise HTTPException(409, 'Unsafe publication path')
    try:
        _core().verify_task(path.parent)
    except (ValueError, OSError, KeyError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return output, path.parent


router = APIRouter(prefix='/cpag/persistent')


@router.post('/dual-source', status_code=202)
async def submit(network_file: UploadFile = File(...), process_file: UploadFile = File(...),
                 profile_file: UploadFile = File(...), synthetic_confirmed: bool = Form(False)):
    _, root, _ = settings()
    if not synthetic_confirmed:
        raise HTTPException(400, 'Explicit synthetic confirmation required')
    task_id = 'dual-' + uuid.uuid4().hex
    staging = root / 'inputs' / ('upload-' + task_id)
    staging.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        refs = {}
        for kind, upload, name, limit in (
            ('network', network_file, 'network.pcap', 16 << 20),
            ('process', process_file, 'process.csv', 2 << 20),
            ('profile', profile_file, 'profile.json', 64 << 10)):
            data = await upload.read(limit + 1)
            if not data or len(data) > limit:
                raise HTTPException(400, kind + ' input is empty or exceeds bound')
            target = staging / name
            target.write_bytes(data)
            refs[kind] = {'path': str(target.relative_to(root)), 'sha256': hashlib.sha256(data).hexdigest()}
        core = _core()
        profile = core.strict_json((staging / 'profile.json').read_text())
        core.validate('DualSourceProfile', profile)
        if profile.get('synthetic') is not True:
            raise HTTPException(400, 'Profile must declare synthetic=true')
        payload = dict(kind='dual-source', **refs, config_fingerprint=core.fingerprint(profile))
        created = call('/v1/jobs', {'id': task_id, 'max_attempts': 3, 'payload': payload})
        return {'task_id': created['id'], 'status': 'queued', 'executor': 'persistent'}
    except (ValueError, KeyError) as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        # API copies immutable inputs before acknowledging enqueue.
        shutil.rmtree(staging)


@router.get('/status/{task_id}')
def status(task_id: str):
    return state(job(task_id))


@router.post('/cancel/{task_id}')
def cancel(task_id: str):
    job(task_id)
    call('/v1/jobs/' + task_id + '/cancel', {})
    return state(job(task_id))


@router.get('/result/{task_id}/json')
def result(task_id: str):
    output, _ = published(task_id)
    return {**output, 'task_id': task_id, 'status': 'completed', 'task_kind': 'synthetic_dual_source'}


@router.get('/artifacts/{task_id}')
def artifacts(task_id: str):
    _, directory = published(task_id)
    return {'files': [{'filename': name, 'size_bytes': (directory/name).stat().st_size} for name in FILES]}


@router.get('/download/{task_id}/{filename}')
def download(task_id: str, filename: str):
    if filename not in FILES:
        raise HTTPException(404, 'Artifact not allowed')
    _, directory = published(task_id)
    data = (directory / filename).read_bytes()
    # Revalidate after copying bytes to close ordinary write/read races.
    published(task_id)
    return Response(data, media_type='application/json', headers={'Content-Disposition': 'attachment; filename="' + filename + '"'})


@router.get('/dual-source/{task_id}/evidence')
def evidence(task_id: str, operation: str = '', change: str = ''):
    if bool(operation) == bool(change):
        raise HTTPException(400, 'Select exactly one operation or change')
    _, directory = published(task_id)
    try:
        # Same evidence resolver as Celery, after PostgreSQL publication verification.
        return _core().query_task(directory, operation_id=operation or None, change_id=change or None)
    except KeyError as exc:
        raise HTTPException(404, 'Unknown operation or change') from exc
    except (ValueError, OSError, TypeError) as exc:
        raise HTTPException(409, str(exc)) from exc



def register(app):
    app.include_router(router)
