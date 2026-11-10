"""Explicit, queued synthetic PCAP and process-data analysis."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

from infrastructure.celery_app import celery_app
from infrastructure.status import read_manifest, write_manifest
from .synthetic import BASE, now, task_dir, artifact_path


UPLOADS = Path(os.getenv('UPLOAD_DIR', 'uploads')).resolve() / 'dual-source'
ARTIFACTS = ('graph.json', 'events.json', 'dataset.json', 'quality.json',
             'analysis.json', 'run_manifest.json')
TASK_KIND = 'synthetic_dual_source'
TASK_NAME = 'api.v2.dual_source.execute_dual_source'


def _core():
    source = Path(__file__).resolve().parents[3] / 'analysis' / 'src'
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    from cpag_core import dual_source_export
    return dual_source_export


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _source_path(directory, entry):
    source_dir = (directory / 'sources').resolve()
    path = directory / entry['path']
    if path.is_symlink():
        raise ValueError('Retained source is a symlink')
    path = path.resolve()
    if path.parent != source_dir or not path.is_file():
        raise ValueError('Retained source path is invalid')
    return path


def verify_completed(task_id, manifest):
    """Validate all published files and the original core source chain."""
    if manifest.get('task_kind') != TASK_KIND or manifest.get('status') != 'completed':
        raise ValueError('Dual-source publication is not completed')
    if set(manifest.get('files', [])) != set(ARTIFACTS):
        raise ValueError('Completed task has incomplete artifacts')
    directory = task_dir(task_id)
    if (directory / 'sources').is_symlink():
        raise ValueError('Retained source directory is a symlink')
    records = manifest.get('retained_inputs')
    network_name = manifest.get('network_name')
    if network_name not in ('network.pcap', 'network.pcapng'):
        raise ValueError('Invalid network source name')
    if (not isinstance(records, list) or len(records) != 3 or
            {entry.get('path') for entry in records if isinstance(entry, dict)} !=
            {f'sources/{network_name}', 'sources/process.csv', 'sources/profile.json'}):
        raise ValueError('Completed task has incomplete source records')
    for entry in records:
        path = _source_path(directory, entry)
        if path.stat().st_size != entry['size_bytes'] or _hash(path) != entry['sha256']:
            raise ValueError('Retained source checksum mismatch')
    if (directory / 'run_manifest.json').is_symlink():
        raise ValueError('Published artifact is a symlink')
    run_path = artifact_path(task_id, 'run_manifest.json')
    if _hash(run_path) != manifest.get('run_manifest_sha256'):
        raise ValueError('Completed run manifest checksum mismatch')
    core_dir = directory / 'core'
    if run_path.read_bytes() != (core_dir / 'run_manifest.json').read_bytes():
        raise ValueError('Published run manifest differs from core export')
    run = json.loads(run_path.read_text())
    if run.get('synthetic') is not True or run.get('status') not in ('succeeded', 'succeeded_with_warnings'):
        raise ValueError('Invalid synthetic dual-source run manifest')
    records_by_name = {entry['path']: entry for entry in run['artifacts']}
    if not set(ARTIFACTS).difference({'run_manifest.json'}).issubset(records_by_name):
        raise ValueError('Completed artifact manifest is incomplete')
    for filename in set(ARTIFACTS) - {'run_manifest.json'}:
        entry = records_by_name[filename]
        if (directory / filename).is_symlink():
            raise ValueError('Published artifact is a symlink')
        published = artifact_path(task_id, filename)
        original = core_dir / filename
        if (published.stat().st_size != entry['size_bytes'] or
                _hash(published) != entry['sha256'] or
                published.read_bytes() != original.read_bytes()):
            raise ValueError('Completed artifact checksum mismatch')
    _core().verify_task(core_dir)
    for service_name, core_name in ((network_name, 'network.pcap'),
                                    ('process.csv', 'process.csv'),
                                    ('profile.json', 'profile.json')):
        if (directory / 'sources' / service_name).read_bytes() != (core_dir / 'dual' / 'sources' / core_name).read_bytes():
            raise ValueError('Retained source differs from core input')
    return manifest


def verify_http_publication(task_id, manifest):
    from fastapi import HTTPException
    try:
        verify_completed(task_id, manifest)
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
        raise HTTPException(409, 'Dual-source publication integrity verification failed')


def _retain_sources(directory, staging, network_name):
    source_dir = directory / 'sources'
    source_dir.mkdir(exist_ok=False)
    records = []
    for name in (network_name, 'process.csv', 'profile.json'):
        target = source_dir / name
        with (staging / name).open('rb') as original, target.open('xb') as retained:
            shutil.copyfileobj(original, retained)
        target.chmod(0o444)
        records.append({'path': f'sources/{name}', 'sha256': _hash(target),
                        'size_bytes': target.stat().st_size})
    source_dir.chmod(0o555)
    return source_dir, records


@celery_app.task(bind=True, name=TASK_NAME, soft_time_limit=300, time_limit=360)
def execute_dual_source(self, task_id):
    directory = task_dir(task_id)
    staging = (UPLOADS / task_id).resolve()
    if staging.parent != UPLOADS:
        raise ValueError('Invalid upload path')
    manifest = read_manifest(str(BASE), task_id)
    if not manifest or manifest.get('task_kind') != TASK_KIND or manifest.get('synthetic') is not True:
        raise ValueError('Missing explicit dual-source task manifest')
    if manifest.get('status') == 'completed':
        return verify_completed(task_id, manifest)
    if manifest.get('status') == 'failed':
        raise ValueError('Failed dual-source task cannot be replayed')

    import redis
    from celery.exceptions import Ignore
    from core.config import get_config
    from infrastructure.slots import acquire, DuplicateActive
    client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
    admitted = False
    try:
        acquire(client, task_id, get_config().max_concurrent_tasks_v2)
        admitted = True
    except DuplicateActive:
        raise Ignore()
    except Exception as exc:
        manifest.update(status='failed', error=str(exc), files=[], failed_at=now())
        write_manifest(str(BASE), task_id, manifest)
        shutil.rmtree(staging, ignore_errors=True)
        raise
    try:
        manifest = read_manifest(str(BASE), task_id)
        if manifest.get('status') == 'completed':
            return verify_completed(task_id, manifest)
        if manifest.get('status') == 'failed':
            raise ValueError('Failed dual-source task cannot be replayed')
        manifest['status'] = 'processing'
        write_manifest(str(BASE), task_id, manifest)
        self.update_state(state='PROGRESS', meta={'status': 'processing', 'synthetic': True})

        network_name = manifest['network_name']
        sources, records = _retain_sources(directory, staging, network_name)
        manifest['retained_inputs'] = records
        write_manifest(str(BASE), task_id, manifest)
        core_dir = directory / 'core'
        result = _core().export_task(sources / network_name, sources / 'process.csv',
                                     sources / 'profile.json', core_dir)
        _core().verify_task(core_dir)
        for filename in ARTIFACTS:
            shutil.copyfile(core_dir / filename, directory / filename)
            if (directory / filename).read_bytes() != (core_dir / filename).read_bytes():
                raise ValueError('Published artifact copy differs from core export')
        # The complete source chain and every copy must pass before success is recorded.
        _core().verify_task(core_dir)
        for service_name, core_name in ((network_name, 'network.pcap'),
                                        ('process.csv', 'process.csv'),
                                        ('profile.json', 'profile.json')):
            if (sources / service_name).read_bytes() != (core_dir / 'dual' / 'sources' / core_name).read_bytes():
                raise ValueError('Retained source differs from core input')
        manifest.update(status='completed', core_status=result['status'],
                        files=list(ARTIFACTS), completed_at=now(),
                        warnings=result.get('warnings', []),
                        run_manifest_sha256=_hash(directory / 'run_manifest.json'))
        write_manifest(str(BASE), task_id, manifest)
        return manifest
    except Exception as exc:
        # A repeated delivery must never rewrite a terminal publication.
        if manifest.get('status') != 'completed':
            manifest.update(status='failed', error=str(exc), files=[], failed_at=now())
            write_manifest(str(BASE), task_id, manifest)
        raise
    finally:
        if admitted:
            try:
                client.srem('v2_active_tasks', task_id)
            except Exception:
                pass
        shutil.rmtree(staging, ignore_errors=True)


def register(app):
    from fastapi import File, Form, UploadFile, HTTPException
    globals()['UploadFile'] = UploadFile

    @app.post('/cpag/dual-source', status_code=202)
    async def submit(network_file: UploadFile = File(...), process_file: UploadFile = File(...),
                     profile_file: UploadFile = File(...), synthetic_confirmed: bool = Form(False)):
        if synthetic_confirmed is not True:
            raise HTTPException(400, 'Explicit synthetic_confirmed=true is required')
        network_extension = Path(network_file.filename or '').suffix.lower()
        if network_extension not in ('.pcap', '.pcapng'):
            raise HTTPException(400, 'Expected .pcap or .pcapng network upload')
        if Path(process_file.filename or '').suffix.lower() != '.csv':
            raise HTTPException(400, 'Expected .csv process upload')
        if Path(profile_file.filename or '').suffix.lower() != '.json':
            raise HTTPException(400, 'Expected .json profile upload')
        task_id = str(uuid.uuid4())
        staging = UPLOADS / task_id
        staging.mkdir(parents=True, exist_ok=False)
        network_name = 'network' + network_extension
        try:
            for upload, filename in ((network_file, network_name),
                                     (process_file, 'process.csv'),
                                     (profile_file, 'profile.json')):
                size = 0
                with (staging / filename).open('xb') as output:
                    while chunk := await upload.read(1024 * 1024):
                        size += len(chunk)
                        if size > 16 * 1024 * 1024:
                            raise HTTPException(413, 'Dual-source input exceeds 16 MiB per file')
                        output.write(chunk)
                if not size:
                    raise HTTPException(400, 'Empty dual-source input')
            profile = json.loads((staging / 'profile.json').read_text())
            if not isinstance(profile, dict) or profile.get('synthetic') is not True:
                raise HTTPException(400, 'Profile must declare synthetic=true')
            manifest = {'task_id': task_id, 'id': task_id, 'status': 'queued',
                        'task_kind': TASK_KIND, 'synthetic': True, 'version': 'v2',
                        'created_at': now(), 'files': [], 'file_name': 'synthetic dual-source inputs',
                        'network_name': network_name}
            write_manifest(str(BASE), task_id, manifest)
            try:
                celery_app.send_task(TASK_NAME, args=[task_id], task_id=task_id,
                                     queue='cpag_generation', retry=False)
            except Exception as exc:
                manifest.update(status='failed', error='Task queue service unavailable', failed_at=now())
                write_manifest(str(BASE), task_id, manifest)
                raise HTTPException(503, 'Task queue service unavailable') from exc
            return manifest
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(400, 'Invalid profile JSON') from exc
        finally:
            if not read_manifest(str(BASE), task_id) or read_manifest(str(BASE), task_id).get('status') == 'failed':
                shutil.rmtree(staging, ignore_errors=True)

    @app.get('/cpag/dual-source/{task_id}/evidence')
    async def evidence(task_id: str, operation: str = None, change: str = None):
        try:
            task_dir(task_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        if bool(operation) == bool(change):
            raise HTTPException(400, 'Specify exactly one operation or change identifier')
        manifest = read_manifest(str(BASE), task_id)
        if not manifest or manifest.get('task_kind') != TASK_KIND:
            raise HTTPException(404, 'Dual-source task not found')
        verify_http_publication(task_id, manifest)
        try:
            return _core().query_task(task_dir(task_id) / 'core', operation_id=operation,
                                      change_id=change)
        except KeyError:
            raise HTTPException(404, 'Evidence identifier not found')
        except (ValueError, OSError, TypeError):
            raise HTTPException(409, 'Dual-source evidence integrity verification failed')
