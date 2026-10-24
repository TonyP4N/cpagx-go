"""Explicit synthetic M1 execution bridge. Never invoked by legacy generation."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from datetime import datetime, timezone

from infrastructure.celery_app import celery_app
from infrastructure.status import read_manifest, write_manifest

BASE = Path(os.getenv('OUTPUT_DIR', 'outputs/v2')).resolve()
UPLOADS = Path(os.getenv('UPLOAD_DIR', 'uploads')).resolve() / 'synthetic'
ARTIFACTS = ('graph.json', 'events.json', 'dataset.json', 'quality.json', 'run_manifest.json')

def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def task_dir(task_id):
    import uuid
    try:
        if str(uuid.UUID(task_id)) != task_id:
            raise ValueError()
    except (ValueError, AttributeError):
        raise ValueError('Invalid task identifier')
    path = (BASE / task_id).resolve()
    if path.parent != BASE:
        raise ValueError('Invalid task path')
    return path

def artifact_path(task_id, filename):
    directory = task_dir(task_id)
    if Path(filename).name != filename:
        raise ValueError('Invalid artifact name')
    manifest = read_manifest(str(BASE), task_id) or {}
    if filename not in manifest.get('files', []):
        raise FileNotFoundError(filename)
    path = (directory / filename).resolve()
    if not path.is_relative_to(directory) or not path.is_file():
        raise FileNotFoundError(filename)
    return path

def retain_sources(directory, staging):
    """Reserve original evidence once; never replace a prior attempt's inputs."""
    sources = directory / 'sources'
    sources.mkdir(exist_ok=False)
    records = []
    for filename in ('network.jsonl', 'process.csv', 'profile.json'):
        target = sources / filename
        with (staging / filename).open('rb') as original, target.open('xb') as retained:
            shutil.copyfileobj(original, retained)
        target.chmod(0o444)
        records.append({'path': 'sources/' + filename,
                        'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                        'size_bytes': target.stat().st_size})
    sources.chmod(0o555)
    return sources, records

def verify_completed(task_id, manifest):
    """A repeated delivery may reuse only a complete checksum-verified publication."""
    directory = task_dir(task_id)
    if set(manifest.get('files', [])) != set(ARTIFACTS):
        raise ValueError('Completed task has incomplete artifacts')
    raw = artifact_path(task_id, 'run_manifest.json').read_bytes()
    expected = manifest.get('run_manifest_sha256')
    if expected:
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Completed run manifest checksum mismatch')
    elif raw != (directory/'core'/'run_manifest.json').read_bytes():
        raise ValueError('Completed run manifest differs from original export')
    for entry in manifest.get('retained_inputs', []):
        path = (directory / entry['path']).resolve()
        if path.parent != (directory/'sources').resolve() or not path.is_file():
            raise ValueError('Retained source path is invalid')
        if path.stat().st_size != entry['size_bytes'] or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('Retained source checksum mismatch')
    result = json.loads(raw)
    if result.get('synthetic') is not True or result.get('status') not in ('succeeded', 'succeeded_with_warnings'):
        raise ValueError('Invalid completed synthetic run manifest')
    if {entry['path'] for entry in result['artifacts']} != set(ARTIFACTS) - {'run_manifest.json'}:
        raise ValueError('Completed artifact manifest is incomplete')
    for entry in result['artifacts']:
        path = artifact_path(task_id, entry['path'])
        if path.stat().st_size != entry['size_bytes'] or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('Completed artifact checksum mismatch')
    return manifest

@celery_app.task(bind=True, name='api.v2.synthetic.execute_synthetic', soft_time_limit=300, time_limit=360)
def execute_synthetic(self, task_id):
    directory = task_dir(task_id)
    staging = (UPLOADS / task_id).resolve()
    if staging.parent != UPLOADS:
        raise ValueError('Invalid upload path')
    manifest = read_manifest(str(BASE), task_id)
    if not manifest or manifest.get('synthetic') is not True:
        raise ValueError('Missing explicit synthetic task manifest')
    if manifest.get('status') == 'completed':
        return verify_completed(task_id, manifest)
    import redis
    from celery.exceptions import Ignore
    from core.config import get_config
    from infrastructure.slots import acquire, DuplicateActive
    client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
    try:
        acquire(client, task_id, get_config().max_concurrent_tasks_v2)
    except DuplicateActive:
        # Do not write task state or remove files owned by the running delivery.
        raise Ignore()
    except Exception as exc:
        manifest.update(status='failed', error=str(exc), files=[], failed_at=now())
        write_manifest(str(BASE), task_id, manifest)
        shutil.rmtree(staging, ignore_errors=True)
        raise
    try:
        # Another delivery could have completed between our initial read and admission.
        manifest = read_manifest(str(BASE), task_id)
        if manifest.get('status') == 'completed':
            return verify_completed(task_id, manifest)
        manifest.update(status='processing')
        write_manifest(str(BASE), task_id, manifest)
        self.update_state(state='PROGRESS', meta={'status': 'processing', 'synthetic': True})
        # Locate the same standalone core without adding service dependencies to it.
        source = Path(__file__).resolve().parents[3] / 'analysis' / 'src'
        if str(source) not in sys.path:
            sys.path.insert(0, str(source))
        from cpag_core.pipeline import run, file_hash
        sources, retained_inputs = retain_sources(directory, staging)
        manifest['retained_inputs'] = retained_inputs
        write_manifest(str(BASE), task_id, manifest)
        result = run(sources/'network.jsonl', sources/'process.csv', sources/'profile.json',
                     directory/'core', synthetic=True,
                     source='user-confirmed synthetic HTTP upload', authorization_ref='synthetic_confirmed=true')
        for artifact in result['artifacts']:
            path = directory/'core'/artifact['path']
            if path.stat().st_size != artifact['size_bytes'] or file_hash(path) != artifact['sha256']:
                raise ValueError('Core artifact integrity verification failed')
        # Publish only completed, verified exports, preserving the original core manifest.
        for filename in ARTIFACTS:
            shutil.copyfile(directory/'core'/filename, directory/filename)
        manifest.update(status='completed', core_status=result['status'], files=list(ARTIFACTS),
                        completed_at=now(), warnings=result['warnings'],
                        run_manifest_sha256=file_hash(directory/'run_manifest.json'))
        write_manifest(str(BASE), task_id, manifest)
        return manifest
    except Exception as exc:
        if manifest.get('status') == 'completed':
            raise
        manifest.update(status='failed', error=str(exc), files=[], failed_at=now())
        write_manifest(str(BASE), task_id, manifest)
        raise
    finally:
        try:
            client.srem('v2_active_tasks', task_id)
        except Exception:
            pass
        shutil.rmtree(staging, ignore_errors=True)


def register(app):
    from fastapi import File, Form, UploadFile, HTTPException
    # Explicit annotations resolve in module globals for FastAPI introspection.
    globals()['UploadFile'] = UploadFile

    @app.post('/cpag/synthetic', status_code=202)
    async def submit(network_file: UploadFile = File(...), process_file: UploadFile = File(...),
                     profile_file: UploadFile = File(...), synthetic_confirmed: bool = Form(False)):
        import uuid
        if synthetic_confirmed is not True:
            raise HTTPException(400, 'Explicit synthetic_confirmed=true is required')
        identifier = str(uuid.uuid4())
        staging = UPLOADS / identifier
        staging.mkdir(parents=True, exist_ok=False)
        try:
            for upload, filename, extension in [(network_file, 'network.jsonl', '.jsonl'),
                    (process_file, 'process.csv', '.csv'), (profile_file, 'profile.json', '.json')]:
                if Path(upload.filename or '').suffix.lower() != extension:
                    raise HTTPException(400, 'Expected '+extension+' upload')
                size = 0
                with (staging/filename).open('xb') as output:
                    while chunk := await upload.read(1024*1024):
                        size += len(chunk)
                        if size > 16*1024*1024:
                            raise HTTPException(413, 'Synthetic input exceeds 16 MiB per file')
                        output.write(chunk)
                if not size:
                    raise HTTPException(400, 'Empty synthetic input')
            profile = json.loads((staging/'profile.json').read_text())
            if not isinstance(profile, dict) or profile.get('synthetic') is not True:
                raise HTTPException(400, 'Profile must declare synthetic=true')
            manifest = dict(task_id=identifier, id=identifier, status='queued', synthetic=True,
                            version='v2', created_at=now(), files=[], file_name='synthetic inputs')
            write_manifest(str(BASE), identifier, manifest)
            try:
                celery_app.send_task('api.v2.synthetic.execute_synthetic', args=[identifier],
                                     task_id=identifier, queue='cpag_generation', retry=False)
            except Exception as exc:
                manifest.update(status='failed', error='Task queue service unavailable')
                write_manifest(str(BASE), identifier, manifest)
                raise HTTPException(503, 'Task queue service unavailable') from exc
            return manifest
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise HTTPException(400, 'Invalid profile JSON') from exc
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    @app.get('/cpag/artifacts/{task_id}')
    async def artifacts(task_id: str):
        try:
            task_dir(task_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        manifest = read_manifest(str(BASE), task_id)
        if not manifest:
            raise HTTPException(404, 'Task not found')
        result = dict(manifest)
        result['files'] = [{'filename': name, 'download_url': f'/cpag/download/{task_id}/{name}'} for name in manifest.get('files', [])]
        if manifest.get('synthetic') and manifest.get('status') == 'completed':
            result['run_manifest'] = json.loads(artifact_path(task_id, 'run_manifest.json').read_text())
        return result
