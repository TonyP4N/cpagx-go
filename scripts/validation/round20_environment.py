#!/usr/bin/env python3
"""Retain an isolated ordinary Go/PG/Worker UI restored from passed R19 backup.

No analysis recomputation. Credentials/configuration stay in private state. The
accepted source bundle is read only. Stop with SIGTERM; evidence is retained.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time

import round19_formal_service_acceptance as formal

r = formal.r


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, work = args.source.resolve(), args.output.resolve()
    work.mkdir(parents=True, exist_ok=False, mode=0o700)
    old = json.loads((source / 'state.json').read_text())
    prior = json.loads((source / 'app-restored-config.json').read_text())
    pg = 'cpag-r20-ui-' + secrets.token_hex(5)
    pg_port, public, internal = r.port(), r.port(), r.port()
    app = worker = None
    report = {'status': 'starting', 'scope': 'restored synthetic software UI only',
              'source_bundle_sha256': formal.sha(source / 'bundle/bundle.json'),
              'recomputed_runs': 0, 'pg_container': pg}
    def flush():
        formal.write(work / 'environment-report.json', report)
    flush()
    r.run('docker', 'run', '--name', pg, '-d', '-e', 'POSTGRES_DB=m4_validation',
          '-e', 'POSTGRES_PASSWORD=m4-disposable-only', '-p', f'127.0.0.1:{pg_port}:5432',
          r.PG_IMAGE, stdout=subprocess.DEVNULL)
    try:
        for _ in range(150):
            if subprocess.run(['docker', 'exec', pg, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'm4_validation'], capture_output=True).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('postgres_readiness_timeout')
        root, control = work / 'source', work / 'control'
        restored = r.bundle.restore(pg, source / 'bundle', root, control_destination=control)
        if not restored.get('valid'):
            raise RuntimeError('accepted_backup_restore_failed')
        formal.write(work / 'restore-result.json', restored)
        binary = work / 'cpagx-v3'
        shutil.copy2(source / 'cpagx-v3', binary)
        config = dict(prior, database_url=f'postgres://postgres:m4-disposable-only@127.0.0.1:{pg_port}/m4_restore_validation?sslmode=disable',
                      shared_root=str(root), control_root=str(control), public_addr=f'127.0.0.1:{public}',
                      internal_addr=f'127.0.0.1:{internal}', worker_token=secrets.token_urlsafe(32),
                      coordinator_token=secrets.token_urlsafe(32), static_root=str(r.REPO / 'webui/out'))
        app = r.start_app(work, 'app', binary, config)
        worker_config = {'api_url':f'http://127.0.0.1:{internal}', 'shared_root':str(root),
                         'control_root':str(control), 'worker_token':config['worker_token'],
                         'coordinator_token':config['coordinator_token'], 'worker_id':'r20-ui-worker',
                         'image':prior['compact_verifier_image'], 'poll_seconds':.2, 'recovery_seconds':2,
                         'resource_profile':'storage-budget-2'}
        r.write_private(work / 'worker-config.json', worker_config)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(r.REPO / 'services/worker'), str(r.REPO / 'services/analysis/src')]), NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
        worker = r.start_worker(work, 'worker', work / 'worker-config.json', env)
        state = {k:v for k,v in old.items() if k not in ('app_pid', 'worker_pid', 'harness_pid', 'restored_url', 'source_root', 'restored_root', 'control_root', 'original_control_root', 'pg_container', 'internal_url', 'url')}
        state.update(url=f'http://127.0.0.1:{public}', internal_url=f'http://127.0.0.1:{internal}',
                     source_root=str(root), control_root=str(control), pg_container=pg,
                     fixture_dir=str(source / 'fixture-offline'), restored_url=f'http://127.0.0.1:{public}',
                     app_pid=app.pid, worker_pid=worker.pid, harness_pid=os.getpid())
        r.write_private(work / 'state.json', state)
        report.update(status='ready', url=state['url'], state_path=str(work / 'state.json'),
                      restored_runs=state['run_ids'], binary_sha256=formal.sha(binary))
        flush()
        print(json.dumps({k:report[k] for k in ('status', 'url', 'state_path')}), flush=True)
        halt = False
        def stop(*_):
            nonlocal halt
            halt = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not halt:
            if app.poll() is not None or worker.poll() is not None:
                raise RuntimeError('isolated_service_exited')
            time.sleep(.5)
    except BaseException as error:
        report.update(status='failed', reason=str(error))
        flush()
        raise
    finally:
        r.stop(worker)
        r.stop(app)
        with (work / 'database.sql').open('wb') as stream:
            subprocess.run(['docker', 'exec', pg, 'pg_dump', '-U', 'postgres', 'm4_restore_validation'], stdout=stream, stderr=subprocess.PIPE)
        subprocess.run(['docker', 'stop', pg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report['retained_stopped_database'] = pg
        flush()


if __name__ == '__main__':
    main()
