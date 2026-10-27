"""Independent R16 review: disposable PostgreSQL + unmodified public Go API.

Creates only its own container and temporary files, and cleans up its processes.
No Worker is started; accepted probe jobs are cancelled before backup.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'scripts/validation'), str(REPO / 'scripts/backup'),
               str(REPO / 'services/analysis/src')]
import round16_acceptance as r16
import bundle


def main():
    report = {'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(),
              'scope': 'disposable database, genuine Go public API, synthetic fixture; no worker execution claimed'}
    with tempfile.TemporaryDirectory(prefix='cpag-r16-review-') as temp:
        work = Path(temp)
        root = work / 'shared'; root.mkdir()
        control = work / 'control'; control.mkdir()
        network, process, dual = r16.make_case(work / 'fixture', 'success')
        container = 'cpag-r16-review-' + secrets.token_hex(5)
        pgport, public, internal = [r16.port() for _ in range(3)]
        app = None
        created = False
        binary = work / 'cpagx-v3'
        env = dict(os.environ, GOCACHE='/tmp/cpag-review-go-cache', GOMODCACHE='/tmp/cpag-go-mod')
        try:
            subprocess.run(['go', 'build', '-o', str(binary), './cmd/cpagx-v3'],
                           cwd=REPO / 'internal/jobs/integration', env=env, check=True)
            subprocess.run(['docker', 'run', '--name', container, '-d', '-e', 'POSTGRES_DB=m4_validation',
                            '-e', 'POSTGRES_PASSWORD=m4-disposable-only', '-p', f'127.0.0.1:{pgport}:5432',
                            r16.PG_IMAGE], check=True, stdout=subprocess.DEVNULL)
            created = True
            for _ in range(100):
                ready = subprocess.run(['docker', 'exec', container, 'pg_isready', '-h', '127.0.0.1',
                                        '-U', 'postgres', '-d', 'm4_validation'], capture_output=True)
                if ready.returncode == 0:
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('isolated PostgreSQL did not become ready')
            for migration in sorted((REPO / 'internal/jobs/migrations').glob('*.sql')):
                with migration.open('rb') as source:
                    bundle.pg(container, 'm4_validation', 'psql', '-v', 'ON_ERROR_STOP=1',
                              stdin=source, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            username, password = 'review-admin', secrets.token_urlsafe(24)
            config = r16.make_config(pgport, 'm4_validation', root, control, public, internal,
                                    secrets.token_urlsafe(32), secrets.token_urlsafe(32),
                                    username, password, REPO / 'webui/out')
            app = r16.start_app(work, 'app-1', binary, config)
            client = r16.Client(f'http://127.0.0.1:{public}')
            client.expect('POST', '/api/v3/session', {'username': username, 'password': password})
            dataset = client.expect('POST', '/api/v3/datasets', {
                'name': 'single source then complete pair', 'source_kind': 'synthetic',
                'source': 'generated test', 'batch': 'review-only', 'authorization_ref': 'synthetic fixture'}, code=201)['dataset']['id']
            r16.upload(client, dataset, 'network', network, 'review-network-1')
            intake = {'dataset_id': dataset, 'synthetic': True,
                      'authorization': {'allowed_use': 'synthetic test', 'evidence_ref': 'fixture', 'reviewer': 'review'},
                      'time_basis': {'timezone': 'UTC', 'precision': 'fixture ticks', 'synchronization': 'declared', 'evidence_ref': 'fixture'},
                      'mapping': {'field_units_ref': 'fixture', 'device_map_ref': 'fixture', 'effective_period_ref': 'fixture'}}
            cid = client.expect('POST', f'/api/v3/datasets/{dataset}/configs',
                                {'kind': 'intake', 'document': intake}, code=201)['config']['id']
            first = client.expect('POST', f'/api/v3/datasets/{dataset}/preflight', {'config_version_id': cid})
            report['single_source_preflight_status'] = first['report']['status']
            r16.stop(app); app = None
            before = bundle.backup(container, 'm4_validation', root, work / 'before-backup')
            report['backup_before_append_valid'] = before['catalog_audit']['valid']
            app = r16.start_app(work, 'app-2', binary, config)
            r16.upload(client, dataset, 'process', process, 'review-process-1')
            second = client.expect('POST', f'/api/v3/datasets/{dataset}/preflight', {'config_version_id': cid})
            report['dual_source_preflight_status'] = second['report']['status']
            r16.stop(app); app = None
            try:
                bundle.backup(container, 'm4_validation', root, work / 'after-backup')
                report['backup_after_append_valid'] = True
            except ValueError as exc:
                report['backup_after_append_valid'] = False
                report['backup_after_append_error'] = str(exc)
            app = r16.start_app(work, 'app-3', binary, config)
            missing = client.expect('POST', '/api/v3/datasets', {
                'name': 'missing provenance', 'source_kind': 'synthetic',
                'source': '', 'batch': '', 'authorization_ref': ''}, code=201)['dataset']['id']
            r16.upload(client, missing, 'network', network, 'review-network-2')
            r16.upload(client, missing, 'process', process, 'review-process-2')
            incomplete = client.expect('POST', f'/api/v3/datasets/{missing}/configs',
                                       {'kind': 'intake', 'document': {'dataset_id': missing, 'synthetic': True}}, code=201)['config']['id']
            missing_report = client.expect('POST', f'/api/v3/datasets/{missing}/preflight',
                                           {'config_version_id': incomplete})['report']
            report['missing_provenance_preflight_status'] = missing_report['status']
            report['missing_provenance_gaps'] = missing_report['material_gaps']
            cfg = client.expect('POST', f'/api/v3/datasets/{missing}/configs',
                                {'kind': 'dual', 'document': json.loads(Path(dual).read_text())}, code=201)['config']['id']
            status, result = client.request('POST', '/api/v3/runs',
                                            {'dataset_id': missing, 'config_version_id': cfg, 'mode': 'dual_source'})
            report['missing_provenance_run_status'] = status
            report['missing_provenance_run_state'] = result.get('run', {}).get('state')
            if status == 201:
                client.expect('POST', '/api/v3/runs/' + result['run']['id'] + '/cancel', {})
            status, result = client.request('POST', '/api/v3/datasets', {'name': 'invalid origin', 'source_kind': 'invalid'})
            report['invalid_source_kind_status'] = status
            report['invalid_source_kind_error'] = result.get('error', {}).get('code')
        finally:
            r16.stop(app)
            if created:
                subprocess.run(['docker', 'rm', '-f', container], check=True, stdout=subprocess.DEVNULL)
    destination = Path(os.environ.get('CPAG_REVIEW_RESULT', str(Path(tempfile.gettempdir()) / 'cpag-r16-review-results.json')))
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
