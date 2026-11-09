#!/usr/bin/env python3
"""Disposable native Linux k3s acceptance; never contacts EU or external data."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import threading

REPO = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OUT = REPO/'outputs/resident-native'
K = ['docker', 'exec', '-i', 'cpag-resident-native', 'kubectl']

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def output(args):
    return subprocess.check_output(args, text=True).strip()

def apply(items):
    run(K+['apply', '-f', '-'], input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items}), text=True, stdout=subprocess.DEVNULL)

def obj(kind, name, **kw):
    return {'apiVersion': 'v1', 'kind': kind, 'metadata': {'name': name, 'namespace': 'cpag'}, **kw}

def wait_until(function, seconds=180):
    end = time.monotonic()+seconds
    while True:
        try:
            if function(): return
        except subprocess.CalledProcessError: pass
        if time.monotonic() >= end: raise TimeoutError('native lab readiness')
        time.sleep(2)

def worker_identity():
    pods = json.loads(output(K+['-n', 'cpag', 'get', 'pods', '-l', 'app=cpag-worker', '-o', 'json']))['items']
    assert len(pods) == 1
    pod = pods[0]
    status = next(row for row in pod['status']['containerStatuses'] if row['name'] == 'worker')
    return {'pod_uid': pod['metadata']['uid'], 'container_id': status['containerID'], 'restart_count': status['restartCount']}


def start_watch(resource):
    initial = json.loads(output(K+['-n', 'cpag', 'get', resource, '-o', 'json']))
    rv = initial['metadata']['resourceVersion']
    prefix = '/api/v1' if resource == 'pods' else '/apis/batch/v1'
    endpoint = prefix+'/namespaces/cpag/'+resource+'?watch=true&allowWatchBookmarks=true&resourceVersion='+rv
    process = subprocess.Popen(K+['get', '--raw', endpoint, '--request-timeout=0'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    events = []
    watch = {'resource': resource, 'resource_version': rv, 'initial_count': len(initial['items']), 'events': events}
    def read():
        try:
            for line in process.stdout:
                event = json.loads(line)
                obj = event.get('object', {}); metadata = obj.get('metadata', {})
                status = obj.get('status', {})
                if not isinstance(status, dict): status = {}
                events.append({'type': event['type'], 'name': metadata.get('name'), 'uid': metadata.get('uid'),
                               'resource_version': metadata.get('resourceVersion'),
                               'container_ids': [c.get('containerID') for c in status.get('containerStatuses', [])]})
        except Exception as error:
            watch['reader_error'] = type(error).__name__
    reader = threading.Thread(target=read, daemon=True); reader.start()
    time.sleep(.3)
    if process.poll() is not None:
        watch['exit_code'] = process.returncode
        watch['error'] = process.stderr.read()[-1000:]
        (OUT/'watch-evidence.json').write_text(json.dumps([watch], indent=2)+'\n')
        raise RuntimeError('Kubernetes watch exited immediately: '+json.dumps(watch))
    return process, reader, watch


def memory_bytes(value):
    from decimal import Decimal
    for suffix, scale in (('Ti', 1024**4), ('Gi', 1024**3), ('Mi', 1024**2), ('Ki', 1024), ('G', 10**9), ('M', 10**6), ('K', 1000)):
        if value.endswith(suffix): return int(Decimal(value[:-len(suffix)])*scale)
    return int(Decimal(value))


def capacity_preflight():
    node = json.loads(output(K+['get', 'node', 'resident-native', '-o', 'json']))
    available = memory_bytes(node['status']['allocatable']['memory'])
    requested = 0
    for name in ('resources.json', 'storage.json'):
        for resource in json.loads((HERE/name).read_text())['items']:
            if resource['kind'] != 'Deployment': continue
            for container in resource['spec']['template']['spec']['containers']:
                requested += memory_bytes(container.get('resources', {}).get('requests', {}).get('memory', '0'))
    system = json.loads(output(K+['-n', 'kube-system', 'get', 'pods', '-o', 'json']))
    system_requested = sum(memory_bytes(c.get('resources', {}).get('requests', {}).get('memory', '0'))
                           for pod in system['items'] for c in pod['spec']['containers'])
    capacity = {'scope': 'scheduler requests only; no capacity acceptance', 'allocatable_bytes': available, 'candidate_requested_bytes': requested,
                'system_requested_bytes': system_requested, 'fits': available >= requested+system_requested}
    (OUT/'capacity.json').write_text(json.dumps(capacity, indent=2)+'\n')
    assert capacity['fits'], 'native node lacks scheduler memory requests: '+json.dumps(capacity)
    return capacity


def main():
    assert output(['uname', '-m']) == 'x86_64', 'requires native AMD64 Linux runner'
    OUT.mkdir(parents=True, exist_ok=True)
    archive = REPO/'deployments/resident/build/cpag-resident-amd64.tar'
    sha = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
    state = OUT/'state'; state.mkdir(exist_ok=True)
    for name in ('cpag-shared/jobs', 'cpag-control', 'cpag-postgres'):
        (state/name).mkdir(parents=True, exist_ok=True)
    (state/'cpag-shared').chmod(0o700)
    run(['docker', 'run', '-d', '--privileged', '--name', 'cpag-resident-native',
         '-p', '127.0.0.1:8095:8095', '-v', str(state)+':/cpag-resident-lab',
         '-v', str(archive)+':/candidate.tar:ro', 'rancher/k3s:v1.32.5-k3s1',
         'server', '--disable', 'traefik', '--disable', 'servicelb', '--node-name', 'resident-native'])
    run(['docker','exec','cpag-resident-native','chown','0:0','/cpag-resident-lab/cpag-shared',
         '/cpag-resident-lab/cpag-shared/jobs','/cpag-resident-lab/cpag-control'])
    wait_until(lambda: output(K+['get', 'node', 'resident-native', '-o', 'jsonpath={.status.conditions[?(@.type=="Ready")].status}']) == 'True')
    capacity = capacity_preflight()
    run(['docker', 'exec', 'cpag-resident-native', 'ctr', 'images', 'import', '--digests', '/candidate.tar'])
    image_rows = output(['docker', 'exec', 'cpag-resident-native', 'ctr', 'images', 'ls']).splitlines()[1:]
    images = {}
    for role in ('api', 'worker'):
        tag = 'docker.io/library/cpag-resident-'+role+':review-amd64'
        digest = next(row.split()[2] for row in image_rows if row.split()[0] == tag)
        pin = tag.split(':')[0]+'@'+digest
        run(['docker', 'exec', 'cpag-resident-native', 'ctr', 'images', 'tag', tag, pin])
        images[role] = pin
    credentials = {key: secrets.token_hex(24) for key in ('pg', 'worker', 'coord', 'admin')}
    apply([{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'cpag'}}])
    apply([obj('Secret', 'cpag-postgres', stringData={'POSTGRES_PASSWORD': credentials['pg']})])
    storage = json.loads((HERE/'storage.json').read_text())['items']
    volumes = []
    for resource in storage:
        if resource['kind'] == 'PersistentVolumeClaim':
            spec = resource['spec']; name = resource['metadata']['name']
            spec.update(storageClassName='', volumeName='lab-'+name)
            volumes.append({'apiVersion': 'v1', 'kind': 'PersistentVolume', 'metadata': {'name': 'lab-'+name},
                'spec': {'accessModes': spec['accessModes'], 'storageClassName': '', 'capacity': spec['resources']['requests'],
                         'hostPath': {'path': '/cpag-resident-lab/'+name, 'type': 'DirectoryOrCreate'}}})
        elif resource['kind'] == 'Deployment':
            resource['spec']['replicas'] = 1
    apply(volumes+storage)
    run(K+['-n', 'cpag', 'rollout', 'status', 'deploy/cpag-postgres', '--timeout=180s'])
    def sql(query):
        return output_sql(query)
    def output_sql(query):
        return run(K+['-n', 'cpag', 'exec', '-i', 'deploy/cpag-postgres', '--', 'psql', '-qAtX', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'cpag_app'], input=query, text=True, capture_output=True).stdout.strip()
    for path in sorted((REPO/'internal/jobs/migrations').glob('*.sql')):
        sql('BEGIN;\n'+path.read_text()+'\nCOMMIT;')
    uid = output(K+['get', 'ns', 'cpag', '-o', 'jsonpath={.metadata.uid}'])
    api_id = output(['docker', 'image', 'inspect', 'cpag-resident-api:review-amd64', '--format', '{{.Id}}'])
    app = {'database_url': 'postgres://postgres:'+credentials['pg']+'@cpag-postgres:5432/cpag_app?sslmode=disable',
        'shared_root': '/state/shared', 'control_root': '/state/control', 'public_addr': '127.0.0.1:8095', 'internal_addr': '127.0.0.1:8094',
        'worker_token': credentials['worker'], 'coordinator_token': credentials['coord'], 'bootstrap_admin_username': 'lab-admin',
        'bootstrap_admin_password': credentials['admin'], 'static_root': '/opt/cpag/webui/out', 'python_bin': 'python3',
        'python_path': '/opt/cpag/services/analysis/src', 'resource_profile': 'storage-budget-2',
        'capacity_policy': 'engineering-core-capacity-3', 'compact_verifier_image': api_id}
    worker = {key: app[key] for key in ('shared_root', 'control_root', 'worker_token', 'coordinator_token', 'resource_profile')}
    worker.update(api_url='http://cpag-resident-internal:8096', worker_id='resident-native', poll_seconds=.2)
    apply([obj('Secret', 'cpag-app-config', stringData={'app.json': json.dumps(app)}),
           obj('Secret', 'cpag-worker-config', stringData={'worker.json': json.dumps(worker)})])
    resources = json.loads((HERE/'resources.json').read_text())['items']
    for resource in resources:
        if resource['kind'] != 'Deployment': continue
        resource['spec']['replicas'] = 1
        for container in resource['spec']['template']['spec']['containers']:
            if container['name'] == 'public-relay': continue
            container['image'] = images['worker' if container['name'] == 'worker' else 'api']
            for env in container.get('env', []):
                if env['name'] == 'CPAG_NAMESPACE_UID': env['value'] = uid
    apply(resources)
    for name in ('cpag-api', 'cpag-worker'):
        run(K+['-n', 'cpag', 'rollout', 'status', 'deploy/'+name, '--timeout=180s'])
    probe = r"""
import json, os, socket
from cpag_worker.resident_sandbox import enter
enter({'cwd':'/resident-work'})
assert os.geteuid() == 65532
checks = {}
def denied(name, action):
    try: action()
    except PermissionError: checks[name] = True
    else: raise AssertionError('sandbox boundary writable/readable: '+name)
denied('worker_config', lambda: open('/private/config.json','rb').read(1))
denied('serviceaccount', lambda: open('/var/run/secrets/kubernetes.io/serviceaccount/token','rb').read(1))
denied('parent_environment', lambda: open('/proc/1/environ','rb').read(1))
denied('publication', lambda: open('/state/shared/jobs/resident-probe','x'))
denied('control', lambda: open('/state/control/resident-probe','x'))
denied('network', lambda: socket.socket())
denied('session_escape', lambda: os.setsid())
denied('regain_root', lambda: os.setuid(0))
print(json.dumps(checks))
"""
    sandbox = json.loads(output(K+['-n', 'cpag', 'exec', 'deploy/cpag-worker', '-c', 'worker', '--', 'python3', '-c', probe]))
    service_port = next(r['spec']['ports'][0]['port'] for r in resources if r['kind'] == 'Service' and r['metadata']['name'] == 'cpag-workbench')
    port = subprocess.Popen(K+['-n', 'cpag', 'port-forward', '--address=0.0.0.0', 'svc/cpag-workbench', '8095:'+str(service_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    watches = []
    try:
        sys.path.insert(0, str(REPO/'scripts/validation'))
        from round19_core_small import inputs
        offline = OUT/'offline'; replay = OUT/'replay'
        _, _, off_profile, _ = inputs(offline, 'success', 'offline')
        _, _, replay_profile, _ = inputs(replay, 'normal', 'replay')
        env = {**os.environ, 'CPAG_URL': 'http://127.0.0.1:8095', 'CPAG_TEST_PASSWORD': credentials['admin']}
        wait_until(lambda: subprocess.call(['curl', '-fsS', 'http://127.0.0.1:8095/health/ready'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0)
        before_identity = worker_identity()
        watches = [start_watch(resource) for resource in ('pods', 'jobs')]
        run(['node', str(HERE/'workbench.cjs'), str(replay), str(off_profile), str(replay_profile), str(OUT/'workbench.json')], env=env)
        after_identity = worker_identity()
        assert before_identity == after_identity, 'offline/replay changed resident container'
        for process, reader, watch in watches:
            assert process.poll() is None, 'Kubernetes watch ended before acceptance'
            watch['closed_by_harness'] = True
            process.terminate(); process.wait(timeout=10); reader.join(timeout=5)
            assert not watch.get('reader_error'), 'Kubernetes watch parse failed'
            assert not any(e['type'] == 'ADDED' for e in watch['events']), 'Pod or per-attempt Job created during baseline'
            assert not any(e['type'] == 'ERROR' for e in watch['events']), 'Kubernetes watch error event'
            assert watch['resource'] != 'jobs' or watch['initial_count'] == 0, 'pre-existing compute Job'
        (OUT/'watch-evidence.json').write_text(json.dumps([w[2] for w in watches], indent=2)+'\n')
        assert json.loads(output(K+['-n', 'cpag', 'get', 'jobs', '-o', 'json']))['items'] == [], 'resident path created per-attempt Jobs'
        browser = json.loads((OUT/'workbench.json').read_text())
        receipts = []
        for record in browser['runs']:
            file = f"/state/control/jobs/{record['id']}/attempt-{record['attempt']}.worker/exit.json"
            receipt = json.loads(output(K+['-n', 'cpag', 'exec', 'deploy/cpag-api', '-c', 'api', '--', 'cat', file]))
            receipt.pop('token', None)
            assert receipt['resident']['group_exited'] and receipt['resident']['returncode'] == 0
            assert receipt['container_id'] == before_identity['container_id'], 'receipt changed baseline container'
            assert receipt['resident']['pod_uid'] == before_identity['pod_uid'], 'receipt changed baseline Pod'
            receipts.append(receipt)
        drill_env = {**os.environ, 'CPAG_LAB_NODE': 'cpag-resident-native', 'CPAG_DRILL_OUTPUT': str(OUT/'drills')}
        run([sys.executable, str(HERE/'drills.py'), '--baseline', browser['runs'][0]['id'], '--execute'], env=drill_env)
        report = {'source_commit': output(['git', 'rev-parse', 'HEAD']), 'platform': 'native-linux-amd64', 'capacity': capacity,
                  'archive_sha256': sha, 'images': images, 'no_compute_jobs': True, 'guardian_receipts': receipts,
                  'synthetic_only': True, 'baseline_worker_identity': before_identity, 'kubernetes_watches': [w[2] for w in watches], 'sandbox_denials': sandbox, 'workbench': browser}
        (OUT/'acceptance.json').write_text(json.dumps(report, indent=2)+'\n')
    finally:
        for process, reader, watch in watches:
            if process.poll() is None:
                watch['closed_by_harness'] = True
                process.terminate(); process.wait(timeout=10)
            else:
                watch['exit_code'] = process.returncode
                if process.returncode and not watch.get('closed_by_harness'): watch['error'] = process.stderr.read()[-1000:]
            reader.join(timeout=5)
        if watches: (OUT/'watch-evidence.json').write_text(json.dumps([w[2] for w in watches], indent=2)+'\n')
        port.terminate(); port.wait(timeout=10)


if __name__ == '__main__': main()
