"""Build the suspended, per-attempt Kubernetes Job for compact offline exports."""
import re

from .resources import resolve
from .worker import compact_payload, network_refs


def compute_job(claim, worker, image):
    run = claim['id']
    attempt = claim['attempt']
    if not re.fullmatch(r'[0-9a-f]{32}', run) or type(attempt) is not int or not 1 <= attempt <= 100:
        raise ValueError('invalid run or attempt')
    if worker != claim['worker'] or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', worker):
        raise ValueError('invalid worker identity')
    if not re.fullmatch(r'[a-z0-9./:-]+@sha256:[0-9a-f]{64}', image):
        raise ValueError('immutable compute image required')
    payload = claim['payload']
    if payload['kind'] != 'dual-source' or not compact_payload(payload):
        raise ValueError('this executor requires a compact offline task')
    limits = resolve(payload['resource_profile'])
    labels = {'cpag-role': 'compute', 'cpag.job': run, 'cpag.attempt': str(attempt), 'cpag.worker': worker}
    base = f'kube-staging/{run}/{attempt}'
    args = ['python', '-m', 'cpag_core.shared_cli', '--action', 'export', '--mode', 'offline',
            '--seconds', str(limits['timeout'])]
    for index, ref in enumerate(network_refs(payload)):
        ext = ref['path'].rsplit('.', 1)[-1].lower()
        if ext not in ('pcap', 'pcapng'):
            raise ValueError('unsupported capture extension')
        args.extend(['--network', f'/inputs/network-{index}.{ext}'])
    args.extend(['--process', '/inputs/process.csv', '--profile', '/inputs/profile.json',
                 '--root', '/output/run', '--run-id', run, '--attempt-id', str(attempt)])
    container = {
        'name': 'compute', 'image': image, 'imagePullPolicy': 'Never', 'command': args,
        'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                            'capabilities': {'drop': ['ALL']}},
        'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'},
                      'limits': {'cpu': limits['cpus'], 'memory': str(limits['memory_bytes'])}},
        'volumeMounts': [{'name': 'staging', 'mountPath': '/inputs', 'subPath': base+'/inputs', 'readOnly': True},
                         {'name': 'staging', 'mountPath': '/output', 'subPath': base+'/output'},
                         {'name': 'tmp', 'mountPath': '/tmp'}]}
    pod = {'automountServiceAccountToken': False, 'restartPolicy': 'Never',
           'securityContext': {'runAsUser': 65532, 'runAsGroup': 65532, 'runAsNonRoot': True,
                               'seccompProfile': {'type': 'RuntimeDefault'}},
           'containers': [container], 'volumes': [
               {'name': 'staging', 'persistentVolumeClaim': {'claimName': 'cpag-shared'}},
               {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': str(limits['temporary_bytes'])}}]}
    return {'apiVersion': 'batch/v1', 'kind': 'Job',
            'metadata': {'namespace': 'cpag', 'name': f'cpag-{run}-{attempt}', 'labels': labels},
            'spec': {'suspend': True, 'backoffLimit': 0, 'activeDeadlineSeconds': limits['timeout'],
                     'template': {'metadata': {'labels': labels}, 'spec': pod}}}


def stage_attempt(root, claim, image):
    """Return a suspended Job only after all staged inputs match the run binding."""
    import hashlib
    import os
    from pathlib import Path
    from .worker import beneath

    job = compute_job(claim, claim['worker'], image)
    work = Path(root) / 'kube-staging' / claim['id'] / str(claim['attempt'])
    work.parent.mkdir(parents=True, exist_ok=True)
    # Never reuse a failed or partially written attempt.
    work.mkdir(mode=0o700)
    inputs = work / 'inputs'
    inputs.mkdir(mode=0o700)
    payload = claim['payload']
    names = [(f"network-{i}."+r['path'].rsplit('.', 1)[-1].lower(), r)
             for i, r in enumerate(network_refs(payload))]
    names += [('process.csv', payload['process']), ('profile.json', payload['profile'])]
    for name, ref in names:
        checksum = hashlib.sha256()
        with beneath(root, ref['path']).open('rb') as source, (inputs/name).open('xb') as dest:
            while chunk := source.read(1024 * 1024):
                checksum.update(chunk)
                dest.write(chunk)
            dest.flush()
            os.fsync(dest.fileno())
        if checksum.hexdigest() != ref['sha256']:
            raise ValueError('staged input hash mismatch: '+name)
        (inputs/name).chmod(0o444)
    inputs.chmod(0o555)
    output = work / 'output'
    output.mkdir(mode=0o700)
    os.chown(output, 65532, 65532)
    return job
