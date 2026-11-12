"""Private service bridge: server-owned source verification and bounded DAG6 reads.

The key is accepted only on an inherited descriptor or dedicated Docker stdin,
never from HTTP, artifacts, arguments or environment. Approvals are versioned separately from core-local
experimental approvals. The Go caller owns authentication, current attempt and
terminal-state checks before and after this bridge; restart loses all approvals.
"""
import argparse
from contextlib import contextmanager
import hashlib
import hmac
import io
import json
import os
import resource
import sys
from pathlib import Path
import sqlite3
import time

from . import shared_export as core
from .pipeline import canonical, file_hash, fingerprint, json_chunks

VERSION = 'service-dag6-read-guard-1'
CAPACITY = 'engineering-core-capacity-3'
RESOURCE = 'storage-budget-2'
BUDGET = 'shared-storage-budget-2'
MAX_REQUEST = 8 * 1024 * 1024


def _deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise ValueError('service_query_deadline')


def _binding(manifest, binding):
    if not isinstance(binding, dict):
        raise ValueError('service_binding_required')
    wanted = {'run_id': manifest['run_id'], 'attempt_id': manifest['attempt_id'],
              'config_fingerprint': manifest['config_fingerprint'],
              'storage_format': core.FORMAT, 'capacity_profile': CAPACITY,
              'resource_profile': RESOURCE, 'storage_budget_version': BUDGET}
    for name, value in wanted.items():
        if binding.get(name) != value:
            raise ValueError('service_binding_mismatch:' + name)
    payload = binding.get('payload_sha256')
    if not isinstance(payload, str) or len(payload) != 64 or any(c not in '0123456789abcdef' for c in payload):
        raise ValueError('service_payload_binding_required')
    if manifest['storage_budget']['version'] != BUDGET:
        raise ValueError('service_storage_budget_mismatch')


def _inventory(output, binding, deadline=None):
    root = Path(output)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('service_output_directory_required')
    manifest = core.read_json(root/'run_manifest.json', 65536)
    _binding(manifest, binding)
    publication_sha=file_hash(root/'manifest.json')
    if binding.get('publication_sha256',publication_sha)!=publication_sha:
        raise ValueError('service_publication_sha_mismatch')
    anchor=publication_sha+'.json'
    expected = set(core.artifact_files_for_inputs(manifest['network_count'], mode=manifest['mode']))
    found = set(); directories = set(); rows = []
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(parent)/name
            if path.is_symlink():
                raise ValueError('service_symlink_artifact')
        directories.update((Path(parent)/name).relative_to(root).as_posix() for name in dirs)
        for name in files:
            _deadline(deadline)
            path = Path(parent)/name
            rel = path.relative_to(root).as_posix()
            if not path.is_file():
                raise ValueError('service_non_regular_artifact')
            before = path.stat()
            digest = file_hash(path)
            after = path.stat()
            stamp = lambda stat: [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]
            if stamp(before) != stamp(after):
                raise ValueError('service_artifact_changed_during_hash')
            if rel == anchor:
                if digest != publication_sha:
                    raise ValueError('service_publication_anchor_changed')
            else:
                rows.append({'path': rel, 'sha256': digest, 'size': after.st_size})
            found.add(rel)
    if found not in (expected | {'manifest.json'}, expected | {'manifest.json',anchor}) or directories != {'shared', 'sources'}:
        raise ValueError('service_exact_inventory_mismatch')
    publication = core.read_json(root/'manifest.json', 65536)
    entries = publication.get('artifacts', [])
    actual = {row['path']: row for row in rows}
    if len(entries) != len(expected) or {row['path'] for row in entries} != expected:
        raise ValueError('service_publication_inventory_mismatch')
    if publication.get('config_fingerprint') != binding['config_fingerprint']:
        raise ValueError('service_publication_config_mismatch')
    for entry in entries:
        row = actual[entry['path']]
        if entry.get('sha256') != row['sha256'] or entry.get('size') != row['size']:
            raise ValueError('service_publication_artifact_changed')
    for field in ('storage_format','capacity_profile','resource_profile','storage_budget_version'):
        if publication.get(field) != binding[field]:
            raise ValueError('service_publication_binding_mismatch:' + field)
    if publication.get('run_id') != binding['run_id'] or publication.get('attempt_id') != binding['attempt_id']:
        raise ValueError('service_publication_attempt_mismatch')
    sources = {row['path']: row['sha256'] for row in rows}
    if publication.get('inputs') != {'network': sources['sources/network.pcap'], 'process': sources['sources/process.csv'], 'profile': sources['sources/profile.json']}:
        raise ValueError('service_publication_input_mismatch')
    networks = [sources['sources/'+name] for name in core.network_names(manifest['network_count'])]
    if manifest['network_count'] > 1 and publication.get('networks') != networks:
        raise ValueError('service_publication_network_order_mismatch')
    if manifest['mode'] == 'replay' and any(publication.get(name) != manifest.get(name) for name in ('replay_version','history_format')):
        raise ValueError('service_publication_history_mismatch')
    return root, manifest, sorted(rows, key=lambda row: row['path'])


@contextmanager
def _envelope(root, rows):
    sha = next(row['sha256'] for row in rows if row['path'] == 'manifest.json')
    anchor=sha+'.json'
    extras={anchor} if (root/anchor).exists() else set()
    token = core._SERVICE_ENVELOPE.set((root.resolve(), sha, extras))
    try:
        yield
    finally:
        core._SERVICE_ENVELOPE.reset(token)


def verify(output, binding, key, *, deadline=None):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('service_private_key_required')
    started_at=time.time();started=time.monotonic();cpu=time.process_time()
    root, initial, rows = _inventory(output, binding, deadline)
    report = {}
    with _envelope(root, rows):
        manifest = core.verify_task(root, deadline=deadline, verification_report=report)
    _, after, final_rows = _inventory(output, binding, deadline)
    if canonical(initial) != canonical(manifest) or canonical(after) != canonical(manifest) or rows != final_rows:
        raise ValueError('service_changed_during_source_verification')
    payload = {'version': VERSION, 'binding': binding, 'inventory': rows,
               'logical_roots_sha256': fingerprint(manifest['logical_artifacts']),
               'verified_at': int(time.time())}
    approval = {'payload': payload, 'mac': hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()}
    metrics={'started_at':started_at,'ended_at':time.time(),'wall_seconds':time.monotonic()-started,
             'process_cpu_seconds':time.process_time()-cpu,
             'max_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024),
             'cgroup_memory_peak_bytes':None,'cgroup_cpu_usage_usec':None}
    try:
        metrics['cgroup_memory_peak_bytes']=int(Path('/sys/fs/cgroup/memory.peak').read_text())
        counters=dict(line.split() for line in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())
        metrics['cgroup_cpu_usage_usec']=int(counters['usage_usec'])
    except (OSError,ValueError,KeyError):pass
    target=os.environ.get('CPAG_PHASE_METRICS')
    if target and os.environ.get('CPAG_PHASE_STRATEGY')=='phase-resources-3':
        from .measurement_v3 import flush_summaries
        flush_summaries()
        path=Path(target)
        if not path.is_file() or path.stat().st_size>1024**2:raise ValueError('service_phase_measurement_missing_or_large')
        metrics['phase_resources']=[json.loads(line) for line in path.read_text().splitlines() if line]
    return {'approval': approval, 'metadata': _metadata(manifest), 'verification_report': report,'execution_metrics':metrics}


def _metadata(manifest):
    return {'storage_format': core.FORMAT, 'synthetic':manifest['synthetic'], 'mode': manifest['mode'], 'manifest': manifest,
            'counts': manifest['counts'], 'final_snapshot_number': manifest.get('final_snapshot_number'),
            'complete_logical_result_hashes': manifest['result_hashes'], 'result_hash_kind': 'merkle-json-dag-1',
            'verification': VERSION}


@contextmanager
def open_service_reader(output, binding, approval, key, *, deadline=None):
    if not isinstance(key, bytes) or len(key) != 32 or not isinstance(approval, dict) or set(approval) != {'payload','mac'}:
        raise ValueError('service_private_approval_required')
    payload = approval['payload']
    if not isinstance(payload, dict) or payload.get('version') != VERSION or not isinstance(approval['mac'], str):
        raise ValueError('service_approval_version_invalid')
    if not hmac.compare_digest(hmac.new(key, canonical(payload), hashlib.sha256).hexdigest(), approval['mac']):
        raise ValueError('service_approval_mac_invalid')
    if payload.get('binding') != binding:
        raise ValueError('service_approval_attempt_binding_mismatch')
    root, manifest, rows = _inventory(output, binding, deadline)
    if rows != payload.get('inventory') or fingerprint(manifest['logical_artifacts']) != payload.get('logical_roots_sha256'):
        raise ValueError('service_verified_bytes_changed')
    sha = next(row['sha256'] for row in rows if row['path'] == 'run_manifest.json')
    token = core._SERVICE_VERIFIED.set((root.resolve(), sha))
    try:
        with _envelope(root, rows), core.open_reader(root, deadline=deadline) as reader:
            yield reader
        if _inventory(output, binding, deadline)[2] != rows:
            raise ValueError('service_bytes_changed_during_read')
    finally:
        core._SERVICE_VERIFIED.reset(token)


def query(output, binding, approval, key, request, *, deadline=None):
    if not isinstance(request, dict):
        raise ValueError('service_query_required')
    action = request.get('action', 'metadata')
    with open_service_reader(output, binding, approval, key, deadline=deadline) as reader:
        if action == 'metadata':
            return _metadata(reader.run_manifest)
        if action == 'graph':
            if request.get('snapshot') is not None:
                number=request['snapshot']
                if reader.run_manifest['mode']!='replay' or type(number) is not int or not 0<=number<reader.run_manifest['counts']['snapshots']:raise ValueError('service_snapshot_outside_history')
                graph=reader.get('history/snapshots',path=[number,'graph'])
            else:graph=reader.get('graph.json')
            return {'storage_format':core.FORMAT,'synthetic':reader.run_manifest['synthetic'],'graph':graph}
        if action == 'evaluation':
            from .evaluation_shared import adapt_reader
            return adapt_reader(reader, batch=request['batch'], sample_sha256=request['sample_sha256'], projection=request.get('projection', 'dual'))
        if action == 'evaluation-document':
            from .evaluation_shared import reader_context
            from .evaluation_bundle import verify_document
            with reader_context(output,reader):
                return verify_document(request['document'],output,identity=request.get('identity'),reference=request.get('reference',False))
        if action in ('page', 'get'):
            logical = request.get('logical_root')
            if logical not in {row['name'] for row in reader.run_manifest['logical_artifacts']}:
                raise ValueError('service_unknown_logical_root')
            path = request.get('path', [])
            if not isinstance(path, list) or len(path) > 64 or any(type(v) not in (int,str) or (type(v) is int and v < 0) for v in path):
                raise ValueError('service_query_path_invalid')
            if action == 'page':
                return reader.page(logical, path=path, offset=request.get('offset',0), limit=request.get('limit',100))
            return reader.get(logical, path=path)
        if action == 'snapshot':
            number = request.get('snapshot')
            if reader.run_manifest['mode'] != 'replay' or type(number) is not int or not 0 <= number < reader.run_manifest['counts']['snapshots']:
                raise ValueError('service_snapshot_outside_history')
            return reader.get('history/snapshots', path=[number] + request.get('path', []))
        if action == 'revisions':
            if reader.run_manifest['mode'] != 'replay':
                raise ValueError('service_replay_required')
            return reader.page('history/revisions', offset=request.get('after',0),limit=request.get('limit',100))
        if action in ('selection','evidence'):
            return core.query_reader(output,reader, operation_id=request.get('operation'), change_id=request.get('change'), snapshot=request.get('snapshot'),trigger=request.get('trigger',False),ref_offset=request.get('ref_offset',0),ref_limit=request.get('ref_limit',100),deadline=deadline)
        raise ValueError('service_query_action_invalid')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-fd',type=int)
    parser.add_argument('--private-stdin',action='store_true')
    parser.add_argument('--key-stdin',action='store_true')
    args = parser.parse_args()
    try:
        raw = __import__('sys').stdin.buffer.read(MAX_REQUEST+1)
        if len(raw)>MAX_REQUEST:
            raise ValueError('service_request_byte_limit')
        request = json.loads(raw)
        if args.key_stdin:
            if args.key_fd is not None or args.private_stdin:
                raise ValueError('service_key_transport_ambiguous')
            encoded=request['authority_key'];request=request['request']
            if not isinstance(encoded,str) or len(encoded)!=64:
                raise ValueError('service_private_key_invalid')
            key=bytes.fromhex(encoded)
        elif args.private_stdin:
            if args.key_fd is not None:
                raise ValueError('service_key_transport_ambiguous')
            encoded=request.pop('service_key',None)
            if not isinstance(encoded,str) or len(encoded)!=64:
                raise ValueError('service_private_key_invalid')
            key=bytes.fromhex(encoded)
        else:
            if args.key_fd is None or args.key_fd < 3:
                raise ValueError('service_private_key_fd_required')
            with os.fdopen(args.key_fd,'rb') as stream:
                key = stream.read(33)
        if len(key) != 32:
            raise ValueError('service_private_key_invalid')
        action = request.get('action')
        seconds = request.get('seconds',1800 if action=='verify' else 10)
        if type(seconds) not in (int,float) or not 0 < seconds <= (1800 if action=='verify' else 10):
            raise ValueError('service_deadline_outside_budget')
        deadline=time.monotonic()+seconds
        if action == 'verify':
            result=verify(request['output_dir'],request['binding'],key,deadline=deadline)
        elif action == 'query':
            result=query(request['output_dir'],request['binding'],request['approval'],key,request.get('query',{}),deadline=deadline)
        else:
            raise ValueError('service_action_invalid')
        output=io.BytesIO()
        for chunk in json_chunks(result):
            if output.tell()+len(chunk)+1>core.QUERY_BYTES:
                raise ValueError('service_response_byte_limit')
            output.write(chunk)
        print(output.getvalue().decode())
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as error:
        parser.exit(2,json.dumps({'status':'failed','error_type':type(error).__name__,'reason':str(error)})+'\n')


if __name__ == '__main__':
    main()
