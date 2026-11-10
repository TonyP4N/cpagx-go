"""Explicit compact replay artifacts; reuse the arrived-prefix judgement unchanged."""
from pathlib import Path
import platform
import shutil
import sqlite3
import tempfile
import uuid

from . import __version__
from .capacity import resolve_capacity_profile
from .contracts import validate
from .dual_source_rules import validate_profile
from .dual_source_export import event_graph
from .pipeline import canonical, canonical_file_matches, file_hash, fingerprint, write_canonical
from .replay_history import HistorySink, HistoryReader, VERSION as FORMAT


def files(count):
    from .replay_export import artifact_files_for_inputs
    return frozenset((artifact_files_for_inputs(count) - {'snapshots.jsonl', 'revisions.jsonl'})
                     | {'history/manifest.json', 'history/history.sqlite3'})


def _inputs(network, process, profile):
    from .replay_export import network_names, read_json
    networks = [Path(p) for p in (network if isinstance(network, (list, tuple)) else [network])]
    process, profile = Path(process), Path(profile)
    network_names(len(networks))
    if any(p.is_symlink() or not p.is_file() for p in [*networks, process, profile]):
        raise ValueError('invalid_original_file')
    if profile.stat().st_size > 8 * 1024**2:
        raise ValueError('profile_byte_limit')
    config = read_json(profile); validate_profile(config)
    if config.get('replay', {}).get('history_format') != FORMAT:
        raise ValueError('explicit_spool_history_required')
    budget = resolve_capacity_profile(config)
    if (profile.stat().st_size > budget.profile_bytes or process.stat().st_size > budget.process_bytes
            or any(p.stat().st_size > budget.network_file_bytes for p in networks)
            or sum(p.stat().st_size for p in networks) > budget.network_total_bytes):
        raise ValueError('input_size_limit')
    return networks, process, profile, config, budget


def _sink(root, config, run_id, attempt, *, source_bytes=0):
    budget = resolve_capacity_profile(config)
    remaining=min(budget.output_bytes,config['replay']['max_output_bytes'])-source_bytes-131072
    if remaining<256*1024:raise ValueError('replay_output_limit:insufficient_history_storage_budget')
    return HistorySink(root, run_id=run_id, attempt_id=attempt, version=FORMAT,
                       max_bytes=remaining, max_snapshots=config['replay']['max_snapshots'],
                       max_revisions=config['replay']['max_revisions'])


def values(run, config):
    from .replay_export import VERSION, ANALYSIS_VERSION
    result = run['analysis']; projected = event_graph(result, replay=True)
    h = run['history_spool']['manifest']
    return {'analysis.json': result, 'events.json': projected['events.json'],
            'graph.json': projected['graph.json'], 'quality.json': result['quality'],
            'metrics.json': run['metrics'],
            'replay.json': {'schema_version': '1.0.0', 'replay_version': VERSION,
                            'analysis_version': ANALYSIS_VERSION, 'synthetic': config['synthetic'],
                            'semantic_config_fingerprint': result['config_fingerprint'],
                            'snapshot_count': h['snapshot_count'], 'revision_count': h['revision_count'],
                            'final_snapshot_id': h['last_snapshot_id'], 'history_format': FORMAT}}


def close_run(run):
    if run is not None:
        run['inputs'].close()
        if run.get('history_reader') is not None: run['history_reader'].close()


def export_task(network, process, profile, output, *, run_id=None, attempt_id=1, replay_version='dual-source-replay-1'):
    from .replay_export import VERSION, ANALYSIS_VERSION, input_rows, network_names, dataset_manifest, execute
    networks, process, profile, config, budget = _inputs(network, process, profile)
    if replay_version != VERSION or type(attempt_id) is not int or not 1 <= attempt_id <= 1000000:
        raise ValueError('invalid_execution_identity')
    run_id = run_id or str(uuid.uuid4())
    if not isinstance(run_id, str) or not 1 <= len(run_id) <= 128: raise ValueError('invalid_execution_identity')
    before = input_rows(networks, process); profile_hash = file_hash(profile)
    output = Path(output)
    if output.exists() or output.is_symlink(): raise ValueError('output_already_exists')
    output.mkdir(parents=True); run = None
    try:
        source = output / 'sources'; source.mkdir()
        for path, name in zip(networks, network_names(len(networks))): shutil.copyfile(path, source / name)
        shutil.copyfile(process, source / 'process.csv'); shutil.copyfile(profile, source / 'profile.json')
        retained = [source / name for name in network_names(len(networks))]
        if input_rows(retained, source / 'process.csv') != before or file_hash(source / 'profile.json') != profile_hash:
            raise ValueError('original_changed_during_copy')
        source_bytes=sum(path.stat().st_size for path in source.iterdir())
        run = execute(retained, source / 'process.csv', config, pace=True,
                      history_sink=_sink(output / 'history', config, run_id, attempt_id,source_bytes=source_bytes))
        payloads = values(run, config)
        payloads['dataset.json'] = dataset_manifest(config, before, len(networks))
        payloads['runtime_metrics.json'] = run['runtime_metrics']
        output_limit=min(budget.output_bytes,config['replay']['max_output_bytes'])
        def remaining():return output_limit-sum(path.stat().st_size for path in output.rglob('*') if path.is_file())
        for name, value in payloads.items():write_canonical(output/name,value,max_bytes=remaining())
        with (output / 'arrivals.jsonl').open('wb') as stream:
            written=0;allowance=remaining()
            for row in run['metrics']['arrival_samples']:
                data=canonical(row)+b'\n';written+=len(data)
                if written>allowance:raise ValueError('replay_output_limit')
                stream.write(data)
        if input_rows(networks, process) != before or file_hash(profile) != profile_hash:
            raise ValueError('original_changed_during_replay')
        entries = [{'path': name, 'sha256': file_hash(output / name), 'size_bytes': (output / name).stat().st_size}
                   for name in sorted(files(len(networks)) - {'run_manifest.json'})]
        result = run['analysis']
        manifest = {'schema_version': '1.0.0', 'synthetic': config['synthetic'], 'run_id': run_id,
                    'attempt_id': attempt_id, 'input_fingerprint': fingerprint(before), 'config_fingerprint': fingerprint(config),
                    'semantic_config_fingerprint': result['config_fingerprint'], 'replay_version': VERSION,
                    'analysis_version': ANALYSIS_VERSION, 'history_format': FORMAT,
                    'history_manifest_sha256': run['history_spool']['manifest_sha256'],
                    'tool_versions': {'core': __version__, 'python': platform.python_version()},
                    'mode': 'replay', 'artifacts': entries,
                    'result_hashes': {'events': fingerprint(payloads['events.json']), 'graph': fingerprint(payloads['graph.json'])},
                    'limitations': result['limitations'], 'status': 'succeeded_with_warnings',
                    'warnings': ['synthetic_replay_engineering_only'] if config['synthetic'] else ['replay_hypotheses_not_causality', 'real_source_unvalidated']}
        if budget.version: manifest['capacity_profile'] = budget.version
        validate('ReplaySpoolRunManifest', manifest)
        write_canonical(output / 'run_manifest.json', manifest,max_bytes=remaining())
        if sum((output / name).stat().st_size for name in files(len(networks))) > config['replay']['max_output_bytes']:
            raise ValueError('replay_output_limit')
        verify(output)
        return manifest
    except BaseException as error:
        shutil.rmtree(output, ignore_errors=True)
        if isinstance(error,sqlite3.Error):
            raise ValueError('history_sqlite_write_failed:'+getattr(error,'sqlite_errorname','SQLITE_ERROR')) from error
        raise
    finally: close_run(run)


def verify(output, *, retain_run=False):
    from .replay_export import read_json, input_rows, network_names, dataset_manifest, execute
    root = Path(output)
    if root.is_symlink() or not root.is_dir(): raise ValueError('invalid_replay_root')
    manifest = read_json(root / 'run_manifest.json'); validate('ReplaySpoolRunManifest', manifest)
    if not canonical_file_matches(root / 'run_manifest.json', manifest): raise ValueError('run_manifest_encoding_mismatch')
    dataset = read_json(root / 'dataset.json')
    count = sum(row['kind'] == 'network' for row in dataset['files'])
    expected = files(count)
    found, directories = set(), set()
    for path in root.rglob('*'):
        if path.is_symlink(): raise ValueError('symlink_artifact')
        rel = path.relative_to(root).as_posix()
        if path.is_dir(): directories.add(rel)
        elif path.is_file() and path.stat().st_nlink == 1: found.add(rel)
        else: raise ValueError('ordinary_unlinked_artifact_required')
    extras = found - expected
    if extras:
        publication = root / 'manifest.json'
        anchor = file_hash(publication) + '.json' if publication.is_file() else None
        if extras not in ({'manifest.json'}, {'manifest.json', anchor}): raise ValueError('artifact_inventory_mismatch')
        if anchor in extras and (root / anchor).read_bytes() != publication.read_bytes(): raise ValueError('publication_anchor_mismatch')
        wrapper = read_json(publication)
        if wrapper.get('replay_version') != manifest['replay_version'] or wrapper.get('history_format') != FORMAT:
            raise ValueError('publication_replay_history_version_mismatch')
        records = wrapper.get('artifacts', [])
        if len(records) != len(expected) or {row.get('path') for row in records} != expected: raise ValueError('publication_inventory_mismatch')
        for row in records:
            path = root / row['path']
            if path.stat().st_size != row['size'] or file_hash(path) != row['sha256']: raise ValueError('publication_integrity_mismatch')
    if not expected <= found or directories != {'sources', 'history'}: raise ValueError('artifact_inventory_mismatch')
    fixed_manifest_sha=file_hash(root/'run_manifest.json')
    fixed_extras={name:file_hash(root/name) for name in extras}
    entries = manifest['artifacts']
    if len(entries) != len(expected) - 1 or {row['path'] for row in entries} != expected - {'run_manifest.json'}:
        raise ValueError('manifest_inventory_mismatch')
    for row in entries:
        path = root / row['path']
        if path.stat().st_size != row['size_bytes'] or file_hash(path) != row['sha256']: raise ValueError('artifact_integrity_mismatch:' + row['path'])
    networks, process, _, config, budget = _inputs([root / 'sources' / n for n in network_names(count)], root / 'sources/process.csv', root / 'sources/profile.json')
    before = input_rows(networks, process)
    if manifest.get('capacity_profile', '') != budget.version or manifest['synthetic'] != config['synthetic']:
        raise ValueError('capacity_or_source_category_mismatch')
    if fingerprint(config) != manifest['config_fingerprint'] or fingerprint(before) != manifest['input_fingerprint']:
        raise ValueError('original_binding_mismatch')
    if dataset != dataset_manifest(config, before, count): raise ValueError('dataset_original_binding_mismatch')
    if sum((root / name).stat().st_size for name in expected) > config['replay']['max_output_bytes']: raise ValueError('replay_output_limit')
    context = {'run_id': manifest['run_id'], 'attempt_id': manifest['attempt_id'],
               'semantic_config_fingerprint': manifest['semantic_config_fingerprint'], 'replay_version': manifest['replay_version']}
    reader = HistoryReader(root / 'history', expected_manifest_sha256=manifest['history_manifest_sha256'], expected_context=context)
    run = None
    try:
        with tempfile.TemporaryDirectory(prefix='cpag-replay-reverify-') as work:
            source_bytes=sum(path.stat().st_size for path in (root/'sources').iterdir())
            run = execute(networks, process, config, history_sink=_sink(Path(work) / 'history', config, manifest['run_id'], manifest['attempt_id'],source_bytes=source_bytes))
            other = HistoryReader(Path(work) / 'history', expected_manifest_sha256=run['history_spool']['manifest_sha256'], expected_context=context)
            try:
                if any(reader.manifest[key] != other.manifest[key] for key in ('snapshot_count', 'revision_count', 'last_snapshot_id','limits','context','version','synthetic')):
                    raise ValueError('replay_history_counts_mismatch')
                for number in range(reader.manifest['snapshot_count']):
                    if reader.snapshot(number) != other.snapshot(number): raise ValueError('replay_snapshot_semantic_mismatch')
                for after in range(0, reader.manifest['revision_count'], 100):
                    if reader.revisions(after, 100) != other.revisions(after, 100): raise ValueError('replay_revision_semantic_mismatch')
            finally: other.close()
        for name, value in values(run, config).items():
            if not canonical_file_matches(root / name, value): raise ValueError('replay_semantic_mismatch:' + name)
        arrivals = run['metrics']['arrival_samples']
        with (root / 'arrivals.jsonl').open('rb') as stream:
            for row in arrivals:
                if stream.readline() != canonical(row) + b'\n': raise ValueError('arrival_semantic_mismatch')
            if stream.read(1): raise ValueError('arrival_semantic_mismatch')
        if manifest['semantic_config_fingerprint'] != run['analysis']['config_fingerprint']: raise ValueError('semantic_profile_mismatch')
        expected_warnings=['synthetic_replay_engineering_only'] if config['synthetic'] else ['replay_hypotheses_not_causality','real_source_unvalidated']
        if manifest['status']!='succeeded_with_warnings' or manifest['warnings']!=expected_warnings or manifest['limitations']!=run['analysis']['limitations']:raise ValueError('replay_status_or_limitations_mismatch')
        for key, name in (('events', 'events.json'), ('graph', 'graph.json')):
            if fingerprint(read_json(root / name)) != manifest['result_hashes'][key]: raise ValueError('result_hash_mismatch')
        runtime = read_json(root / 'runtime_metrics.json')
        import math
        number = lambda value: type(value) in (int, float) and math.isfinite(value) and value >= 0
        if (runtime.get('clock') != 'monotonic_wall_seconds' or runtime.get('speed') != config['replay'].get('speed', 1)
                or type(runtime.get('paced')) is not bool or not number(runtime.get('elapsed_seconds'))
                or len(runtime.get('samples', [])) != len(config['replay']['sequence'])): raise ValueError('runtime_metrics_contract')
        from .replay import instant
        previous = 0
        for index, (sample, step) in enumerate(zip(runtime['samples'], config['replay']['sequence']), 1):
            scheduled = (instant(step['available_at']) - instant(config['replay']['simulation_start'])).total_seconds() / runtime['speed']
            if sample.get('arrival_seq') != index or sample.get('available_at') != step['available_at'] or sample.get('scheduled_elapsed_seconds') != scheduled: raise ValueError('runtime_schedule_mismatch')
            if any(not number(sample.get(key)) for key in ('actual_elapsed_seconds', 'processing_seconds')): raise ValueError('runtime_metrics_contract')
            actual = sample['actual_elapsed_seconds']
            if actual < previous or actual > runtime['elapsed_seconds'] or (runtime['paced'] and actual < scheduled): raise ValueError('runtime_sample_order')
            previous = actual
        if len(runtime.get('core_samples', [])) != len(run['runtime_metrics']['core_samples']) or any(not number(sample.get('wall_seconds')) for sample in runtime.get('core_samples', [])): raise ValueError('runtime_core_samples')
        if file_hash(root/'run_manifest.json')!=fixed_manifest_sha:raise ValueError('replay_artifact_changed_during_verification')
        final_files=set();final_dirs=set()
        for path in root.rglob('*'):
            if path.is_symlink():raise ValueError('replay_artifact_changed_during_verification')
            if path.is_dir():final_dirs.add(path.relative_to(root).as_posix())
            elif path.is_file() and path.stat().st_nlink==1:final_files.add(path.relative_to(root).as_posix())
            else:raise ValueError('replay_artifact_changed_during_verification')
        if final_files!=found or final_dirs!=directories:raise ValueError('replay_artifact_changed_during_verification')
        for item in entries:
            path=root/item['path']
            if path.stat().st_size!=item['size_bytes'] or file_hash(path)!=item['sha256']:raise ValueError('replay_artifact_changed_during_verification')
        if any(file_hash(root/name)!=digest for name,digest in fixed_extras.items()):raise ValueError('replay_publication_changed_during_verification')
        run['history_reader'] = reader
        run['history_spool'] = {'manifest': reader.manifest, 'manifest_sha256': manifest['history_manifest_sha256']}
        if retain_run: return manifest, run
        return manifest
    finally:
        if not retain_run or run is None or run.get('history_reader') is None:
            reader.close(); close_run(run)
