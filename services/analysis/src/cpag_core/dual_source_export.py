"""Opt-in standard artifact adapter for the bounded synthetic dual-source run.

The original dual-source result and all source bytes remain beneath ``dual/``.
Every read verifies the retained run and rebuilds the standard projection.
"""
from .measurement import phase
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import uuid

from . import __version__
from .contracts import validate, validation_session
from .dual_source import analyze, query, run_dual, strict_json, VERSION, LIMITATIONS, retained_networks, R17_VERSION, R17_LEGACY_VERSION
from .pipeline import canonical, file_hash, fingerprint, write_canonical, canonical_file_matches


STANDARD = ('dataset.json', 'events.json', 'graph.json', 'quality.json', 'analysis.json')
DUAL = ('dual/manifest.json', 'dual/analysis.json', 'dual/sources/network.pcap',
        'dual/sources/process.csv', 'dual/sources/profile.json')
FILES = frozenset((*STANDARD, 'run_manifest.json', *DUAL))
DIRECTORIES = frozenset(('dual', 'dual/sources'))


@validation_session()
def event_graph(result, *, replay=False):
    """Shared standard observation projection; only the reference schema differs."""
    finite_events=[]
    for finding in result.get('rule_findings',[]):
        interval=finding['interval']
        from .dual_source import utc
        finite_events.append({'schema_version':'1.0.0','synthetic':result['synthetic'],'event_id':finding['finding_id'],
            'event_type':'finite_rule_finding','rule_version':finding['rule_version'],'parameters':finding['parameters'],
            'evidence_refs':finding['evidence_refs'],'time_range':{'start':utc(interval[0]) if interval else None,'end':utc(interval[1]) if interval else None},'result':finding})
    events = ([item['event'] for item in result['network']] +
              [item['event'] for item in result['process']] + result['changes'] + finite_events)
    nodes = ([{'id':item['event']['event_id'], 'event_id':item['event']['event_id'],
               'kind':'network', 'evidence_refs':item['observation']['source_refs']}
              for item in result['network']] +
             [{'id':item['event']['event_id'], 'event_id':item['event']['event_id'],
               'kind':'process', 'evidence_refs':[item['event']['source_ref']]}
              for item in result['process']] +
             [{'id':change['event_id'], 'event_id':change['event_id'],
               'kind':'derived_event', 'evidence_refs':change['evidence_refs']}
              for change in result['changes']+finite_events])
    edges = [{'id':candidate['candidate_id'], 'source':candidate['operation_id'],
              'target':candidate['change_id'], 'claim_id':candidate['claim']['claim_id'],
              'rule_id':candidate['rule_id'], 'rule_version':candidate['rule_version'],
              'config_version':candidate['config_version'],
              'config_fingerprint':result['config_fingerprint'],
              'candidate_state':candidate['state']}
             for candidate in result['candidates']]
    graph = {'schema_version':'1.0.0', 'synthetic':result['synthetic'], 'graph_id':'',
             'nodes':nodes, 'edges':edges,
             'claims':[candidate['claim'] for candidate in result['candidates']],
             'input_fingerprint':result['input_fingerprint'], 'core_version':__version__,
             'statistics':{'nodes':len(nodes), 'edges':len(edges)},
             'truncation':{'truncated':False, 'reason':None}}
    graph['graph_id'] = 'dual-graph-' + fingerprint({k:v for k,v in graph.items() if k!='graph_id'})
    for item in result['network']:
        validate(('Replay' if replay else '')+'NetworkEvent', item['event'])
    for item in result['process']:
        validate(('Replay' if replay else '')+'ProcessObservation', item['event'])
    for event in result['changes']+finite_events:
        validate(('Replay' if replay else '')+'DerivedEvent', event)
    validate(('Replay' if replay else '')+'GraphArtifact', graph)
    return {'events.json':events, 'graph.json':graph}


@phase('standard_projection')
def projection(result, source_dir):
    """Make a deterministic graph of observations, transitions and candidate claims."""
    source_dir = Path(source_dir)
    projected=event_graph(result)
    events,graph=projected['events.json'],projected['graph.json']
    source_manifest=_read_json(source_dir.parent/'manifest.json')
    source_networks=retained_networks(source_dir.parent,source_manifest)
    files = [{'name':name, 'sha256':file_hash(source_dir/name),
              'size_bytes':(source_dir/name).stat().st_size, 'kind':kind}
             for kind,name in [('network',p.name) for p in source_networks]+[('process','process.csv')]]
    dataset = {'schema_version':'1.0.0', 'synthetic':result['synthetic'],
               'dataset_id':'dual-dataset-'+result['input_fingerprint'],
               'source':'retained synthetic dual-source inputs', 'release':result['analysis_version'],
               'files':files, 'collection_range':{'start':None, 'end':None},
               'timezone_basis':'configured offsets and uncertainties in retained profile',
               'authorization_ref':'explicit synthetic dual-source opt-in'}
    if result['synthetic'] is False:
        provenance=result['source_provenance']
        dataset.update({key:provenance[key] for key in ('source','release','collection_range','timezone_basis','authorization_ref')})
    validate('DatasetManifest', dataset)
    return {'dataset.json':dataset, 'events.json':events, 'graph.json':graph,
            'quality.json':result['quality'], 'analysis.json':result}


def _warnings(result):
    quality = result['quality']
    warnings = list(quality['unknown_reasons'])
    if result['analysis_version']==R17_VERSION:
        warnings += ['operation: '+reason for issue in quality['operation_time_issues'] for reason in issue['reasons']]
    if result['synthetic'] is False:warnings.append('real_source_unvalidated')
    if any(f['state']=='unknown' for f in result.get('rule_findings',[])):warnings.append('finite_rules_have_unknown_findings')
    warnings += ['process: '+reason for reason in quality['process']['reasons']]
    if quality['network_unsupported']:
        warnings.append('unsupported_network_records_present')
    return sorted(set(warnings))


def artifact_files(output):
    """Exact allowed inventory, derived from validated bounded capture filenames."""
    output=Path(output)
    networks=retained_networks(output/'dual')
    dynamic=tuple('dual/'+p.relative_to(output/'dual').as_posix() for p in networks)
    return frozenset((*STANDARD,'run_manifest.json','dual/manifest.json','dual/analysis.json',
                      'dual/sources/process.csv','dual/sources/profile.json',*dynamic))


def _inventory(root):
    """Exact regular-file inventory; reject links and unexpected files."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('artifact_root_missing_or_symlink')
    files_expected=artifact_files(root)
    found = set()
    found_dirs = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in (*dirs, *files):
            path = Path(directory)/name
            if path.is_symlink():
                raise ValueError('symlink_artifact')
        found_dirs.update((Path(directory)/name).relative_to(root).as_posix() for name in dirs)
        for name in files:
            path = Path(directory)/name
            if not path.is_file():
                raise ValueError('nonregular_artifact')
            found.add(path.relative_to(root).as_posix())
    extras = found-files_expected
    if extras:
        publication = root/'manifest.json'
        anchor = file_hash(publication)+'.json' if publication.is_file() else None
        if extras not in ({'manifest.json'}, {'manifest.json',anchor}):
            raise ValueError('artifact_inventory_mismatch')
        if anchor in extras and (root/anchor).read_bytes() != publication.read_bytes():
            raise ValueError('publication_anchor_mismatch')
    if not files_expected <= found or found_dirs != DIRECTORIES:
        raise ValueError('artifact_inventory_mismatch')


def _read_json(path):
    try:
        return strict_json(Path(path).read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('invalid_or_missing_artifact: '+str(path)) from exc


@phase('artifact_verification')
def verify_task(output):
    """Check all bytes, original inputs and a fresh projection of source analysis."""
    output = Path(output)
    _inventory(output)
    manifest = _read_json(output/'run_manifest.json')
    if (output/'run_manifest.json').read_bytes() != canonical(manifest)+b'\n':
        raise ValueError('run_manifest_encoding_mismatch')
    validate('RunManifest', manifest)
    files_expected=artifact_files(output)
    entries = manifest['artifacts']
    if len(entries) != len(files_expected)-1 or {entry['path'] for entry in entries} != files_expected-{'run_manifest.json'}:
        raise ValueError('artifact_manifest_inventory_mismatch')
    for entry in entries:
        path = output/entry['path']
        if file_hash(path) != entry['sha256'] or path.stat().st_size != entry['size_bytes']:
            raise ValueError('artifact_integrity_mismatch: '+entry['path'])
    dual = output/'dual'
    dual_manifest = _read_json(dual/'manifest.json')
    networks=retained_networks(dual,dual_manifest)
    source_names={p.relative_to(dual).as_posix() for p in networks}|{'sources/process.csv','sources/profile.json','analysis.json'}
    if (set(dual_manifest) != ({'schema_version','synthetic','analysis_version','config_fingerprint','files','network_inputs'} if len(networks)>1 else {'schema_version','synthetic','analysis_version','config_fingerprint','files'})
            or dual_manifest['schema_version'] != '1.0.0' or dual_manifest['synthetic'] is not manifest['synthetic']
            or dual_manifest['analysis_version'] not in (VERSION,R17_LEGACY_VERSION,R17_VERSION)
            or set(dual_manifest.get('files', {})) != source_names):
        raise ValueError('dual_manifest_inventory_mismatch')
    for name in source_names:
        if file_hash(dual/name) != dual_manifest['files'][name]:
            raise ValueError('dual_source_integrity_mismatch: '+name)
    config = _read_json(dual/'sources/profile.json')
    actual = analyze(networks if len(networks)>1 else networks[0], dual/'sources/process.csv', config,
                     _analysis_version=dual_manifest['analysis_version'])
    if actual['synthetic'] is not manifest['synthetic']:raise ValueError('synthetic_manifest_mismatch')
    if dual_manifest['analysis_version'] != actual['analysis_version']:raise ValueError('dual_analysis_version_mismatch')
    retained_matches = canonical_file_matches(dual/'analysis.json', actual)
    if not retained_matches:
        retained_matches = canonical(actual) == canonical(_read_json(dual/'analysis.json'))
    if not retained_matches or dual_manifest['config_fingerprint'] != fingerprint(config):
        raise ValueError('dual_analysis_does_not_match_sources')
    expected = projection(actual, dual/'sources')
    for name,payload in expected.items():
        if not canonical_file_matches(output/name,payload) and canonical(_read_json(output/name)) != canonical(payload):
            raise ValueError('standard_projection_mismatch: '+name)
    if manifest['input_fingerprint'] != actual['input_fingerprint'] or manifest['config_fingerprint'] != actual['config_fingerprint']:
        raise ValueError('run_manifest_fingerprint_mismatch')
    if manifest['result_hashes'] != {'events':fingerprint(expected['events.json']),
                                     'graph':fingerprint(expected['graph.json'])}:
        raise ValueError('run_manifest_result_hash_mismatch')
    if (manifest['warnings'] != _warnings(actual)
            or manifest['status'] != ('succeeded_with_warnings' if manifest['warnings'] else 'succeeded')
            or manifest['limitations'] != actual['limitations'] or manifest['mode'] != 'offline'):
        raise ValueError('run_manifest_status_mismatch')
    publication_path = output/'manifest.json'
    if publication_path.exists():
        publication = _read_json(publication_path)
        if (set(publication) != ({'config_fingerprint','inputs','artifacts','networks'} if len(networks)>1 else {'config_fingerprint','inputs','artifacts'})
                or publication['config_fingerprint'] != manifest['config_fingerprint']
                or publication['inputs'] != {name:file_hash(dual/'sources'/filename)
                    for name,filename in (('network','network.pcap'),('process','process.csv'),('profile','profile.json'))}):
            raise ValueError('publication_identity_mismatch')
        if len(networks)>1 and publication['networks'] != [file_hash(p) for p in networks]:raise ValueError('publication_network_identity_mismatch')
        records = publication['artifacts']
        if (not isinstance(records,list) or len(records) != len(files_expected)
                or {entry.get('path') for entry in records if isinstance(entry,dict)} != files_expected):
            raise ValueError('publication_inventory_mismatch')
        for entry in records:
            name = entry['path']
            path = output/name
            if (set(entry) != {'path','sha256','size'} or path.stat().st_size != entry['size']
                    or file_hash(path) != entry['sha256']):
                raise ValueError('publication_integrity_mismatch: '+name)
    return manifest


@phase('complete_export')
def export_task(network, process, profile, output, *, run_id=None, attempt_id=1):
    """Publish an immutable standard run with the complete original dual run."""
    if run_id is not None and (not isinstance(run_id,str) or not run_id or len(run_id)>128):
        raise ValueError('invalid_run_id')
    if type(attempt_id) is not int or attempt_id < 1:
        raise ValueError('invalid_attempt_id')
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('output_already_exists')
    output.mkdir(parents=True, exist_ok=False)
    try:
        result = run_dual(network, process, profile, output/'dual')
        payloads = projection(result, output/'dual/sources')
        entries = []
        from .capacity import resolve_capacity_profile
        budget=resolve_capacity_profile(_read_json(output/'dual/sources/profile.json'))
        used=sum(p.stat().st_size for p in (output/'dual').rglob('*') if p.is_file())
        for name,payload in payloads.items():
            path = output/name
            write_canonical(path,payload,max_bytes=budget.output_bytes-used if budget.version else None)
            used+=path.stat().st_size
        for name in sorted(artifact_files(output)-{'run_manifest.json'}) if 'analysis_mode' in result else (*STANDARD,*DUAL):
            path = output/name
            entries.append({'path':name, 'sha256':file_hash(path), 'size_bytes':path.stat().st_size})
        warnings = _warnings(result)
        manifest = {'schema_version':'1.0.0', 'synthetic':result['synthetic'], 'run_id':run_id or str(uuid.uuid4()),
                    'attempt_id':attempt_id, 'input_fingerprint':result['input_fingerprint'],
                    'config_fingerprint':result['config_fingerprint'],
                    'tool_versions':{'core':__version__, 'python':platform.python_version()},
                    'mode':'offline', 'artifacts':entries,
                    'result_hashes':{'events':fingerprint(payloads['events.json']),
                                     'graph':fingerprint(payloads['graph.json'])},
                    'limitations':result['limitations'], 'status':'succeeded_with_warnings' if warnings else 'succeeded',
                    'warnings':warnings}
        validate('RunManifest', manifest)
        (output/'run_manifest.json').write_bytes(canonical(manifest)+b'\n')
        verify_task(output)
        return manifest
    except Exception:
        shutil.rmtree(output)
        raise


def query_task(output, operation_id=None, change_id=None):
    """Return verified original evidence for one operation or sample transition."""
    verify_task(output)
    if (operation_id is None) == (change_id is None):
        raise ValueError('select_exactly_one_operation_or_change')
    try:
        return query(Path(output)/'dual', operation_id=operation_id, change_id=change_id)
    except ValueError as exc:
        if str(exc) in ('unknown_operation', 'unknown_change'):
            raise KeyError(str(exc)) from exc
        raise


def backup_task(output, bundle):
    """Copy one self-contained artifact tree; this does not back up task databases."""
    verify_task(output)
    bundle = Path(bundle)
    if bundle.exists() or bundle.is_symlink():
        raise ValueError('bundle_already_exists')
    try:
        shutil.copytree(output, bundle, symlinks=True)
        return verify_task(bundle)
    except Exception:
        if bundle.exists() and not bundle.is_symlink():
            shutil.rmtree(bundle)
        raise


def restore_task(bundle, destination):
    verify_task(bundle)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('restore_target_already_exists')
    try:
        shutil.copytree(bundle, destination, symlinks=True)
        return verify_task(destination)
    except Exception:
        if destination.exists() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--network',required=True,action='append')
    for name in ('process','profile','output'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--synthetic', action='store_true', help='legacy synthetic acknowledgement; profile remains authoritative')
    parser.add_argument('--run-id')
    parser.add_argument('--attempt-id', type=int, default=1)
    args = parser.parse_args()
    try:
        if args.synthetic and _read_json(args.profile)['synthetic'] is not True:raise ValueError('synthetic_flag_profile_mismatch')
        manifest = export_task(args.network,args.process,args.profile,args.output,
                               run_id=args.run_id,attempt_id=args.attempt_id)
    except (OSError,ValueError,KeyError,TypeError) as error:
        parser.exit(2,str(error)+'\n')
    print(json.dumps({'run_id':manifest['run_id'],'attempt_id':manifest['attempt_id'],
                      'output':args.output},sort_keys=True))


if __name__ == '__main__':
    main()
