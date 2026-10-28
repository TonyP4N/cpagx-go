#!/usr/bin/env python3
"""Generate dense raw synthetic R19 PCAP/CSV; never reads analysis or gold labels.

S/M/L preserve 100/1000/10000 request operations and the same logical CSV count.
These are density cases, not the independent 128MiB/64MiB/8MiB byte boundaries.
Replay includes every request, response, CSV header and row without dropping data.
"""
import argparse
from bisect import bisect_left, bisect_right
from dataclasses import asdict
import hashlib
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import struct
import sys

from round17_profile import profile

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
LEGACY_VERSION = 'r19-raw-scale-fixture-1'
CAPACITY_VERSION = 'r19-density-capacity-2'
PREFLIGHT_VERSION = 'r19-density-preflight-2'
CAPACITY_PROFILE = 'engineering-capacity-1'
HISTORY_FORMAT = 'replay-history-checkpoint-delta-2'
SCALES = {'S':100,'M':1000,'L':10000}
# Frozen from the pre-change generator, independently of all analysis outputs.
RAW_SHA256 = {
 'S': {'network.pcap':'cc88eb70769587ae38cc40828a37fa55abc988981b1497302b956394be40dd85','process.csv':'9d933fd88020df0172cbd12fd58ac1ee63f71b83ebfb901f5ea500c42c856c55'},
 'M': {'network.pcap':'dbff44ef84c282825e67b3ec891bd4cd4598c99da2530f901a6bdafb8fba3e77','process.csv':'f1a9e817245b416781da470e48a052501c280bdb5fad9185bb970664bc5e411c'},
 'L': {'network.pcap':'abac2b769dbe57b4cc9558dfc1a98dc5a910358d2bca4e3f129a0ddf90d8e381','process.csv':'02508de1fa3a2e76702edbb0dc70658ffb7b577263a87386ac553a26c69818f4'}}



def at(microseconds):
    return (BASE + timedelta(microseconds=microseconds)).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def message(cip, context):
    cpf = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0xb2, len(cip)) + cip
    return struct.pack('<HHII8sI', 0x6f, len(cpf), 1, 0, context, 0) + cpf


def frame(payload, seq, reverse=False):
    src, dst, ports = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]), (1234, 44818)
    if reverse: src, dst, ports = dst, src, ports[::-1]
    tcp = struct.pack('!HHIIBBHHH', *ports, seq, 0, 80, 24, 4096, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
    return b'\0' * 12 + b'\x08\x00' + ip + tcp


def generate(root, scale, *, version=LEGACY_VERSION):
    if version not in (LEGACY_VERSION,CAPACITY_VERSION):raise ValueError('unsupported_density_fixture_version')
    if scale not in SCALES:raise ValueError('unsupported_density_scale')
    root = Path(root); root.mkdir(parents=True, mode=0o700, exist_ok=False)
    count = {'S': 100, 'M': 1000, 'L': 10000}[scale]
    arrivals = [{'source_slot': 'process', 'record_number': 1, 'available_at': at(8_000_000)}]
    request_seq = response_seq = 100
    network = root / 'network.pcap'
    with network.open('wb') as stream:
        stream.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiiII', 2, 4, 0, 0, 65535, 1))
        for number in range(count):
            context = (number + 1).to_bytes(8, 'little')
            request = message(bytes.fromhex('10032001240130010100'), context)
            response = message(bytes.fromhex('90000000'), context)
            for ordinal, (payload, seq, reverse, delay) in enumerate(((request, request_seq, False, 0), (response, response_seq, True, 10_000))):
                when = 10_000_000 + number * 50_000 + delay
                raw = frame(payload, seq, reverse)
                seconds, micros = divmod(when, 1_000_000)
                stream.write(struct.pack('<IIII', int(BASE.timestamp()) + seconds, micros, len(raw), len(raw)) + raw)
                arrivals.append({'source_slot': 'network-0', 'record_number': number * 2 + ordinal + 1, 'available_at': at(when + 100_000)})
            request_seq += len(request); response_seq += len(response)
    process = root / 'process.csv'
    with process.open('w') as stream:
        stream.write('time,pump\n')
        for number in range(count):
            when = 9_000_000 + number * 80_000
            stream.write(at(when) + ',' + str(number % 2) + '\n')
            arrivals.append({'source_slot': 'process', 'record_number': number + 2, 'available_at': at(when + 100_000)})
    config = profile()
    until = at(86_399_000_000)
    for clock in config['clocks'].values(): clock['valid_to'] = until
    for mapping in config['mappings']: mapping['valid_to'] = until
    config['source_provenance']['collection_range']['end'] = until
    if version==CAPACITY_VERSION:config['capacity_profile']=CAPACITY_PROFILE
    offline = root / 'offline-profile.json'; offline.write_text(json.dumps(config, separators=(',', ':')) + '\n')
    arrivals.sort(key=lambda row: row['available_at'])
    last = max(10_000_000 + (count - 1) * 50_000 + 110_000, 9_000_000 + (count - 1) * 80_000 + 100_000)
    for slot in ('network-0', 'process'):
        arrivals.append({'kind': 'source_eof', 'source_slot': slot, 'available_at': at(last + 1_000_000)})
    finish = last + 9_000_000
    arrivals.append({'kind': 'advance', 'available_at': at(finish)})
    config['replay'] = {'version': 'dual-source-replay-1', 'simulation_start': at(8_000_000),
        'arrival_time_basis': 'independently generated UTC raw-record arrival schedule',
        'warmup_seconds': 1, 'allowed_lateness_seconds': 2, 'buffer_seconds': 300,
        'max_buffer_records': 11000, 'max_snapshots': 4096, 'max_revisions': 8192,
        'max_output_bytes': 16777216, 'speed': 1, 'realtime': False,
        'finish_at': at(finish), 'sequence': arrivals}
    if version==CAPACITY_VERSION:config['replay'].update(_capacity_replay_limits(config))
    replay = root / 'replay-profile.json'; replay.write_text(json.dumps(config, separators=(',', ':')) + '\n')
    for mode, chosen in (('dual_source', offline), ('dual_source_replay', replay)):
        for repetition in (1, 2, 3):
            case = {'schema_version': 'r19-capacity-case-1', 'id': f'{scale}-{mode}-{repetition}',
                    'scale': scale, 'mode': mode, 'networks': [network.name], 'process': process.name,
                    'profile': chosen.name, 'repetition': repetition,
                    'cache_condition': 'unverified_cold' if repetition == 1 else 'warm'}
            (root / f'{mode}-{repetition}.json').write_text(json.dumps(case, indent=2) + '\n')
    report = {'schema_version': 'r19-raw-scale-fixture-1', 'scale': scale, 'operations': count,
              'request_frames': count, 'response_frames': count, 'logical_process_records': count,
              'arrival_steps': len(arrivals), 'replay_profile_bytes': replay.stat().st_size,
              'bytes': {'network': network.stat().st_size, 'process': process.stat().st_size},
              'claim': 'generated density fixture only; current runtime may explicitly refuse limits; no byte-boundary or industrial coverage'}
    if version==CAPACITY_VERSION:
        report.update(schema_version=CAPACITY_VERSION,capacity_profile=CAPACITY_PROFILE,history_format=HISTORY_FORMAT,
                      preflight='preflight.json',matrix='matrix.json',claim='raw density preserved; static admission checks only, not runtime or reference-environment acceptance')
        preflight=build_preflight(root,scale)
        (root/'preflight.json').write_text(json.dumps(preflight,indent=2)+'\n')
        matrix={'schema_version':'r19-density-matrix-2','fixture_version':CAPACITY_VERSION,'scale':scale,
                'operator_resource_profile':CAPACITY_PROFILE,'preflight':'preflight.json',
                'preflight_sha256':_sha(root/'preflight.json'),'rows':[
                  {'case_manifest':f'{mode}-{rep}.json','mode':mode,'repetition':rep,
                   'status':preflight['modes'][mode]['status'],'profile_sha256':preflight['modes'][mode]['profile_sha256']}
                  for mode in ('dual_source','dual_source_replay') for rep in (1,2,3)]}
        (root/'matrix.json').write_text(json.dumps(matrix,indent=2)+'\n')
    (root / 'fixture.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def _sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def _runtime():
    location=str(Path(__file__).resolve().parents[2]/'services/analysis/src')
    if location not in sys.path:sys.path.insert(0,location)
    from cpag_core.capacity import resolve_capacity_profile
    from cpag_core.pipeline import fingerprint
    from cpag_core.dual_source_rules import validate_profile
    return resolve_capacity_profile,fingerprint,validate_profile


def _capacity_replay_limits(config):
    budget,_,_=_runtime();budget=budget(config)
    return {'history_format':HISTORY_FORMAT,'max_buffer_records':budget.frames+budget.process_records+1,
            'max_snapshots':budget.snapshots,'max_revisions':budget.revisions,'max_output_bytes':budget.output_bytes}


def _schedule(count):
    rows=[{'source_slot':'process','record_number':1,'available_at':at(8_000_000)}]
    for number in range(count):
        for ordinal,delay in ((0,0),(1,10_000)):
            rows.append({'source_slot':'network-0','record_number':number*2+ordinal+1,
                         'available_at':at(10_000_000+number*50_000+delay+100_000)})
    rows.extend({'source_slot':'process','record_number':number+2,'available_at':at(9_000_000+number*80_000+100_000)}
                for number in range(count))
    rows.sort(key=lambda row:row['available_at'])
    last=max(10_000_000+(count-1)*50_000+110_000,9_000_000+(count-1)*80_000+100_000)
    rows.extend({'kind':'source_eof','source_slot':slot,'available_at':at(last+1_000_000)} for slot in ('network-0','process'))
    rows.append({'kind':'advance','available_at':at(last+9_000_000)})
    return rows,last+9_000_000


def _expected_profiles(count):
    config=profile();until=at(86_399_000_000)
    for clock in config['clocks'].values():clock['valid_to']=until
    for mapping in config['mappings']:mapping['valid_to']=until
    config['source_provenance']['collection_range']['end']=until
    config['capacity_profile']=CAPACITY_PROFILE
    offline=json.loads(json.dumps(config))
    sequence,finish=_schedule(count)
    config['replay']={'version':'dual-source-replay-1','simulation_start':at(8_000_000),
        'arrival_time_basis':'independently generated UTC raw-record arrival schedule',
        'warmup_seconds':1,'allowed_lateness_seconds':2,'buffer_seconds':300,
        'max_buffer_records':11000,'max_snapshots':4096,'max_revisions':8192,
        'max_output_bytes':16777216,'speed':1,'realtime':False,'finish_at':at(finish),'sequence':sequence}
    config['replay'].update(_capacity_replay_limits(config))
    return {'dual_source':offline,'dual_source_replay':config}


def density_budget_math(scale):
    """Independent integer geometry, not parser/predictor output or evaluation gold.

    Transition j spans samples j-1,j. Odd j ends at1, even j at0.
    Zero clock errors and fixed 5s windows make these interval intersections
    necessary; outward float rounding may add boundary candidates, not remove
    the strict integer lower bound. Including equality on the right gives a
    safe upper count because source steps are >=10ms while float ulps <1us.
    """
    if scale not in SCALES:raise ValueError('unsupported_density_scale')
    count=SCALES[scale]
    starts={parity:[9_000_000+(j-1)*80_000 for j in range(parity,count,2)] for parity in (1,2)}
    ends={parity:[9_000_000+j*80_000 for j in range(parity,count,2)] for parity in (1,2)}
    expected=[];unexpected=[];upper=[]
    for operation in range(count):
        request=10_000_000+operation*50_000
        def overlap(parity,right_inclusive=False):
            right=(bisect_right if right_inclusive else bisect_left)(starts[parity],request+5_000_000)
            left=bisect_left(ends[parity],request)
            return max(0,right-left)
        expected.append(overlap(1));unexpected.append(overlap(2));upper.append(overlap(1,True))
    products=sum(e*u for e,u in zip(expected,unexpected));candidate_count=sum(expected)
    # Canonical offline CSV SourceRef is >=177 bytes (64 hex,27 timestamp,
    # pump column, null frame, positive record). Replay adds source fields.
    # Offline has two complete analysis copies plus graph claims: 10*e*u refs.
    # Spool replay still emits one flat analysis plus graph claims: 6*e*u refs.
    # candidate-<64hex> appears5/3 times respectively; count only string bytes.
    reference_bytes=177;candidate_id_bytes=74
    steps=3*count+4
    return {'operations':count,'request_frames':count,'response_frames':count,'process_records':count,
            'changes':count-1,'candidate_count_lower_bound':candidate_count,'candidate_count_upper_bound':sum(upper),
            'candidate_counter_product_sum':products,'min_expected_per_operation':min(expected),
            'min_unexpected_per_operation':min(unexpected),'source_ref_min_bytes':reference_bytes,
            'candidate_id_payload_bytes':candidate_id_bytes,
            'offline_flat_output_lower_bound_bytes':10*reference_bytes*products+5*candidate_id_bytes*candidate_count,
            'replay_flat_output_lower_bound_bytes':6*reference_bytes*products+3*candidate_id_bytes*candidate_count,
            'arrival_steps':steps,'snapshot_lower_bound':steps+4,'snapshot_upper_bound':2*steps+4,
            'revision_upper_bound':2*steps+3,
            'output_storage_assumption':'current complete flat final analysis copies and graph claims; a new shared storage version requires a new registered preflight proof',
            'proof_scope':'complete retained fixed-density observations; excludes parser execution, history bytes and most other mandatory fields; not a measured runtime output',
            'snapshot_scope':'base publications plus at most one clock-before-arrival per consume; upper bound is a planning bound, not an observed count'}


def build_preflight(root,scale):
    root=Path(root);count=SCALES[scale]
    for name in ('network.pcap','process.csv','offline-profile.json','replay-profile.json'):
        path=root/name
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1:raise ValueError('ordinary_density_source_required')
    resolve,fingerprint,validate=_runtime()
    raw={name:{'sha256':_sha(root/name),'size_bytes':(root/name).stat().st_size} for name in ('network.pcap','process.csv')}
    if {name:row['sha256'] for name,row in raw.items()}!=RAW_SHA256[scale]:raise ValueError('density_raw_specification_changed')
    profiles=_expected_profiles(count);math=density_budget_math(scale);modes={}
    for mode,name in (('dual_source','offline-profile.json'),('dual_source_replay','replay-profile.json')):
        config=json.loads((root/name).read_text())
        if config!=profiles[mode]:raise ValueError('density_profile_or_schedule_changed')
        validate(config);budget=resolve(config);issues=[]
        def fail(code,required,limit,kind='known_conflict'):
            issues.append({'code':code,'required':required,'limit':limit,'kind':kind})
        for code,required,limit in (
                ('operation_budget',count,budget.operations),('change_budget',count-1,budget.changes),
                ('frame_budget',2*count,budget.frames),('process_record_budget',count,budget.process_records),
                ('profile_byte_budget',(root/name).stat().st_size,budget.profile_bytes),
                ('network_file_byte_budget',raw['network.pcap']['size_bytes'],budget.network_file_bytes),
                ('network_total_byte_budget',raw['network.pcap']['size_bytes'],budget.network_total_bytes),
                ('process_byte_budget',raw['process.csv']['size_bytes'],budget.process_bytes)):
            if required>limit:fail(code,required,limit)
        if math['candidate_count_lower_bound']>budget.candidates:fail('candidate_lower_bound_exceeds_budget',math['candidate_count_lower_bound'],budget.candidates)
        output=math['offline_flat_output_lower_bound_bytes' if mode=='dual_source' else 'replay_flat_output_lower_bound_bytes']
        if output>budget.output_bytes:fail('flat_output_lower_bound_exceeds_budget',output,budget.output_bytes)
        if mode=='dual_source_replay':
            options=config['replay']
            if math['arrival_steps']>budget.arrival_steps:fail('arrival_budget',math['arrival_steps'],budget.arrival_steps)
            if math['snapshot_lower_bound']>options['max_snapshots']:fail('snapshot_lower_bound_exceeds_budget',math['snapshot_lower_bound'],options['max_snapshots'])
            elif math['snapshot_upper_bound']>options['max_snapshots']:fail('snapshot_coverage_not_proven',math['snapshot_upper_bound'],options['max_snapshots'],'conservative_planning_gap')
            if math['revision_upper_bound']>options['max_revisions']:fail('revision_coverage_not_proven',math['revision_upper_bound'],options['max_revisions'],'conservative_planning_gap')
        modes[mode]={'status':'blocked_budget_design' if issues else 'admissible_for_formal_attempt',
                     'profile':name,'profile_sha256':_sha(root/name),'config_fingerprint':fingerprint(config),
                     'capacity_profile':budget.version,'history_format':config.get('replay',{}).get('history_format'),
                     'budget':asdict(budget),'output_lower_bound_bytes':output,'issues':issues}
    return {'schema_version':PREFLIGHT_VERSION,'fixture_version':CAPACITY_VERSION,'scale':scale,
            'generator_sha256':_sha(Path(__file__)),'raw_inputs':raw,'density_math':math,'modes':modes,
            'admission_scope':'necessary static budget checks only; admission is permission to attempt, not runtime/performance/reference/industrial acceptance'}


def read_preflight(case_manifest, *, require_new=False):
    """Formal-harness hook: sibling preflight.json, recomputed, version/binding checked.

    Legacy directories without this file return None. A supplied preflight must
    match actual frozen raw bytes, exact profiles/schedule and current budgets;
    editing its issue list cannot bypass the planning refusal.
    """
    case_manifest=Path(case_manifest);path=case_manifest.parent/'preflight.json'
    if path.is_symlink():raise ValueError('ordinary_density_preflight_required')
    if not path.exists():
        marker=case_manifest.parent/'fixture.json'
        declared=json.loads(marker.read_text()) if marker.is_file() else {}
        if require_new or declared.get('schema_version')==CAPACITY_VERSION:raise ValueError('density_preflight_missing')
        return None
    if not path.is_file() or path.stat().st_nlink!=1:raise ValueError('ordinary_density_preflight_required')
    case=json.loads(case_manifest.read_text());stored=json.loads(path.read_text())
    if stored.get('schema_version')!=PREFLIGHT_VERSION or case.get('scale') not in SCALES:
        raise ValueError('unsupported_density_preflight')
    expected=build_preflight(path.parent,case['scale'])
    declared_generator=stored.get('generator_sha256')
    if not isinstance(declared_generator,str) or len(declared_generator)!=64 or any(c not in '0123456789abcdef' for c in declared_generator):raise ValueError('density_generator_digest_invalid')
    # This is a declared generation identity, not custody proof. Future source
    # comments/refactors do not invalidate the same version/raw/config/math.
    expected['generator_sha256']=declared_generator
    if stored!=expected:raise ValueError('density_preflight_or_bindings_changed')
    mode=case.get('mode')
    if mode not in expected['modes'] or case.get('profile')!=expected['modes'][mode]['profile'] or case.get('networks')!=['network.pcap'] or case.get('process')!='process.csv':
        raise ValueError('density_case_profile_mismatch')
    return {'path':str(path.resolve()),'sha256':_sha(path),'case_manifest_sha256':_sha(case_manifest),'generator_sha256':declared_generator,'schema_version':PREFLIGHT_VERSION,
            'fixture_version':CAPACITY_VERSION,'scale':case['scale'],'mode':mode,'density_math':expected['density_math'],
            'admission_scope':expected['admission_scope'],**expected['modes'][mode]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scale', choices=('S', 'M', 'L'), required=True)
    parser.add_argument('--version',choices=(LEGACY_VERSION,CAPACITY_VERSION),default=LEGACY_VERSION)
    args = parser.parse_args(); print(json.dumps(generate(args.output, args.scale,version=args.version)))


if __name__ == '__main__': main()
