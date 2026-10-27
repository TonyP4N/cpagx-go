#!/usr/bin/env python3
"""Generate dense raw synthetic R19 PCAP/CSV; never reads analysis or gold labels.

S/M/L preserve 100/1000/10000 request operations and the same logical CSV count.
These are density cases, not the independent 128MiB/64MiB/8MiB byte boundaries.
Replay includes every request, response, CSV header and row without dropping data.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import struct

from round17_profile import profile

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


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


def generate(root, scale):
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
    (root / 'fixture.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scale', choices=('S', 'M', 'L'), required=True)
    args = parser.parse_args(); print(json.dumps(generate(args.output, args.scale)))


if __name__ == '__main__': main()
