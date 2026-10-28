"""Immutable opt-in capacity budgets; omission preserves historical bounds."""
from dataclasses import dataclass

ENGINEERING = 'engineering-capacity-1'


@dataclass(frozen=True)
class Budget:
    version: str = ''
    network_files: int = 4
    network_file_bytes: int = 16 * 1024**2
    network_total_bytes: int = 16 * 1024**2
    frames: int = 10000
    frame_bytes: int = 262144
    process_bytes: int = 2 * 1024**2
    process_records: int = 1000
    process_columns: int = 16
    profile_bytes: int = 65536
    operations: int = 100
    changes: int = 1000
    candidates: int = 10000
    output_bytes: int = 16 * 1024**2
    arrival_steps: int = 22000
    snapshots: int = 4096
    revisions: int = 8192


def resolve_capacity_profile(config):
    if 'capacity_profile' not in config:
        return Budget()
    if config['capacity_profile'] != ENGINEERING:
        raise ValueError('unsupported_capacity_profile')
    if config.get('analysis_mode') != 'bounded-real-capable-v1':
        raise ValueError('capacity_requires_bounded_analysis_mode')
    return Budget(version=ENGINEERING, network_file_bytes=64*1024**2,
        network_total_bytes=128*1024**2, frames=100000, process_bytes=8*1024**2,
        process_records=10000, profile_bytes=8*1024**2, operations=10000,
        changes=10000, candidates=100000, output_bytes=1024**3,
        arrival_steps=40000, snapshots=45000, revisions=90000)


def parser_limits(config):
    # Lazy imports avoid changing default parser initialization or import cycles.
    from .parsers.packet_envelope import Limits
    from .parsers import ProcessLimits
    from .packet_pipeline import CaptureSetLimits, StreamLimits
    b = resolve_capacity_profile(config)
    stream = StreamLimits() if not b.version else StreamLimits(max_streams=128,
        max_segments=100000, max_stream_bytes=128*1024**2, max_pdus=100000,
        max_capture_seconds=1800, max_processing_seconds=1800)
    return {'packet_limits': Limits(b.network_file_bytes,b.frames,b.frame_bytes),
            'capture_limits': CaptureSetLimits(b.network_files,b.network_total_bytes,b.frames),
            'process_limits': ProcessLimits(b.process_bytes,b.process_records,b.process_columns),
            'stream_limits': stream}
