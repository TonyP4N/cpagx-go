"""Immutable opt-in capacity budgets; omission preserves historical bounds."""
from dataclasses import dataclass

ENGINEERING = 'engineering-capacity-1'
SHARED = 'engineering-capacity-2'
SHARED_FORMAT = 'shared-observation-dag-5'
COMPACT = 'engineering-core-capacity-3'
COMPACT_FORMAT = 'shared-observation-dag-6'


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
    if 'storage_budget_version' in config and (config.get('capacity_profile')!=COMPACT or config['storage_budget_version']!='shared-storage-budget-2'):
        raise ValueError('unsupported_storage_budget_version')
    if 'capacity_profile' not in config:
        if 'storage_format' in config:raise ValueError('storage_requires_explicit_capacity')
        return Budget()
    if config['capacity_profile'] not in (ENGINEERING, SHARED, COMPACT):
        raise ValueError('unsupported_capacity_profile')
    if config.get('analysis_mode') != 'bounded-real-capable-v1':
        raise ValueError('capacity_requires_bounded_analysis_mode')
    shared = config['capacity_profile'] in (SHARED,COMPACT)
    storage_format = COMPACT_FORMAT if config['capacity_profile']==COMPACT else SHARED_FORMAT
    if shared:
        if config.get('storage_format') != storage_format:raise ValueError('shared_capacity_requires_storage_format')
        if 'replay' in config and any(config['replay'].get(key) != expected for key, expected in (
                ('history_format', storage_format), ('identity_strategy', 'merkle-json-dag-1'),
                ('prefix_digest_strategy', 'incremental-prefix-digest-2'))):
            raise ValueError('shared_capacity_requires_versioned_replay')
    elif 'storage_format' in config:
        raise ValueError('storage_capacity_version_mismatch')
    return Budget(version=config['capacity_profile'], network_file_bytes=64*1024**2,
        network_total_bytes=128*1024**2, frames=100000, process_bytes=8*1024**2,
        process_records=10000, profile_bytes=8*1024**2, operations=10000,
        changes=10000, candidates=500000 if shared else 100000, output_bytes=1024**3,
        arrival_steps=40000, snapshots=65000 if shared else 45000, revisions=90000)


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


@dataclass(frozen=True)
class SharedStorageBudget:
    version: str = 'shared-storage-budget-1'
    physical_bytes: int = 1024**3
    max_nodes: int = 8_000_000
    max_roots: int = 160_000
    max_node_bytes: int = 8*1024**2
    max_dict_items: int = 4096
    cache_bytes: int = 16*1024**2
    query_bytes: int = 8*1024**2
    query_items: int = 100
    max_logical_root_bytes: int = 512*1024**3


def shared_storage_budget(config):
    if resolve_capacity_profile(config).version not in (SHARED,COMPACT):
        raise ValueError('shared_storage_budget_requires_capacity_v2')
    if config.get('storage_budget_version')=='shared-storage-budget-2':
        return SharedStorageBudget(version='shared-storage-budget-2',max_logical_root_bytes=4*1024**5)
    return SharedStorageBudget()
