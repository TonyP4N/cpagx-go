#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_processor_optimized.py
---------------------------
Optimized PCAP/PCAPNG processor for enhanced CPAG unit generation.

Features:
- Advanced industrial protocol analysis (ENIP/CIP, Modbus, DNP3, etc.)
- Deep packet inspection for better attack detection
- Time-series analysis of network traffic patterns
- Advanced anomaly detection
- Attack sequence reconstruction
"""

import struct
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import ipaddress


class OptimizedPCAPProcessor:
    """Enhanced PCAP processor with advanced analysis capabilities"""
    
    def __init__(self, base_processor):
        self.base_processor = base_processor
        self.confidence_calculator = base_processor.confidence_calculator
        
        # Industrial protocol ports
        self.industrial_ports = {
            44818: 'ENIP/CIP',
            502: 'Modbus',
            20000: 'DNP3',
            102: 'S7',
            2222: 'IEC-104',
            47808: 'BACnet'
        }
        
        # Attack patterns
        self.attack_patterns = {
            'scan': {'threshold': 10, 'window': 60},  # 10+ targets in 60s
            'flood': {'threshold': 100, 'window': 10},  # 100+ packets in 10s
            'injection': {'threshold': 5, 'window': 30},  # 5+ writes in 30s
            'replay': {'threshold': 0.9, 'window': 300}  # 90% similarity in 5min
        }
    
    def process_pcap_optimized(self, file_path: str, file_type: str, 
                              custom_params: Optional[Dict[str, Any]] = None,
                              **kwargs) -> Dict[str, Any]:
        """Process PCAP file with enhanced analysis"""
        
        # Get parameters
        params = custom_params or {}
        anomaly_threshold = params.get('anomaly_threshold', 3.0)
        time_window = params.get('time_window_size', 300)  # seconds
        
        # Parse PCAP data
        if file_type == 'pcapng':
            df = self._parse_pcapng_enhanced(file_path, **kwargs)
        else:
            df = self._parse_pcap_enhanced(file_path, **kwargs)
        
        if df.empty:
            return {
                'status': 'success',
                'units': [],
                'graph_data': {'nodes': [], 'edges': []},
                'stats': {'packets_processed': 0}
            }
        
        # Enhanced analysis
        cpag_units = []
        
        # 1. Protocol-specific analysis
        protocol_units = self._analyze_industrial_protocols(df)
        cpag_units.extend(protocol_units)
        
        # 2. Attack pattern detection
        attack_units = self._detect_attack_patterns(df, time_window)
        cpag_units.extend(attack_units)
        
        # 3. Anomaly detection
        anomaly_units = self._detect_network_anomalies(df, anomaly_threshold)
        cpag_units.extend(anomaly_units)
        
        # 4. Session analysis
        session_units = self._analyze_sessions(df)
        cpag_units.extend(session_units)
        
        # 5. Time-series analysis
        temporal_units = self._analyze_temporal_patterns(df, time_window)
        cpag_units.extend(temporal_units)
        
        # Remove duplicates and enhance relationships
        cpag_units = self._deduplicate_and_enhance(cpag_units)
        
        # Build graph
        graph_data = self._build_enhanced_graph(cpag_units, df)
        
        return {
            'status': 'success',
            'units': cpag_units,
            'graph_data': graph_data,
            'stats': {
                'packets_processed': len(df),
                'cpag_units': len(cpag_units),
                'protocols': df['protocol'].value_counts().to_dict() if 'protocol' in df else {},
                'attack_patterns': len([u for u in cpag_units if u['category'] == 'attack_execution'])
            }
        }
    
    def _parse_pcapng_enhanced(self, file_path: str, **kwargs) -> pd.DataFrame:
        """Enhanced PCAPNG parsing with deep packet inspection"""
        records = []
        
        # Use base parser first
        base_df = self.base_processor._parse_pcapng_enip_requests(
            file_path, 
            kwargs.get('max_pkts', 200000),
            kwargs.get('target_cip', 8000)
        )
        
        # Convert to enhanced format
        for _, row in base_df.iterrows():
            record = {
                'timestamp': row.get('timestamp', pd.Timestamp.now()),
                'src': row.get('src', ''),
                'dst': row.get('dst', ''),
                'sport': row.get('sport', 0),
                'dport': row.get('dport', 44818),
                'protocol': 'ENIP/CIP',
                'service': row.get('service_name', ''),
                'path': row.get('path', ''),
                'size': row.get('size', 0),
                'flags': row.get('flags', ''),
                'payload_hash': self._hash_payload(row.get('payload', b''))
            }
            records.append(record)
        
        # Create DataFrame with enhanced features
        df = pd.DataFrame(records)
        
        if not df.empty:
            # Add derived features
            df['is_write'] = df['service'].str.contains('Write', case=False, na=False)
            df['is_read'] = df['service'].str.contains('Read', case=False, na=False)
            df['is_scan'] = self._detect_scanning_behavior(df)
            df['session_id'] = self._assign_session_ids(df)
            
        return df
    
    def _analyze_industrial_protocols(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyze industrial protocol specific patterns"""
        units = []
        
        # Group by protocol and analyze
        for protocol in df['protocol'].unique():
            protocol_df = df[df['protocol'] == protocol]
            
            # Analyze write operations
            writes = protocol_df[protocol_df['is_write']]
            if len(writes) > 0:
                # Group consecutive writes
                write_sequences = self._group_consecutive_operations(writes)
                
                for seq in write_sequences:
                    if len(seq) >= 3:  # Sequence of 3+ writes
                        unit = {
                            'id': f"PROTOCOL_WRITE_SEQ_{protocol}_{seq.iloc[0]['dst']}_{len(seq)}",
                            'category': 'attack_execution',
                            'type': 'protocol_manipulation',
                            'precondition': [
                                f"{protocol} write access to {seq.iloc[0]['dst']}",
                                "Knowledge of target tags/registers"
                            ],
                            'action': f"Sequential {protocol} writes to {len(seq)} tags",
                            'postcondition': [
                                "Process values modified",
                                f"{len(seq)} control points potentially compromised"
                            ],
                            'confidence': self._calculate_sequence_confidence(seq),
                            'evidence': {
                                'count': len(seq),
                                'targets': seq['path'].unique().tolist(),
                                'duration': (seq.iloc[-1]['timestamp'] - seq.iloc[0]['timestamp']).total_seconds()
                            }
                        }
                        units.append(unit)
            
            # Analyze reconnaissance patterns
            reads = protocol_df[protocol_df['is_read']]
            if len(reads) > 10:
                read_patterns = self._analyze_read_patterns(reads)
                for pattern in read_patterns:
                    units.append(pattern)
        
        return units
    
    def _detect_attack_patterns(self, df: pd.DataFrame, time_window: int) -> List[Dict[str, Any]]:
        """Detect known attack patterns in network traffic"""
        units = []
        
        # 1. Port scanning detection
        scan_units = self._detect_port_scanning(df, time_window)
        units.extend(scan_units)
        
        # 2. DoS/DDoS detection
        flood_units = self._detect_flooding_attacks(df, time_window)
        units.extend(flood_units)
        
        # 3. Command injection detection
        injection_units = self._detect_command_injection(df)
        units.extend(injection_units)
        
        # 4. Replay attack detection
        replay_units = self._detect_replay_attacks(df, time_window)
        units.extend(replay_units)
        
        # 5. Man-in-the-middle indicators
        mitm_units = self._detect_mitm_indicators(df)
        units.extend(mitm_units)
        
        return units
    
    def _detect_network_anomalies(self, df: pd.DataFrame, threshold: float) -> List[Dict[str, Any]]:
        """Detect anomalies in network traffic patterns"""
        units = []
        
        # 1. Traffic volume anomalies
        if 'timestamp' in df.columns:
            # Group by time windows
            df['time_bin'] = pd.to_datetime(df['timestamp']).dt.floor('1min')
            traffic_stats = df.groupby('time_bin').agg({
                'size': ['count', 'sum', 'mean'],
                'dst': 'nunique'
            })
            
            # Detect anomalies using statistical methods
            for metric in ['count', 'sum']:
                values = traffic_stats['size'][metric].values
                if len(values) > 10:
                    mean = np.mean(values)
                    std = np.std(values)
                    anomalies = values[np.abs(values - mean) > threshold * std]
                    
                    if len(anomalies) > 0:
                        unit = {
                            'id': f"ANOMALY_TRAFFIC_{metric.upper()}",
                            'category': 'anomaly_detection',
                            'type': 'traffic_anomaly',
                            'precondition': ["Network access"],
                            'action': f"Abnormal traffic {metric} detected",
                            'postcondition': ["Potential attack in progress"],
                            'confidence': min(0.9, len(anomalies) / len(values)),
                            'evidence': {
                                'anomaly_count': len(anomalies),
                                'max_deviation': float(np.max(np.abs(anomalies - mean) / std)),
                                'metric': metric
                            }
                        }
                        units.append(unit)
        
        # 2. Protocol anomalies
        protocol_anomalies = self._detect_protocol_anomalies(df)
        units.extend(protocol_anomalies)
        
        # 3. Timing anomalies
        timing_anomalies = self._detect_timing_anomalies(df, threshold)
        units.extend(timing_anomalies)
        
        return units
    
    def _analyze_sessions(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyze network sessions for suspicious patterns"""
        units = []
        
        if 'session_id' not in df.columns:
            return units
        
        # Analyze each session
        for session_id in df['session_id'].unique():
            session_df = df[df['session_id'] == session_id]
            
            # Long-lived sessions
            if len(session_df) > 100:
                duration = (session_df.iloc[-1]['timestamp'] - session_df.iloc[0]['timestamp']).total_seconds()
                if duration > 3600:  # 1 hour
                    unit = {
                        'id': f"SESSION_PERSISTENT_{session_id}",
                        'category': 'persistence',
                        'type': 'long_session',
                        'precondition': ["Initial network access"],
                        'action': f"Maintained session for {duration/3600:.1f} hours",
                        'postcondition': ["Persistent access established"],
                        'confidence': 0.8,
                        'evidence': {
                            'duration': duration,
                            'packet_count': len(session_df),
                            'data_volume': session_df['size'].sum()
                        }
                    }
                    units.append(unit)
            
            # Suspicious session patterns
            suspicious_patterns = self._analyze_session_behavior(session_df)
            units.extend(suspicious_patterns)
        
        return units
    
    def _analyze_temporal_patterns(self, df: pd.DataFrame, window_size: int) -> List[Dict[str, Any]]:
        """Analyze temporal patterns in network traffic"""
        units = []
        
        if 'timestamp' not in df.columns or len(df) < 10:
            return units
        
        # Convert timestamp
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # 1. Periodic behavior detection
        periodic_units = self._detect_periodic_behavior(df, window_size)
        units.extend(periodic_units)
        
        # 2. Burst detection
        burst_units = self._detect_traffic_bursts(df, window_size)
        units.extend(burst_units)
        
        # 3. Time-based attack patterns
        time_attack_units = self._detect_time_based_attacks(df)
        units.extend(time_attack_units)
        
        return units
    
    def _deduplicate_and_enhance(self, units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicates and enhance unit relationships"""
        # Remove exact duplicates
        seen = set()
        unique_units = []
        
        for unit in units:
            unit_key = (unit['id'], unit['category'], unit.get('type', ''))
            if unit_key not in seen:
                seen.add(unit_key)
                unique_units.append(unit)
        
        # Calculate confidence for each unit
        for unit in unique_units:
            if 'confidence' not in unit:
                unit['confidence'] = self.confidence_calculator.calculate_confidence(unit)
        
        # Analyze relationships for all units together
        relationship_info = self.base_processor.relationship_analyzer.analyze_unit_relationships(unique_units)
        
        # Apply relationship enhancements to individual units
        enhanced_units = self.base_processor.relationship_analyzer.enhance_cpag_units_with_relationships(unique_units)
        
        # Sort by importance
        enhanced_units.sort(key=lambda x: (
            x['category'] == 'attack_execution',
            x.get('confidence', 0),
            x.get('evidence', {}).get('count', 0)
        ), reverse=True)
        
        return enhanced_units
    
    def _build_enhanced_graph(self, units: List[Dict[str, Any]], df: pd.DataFrame) -> Dict[str, Any]:
        """Build enhanced graph structure with attack paths"""
        nodes = []
        edges = []
        
        # Create nodes
        for unit in units:
            node = {
                'id': unit['id'],
                'label': unit.get('action', ''),
                'type': unit.get('type', 'action'),
                'category': unit['category'],
                'confidence': unit.get('confidence', 0.5)
            }
            
            # Flatten evidence for Neo4j compatibility
            evidence = unit.get('evidence', {})
            if evidence:
                # Add primitive types directly
                for key, value in evidence.items():
                    if isinstance(value, (str, int, float, bool)):
                        node[f'evidence_{key}'] = value
                    elif isinstance(value, list) and all(isinstance(x, (str, int, float, bool)) for x in value):
                        # Neo4j can handle arrays of primitives
                        node[f'evidence_{key}'] = value
                    else:
                        # Convert complex types to string
                        node[f'evidence_{key}'] = str(value)
            
            nodes.append(node)
        
        # Build edges based on temporal and logical relationships
        edges = self._build_attack_path_edges(units, df)
        
        return {'nodes': nodes, 'edges': edges}
    
    # Helper methods
    def _hash_payload(self, payload: bytes) -> str:
        """Hash payload for comparison"""
        import hashlib
        return hashlib.md5(payload).hexdigest() if payload else ''
    
    def _detect_scanning_behavior(self, df: pd.DataFrame) -> pd.Series:
        """Detect if packets are part of scanning behavior"""
        # Simple heuristic: many destinations in short time
        result = pd.Series(False, index=df.index)
        
        if 'timestamp' in df.columns:
            df_sorted = df.sort_values('timestamp')
            for i in range(len(df_sorted)):
                # Check next 10 packets
                window = df_sorted.iloc[i:i+10]
                if len(window['dst'].unique()) > 5:
                    result.iloc[i] = True
        
        return result
    
    def _assign_session_ids(self, df: pd.DataFrame) -> pd.Series:
        """Assign session IDs based on src/dst pairs and timing"""
        session_map = {}
        session_id = 0
        sessions = []
        
        for _, row in df.iterrows():
            key = (row['src'], row['dst'], row['dport'])
            if key not in session_map:
                session_map[key] = session_id
                session_id += 1
            sessions.append(session_map[key])
        
        return pd.Series(sessions)
    
    def _group_consecutive_operations(self, df: pd.DataFrame) -> List[pd.DataFrame]:
        """Group consecutive operations by time proximity"""
        groups = []
        if df.empty:
            return groups
        
        df_sorted = df.sort_values('timestamp')
        current_group = [df_sorted.iloc[0]]
        
        for i in range(1, len(df_sorted)):
            time_diff = (df_sorted.iloc[i]['timestamp'] - df_sorted.iloc[i-1]['timestamp']).total_seconds()
            if time_diff < 60:  # Within 1 minute
                current_group.append(df_sorted.iloc[i])
            else:
                if len(current_group) > 1:
                    groups.append(pd.DataFrame(current_group))
                current_group = [df_sorted.iloc[i]]
        
        if len(current_group) > 1:
            groups.append(pd.DataFrame(current_group))
        
        return groups
    
    def _calculate_sequence_confidence(self, seq: pd.DataFrame) -> float:
        """Calculate confidence for operation sequence"""
        base_confidence = 0.7
        
        # Increase confidence for:
        # - More operations in sequence
        if len(seq) > 5:
            base_confidence += 0.1
        # - Shorter time span
        duration = (seq.iloc[-1]['timestamp'] - seq.iloc[0]['timestamp']).total_seconds()
        if duration < 30:
            base_confidence += 0.1
        # - Same target device
        if len(seq['dst'].unique()) == 1:
            base_confidence += 0.05
        
        return min(0.95, base_confidence)
    
    def _analyze_read_patterns(self, reads: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyze read patterns for reconnaissance"""
        units = []
        
        # Detect systematic reading
        if len(reads) > 20:
            targets = reads['path'].value_counts()
            if len(targets) > 10:
                unit = {
                    'id': f"RECON_SYSTEMATIC_READ_{reads.iloc[0]['dst']}",
                    'category': 'reconnaissance',
                    'type': 'systematic_enumeration',
                    'precondition': ["Read access to target"],
                    'action': f"Systematic enumeration of {len(targets)} tags",
                    'postcondition': ["Process knowledge acquired"],
                    'confidence': 0.85,
                    'evidence': {
                        'tag_count': len(targets),
                        'read_count': len(reads),
                        'top_targets': targets.head(5).to_dict()
                    }
                }
                units.append(unit)
        
        return units
    
    def _detect_port_scanning(self, df: pd.DataFrame, window: int) -> List[Dict[str, Any]]:
        """Detect port scanning activities"""
        units = []
        
        # Group by source and time window
        if 'timestamp' in df.columns:
            df['time_window'] = pd.to_datetime(df['timestamp']).dt.floor(f'{window}s')
            scan_stats = df.groupby(['src', 'time_window']).agg({
                'dst': 'nunique',
                'dport': 'nunique'
            })
            
            # Detect scanning
            for (src, time_window), stats in scan_stats.iterrows():
                if stats['dst'] > 10 or stats['dport'] > 10:
                    unit = {
                        'id': f"SCAN_{src}_{time_window}",
                        'category': 'reconnaissance',
                        'type': 'port_scan',
                        'precondition': ["Network access"],
                        'action': f"Port scanning from {src}",
                        'postcondition': ["Network topology discovered"],
                        'confidence': min(0.9, stats['dst'] / 20),
                        'evidence': {
                            'unique_targets': int(stats['dst']),
                            'unique_ports': int(stats['dport']),
                            'source': src
                        }
                    }
                    units.append(unit)
        
        return units
    
    def _detect_flooding_attacks(self, df: pd.DataFrame, window: int) -> List[Dict[str, Any]]:
        """Detect flooding/DoS attacks"""
        units = []
        
        if 'timestamp' in df.columns:
            # Calculate packet rate
            df['time_window'] = pd.to_datetime(df['timestamp']).dt.floor(f'{window}s')
            flood_stats = df.groupby(['dst', 'time_window']).size()
            
            # Detect high packet rates
            threshold = self.attack_patterns['flood']['threshold']
            floods = flood_stats[flood_stats > threshold]
            
            for (dst, time_window), count in floods.items():
                unit = {
                    'id': f"FLOOD_{dst}_{time_window}",
                    'category': 'attack_impact',
                    'type': 'dos_attack',
                    'precondition': ["Network access to target"],
                    'action': f"Flooding attack on {dst}",
                    'postcondition': ["Service disruption", "Resource exhaustion"],
                    'confidence': min(0.95, count / (threshold * 2)),
                    'evidence': {
                        'packet_count': int(count),
                        'packet_rate': count / window,
                        'target': dst
                    }
                }
                units.append(unit)
        
        return units
    
    def _detect_command_injection(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect command injection attempts"""
        units = []
        
        # Look for write operations with suspicious patterns
        writes = df[df['is_write'] == True]
        
        for _, write in writes.iterrows():
            # Check for injection patterns
            if self._is_suspicious_write(write):
                unit = {
                    'id': f"INJECTION_{write['dst']}_{write['path']}",
                    'category': 'attack_execution',
                    'type': 'command_injection',
                    'precondition': ["Write access to target", "Knowledge of protocol"],
                    'action': f"Potential command injection to {write['path']}",
                    'postcondition': ["Unauthorized command execution", "Process manipulation"],
                    'confidence': 0.75,
                    'evidence': {
                        'target': write['dst'],
                        'path': write['path'],
                        'service': write.get('service', '')
                    }
                }
                units.append(unit)
        
        return units
    
    def _detect_replay_attacks(self, df: pd.DataFrame, window: int) -> List[Dict[str, Any]]:
        """Detect replay attacks"""
        units = []
        
        # Group packets by payload hash
        if 'payload_hash' in df.columns:
            hash_counts = df['payload_hash'].value_counts()
            repeated_hashes = hash_counts[hash_counts > 5]
            
            for hash_val, count in repeated_hashes.items():
                if hash_val:  # Skip empty payloads
                    matching = df[df['payload_hash'] == hash_val]
                    time_span = (matching['timestamp'].max() - matching['timestamp'].min()).total_seconds()
                    
                    if time_span > 60:  # Repeated over more than 1 minute
                        unit = {
                            'id': f"REPLAY_{hash_val[:8]}",
                            'category': 'attack_execution',
                            'type': 'replay_attack',
                            'precondition': ["Captured legitimate traffic"],
                            'action': "Replay attack detected",
                            'postcondition': ["Unauthorized operations", "Authentication bypass"],
                            'confidence': min(0.9, count / 10),
                            'evidence': {
                                'replay_count': int(count),
                                'time_span': time_span,
                                'targets': matching['dst'].unique().tolist()
                            }
                        }
                        units.append(unit)
        
        return units
    
    def _detect_mitm_indicators(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect Man-in-the-Middle indicators"""
        units = []
        
        # Look for ARP spoofing patterns, unusual routing, etc.
        # This is simplified - real implementation would be more complex
        
        # Check for unusual source/destination patterns
        src_dst_pairs = df.groupby(['src', 'dst']).size()
        
        # Detect potential MITM based on traffic patterns
        for (src, dst), count in src_dst_pairs.items():
            reverse_count = src_dst_pairs.get((dst, src), 0)
            if count > 100 and reverse_count > 100:
                # High bidirectional traffic might indicate MITM
                unit = {
                    'id': f"MITM_INDICATOR_{src}_{dst}",
                    'category': 'attack_execution',
                    'type': 'mitm_indicator',
                    'precondition': ["Network position between targets"],
                    'action': f"Potential MITM between {src} and {dst}",
                    'postcondition': ["Traffic interception", "Data manipulation"],
                    'confidence': 0.6,
                    'evidence': {
                        'forward_packets': int(count),
                        'reverse_packets': int(reverse_count),
                        'src': src,
                        'dst': dst
                    }
                }
                units.append(unit)
        
        return units
    
    def _detect_protocol_anomalies(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect protocol-specific anomalies"""
        units = []
        
        # Check for unusual protocol usage
        if 'protocol' in df.columns and 'dport' in df.columns:
            for protocol, port in self.industrial_ports.items():
                protocol_df = df[df['dport'] == port]
                if len(protocol_df) > 0:
                    # Check for anomalies in protocol usage
                    anomaly = self._check_protocol_anomaly(protocol_df, protocol)
                    if anomaly:
                        units.append(anomaly)
        
        return units
    
    def _detect_timing_anomalies(self, df: pd.DataFrame, threshold: float) -> List[Dict[str, Any]]:
        """Detect timing anomalies in traffic"""
        units = []
        
        if 'timestamp' in df.columns and len(df) > 100:
            # Calculate inter-packet times
            df_sorted = df.sort_values('timestamp')
            df_sorted['time_diff'] = df_sorted['timestamp'].diff().dt.total_seconds()
            
            # Detect anomalies
            time_diffs = df_sorted['time_diff'].dropna()
            mean_diff = time_diffs.mean()
            std_diff = time_diffs.std()
            
            anomalies = time_diffs[np.abs(time_diffs - mean_diff) > threshold * std_diff]
            
            if len(anomalies) > 5:
                unit = {
                    'id': 'TIMING_ANOMALY',
                    'category': 'anomaly_detection',
                    'type': 'timing_anomaly',
                    'precondition': ["Network access"],
                    'action': "Abnormal timing patterns detected",
                    'postcondition': ["Potential covert channel", "Attack in progress"],
                    'confidence': min(0.8, len(anomalies) / len(time_diffs)),
                    'evidence': {
                        'anomaly_count': len(anomalies),
                        'max_deviation': float(anomalies.max()),
                        'mean_interval': float(mean_diff)
                    }
                }
                units.append(unit)
        
        return units
    
    def _analyze_session_behavior(self, session_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyze session behavior for suspicious patterns"""
        units = []
        
        # Check for session hijacking indicators
        if len(session_df) > 20:
            # Look for sudden changes in behavior
            mid_point = len(session_df) // 2
            first_half = session_df.iloc[:mid_point]
            second_half = session_df.iloc[mid_point:]
            
            # Compare behavior patterns
            if self._behavior_changed(first_half, second_half):
                unit = {
                    'id': f"SESSION_HIJACK_{session_df.iloc[0]['session_id']}",
                    'category': 'credential_access',
                    'type': 'session_hijacking',
                    'precondition': ["Valid session exists"],
                    'action': "Potential session hijacking detected",
                    'postcondition': ["Unauthorized access", "Identity theft"],
                    'confidence': 0.7,
                    'evidence': {
                        'session_length': len(session_df),
                        'behavior_change_point': mid_point
                    }
                }
                units.append(unit)
        
        return units
    
    def _detect_periodic_behavior(self, df: pd.DataFrame, window: int) -> List[Dict[str, Any]]:
        """Detect periodic behavior in traffic"""
        units = []
        
        # Simple periodicity detection using FFT
        if len(df) > 100:
            # Create time series
            ts = df.set_index('timestamp').resample('1min').size()
            
            if len(ts) > 10:
                # Detect periodicity
                from scipy.fft import fft
                fft_vals = np.abs(fft(ts.values))
                freqs = np.fft.fftfreq(len(ts))
                
                # Find dominant frequencies
                peak_idx = np.argmax(fft_vals[1:len(fft_vals)//2]) + 1
                if fft_vals[peak_idx] > np.mean(fft_vals) * 3:
                    period = 1 / freqs[peak_idx]
                    
                    unit = {
                        'id': 'PERIODIC_BEHAVIOR',
                        'category': 'command_control',
                        'type': 'beaconing',
                        'precondition': ["Established C2 channel"],
                        'action': f"Periodic communication detected (period: {period:.1f} min)",
                        'postcondition': ["Active C2 communication"],
                        'confidence': 0.8,
                        'evidence': {
                            'period_minutes': float(period),
                            'strength': float(fft_vals[peak_idx] / np.mean(fft_vals))
                        }
                    }
                    units.append(unit)
        
        return units
    
    def _detect_traffic_bursts(self, df: pd.DataFrame, window: int) -> List[Dict[str, Any]]:
        """Detect traffic bursts"""
        units = []
        
        if 'timestamp' in df.columns:
            # Detect bursts using sliding window
            df['time_bin'] = pd.to_datetime(df['timestamp']).dt.floor(f'{window}s')
            burst_counts = df.groupby('time_bin').size()
            
            # Detect significant increases
            if len(burst_counts) > 3:
                burst_threshold = burst_counts.mean() + 2 * burst_counts.std()
                bursts = burst_counts[burst_counts > burst_threshold]
                
                for time_bin, count in bursts.items():
                    unit = {
                        'id': f"TRAFFIC_BURST_{time_bin}",
                        'category': 'execution',
                        'type': 'traffic_burst',
                        'precondition': ["Network access"],
                        'action': f"Traffic burst detected at {time_bin}",
                        'postcondition': ["Potential data exfiltration", "Attack execution"],
                        'confidence': min(0.85, count / (burst_threshold * 1.5)),
                        'evidence': {
                            'packet_count': int(count),
                            'burst_factor': float(count / burst_counts.mean()),
                            'timestamp': str(time_bin)
                        }
                    }
                    units.append(unit)
        
        return units
    
    def _detect_time_based_attacks(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect attacks based on timing patterns"""
        units = []
        
        # Detect attacks during off-hours
        if 'timestamp' in df.columns:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            
            # Off-hours activity (e.g., 10 PM - 6 AM)
            off_hours = df[(df['hour'] >= 22) | (df['hour'] <= 6)]
            
            if len(off_hours) > 50:
                # Significant off-hours activity
                unit = {
                    'id': 'OFF_HOURS_ACTIVITY',
                    'category': 'defense_evasion',
                    'type': 'timing_evasion',
                    'precondition': ["Network access"],
                    'action': "Suspicious off-hours activity",
                    'postcondition': ["Undetected operations"],
                    'confidence': 0.7,
                    'evidence': {
                        'off_hours_packets': len(off_hours),
                        'percentage': len(off_hours) / len(df) * 100,
                        'peak_hour': int(off_hours['hour'].mode()[0]) if not off_hours.empty else 0
                    }
                }
                units.append(unit)
        
        return units
    
    def _is_suspicious_write(self, write: pd.Series) -> bool:
        """Check if a write operation is suspicious"""
        # Implement heuristics for suspicious writes
        suspicious_indicators = [
            'admin', 'config', 'system', 'password', 'key',
            'bypass', 'override', 'disable', 'enable'
        ]
        
        path = str(write.get('path', '')).lower()
        service = str(write.get('service', '')).lower()
        
        return any(indicator in path or indicator in service for indicator in suspicious_indicators)
    
    def _check_protocol_anomaly(self, protocol_df: pd.DataFrame, protocol: str) -> Optional[Dict[str, Any]]:
        """Check for protocol-specific anomalies"""
        # Implement protocol-specific checks
        if protocol == 'ENIP/CIP' and len(protocol_df) > 100:
            # Check for unusual CIP service codes
            if 'service' in protocol_df.columns:
                unusual_services = protocol_df['service'].value_counts()
                if len(unusual_services) > 20:
                    return {
                        'id': f"PROTOCOL_ANOMALY_{protocol}",
                        'category': 'anomaly_detection',
                        'type': 'protocol_anomaly',
                        'precondition': [f"{protocol} access"],
                        'action': f"Unusual {protocol} service usage detected",
                        'postcondition': ["Potential protocol abuse"],
                        'confidence': 0.65,
                        'evidence': {
                            'unique_services': len(unusual_services),
                            'protocol': protocol
                        }
                    }
        return None
    
    def _behavior_changed(self, first_half: pd.DataFrame, second_half: pd.DataFrame) -> bool:
        """Detect if behavior changed between two halves of a session"""
        # Compare key metrics
        metrics_changed = 0
        
        # Check packet rate
        if len(first_half) > 0 and len(second_half) > 0:
            rate1 = len(first_half) / (first_half['timestamp'].max() - first_half['timestamp'].min()).total_seconds()
            rate2 = len(second_half) / (second_half['timestamp'].max() - second_half['timestamp'].min()).total_seconds()
            if abs(rate1 - rate2) / max(rate1, rate2) > 0.5:
                metrics_changed += 1
        
        # Check destination diversity
        if 'dst' in first_half.columns:
            dst1 = len(first_half['dst'].unique())
            dst2 = len(second_half['dst'].unique())
            if abs(dst1 - dst2) > 5:
                metrics_changed += 1
        
        # Check service usage
        if 'service' in first_half.columns:
            services1 = set(first_half['service'].unique())
            services2 = set(second_half['service'].unique())
            if len(services1.symmetric_difference(services2)) > 3:
                metrics_changed += 1
        
        return metrics_changed >= 2
    
    def _build_attack_path_edges(self, units: List[Dict[str, Any]], df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Build edges representing attack paths"""
        edges = []
        
        # Sort units by timestamp if available
        units_with_time = []
        for unit in units:
            # Try to extract timestamp from evidence
            if 'evidence' in unit and 'timestamp' in unit['evidence']:
                units_with_time.append((unit, unit['evidence']['timestamp']))
            else:
                units_with_time.append((unit, None))
        
        # Build temporal edges
        for i, (unit1, time1) in enumerate(units_with_time):
            for j, (unit2, time2) in enumerate(units_with_time[i+1:], i+1):
                # Check if unit2 can follow unit1
                if self._can_follow(unit1, unit2):
                    edge = {
                        'source': unit1['id'],
                        'target': unit2['id'],
                        'relation': 'enables',
                        'confidence': min(unit1.get('confidence', 0.5), unit2.get('confidence', 0.5))
                    }
                    edges.append(edge)
        
        return edges
    
    def _can_follow(self, unit1: Dict[str, Any], unit2: Dict[str, Any]) -> bool:
        """Check if unit2 can follow unit1 in attack sequence"""
        # Check postcondition/precondition matching
        post1 = set(unit1.get('postcondition', []))
        pre2 = set(unit2.get('precondition', []))
        
        # Fuzzy matching for conditions
        for p1 in post1:
            for p2 in pre2:
                if self._conditions_match(p1, p2):
                    return True
        
        # Category-based rules
        category_flow = {
            'reconnaissance': ['attack_execution', 'credential_access', 'persistence'],
            'credential_access': ['attack_execution', 'persistence', 'lateral_movement'],
            'attack_execution': ['attack_impact', 'persistence', 'defense_evasion'],
            'persistence': ['command_control', 'attack_execution'],
            'command_control': ['attack_execution', 'exfiltration'],
            'lateral_movement': ['attack_execution', 'persistence']
        }
        
        cat1 = unit1.get('category', '')
        cat2 = unit2.get('category', '')
        
        return cat2 in category_flow.get(cat1, [])
    
    def _conditions_match(self, cond1: str, cond2: str) -> bool:
        """Check if two conditions match (fuzzy)"""
        # Simple keyword matching
        keywords1 = set(cond1.lower().split())
        keywords2 = set(cond2.lower().split())
        
        # Check for common keywords
        common = keywords1.intersection(keywords2)
        return len(common) >= 2 or any(k in ['access', 'knowledge', 'control'] for k in common)
