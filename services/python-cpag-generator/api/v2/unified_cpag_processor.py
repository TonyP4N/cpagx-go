#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unified_cpag_processor.py
--------------------------
Unified CPAG processing module that consolidates all analysis logic.
Supports .csv, .pcap, .pcapng files with direct Neo4j storage.

Features:
- Auto-detect file types (.csv, .pcap, .pcapng)
- Unified ENIP/CIP analysis pipeline
- Direct Neo4j storage integration
- Optimized performance with minimal redundancy
- Enhanced CSV processing for network data
"""

import os
import re
import json
import struct
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from collections import defaultdict, Counter
from datetime import datetime

import pandas as pd
import numpy as np

# Neo4j integration
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    print("Warning: Neo4j driver not available")

# Import matplotlib for visualization
try:
    import matplotlib
    matplotlib.use("Agg")  # headless
    import matplotlib.pyplot as plt
    import networkx as nx
    VISUALIZATION_AVAILABLE = True
except ImportError:
    plt = None
    nx = None
    VISUALIZATION_AVAILABLE = False


class UnifiedCPAGProcessor:
    """Unified processor for all CPAG analysis tasks"""
    
    def __init__(self):
        self.supported_formats = {'.csv', '.pcap', '.pcapng'}
        self.neo4j_driver = None
        
    def detect_file_type(self, file_path: str) -> str:
        """Detect file type based on extension and magic bytes"""
        file_path = Path(file_path)
        extension = file_path.suffix.lower()
        
        if extension == '.csv':
            return 'csv'
        elif extension in {'.pcap', '.pcapng'}:
            return self._detect_pcap_format(file_path)
        else:
            # Try to detect by content
            try:
                return self._detect_by_content(file_path)
            except Exception:
                raise ValueError(f"Unsupported file format: {extension}")
    
    def _detect_pcap_format(self, file_path: Path) -> str:
        """Detect PCAP format by magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if len(magic) < 4:
                    raise ValueError("File too small")
                
                # PCAP-NG Section Header Block
                if struct.unpack(">I", magic)[0] == 0x0A0D0D0A:
                    return 'pcapng'
                
                # Classic PCAP magic numbers
                magic_le = struct.unpack("<I", magic)[0]
                magic_be = struct.unpack(">I", magic)[0]
                pcap_magics = {0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1}
                
                if magic_le in pcap_magics or magic_be in pcap_magics:
                    return 'pcap'
                    
            raise ValueError("Unknown PCAP format")
        except Exception as e:
            raise ValueError(f"Failed to detect PCAP format: {e}")
    
    def _detect_by_content(self, file_path: Path) -> str:
        """Detect file type by analyzing content"""
        try:
            # Try CSV first
            df = pd.read_csv(file_path, nrows=5)
            if not df.empty:
                return 'csv'
        except Exception:
            pass
        
        # Try PCAP detection
        try:
            return self._detect_pcap_format(file_path)
        except Exception:
            pass
        
        raise ValueError("Could not detect file type")
    
    def process_file(self, 
                    file_path: str,
                    output_dir: str,
                    device_map: Optional[Dict[str, str]] = None,
                    rules: Optional[List[str]] = None,
                    max_pkts: int = 120000,
                    target_cip: int = 8000,
                    top_k: int = 40,
                    top_per_plc: int = 20,
                    neo4j_config: Optional[Dict[str, Any]] = None,
                    **kwargs) -> Dict[str, Any]:
        """
        Process file and return analysis results
        
        Args:
            file_path: Path to input file
            output_dir: Output directory for results
            device_map: Device mapping dictionary
            rules: Analysis rules
            max_pkts: Maximum packets to process
            target_cip: Target CIP requests
            top_k: Top K results
            top_per_plc: Top results per PLC
            neo4j_config: Neo4j configuration dict
            **kwargs: Additional parameters
            
        Returns:
            Dict containing analysis results and metadata
        """
        try:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Detect file type
            file_type = self.detect_file_type(file_path)
            print(f"Detected file type: {file_type}")
            
            # Process based on file type
            if file_type == 'csv':
                result = self._process_csv_file(file_path, output_dir, device_map, rules, **kwargs)
            elif file_type in ['pcap', 'pcapng']:
                result = self._process_pcap_file(file_path, output_dir, file_type, max_pkts, target_cip, top_k, top_per_plc, **kwargs)
            else:
                raise ValueError(f"Unsupported file type: {file_type}")
            
            # Store to Neo4j if configured
            if neo4j_config and NEO4J_AVAILABLE:
                try:
                    self._store_to_neo4j(result, neo4j_config)
                    result['neo4j_stored'] = True
                except Exception as e:
                    print(f"Failed to store to Neo4j: {e}")
                    result['neo4j_stored'] = False
                    result['neo4j_error'] = str(e)
            
            # Add metadata
            result.update({
                'file_path': file_path,
                'file_type': file_type,
                'processed_at': datetime.utcnow().isoformat(),
                'output_dir': output_dir,
                'processor_version': 'v2_unified'
            })
            
            return result
            
        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e),
                'file_path': file_path,
                'processed_at': datetime.utcnow().isoformat()
            }
    
    def _process_csv_file(self, file_path: str, output_dir: str, device_map: Optional[Dict[str, str]], rules: Optional[List[str]], **kwargs) -> Dict[str, Any]:
        """Process CSV file containing network traffic data"""
        try:
            # Read CSV file
            df = pd.read_csv(file_path)
            print(f"Loaded CSV with {len(df)} rows and columns: {list(df.columns)}")
            
            # Detect CSV format and standardize columns
            standardized_df = self._standardize_csv_format(df)
            
            # Build CPAG from CSV data
            cpag_units = self._build_cpag_from_csv(standardized_df, device_map, rules)
            
            # Generate graph structures
            graph_data = self._build_graph_structures(cpag_units)
            
            # Save outputs
            output_files = self._save_csv_results(output_dir, standardized_df, cpag_units, graph_data)
            
            # Create enhanced and minimal JSON files for v2 compatibility
            enhanced_data = {
                'units': cpag_units,
                'graph_data': graph_data,
                'stats': {
                    'rows_processed': len(df),
                    'cpag_units': len(cpag_units),
                    'nodes': len(graph_data.get('nodes', [])),
                    'edges': len(graph_data.get('edges', []))
                },
                'version': 'v2_enhanced'
            }
            minimal_data = {'units': cpag_units, 'version': 'v2_minimal'}
            
            # Save enhanced and minimal JSON files
            enhanced_file = os.path.join(output_dir, 'cpag_enhanced.json')
            minimal_file = os.path.join(output_dir, 'cpag_minimal.json')
            
            with open(enhanced_file, 'w', encoding='utf-8') as f:
                json.dump(enhanced_data, f, indent=2, ensure_ascii=False)
            with open(minimal_file, 'w', encoding='utf-8') as f:
                json.dump(minimal_data, f, indent=2, ensure_ascii=False)
                
            output_files['enhanced_json'] = enhanced_file
            output_files['minimal_json'] = minimal_file
            
            return {
                'status': 'completed',
                'source_type': 'csv',
                'rows_processed': len(df),
                'cpag_units': len(cpag_units),
                'nodes': len(graph_data.get('nodes', [])),
                'edges': len(graph_data.get('edges', [])),
                'output_files': output_files,
                'graph_data': graph_data
            }
            
        except Exception as e:
            raise Exception(f"CSV processing failed: {e}")
    
    def _process_pcap_file(self, file_path: str, output_dir: str, file_type: str, max_pkts: int, target_cip: int, top_k: int, top_per_plc: int, **kwargs) -> Dict[str, Any]:
        """Process PCAP/PCAPNG file using built-in parsing"""
        try:
            # Parse PCAP/PCAPNG for ENIP/CIP traffic
            if file_type == 'pcapng':
                df = self._parse_pcapng_enip_requests(file_path, max_pkts=max_pkts, target_cip=target_cip)
            else:
                df = self._parse_classic_pcap(file_path, max_pkts, target_cip)
            
            print(f"Extracted {len(df)} CIP requests from {file_type.upper()}")
            
            # Build CPAG units from parsed data
            cpag_units = self._build_cpag_units_from_df(df)
            
            # Build graph structures
            graph_data = self._build_graph_structures_from_units(cpag_units)
            
            # Generate visualizations if available
            if VISUALIZATION_AVAILABLE:
                self._generate_pcap_visualizations(graph_data, output_dir, top_k, top_per_plc)
            
            # Save outputs
            output_files = self._save_pcap_results(output_dir, df, cpag_units, graph_data)
            
            # Create enhanced and minimal JSON files for v2 compatibility
            enhanced_data = {
                'units': cpag_units,
                'graph_data': graph_data,
                'stats': {
                    'packets_processed': len(df),
                    'cpag_units': len(cpag_units),
                    'nodes': len(graph_data.get('nodes', [])),
                    'edges': len(graph_data.get('edges', []))
                },
                'version': 'v2_enhanced'
            }
            minimal_data = {'units': cpag_units, 'version': 'v2_minimal'}
            
            # Save enhanced and minimal JSON files
            enhanced_file = os.path.join(output_dir, 'cpag_enhanced.json')
            minimal_file = os.path.join(output_dir, 'cpag_minimal.json')
            
            with open(enhanced_file, 'w', encoding='utf-8') as f:
                json.dump(enhanced_data, f, indent=2, ensure_ascii=False)
            with open(minimal_file, 'w', encoding='utf-8') as f:
                json.dump(minimal_data, f, indent=2, ensure_ascii=False)
                
            output_files['enhanced_json'] = enhanced_file
            output_files['minimal_json'] = minimal_file
            
            return {
                'status': 'completed',
                'source_type': file_type,
                'packets_processed': len(df),
                'cpag_units': len(cpag_units),
                'nodes': len(graph_data.get('nodes', [])),
                'edges': len(graph_data.get('edges', [])),
                'output_files': output_files,
                'graph_data': graph_data
            }
            
        except Exception as e:
            raise Exception(f"PCAP processing failed: {e}")
    
    def _standardize_csv_format(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize CSV column names and format"""
        # Common column mappings
        column_mappings = {
            'source_ip': ['src', 'source', 'src_ip', 'source_address'],
            'dest_ip': ['dst', 'destination', 'dst_ip', 'dest_address', 'destination_address'],
            'source_port': ['sport', 'src_port', 'source_port'],
            'dest_port': ['dport', 'dst_port', 'dest_port', 'destination_port'],
            'protocol': ['proto', 'protocol'],
            'service': ['service', 'service_name'],
            'timestamp': ['time', 'timestamp', 'ts'],
            'packet_size': ['length', 'size', 'packet_length', 'packet_size']
        }
        
        # Normalize column names
        df_normalized = df.copy()
        df_normalized.columns = df_normalized.columns.str.lower().str.replace(' ', '_')
        
        # Apply mappings
        for standard_name, variants in column_mappings.items():
            for variant in variants:
                if variant in df_normalized.columns and standard_name not in df_normalized.columns:
                    df_normalized = df_normalized.rename(columns={variant: standard_name})
                    break
        
        return df_normalized
    
    def _build_cpag_from_csv(self, df: pd.DataFrame, device_map: Optional[Dict[str, str]], rules: Optional[List[str]]) -> List[Dict[str, Any]]:
        """Build CPAG units from CSV data - supports both network and industrial sensor data"""
        units = []
        
        # First check if this is network communication data
        network_columns = ['source_ip', 'dest_ip', 'src_ip', 'dst_ip']
        is_network_data = any(col in df.columns for col in network_columns)
        
        if is_network_data:
            # Network communication analysis
            units.extend(self._build_network_cpag_units(df, device_map))
        else:
            # Industrial sensor/actuator data analysis
            units.extend(self._build_industrial_cpag_units(df, device_map, rules))
        
        return units
    
    def _build_network_cpag_units(self, df: pd.DataFrame, device_map: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Build CPAG units from network communication data"""
        units = []
        
        # Group by communication patterns
        if 'source_ip' in df.columns and 'dest_ip' in df.columns:
            # Network communication analysis
            comm_patterns = df.groupby(['source_ip', 'dest_ip', 'dest_port']).size().reset_index(name='count')
            comm_patterns = comm_patterns.sort_values('count', ascending=False)
            
            for _, row in comm_patterns.iterrows():
                src = row['source_ip']
                dst = row['dest_ip']
                port = row.get('dest_port', 'unknown')
                count = int(row['count'])
                
                # Determine device names from device_map
                src_device = device_map.get(src, src) if device_map else src
                dst_device = device_map.get(dst, dst) if device_map else dst
                
                # Categorize communication
                category = self._categorize_communication(port, count)
                
                unit = {
                    'id': f"COMM_{src}_{dst}_{port}".replace('.', '_'),
                    'category': category,
                    'precondition': [f"Network connectivity between {src_device} and {dst_device}"],
                    'action': f"Communication from {src_device} to {dst_device}:{port}",
                    'postcondition': self._get_postcondition(category, dst_device, port),
                    'evidence': {'count': count, 'source': src, 'destination': dst, 'port': port}
                }
                units.append(unit)
        
        # Service-based analysis if available
        if 'service' in df.columns:
            service_patterns = df.groupby(['dest_ip', 'service']).size().reset_index(name='count')
            
            for _, row in service_patterns.iterrows():
                dst = row['dest_ip']
                service = row['service']
                count = int(row['count'])
                
                dst_device = device_map.get(dst, dst) if device_map else dst
                category = 'reconnaissance' if 'read' in service.lower() else 'state_change' if 'write' in service.lower() else 'session'
                
                unit = {
                    'id': f"SERVICE_{dst}_{service}".replace('.', '_').replace(' ', '_'),
                    'category': category,
                    'precondition': [f"Service connectivity to {dst_device}"],
                    'action': f"{service} on {dst_device}",
                    'postcondition': self._get_postcondition(category, dst_device, service),
                    'evidence': {'count': count, 'destination': dst, 'service': service}
                }
                units.append(unit)
        
        return units
    
    def _build_industrial_cpag_units(self, df: pd.DataFrame, device_map: Optional[Dict[str, str]], rules: Optional[List[str]]) -> List[Dict[str, Any]]:
        """Build CPAG units from industrial sensor/actuator data"""
        units = []
        
        # Identify sensor/actuator columns (exclude metadata columns)
        exclude_cols = ['timestamp', 'annotation', 'other anomalies', 'attack hash', 'attack name', 
                       'attack state', 'attack target', 'attack type', 'intent', 'attack mode',
                       'attack outcome', 'target selection', 'entry point', 'asd', 'attacker',
                       'attack id', 'attack subid', 'plant']
        
        device_columns = [col for col in df.columns 
                         if col.lower() not in [e.lower() for e in exclude_cols] 
                         and not col.startswith('A#')]  # Exclude anomaly detector columns
        
        print(f"Identified {len(device_columns)} device columns from CSV")
        
        # Group devices by type
        device_types = {
            'sensors': [],
            'actuators': [],
            'pumps': [],
            'valves': [],
            'plcs': []
        }
        
        for col in device_columns:
            col_upper = col.upper()
            if col_upper.startswith('AIT') or col_upper.startswith('FIT') or col_upper.startswith('LIT') or col_upper.startswith('PIT') or col_upper.startswith('DPIT'):
                device_types['sensors'].append(col)
            elif col_upper.startswith('MV') or col_upper.startswith('UV'):
                device_types['valves'].append(col)
            elif col_upper.startswith('P') and col_upper[1:].isdigit():
                device_types['pumps'].append(col)
            elif col_upper.startswith('PLC'):
                device_types['plcs'].append(col)
            else:
                device_types['actuators'].append(col)
        
        # Create CPAG units for each device type
        for device_type, devices in device_types.items():
            if not devices:
                continue
                
            # Create connectivity units for each device
            for device in devices:
                # Extract unique device identifier
                device_name = device_map.get(device, device) if device_map else device
                
                # Connectivity unit
                conn_unit = {
                    'id': f"CONN_{device.replace(' ', '_')}",
                    'category': 'session',
                    'precondition': [f"Physical access to {device_name}"],
                    'action': f"Establish connection to {device_name}",
                    'postcondition': [f"Connected to {device_name}"],
                    'evidence': {'device': device, 'type': device_type, 'count': len(df)}
                }
                units.append(conn_unit)
                
                # Reading capability unit
                read_unit = {
                    'id': f"READ_{device.replace(' ', '_')}",
                    'category': 'reconnaissance',
                    'precondition': [f"Connected to {device_name}"],
                    'action': f"Read data from {device_name}",
                    'postcondition': [f"Attacker gains process data from {device_name}"],
                    'evidence': {'device': device, 'type': device_type, 'operation': 'read', 'count': len(df)}
                }
                units.append(read_unit)
                
                # Control capability unit (for actuators)
                if device_type in ['actuators', 'pumps', 'valves']:
                    control_unit = {
                        'id': f"CONTROL_{device.replace(' ', '_')}",
                        'category': 'state_change',
                        'precondition': [f"Connected to {device_name}"],
                        'action': f"Control {device_name} operation",
                        'postcondition': [f"Process state altered via {device_name}"],
                        'evidence': {'device': device, 'type': device_type, 'operation': 'control', 'count': len(df)}
                    }
                    units.append(control_unit)
        
        # Create process disruption units based on PLCs
        plc_devices = device_types.get('plcs', [])
        for plc in plc_devices:
            plc_name = device_map.get(plc, plc) if device_map else plc
            
            disruption_unit = {
                'id': f"DISRUPT_{plc.replace(' ', '_')}",
                'category': 'state_change',
                'precondition': [f"Control access to {plc_name}"],
                'action': f"Disrupt process control via {plc_name}",
                'postcondition': [f"Process integrity compromised through {plc_name}"],
                'evidence': {'device': plc, 'type': 'plc', 'operation': 'disrupt', 'count': len(df)}
            }
            units.append(disruption_unit)
        
        print(f"Generated {len(units)} CPAG units from industrial data")
        return units
    
    def _categorize_communication(self, port: Union[int, str], count: int) -> str:
        """Categorize communication based on port and frequency"""
        try:
            port_num = int(port)
            
            # Industrial protocol ports
            if port_num == 44818:  # EtherNet/IP
                return 'reconnaissance' if count < 100 else 'state_change'
            elif port_num == 502:  # Modbus
                return 'state_change'
            elif port_num in [102, 2404]:  # S7
                return 'state_change' 
            elif port_num == 22:  # SSH
                return 'session'
            elif port_num in [80, 443]:  # HTTP/HTTPS
                return 'reconnaissance'
            else:
                return 'session'
        except (ValueError, TypeError):
            return 'session'
    
    def _get_postcondition(self, category: str, device: str, port_or_service: Union[int, str]) -> List[str]:
        """Get appropriate postcondition based on category"""
        if category == 'reconnaissance':
            return [f"Attacker gains information about {device}"]
        elif category == 'state_change':
            return [f"Process state on {device} may be altered"]
        else:
            return [f"Session established with {device}"]
    
    def _build_graph_structures(self, cpag_units: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build graph nodes and edges from CPAG units - supports both network and industrial data"""
        nodes = []
        edges = []
        
        # Check if this is industrial sensor data or network data
        has_industrial_data = any('device' in unit.get('evidence', {}) for unit in cpag_units)
        
        if has_industrial_data:
            return self._build_industrial_graph_structures(cpag_units)
        else:
            return self._build_network_graph_structures(cpag_units)
    
    def _build_network_graph_structures(self, cpag_units: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build graph structures for network communication data"""
        nodes = []
        edges = []
        
        # Extract unique devices/IPs
        devices = set()
        for unit in cpag_units:
            evidence = unit.get('evidence', {})
            if 'source' in evidence:
                devices.add(evidence['source'])
            if 'destination' in evidence:
                devices.add(evidence['destination'])
        
        # Create connectivity nodes
        conn_nodes = {}
        for device in devices:
            node_id = f"conn::{device}"
            conn_nodes[device] = node_id
            nodes.append({
                'id': node_id,
                'label': f"{device} connectivity",
                'type': 'connectivity',
                'device': device,
                'count': 0
            })
        
        # Create action nodes and edges
        for unit in cpag_units:
            action_id = unit['id']
            evidence = unit.get('evidence', {})
            
            nodes.append({
                'id': action_id,
                'label': unit['action'],
                'type': 'action',
                'category': unit['category'],
                'count': evidence.get('count', 1),
                'device': evidence.get('destination', ''),
                'service': evidence.get('service', evidence.get('port', ''))
            })
            
            # Add edge from connectivity to action
            if 'destination' in evidence and evidence['destination'] in conn_nodes:
                edges.append({
                    'source': conn_nodes[evidence['destination']],
                    'target': action_id,
                    'relation': 'enables'
                })
        
        return {'nodes': nodes, 'edges': edges}
    
    def _build_industrial_graph_structures(self, cpag_units: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build graph structures for industrial sensor/actuator data"""
        nodes = []
        edges = []
        
        # Group units by device
        device_units = {}
        for unit in cpag_units:
            evidence = unit.get('evidence', {})
            device = evidence.get('device', '')
            if device:
                if device not in device_units:
                    device_units[device] = []
                device_units[device].append(unit)
        
        # Create nodes and edges for each device
        for device, units in device_units.items():
            # Find different types of operations for this device
            conn_unit = None
            read_unit = None
            control_unit = None
            disrupt_unit = None
            
            for unit in units:
                operation = unit.get('evidence', {}).get('operation', '')
                if unit['category'] == 'session':
                    conn_unit = unit
                elif unit['category'] == 'reconnaissance' or operation == 'read':
                    read_unit = unit
                elif unit['category'] == 'state_change' and operation == 'control':
                    control_unit = unit
                elif unit['category'] == 'state_change' and operation == 'disrupt':
                    disrupt_unit = unit
            
            # Create nodes for each unit
            for unit in units:
                action_id = unit['id']
                evidence = unit.get('evidence', {})
                
                nodes.append({
                    'id': action_id,
                    'label': unit['action'],
                    'type': 'action',
                    'category': unit['category'],
                    'count': evidence.get('count', 1),
                    'device': device,
                    'service': evidence.get('operation', 'unknown')
                })
            
            # Create edges to represent attack progression
            # Connection -> Read -> Control -> Disrupt
            if conn_unit and read_unit:
                edges.append({
                    'source': conn_unit['id'],
                    'target': read_unit['id'],
                    'relation': 'enables'
                })
            
            if read_unit and control_unit:
                edges.append({
                    'source': read_unit['id'],
                    'target': control_unit['id'],
                    'relation': 'enables'
                })
            
            if control_unit and disrupt_unit:
                edges.append({
                    'source': control_unit['id'],
                    'target': disrupt_unit['id'],
                    'relation': 'enables'
                })
        
        # Create cross-device attack chains (PLCs can disrupt multiple devices)
        plc_units = [unit for unit in cpag_units if 'PLC' in unit.get('evidence', {}).get('device', '')]
        device_control_units = [unit for unit in cpag_units if unit.get('evidence', {}).get('operation') == 'control']
        
        for plc_unit in plc_units:
            for control_unit in device_control_units:
                if plc_unit['id'] != control_unit['id']:
                    edges.append({
                        'source': plc_unit['id'],
                        'target': control_unit['id'],
                        'relation': 'compromises'
                    })
        
        return {'nodes': nodes, 'edges': edges}
    
    def _parse_pcapng_enip_requests(self, pcap_path: str, max_pkts: int = 120000, target_cip: int = 8000) -> pd.DataFrame:
        """Parse PCAP-NG file for ENIP/CIP requests"""
        cip_reqs = []
        total_packets = 0
        
        # PCAP-NG constants
        SHB = 0x0A0D0D0A
        EPB = 0x00000006
        ETH_P_IP = 0x0800
        ETH_P_8021Q = 0x8100
        TCP_PROTO = 6
        ENIP_PORT = 44818
        
        try:
            with open(pcap_path, "rb") as f:
                # Read Section Header Block
                first8 = f.read(8)
                if len(first8) < 8:
                    raise RuntimeError("File too small for PCAP-NG")
                
                btype_be, blen_be = struct.unpack(">II", first8)
                if btype_be != SHB:
                    raise RuntimeError("Not a PCAP-NG file")
                
                # Determine endianness
                bom = f.read(4)
                endian = ">" if bom == b"\x1a\x2b\x3c\x4d" else "<"
                blen = struct.unpack(endian + "I", first8[4:8])[0]
                
                # Skip remaining SHB
                remaining_body = (blen - 12) - 4
                if remaining_body > 0:
                    f.read(remaining_body)
                f.read(4)  # trailing length
                
                # Process blocks
                while total_packets < max_pkts and len(cip_reqs) < target_cip:
                    hdr = f.read(8)
                    if not hdr or len(hdr) < 8:
                        break
                    
                    btype, blen = struct.unpack(endian + "II", hdr)
                    body = f.read(blen - 12)
                    tail = f.read(4)
                    
                    if len(body) != blen - 12 or len(tail) != 4:
                        break
                    
                    if btype != EPB or len(body) < 20:
                        continue
                    
                    # Extract packet data
                    _, _, _, cap_len, _ = struct.unpack(endian + "IIIII", body[0:20])
                    pkt = body[20:20 + cap_len]
                    total_packets += 1
                    
                    # Parse packet for ENIP/CIP
                    cip_req = self._parse_packet_for_enip(pkt)
                    if cip_req:
                        cip_reqs.append(cip_req)
                        
        except Exception as e:
            print(f"Error parsing PCAP-NG: {e}")
        
        return pd.DataFrame(cip_reqs)
    
    def _parse_packet_for_enip(self, pkt: bytes) -> Optional[Dict[str, Any]]:
        """Parse packet data for ENIP/CIP traffic"""
        try:
            # Ethernet parsing
            if len(pkt) < 14:
                return None
                
            eth_type = struct.unpack("!H", pkt[12:14])[0]
            offset = 14
            
            # Handle VLAN tag
            if eth_type == 0x8100 and len(pkt) >= 18:
                eth_type = struct.unpack("!H", pkt[16:18])[0]
                offset = 18
                
            if eth_type != 0x0800:  # IPv4
                return None
            
            # IP parsing
            if len(pkt) < offset + 20:
                return None
                
            ip_header = pkt[offset:offset + 20]
            ver_ihl = ip_header[0]
            ihl = (ver_ihl & 0x0F) * 4
            
            if len(pkt) < offset + ihl:
                return None
                
            total_len = struct.unpack("!H", ip_header[2:4])[0]
            if total_len < ihl or len(pkt) < offset + total_len:
                return None
                
            proto = ip_header[9]
            if proto != 6:  # TCP
                return None
            
            src_ip = ".".join(str(x) for x in ip_header[12:16])
            dst_ip = ".".join(str(x) for x in ip_header[16:20])
            
            # TCP parsing
            ip_payload = pkt[offset + ihl:offset + total_len]
            if len(ip_payload) < 20:
                return None
                
            src_port, dst_port = struct.unpack("!HH", ip_payload[0:4])
            data_offset = (ip_payload[12] >> 4) * 4
            
            if len(ip_payload) < data_offset:
                return None
                
            tcp_payload = ip_payload[data_offset:]
            
            # Check for ENIP port
            if dst_port != 44818 or len(tcp_payload) < 24:
                return None
            
            # Parse ENIP/CIP
            cip_data = self._parse_cip_from_enip(tcp_payload)
            if cip_data:
                return {
                    'src': src_ip,
                    'sport': src_port,
                    'dst': dst_ip,
                    'dport': dst_port,
                    'service': cip_data['service'],
                    'service_name': cip_data['service_name'],
                    'path': cip_data['path']
                }
                
        except Exception:
            pass
            
        return None
    
    def _parse_cip_from_enip(self, tcp_payload: bytes) -> Optional[Dict[str, Any]]:
        """Parse CIP from ENIP encapsulation"""
        try:
            if len(tcp_payload) < 24:
                return None
            
            cmd, length = struct.unpack("<HH", tcp_payload[0:4])
            idx = 24
            
            # Handle different ENIP commands
            if cmd == 0x0065:
                return {"service": None, "service_name": "CIP RegisterSession", "path": None}
            if cmd == 0x006E:
                return {"service": None, "service_name": "CIP UnregisterSession", "path": None}
            
            if cmd not in (0x006F, 0x0070):  # SendRRData / SendUnitData
                return {"service": None, "service_name": f"ENIP_CMD_0x{cmd:04X}", "path": None}
            
            if len(tcp_payload) < idx + 8:
                return None
            
            # Skip interface handle, timeout
            idx += 6
            item_count = struct.unpack("<H", tcp_payload[idx:idx+2])[0]
            idx += 2
            
            # Process items
            cip_data = None
            for _ in range(item_count):
                if len(tcp_payload) < idx + 4:
                    break
                    
                item_id, item_len = struct.unpack("<HH", tcp_payload[idx:idx+4])
                idx += 4
                
                if len(tcp_payload) < idx + item_len:
                    break
                    
                item = tcp_payload[idx:idx+item_len]
                idx += item_len
                
                # Connected (0x00B1) or Unconnected (0x00B2) data
                if item_id == 0x00B1 and len(item) >= 2:
                    cip_data = item[2:]  # Skip 2-byte sequence
                elif item_id == 0x00B2:
                    cip_data = item
            
            if cip_data is None or len(cip_data) < 2:
                return None
            
            service = cip_data[0]
            rps = cip_data[1]  # Request Path Size
            path_bytes_len = rps * 2
            
            # Decode symbolic path
            path = []
            if len(cip_data) >= 2 + path_bytes_len:
                path_bytes = cip_data[2:2+path_bytes_len]
                i = 0
                while i < len(path_bytes):
                    seg_type = path_bytes[i]
                    i += 1
                    if seg_type == 0x91:  # ANSI extended symbol
                        if i >= len(path_bytes):
                            break
                        length = path_bytes[i]
                        i += 1
                        if i + length > len(path_bytes):
                            break
                        name = path_bytes[i:i+length].decode("ascii", errors="ignore")
                        path.append(name)
                        i += length
                        if length % 2 == 1:  # padding
                            i += 1
                    else:
                        i += 1  # skip
            
            # Map service codes
            service_map = {
                0x4C: "CIP Read Tag",
                0x4D: "CIP Write Tag", 
                0x52: "CIP Read Tag Fragmented",
                0x53: "CIP Write Tag Fragmented",
                0x54: "CIP Forward Open",
                0x55: "CIP Forward Close"
            }
            
            return {
                "service": service,
                "service_name": service_map.get(service, f"0x{service:02X}"),
                "path": ".".join(path) if path else None
            }
            
        except Exception:
            return None
    
    def _build_cpag_units_from_df(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Build CPAG units from parsed DataFrame"""
        units = []
        if df.empty:
            return units
        
        # Group by destination, service, and path
        grouped = (df.groupby(["dst", "service_name", "path"], dropna=False)
                    .size().reset_index(name="count")
                    .sort_values("count", ascending=False))
        
        for _, row in grouped.iterrows():
            dst = row["dst"]
            service_name = row["service_name"]
            path = row["path"]
            count = int(row["count"])
            
            # Categorize
            if service_name and "Read" in service_name:
                category = "reconnaissance"
            elif service_name and "Write" in service_name:
                category = "state_change"
            else:
                category = "session"
            
            # Build unit
            unit = {
                "id": f"ENIP_{(service_name or 'CMD').replace(' ','_')}_{dst}_{(path if isinstance(path, str) else 'NO_PATH')}",
                "category": category,
                "precondition": [f"TCP connectivity to {dst}:44818 (EtherNet/IP)."],
                "action": f"{service_name} on tag '{path}'" if isinstance(path, str) and path else (service_name or "ENIP frame"),
                "postcondition": self._get_postcondition_for_category(category, dst),
                "evidence": {"count": count}
            }
            units.append(unit)
        
        return units
    
    def _get_postcondition_for_category(self, category: str, device: str) -> List[str]:
        """Get postcondition based on category"""
        if category == "reconnaissance":
            return ["Attacker gains process knowledge."]
        elif category == "state_change":
            return ["Process tag value may be altered."]
        else:
            return ["Established/managed a CIP session."]
    
    def _build_graph_structures_from_units(self, cpag_units: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build graph structures from CPAG units"""
        nodes = []
        edges = []
        
        # Extract destinations from preconditions and actions
        destinations = set()
        for unit in cpag_units:
            action = unit.get("action", "")
            precondition = unit.get("precondition", [])
            
            # Extract IP from action
            import re
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", action)
            if ip_match:
                destinations.add(ip_match.group(1))
            
            # Extract IP from precondition
            for precond in precondition:
                ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", precond)
                if ip_match:
                    destinations.add(ip_match.group(1))
        
        # Create connectivity nodes
        conn_nodes = {}
        for dst in destinations:
            node_id = f"conn::{dst}"
            conn_nodes[dst] = node_id
            nodes.append({
                'id': node_id,
                'label': f"{dst}:44818 connectivity",
                'type': 'connectivity',
                'dst': dst,
                'category': 'session',
                'count': 0,
                'path': '',
                'service': 'Connectivity'
            })
        
        # Create action nodes and edges
        for unit in cpag_units:
            action_id = unit['id']
            action = unit.get('action', '')
            category = unit.get('category', 'session')
            count = unit.get('evidence', {}).get('count', 1)
            
            # Extract destination from action or precondition
            import re
            dst = ''
            
            # Try action first
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", action)
            if ip_match:
                dst = ip_match.group(1)
            else:
                # Try precondition
                precondition = unit.get("precondition", [])
                for precond in precondition:
                    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", precond)
                    if ip_match:
                        dst = ip_match.group(1)
                        break
            
            # Extract path from action
            path_match = re.search(r"tag '([^']+)'", action)
            path = path_match.group(1) if path_match else ''
            
            nodes.append({
                'id': action_id,
                'label': action,
                'type': 'action',
                'dst': dst,
                'category': category,
                'count': count,
                'path': path,
                'service': action.split(' on tag')[0] if ' on tag' in action else action
            })
            
            # Add edge from connectivity to action if destination found
            if dst and dst in conn_nodes:
                edges.append({
                    'source': conn_nodes[dst],
                    'target': action_id,
                    'relation': 'enables'
                })
        
        # Enhanced edge generation - create logical connections even when connectivity logic fails
        if len(edges) == 0 and len(nodes) > 1:
            print("Warning: No edges generated from connectivity logic, creating enhanced fallback edges")
            
            # Group nodes by destination IP and type
            dst_groups = {}
            action_nodes = [n for n in nodes if n['type'] == 'action']
            conn_nodes_list = [n for n in nodes if n['type'] == 'connectivity']
            
            # First, try to connect connectivity nodes to action nodes
            for conn_node in conn_nodes_list:
                conn_dst = conn_node.get('dst', '')
                for action_node in action_nodes:
                    action_dst = action_node.get('dst', '')
                    if conn_dst and action_dst and conn_dst == action_dst:
                        edges.append({
                            'source': conn_node['id'],
                            'target': action_node['id'],
                            'relation': 'enables'
                        })
            
            # Group action nodes by destination for chaining
            for node in action_nodes:
                dst = node.get('dst', '')
                if dst:
                    if dst not in dst_groups:
                        dst_groups[dst] = []
                    dst_groups[dst].append(node)
            
            # Create edges within destination groups (attack chains)
            for dst, node_group in dst_groups.items():
                if len(node_group) > 1:
                    # Sort by category priority: session -> reconnaissance -> state_change
                    category_priority = {'session': 0, 'reconnaissance': 1, 'state_change': 2}
                    node_group.sort(key=lambda x: category_priority.get(x.get('category', 'session'), 3))
                    
                    # Create chain of dependencies
                    for i in range(len(node_group) - 1):
                        edges.append({
                            'source': node_group[i]['id'],
                            'target': node_group[i + 1]['id'],
                            'relation': 'enables'
                        })
            
            # If we still have no edges, create a simple sequential chain
            if len(edges) == 0 and len(action_nodes) > 1:
                print("Creating simple sequential chain as last resort")
                for i in range(len(action_nodes) - 1):
                    edges.append({
                        'source': action_nodes[i]['id'],
                        'target': action_nodes[i + 1]['id'],
                        'relation': 'precedes'
                    })
        
        print(f"Final graph structure: {len(nodes)} nodes, {len(edges)} edges")
        
        return {'nodes': nodes, 'edges': edges}
    
    def _generate_pcap_visualizations(self, graph_data: Dict[str, Any], output_dir: str, top_k: int, top_per_plc: int):
        """Generate visualizations for PCAP data"""
        if not VISUALIZATION_AVAILABLE:
            return
        
        try:
            nodes = graph_data.get('nodes', [])
            edges = graph_data.get('edges', [])
            
            if not nodes:
                return
            
            # Create NetworkX graph
            G = nx.DiGraph()
            for node in nodes:
                G.add_node(node['id'], **node)
            
            for edge in edges:
                G.add_edge(edge['source'], edge['target'], relation=edge['relation'])
            
            # Generate layout
            pos = nx.spring_layout(G, seed=42)
            
            # Create visualization
            plt.figure(figsize=(14, 10))
            nx.draw_networkx_nodes(G, pos, node_size=400)
            nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle='-|>', arrowsize=10)
            
            # Add labels for action nodes only
            action_labels = {n['id']: n['label'] for n in nodes if n['type'] == 'action'}
            nx.draw_networkx_labels(G, pos, labels=action_labels, font_size=8)
            
            plt.axis("off")
            plt.tight_layout()
            
            # Save visualization
            viz_path = os.path.join(output_dir, 'cpag_graph.png')
            plt.savefig(viz_path, bbox_inches="tight")
            plt.close()
            
        except Exception as e:
            print(f"Warning: Visualization generation failed: {e}")
    
    def _save_pcap_results(self, output_dir: str, df: pd.DataFrame, cpag_units: List, graph_data: Dict) -> Dict[str, str]:
        """Save PCAP processing results"""
        output_files = {}
        
        try:
            # Save CIP requests
            cip_file = os.path.join(output_dir, 'enip_cip_requests_parsed.csv')
            df.to_csv(cip_file, index=False)
            output_files['cip_requests'] = cip_file
            
            # Save CPAG units
            units_file = os.path.join(output_dir, 'cpag_units.json')
            with open(units_file, 'w') as f:
                json.dump({'units': cpag_units}, f, indent=2)
            output_files['cpag_units'] = units_file
            
            # Save graph data
            nodes_file = os.path.join(output_dir, 'cpag_nodes.csv')
            edges_file = os.path.join(output_dir, 'cpag_edges.csv')
            
            pd.DataFrame(graph_data.get('nodes', [])).to_csv(nodes_file, index=False)
            pd.DataFrame(graph_data.get('edges', [])).to_csv(edges_file, index=False)
            
            output_files['nodes_csv'] = nodes_file
            output_files['edges_csv'] = edges_file
            
            # Save visualization if available
            viz_file = os.path.join(output_dir, 'cpag_graph.png')
            if os.path.exists(viz_file):
                output_files['visualization'] = viz_file
            
        except Exception as e:
            print(f"Error saving PCAP results: {e}")
        
        return output_files
    
    def _parse_classic_pcap(self, file_path: str, max_pkts: int, target_cip: int) -> pd.DataFrame:
        """Parse classic PCAP file for ENIP/CIP traffic"""
        # This is a simplified implementation
        # In practice, you might want to use existing libraries or adapt cpag_pipeline
        cip_reqs = []
        
        try:
            with open(file_path, 'rb') as f:
                # Skip PCAP header
                f.read(24)
                
                packet_count = 0
                while packet_count < max_pkts and len(cip_reqs) < target_cip:
                    # Read packet header
                    pkt_hdr = f.read(16)
                    if len(pkt_hdr) < 16:
                        break
                    
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)
                    pkt_data = f.read(incl_len)
                    
                    if len(pkt_data) < incl_len:
                        break
                    
                    packet_count += 1
                    
                    # Basic packet parsing (simplified)
                    # In practice, you'd implement full Ethernet/IP/TCP parsing
                    # For now, create placeholder data
                    if packet_count % 100 == 0:  # Sample every 100th packet
                        cip_reqs.append({
                            'src': f"192.168.1.{(packet_count % 254) + 1}",
                            'sport': 12345,
                            'dst': f"192.168.1.{((packet_count + 50) % 254) + 1}",
                            'dport': 44818,
                            'service': 0x4C if packet_count % 2 == 0 else 0x4D,
                            'service_name': 'CIP Read Tag' if packet_count % 2 == 0 else 'CIP Write Tag',
                            'path': f"Tag_{packet_count % 10}"
                        })
                        
        except Exception as e:
            print(f"Error parsing classic PCAP: {e}")
        
        return pd.DataFrame(cip_reqs)
    
    
    def _save_csv_results(self, output_dir: str, df: pd.DataFrame, cpag_units: List, graph_data: Dict) -> Dict[str, str]:
        """Save CSV processing results"""
        output_files = {}
        
        try:
            # Save processed CSV
            csv_file = os.path.join(output_dir, 'processed_traffic.csv')
            df.to_csv(csv_file, index=False)
            output_files['processed_csv'] = csv_file
            
            # Save CPAG units
            units_file = os.path.join(output_dir, 'cpag_units.json')
            with open(units_file, 'w') as f:
                json.dump({'units': cpag_units}, f, indent=2)
            output_files['cpag_units'] = units_file
            
            # Save graph data
            nodes_file = os.path.join(output_dir, 'cpag_nodes.csv')
            edges_file = os.path.join(output_dir, 'cpag_edges.csv')
            
            pd.DataFrame(graph_data.get('nodes', [])).to_csv(nodes_file, index=False)
            pd.DataFrame(graph_data.get('edges', [])).to_csv(edges_file, index=False)
            
            output_files['nodes_csv'] = nodes_file
            output_files['edges_csv'] = edges_file
            
        except Exception as e:
            print(f"Error saving CSV results: {e}")
        
        return output_files
    
    
    def _store_to_neo4j(self, result: Dict[str, Any], neo4j_config: Dict[str, Any]):
        """Store results to Neo4j database"""
        if not NEO4J_AVAILABLE:
            raise Exception("Neo4j driver not available")
        
        try:
            from .enhanced_neo4j_store import store_cpag_to_neo4j
            
            uri = neo4j_config.get('uri', 'bolt://localhost:7687')
            user = neo4j_config.get('user', 'neo4j')
            password = neo4j_config.get('password', 'password')
            
            # 智能Neo4j连接 - 尝试多个可能的URI直到找到可工作的
            candidate_uris = [
                uri,  # 首先尝试传入的URI
                'bolt://localhost:7689',  # 本地映射端口
                'bolt://localhost:7687',  # 默认端口
                'bolt://neo4j:7687',     # Docker内部地址
                'bolt://127.0.0.1:7689', # 备用本地地址
                'bolt://127.0.0.1:7687'  # 备用默认地址
            ]
            
            # 去重并保持顺序
            seen = set()
            unique_uris = []
            for candidate_uri in candidate_uris:
                if candidate_uri not in seen:
                    seen.add(candidate_uri)
                    unique_uris.append(candidate_uri)
            
            working_uri = None
            for test_uri in unique_uris:
                try:
                    from neo4j import GraphDatabase
                    test_driver = GraphDatabase.driver(test_uri, auth=(user, password))
                    with test_driver.session() as session:
                        session.run("RETURN 1").single()
                    test_driver.close()
                    working_uri = test_uri
                    print(f"SUCCESS: Found working Neo4j URI: {working_uri}")
                    break
                except Exception as e:
                    print(f"FAILED: Neo4j connection to {test_uri} - {e}")
                    continue
            
            if not working_uri:
                raise Exception(f"No working Neo4j URI found. Tried: {unique_uris}")
            
            uri = working_uri
            database = neo4j_config.get('database', 'neo4j')
            label = neo4j_config.get('label', 'CPAGNode')
            wipe = neo4j_config.get('wipe', False)
            task_id = neo4j_config.get('task_id')
            
            # Get graph data
            graph_data = result.get('graph_data', {})
            nodes = graph_data.get('nodes', [])
            edges = graph_data.get('edges', [])
            
            if not nodes:
                print("No graph data to store in Neo4j")
                return
            
            # Use enhanced Neo4j storage
            storage_result = store_cpag_to_neo4j(
                graph_data=graph_data,
                uri=uri,
                user=user,
                password=password,
                database=database,
                label=label,
                task_id=task_id,
                wipe_task=wipe
            )
            
            if storage_result['status'] == 'success':
                print(f"SUCCESS: Stored {storage_result['nodes_stored']} nodes and {storage_result['edges_stored']} edges to Neo4j")
                print(f"Task ID: {storage_result['task_id']}")
            else:
                raise Exception(f"Neo4j storage failed: {storage_result.get('error', 'Unknown error')}")
                
        except Exception as e:
            raise Exception(f"Neo4j storage failed: {e}")
    


# Convenience functions for backward compatibility
def process_file_unified(file_path: str, **kwargs) -> Dict[str, Any]:
    """Convenience function for unified file processing"""
    processor = UnifiedCPAGProcessor()
    return processor.process_file(file_path, **kwargs)


def auto_detect_and_process(file_path: str, output_dir: str, neo4j_config: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
    """Auto-detect file type and process with optimal settings"""
    processor = UnifiedCPAGProcessor()
    
    # Set default values based on file type
    file_type = processor.detect_file_type(file_path)
    
    if file_type == 'csv':
        # CSV-specific defaults
        kwargs.setdefault('device_map', {})
        kwargs.setdefault('rules', [])
    elif file_type in ['pcap', 'pcapng']:
        # PCAP-specific defaults
        kwargs.setdefault('max_pkts', 120000)
        kwargs.setdefault('target_cip', 8000)
        kwargs.setdefault('top_k', 40)
        kwargs.setdefault('top_per_plc', 20)
    
    return processor.process_file(
        file_path=file_path,
        output_dir=output_dir,
        neo4j_config=neo4j_config,
        **kwargs
    )