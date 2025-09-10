#!/usr/bin/env python3
"""
Enhanced CPAG Evaluation Framework with SWaT-specific optimizations
"""

import pandas as pd
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
import time, tracemalloc
from typing import List, Dict, Tuple, Optional
import json
from pathlib import Path
from collections import defaultdict
import re

# Load configurations
def load_configurations():
    """Load device mappings and custom rules"""
    device_map = {}
    rules = {}
    
    # Load SWaT device map
    device_map_file = Path("config/device-maps/swat_device_map.json")
    if device_map_file.exists():
        with open(device_map_file) as f:
            swat_config = json.load(f)
            device_map = swat_config.get('device_mappings', {})
            # Add reverse mappings for better matching
            original_items = list(device_map.items())
            for code, name in original_items:
                device_map[name] = code
                device_map[code.lower()] = name
                device_map[name.lower()] = code
    
    # Load custom rules
    rules_file = Path("config/custom-rules/swat_water_treatment_rules.json")
    if rules_file.exists():
        with open(rules_file) as f:
            rules_config = json.load(f)
            rules = rules_config.get('rules', [])
    
    return device_map, rules

# === Enhanced CPAG Generation Functions ===

def build_cpag_from_csv(df: pd.DataFrame, device_map=None, rules=None):
    """Generate CPAG units from input DataFrame with SWaT optimizations"""
    # Normalize column names
    df_norm = df.copy()
    df_norm.columns = df_norm.columns.str.lower().str.replace(' ', '_')
    
    # Check if this is network data
    is_network = any(col in df_norm.columns for col in ['source_ip','dest_ip','src_ip','dst_ip'])
    
    units = []
    if is_network:
        units = build_network_cpag_units(df_norm, device_map)
    else:
        units = build_swat_industrial_cpag_units(df_norm, device_map, rules)
    
    return units

def build_swat_industrial_cpag_units(df: pd.DataFrame, device_map=None, rules=None):
    """Build CPAG units specifically optimized for SWaT data"""
    units = []
    
    # Identify SWaT-specific columns
    swat_devices = ['fit101', 'lit101', 'mv101', 'p101', 'p102',
                    'ait201', 'ait202', 'ait203', 'fit201', 'mv201',
                    'p201', 'p202', 'p203', 'p204', 'p205', 'p206', 'p207', 'p208',
                    'ait301', 'ait302', 'ait303', 'dpit301', 'fit301', 'lit301',
                    'mv301', 'mv302', 'mv303', 'mv304', 'p301', 'p302',
                    'ait401', 'ait402', 'fit401', 'lit401', 'p401', 'p402', 'p403', 'p404', 'uv401',
                    'ait501', 'ait502', 'ait503', 'ait504', 'fit501', 'fit502', 'fit503', 'fit504',
                    'mv501', 'mv502', 'mv503', 'mv504', 'p501', 'p502', 
                    'pit501', 'pit502', 'pit503',
                    'fit601', 'fit602', 'lit601', 'lit602', 'p601', 'p602', 'p603']
    
    # Find actual device columns in the dataframe
    device_cols = []
    for col in df.columns:
        col_lower = col.lower()
        if any(device in col_lower for device in swat_devices):
            device_cols.append(col)
    
    # Process attack information if available
    attack_info = extract_attack_info(df)
    
    # Generate CPAG units for each device
    for device_col in device_cols:
        device_name = device_col.upper()
        device_desc = device_map.get(device_name, device_name) if device_map else device_name
        
        # Determine device type
        device_type = get_device_type(device_name)
        
        # Analyze device behavior
        try:
            values = pd.to_numeric(df[device_col], errors='coerce')
            
            if not values.isna().all():
                # Calculate statistics
                mean_val = values.mean()
                std_val = values.std()
                min_val = values.min()
                max_val = values.max()
                
                # Detect anomalies
                if std_val > 0:
                    anomalies = values[(values < mean_val - 2*std_val) | (values > mean_val + 2*std_val)]
                    anomaly_ratio = len(anomalies) / len(values)
                else:
                    anomaly_ratio = 0
                
                # Check if device is mentioned in attack data
                is_attack_target = device_name in attack_info.get('targets', [])
                
                # Create appropriate CPAG units based on device type and behavior
                if device_type == 'sensor':
                    # Sensor reading unit
                    unit = {
                        'id': f"SENSOR_{device_name}",
                        'category': 'reconnaissance',
                        'precondition': [f"Network access to {device_desc}"],
                        'action': f"Read sensor values from {device_desc}",
                        'postcondition': [f"Attacker knows {device_desc} readings"],
                        'evidence': {
                            'device': device_name,
                            'type': 'sensor',
                            'mean_value': round(mean_val, 2),
                            'range': [round(min_val, 2), round(max_val, 2)]
                        }
                    }
                    units.append(unit)
                    
                    # Anomaly unit if detected
                    if anomaly_ratio > 0.01 or is_attack_target:
                        unit = {
                            'id': f"ANOMALY_{device_name}",
                            'category': 'attack_impact',
                            'precondition': [f"Control access to {device_desc}"],
                            'action': f"Manipulate {device_desc} readings",
                            'postcondition': [f"{device_desc} shows anomalous values"],
                            'evidence': {
                                'device': device_name,
                                'anomaly_ratio': round(anomaly_ratio, 3),
                                'is_attack_target': is_attack_target
                            }
                        }
                        units.append(unit)
                
                elif device_type in ['pump', 'valve']:
                    # Actuator control unit
                    unit = {
                        'id': f"CONTROL_{device_name}",
                        'category': 'state_change',
                        'precondition': [f"Control access to {device_desc}"],
                        'action': f"Control {device_desc} state",
                        'postcondition': [f"{device_desc} state modified"],
                        'evidence': {
                            'device': device_name,
                            'type': device_type,
                            'states': int(values.nunique())
                        }
                    }
                    units.append(unit)
                    
                    # Abnormal operation if detected
                    if anomaly_ratio > 0.01 or is_attack_target:
                        unit = {
                            'id': f"ATTACK_{device_name}",
                            'category': 'attack_impact',
                            'precondition': [f"Compromised control of {device_desc}"],
                            'action': f"Malicious operation of {device_desc}",
                            'postcondition': [f"{device_desc} in abnormal state", "Process disruption"],
                            'evidence': {
                                'device': device_name,
                                'type': device_type,
                                'is_attack_target': is_attack_target
                            }
                        }
                        units.append(unit)
                
        except Exception as e:
            # Handle non-numeric data
            pass
    
    # Add stage-level coordination units
    stage_units = generate_stage_coordination_units(df, device_map or {})
    units.extend(stage_units)
    
    # Add cyber attack pattern units if detected
    if attack_info:
        attack_units = generate_attack_pattern_units(attack_info, device_map or {})
        units.extend(attack_units)
    
    return units

def get_device_type(device_name: str) -> str:
    """Determine device type from name"""
    device_upper = device_name.upper()
    if any(prefix in device_upper for prefix in ['FIT', 'LIT', 'AIT', 'PIT', 'DPIT']):
        return 'sensor'
    elif device_upper.startswith('P') and device_upper[1:].isdigit():
        return 'pump'
    elif device_upper.startswith('MV'):
        return 'valve'
    elif device_upper.startswith('UV'):
        return 'disinfection'
    elif device_upper.startswith('PLC'):
        return 'controller'
    else:
        return 'unknown'

def extract_attack_info(df: pd.DataFrame) -> Dict:
    """Extract attack information from SWaT data"""
    attack_info = {
        'has_attack': False,
        'targets': [],
        'types': [],
        'stages': []
    }
    
    # Check for attack columns
    for col in df.columns:
        col_lower = col.lower()
        if 'attack' in col_lower:
            if 'target' in col_lower:
                targets = df[col].dropna().unique()
                attack_info['targets'].extend([t for t in targets if t not in ['none', 'normal', '']])
            elif 'type' in col_lower:
                types = df[col].dropna().unique()
                attack_info['types'].extend([t for t in types if t not in ['none', 'normal', '']])
            elif 'name' in col_lower:
                names = df[col].dropna().unique()
                attack_info['has_attack'] = any(n not in ['normal', ''] for n in names)
    
    # Extract affected stages from targets
    for target in attack_info['targets']:
        if isinstance(target, str):
            # Extract stage number from device name
            match = re.search(r'(\d)\d{2}', target.upper())
            if match:
                stage = f"Stage_{match.group(1)}"
                if stage not in attack_info['stages']:
                    attack_info['stages'].append(stage)
    
    return attack_info if attack_info['has_attack'] else {}

def generate_stage_coordination_units(df: pd.DataFrame, device_map: Dict) -> List[Dict]:
    """Generate CPAG units for multi-stage coordination"""
    units = []
    
    # Define stage relationships
    stage_flow = [
        ('Stage_1', 'Stage_2', 'Raw water to chemical dosing'),
        ('Stage_2', 'Stage_3', 'Chemical dosing to ultrafiltration'),
        ('Stage_3', 'Stage_4', 'Ultrafiltration to dechlorination'),
        ('Stage_4', 'Stage_5', 'Dechlorination to reverse osmosis'),
        ('Stage_5', 'Stage_6', 'RO to product water storage')
    ]
    
    for source, dest, description in stage_flow:
        unit = {
            'id': f"FLOW_{source}_TO_{dest}",
            'category': 'process_flow',
            'precondition': [f"{source} operational"],
            'action': f"Process flow: {description}",
            'postcondition': [f"{dest} receives input from {source}"],
            'evidence': {
                'source_stage': source,
                'dest_stage': dest,
                'flow_type': 'water_treatment'
            }
        }
        units.append(unit)
    
    return units

def generate_attack_pattern_units(attack_info: Dict, device_map: Dict) -> List[Dict]:
    """Generate CPAG units for detected attack patterns"""
    units = []
    
    # Create attack chain units
    if attack_info.get('stages'):
        for i, stage in enumerate(attack_info['stages']):
            unit = {
                'id': f"ATTACK_STAGE_{stage}",
                'category': 'attack_impact',
                'precondition': [f"Compromised access to {stage}"],
                'action': f"Execute attack on {stage}",
                'postcondition': [f"{stage} operation disrupted", "Downstream effects possible"],
                'evidence': {
                    'stage': stage,
                    'attack_detected': True,
                    'sequence': i + 1
                }
            }
            units.append(unit)
    
    # Create attack propagation units
    for i in range(len(attack_info.get('stages', [])) - 1):
        current_stage = attack_info['stages'][i]
        next_stage = attack_info['stages'][i + 1]
        unit = {
            'id': f"ATTACK_PROPAGATION_{current_stage}_TO_{next_stage}",
            'category': 'attack_propagation',
            'precondition': [f"{current_stage} compromised"],
            'action': f"Attack propagates from {current_stage} to {next_stage}",
            'postcondition': [f"{next_stage} affected by upstream attack"],
            'evidence': {
                'propagation_path': f"{current_stage} -> {next_stage}",
                'attack_type': 'cascading_failure'
            }
        }
        units.append(unit)
    
    return units

def build_network_cpag_units(df: pd.DataFrame, device_map=None):
    """Build CPAG units from network communication data"""
    units = []
    
    # Group by communication patterns
    if 'source_ip' in df.columns and 'dest_ip' in df.columns:
        comm = df.groupby(['source_ip', 'dest_ip']).agg({
            'dest_port': lambda x: x.mode()[0] if len(x.mode()) > 0 else x.iloc[0],
            'timestamp': 'count'
        }).rename(columns={'timestamp': 'count'}).reset_index()
        
        for _, row in comm.iterrows():
            src, dst = row['source_ip'], row['dest_ip']
            port = row.get('dest_port', 'unknown')
            count = int(row['count'])
            
            # Map IPs to device names
            src_name = device_map.get(src, src) if device_map else src
            dst_name = device_map.get(dst, dst) if device_map else dst
            
            # Industrial protocol detection
            category = 'reconnaissance'
            if port == 44818:  # EtherNet/IP
                category = 'industrial_control' if count > 100 else 'reconnaissance'
            elif port == 502:  # Modbus
                category = 'industrial_control'
            elif port == 102:  # S7
                category = 'industrial_control'
            elif port in [80, 443]:
                category = 'reconnaissance'
            elif port == 22:
                category = 'remote_access'
            
            unit = {
                'id': f"NET_{src.replace('.', '_')}_{dst.replace('.', '_')}_{port}",
                'category': category,
                'precondition': [f"Network route from {src_name} to {dst_name}"],
                'action': f"{category.replace('_', ' ').title()} from {src_name} to {dst_name}:{port}",
                'postcondition': ([f"Control commands sent to {dst_name}"] if category == 'industrial_control'
                                  else [f"Information gathered about {dst_name}"] if category == 'reconnaissance'
                                  else [f"Remote session established with {dst_name}"]),
                'evidence': {
                    'source': src,
                    'destination': dst,
                    'port': port,
                    'protocol': get_protocol_name(port),
                    'packet_count': count
                }
            }
            units.append(unit)
    
    return units

def get_protocol_name(port):
    """Get protocol name from port number"""
    protocols = {
        44818: 'EtherNet/IP',
        502: 'Modbus/TCP',
        102: 'S7comm',
        80: 'HTTP',
        443: 'HTTPS',
        22: 'SSH',
        21: 'FTP',
        23: 'Telnet'
    }
    return protocols.get(port, f'Unknown({port})')

# === Enhanced Evaluation Functions ===

def derive_gold_units(df: pd.DataFrame, cpag_units: List[Dict]) -> List[Dict]:
    """Derive gold standard CPAG units with SWaT-specific logic"""
    gold_units = []
    
    # Extract attack information
    attack_info = extract_attack_info(df)
    
    if attack_info and attack_info.get('has_attack'):
        # Use attack targets to identify gold units
        for target in attack_info.get('targets', []):
            if target and target not in ['none', 'normal']:
                # Find matching CPAG units
                matching_units = [u for u in cpag_units 
                                if target.upper() in u.get('id', '') or 
                                   target.upper() in str(u.get('evidence', {}))]
                
                # Prioritize attack impact and state change units
                for unit in matching_units:
                    if unit.get('category') in ['attack_impact', 'state_change']:
                        gold_units.append(unit)
                        break
                else:
                    # If no specific match, add the first matching unit
                    if matching_units:
                        gold_units.append(matching_units[0])
        
        # Add attack stage units
        stage_units = [u for u in cpag_units if u.get('category') == 'attack_impact' 
                      and 'STAGE' in u.get('id', '')]
        gold_units.extend(stage_units)
        
        # Add attack propagation units
        prop_units = [u for u in cpag_units if u.get('category') == 'attack_propagation']
        gold_units.extend(prop_units)
    
    # If no attack info, use anomaly detection
    if not gold_units:
        # Select units with anomalies
        anomaly_units = [u for u in cpag_units 
                        if 'ANOMALY' in u.get('id', '') or 
                           u.get('evidence', {}).get('anomaly_ratio', 0) > 0]
        gold_units.extend(anomaly_units[:5])
    
    # If still no gold units, select critical state changes
    if not gold_units:
        state_units = [u for u in cpag_units if u.get('category') == 'state_change']
        critical_devices = ['P101', 'P102', 'MV101', 'P301', 'P501', 'P502', 'UV401']
        
        for device in critical_devices:
            for unit in state_units:
                if device in unit.get('id', ''):
                    gold_units.append(unit)
                    break
    
    # Ensure we have at least some gold units
    if not gold_units and cpag_units:
        # Select top units by importance
        importance_order = ['attack_impact', 'state_change', 'industrial_control', 'attack_propagation']
        for category in importance_order:
            cat_units = [u for u in cpag_units if u.get('category') == category]
            if cat_units:
                gold_units.extend(cat_units[:3])
                break
    
    return gold_units

def extract_reference_paths(df: pd.DataFrame, gold_units: List[Dict]) -> List[List[str]]:
    """Extract reference attack paths for SWaT system"""
    paths = []
    
    # Extract attack stages
    attack_info = extract_attack_info(df)
    
    if attack_info and attack_info.get('stages'):
        # Create paths based on attack progression through stages
        stage_units = {stage: [] for stage in attack_info['stages']}
        
        for unit in gold_units:
            evidence = unit.get('evidence', {})
            if 'stage' in evidence:
                stage = evidence['stage']
                if stage in stage_units:
                    stage_units[stage].append(unit['id'])
        
        # Create paths following stage progression
        if len(attack_info['stages']) >= 2:
            for i in range(len(attack_info['stages']) - 1):
                current_stage = attack_info['stages'][i]
                next_stage = attack_info['stages'][i + 1]
                
                if stage_units[current_stage] and stage_units[next_stage]:
                    path = [stage_units[current_stage][0], stage_units[next_stage][0]]
                    paths.append(path)
    
    # Create paths based on SWaT process flow
    if not paths:
        process_flow_paths = [
            ['SENSOR_FIT101', 'CONTROL_P101', 'SENSOR_LIT101'],
            ['SENSOR_AIT201', 'CONTROL_P201', 'SENSOR_FIT201'],
            ['SENSOR_LIT301', 'CONTROL_P301', 'SENSOR_DPIT301'],
            ['SENSOR_AIT401', 'CONTROL_UV401', 'SENSOR_FIT401'],
            ['SENSOR_PIT501', 'CONTROL_P501', 'SENSOR_FIT502'],
            ['SENSOR_LIT601', 'CONTROL_P601', 'SENSOR_FIT601']
        ]
        
        for path_template in process_flow_paths:
            path = []
            for node_template in path_template:
                for unit in gold_units:
                    if node_template in unit['id']:
                        path.append(unit['id'])
                        break
            if len(path) >= 2:
                paths.append(path)
    
    # Add attack propagation paths
    prop_units = [u for u in gold_units if 'PROPAGATION' in u.get('id', '')]
    for unit in prop_units:
        # Extract source and destination from propagation unit
        parts = unit['id'].split('_')
        if len(parts) >= 5:  # ATTACK_PROPAGATION_X_TO_Y format
            source_stage = f"ATTACK_STAGE_{parts[2]}"
            dest_stage = f"ATTACK_STAGE_{parts[4]}"
            
            source_units = [u['id'] for u in gold_units if source_stage in u['id']]
            dest_units = [u['id'] for u in gold_units if dest_stage in u['id']]
            
            if source_units and dest_units:
                paths.append([source_units[0], unit['id'], dest_units[0]])
    
    return paths

def unit_similarity(u1: Dict, u2: Dict) -> float:
    """Enhanced similarity calculation for SWaT-specific units"""
    score = 0.0
    
    # Category match (weighted by importance)
    category_weights = {
        'attack_impact': 1.0,
        'state_change': 0.9,
        'attack_propagation': 0.8,
        'industrial_control': 0.7,
        'process_flow': 0.6,
        'reconnaissance': 0.5,
        'session': 0.4
    }
    
    cat1 = u1.get('category', '')
    cat2 = u2.get('category', '')
    
    if cat1 == cat2:
        weight = category_weights.get(cat1, 0.5)
        score += 0.3 * weight
    
    # Device/target similarity
    evidence1 = u1.get('evidence', {})
    evidence2 = u2.get('evidence', {})
    
    device1 = (evidence1.get('device') or evidence1.get('destination') or 
               evidence1.get('target') or evidence1.get('stage', '')).upper()
    device2 = (evidence2.get('device') or evidence2.get('destination') or 
               evidence2.get('target') or evidence2.get('stage', '')).upper()
    
    if device1 and device2:
        if device1 == device2:
            score += 0.4
        elif device1 in device2 or device2 in device1:
            score += 0.2
        # Check if same stage
        elif device1[:2] == device2[:2] and device1[0].isdigit():
            score += 0.1
    
    # Action similarity
    action1 = u1.get('action', '').lower()
    action2 = u2.get('action', '').lower()
    
    # Extract key action terms
    action_terms1 = set(re.findall(r'\b\w+\b', action1))
    action_terms2 = set(re.findall(r'\b\w+\b', action2))
    
    if action_terms1 and action_terms2:
        jaccard = len(action_terms1 & action_terms2) / len(action_terms1 | action_terms2)
        score += 0.2 * jaccard
    
    # Special case: both are attack-related
    if 'attack' in u1.get('id', '').lower() and 'attack' in u2.get('id', '').lower():
        score += 0.1
    
    # Special case: both are anomaly-related
    if 'anomaly' in u1.get('id', '').lower() and 'anomaly' in u2.get('id', '').lower():
        score += 0.1
    
    return min(score, 1.0)

def match_units(gold_units: List[Dict], pred_units: List[Dict], 
                similarity_threshold: float = 0.3) -> List[Tuple[int, int]]:
    """Optimized unit matching for SWaT evaluation"""
    matches = []
    used_pred = set()
    
    # Calculate all similarities
    similarities = []
    
    for i, gold in enumerate(gold_units):
        for j, pred in enumerate(pred_units):
            if j not in used_pred:
                sim = unit_similarity(gold, pred)
                if sim >= similarity_threshold:
                    similarities.append((sim, i, j))
    
    # Sort by similarity (descending)
    similarities.sort(reverse=True)
    
    # Greedy matching
    used_gold = set()
    for sim, i, j in similarities:
        if i not in used_gold and j not in used_pred:
            matches.append((i, j))
            used_gold.add(i)
            used_pred.add(j)
    
    return matches

def precision_recall_F1(gold_units: List[Dict], pred_units: List[Dict], 
                       matches: List[Tuple[int, int]]) -> Tuple[float, float, float, int, int, int]:
    """Calculate precision, recall, and F1 score"""
    TP = len(matches)
    FP = len(pred_units) - TP
    FN = len(gold_units) - TP
    
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return precision, recall, f1, TP, FP, FN

def build_graph_from_units(units: List[Dict]) -> nx.DiGraph:
    """Build directed graph from CPAG units with SWaT-specific logic"""
    G = nx.DiGraph()
    
    # Add nodes
    for unit in units:
        G.add_node(unit['id'], **unit)
    
    # Add edges based on SWaT process flow
    for i, u1 in enumerate(units):
        for j, u2 in enumerate(units):
            if i != j:
                # Check logical flow
                if should_connect(u1, u2):
                    G.add_edge(u1['id'], u2['id'])
    
    return G

def should_connect(u1: Dict, u2: Dict) -> bool:
    """Determine if two units should be connected in the graph"""
    # Category-based connections
    cat1 = u1.get('category')
    cat2 = u2.get('category')
    
    # Logical attack progression
    connections = [
        ('reconnaissance', 'session'),
        ('reconnaissance', 'industrial_control'),
        ('session', 'state_change'),
        ('industrial_control', 'state_change'),
        ('state_change', 'attack_impact'),
        ('attack_impact', 'attack_propagation'),
        ('process_flow', 'state_change'),
        ('process_flow', 'attack_impact')
    ]
    
    if (cat1, cat2) in connections:
        return True
    
    # Stage-based connections
    evidence1 = u1.get('evidence', {})
    evidence2 = u2.get('evidence', {})
    
    # Check stage progression
    stage1 = evidence1.get('stage', '')
    stage2 = evidence2.get('stage', '')
    
    if stage1 and stage2:
        # Extract stage numbers
        match1 = re.search(r'Stage_(\d)', stage1)
        match2 = re.search(r'Stage_(\d)', stage2)
        
        if match1 and match2:
            num1 = int(match1.group(1))
            num2 = int(match2.group(1))
            
            # Connect sequential stages
            if num2 == num1 + 1:
                return True
    
    # Device-based connections (same stage)
    device1 = evidence1.get('device', '')
    device2 = evidence2.get('device', '')
    
    if device1 and device2:
        # Check if devices are in the same stage
        if device1[:1] == device2[:1] and device1[:1].isdigit():
            # Different device types in same stage
            type1 = get_device_type(device1)
            type2 = get_device_type(device2)
            
            if type1 != type2 and type1 != 'unknown' and type2 != 'unknown':
                return True
    
    # Postcondition-precondition matching
    post1 = ' '.join(u1.get('postcondition', []))
    pre2 = ' '.join(u2.get('precondition', []))
    
    if post1 and pre2:
        # Check for significant term overlap
        terms1 = set(re.findall(r'\b\w+\b', post1.lower()))
        terms2 = set(re.findall(r'\b\w+\b', pre2.lower()))
        
        if terms1 and terms2 and len(terms1 & terms2) >= 2:
            return True
    
    return False

def compute_path_coverage(paths: List[List[str]], pred_graph: nx.DiGraph) -> float:
    """Calculate path coverage with partial credit"""
    if not paths:
        return 0.0
    
    total_coverage = 0.0
    
    for path in paths:
        path_score = 0.0
        path_length = len(path)
        
        # Check node coverage
        nodes_present = sum(1 for node in path if node in pred_graph)
        node_coverage = nodes_present / path_length
        
        # Check edge coverage
        edges_present = 0
        for i in range(len(path) - 1):
            if path[i] in pred_graph and path[i+1] in pred_graph:
                try:
                    # Check for direct edge or path
                    if pred_graph.has_edge(path[i], path[i+1]):
                        edges_present += 1
                    elif nx.has_path(pred_graph, path[i], path[i+1]):
                        edges_present += 0.5  # Partial credit for indirect path
                except:
                    pass
        
        edge_coverage = edges_present / (path_length - 1) if path_length > 1 else 1.0
        
        # Combined score with weights
        path_score = 0.6 * node_coverage + 0.4 * edge_coverage
        total_coverage += path_score
    
    return total_coverage / len(paths)

def compute_graph_edit_distance(gold_graph: nx.DiGraph, pred_graph: nx.DiGraph) -> float:
    """Compute normalized graph edit distance"""
    # Get node sets
    gold_nodes = set(gold_graph.nodes())
    pred_nodes = set(pred_graph.nodes())
    
    # Node operations
    node_insertions = len(pred_nodes - gold_nodes)
    node_deletions = len(gold_nodes - pred_nodes)
    
    # Get edge sets
    gold_edges = set(gold_graph.edges())
    pred_edges = set(pred_graph.edges())
    
    # Edge operations
    edge_insertions = len(pred_edges - gold_edges)
    edge_deletions = len(gold_edges - pred_edges)
    
    # Total edit distance
    total_edits = node_insertions + node_deletions + edge_insertions + edge_deletions
    
    # Normalize by total elements
    total_elements = len(gold_nodes) + len(gold_edges) + len(pred_nodes) + len(pred_edges)
    
    if total_elements > 0:
        normalized_ged = total_edits / total_elements
    else:
        normalized_ged = 0.0
    
    return total_edits  # Return raw count for now

# === Main Evaluation Workflow ===

def evaluate_files(file_list, device_map=None, custom_rules=None):
    """Evaluate CPAG generation on each file"""
    all_prec, all_rec, all_f1 = [], [], []
    pc_values = []
    ged_values = []
    
    for file_path in file_list:
        print(f"\n*** Evaluating file: {file_path} ***")
        
        # Read data
        df = pd.read_csv(file_path)
        print(f"Loaded {len(df)} rows with {len(df.columns)} columns")
        
        # Generate CPAG units
        cpag_units = build_cpag_from_csv(df, device_map=device_map, rules=custom_rules)
        print(f"Generated {len(cpag_units)} CPAG units")
        
        # Derive gold units
        gold_units = derive_gold_units(df, cpag_units)
        print(f"Gold standard has {len(gold_units)} units")
        
        if gold_units:
            # Match units
            matches = match_units(gold_units, cpag_units, similarity_threshold=0.3)
            prec, rec, f1, TP, FP, FN = precision_recall_F1(gold_units, cpag_units, matches)
            
            all_prec.append(prec)
            all_rec.append(rec)
            all_f1.append(f1)
            
            print(f"Precision={prec:.3f}, Recall={rec:.3f}, F1={f1:.3f}  (TP={TP}, FP={FP}, FN={FN})")
            
            # Build graphs
            gold_graph = build_graph_from_units(gold_units)
            pred_graph = build_graph_from_units(cpag_units)
            
            # Path coverage
            paths = extract_reference_paths(df, gold_units)
            if paths:
                pc = compute_path_coverage(paths, pred_graph)
                pc_values.append(pc)
                print(f"Path Coverage={pc:.2f} for {len(paths)} reference paths")
            
            # Graph edit distance
            ged = compute_graph_edit_distance(gold_graph, pred_graph)
            ged_values.append(ged)
            print(f"Graph Edit Distance = {ged:.0f}")
    
    # Summary
    if all_prec:
        print(f"\n=== EVALUATION SUMMARY ===")
        print(f"Average Precision: {np.mean(all_prec):.3f}")
        print(f"Average Recall: {np.mean(all_rec):.3f}")
        print(f"Average F1 Score: {np.mean(all_f1):.3f}")
        
        if pc_values:
            print(f"Average Path Coverage: {np.mean(pc_values):.3f}")
        
        # Generate visualizations
        generate_evaluation_plots(all_prec, all_rec, all_f1, pc_values, ged_values)

def generate_evaluation_plots(all_prec, all_rec, all_f1, pc_values, ged_values):
    """Generate evaluation visualization plots"""
    # Set style
    plt.style.use('seaborn-v0_8-darkgrid')
    
    # Figure 1: Precision, Recall, F1
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Bar plot
    x = np.arange(len(all_prec))
    width = 0.25
    
    ax1.bar(x - width, all_prec, width, label='Precision', color='skyblue', alpha=0.8)
    ax1.bar(x, all_rec, width, label='Recall', color='lightcoral', alpha=0.8)
    ax1.bar(x + width, all_f1, width, label='F1 Score', color='lightgreen', alpha=0.8)
    
    ax1.set_xlabel('Evaluation Run')
    ax1.set_ylabel('Score')
    ax1.set_title('CPAG Evaluation Metrics')
    ax1.set_xticks(x)
    ax1.set_xticklabels([f'Run {i+1}' for i in range(len(all_prec))])
    ax1.legend()
    ax1.set_ylim(0, 1.05)
    
    # Summary statistics
    metrics_data = {
        'Metric': ['Precision', 'Recall', 'F1 Score'],
        'Mean': [np.mean(all_prec), np.mean(all_rec), np.mean(all_f1)],
        'Std': [np.std(all_prec), np.std(all_rec), np.std(all_f1)]
    }
    
    ax2.axis('tight')
    ax2.axis('off')
    table_data = [[m, f"{mean:.3f} ± {std:.3f}"] 
                  for m, mean, std in zip(metrics_data['Metric'], 
                                          metrics_data['Mean'], 
                                          metrics_data['Std'])]
    
    table = ax2.table(cellText=table_data,
                      colLabels=['Metric', 'Value (Mean ± Std)'],
                      cellLoc='center',
                      loc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(12)
    table.scale(1, 2)
    ax2.set_title('Summary Statistics', pad=20)
    
    plt.tight_layout()
    plt.savefig('swat_evaluation_metrics.png', dpi=150, bbox_inches='tight')
    plt.close()
    
    # Figure 2: Path Coverage and GED
    if pc_values or ged_values:
        fig, axes = plt.subplots(1, 2 if pc_values and ged_values else 1, 
                                figsize=(10 if pc_values and ged_values else 5, 5))
        
        if not isinstance(axes, np.ndarray):
            axes = [axes]
        
        ax_idx = 0
        
        if pc_values:
            ax = axes[ax_idx]
            ax.bar(range(len(pc_values)), pc_values, color='purple', alpha=0.7)
            ax.set_xlabel('Evaluation Run')
            ax.set_ylabel('Path Coverage')
            ax.set_title('Attack Path Coverage')
            ax.set_ylim(0, 1.05)
            ax.axhline(y=np.mean(pc_values), color='red', linestyle='--', 
                      label=f'Mean: {np.mean(pc_values):.3f}')
            ax.legend()
            ax_idx += 1
        
        if ged_values and ax_idx < len(axes):
            ax = axes[ax_idx]
            ax.bar(range(len(ged_values)), ged_values, color='orange', alpha=0.7)
            ax.set_xlabel('Evaluation Run')
            ax.set_ylabel('Graph Edit Distance')
            ax.set_title('Graph Structure Difference')
            ax.axhline(y=np.mean(ged_values), color='red', linestyle='--',
                      label=f'Mean: {np.mean(ged_values):.0f}')
            ax.legend()
        
        plt.tight_layout()
        plt.savefig('swat_graph_metrics.png', dpi=150, bbox_inches='tight')
        plt.close()
    
    print("\nEvaluation plots saved: swat_evaluation_metrics.png, swat_graph_metrics.png")

def main():
    """Main evaluation entry point"""
    print("SWaT-Optimized CPAG Evaluation Framework")
    print("=" * 50)
    
    # Load configurations
    device_map, rules = load_configurations()
    print(f"Loaded {len(device_map)} device mappings")
    print(f"Loaded {len(rules)} custom rules")
    
    # Get test files
    csv_files = list(Path("data/csv").glob("*.csv"))  # Test with all files
    
    if not csv_files:
        print("No CSV files found in data/csv/")
        return
    
    test_files = [str(f) for f in csv_files]
    print(f"\nEvaluating {len(test_files)} files...")
    
    # Run evaluation
    evaluate_files(test_files, device_map=device_map, custom_rules=rules)

if __name__ == "__main__":
    main()
