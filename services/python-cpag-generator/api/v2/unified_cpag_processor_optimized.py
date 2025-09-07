#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Optimized CPAG processor to reduce redundant units and improve quality
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import re


class OptimizedCPAGProcessor:
    """Optimized CPAG processor with reduced unit generation"""
    
    def __init__(self, base_processor):
        """Initialize with reference to base processor for reusing methods"""
        self.base_processor = base_processor
        # Critical device list
        self.critical_devices = {
            'P101', 'P102', 'MV101', 'P201', 'P301', 'P302', 
            'P401', 'UV401', 'P501', 'P502', 'P601', 'P602'
        }
        # Important sensors
        self.important_sensors = {
            'LIT101', 'LIT301', 'LIT401', 'LIT601', 'LIT602',
            'FIT101', 'FIT201', 'FIT301', 'FIT401', 'FIT501',
            'AIT201', 'AIT202', 'AIT203', 'AIT301', 'AIT401',
            'PIT501', 'PIT502', 'PIT503', 'DPIT301'
        }
    
    def build_industrial_cpag_units_optimized(self, df: pd.DataFrame, 
                                            device_map: Optional[Dict[str, str]], 
                                            rules: Optional[List[str]],
                                            custom_params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """构建优化的CPAG单元，减少冗余"""
        units = []
        
        # Identify device columns
        exclude_cols = ['timestamp', 'annotation', 'other anomalies', 'attack hash', 'attack name', 
                       'attack state', 'attack target', 'attack type', 'intent', 'attack mode',
                       'attack outcome', 'target selection', 'entry point', 'asd', 'attacker',
                       'attack id', 'attack subid', 'plant']
        
        device_columns = [col for col in df.columns 
                         if col.lower() not in [e.lower() for e in exclude_cols] 
                         and not col.startswith('A#')]
        
        print(f"Processing {len(device_columns)} devices with {len(df)} data points")
        
        # Get custom parameters
        params = custom_params or {}
        self.anomaly_threshold = params.get('anomaly_threshold', 3.0)
        self.state_transition_min_count = params.get('state_transition_min_count', 10)
        self.unit_generation_strategy = params.get('unit_generation_strategy', 'balanced')
        self.confidence_threshold = params.get('confidence_threshold', 0.7)
        self.time_window_size = params.get('time_window_size', 500)
        self.correlation_threshold = params.get('correlation_threshold', 0.8)
        
        # 1. Analyze behavior of each device (optimized version)
        for device in device_columns:
            device_units = self._analyze_device_behavior_optimized(df, device, device_map)
            units.extend(device_units)
        
        # 2. Only add critical interaction units
        interaction_units = self._analyze_key_interactions(df, device_columns, device_map)
        units.extend(interaction_units)
        
        # 3. Analyze attack patterns (if any)
        attack_columns = [col for col in df.columns if 'attack' in col.lower()]
        if attack_columns:
            attack_units = self._analyze_attack_patterns_optimized(df, device_columns, device_map)
            units.extend(attack_units)
        
        # 4. Aggregate and prioritize
        optimized_units = self._aggregate_and_prioritize_units(units)
        
        print(f"Generated {len(optimized_units)} optimized CPAG units (reduced from {len(units)})")
        
        return optimized_units
    
    def _analyze_device_behavior_optimized(self, df: pd.DataFrame, device: str, 
                                         device_map: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """优化的设备行为分析，减少冗余单元"""
        units = []
        device_name = device_map.get(device, device) if device_map else device
        
        try:
            values = pd.to_numeric(df[device], errors='coerce')
            if values.isna().all():
                return units
            
            # Basic statistics
            mean_val = values.mean()
            std_val = values.std()
            unique_values = values.nunique()
            valid_count = values.notna().sum()
            
            # Device type identification
            device_upper = device.upper()
            is_sensor = any(device_upper.startswith(p) for p in ['FIT', 'LIT', 'AIT', 'PIT', 'DPIT'])
            is_pump = device_upper.startswith('P') and len(device_upper) <= 4 and device_upper[1:].isdigit()
            is_valve = device_upper.startswith('MV')
            is_uv = device_upper.startswith('UV')
            is_critical = any(cd in device_upper for cd in self.critical_devices)
            is_important_sensor = any(s in device_upper for s in self.important_sensors)
            
            # 1. Only create connection units for critical devices
            if is_critical and valid_count > 100:
                conn_unit = {
                    'id': f"CONN_{device.replace(' ', '_')}",
                    'category': 'session',
                    'precondition': [f"Network access to {device_name}"],
                    'action': f"Establish connection to {device_name}",
                    'postcondition': [f"Connected to {device_name}"],
                    'evidence': {
                        'device': device,
                        'device_type': self._get_device_type(device_upper),
                        'data_points': int(valid_count),
                        'confidence': min(0.9, valid_count / 1000)
                    }
                }
                units.append(conn_unit)
            
            # 2. State change units - only record significant transitions of actuators
            if 2 <= unique_values <= 10 and (is_pump or is_valve) and valid_count > 50:
                state_transitions = self._detect_state_transitions(values)
                if state_transitions:
                    # Calculate total transition count
                    total_transitions = sum(t[2] for t in state_transitions)
                    
                    # Only create state units for frequently transitioning actuators
                    if total_transitions >= 20 and state_transitions[0][2] >= self.state_transition_min_count:
                        from_state, to_state, count = state_transitions[0]
                        state_unit = {
                            'id': f"STATE_{device.replace(' ', '_')}",
                            'category': 'state_change',
                            'precondition': [f"Control access to {device_name}"],
                            'action': f"Change {device_name} state",
                            'postcondition': [f"{device_name} state modified"],
                            'evidence': {
                                'device': device,
                                'device_type': 'pump' if is_pump else 'valve',
                                'primary_transition': f"{from_state} -> {to_state}",
                                'occurrences': count,
                                'total_transitions': total_transitions,
                                'confidence': min(0.95, count / 50) if count / 50 >= self.confidence_threshold else 0
                            }
                        }
                        units.append(state_unit)
            
            # 3. Anomaly detection - raise threshold, only detect significant anomalies
            if std_val > 0.1 and valid_count > 500:
                # Use configurable standard deviation as anomaly threshold
                anomalies = values[(values < mean_val - self.anomaly_threshold*std_val) | (values > mean_val + self.anomaly_threshold*std_val)]
                anomaly_ratio = len(anomalies) / valid_count
                
                # Only create units when anomaly ratio exceeds threshold
                if anomaly_ratio > 0.005:  # Above 0.5%
                    severity = 'high' if anomaly_ratio > 0.02 else 'medium'
                    
                    anomaly_unit = {
                        'id': f"ANOMALY_{device.replace(' ', '_')}",
                        'category': 'anomaly_detection',
                        'precondition': [f"Monitoring {device_name}"],
                        'action': f"Detect anomalous behavior in {device_name}",
                        'postcondition': [f"Anomaly identified in {device_name}"],
                        'evidence': {
                            'device': device,
                            'device_type': self._get_device_type(device_upper),
                            'anomaly_count': int(len(anomalies)),
                            'anomaly_ratio': round(anomaly_ratio, 4),
                            'severity': severity,
                            'mean': round(mean_val, 2),
                            'std': round(std_val, 2),
                            'confidence': min(0.9, anomaly_ratio * 50)
                        }
                    }
                    units.append(anomaly_unit)
            
            # 4. Industrial control units - only create for active actuators
            if (is_pump or is_valve or is_uv) and unique_values >= 2 and is_critical:
                # Check if there's actual control activity
                value_changes = values.diff().abs() > 0
                change_count = value_changes.sum()
                change_ratio = change_count / valid_count if valid_count > 0 else 0
                
                # Only create control units for active actuators
                if change_ratio > 0.005 and change_count > 10:
                    control_unit = {
                        'id': f"CONTROL_{device.replace(' ', '_')}",
                        'category': 'industrial_control',
                        'precondition': [f"Control access to {device_name}"],
                        'action': f"Execute control commands on {device_name}",
                        'postcondition': [f"Process affected by {device_name}"],
                        'evidence': {
                            'device': device,
                            'device_type': 'pump' if is_pump else 'valve' if is_valve else 'uv',
                            'activity_level': round(change_ratio, 4),
                            'change_count': int(change_count),
                            'confidence': 0.85
                        }
                    }
                    units.append(control_unit)
            
            # 5. Reconnaissance units - only create for important sensors
            if is_sensor and is_important_sensor and std_val > 0.5 and unique_values > 20:
                recon_unit = {
                    'id': f"RECON_{device.replace(' ', '_')}",
                    'category': 'reconnaissance',
                    'precondition': [f"Connected to {device_name}"],
                    'action': f"Monitor {device_name} readings",
                    'postcondition': [f"Attacker gains knowledge of {device_name} patterns"],
                    'evidence': {
                        'device': device,
                        'device_type': 'sensor',
                        'value_range': [round(values.min(), 2), round(values.max(), 2)],
                        'variation': round(std_val, 2),
                        'confidence': 0.7
                    }
                }
                units.append(recon_unit)
                
        except Exception as e:
            print(f"Warning: Error analyzing device {device}: {e}")
        
        return units
    
    def _get_device_type(self, device_upper: str) -> str:
        """获取设备类型"""
        if any(device_upper.startswith(p) for p in ['FIT', 'LIT', 'AIT', 'PIT', 'DPIT']):
            return 'sensor'
        elif device_upper.startswith('P') and len(device_upper) <= 4 and device_upper[1:].isdigit():
            return 'pump'
        elif device_upper.startswith('MV'):
            return 'valve'
        elif device_upper.startswith('UV'):
            return 'uv'
        elif device_upper.startswith('PLC'):
            return 'controller'
        else:
            return 'unknown'
    
    def _detect_state_transitions(self, values: pd.Series) -> List[Tuple[float, float, int]]:
        """检测状态转换"""
        transitions = defaultdict(int)
        clean_values = values.dropna()
        
        if len(clean_values) < 2:
            return []
        
        for i in range(1, len(clean_values)):
            if clean_values.iloc[i] != clean_values.iloc[i-1]:
                from_state = clean_values.iloc[i-1]
                to_state = clean_values.iloc[i]
                transitions[(from_state, to_state)] += 1
        
        # Sort by frequency
        sorted_transitions = sorted(
            [(k[0], k[1], v) for k, v in transitions.items()],
            key=lambda x: x[2],
            reverse=True
        )
        
        return sorted_transitions[:3]  # Only return top 3 most frequent transitions
    
    def _analyze_key_interactions(self, df: pd.DataFrame, device_columns: List[str], 
                                device_map: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """只分析关键设备之间的交互"""
        units = []
        
        # Only analyze critical devices
        critical_columns = []
        for col in device_columns:
            if any(cd in col.upper() for cd in self.critical_devices):
                critical_columns.append(col)
        
        if len(critical_columns) < 2:
            return units
        
        # Calculate correlations between critical devices
        numeric_data = df[critical_columns].apply(pd.to_numeric, errors='coerce')
        correlation_matrix = numeric_data.corr()
        
        # Only record strong correlations (> 0.8)
        added_pairs = set()
        
        for i, col1 in enumerate(critical_columns):
            for j, col2 in enumerate(critical_columns):
                if i < j and abs(correlation_matrix.iloc[i, j]) > self.correlation_threshold:
                    pair_key = tuple(sorted([col1, col2]))
                    if pair_key not in added_pairs:
                        added_pairs.add(pair_key)
                        
                        device1_name = device_map.get(col1, col1) if device_map else col1
                        device2_name = device_map.get(col2, col2) if device_map else col2
                        
                        interaction_unit = {
                            'id': f"INTERACT_{col1.replace(' ', '_')}_{col2.replace(' ', '_')}",
                            'category': 'process_dependency',
                            'precondition': [f"Monitoring {device1_name} and {device2_name}"],
                            'action': f"Identify dependency between {device1_name} and {device2_name}",
                            'postcondition': [f"Process correlation established"],
                            'evidence': {
                                'device1': col1,
                                'device2': col2,
                                'correlation': round(correlation_matrix.iloc[i, j], 3),
                                'confidence': abs(correlation_matrix.iloc[i, j])
                            }
                        }
                        units.append(interaction_unit)
        
        return units[:10]  # Return at most 10 interaction units
    
    def _analyze_attack_patterns_optimized(self, df: pd.DataFrame, device_columns: List[str],
                                         device_map: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """优化的攻击模式分析"""
        units = []
        
        # Find attack-related columns
        attack_target_cols = [col for col in df.columns if 'attack' in col.lower() and 'target' in col.lower()]
        attack_type_cols = [col for col in df.columns if 'attack' in col.lower() and 'type' in col.lower()]
        
        if not attack_target_cols:
            return units
        
        # Identify attack targets
        targets = set()
        for col in attack_target_cols:
            unique_targets = df[col].dropna().unique()
            targets.update([t for t in unique_targets if t not in ['', 'none', 'normal']])
        
        # Create one unit for each attack target
        for target in list(targets)[:5]:  # At most 5 attack targets
            target_upper = str(target).upper()
            
            # Find matching devices
            matched_devices = []
            for device in device_columns:
                if target_upper in device.upper():
                    matched_devices.append(device)
            
            if matched_devices:
                device_name = device_map.get(matched_devices[0], matched_devices[0]) if device_map else matched_devices[0]
                
                attack_unit = {
                    'id': f"ATTACK_{target_upper.replace(' ', '_')}",
                    'category': 'attack_execution',
                    'precondition': [f"Compromised access to {device_name}"],
                    'action': f"Execute attack on {device_name}",
                    'postcondition': [f"{device_name} operation disrupted"],
                    'evidence': {
                        'target': target,
                        'affected_devices': matched_devices,
                        'confidence': 0.9
                    }
                }
                units.append(attack_unit)
        
        return units
    
    def _aggregate_and_prioritize_units(self, units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """聚合相似单元并优先排序"""
        # 1. Remove completely duplicate units
        unique_units = []
        seen_ids = set()
        
        for unit in units:
            unit_id = unit['id']
            if unit_id not in seen_ids:
                seen_ids.add(unit_id)
                unique_units.append(unit)
        
        # 2. Group by category
        units_by_category = defaultdict(list)
        for unit in unique_units:
            units_by_category[unit['category']].append(unit)
        
        # 3. Sort by priority and limit quantity per category
        prioritized_units = []
        
        # Adjust category limits based on strategy
        if hasattr(self, 'unit_generation_strategy'):
            strategy = self.unit_generation_strategy
        else:
            strategy = 'balanced'
            
        if strategy == 'conservative':
            # Conservative strategy: fewer units, higher confidence requirements
            category_limits = {
                'attack_execution': (1.0, 3),
                'anomaly_detection': (0.9, 5),
                'state_change': (0.85, 5),
                'industrial_control': (0.8, 4),
                'process_dependency': (0.7, 3),
                'reconnaissance': (0.6, 2),
                'session': (0.5, 2),
                'process_flow': (0.4, 1)
            }
            min_confidence = 0.8
        elif strategy == 'aggressive':
            # Aggressive strategy: more units, lower confidence requirements
            category_limits = {
                'attack_execution': (1.0, 10),
                'anomaly_detection': (0.9, 20),
                'state_change': (0.85, 20),
                'industrial_control': (0.8, 15),
                'process_dependency': (0.7, 10),
                'reconnaissance': (0.6, 10),
                'session': (0.5, 10),
                'process_flow': (0.4, 5)
            }
            min_confidence = 0.5
        else:
            # Balanced strategy (default)
            category_limits = {
                'attack_execution': (1.0, 5),
                'anomaly_detection': (0.9, 10),
                'state_change': (0.85, 10),
                'industrial_control': (0.8, 8),
                'process_dependency': (0.7, 5),
                'reconnaissance': (0.6, 5),
                'session': (0.5, 5),
                'process_flow': (0.4, 3)
            }
            min_confidence = 0.7
        
        # Sort categories by priority
        sorted_categories = sorted(category_limits.items(), key=lambda x: x[1][0], reverse=True)
        
        for category, (priority, limit) in sorted_categories:
            category_units = units_by_category.get(category, [])
            
            # Sort units in this category by confidence
            sorted_units = sorted(
                category_units,
                key=lambda u: u.get('evidence', {}).get('confidence', 0),
                reverse=True
            )
            
            # Filter low confidence units
            if hasattr(self, 'confidence_threshold'):
                min_conf = self.confidence_threshold
            else:
                min_conf = min_confidence
                
            filtered_units = [u for u in sorted_units 
                            if u.get('evidence', {}).get('confidence', 0) >= min_conf]
            
            # Add limited quantity of units
            prioritized_units.extend(filtered_units[:limit])
        
        print(f"Unit distribution after optimization:")
        final_distribution = defaultdict(int)
        for unit in prioritized_units:
            final_distribution[unit['category']] += 1
        for cat, count in final_distribution.items():
            print(f"  {cat}: {count}")
        
        return prioritized_units
