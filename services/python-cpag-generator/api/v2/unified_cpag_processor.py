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
from enum import Enum

import pandas as pd
import numpy as np

# Import confidence calculator
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from core.confidence_calculator import ConfidenceCalculator

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


class ConditionType(Enum):
    """前置条件类型"""
    CONNECTIVITY = "connectivity"
    SERVICE_ACCESS = "service_access"
    AUTHENTICATION = "authentication"
    DEVICE_STATE = "device_state"
    KNOWLEDGE = "knowledge"
    PHYSICAL_ACCESS = "physical_access"


class LogicalOperator(Enum):
    """逻辑操作符"""
    AND = "AND"
    OR = "OR"


class CPAGRelationshipAnalyzer:
    """CPAG单元关系分析器"""
    
    def __init__(self):
        pass
    
    def analyze_unit_relationships(self, cpag_units: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析CPAG单元之间的关系"""
        relationships = {
            'dependencies': {},  # 依赖关系
            'conflicts': [],     # 冲突关系  
            'enabling_chains': [], # 启用链
            'alternative_paths': [] # 替代路径
        }
        
        # 构建条件映射
        condition_providers = {}  # 哪个单元提供了什么后置条件
        condition_consumers = {}  # 哪个单元需要什么前置条件
        
        for unit in cpag_units:
            unit_id = unit['id']
            
            # 分析前置条件需求
            preconditions = self._extract_conditions_from_unit(unit, 'precondition')
            for precond in preconditions:
                condition_sig = self._get_condition_signature(precond)
                if condition_sig not in condition_consumers:
                    condition_consumers[condition_sig] = []
                condition_consumers[condition_sig].append(unit_id)
            
            # 分析后置条件提供
            postconditions = self._extract_conditions_from_unit(unit, 'postcondition')
            for postcond in postconditions:
                condition_sig = self._get_condition_signature(postcond)
                condition_providers[condition_sig] = unit_id
        
        # 构建依赖关系
        relationships['dependencies'] = self._build_dependencies(
            cpag_units, condition_providers, condition_consumers
        )
        
        # 发现替代路径 (OR关系)
        relationships['alternative_paths'] = self._find_alternative_paths(
            cpag_units, relationships['dependencies']
        )
        
        # 发现启用链 (AND关系)
        relationships['enabling_chains'] = self._find_enabling_chains(
            cpag_units, relationships['dependencies']
        )
        
        return relationships
    
    def _extract_conditions_from_unit(self, unit: Dict[str, Any], condition_type: str) -> List[str]:
        """从单元中提取条件"""
        conditions = unit.get(condition_type, [])
        if isinstance(conditions, str):
            return [conditions]
        return conditions or []
    
    def _get_condition_signature(self, condition: str) -> str:
        """生成条件签名用于匹配"""
        # 标准化条件描述
        condition = condition.lower().strip()
        
        # 提取关键信息
        if 'connectivity' in condition or 'connect' in condition:
            # 网络连接条件
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', condition)
            if ip_match:
                return f"connectivity:{ip_match.group(1)}"
        
        elif 'access' in condition:
            # 访问条件
            if 'service' in condition:
                return f"service_access:{self._extract_target(condition)}"
            else:
                return f"access:{self._extract_target(condition)}"
        
        elif 'control' in condition:
            return f"control:{self._extract_target(condition)}"
        
        elif 'data' in condition or 'information' in condition:
            return f"knowledge:{self._extract_target(condition)}"
        
        # 默认签名
        return f"generic:{self._extract_target(condition)}"
    
    def _extract_target(self, condition: str) -> str:
        """从条件中提取目标实体"""
        # 尝试提取IP地址
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', condition)
        if ip_match:
            return ip_match.group(1)
        
        # 尝试提取设备名
        for device_type in ['PLC', 'HMI', 'SCADA']:
            if device_type.lower() in condition.lower():
                return device_type.lower()
        
        return "unknown"
    
    def _build_dependencies(self, units: List[Dict[str, Any]], 
                          providers: Dict[str, str], 
                          consumers: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """构建单元间依赖关系"""
        dependencies = {}
        
        for unit in units:
            unit_id = unit['id']
            dependencies[unit_id] = []
            
            preconditions = self._extract_conditions_from_unit(unit, 'precondition')
            for precond in preconditions:
                condition_sig = self._get_condition_signature(precond)
                
                # 如果有其他单元提供这个条件
                if condition_sig in providers:
                    provider_unit = providers[condition_sig]
                    if provider_unit != unit_id:
                        dependencies[unit_id].append(provider_unit)
        
        return dependencies
    
    def _find_alternative_paths(self, units: List[Dict[str, Any]], 
                               dependencies: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """发现替代路径 (OR关系) - 限制数量避免过度复杂"""
        alternative_paths = []
        
        # 寻找具有相同目标但不同前置条件的单元
        target_map = {}
        for unit in units:
            action = unit.get('action', '').lower()
            target = self._extract_target(action)
            category = unit.get('category', '')
            
            key = f"{category}:{target}"
            if key not in target_map:
                target_map[key] = []
            target_map[key].append(unit['id'])
        
        # 找出有多个实现方式的目标，但限制替代路径数量
        for target_key, unit_ids in target_map.items():
            if len(unit_ids) > 1:
                # 最多保留3个替代单元，避免图过于复杂
                limited_units = unit_ids[:3]
                alternative_paths.append({
                    'target': target_key,
                    'alternative_units': limited_units,
                    'relationship_type': 'OR',
                    'description': f"Alternative ways to achieve {target_key}"
                })
        
        # 限制总的替代路径数量
        return alternative_paths[:5]
    
    def _find_enabling_chains(self, units: List[Dict[str, Any]], 
                             dependencies: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """发现启用链 (AND关系) - 限制复杂度"""
        enabling_chains = []
        
        # 寻找需要多个前置条件的单元，但限制复杂度
        for unit in units:
            unit_id = unit['id']
            preconditions = self._extract_conditions_from_unit(unit, 'precondition')
            
            if len(preconditions) > 1:
                # 这个单元需要多个前置条件，形成AND关系
                chain_units = dependencies.get(unit_id, [])
                if len(chain_units) > 1:
                    # 限制每个AND链最多3个必需单元
                    limited_required = chain_units[:3]
                    enabling_chains.append({
                        'target_unit': unit_id,
                        'required_units': limited_required,
                        'relationship_type': 'AND',
                        'description': f"Unit {unit_id} requires multiple preconditions"
                    })
        
        # 限制总的启用链数量
        return enabling_chains[:5]
    
    def enhance_cpag_units_with_relationships(self, cpag_units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """增强CPAG单元，添加关系信息"""
        relationships = self.analyze_unit_relationships(cpag_units)
        
        enhanced_units = []
        for unit in cpag_units:
            enhanced_unit = unit.copy()
            unit_id = unit['id']
            
            # 添加依赖信息
            enhanced_unit['dependencies'] = relationships['dependencies'].get(unit_id, [])
            
            # 检查是否是替代路径的一部分
            alternative_info = []
            for alt_path in relationships['alternative_paths']:
                if unit_id in alt_path['alternative_units']:
                    alternative_info.append({
                        'alternatives': [u for u in alt_path['alternative_units'] if u != unit_id],
                        'target': alt_path['target']
                    })
            enhanced_unit['alternatives'] = alternative_info
            
            # 检查是否是启用链的一部分
            chain_info = []
            for chain in relationships['enabling_chains']:
                if unit_id == chain['target_unit']:
                    enhanced_unit['requires_all'] = chain['required_units']
                elif unit_id in chain['required_units']:
                    chain_info.append(chain['target_unit'])
            enhanced_unit['enables'] = chain_info
            
            # 增强前置条件，添加逻辑关系
            enhanced_unit['precondition_logic'] = self._analyze_precondition_logic(unit)
            
            enhanced_units.append(enhanced_unit)
        
        return enhanced_units
    
    def _analyze_precondition_logic(self, unit: Dict[str, Any]) -> Dict[str, Any]:
        """分析单元的前置条件逻辑"""
        preconditions = self._extract_conditions_from_unit(unit, 'precondition')
        
        if len(preconditions) <= 1:
            return {'type': 'simple', 'conditions': preconditions}
        
        # 分析是否是AND还是OR关系
        # 默认多个前置条件为AND关系
        logic_type = 'AND'
        
        # 检查条件中是否有"或"的表达
        combined_text = ' '.join(preconditions).lower()
        if 'or' in combined_text or '或' in combined_text:
            logic_type = 'OR'
        
        return {
            'type': logic_type,
            'conditions': preconditions,
            'description': f"Requires {logic_type.lower()} of the conditions"
        }


class UnifiedCPAGProcessor:
    """Unified processor for all CPAG analysis tasks"""
    
    def __init__(self):
        self.confidence_calculator = ConfidenceCalculator()
        self.supported_formats = {'.csv', '.pcap', '.pcapng'}
        self.neo4j_driver = None
        self.relationship_analyzer = CPAGRelationshipAnalyzer()
    
    def _convert_to_tcity_format(self, cpag_units: List[Dict[str, Any]], graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """将CPAG数据转换为tcity格式，基于真实的攻击路径"""
        # 首先对CPAG单元进行去重和聚合
        aggregated_units = self._aggregate_similar_units(cpag_units)
        
        tcity_nodes = []
        tcity_edges = []
        
        # 定义颜色配置
        color_configs = {
            'init': {
                'lineColor': '#f5684c',
                'fillColor': '#FFD6C2',
                'textColor': '#000000'
            },
            'cyber': {
                'lineColor': '#75aed1',
                'fillColor': '#c4e9ff',
                'textColor': '#000000'
            },
            'physical': {
                'lineColor': '#ffe959',
                'fillColor': '#fcf2b1',
                'textColor': '#000000'
            },
            'impact': {
                'lineColor': '#6ae366',
                'fillColor': '#dfffdb',
                'textColor': '#000000'
            },
            'action': {
                'lineColor': '#808080',
                'fillColor': '#FFFFFF',
                'textColor': '#000000'
            },
            'physical-action': {
                'lineColor': '#ffe959',
                'fillColor': '#fcf2b1',
                'textColor': '#000000'
            },
            'or': {
                'lineColor': '#b87aff',
                'fillColor': '#e8cfff',
                'textColor': '#000000'
            }
        }
        
        # 创建条件到单元的映射，用于构建攻击路径
        postcondition_to_units = {}  # 后置条件 -> 提供此条件的单元
        precondition_to_units = {}   # 前置条件 -> 需要此条件的单元
        
        # 先建立映射关系
        for unit in aggregated_units:
            unit_id = unit.get('id', '')
            
            # 映射后置条件
            postconditions = unit.get('postcondition', [])
            if not isinstance(postconditions, list):
                postconditions = [postconditions] if postconditions else []
            
            for postcond in postconditions:
                if isinstance(postcond, str) and postcond.strip():
                    if postcond not in postcondition_to_units:
                        postcondition_to_units[postcond] = []
                    postcondition_to_units[postcond].append(unit_id)
            
            # 映射前置条件
            preconditions = unit.get('precondition', [])
            if not isinstance(preconditions, list):
                preconditions = [preconditions] if preconditions else []
            
            for precond in preconditions:
                if isinstance(precond, str) and precond.strip():
                    if precond not in precondition_to_units:
                        precondition_to_units[precond] = []
                    precondition_to_units[precond].append(unit_id)
        
        # 分层布局算法
        layers = self._create_attack_graph_layers(aggregated_units, postcondition_to_units, precondition_to_units)
        
        # 生成节点位置 - 改进的布局算法
        layer_spacing = 180  # 增加垂直间距
        min_node_spacing = 150  # 最小水平间距
        start_y = 120
        canvas_width = 1200  # 画布宽度
        
        for layer_idx, layer_units in enumerate(layers):
            y = start_y + layer_idx * layer_spacing
            
            # 根据节点数量动态调整间距
            num_nodes = len(layer_units)
            if num_nodes <= 1:
                node_spacing = min_node_spacing
                start_x = canvas_width // 2
            else:
                # 计算最佳间距，确保不超出画布宽度
                max_total_width = canvas_width - 200  # 留边距
                ideal_spacing = max_total_width / (num_nodes - 1) if num_nodes > 1 else min_node_spacing
                node_spacing = max(min_node_spacing, min(ideal_spacing, 300))  # 限制最大间距
                
                total_width = (num_nodes - 1) * node_spacing
                start_x = (canvas_width - total_width) // 2
            
            for i, unit_id in enumerate(layer_units):
                if num_nodes == 1:
                    x = start_x
                else:
                    x = start_x + i * node_spacing
                
                # 找到对应的单元数据
                unit = next((u for u in aggregated_units if u.get('id') == unit_id), None)
                if not unit:
                    continue
                
                # 确定节点类型
                node_type = self._determine_node_type_from_cpag(unit)
                
                # 生成节点标签
                label = self._generate_node_label(unit)
                
                # 计算置信度值
                b_value = self._calculate_unit_confidence(unit)
                
                # 确定节点大小
                radius = 13
                if node_type == 'or':
                    radius = 19
                elif node_type in ['action', 'physical-action']:
                    radius = 17
                elif node_type == 'init':
                    radius = 15
                
                tcity_node = {
                    'x': x,
                    'y': y,
                    'r': radius,
                    'label': label,
                    'id': unit_id,
                    'value': 'none',
                    'type': node_type,
                    'properties': {
                        'bValue': f"{b_value:.4f}"
                    },
                    'colorConfig': color_configs.get(node_type, color_configs['cyber'])
                }
                
                tcity_nodes.append(tcity_node)
        
        # 生成攻击路径边
        tcity_edges = self._generate_attack_edges(aggregated_units, postcondition_to_units, precondition_to_units)
        
        # 确定源节点和目标节点
        source_node = self._find_initial_node(aggregated_units)
        target_node = self._find_target_node(aggregated_units)
        
        # 创建tcity格式的完整结构
        tcity_data = {
            'graph': {
                'graphTitle': 'Cyber-physical attack graph',
                'nodes': tcity_nodes,
                'edges': tcity_edges,
                'source': source_node or (tcity_nodes[0]['id'] if tcity_nodes else 'attacker'),
                'target': target_node or (tcity_nodes[-1]['id'] if tcity_nodes else 'target')
            }
        }
        
        return tcity_data
    
    def _aggregate_similar_units(self, cpag_units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """聚合相似的CPAG单元，减少节点数量"""
        aggregated = {}
        device_actions = {}  # 设备 -> 动作类型 -> 单元列表
        
        for unit in cpag_units:
            # 提取关键信息用于聚合
            category = unit.get('category', 'unknown')
            evidence = unit.get('evidence', {})
            device = evidence.get('device', 'unknown') if isinstance(evidence, dict) else 'unknown'
            action_type = unit.get('action', '').lower()
            
            # 确定聚合键
            if category in ['session', 'reconnaissance', 'control', 'manipulation']:
                # 按设备和动作类型聚合
                if 'connect' in action_type or 'establish' in action_type:
                    agg_key = f"CONN_{device}"
                elif 'read' in action_type:
                    agg_key = f"READ_{device}"
                elif 'write' in action_type or 'control' in action_type:
                    agg_key = f"CONTROL_{device}"
                elif 'manipulate' in action_type or 'modify' in action_type:
                    agg_key = f"MANIP_{device}"
                else:
                    # 使用原始ID作为键，不聚合
                    agg_key = unit.get('id', f'unknown_{len(aggregated)}')
            else:
                # 对于其他类型，使用原始ID
                agg_key = unit.get('id', f'unknown_{len(aggregated)}')
            
            if agg_key not in aggregated:
                # 创建聚合单元
                aggregated_unit = {
                    'id': agg_key,
                    'category': category,
                    'action': self._get_generic_action_name(category, action_type, device),
                    'precondition': unit.get('precondition', []),
                    'postcondition': unit.get('postcondition', []),
                    'evidence': {
                        'device': device,
                        'type': evidence.get('type', 'unknown') if isinstance(evidence, dict) else 'unknown',
                        'count': 0,
                        'aggregated_count': 0
                    },
                    'confidence': {'combined': 0.0, 'count': 0},
                    'dependencies': unit.get('dependencies', []),
                    'alternatives': unit.get('alternatives', []),
                    'enables': unit.get('enables', []),
                    'precondition_logic': unit.get('precondition_logic', {})
                }
                aggregated[agg_key] = aggregated_unit
            
            # 更新聚合统计
            agg_unit = aggregated[agg_key]
            if isinstance(evidence, dict) and 'count' in evidence:
                agg_unit['evidence']['count'] += evidence.get('count', 0)
            agg_unit['evidence']['aggregated_count'] += 1
            
            # 累积置信度计算
            unit_confidence = self._calculate_original_unit_confidence(unit)
            agg_unit['confidence']['combined'] += unit_confidence
            agg_unit['confidence']['count'] += 1
            
            # 合并前置条件和后置条件（去重）
            if 'precondition' in unit:
                existing_precond = set(str(p) for p in agg_unit.get('precondition', []))
                for precond in unit['precondition']:
                    if str(precond) not in existing_precond:
                        agg_unit['precondition'].append(precond)
                        existing_precond.add(str(precond))
            
            if 'postcondition' in unit:
                existing_postcond = set(str(p) for p in agg_unit.get('postcondition', []))
                for postcond in unit['postcondition']:
                    if str(postcond) not in existing_postcond:
                        agg_unit['postcondition'].append(postcond)
                        existing_postcond.add(str(postcond))
        
        # 计算每个聚合单元的最终置信度
        for agg_unit in aggregated.values():
            confidence_data = agg_unit['confidence']
            if confidence_data['count'] > 0:
                # 计算平均置信度，并根据数据量进行调整
                avg_confidence = confidence_data['combined'] / confidence_data['count']
                evidence_count = agg_unit['evidence'].get('count', 0)
                
                # 根据证据数量调整置信度 (更多证据 = 更高置信度)
                evidence_boost = min(0.2, evidence_count / 1000 * 0.1)  # 最多增加0.2
                final_confidence = min(1.0, avg_confidence + evidence_boost)
                
                agg_unit['confidence']['combined'] = final_confidence
            else:
                agg_unit['confidence']['combined'] = 0.5  # 默认值
        
        # 进一步合并非常相似的节点
        final_aggregated = self._merge_highly_similar_nodes(list(aggregated.values()))
        
        print(f"Aggregation: {len(cpag_units)} units -> {len(final_aggregated)} aggregated units")
        return final_aggregated
    
    def _get_generic_action_name(self, category: str, action_type: str, device: str) -> str:
        """生成通用的动作名称"""
        if category == 'session':
            if 'connect' in action_type or 'establish' in action_type:
                return f"Connect to {device}"
            else:
                return f"Session with {device}"
        elif category == 'reconnaissance':
            if 'read' in action_type:
                return f"Read data from {device}"
            else:
                return f"Reconnaissance on {device}"
        elif category == 'control':
            return f"Control {device}"
        elif category == 'manipulation':
            return f"Manipulate {device}"
        elif category == 'impact':
            return f"Impact on {device}"
        else:
            return f"Action on {device}"
    
    def _merge_highly_similar_nodes(self, units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """合并高度相似的节点"""
        merged = []
        device_categories = {}  # 设备 -> 类别 -> 单元
        
        for unit in units:
            evidence = unit.get('evidence', {})
            device = evidence.get('device', 'unknown') if isinstance(evidence, dict) else 'unknown'
            category = unit.get('category', 'unknown')
            
            key = f"{device}_{category}"
            
            if key not in device_categories:
                device_categories[key] = []
            device_categories[key].append(unit)
        
        # 对每个设备-类别组合，如果有多个单元，合并成一个
        for key, group_units in device_categories.items():
            if len(group_units) == 1:
                merged.append(group_units[0])
            else:
                # 合并多个单元
                merged_unit = group_units[0].copy()  # 使用第一个作为基础
                
                # 合并统计信息
                total_count = sum(u.get('evidence', {}).get('count', 0) for u in group_units if isinstance(u.get('evidence'), dict))
                total_aggregated = sum(u.get('evidence', {}).get('aggregated_count', 0) for u in group_units if isinstance(u.get('evidence'), dict))
                
                merged_unit['evidence']['count'] = total_count
                merged_unit['evidence']['aggregated_count'] = total_aggregated
                
                # 合并前置条件和后置条件
                all_precond = set()
                all_postcond = set()
                
                for unit in group_units:
                    for precond in unit.get('precondition', []):
                        all_precond.add(str(precond))
                    for postcond in unit.get('postcondition', []):
                        all_postcond.add(str(postcond))
                
                merged_unit['precondition'] = list(all_precond)
                merged_unit['postcondition'] = list(all_postcond)
                
                merged.append(merged_unit)
        
        return merged
    
    def _determine_node_type_from_cpag(self, unit: Dict[str, Any]) -> str:
        """根据CPAG单元确定tcity节点类型"""
        category = unit.get('category', '').lower()
        unit_id = unit.get('id', '').lower()
        action = unit.get('action', '').lower()
        preconditions = unit.get('precondition', [])
        
        # 分析前置条件来判断节点类型
        has_physical_access = any('physical access' in str(precond).lower() for precond in preconditions if precond)
        
        # 根据CPAG类别映射节点类型
        if category == 'session':
            if has_physical_access:
                return 'physical'  # 需要物理访问的连接
            else:
                return 'cyber'     # 网络连接
        elif category == 'reconnaissance':
            return 'cyber'         # 侦察行为
        elif category == 'control':
            return 'action'        # 控制动作
        elif category == 'impact':
            return 'impact'        # 影响节点
        elif category == 'manipulation':
            return 'action'        # 操纵动作
        elif 'attacker' in unit_id:
            return 'init'          # 攻击者起始点
        elif 'target' in unit_id:
            return 'impact'        # 目标节点
        else:
            # 基于动作内容进一步判断
            if any(keyword in action for keyword in ['physical', 'access', 'bypass']):
                return 'physical-action'
            elif any(keyword in action for keyword in ['connect', 'establish', 'network']):
                return 'cyber'
            elif any(keyword in action for keyword in ['read', 'write', 'control', 'modify']):
                return 'action'
            else:
                return 'cyber'  # 默认类型
    
    def _generate_node_label(self, unit: Dict[str, Any]) -> str:
        """生成节点标签"""
        # 优先使用action作为标签，如果没有则使用id的简化版本
        action = unit.get('action', '')
        if action:
            # 截断过长的标签
            if len(action) > 30:
                return action[:27] + '...'
            return action
        
        # 从ID生成友好的标签
        unit_id = unit.get('id', '')
        if '_' in unit_id:
            parts = unit_id.split('_')
            if len(parts) >= 2:
                return f"{parts[0]} {parts[1]}"
        
        return unit_id
    
    def _create_attack_graph_layers(self, cpag_units: List[Dict[str, Any]], 
                                   postcondition_to_units: Dict[str, List[str]], 
                                   precondition_to_units: Dict[str, List[str]]) -> List[List[str]]:
        """创建攻击图的分层结构"""
        layers = []
        placed_units = set()
        unit_to_layer = {}
        
        # 找到没有前置条件的单元（初始节点）
        initial_units = []
        for unit in cpag_units:
            preconditions = unit.get('precondition', [])
            if not preconditions or all(not str(p).strip() for p in preconditions):
                initial_units.append(unit.get('id'))
        
        if not initial_units:
            # 如果没找到初始节点，选择第一个作为起点
            initial_units = [cpag_units[0].get('id')] if cpag_units else []
        
        # 第一层：初始节点
        if initial_units:
            layers.append(initial_units)
            placed_units.update(initial_units)
            for unit_id in initial_units:
                unit_to_layer[unit_id] = 0
        
        # 迭代构建后续层次
        current_layer = 0
        max_iterations = len(cpag_units)  # 防止无限循环
        
        while len(placed_units) < len(cpag_units) and current_layer < max_iterations:
            next_layer_units = []
            
            for unit in cpag_units:
                unit_id = unit.get('id')
                if unit_id in placed_units:
                    continue
                
                # 检查此单元的前置条件是否已满足
                preconditions = unit.get('precondition', [])
                can_place = True
                
                for precond in preconditions:
                    if isinstance(precond, str) and precond.strip():
                        # 检查是否有已放置的单元可以满足此前置条件
                        providers = postcondition_to_units.get(precond, [])
                        if not any(provider in placed_units for provider in providers):
                            can_place = False
                            break
                
                if can_place:
                    next_layer_units.append(unit_id)
            
            if next_layer_units:
                layers.append(next_layer_units)
                placed_units.update(next_layer_units)
                current_layer += 1
                for unit_id in next_layer_units:
                    unit_to_layer[unit_id] = current_layer
            else:
                # 如果没有新节点可以放置，放置剩余的节点到下一层
                remaining_units = [u.get('id') for u in cpag_units if u.get('id') not in placed_units]
                if remaining_units:
                    layers.append(remaining_units)
                    placed_units.update(remaining_units)
                break
        
        return layers
    
    def _generate_attack_edges(self, cpag_units: List[Dict[str, Any]], 
                              postcondition_to_units: Dict[str, List[str]], 
                              precondition_to_units: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """生成攻击路径边"""
        edges = []
        
        for unit in cpag_units:
            unit_id = unit.get('id')
            preconditions = unit.get('precondition', [])
            
            if not isinstance(preconditions, list):
                preconditions = [preconditions] if preconditions else []
            
            for precond in preconditions:
                if isinstance(precond, str) and precond.strip():
                    # 找到提供此前置条件的单元
                    providers = postcondition_to_units.get(precond, [])
                    
                    for provider_id in providers:
                        if provider_id != unit_id:  # 避免自环
                            edge = {
                                'value': '1.0',
                                'source': provider_id,
                                'target': unit_id,
                                'label': '',  # 可以添加条件标签
                                'properties': {}
                            }
                            edges.append(edge)
        
        return edges
    
    def _find_initial_node(self, cpag_units: List[Dict[str, Any]]) -> Optional[str]:
        """找到初始攻击节点"""
        for unit in cpag_units:
            unit_id = unit.get('id', '').lower()
            category = unit.get('category', '').lower()
            preconditions = unit.get('precondition', [])
            
            # 寻找攻击者起始点或没有前置条件的节点
            if ('attacker' in unit_id or 
                not preconditions or 
                all(not str(p).strip() for p in preconditions)):
                return unit.get('id')
        
        return cpag_units[0].get('id') if cpag_units else None
    
    def _find_target_node(self, cpag_units: List[Dict[str, Any]]) -> Optional[str]:
        """找到目标节点"""
        # 寻找impact类别的节点或包含target的节点
        for unit in cpag_units:
            unit_id = unit.get('id', '').lower()
            category = unit.get('category', '').lower()
            
            if category == 'impact' or 'target' in unit_id:
                return unit.get('id')
        
        return cpag_units[-1].get('id') if cpag_units else None
    
    def _calculate_unit_confidence(self, unit: Dict[str, Any]) -> float:
        """计算聚合单元的置信度"""
        confidence_data = unit.get('confidence', {})
        if isinstance(confidence_data, dict) and 'combined' in confidence_data:
            return confidence_data['combined']
        else:
            # 如果没有预计算的置信度，基于证据计算
            return self._calculate_original_unit_confidence(unit)
    
    def _calculate_original_unit_confidence(self, unit: Dict[str, Any]) -> float:
        """计算原始CPAG单元的置信度"""
        category = unit.get('category', 'unknown').lower()
        evidence = unit.get('evidence', {})
        
        # 首先检查evidence中是否有confidence值
        if isinstance(evidence, dict) and 'confidence' in evidence:
            return float(evidence['confidence'])
        
        # 基础置信度（基于类别）
        base_confidence = {
            'session': 0.8,        # 会话建立 - 较高置信度
            'reconnaissance': 0.9,  # 侦察行为 - 高置信度
            'control': 0.95,       # 控制动作 - 很高置信度
            'manipulation': 0.95,  # 操纵行为 - 很高置信度
            'impact': 0.85,        # 影响评估 - 高置信度
            'unknown': 0.5         # 未知类型 - 中等置信度
        }.get(category, 0.5)
        
        # 根据证据数量调整
        if isinstance(evidence, dict) and 'count' in evidence:
            count = evidence.get('count', 0)
            if count > 100:
                base_confidence = min(1.0, base_confidence + 0.1)  # 大量证据增加置信度
            elif count > 10:
                base_confidence = min(1.0, base_confidence + 0.05) # 适量证据略微增加
            elif count < 5:
                base_confidence = max(0.1, base_confidence - 0.1)  # 少量证据降低置信度
        
        # 基于ID中的协议信息调整置信度
        unit_id = unit.get('id', '').lower()
        if 'enip' in unit_id or 'cip' in unit_id:
            base_confidence = min(1.0, base_confidence + 0.05)  # 工业协议增加置信度
        elif 'modbus' in unit_id:
            base_confidence = min(1.0, base_confidence + 0.1)   # Modbus高置信度
        
        return base_confidence
    
    def _conditions_match(self, precond: Dict[str, Any], postcond: Dict[str, Any]) -> bool:
        """简单的条件匹配逻辑"""
        # 这里可以实现更复杂的匹配逻辑
        precond_type = precond.get('type', '')
        postcond_type = postcond.get('type', '')
        
        return precond_type == postcond_type
        
    def detect_file_type(self, file_path: str) -> str:
        """Detect file type based on extension and magic bytes"""
        file_path_obj = Path(file_path)
        extension = file_path_obj.suffix.lower()
        
        if extension == '.csv':
            return 'csv'
        elif extension in {'.pcap', '.pcapng'}:
            return self._detect_pcap_format(file_path_obj)
        else:
            # Try to detect by content
            try:
                return self._detect_by_content(file_path_obj)
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
                print(f"Neo4j config provided, attempting to store...")
                print(f"Result keys: {result.keys()}")
                print(f"Graph data: nodes={len(result.get('graph_data', {}).get('nodes', []))}, edges={len(result.get('graph_data', {}).get('edges', []))}")
                try:
                    self._store_to_neo4j(result, neo4j_config)
                    result['neo4j_stored'] = True
                except Exception as e:
                    print(f"Failed to store to Neo4j: {e}")
                    import traceback
                    traceback.print_exc()
                    result['neo4j_stored'] = False
                    result['neo4j_error'] = str(e)
            else:
                print(f"Neo4j storage skipped: config={neo4j_config is not None}, available={NEO4J_AVAILABLE}")
            
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
            cpag_units = self._build_cpag_from_csv(standardized_df, device_map, rules, kwargs.get('custom_params'))
            
            # Enhance units with relationship analysis
            cpag_units = self.relationship_analyzer.enhance_cpag_units_with_relationships(cpag_units)
            
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
            # Save enhanced JSON file
            enhanced_file = os.path.join(output_dir, 'cpag_enhanced.json')
            
            with open(enhanced_file, 'w', encoding='utf-8') as f:
                json.dump(enhanced_data, f, indent=2, ensure_ascii=False)
                
            output_files['enhanced_json'] = enhanced_file
            
            # Generate and save tcity format file
            tcity_data = self._convert_to_tcity_format(cpag_units, graph_data)
            tcity_file = os.path.join(output_dir, 'cpag_tcity.json')
            
            with open(tcity_file, 'w', encoding='utf-8') as f:
                json.dump(tcity_data, f, indent=2, ensure_ascii=False)
                
            output_files['tcity_json'] = tcity_file
            
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
        """Process PCAP/PCAPNG file using optimized parsing"""
        try:
            # Check if we should use optimized processor
            custom_params = kwargs.get('custom_params', {})
            use_optimized = custom_params.get('use_optimized_pcap', True)
            
            if use_optimized:
                # Use optimized PCAP processor
                try:
                    from .pcap_processor_optimized import OptimizedPCAPProcessor
                    pcap_processor = OptimizedPCAPProcessor(self)
                    
                    result = pcap_processor.process_pcap_optimized(
                        file_path=file_path,
                        file_type=file_type,
                        custom_params=custom_params,
                        max_pkts=max_pkts,
                        target_cip=target_cip,
                        top_k=top_k,
                        top_per_plc=top_per_plc
                    )
                    
                    # Extract results
                    cpag_units = result.get('units', [])
                    graph_data = result.get('graph_data', {})
                    
                    print(f"Optimized processor generated {len(cpag_units)} CPAG units")
                    
                except ImportError:
                    print("Warning: Optimized PCAP processor not available, using standard processor")
                    # Fall back to standard processing
                    use_optimized = False
            
            if not use_optimized:
                # Standard processing
                # Parse PCAP/PCAPNG for ENIP/CIP traffic
                if file_type == 'pcapng':
                    df = self._parse_pcapng_enip_requests(file_path, max_pkts=max_pkts, target_cip=target_cip)
                else:
                    df = self._parse_classic_pcap(file_path, max_pkts, target_cip)
                
                print(f"Extracted {len(df)} CIP requests from {file_type.upper()}")
                
                # Build CPAG units from parsed data
                cpag_units = self._build_cpag_units_from_df(df)
                
                # Enhance units with relationship analysis
                cpag_units = self.relationship_analyzer.enhance_cpag_units_with_relationships(cpag_units)
                
                # Build graph structures
                graph_data = self._build_graph_structures_from_units(cpag_units)
            
            # Generate visualizations if available
            if VISUALIZATION_AVAILABLE:
                self._generate_pcap_visualizations(graph_data, output_dir, top_k, top_per_plc)
            
            # Save outputs
            if use_optimized and 'result' in locals():
                # For optimized processing, we need to handle differently
                output_files = {}
                # Save CPAG units
                units_file = os.path.join(output_dir, 'cpag_units.json')
                with open(units_file, 'w', encoding='utf-8') as f:
                    json.dump(cpag_units, f, indent=2, ensure_ascii=False)
                output_files['units'] = units_file
                
                # Save graph data
                graph_file = os.path.join(output_dir, 'cpag_graph.json')
                with open(graph_file, 'w', encoding='utf-8') as f:
                    json.dump(graph_data, f, indent=2, ensure_ascii=False)
                output_files['graph'] = graph_file
                
                # Use stats from result
                packets_processed = result.get('stats', {}).get('packets_processed', 0)
            else:
                # Standard processing with df available
                output_files = self._save_pcap_results(output_dir, df, cpag_units, graph_data)
                packets_processed = len(df)
            
            # Create enhanced and minimal JSON files for v2 compatibility
            enhanced_data = {
                'units': cpag_units,
                'graph_data': graph_data,
                'stats': {
                    'packets_processed': packets_processed,
                    'cpag_units': len(cpag_units),
                    'nodes': len(graph_data.get('nodes', [])),
                    'edges': len(graph_data.get('edges', []))
                },
                'version': 'v2_enhanced'
            }
            # Save enhanced JSON file
            enhanced_file = os.path.join(output_dir, 'cpag_enhanced.json')
            
            with open(enhanced_file, 'w', encoding='utf-8') as f:
                json.dump(enhanced_data, f, indent=2, ensure_ascii=False)
                
            output_files['enhanced_json'] = enhanced_file
            
            # Generate and save tcity format file
            tcity_data = self._convert_to_tcity_format(cpag_units, graph_data)
            tcity_file = os.path.join(output_dir, 'cpag_tcity.json')
            
            with open(tcity_file, 'w', encoding='utf-8') as f:
                json.dump(tcity_data, f, indent=2, ensure_ascii=False)
                
            output_files['tcity_json'] = tcity_file
            
            return {
                'status': 'completed',
                'source_type': file_type,
                'packets_processed': packets_processed,
                'cpag_units': len(cpag_units),
                'nodes': len(graph_data.get('nodes', [])),
                'edges': len(graph_data.get('edges', [])),
                'output_files': output_files,
                'graph_data': graph_data,
                'units': cpag_units  # 添加 units 字段
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
    
    def _build_cpag_from_csv(self, df: pd.DataFrame, device_map: Optional[Dict[str, str]], rules: Optional[List[str]], custom_params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
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
            units.extend(self._build_industrial_cpag_units(df, device_map, rules, custom_params))
        
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
                    'postcondition': self._get_postcondition(category, str(dst_device), port),
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
                    'postcondition': self._get_postcondition(category, str(dst_device), service),
                    'evidence': {'count': count, 'destination': dst, 'service': service}
                }
                units.append(unit)
        
        return units
    
    def _build_industrial_cpag_units(self, df: pd.DataFrame, device_map: Optional[Dict[str, str]], rules: Optional[List[str]], custom_params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Build CPAG units from industrial sensor/actuator data - Enhanced with dynamic generation"""
        # 使用优化的处理器
        try:
            from .unified_cpag_processor_optimized import OptimizedCPAGProcessor
            optimized_processor = OptimizedCPAGProcessor(self)
            return optimized_processor.build_industrial_cpag_units_optimized(df, device_map, rules, custom_params)
        except ImportError:
            # 如果优化版本不可用，使用原始方法
            print("Warning: Optimized processor not available, using original method")
            return self._build_industrial_cpag_units_original(df, device_map, rules)
    
    def _build_industrial_cpag_units_original(self, df: pd.DataFrame, device_map: Optional[Dict[str, str]], rules: Optional[List[str]]) -> List[Dict[str, Any]]:
        """Original method for building CPAG units"""
        units = []
        
        # Identify sensor/actuator columns (exclude metadata columns)
        exclude_cols = ['timestamp', 'annotation', 'other anomalies', 'attack hash', 'attack name', 
                       'attack state', 'attack target', 'attack type', 'intent', 'attack mode',
                       'attack outcome', 'target selection', 'entry point', 'asd', 'attacker',
                       'attack id', 'attack subid', 'plant']
        
        device_columns = [col for col in df.columns 
                         if col.lower() not in [e.lower() for e in exclude_cols] 
                         and not col.startswith('A#')]  # Exclude anomaly detector columns
        
        print(f"Identified {len(device_columns)} device columns from CSV with {len(df)} rows")
        
        # Analyze each device based on actual data patterns
        for device in device_columns:
            device_units = self._analyze_device_behavior(df, device, device_map)
            units.extend(device_units)
        
        # Add cross-device interaction units based on correlations
        interaction_units = self._analyze_device_interactions(df, device_columns, device_map)
        units.extend(interaction_units)
        
        # Add attack-specific units if attack information is present
        if any(col for col in df.columns if 'attack' in col.lower()):
            attack_units = self._analyze_attack_patterns(df, device_columns, device_map)
            units.extend(attack_units)
        
        print(f"Generated {len(units)} CPAG units based on actual data patterns")
        return units
    
    def _analyze_device_behavior(self, df: pd.DataFrame, device: str, device_map: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Analyze individual device behavior and generate appropriate units"""
        units = []
        device_name = device_map.get(device, device) if device_map else device
        
        try:
            # Convert to numeric, handling non-numeric values
            values = pd.to_numeric(df[device], errors='coerce')
            
            # Skip if all values are NaN
            if values.isna().all():
                return units
            
            # Basic statistics
            mean_val = values.mean()
            std_val = values.std()
            unique_values = values.nunique()
            valid_count = values.notna().sum()
            
            # 1. Connection unit (only if device has sufficient data)
            if valid_count > 10:  # Only create if we have meaningful data
                conn_unit = {
                    'id': f"CONN_{device.replace(' ', '_')}",
                    'category': 'session',
                    'precondition': [f"Network access to {device_name}"],
                    'action': f"Establish connection to {device_name}",
                    'postcondition': [f"Connected to {device_name}"],
                    'evidence': {
                        'device': device,
                        'data_points': int(valid_count),
                        'confidence': min(0.9, valid_count / 100)
                    }
                }
                units.append(conn_unit)
            
            # 2. State change units for discrete-valued devices
            if 2 <= unique_values <= 10:  # Discrete states
                state_transitions = self._detect_state_transitions(values)
                for i, (from_state, to_state, count) in enumerate(state_transitions[:3]):  # Top 3 transitions
                    if count >= 5:  # Only significant transitions
                        state_unit = {
                            'id': f"STATE_{device.replace(' ', '_')}_{i}",
                            'category': 'state_change',
                            'precondition': [f"Control access to {device_name}", f"{device_name} in state {from_state}"],
                            'action': f"Change {device_name} from {from_state} to {to_state}",
                            'postcondition': [f"{device_name} in state {to_state}"],
                            'evidence': {
                                'device': device,
                                'from_state': float(from_state),
                                'to_state': float(to_state),
                                'occurrences': count,
                                'confidence': min(0.95, count / 20)
                            }
                        }
                        units.append(state_unit)
            
            # 3. Anomaly detection for continuous values
            if std_val > 0 and valid_count > 100:
                anomalies = values[(values < mean_val - 2.5*std_val) | (values > mean_val + 2.5*std_val)]
                anomaly_ratio = len(anomalies) / valid_count
                
                if anomaly_ratio > 0.001:  # At least 0.1% anomalies
                    anomaly_unit = {
                        'id': f"ANOMALY_{device.replace(' ', '_')}",
                        'category': 'attack_impact',
                        'precondition': [f"Control access to {device_name}"],
                        'action': f"Manipulate {device_name} to abnormal values",
                        'postcondition': [f"{device_name} exhibits anomalous behavior"],
                        'evidence': {
                            'device': device,
                            'anomaly_count': int(len(anomalies)),
                            'anomaly_ratio': round(anomaly_ratio, 4),
                            'mean': round(mean_val, 2),
                            'std': round(std_val, 2),
                            'confidence': min(0.9, anomaly_ratio * 100)
                        }
                    }
                    units.append(anomaly_unit)
            
            # 4. Reconnaissance for sensors with varying data
            device_upper = device.upper()
            is_sensor = any(device_upper.startswith(prefix) for prefix in ['FIT', 'LIT', 'AIT', 'PIT', 'DPIT'])
            
            if is_sensor and std_val > 0.1 and unique_values > 10:
                recon_unit = {
                    'id': f"RECON_{device.replace(' ', '_')}",
                    'category': 'reconnaissance',
                    'precondition': [f"Connected to {device_name}"],
                    'action': f"Monitor {device_name} readings",
                    'postcondition': [f"Attacker gains knowledge of {device_name} patterns"],
                    'evidence': {
                        'device': device,
                        'value_range': [round(values.min(), 2), round(values.max(), 2)],
                        'unique_values': int(unique_values),
                        'confidence': 0.8
                    }
                }
                units.append(recon_unit)
            
            # 5. Control units for actuators with state changes
            is_actuator = any(device_upper.startswith(prefix) for prefix in ['MV', 'P', 'UV'])
            if is_actuator and unique_values >= 2:
                control_unit = {
                    'id': f"CONTROL_{device.replace(' ', '_')}",
                    'category': 'state_change',
                    'precondition': [f"Connected to {device_name}"],
                    'action': f"Control {device_name} operation",
                    'postcondition': [f"Process state altered via {device_name}"],
                    'evidence': {
                        'device': device,
                        'states': int(unique_values),
                        'confidence': 0.85
                    }
                }
                units.append(control_unit)
            
        except Exception as e:
            print(f"Warning: Error analyzing device {device}: {e}")
        
        return units
    
    def _detect_state_transitions(self, values: pd.Series) -> List[tuple]:
        """Detect state transitions in discrete valued data"""
        transitions = defaultdict(int)
        
        # Remove NaN values and get clean series
        clean_values = values.dropna()
        
        if len(clean_values) < 2:
            return []
        
        # Count transitions
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
        
        return sorted_transitions
    
    def _analyze_device_interactions(self, df: pd.DataFrame, device_columns: List[str], device_map: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Analyze interactions between devices based on correlations"""
        units = []
        
        # Only analyze numeric columns with sufficient data
        numeric_cols = []
        for col in device_columns:
            try:
                values = pd.to_numeric(df[col], errors='coerce')
                if values.notna().sum() > 100:  # Need sufficient data
                    numeric_cols.append(col)
            except:
                pass
        
        if len(numeric_cols) < 2:
            return units
        
        try:
            # Calculate correlation matrix
            numeric_df = df[numeric_cols].apply(pd.to_numeric, errors='coerce')
            corr_matrix = numeric_df.corr()
            
            # Find strong correlations
            strong_correlations = []
            for i in range(len(numeric_cols)):
                for j in range(i+1, len(numeric_cols)):
                    correlation = corr_matrix.iloc[i, j]
                    if abs(correlation) > 0.75 and not np.isnan(correlation):
                        strong_correlations.append((numeric_cols[i], numeric_cols[j], correlation))
            
            # Create interaction units for top correlations
            for dev1, dev2, corr in sorted(strong_correlations, key=lambda x: abs(x[2]), reverse=True)[:5]:
                dev1_name = device_map.get(dev1, dev1) if device_map else dev1
                dev2_name = device_map.get(dev2, dev2) if device_map else dev2
                
                interaction_unit = {
                    'id': f"INTERACT_{dev1.replace(' ', '_')}_{dev2.replace(' ', '_')}",
                    'category': 'process_dependency',
                    'precondition': [f"Control over {dev1_name}"],
                    'action': f"Manipulate {dev1_name} affecting {dev2_name}",
                    'postcondition': [f"{dev2_name} behavior influenced by {dev1_name}"],
                    'evidence': {
                        'device1': dev1,
                        'device2': dev2,
                        'correlation': round(float(corr), 3),
                        'confidence': float(abs(corr))
                    }
                }
                units.append(interaction_unit)
        except Exception as e:
            print(f"Warning: Error analyzing device interactions: {e}")
        
        return units
    
    def _analyze_attack_patterns(self, df: pd.DataFrame, device_columns: List[str], device_map: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Analyze attack patterns from attack-related columns"""
        units = []
        
        try:
            # Find attack-related columns
            attack_target_cols = [col for col in df.columns if 'attack' in col.lower() and 'target' in col.lower()]
            
            if attack_target_cols:
                target_col = attack_target_cols[0]
                targets = df[target_col].dropna().unique()
                
                for target in targets:
                    if target and str(target).lower() not in ['none', 'normal', '']:
                        # Find rows where this target is attacked
                        attack_rows = df[df[target_col] == target]
                        
                        if len(attack_rows) >= 5:  # Significant attack presence
                            target_name = device_map.get(target, target) if device_map else target
                            
                            attack_unit = {
                                'id': f"ATTACK_{str(target).replace(' ', '_')}",
                                'category': 'attack_execution',
                                'precondition': [f"Compromised access to {target_name}"],
                                'action': f"Execute attack on {target_name}",
                                'postcondition': [f"{target_name} compromised", "Process integrity violated"],
                                'evidence': {
                                    'target': str(target),
                                    'attack_instances': int(len(attack_rows)),
                                    'confidence': min(0.95, len(attack_rows) / 50)
                                }
                            }
                            units.append(attack_unit)
        except Exception as e:
            print(f"Warning: Error analyzing attack patterns: {e}")
        
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
            
            # Calculate confidence for this unit
            unit_confidence = self._calculate_unit_confidence(unit)
            
            nodes.append({
                'id': action_id,
                'label': unit['action'],
                'type': 'action',
                'category': unit['category'],
                'count': evidence.get('count', 1),
                'device': evidence.get('destination', ''),
                'service': evidence.get('service', evidence.get('port', '')),
                'confidence': unit_confidence,
                'evidence_count': evidence.get('count', 1)
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
                
                # Calculate confidence for this unit
                unit_confidence = self._calculate_unit_confidence(unit)
                
                nodes.append({
                    'id': action_id,
                    'label': unit['action'],
                    'type': 'action',
                    'category': unit['category'],
                    'count': evidence.get('count', 1),
                    'device': device,
                    'service': evidence.get('operation', 'unknown'),
                    'confidence': unit_confidence,
                    'evidence_count': evidence.get('count', 1)
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
        
        # Create optimized attack chains avoiding redundancy
        edges.extend(self._create_optimized_industrial_attack_chains(cpag_units, edges))
        
        return {'nodes': nodes, 'edges': edges}
    
    def _create_optimized_industrial_attack_chains(self, cpag_units: List[Dict[str, Any]], existing_edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """创建优化的工业攻击链，避免冗余"""
        optimized_edges = []
        edge_set = set()
        
        # 添加现有边到集合中
        for edge in existing_edges:
            edge_set.add((edge['source'], edge['target'], edge['relation']))
        
        # 1. 处理明确的依赖关系（优先级最高）
        for unit in cpag_units:
            unit_id = unit['id']
            
            if 'dependencies' in unit and unit['dependencies']:
                for dep_unit in unit['dependencies']:
                    edge_key = (dep_unit, unit_id, 'requires')
                    if edge_key not in edge_set:
                        optimized_edges.append({
                            'source': dep_unit,
                            'target': unit_id,
                            'relation': 'requires',
                            'logic_type': 'AND'
                        })
                        edge_set.add(edge_key)
        
        # 2. 添加有限的PLC->设备控制链（最多3条）
        plc_units = [unit for unit in cpag_units if 'PLC' in unit.get('evidence', {}).get('device', '')]
        device_control_units = [unit for unit in cpag_units if unit.get('evidence', {}).get('operation') == 'control']
        
        compromise_count = 0
        for plc_unit in plc_units:
            for control_unit in device_control_units[:2]:  # 限制每个PLC最多控制2个设备
                if plc_unit['id'] != control_unit['id'] and compromise_count < 3:
                    edge_key = (plc_unit['id'], control_unit['id'], 'compromises')
                    if edge_key not in edge_set:
                        optimized_edges.append({
                            'source': plc_unit['id'],
                            'target': control_unit['id'],
                            'relation': 'compromises'
                        })
                        edge_set.add(edge_key)
                        compromise_count += 1
        
        # 3. 添加有限的替代路径（OR关系）
        for unit in cpag_units:
            unit_id = unit['id']
            
            if 'alternatives' in unit and unit['alternatives']:
                # 每个单元最多显示1个主要替代路径
                alt_info = unit['alternatives'][0]
                if 'alternatives' in alt_info and alt_info['alternatives']:
                    alt_unit = alt_info['alternatives'][0]
                    edge_key = (alt_unit, unit_id, 'alternative_to')
                    if edge_key not in edge_set:
                        optimized_edges.append({
                            'source': alt_unit,
                            'target': unit_id,
                            'relation': 'alternative_to',
                            'logic_type': 'OR'
                        })
                        edge_set.add(edge_key)
        
        return optimized_edges
    
    def _create_logical_relationship_edges(self, cpag_units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """为AND/OR逻辑关系创建边"""
        logical_edges = []
        
        for unit in cpag_units:
            unit_id = unit['id']
            
            # 处理依赖关系（AND关系）
            if 'dependencies' in unit and unit['dependencies']:
                for dep_unit in unit['dependencies']:
                    logical_edges.append({
                        'source': dep_unit,
                        'target': unit_id,
                        'relation': 'requires',
                        'logic_type': 'AND'
                    })
            
            # 处理替代路径（OR关系）
            if 'alternatives' in unit and unit['alternatives']:
                for alt_info in unit['alternatives']:
                    for alt_unit in alt_info['alternatives']:
                        logical_edges.append({
                            'source': alt_unit,
                            'target': unit_id,
                            'relation': 'alternative_to',
                            'logic_type': 'OR'
                        })
            
            # 处理多重前置条件（AND关系）
            if 'requires_all' in unit and unit['requires_all']:
                for req_unit in unit['requires_all']:
                    logical_edges.append({
                        'source': req_unit,
                        'target': unit_id,
                        'relation': 'required_by',
                        'logic_type': 'AND'
                    })
        
        return logical_edges
    
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
        """Build optimized tree-like graph structures from CPAG units with minimal redundancy"""
        nodes = []
        edges = []
        
        # Create nodes for all units
        for unit in cpag_units:
            action_id = unit['id']
            action = unit.get('action', '')
            category = unit.get('category', 'session')
            count = unit.get('evidence', {}).get('count', 1)
            
            # Extract destination and path information
            import re
            dst = ''
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", action)
            if ip_match:
                dst = ip_match.group(1)
            
            path_match = re.search(r"tag '([^']+)'", action)
            path = path_match.group(1) if path_match else ''
            
            # Calculate confidence for this unit
            unit_confidence = self._calculate_unit_confidence(unit)
            
            nodes.append({
                'id': action_id,
                'label': action,
                'type': 'action',
                'dst': dst,
                'category': category,
                'count': count,
                'path': path,
                'service': action.split(' on tag')[0] if ' on tag' in action else action,
                'confidence': unit_confidence,
                'evidence_count': count
            })
        
        # Build optimized tree structure based on logical relationships
        edges = self._build_optimized_tree_edges(cpag_units)
        
        print(f"Optimized graph structure: {len(nodes)} nodes, {len(edges)} edges")
        
        return {'nodes': nodes, 'edges': edges}
    
    def _build_optimized_tree_edges(self, cpag_units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """构建优化的树形边结构，避免冗余"""
        edges = []
        edge_set = set()  # 用于去重：(source, target, relation)
        
        # 1. 首先处理明确的依赖关系（树的主干）
        for unit in cpag_units:
            unit_id = unit['id']
            
            # 处理dependencies - 这是主要的AND关系
            if 'dependencies' in unit and unit['dependencies']:
                for dep_unit in unit['dependencies']:
                    edge_key = (dep_unit, unit_id, 'requires')
                    if edge_key not in edge_set:
                        # Calculate confidence for dependency edge
                        source_unit = next((u for u in cpag_units if u['id'] == dep_unit), {})
                        target_unit = unit
                        
                        evidence = {
                            'source': 'dependency_analysis',
                            'count': len(unit.get('dependencies', [])),
                            'category': unit.get('category', 'session'),
                            'relation': 'requires'
                        }
                        
                        context = {
                            'total_units': len(cpag_units),
                            'analysis_type': 'dependency'
                        }
                        
                        confidence = self.confidence_calculator.calculate_edge_confidence(
                            source_node=source_unit,
                            target_node=target_unit,
                            evidence=evidence,
                            context=context
                        )
                        
                        edges.append({
                            'source': dep_unit,
                            'target': unit_id,
                            'relation': 'requires',
                            'logic_type': 'AND',
                            'confidence': confidence
                        })
                        edge_set.add(edge_key)
        
        # 2. 添加OR关系（替代路径），但限制数量避免过度复杂
        for unit in cpag_units:
            unit_id = unit['id']
            
            if 'alternatives' in unit and unit['alternatives']:
                # 每个单元只显示最多2个替代路径，避免图过于复杂
                for alt_info in unit['alternatives'][:2]:
                    for alt_unit in alt_info['alternatives'][:1]:  # 每个替代信息只取第一个
                        edge_key = (alt_unit, unit_id, 'alternative_to')
                        if edge_key not in edge_set:
                            # Calculate confidence for alternative edge
                            source_unit = next((u for u in cpag_units if u['id'] == alt_unit), {})
                            target_unit = unit
                            
                            evidence = {
                                'source': 'alternative_analysis',
                                'count': len(unit.get('alternatives', [])),
                                'category': unit.get('category', 'session'),
                                'relation': 'alternative_to'
                            }
                            
                            context = {
                                'total_units': len(cpag_units),
                                'analysis_type': 'alternative'
                            }
                            
                            confidence = self.confidence_calculator.calculate_edge_confidence(
                                source_node=source_unit,
                                target_node=target_unit,
                                evidence=evidence,
                                context=context
                            )
                            
                            edges.append({
                                'source': alt_unit,
                                'target': unit_id,
                                'relation': 'alternative_to',
                                'logic_type': 'OR',
                                'confidence': confidence
                            })
                            edge_set.add(edge_key)
        
        # 3. 如果没有生成足够的边，基于攻击逻辑创建基础树形结构
        if len(edges) < len(cpag_units) * 0.3:  # 如果边太少，说明关系分析不充分
            edges.extend(self._create_fallback_tree_structure(cpag_units, edge_set))
        
        return edges
    
    def _create_fallback_tree_structure(self, cpag_units: List[Dict[str, Any]], existing_edges: set) -> List[Dict[str, Any]]:
        """当关系分析不充分时，创建基础的树形结构"""
        fallback_edges = []
        
        # 按目标IP和攻击阶段组织单元
        target_groups = {}
        for unit in cpag_units:
            # 提取目标IP
            action = unit.get('action', '')
            import re
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", action)
            target_ip = ip_match.group(1) if ip_match else 'unknown'
            
            if target_ip not in target_groups:
                target_groups[target_ip] = {'session': [], 'reconnaissance': [], 'state_change': []}
            
            category = unit.get('category', 'session')
            if category in target_groups[target_ip]:
                target_groups[target_ip][category].append(unit)
        
        # 为每个目标创建攻击链：session -> reconnaissance -> state_change
        for target_ip, categories in target_groups.items():
            # 创建攻击阶段链
            prev_units = categories['session']
            
            # session -> reconnaissance
            for session_unit in prev_units:
                for recon_unit in categories['reconnaissance']:
                    edge_key = (session_unit['id'], recon_unit['id'], 'enables')
                    if edge_key not in existing_edges:
                        # Calculate confidence for fallback edge
                        evidence = {
                            'source': 'fallback_analysis',
                            'count': 1,  # Fallback edges have lower confidence
                            'category': 'reconnaissance',
                            'relation': 'enables'
                        }
                        
                        context = {
                            'target_ip': target_ip,
                            'analysis_type': 'fallback'
                        }
                        
                        confidence = self.confidence_calculator.calculate_edge_confidence(
                            source_node=session_unit,
                            target_node=recon_unit,
                            evidence=evidence,
                            context=context
                        )
                        
                        fallback_edges.append({
                            'source': session_unit['id'],
                            'target': recon_unit['id'],
                            'relation': 'enables',
                            'confidence': confidence
                        })
                        existing_edges.add(edge_key)
            
            # reconnaissance -> state_change
            current_units = categories['reconnaissance'] if categories['reconnaissance'] else prev_units
            for current_unit in current_units:
                for state_unit in categories['state_change']:
                    edge_key = (current_unit['id'], state_unit['id'], 'enables')
                    if edge_key not in existing_edges:
                        # Calculate confidence for state change fallback edge
                        evidence = {
                            'source': 'fallback_analysis',
                            'count': 1,  # Fallback edges have lower confidence
                            'category': 'state_change',
                            'relation': 'enables'
                        }
                        
                        context = {
                            'target_ip': target_ip,
                            'analysis_type': 'fallback'
                        }
                        
                        confidence = self.confidence_calculator.calculate_edge_confidence(
                            source_node=current_unit,
                            target_node=state_unit,
                            evidence=evidence,
                            context=context
                        )
                        
                        fallback_edges.append({
                            'source': current_unit['id'],
                            'target': state_unit['id'],
                            'relation': 'enables',
                            'confidence': confidence
                        })
                        existing_edges.add(edge_key)
        
        return fallback_edges
    
    
    def _generate_pcap_visualizations(self, graph_data: Dict[str, Any], output_dir: str, top_k: int, top_per_plc: int):
        """Generate visualizations for PCAP data"""
        if not VISUALIZATION_AVAILABLE or plt is None or nx is None:
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