#!/usr/bin/env python3
"""
Optimized evaluation functions for better gold unit derivation
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Tuple
from collections import defaultdict
import re


def derive_gold_units_optimized(df: pd.DataFrame, cpag_units: List[Dict]) -> List[Dict]:
    """改进的gold units推导，选择更多有代表性的单元"""
    gold_units = []
    
    # 1. 基于设备重要性评分
    critical_devices = {
        # Stage 1 - 关键设备
        'P101': 1.0, 'P102': 1.0, 'MV101': 0.9, 'LIT101': 0.8, 'FIT101': 0.8,
        # Stage 2
        'P201': 0.9, 'P202': 0.9, 'P203': 0.8, 'AIT201': 0.7, 'AIT202': 0.7, 'AIT203': 0.7,
        # Stage 3  
        'P301': 1.0, 'P302': 0.9, 'LIT301': 0.8, 'DPIT301': 0.7, 'FIT301': 0.7,
        # Stage 4
        'P401': 0.9, 'UV401': 1.0, 'AIT401': 0.7, 'AIT402': 0.7, 'FIT401': 0.7,
        # Stage 5
        'P501': 1.0, 'P502': 1.0, 'PIT501': 0.8, 'PIT502': 0.8, 'PIT503': 0.8,
        # Stage 6
        'P601': 0.9, 'P602': 0.9, 'LIT601': 0.8, 'LIT602': 0.8, 'FIT601': 0.7
    }
    
    # 2. 基于单元质量评分
    scored_units = []
    for unit in cpag_units:
        score = 0.0
        
        # 类别权重
        category_scores = {
            'attack_impact': 1.0,
            'anomaly_detection': 0.9,  # 提高异常检测权重
            'state_change': 0.85,
            'industrial_control': 0.8,
            'attack_propagation': 0.75,
            'process_flow': 0.6,
            'reconnaissance': 0.5,
            'session': 0.3
        }
        score += category_scores.get(unit.get('category', ''), 0.2)
        
        # 设备重要性
        evidence = unit.get('evidence', {})
        device = evidence.get('device', '')
        device_upper = device.upper()
        
        # 检查是否匹配关键设备
        for critical_dev, importance in critical_devices.items():
            if critical_dev in device_upper:
                score += importance * 0.5
                break
        
        # 置信度
        confidence = evidence.get('confidence', 0)
        score += confidence * 0.3
        
        # 异常相关指标
        anomaly_ratio = evidence.get('anomaly_ratio', 0)
        if anomaly_ratio > 0:
            score += min(anomaly_ratio * 20, 0.5)  # 提高异常权重
        
        # 严重性
        severity = evidence.get('severity', '')
        if severity == 'high':
            score += 0.4
        elif severity == 'medium':
            score += 0.2
        
        # 状态转换次数
        occurrences = evidence.get('occurrences', 0)
        total_transitions = evidence.get('total_transitions', 0)
        if occurrences > 10:
            score += 0.3
        if total_transitions > 50:
            score += 0.2
        
        # 活动水平（对于控制单元）
        activity_level = evidence.get('activity_level', 0)
        if activity_level > 0.01:
            score += 0.3
        
        # ID中包含ANOMALY或STATE的单元额外加分
        if 'ANOMALY' in unit.get('id', ''):
            score += 0.2
        elif 'STATE' in unit.get('id', ''):
            score += 0.15
        elif 'CONTROL' in unit.get('id', ''):
            score += 0.1
        
        scored_units.append((score, unit))
    
    # 3. 选择得分最高的单元（动态数量）
    scored_units.sort(reverse=True, key=lambda x: x[0])
    
    # 基于单元总数动态确定gold units数量
    total_units = len(cpag_units)
    if total_units < 50:
        target_gold_units = max(10, int(total_units * 0.35))
    elif total_units < 100:
        target_gold_units = max(15, int(total_units * 0.25))
    else:
        target_gold_units = max(20, int(total_units * 0.20))
    
    # 确保不超过30个gold units
    target_gold_units = min(target_gold_units, 30)
    
    print(f"Total units: {total_units}, Target gold units: {target_gold_units}")
    
    # 确保各类别的多样性
    category_counts = defaultdict(int)
    max_per_category = max(5, target_gold_units // 4)  # 增加每个类别的上限
    
    # 首先添加得分最高的单元
    for score, unit in scored_units[:5]:
        gold_units.append(unit)
        category_counts[unit.get('category', '')] += 1
    
    # 然后保证类别多样性
    for score, unit in scored_units[5:]:
        category = unit.get('category', '')
        if category_counts[category] < max_per_category:
            gold_units.append(unit)
            category_counts[category] += 1
            
            if len(gold_units) >= target_gold_units:
                break
    
    # 如果还没达到目标数量，继续添加高分单元
    if len(gold_units) < target_gold_units:
        for score, unit in scored_units[len(gold_units):]:
            if unit not in gold_units:
                gold_units.append(unit)
                if len(gold_units) >= target_gold_units:
                    break
    
    print(f"Selected {len(gold_units)} gold units")
    
    # 打印类别分布
    final_categories = defaultdict(int)
    for unit in gold_units:
        final_categories[unit.get('category', 'unknown')] += 1
    print(f"Gold units by category: {dict(final_categories)}")
    
    return gold_units


def calculate_weighted_metrics(gold_units: List[Dict], pred_units: List[Dict], 
                             matches: List[Tuple[int, int]]) -> Dict[str, float]:
    """计算加权的评估指标，考虑单元的重要性"""
    # 计算每个gold unit的权重
    weights = []
    for unit in gold_units:
        weight = 1.0
        category = unit.get('category', '')
        
        # 类别权重
        if category in ['attack_impact', 'anomaly_detection']:
            weight *= 1.5
        elif category in ['state_change', 'industrial_control']:
            weight *= 1.3
        elif category == 'session':
            weight *= 0.7
        
        # 置信度权重
        confidence = unit.get('evidence', {}).get('confidence', 0.5)
        weight *= (0.5 + confidence * 0.5)
        
        weights.append(weight)
    
    # 计算加权的TP
    weighted_tp = 0
    for gold_idx, pred_idx in matches:
        weighted_tp += weights[gold_idx]
    
    # 总权重
    total_weight = sum(weights)
    
    # 加权指标
    weighted_recall = weighted_tp / total_weight if total_weight > 0 else 0
    
    # Precision仍使用原始计算
    tp = len(matches)
    fp = len(pred_units) - tp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    
    # 加权F1
    weighted_f1 = 2 * (precision * weighted_recall) / (precision + weighted_recall) \
                  if (precision + weighted_recall) > 0 else 0
    
    return {
        'precision': precision,
        'recall': weighted_recall,
        'f1_score': weighted_f1,
        'weighted_tp': weighted_tp,
        'total_weight': total_weight
    }
