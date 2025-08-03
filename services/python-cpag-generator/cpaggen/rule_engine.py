"""
规则引擎
处理前置条件→动作→后置条件的攻击图推演
"""

import pandas as pd
from typing import Dict, List, Any, Tuple
import networkx as nx
from datetime import datetime

class RuleEngine:
    """攻击规则引擎"""
    
    def __init__(self):
        self.default_rules = [
            {
                'id': 'rule_001',
                'name': 'Port Scan Detection',
                'preconditions': ['tcp_connection', 'multiple_ports'],
                'action': 'port_scan',
                'postconditions': ['vulnerability_discovery', 'attack_surface_expansion']
            },
            {
                'id': 'rule_002',
                'name': 'Brute Force Attack',
                'preconditions': ['repeated_connections', 'same_destination'],
                'action': 'brute_force',
                'postconditions': ['credential_compromise', 'system_access']
            },
            {
                'id': 'rule_003',
                'name': 'Data Exfiltration',
                'preconditions': ['established_connection', 'large_data_transfer'],
                'action': 'data_exfiltration',
                'postconditions': ['data_loss', 'privacy_violation']
            }
        ]
    
    def process_rules(self, mapped_data: pd.DataFrame, custom_rules: List[str] = None) -> Dict[str, Any]:
        """
        处理规则并生成攻击图
        
        Args:
            mapped_data: 设备映射后的数据
            custom_rules: 自定义规则列表
            
        Returns:
            攻击图数据
        """
        # 合并默认规则和自定义规则
        all_rules = self.default_rules.copy()
        if custom_rules:
            all_rules.extend(self._parse_custom_rules(custom_rules))
        
        # 创建攻击图
        attack_graph = nx.DiGraph()
        
        # 分析数据包并应用规则
        events = self._analyze_packets(mapped_data)
        
        # 构建攻击路径
        attack_paths = self._build_attack_paths(events, all_rules)
        
        # 生成攻击图
        for path in attack_paths:
            self._add_path_to_graph(attack_graph, path)
        
        # 转换为可序列化的格式
        return self._graph_to_dict(attack_graph)
    
    def _parse_custom_rules(self, custom_rules: List[str]) -> List[Dict[str, Any]]:
        """解析自定义规则"""
        parsed_rules = []
        for i, rule in enumerate(custom_rules):
            # 简单的规则解析（实际实现中应该有更复杂的解析逻辑）
            parsed_rule = {
                'id': f'custom_rule_{i:03d}',
                'name': f'Custom Rule {i+1}',
                'preconditions': ['custom_precondition'],
                'action': 'custom_action',
                'postconditions': ['custom_postcondition']
            }
            parsed_rules.append(parsed_rule)
        
        return parsed_rules
    
    def _analyze_packets(self, mapped_data: pd.DataFrame) -> List[Dict[str, Any]]:
        """分析数据包并识别事件"""
        events = []
        
        if mapped_data.empty:
            return events
        
        # 按时间窗口分组分析
        time_windows = self._create_time_windows(mapped_data)
        
        for window_start, window_data in time_windows:
            window_events = self._analyze_time_window(window_data)
            events.extend(window_events)
        
        return events
    
    def _create_time_windows(self, data: pd.DataFrame, window_size: int = 60) -> List[Tuple[float, pd.DataFrame]]:
        """创建时间窗口"""
        if 'timestamp' not in data.columns:
            return [(0, data)]
        
        # 按时间窗口分组
        data['time_window'] = (data['timestamp'] // window_size).astype(int)
        windows = []
        
        for window_id, window_data in data.groupby('time_window'):
            window_start = window_id * window_size
            windows.append((window_start, window_data))
        
        return windows
    
    def _analyze_time_window(self, window_data: pd.DataFrame) -> List[Dict[str, Any]]:
        """分析单个时间窗口"""
        events = []
        
        # 检测端口扫描
        if self._detect_port_scan(window_data):
            events.append({
                'type': 'port_scan',
                'timestamp': window_data['timestamp'].iloc[0],
                'source': window_data['src_device'].iloc[0],
                'target': window_data['dst_device'].iloc[0],
                'confidence': 0.8
            })
        
        # 检测暴力破解
        if self._detect_brute_force(window_data):
            events.append({
                'type': 'brute_force',
                'timestamp': window_data['timestamp'].iloc[0],
                'source': window_data['src_device'].iloc[0],
                'target': window_data['dst_device'].iloc[0],
                'confidence': 0.9
            })
        
        # 检测数据泄露
        if self._detect_data_exfiltration(window_data):
            events.append({
                'type': 'data_exfiltration',
                'timestamp': window_data['timestamp'].iloc[0],
                'source': window_data['src_device'].iloc[0],
                'target': window_data['dst_device'].iloc[0],
                'confidence': 0.7
            })
        
        return events
    
    def _detect_port_scan(self, data: pd.DataFrame) -> bool:
        """检测端口扫描"""
        if data.empty:
            return False
        
        # 检查是否有多个目标端口
        unique_ports = data['dst_port'].nunique()
        return unique_ports > 10  # 阈值可配置
    
    def _detect_brute_force(self, data: pd.DataFrame) -> bool:
        """检测暴力破解"""
        if data.empty:
            return False
        
        # 检查重复连接
        connection_counts = data.groupby(['src_device', 'dst_device']).size()
        return connection_counts.max() > 50  # 阈值可配置
    
    def _detect_data_exfiltration(self, data: pd.DataFrame) -> bool:
        """检测数据泄露"""
        if data.empty:
            return False
        
        # 检查大量数据传输
        total_bytes = data['length'].sum()
        return total_bytes > 1000000  # 1MB阈值
    
    def _build_attack_paths(self, events: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """构建攻击路径"""
        paths = []
        
        for event in events:
            # 查找匹配的规则
            matching_rules = self._find_matching_rules(event, rules)
            
            for rule in matching_rules:
                path = self._create_attack_path(event, rule)
                paths.append(path)
        
        return paths
    
    def _find_matching_rules(self, event: Dict[str, Any], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """查找匹配的规则"""
        matching_rules = []
        
        for rule in rules:
            if event['type'] in rule['preconditions']:
                matching_rules.append(rule)
        
        return matching_rules
    
    def _create_attack_path(self, event: Dict[str, Any], rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """创建攻击路径"""
        path = []
        
        # 添加前置条件
        for precondition in rule['preconditions']:
            path.append({
                'type': 'precondition',
                'name': precondition,
                'timestamp': event['timestamp'],
                'source': event['source'],
                'target': event['target']
            })
        
        # 添加动作
        path.append({
            'type': 'action',
            'name': rule['action'],
            'timestamp': event['timestamp'],
            'source': event['source'],
            'target': event['target'],
            'confidence': event['confidence']
        })
        
        # 添加后置条件
        for postcondition in rule['postconditions']:
            path.append({
                'type': 'postcondition',
                'name': postcondition,
                'timestamp': event['timestamp'],
                'source': event['source'],
                'target': event['target']
            })
        
        return path
    
    def _add_path_to_graph(self, graph: nx.DiGraph, path: List[Dict[str, Any]]):
        """将攻击路径添加到图中"""
        for i, node in enumerate(path):
            node_id = f"{node['type']}_{node['name']}_{i}"
            
            # 添加节点
            graph.add_node(node_id, **node)
            
            # 添加边
            if i > 0:
                prev_node_id = f"{path[i-1]['type']}_{path[i-1]['name']}_{i-1}"
                graph.add_edge(prev_node_id, node_id)
    
    def _graph_to_dict(self, graph: nx.DiGraph) -> Dict[str, Any]:
        """将NetworkX图转换为字典格式"""
        return {
            'nodes': [dict(node) for node in graph.nodes(data=True)],
            'edges': [{'source': u, 'target': v} for u, v in graph.edges()],
            'metadata': {
                'total_nodes': graph.number_of_nodes(),
                'total_edges': graph.number_of_edges(),
                'generated_at': datetime.now().isoformat()
            }
        } 