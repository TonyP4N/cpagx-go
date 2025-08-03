import json
from typing import Dict, List, Any
from datetime import datetime

class TCITYExporter:
    """T-CITY格式导出器"""
    
    def __init__(self):
        self.tcity_schema = {
            "version": "1.0",
            "metadata": {},
            "nodes": [],
            "edges": [],
            "properties": {}
        }
    
    def export_tcity(self, attack_graph: Dict[str, Any]) -> Dict[str, Any]:
        """
        将攻击图导出为T-CITY格式
        
        Args:
            attack_graph: 攻击图数据
            
        Returns:
            T-CITY格式的JSON数据
        """
        tcity_data = self.tcity_schema.copy()
        
        # 设置元数据
        tcity_data["metadata"] = self._create_metadata(attack_graph)
        
        # 转换节点
        tcity_data["nodes"] = self._convert_nodes(attack_graph.get("nodes", []))
        
        # 转换边
        tcity_data["edges"] = self._convert_edges(attack_graph.get("edges", []))
        
        # 设置属性
        tcity_data["properties"] = self._create_properties(attack_graph)
        
        return tcity_data
    
    def _create_metadata(self, attack_graph: Dict[str, Any]) -> Dict[str, Any]:
        """创建T-CITY元数据"""
        metadata = attack_graph.get("metadata", {})
        
        return {
            "title": "Cyber-Physical Attack Graph",
            "description": "Generated attack graph from network traffic analysis",
            "version": "1.0",
            "created_at": metadata.get("generated_at", datetime.now().isoformat()),
            "total_nodes": metadata.get("total_nodes", 0),
            "total_edges": metadata.get("total_edges", 0),
            "format": "T-CITY",
            "source": "CPAGX-Go"
        }
    
    def _convert_nodes(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """转换节点为T-CITY格式"""
        tcity_nodes = []
        
        for i, node in enumerate(nodes):
            tcity_node = {
                "id": node.get("id", f"node_{i}"),
                "type": self._map_node_type(node.get("type", "unknown")),
                "label": node.get("name", f"Node {i}"),
                "properties": {
                    "timestamp": node.get("timestamp", ""),
                    "source": node.get("source", ""),
                    "target": node.get("target", ""),
                    "confidence": node.get("confidence", 0.0)
                }
            }
            
            # 添加特定类型的属性
            if node.get("type") == "action":
                tcity_node["properties"]["action_type"] = node.get("name", "")
            elif node.get("type") == "precondition":
                tcity_node["properties"]["condition_type"] = node.get("name", "")
            elif node.get("type") == "postcondition":
                tcity_node["properties"]["outcome_type"] = node.get("name", "")
            
            tcity_nodes.append(tcity_node)
        
        return tcity_nodes
    
    def _convert_edges(self, edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """转换边为T-CITY格式"""
        tcity_edges = []
        
        for i, edge in enumerate(edges):
            tcity_edge = {
                "id": f"edge_{i}",
                "source": edge.get("source", ""),
                "target": edge.get("target", ""),
                "type": "attack_path",
                "properties": {
                    "weight": 1.0,
                    "direction": "forward"
                }
            }
            
            tcity_edges.append(tcity_edge)
        
        return tcity_edges
    
    def _map_node_type(self, node_type: str) -> str:
        """映射节点类型到T-CITY标准类型"""
        type_mapping = {
            "precondition": "condition",
            "action": "action",
            "postcondition": "outcome",
            "device": "asset",
            "unknown": "unknown"
        }
        
        return type_mapping.get(node_type, "unknown")
    
    def _create_properties(self, attack_graph: Dict[str, Any]) -> Dict[str, Any]:
        """创建T-CITY属性"""
        return {
            "graph_type": "attack_graph",
            "analysis_type": "cyber_physical",
            "generation_method": "rule_based",
            "confidence_threshold": 0.5,
            "time_window": "60s",
            "supported_protocols": ["tcp", "udp", "icmp"],
            "device_types": ["router", "switch", "firewall", "server", "workstation", "iot_device"]
        }
    
    def export_to_file(self, attack_graph: Dict[str, Any], file_path: str) -> bool:
        """
        导出T-CITY格式到文件
        
        Args:
            attack_graph: 攻击图数据
            file_path: 输出文件路径
            
        Returns:
            是否成功导出
        """
        try:
            tcity_data = self.export_tcity(attack_graph)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(tcity_data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"Failed to export T-CITY file: {str(e)}")
            return False
    
    def validate_tcity_format(self, tcity_data: Dict[str, Any]) -> bool:
        """
        验证T-CITY格式是否正确
        
        Args:
            tcity_data: T-CITY格式数据
            
        Returns:
            格式是否有效
        """
        required_fields = ["version", "metadata", "nodes", "edges"]
        
        # 检查必需字段
        for field in required_fields:
            if field not in tcity_data:
                return False
        
        # 检查节点格式
        for node in tcity_data.get("nodes", []):
            if not self._validate_node(node):
                return False
        
        # 检查边格式
        for edge in tcity_data.get("edges", []):
            if not self._validate_edge(edge):
                return False
        
        return True
    
    def _validate_node(self, node: Dict[str, Any]) -> bool:
        """验证节点格式"""
        required_node_fields = ["id", "type", "label"]
        
        for field in required_node_fields:
            if field not in node:
                return False
        
        return True
    
    def _validate_edge(self, edge: Dict[str, Any]) -> bool:
        """验证边格式"""
        required_edge_fields = ["id", "source", "target"]
        
        for field in required_edge_fields:
            if field not in edge:
                return False
        
        return True 