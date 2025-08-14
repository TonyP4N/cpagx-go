"""
简化的 PCAP 处理服务
专门处理网络捕获文件 (.pcap/.pcapng) 并生成 CPAG
"""

import os
import json
import pandas as pd
import networkx as nx
from typing import Dict, Any, List
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import tempfile
import uuid
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP

app = FastAPI(title="PCAP CPAG Generator", version="1.0.0")

class PCAPCPAGGenerator:
    """简化的 PCAP CPAG 生成器"""
    
    def __init__(self):
        pass
    
    def parse_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """解析 PCAP 文件"""
        try:
            # 使用 scapy 解析 PCAP
            packets = rdpcap(pcap_path)
            
            packets_data = []
            modbus_evidence = []
            
            for packet in packets:
                packet_info = {
                    'timestamp': float(packet.time),
                    'protocol': packet.proto if hasattr(packet, 'proto') else 'Unknown',
                    'src_ip': packet[IP].src if IP in packet else None,
                    'dst_ip': packet[IP].dst if IP in packet else None,
                    'src_port': None,
                    'dst_port': None,
                    'modbus_function': None
                }
                
                # 提取端口信息
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                elif UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                
                # 简单的 Modbus 检测 (基于端口 502)
                if packet_info['dst_port'] == 502 or packet_info['src_port'] == 502:
                    # 尝试从负载中提取功能码
                    if hasattr(packet, 'load') and packet.load:
                        try:
                            # Modbus 功能码通常在第二个字节
                            if len(packet.load) >= 2:
                                func_code = packet.load[1]
                                packet_info['modbus_function'] = str(func_code)
                                
                                # 记录 Modbus 写入操作 (功能码 6, 16)
                                if func_code in [6, 16]:
                                    modbus_evidence.append({
                                        'type': 'ModbusWriteObserved',
                                        'src': packet_info['src_ip'],
                                        'dst': packet_info['dst_ip'],
                                        'function_code': str(func_code),
                                        'timestamp': packet_info['timestamp']
                                    })
                        except:
                            pass
                
                packets_data.append(packet_info)
            
            return {
                'packets': packets_data,
                'modbus_evidence': modbus_evidence,
                'total_packets': len(packets_data),
                'modbus_writes': len(modbus_evidence)
            }
            
        except Exception as e:
            raise RuntimeError(f"PCAP 解析失败: {e}")
    
    def build_cpag(self, pcap_data: Dict[str, Any], device_map: Dict[str, str]) -> Dict[str, Any]:
        """构建 CPAG 图"""
        graph = nx.DiGraph()
        
        modbus_evidence = pcap_data.get('modbus_evidence', [])
        
        if not modbus_evidence:
            # 如果没有 Modbus 证据，创建基本的网络连接节点
            return self._build_basic_network_cpag(pcap_data, device_map)
        
        # 1. 前置条件节点
        pre_nodes = []
        for i, evidence in enumerate(modbus_evidence[:5]):  # 限制数量
            src = evidence.get('src', f'host_{i}')
            dst = evidence.get('dst', f'plc_{i}')
            
            # 可达性前置条件
            pre_id = f"pre_reachable_{i}"
            graph.add_node(pre_id, 
                          type="precondition", 
                          name=f"Reachable({src}->{dst})", 
                          source=src, 
                          target=dst)
            pre_nodes.append(pre_id)
            
            # 服务开放前置条件
            pre2_id = f"pre_service_{i}"
            graph.add_node(pre2_id, 
                          type="precondition", 
                          name=f"ServiceOpen({dst}:502)", 
                          source=dst, 
                          target=dst)
            pre_nodes.append(pre2_id)
        
        # 2. 动作节点
        action_nodes = []
        for i, evidence in enumerate(modbus_evidence[:5]):  # 限制数量
            src = evidence.get('src', f'host_{i}')
            dst = evidence.get('dst', f'plc_{i}')
            fc = evidence.get('function_code', '6')
            
            act_id = f"act_modbus_{i}"
            graph.add_node(act_id, 
                          type="action", 
                          name=f"ModbusWrite(fc={fc})", 
                          source=src, 
                          target=dst)
            action_nodes.append(act_id)
        
        # 3. 后置条件节点
        post_nodes = []
        for i, evidence in enumerate(modbus_evidence[:3]):  # 限制数量
            dst = evidence.get('dst', f'plc_{i}')
            
            post_id = f"post_control_{i}"
            graph.add_node(post_id, 
                          type="postcondition", 
                          name=f"ControlEstablished({dst})", 
                          source=dst, 
                          target=dst)
            post_nodes.append(post_id)
        
        # 4. 连接边
        edges = []
        edge_id = 0
        
        # 前置条件 -> 动作
        for pre_id in pre_nodes:
            for act_id in action_nodes:
                graph.add_edge(pre_id, act_id, 
                              probability=0.9, 
                              evidence=[{"source": "precondition", "detail": graph.nodes[pre_id]}])
                edges.append({
                    "id": f"e{edge_id}",
                    "source": pre_id,
                    "target": act_id,
                    "probability": 0.9,
                    "evidence": [{"source": "precondition", "detail": graph.nodes[pre_id]}]
                })
                edge_id += 1
        
        # 动作 -> 后置条件
        for act_id in action_nodes:
            for post_id in post_nodes:
                graph.add_edge(act_id, post_id, 
                              probability=0.8, 
                              evidence=[{"source": "action", "detail": graph.nodes[act_id]}])
                edges.append({
                    "id": f"e{edge_id}",
                    "source": act_id,
                    "target": post_id,
                    "probability": 0.8,
                    "evidence": [{"source": "action", "detail": graph.nodes[act_id]}]
                })
                edge_id += 1
        
        # 5. 转换为字典格式
        nodes = []
        for i, (nid, data) in enumerate(graph.nodes(data=True)):
            nodes.append({
                "id": nid,
                "type": data.get("type", ""),
                "name": data.get("name", ""),
                "source": data.get("source", ""),
                "target": data.get("target", "")
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": "pcap",
                "device_map": device_map,
                "total_packets": pcap_data.get('total_packets', 0),
                "modbus_writes": pcap_data.get('modbus_writes', 0),
                "generated_at": datetime.now().isoformat()
            }
        }
    
    def _build_basic_network_cpag(self, pcap_data: Dict[str, Any], device_map: Dict[str, str]) -> Dict[str, Any]:
        """构建基本的网络连接 CPAG"""
        graph = nx.DiGraph()
        
        packets = pcap_data.get('packets', [])
        if not packets:
            return {"nodes": [], "edges": [], "metadata": {}}
        
        # 提取唯一的 IP 地址
        unique_ips = set()
        for packet in packets:
            if packet.get('src_ip'):
                unique_ips.add(packet['src_ip'])
            if packet.get('dst_ip'):
                unique_ips.add(packet['dst_ip'])
        
        unique_ips = list(unique_ips)[:5]  # 限制数量
        
        # 创建基本节点
        nodes = []
        edges = []
        
        # 前置条件：网络可达
        for i, ip in enumerate(unique_ips):
            pre_id = f"pre_network_{i}"
            nodes.append({
                "id": pre_id,
                "type": "precondition",
                "name": f"NetworkReachable({ip})",
                "source": ip,
                "target": ip
            })
        
        # 动作：网络扫描
        for i, ip in enumerate(unique_ips[:3]):
            act_id = f"act_scan_{i}"
            nodes.append({
                "id": act_id,
                "type": "action",
                "name": f"NetworkScan({ip})",
                "source": "attacker",
                "target": ip
            })
        
        # 后置条件：服务发现
        for i, ip in enumerate(unique_ips[:3]):
            post_id = f"post_discovery_{i}"
            nodes.append({
                "id": post_id,
                "type": "postcondition",
                "name": f"ServiceDiscovered({ip})",
                "source": ip,
                "target": ip
            })
        
        # 创建边
        edge_id = 0
        for i in range(min(len(unique_ips), 3)):
            pre_id = f"pre_network_{i}"
            act_id = f"act_scan_{i}"
            post_id = f"post_discovery_{i}"
            
            # 前置条件 -> 动作
            edges.append({
                "id": f"e{edge_id}",
                "source": pre_id,
                "target": act_id,
                "probability": 0.7,
                "evidence": [{"source": "network_analysis"}]
            })
            edge_id += 1
            
            # 动作 -> 后置条件
            edges.append({
                "id": f"e{edge_id}",
                "source": act_id,
                "target": post_id,
                "probability": 0.6,
                "evidence": [{"source": "network_analysis"}]
            })
            edge_id += 1
        
        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": "pcap_basic",
                "device_map": device_map,
                "total_packets": pcap_data.get('total_packets', 0),
                "unique_ips": len(unique_ips),
                "generated_at": datetime.now().isoformat()
            }
        }

# 全局生成器实例
generator = PCAPCPAGGenerator()

@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy", "service": "pcap-cpag-generator"}

@app.post("/generate")
async def generate_cpag(
    pcap_file: UploadFile = File(...),
    device_map: str = Form("{}")
):
    """生成 CPAG"""
    try:
        # 解析设备映射
        device_map_dict = json.loads(device_map) if device_map else {}
        
        # 验证文件类型
        if not pcap_file.filename:
            raise HTTPException(status_code=400, detail="文件名不能为空")
        filename = pcap_file.filename.lower()
        if not (filename.endswith('.pcap') or filename.endswith('.pcapng')):
            raise HTTPException(status_code=400, detail="只支持 .pcap 或 .pcapng 文件")
        
        # 保存临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as temp_file:
            content = await pcap_file.read()
            temp_file.write(content)
            temp_path = temp_file.name
        
        try:
            # 解析 PCAP
            pcap_data = generator.parse_pcap(temp_path)
            
            # 构建 CPAG
            cpag_data = generator.build_cpag(pcap_data, device_map_dict)
            
            # 生成输出目录
            task_id = str(uuid.uuid4())
            output_dir = f"outputs/{task_id}"
            os.makedirs(output_dir, exist_ok=True)
            
            # 保存结果
            output_file = os.path.join(output_dir, "cpag.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(cpag_data, f, ensure_ascii=False, indent=2)
            
            return {
                "status": "success",
                "task_id": task_id,
                "output_file": output_file,
                "nodes_count": len(cpag_data["nodes"]),
                "edges_count": len(cpag_data["edges"]),
                "cpag_data": cpag_data
            }
            
        finally:
            # 清理临时文件
            try:
                os.unlink(temp_path)
            except:
                pass
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"处理失败: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)

