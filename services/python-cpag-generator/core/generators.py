"""
Shared CPAG generators for CSV time-series and PCAP traffic
Used by multiple versions to avoid duplicated logic
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

import networkx as nx
import pandas as pd
import os


class CSVCPAGGenerator:
    """CSV CPAG generator (simplified)

    Responsibilities:
    - parse_csv: normalize and melt CSV into long-form time-series
    - build_cpag: derive a basic CPAG graph from time-series
    """

    def parse_csv(self, csv_path: str) -> pd.DataFrame:
        try:
            df = pd.read_csv(csv_path)
            if df.empty:
                return pd.DataFrame()

            # standardize columns
            df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]

            # detect timestamp column
            timestamp_col = None
            for col in df.columns:
                if any(ts in col for ts in ["timestamp", "time", "datetime", "date", "ts"]):
                    timestamp_col = col
                    break
            if timestamp_col is None:
                timestamp_col = df.columns[0]

            # convert timestamp
            df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors="coerce")
            df = df.dropna(subset=[timestamp_col])

            # to long-form
            value_cols = [c for c in df.columns if c != timestamp_col]
            if not value_cols:
                return pd.DataFrame()

            long_df = df.melt(id_vars=[timestamp_col], value_vars=value_cols, var_name="tag", value_name="value")
            long_df = long_df.rename(columns={timestamp_col: "timestamp"})

            # enrich
            long_df["tag_type"] = long_df["tag"].apply(self._extract_tag_type)
            long_df["tag_id"] = long_df["tag"].apply(self._extract_tag_id)
            long_df["value"] = pd.to_numeric(long_df["value"], errors="coerce")

            return long_df[["timestamp", "tag", "tag_type", "tag_id", "value"]]
        except Exception as e:
            raise RuntimeError(f"CSV 解析失败: {e}")

    def _extract_tag_type(self, tag: str) -> str:
        if not isinstance(tag, str):
            return ""
        tag_types = ["FIT", "LIT", "PIT", "AIT", "MV", "PU", "PLC", "HMI", "SCADA"]
        tag_upper = tag.upper()
        for tag_type in tag_types:
            if tag_type in tag_upper:
                return tag_type
        return ""

    def _extract_tag_id(self, tag: str) -> str:
        if not isinstance(tag, str):
            return ""
        import re
        m = re.search(r"\d+", tag)
        return m.group() if m else ""

    def build_cpag(self, df: pd.DataFrame, device_map: Dict[str, str]) -> Dict[str, Any]:
        graph = nx.DiGraph()
        if df.empty:
            return {"nodes": [], "edges": [], "metadata": {}}

        # preconditions
        pre_nodes = []
        unique_tags = df['tag'].unique()[:5]
        for i, tag in enumerate(unique_tags):
            pre_id = f"pre_{i}"
            graph.add_node(pre_id, type="precondition", name=f"DeviceActive({tag})", source=tag, target=tag)
            pre_nodes.append(pre_id)

        # actions
        action_nodes = []
        tag_types = df['tag_type'].unique()
        for i, tag_type in enumerate(tag_types[:3]):
            act_id = f"act_{i}"
            graph.add_node(act_id, type="action", name=f"SensorRead({tag_type})", source=f"{tag_type}_Device", target=f"{tag_type}_Sensor")
            action_nodes.append(act_id)

        # postconditions
        post_nodes = []
        for i, tag in enumerate(unique_tags[:3]):
            post_id = f"post_{i}"
            graph.add_node(post_id, type="postcondition", name=f"SensorData({tag})", source=tag, target=tag)
            post_nodes.append(post_id)

        # edges
        edges = []
        edge_id = 0
        for pre_id in pre_nodes:
            for act_id in action_nodes:
                graph.add_edge(pre_id, act_id, probability=0.8, evidence=[{"source": "precondition", "detail": graph.nodes[pre_id]}])
                edges.append({"id": f"e{edge_id}", "source": pre_id, "target": act_id, "probability": 0.8, "evidence": [{"source": "precondition", "detail": graph.nodes[pre_id]}]})
                edge_id += 1
        for act_id in action_nodes:
            for post_id in post_nodes:
                graph.add_edge(act_id, post_id, probability=0.7, evidence=[{"source": "action", "detail": graph.nodes[act_id]}])
                edges.append({"id": f"e{edge_id}", "source": act_id, "target": post_id, "probability": 0.7, "evidence": [{"source": "action", "detail": graph.nodes[act_id]}]})
                edge_id += 1

        nodes = []
        for nid, data in graph.nodes(data=True):
            nodes.append({"id": nid, "type": data.get("type", ""), "name": data.get("name", ""), "source": data.get("source", ""), "target": data.get("target", "")})

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": "csv",
                "device_map": device_map,
                "generated_at": datetime.now().isoformat(),
            },
        }


class PCAPCPAGGenerator:
    """PCAP CPAG generator (simplified)

    Responsibilities:
    - parse_pcap: extract basic packet/evidence features
    - build_cpag: derive a basic CPAG from Modbus or fall back to network reachability
    """

    def parse_pcap(self, pcap_path: str) -> Dict[str, Any]:
        try:
            from scapy.all import IP, TCP, UDP, PcapReader  # lazy import to speed module load
            
            # 检查文件是否存在
            if not os.path.exists(pcap_path):
                raise RuntimeError(f"PCAP file not found: {pcap_path}")
            
            # 检查文件大小
            file_size = os.path.getsize(pcap_path)
            if file_size == 0:
                raise RuntimeError(f"PCAP file is empty: {pcap_path}")
            
            print(f"DEBUG: Processing PCAP file: {pcap_path}, size: {file_size} bytes")
            
            # 使用流式读取，避免内存不足
            packets_data = []
            modbus_evidence = []
            packet_count = 0
            max_packets = 10000  # 限制处理的包数量，避免内存问题
            
            try:
                # 使用PcapReader进行流式读取
                reader = PcapReader(pcap_path)
                for packet in reader:
                    if packet_count >= max_packets:
                        print(f"DEBUG: Reached max packet limit ({max_packets}), stopping processing")
                        break
                    
                    packet_info = {
                        'timestamp': float(packet.time),
                        'protocol': packet.proto if hasattr(packet, 'proto') else 'Unknown',
                        'src_ip': packet[IP].src if IP in packet else None,
                        'dst_ip': packet[IP].dst if IP in packet else None,
                        'src_port': None,
                        'dst_port': None,
                        'modbus_function': None,
                    }

                    if TCP in packet:
                        packet_info['src_port'] = packet[TCP].sport
                        packet_info['dst_port'] = packet[TCP].dport
                    elif UDP in packet:
                        packet_info['src_port'] = packet[UDP].sport
                        packet_info['dst_port'] = packet[UDP].dport

                    # simple Modbus detect via port 502 and function code
                    if packet_info['dst_port'] == 502 or packet_info['src_port'] == 502:
                        if hasattr(packet, 'load') and packet.load:
                            try:
                                if len(packet.load) >= 2:
                                    func_code = packet.load[1]
                                    packet_info['modbus_function'] = str(func_code)
                                    if func_code in [6, 16]:
                                        modbus_evidence.append({
                                            'type': 'ModbusWriteObserved',
                                            'src': packet_info['src_ip'],
                                            'dst': packet_info['dst_ip'],
                                            'function_code': str(func_code),
                                            'timestamp': packet_info['timestamp'],
                                        })
                            except Exception:
                                pass

                    packets_data.append(packet_info)
                    packet_count += 1
                    
                    # 每处理1000个包输出一次进度
                    if packet_count % 1000 == 0:
                        print(f"DEBUG: Processed {packet_count} packets...")
                
                reader.close()
                
            except Exception as e:
                # 如果流式读取失败，回退到传统方法但限制包数量
                print(f"DEBUG: Stream reading failed, falling back to rdpcap with limit: {e}")
                from scapy.all import rdpcap
                packets = rdpcap(pcap_path, count=max_packets)
                
                for packet in packets:
                    packet_info = {
                        'timestamp': float(packet.time),
                        'protocol': packet.proto if hasattr(packet, 'proto') else 'Unknown',
                        'src_ip': packet[IP].src if IP in packet else None,
                        'dst_ip': packet[IP].dst if IP in packet else None,
                        'src_port': None,
                        'dst_port': None,
                        'modbus_function': None,
                    }

                    if TCP in packet:
                        packet_info['src_port'] = packet[TCP].sport
                        packet_info['dst_port'] = packet[TCP].dport
                    elif UDP in packet:
                        packet_info['src_port'] = packet[UDP].sport
                        packet_info['dst_port'] = packet[UDP].dport

                    # simple Modbus detect via port 502 and function code
                    if packet_info['dst_port'] == 502 or packet_info['src_port'] == 502:
                        if hasattr(packet, 'load') and packet.load:
                            try:
                                if len(packet.load) >= 2:
                                    func_code = packet.load[1]
                                    packet_info['modbus_function'] = str(func_code)
                                    if func_code in [6, 16]:
                                        modbus_evidence.append({
                                            'type': 'ModbusWriteObserved',
                                            'src': packet_info['src_ip'],
                                            'dst': packet_info['dst_ip'],
                                            'function_code': str(func_code),
                                            'timestamp': packet_info['timestamp'],
                                        })
                            except Exception:
                                pass

                    packets_data.append(packet_info)

            print(f"DEBUG: Successfully processed {len(packets_data)} packets, found {len(modbus_evidence)} Modbus writes")

            return {
                'packets': packets_data,
                'modbus_evidence': modbus_evidence,
                'total_packets': len(packets_data),
                'modbus_writes': len(modbus_evidence),
            }
        except Exception as e:
            raise RuntimeError(f"PCAP 解析失败: {e}")

    def build_cpag(self, pcap_data: Dict[str, Any], device_map: Dict[str, str]) -> Dict[str, Any]:
        graph = nx.DiGraph()
        modbus_evidence = pcap_data.get('modbus_evidence', [])
        if not modbus_evidence:
            return self._build_basic_network_cpag(pcap_data, device_map)

        pre_nodes = []
        for i, evidence in enumerate(modbus_evidence[:5]):
            src = evidence.get('src', f'host_{i}')
            dst = evidence.get('dst', f'plc_{i}')

            pre_id = f"pre_reachable_{i}"
            graph.add_node(pre_id, type="precondition", name=f"Reachable({src}->{dst})", source=src, target=dst)
            pre_nodes.append(pre_id)

            pre2_id = f"pre_service_{i}"
            graph.add_node(pre2_id, type="precondition", name=f"ServiceOpen({dst}:502)", source=dst, target=dst)
            pre_nodes.append(pre2_id)

        action_nodes = []
        for i, evidence in enumerate(modbus_evidence[:5]):
            src = evidence.get('src', f'host_{i}')
            dst = evidence.get('dst', f'plc_{i}')
            fc = evidence.get('function_code', '6')
            act_id = f"act_modbus_{i}"
            graph.add_node(act_id, type="action", name=f"ModbusWrite(fc={fc})", source=src, target=dst)
            action_nodes.append(act_id)

        post_nodes = []
        for i, evidence in enumerate(modbus_evidence[:3]):
            dst = evidence.get('dst', f'plc_{i}')
            post_id = f"post_control_{i}"
            graph.add_node(post_id, type="postcondition", name=f"ControlEstablished({dst})", source=dst, target=dst)
            post_nodes.append(post_id)

        edges = []
        edge_id = 0
        for pre_id in pre_nodes:
            for act_id in action_nodes:
                graph.add_edge(pre_id, act_id, probability=0.9, evidence=[{"source": "precondition", "detail": graph.nodes[pre_id]}])
                edges.append({"id": f"e{edge_id}", "source": pre_id, "target": act_id, "probability": 0.9, "evidence": [{"source": "precondition", "detail": graph.nodes[pre_id]}]})
                edge_id += 1
        for act_id in action_nodes:
            for post_id in post_nodes:
                graph.add_edge(act_id, post_id, probability=0.8, evidence=[{"source": "action", "detail": graph.nodes[act_id]}])
                edges.append({"id": f"e{edge_id}", "source": act_id, "target": post_id, "probability": 0.8, "evidence": [{"source": "action", "detail": graph.nodes[act_id]}]})
                edge_id += 1

        nodes = []
        for nid, data in graph.nodes(data=True):
            nodes.append({"id": nid, "type": data.get("type", ""), "name": data.get("name", ""), "source": data.get("source", ""), "target": data.get("target", "")})

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": "pcap",
                "device_map": device_map,
                "total_packets": pcap_data.get('total_packets', 0),
                "modbus_writes": pcap_data.get('modbus_writes', 0),
                "generated_at": datetime.now().isoformat(),
            },
        }

    def _build_basic_network_cpag(self, pcap_data: Dict[str, Any], device_map: Dict[str, str]) -> Dict[str, Any]:
        packets = pcap_data.get('packets', [])
        if not packets:
            return {"nodes": [], "edges": [], "metadata": {}}

        unique_ips = set()
        for packet in packets:
            if packet.get('src_ip'):
                unique_ips.add(packet['src_ip'])
            if packet.get('dst_ip'):
                unique_ips.add(packet['dst_ip'])
        unique_ips = list(unique_ips)[:5]

        nodes = []
        edges = []
        for i, ip in enumerate(unique_ips):
            pre_id = f"pre_network_{i}"
            nodes.append({"id": pre_id, "type": "precondition", "name": f"NetworkReachable({ip})", "source": ip, "target": ip})
        for i, ip in enumerate(unique_ips[:3]):
            act_id = f"act_scan_{i}"
            nodes.append({"id": act_id, "type": "action", "name": f"NetworkScan({ip})", "source": "attacker", "target": ip})
        for i, ip in enumerate(unique_ips[:3]):
            post_id = f"post_discovery_{i}"
            nodes.append({"id": post_id, "type": "postcondition", "name": f"ServiceDiscovered({ip})", "source": ip, "target": ip})

        edge_id = 0
        for i in range(min(len(unique_ips), 3)):
            pre_id = f"pre_network_{i}"
            act_id = f"act_scan_{i}"
            post_id = f"post_discovery_{i}"
            edges.append({"id": f"e{edge_id}", "source": pre_id, "target": act_id, "probability": 0.7, "evidence": [{"source": "network_analysis"}]})
            edge_id += 1
            edges.append({"id": f"e{edge_id}", "source": act_id, "target": post_id, "probability": 0.6, "evidence": [{"source": "network_analysis"}]})
            edge_id += 1

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": "pcap_basic",
                "device_map": device_map,
                "unique_ips": len(unique_ips),
                "total_packets": pcap_data.get('total_packets', 0),
                "generated_at": datetime.now().isoformat(),
            },
        }


