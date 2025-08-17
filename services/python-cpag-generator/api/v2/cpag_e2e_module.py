#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cpag_e2e_module.py
------------------
Module version of cpag_e2e.py for API integration
"""

import os
import re
import math
import json
import struct
from collections import defaultdict
from typing import Optional, Dict, Any

import pandas as pd

# Reuse parsing & exporting primitives from existing modules if available
try:
    import cpag_pipeline as CP  # must be in PYTHONPATH / same folder
except Exception as e:
    print(f"Warning: cpag_pipeline not available: {e}")
    CP = None

try:
    # Import Neo4j helpers (optional)
    import cpag_to_neo4j as NEO
except Exception as e:
    NEO = None

# ------------
# PCAP detect
# ------------
PCAPNG_SHB = 0x0A0D0D0A

def detect_container(path: str) -> str:
    """
    Return 'pcapng' or 'pcap' based on magic.
    """
    with open(path, 'rb') as f:
        head = f.read(8)
    if len(head) < 4:
        raise RuntimeError("File too small to be a pcap/pcapng")
    # pcapng SHB (first 4 bytes big-endian)
    if struct.unpack(">I", head[:4])[0] == PCAPNG_SHB:
        return "pcapng"
    # classic libpcap (magic numbers incl. ns variants)
    magic = struct.unpack("<I", head[:4])[0]
    if magic in (0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1):
        return "pcap"
    # also try big-endian for safety
    magic_be = struct.unpack(">I", head[:4])[0]
    if magic_be in (0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1):
        return "pcap"
    raise RuntimeError("Unknown capture format (not pcap/pcapng)")

# ----------------------
# Classic PCAP parsing
# ----------------------
ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100
TCP_PROTO = 6
ENIP_PORT = 44818

def ipv4_addr(b) -> str:
    return ".".join(str(x) for x in b)

def parse_pcap_classic_enip_requests(pcap_path: str, max_pkts: int = 120000, target_cip: int = 8000) -> pd.DataFrame:
    """
    Stream-parse a classic PCAP file and return a DataFrame of ENIP/CIP requests:
    columns: [src, sport, dst, dport, service, service_name, path]
    """
    cip_reqs = []
    total_packets = 0

    with open(pcap_path, 'rb') as f:
        # Skip pcap header (24 bytes)
        f.read(24)
        
        while total_packets < max_pkts:
            # Read packet header (16 bytes)
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
                
            # Parse packet header
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)
            
            # Read packet data
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
                
            total_packets += 1
            
            # Parse Ethernet header
            if len(pkt_data) < 14:
                continue
            eth_dst = pkt_data[:6]
            eth_src = pkt_data[6:12]
            eth_type = struct.unpack(">H", pkt_data[12:14])[0]
            
            # Handle VLAN tags
            if eth_type == ETH_P_8021Q:
                if len(pkt_data) < 18:
                    continue
                eth_type = struct.unpack(">H", pkt_data[16:18])[0]
                pkt_data = pkt_data[4:]  # Skip VLAN header
            
            # Only process IPv4 packets
            if eth_type != ETH_P_IP:
                continue
                
            # Parse IP header
            if len(pkt_data) < 34:
                continue
            ip_ver_ihl = pkt_data[14]
            ip_ver = (ip_ver_ihl >> 4) & 0xF
            ip_ihl = ip_ver_ihl & 0xF
            
            if ip_ver != 4:
                continue
                
            ip_proto = pkt_data[23]
            if ip_proto != TCP_PROTO:
                continue
                
            ip_src = ipv4_addr(pkt_data[26:30])
            ip_dst = ipv4_addr(pkt_data[30:34])
            
            # Parse TCP header
            ip_header_len = ip_ihl * 4
            if len(pkt_data) < 14 + ip_header_len + 20:
                continue
                
            tcp_start = 14 + ip_header_len
            tcp_sport = struct.unpack(">H", pkt_data[tcp_start:tcp_start+2])[0]
            tcp_dport = struct.unpack(">H", pkt_data[tcp_start+2:tcp_start+4])[0]
            
            # Check if this is ENIP traffic
            if tcp_dport == ENIP_PORT or tcp_sport == ENIP_PORT:
                # Extract ENIP/CIP data
                tcp_data_start = tcp_start + 20
                if len(pkt_data) > tcp_data_start:
                    enip_data = pkt_data[tcp_data_start:]
                    # Basic ENIP parsing (simplified)
                    if len(enip_data) >= 24:
                        command = struct.unpack(">H", enip_data[16:18])[0]
                        service = struct.unpack(">H", enip_data[20:22])[0]
                        
                        cip_reqs.append({
                            'src': ip_src,
                            'sport': tcp_sport,
                            'dst': ip_dst,
                            'dport': tcp_dport,
                            'service': service,
                            'service_name': f'Service_{service}',
                            'path': f'Path_{command}'
                        })
                        
                        if len(cip_reqs) >= target_cip:
                            break
    
    return pd.DataFrame(cip_reqs)

def load_csv_as_records(nodes_csv: str, edges_csv: str):
    df_n = pd.read_csv(nodes_csv)
    df_e = pd.read_csv(edges_csv)
    # Harmonize column names expected by cpag_to_neo4j
    if "node_type" not in df_n.columns and "type" in df_n.columns:
        df_n["node_type"] = df_n["type"]
    if "relation" not in df_e.columns and "type" in df_e.columns:
        df_e["relation"] = df_e["type"]
    return df_n.to_dict(orient="records"), df_e.to_dict(orient="records")

def import_into_neo4j(nodes_csv: str, edges_csv: str, uri: str, user: str, password: str,
                      database: str = "neo4j", label: str = "CPAGNode", wipe: bool = False, batch_size: int = 1000):
    if NEO is None:
        print("Warning: Neo4j import requested, but cpag_to_neo4j.py is not available.")
        return

    nodes, edges = load_csv_as_records(nodes_csv, edges_csv)
    driver = NEO.open_driver(uri, user, password)
    NEO.verify_or_exit(driver, uri)
    NEO.ensure_constraints(driver, database, label)
    if wipe:
        print(f"[!] Wiping existing graph for label: {label}")
        NEO.wipe_graph(driver, database, label)
    print(f"[+] Importing into Neo4j ({label}) — nodes={len(nodes)}, edges={len(edges)}")
    NEO.batch_nodes(driver, database, label, nodes, batch_size=batch_size)
    NEO.batch_edges(driver, database, label, edges, batch_size=max(1, batch_size*2))
    driver.close()

def run_pcap_processing(
    pcap_path: str,
    outdir: str,
    max_pkts: int = 120000,
    target_cip: int = 8000,
    top_k: int = 40,
    top_per_plc: int = 20,
    neo4j_uri: Optional[str] = None,
    neo4j_user: Optional[str] = None,
    neo4j_password: Optional[str] = None,
    neo4j_db: str = "neo4j",
    label: str = "CPAGNode",
    wipe: bool = False
) -> Dict[str, Any]:
    """
    Main entry point for PCAP processing
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(pcap_path):
            raise RuntimeError(f"PCAP file not found: {pcap_path}")
        
        # 检查文件大小
        file_size = os.path.getsize(pcap_path)
        if file_size == 0:
            raise RuntimeError(f"PCAP file is empty: {pcap_path}")
        
        # 检测文件类型
        try:
            container_type = detect_container(pcap_path)
            print(f"Detected container type: {container_type}")
        except Exception as e:
            print(f"Warning: Could not detect container type: {e}")
            container_type = "unknown"
        
        # 确保输出目录存在
        os.makedirs(outdir, exist_ok=True)
        
        # 处理PCAP文件
        if container_type in ["pcap", "pcapng"]:
            # 使用经典PCAP解析器
            enip_df = parse_pcap_classic_enip_requests(pcap_path, max_pkts, target_cip)
        else:
            raise RuntimeError(f"Unsupported container type: {container_type}")
        
        if enip_df.empty:
            print("No ENIP/CIP requests found in PCAP")
            return {"status": "completed", "message": "No ENIP/CIP requests found"}
        
        # 构建CPAG
        cpag_result = build_cpag_from_enip_requests(enip_df, top_k, top_per_plc)
        
        # 保存结果
        save_cpag_results(cpag_result, outdir)
        
        # 存储到Neo4j（如果配置了）
        if neo4j_uri and neo4j_user and neo4j_password:
            try:
                store_cpag_to_neo4j(cpag_result, neo4j_uri, neo4j_user, neo4j_password, neo4j_db, label, wipe)
            except Exception as e:
                print(f"Warning: Failed to store to Neo4j: {e}")
        
        return {
            "status": "completed",
            "container_type": container_type,
            "total_requests": len(enip_df),
            "cpag_nodes": len(cpag_result.get("nodes", [])),
            "cpag_edges": len(cpag_result.get("edges", []))
        }
        
    except Exception as e:
        print(f"Error in PCAP processing: {e}")
        return {"status": "failed", "error": str(e)}

def build_cpag_from_enip_requests(enip_df: pd.DataFrame, top_k: int = 40, top_per_plc: int = 20) -> Dict[str, Any]:
    """从ENIP/CIP请求构建CPAG"""
    if enip_df.empty:
        return {"nodes": [], "edges": [], "metadata": {}}
    
    # 简单的CPAG构建逻辑
    nodes = []
    edges = []
    
    # 获取前top_k个请求
    top_requests = enip_df.head(top_k)
    
    for i, (_, row) in enumerate(top_requests.iterrows()):
        # 创建节点
        src_node_id = f"src_{i}"
        dst_node_id = f"dst_{i}"
        action_node_id = f"action_{i}"
        
        nodes.extend([
            {
                "id": src_node_id,
                "type": "precondition",
                "name": f"Reachable({row.get('src', 'unknown')})",
                "source": row.get('src', 'unknown'),
                "target": row.get('dst', 'unknown')
            },
            {
                "id": action_node_id,
                "type": "action",
                "name": f"ENIPRequest({row.get('service_name', 'unknown')})",
                "source": row.get('src', 'unknown'),
                "target": row.get('dst', 'unknown')
            },
            {
                "id": dst_node_id,
                "type": "postcondition",
                "name": f"ServiceResponded({row.get('dst', 'unknown')})",
                "source": row.get('dst', 'unknown'),
                "target": row.get('dst', 'unknown')
            }
        ])
        
        # 创建边
        edges.extend([
            {
                "id": f"e_{i}_1",
                "source": src_node_id,
                "target": action_node_id,
                "probability": 0.9,
                "evidence": [{"source": "network_analysis"}]
            },
            {
                "id": f"e_{i}_2",
                "source": action_node_id,
                "target": dst_node_id,
                "probability": 0.8,
                "evidence": [{"source": "network_analysis"}]
            }
        ])
    
    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "source": "enip_cip_analysis",
            "total_requests": len(enip_df),
            "processed_requests": len(top_requests),
            "generated_at": datetime.now().isoformat()
        }
    }


def save_cpag_results(cpag_result: Dict[str, Any], outdir: str):
    """保存CPAG结果到文件"""
    # 保存主要结果
    cpag_json = os.path.join(outdir, "cpag_units.json")
    with open(cpag_json, "w", encoding="utf-8") as f:
        json.dump(cpag_result, f, ensure_ascii=False, indent=2)
    
    # 保存CSV格式的节点和边
    if cpag_result.get("nodes"):
        nodes_df = pd.DataFrame(cpag_result["nodes"])
        nodes_csv = os.path.join(outdir, "cpag_nodes.csv")
        nodes_df.to_csv(nodes_csv, index=False)
    
    if cpag_result.get("edges"):
        edges_df = pd.DataFrame(cpag_result["edges"])
        edges_csv = os.path.join(outdir, "cpag_edges.csv")
        edges_df.to_csv(edges_csv, index=False)


def store_cpag_to_neo4j(cpag_result: Dict[str, Any], neo4j_uri: str, neo4j_user: str, 
                        neo4j_password: str, neo4j_db: str, label: str, wipe: bool):
    """存储CPAG到Neo4j"""
    if NEO is None:
        print("Warning: Neo4j module not available")
        return
    
    try:
        # 这里可以调用Neo4j存储函数
        # NEO.store_cpag(cpag_result, neo4j_uri, neo4j_user, neo4j_password, neo4j_db, label, wipe)
        print(f"Neo4j storage not implemented yet for {len(cpag_result.get('nodes', []))} nodes")
    except Exception as e:
        print(f"Error storing to Neo4j: {e}")


# 添加必要的导入
from datetime import datetime
