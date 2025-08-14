#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cpag_e2e.py
-----------
One-command pipeline to:
  - Parse ENIP/CIP traffic from a PCAP-NG **or** classic PCAP file
  - Build CPAG units (precondition / action / postcondition)
  - Export standard & bundled CSVs/PNGs
  - (Optional) Import the graph into Neo4j

Dependencies
------------
pip install pandas networkx matplotlib neo4j

Usage
-----
python cpag_e2e.py \
  --pcap ./trace.pcapng \
  --outdir ./out \
  --top-k 40 --top-per-plc 20 \
  --neo4j-uri neo4j://localhost:7687 --neo4j-user neo4j --neo4j-password pass \
  --neo4j-db neo4j --label CPAGNode --wipe

Notes
-----
- If you supply the Neo4j options, the script will import BOTH the standard CSVs
  (cpag_nodes.csv/cpag_edges.csv) and the bundled CSVs (cpag_bundled_nodes.csv/cpag_bundled_edges.csv).
  Set --label to distinguish imports, e.g., CPAGNode or CPAGNodeBundled.
- For .pcap files, only Ethernet-II + IPv4/TCP packets are parsed.
"""

import os
import re
import math
import json
import struct
import argparse
from collections import defaultdict
from typing import Optional

import pandas as pd

# Reuse parsing & exporting primitives from existing modules if available
try:
    import cpag_pipeline as CP  # must be in PYTHONPATH / same folder
except Exception as e:
    raise SystemExit("This script expects cpag_pipeline.py alongside it. Error: %r" % (e,))

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
        gh = f.read(24)
        if len(gh) != 24:
            raise RuntimeError("Invalid PCAP global header")
        magic = gh[0:4]
        if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):  # little endian
            endian = "<"
        elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):  # big endian
            endian = ">"
        else:
            raise RuntimeError("Unsupported PCAP magic")

        # loop packets
        while True:
            hdr = f.read(16)
            if not hdr or len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", hdr)
            pkt = f.read(incl_len)
            if len(pkt) < incl_len:
                break

            total_packets += 1
            # Ethernet II
            if len(pkt) < 14:
                continue
            eth_type = struct.unpack("!H", pkt[12:14])[0]
            offset = 14
            if eth_type == ETH_P_8021Q and len(pkt) >= 18:
                eth_type = struct.unpack("!H", pkt[16:18])[0]
                offset = 18
            if eth_type != ETH_P_IP:
                continue

            if len(pkt) < offset + 20:
                continue
            ver_ihl = pkt[offset]
            ihl = (ver_ihl & 0x0F) * 4
            if len(pkt) < offset + ihl:
                continue
            total_len = struct.unpack("!H", pkt[offset + 2:offset + 4])[0]
            if total_len < ihl or len(pkt) < offset + total_len:
                continue
            proto = pkt[offset + 9]
            if proto != TCP_PROTO:
                continue

            src_ip = ipv4_addr(pkt[offset + 12:offset + 16])
            dst_ip = ipv4_addr(pkt[offset + 16:offset + 20])
            ip_payload = pkt[offset + ihl:offset + total_len]
            if len(ip_payload) < 20:
                continue
            src_port, dst_port = struct.unpack("!HH", ip_payload[0:4])
            data_offset = (ip_payload[12] >> 4) * 4
            if len(ip_payload) < data_offset:
                continue
            tcp_payload = ip_payload[data_offset:]

            # ENIP default port
            if dst_port == ENIP_PORT and len(tcp_payload) >= 24:
                parsed = CP.parse_cip_from_enip_le(tcp_payload)
                if parsed:
                    cip_reqs.append({
                        "src": src_ip,
                        "sport": src_port,
                        "dst": dst_ip,
                        "dport": dst_port,
                        "service": parsed["service"],
                        "service_name": parsed["service_name"],
                        "path": parsed["path"]
                    })

            if total_packets >= max_pkts or len(cip_reqs) >= target_cip:
                break

    return pd.DataFrame(cip_reqs)

# ----------------------
# Export + Neo4j import
# ----------------------

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
        raise SystemExit("Neo4j import requested, but cpag_to_neo4j.py is not available.")

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

# ----------------------
# Main
# ----------------------

def main():
    ap = argparse.ArgumentParser(description="End-to-end CPAG pipeline for ENIP/CIP traffic (pcapng or pcap) + optional Neo4j import.")
    ap.add_argument("--pcap", required=True, help="Path to .pcapng or .pcap file")
    ap.add_argument("--outdir", default="./out", help="Output directory")
    ap.add_argument("--max-pkts", type=int, default=120000, help="Max packets to scan (early stop)")
    ap.add_argument("--target-cip", type=int, default=8000, help="Stop after collecting this many CIP requests")
    ap.add_argument("--top-k", type=int, default=40, help="Top-K actions to draw in standard graph")
    ap.add_argument("--top-per-plc", type=int, default=20, help="Top actions per PLC in bundled graphs")

    # Neo4j (optional)
    ap.add_argument("--neo4j-uri", help="neo4j://host:7687 or bolt://host:7687")
    ap.add_argument("--neo4j-user", help="Neo4j username")
    ap.add_argument("--neo4j-password", help="Neo4j password")
    ap.add_argument("--neo4j-db", default="neo4j", help="Neo4j database name")
    ap.add_argument("--label", default="CPAGNode", help="Node label to use in Neo4j (default CPAGNode)")
    ap.add_argument("--wipe", action="store_true", help="Delete existing graph for this label before import")

    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    kind = detect_container(args.pcap)
    print(f"[+] Detected capture format: {kind.upper()}")
    if kind == "pcapng":
        df = CP.parse_pcap_enip_requests(args.pcap, max_pkts=args.max_pkts, target_cip=args.target_cip)
    else:
        df = parse_pcap_classic_enip_requests(args.pcap, max_pkts=args.max_pkts, target_cip=args.target_cip)

    cip_csv = os.path.join(args.outdir, "enip_cip_requests_parsed.csv")
    df.to_csv(cip_csv, index=False)
    print(f"[+] CIP requests saved: {cip_csv} ({len(df)} rows)")

    print("[+] Building CPAG units...")
    units = CP.build_cpag_units(df)
    cpag_json = os.path.join(args.outdir, "cpag_units.json")
    with open(cpag_json, "w", encoding="utf-8") as f:
        json.dump({"units": units}, f, ensure_ascii=False, indent=2)
    print(f"[+] CPAG units saved: {cpag_json} ({len(units)} units)")

    print("[+] Exporting nodes/edges and drawing standard Top-K graph...")
    std = CP.export_nodes_edges(units, args.outdir, top_k=args.top_k)
    print(f"    Nodes: {std['nodes_csv']}")
    print(f"    Edges: {std['edges_csv']}")
    print(f"    Graph: {std['graph_png']}")

    print("[+] Bundling R/W per tag and drawing per-PLC layered graphs...")
    bnd = CP.export_bundled_per_plc(units, args.outdir, top_per_plc=args.top_per_plc)
    print(f"    Bundled nodes: {bnd['bundled_nodes_csv']}")
    print(f"    Bundled edges: {bnd['bundled_edges_csv']}")
    for p in bnd["per_plc_pngs"]:
        print(f"    Per-PLC image: {p}")

    # Optional Neo4j import
    if args.neo4j_uri and args.neo4j_user and args.neo4j_password:
        print("[+] Importing standard CSVs into Neo4j...")
        import_into_neo4j(std["nodes_csv"], std["edges_csv"],
                          uri=args.neo4j_uri, user=args.neo4j_user, password=args.neo4j_password,
                          database=args.neo4j_db, label=args.label, wipe=args.wipe)

        print("[+] Importing bundled CSVs into Neo4j with label suffix 'Bundled'...")
        label2 = (args.label + "Bundled") if args.label else "CPAGNodeBundled"
        import_into_neo4j(bnd["bundled_nodes_csv"], bnd["bundled_edges_csv"],
                          uri=args.neo4j_uri, user=args.neo4j_user, password=args.neo4j_password,
                          database=args.neo4j_db, label=label2, wipe=False)

    print("[+] Done.")

if __name__ == "__main__":
    main()
