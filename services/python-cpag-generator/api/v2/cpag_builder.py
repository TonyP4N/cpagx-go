#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPAG Builder & Visualizer from CSV time-series (Patched)
- Fix: avoid UnboundLocalError on 'plt' by not reassigning inside function; add lazy import fallback.
- Features:
  * Minimal CPAG from binary transitions
  * Enhanced CPAG with analog context (pre-window range + post-window effect)
  * PNG visualization (matplotlib + networkx), no explicit colors
Requirements:
  pandas, numpy, networkx, matplotlib
"""
import argparse
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# Optional imports (may be None and resolved lazily in visualize_cpag)
try:
    import matplotlib.pyplot as plt  # type: ignore
except Exception:
    plt = None  # type: ignore
try:
    import networkx as nx  # type: ignore
except Exception:
    nx = None  # type: ignore

# --------------------- Utilities ---------------------
TS_FORMATS = [
    "%d/%m/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"
]

def parse_ts(x) -> Optional[datetime]:
    s = str(x)
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

META_PREFIXES = ["A#", "Attack", "Intent", "Entry", "Attacker", "ASD", "Annotation", "Other Anomalies"]

def split_meta_signal_cols(df: pd.DataFrame) -> Tuple[List[str], List[str]]:
    meta_cols = set([c for c in df.columns if any(str(c).startswith(p) for p in META_PREFIXES)] + ["Timestamp", "__ts"])
    signal_cols = [c for c in df.columns if c not in meta_cols]
    return list(meta_cols), signal_cols

def detect_binary_and_analog(df: pd.DataFrame, signal_cols: List[str]) -> Tuple[List[str], List[str]]:
    binary, analog = [], []
    for c in signal_cols:
        vals = pd.to_numeric(df[c], errors="coerce")
        uniq = np.sort(vals.dropna().unique())
        if len(uniq) <= 3 and set(uniq).issubset({0,1,2}):
            binary.append(c)
        elif vals.dropna().nunique() >= 5:
            analog.append(c)
    return binary, analog

def extract_stage(tag: str) -> Optional[int]:
    m = re.search(r"(\d+)", str(tag))
    if not m:
        return None
    try:
        v = int(m.group(1))
        if v >= 100:
            return v // 100
        if v >= 10:
            return v // 10
        return v
    except Exception:
        return None

def state_label(tag: str, v: int) -> str:
    name = {0:"OFF/CLOSED", 1:"ON/OPEN", 2:"STATE2"}.get(int(v), f"VAL_{v}")
    return f"{tag}={name}"

# --------------------- Event detection ---------------------
@dataclass
class Event:
    idx: int
    timestamp: Optional[datetime]
    tag: str
    stage: Optional[int]
    from_val: int
    to_val: int
    direction: str   # rise/fall/toggle

def detect_binary_events(df: pd.DataFrame, binary_cols: List[str], limit_per_tag: int = 5) -> List[Event]:
    events: List[Event] = []
    if not df["__ts"].notna().any():
        return events
    stages = {c: extract_stage(c) for c in binary_cols}
    for c in binary_cols:
        vals = pd.to_numeric(df[c], errors="coerce")
        prev = vals.shift(1)
        changed = (vals != prev) & vals.notna() & prev.notna()
        idxs = list(np.where(changed)[0])
        for idx in idxs[:max(0, int(limit_per_tag))]:
            f = int(prev.iloc[idx]); t = int(vals.iloc[idx])
            direction = "rise" if (f==0 and t==1) else ("fall" if (f==1 and t==0) else "toggle")
            events.append(Event(
                idx=int(idx),
                timestamp=df["__ts"].iloc[idx] if "__ts" in df.columns else None,
                tag=c,
                stage=stages.get(c),
                from_val=f,
                to_val=t,
                direction=direction,
            ))
    return events

# --------------------- Analog context ---------------------
@dataclass
class AnalogStats:
    q25: float
    q50: float
    q75: float
    mean: float
    std: float
    iqr: float

def robust_stats(series: pd.Series) -> Optional[AnalogStats]:
    vals = pd.to_numeric(series, errors="coerce").dropna()
    if vals.empty:
        return None
    q25 = float(vals.quantile(0.25))
    q50 = float(vals.quantile(0.50))
    q75 = float(vals.quantile(0.75))
    mean = float(vals.mean())
    std = float(vals.std(ddof=1)) if len(vals) > 1 else 0.0
    iqr = q75 - q25
    return AnalogStats(q25=q25, q50=q50, q75=q75, mean=mean, std=std, iqr=float(iqr))

def effect_direction(pre: AnalogStats, post: AnalogStats):
    """Return (direction, delta, thr, score) where score = |delta|/max(IQR,1e-6)"""
    eps = 1e-6
    thr = max(0.5 * (pre.iqr if pre.iqr is not None else 0.0), 0.05)
    delta = post.q50 - pre.q50
    if delta > thr:
        d = "increase"
    elif delta < -thr:
        d = "decrease"
    else:
        d = "stable"
    score = abs(delta) / max(pre.iqr, eps)
    return d, float(delta), float(thr), float(score)

# --------------------- CPAG structures ---------------------
def add_node(nodes, added, nid_type: str, label: str) -> str:
    nid = f"{nid_type}:{label}"
    if nid not in added:
        nodes.append({"id": nid, "type": nid_type, "label": label})
        added.add(nid)
    return nid

def minimal_cpag_from_events(events: List[Event]) -> Dict:
    nodes, edges, units = [], [], []
    added = set()
    for ev in events:
        pre_label = state_label(ev.tag, ev.from_val)
        post_label = state_label(ev.tag, ev.to_val)
        action_label = f"COMMAND {ev.tag} -> {post_label.split('=')[1]}"

        pre_id = add_node(nodes, added, "precondition", pre_label)
        act_id = add_node(nodes, added, "action", action_label)
        post_id = add_node(nodes, added, "postcondition", post_label)

        edges.append({"from": pre_id, "to": act_id, "type": "AND"})
        edges.append({"from": act_id, "to": post_id, "type": "CAUSES"})

        units.append({
            "timestamp": ev.timestamp.isoformat() if isinstance(ev.timestamp, datetime) else None,
            "tag": ev.tag,
            "stage": ev.stage,
            "preconditions": [pre_id],
            "action": act_id,
            "postconditions": [post_id],
            "note": f"Auto-derived from {ev.direction} event"
        })
    return {"schema": "cpag-minimal-0.1", "nodes": nodes, "edges": edges, "units": units}

def enhanced_cpag_from_events(df: pd.DataFrame,
                              events: List[Event],
                              analog_cols: List[str],
                              pre_s: int = 20,
                              post_s: int = 20,
                              top_k_analog: int = 3) -> Dict:
    nodes, edges, units = [], [], []
    added = set()
    tag_stage = {c: extract_stage(c) for c in analog_cols}

    pre_window = timedelta(seconds=int(pre_s))
    post_window = timedelta(seconds=int(post_s))

    for ev in events:
        ts = ev.timestamp
        pre_label = state_label(ev.tag, ev.from_val)
        post_label = state_label(ev.tag, ev.to_val)
        action_label = f"COMMAND {ev.tag} -> {post_label.split('=')[1]}"

        pre_id = add_node(nodes, added, "precondition", pre_label)
        act_id = add_node(nodes, added, "action", action_label)
        post_id = add_node(nodes, added, "postcondition", post_label)

        edges.append({"from": pre_id, "to": act_id, "type": "AND"})
        edges.append({"from": act_id, "to": post_id, "type": "CAUSES"})

        preconditions = [pre_id]
        postconditions = [post_id]

        analog_ctx = []
        if isinstance(ts, datetime) and df["__ts"].notna().any():
            pre_mask = (df["__ts"] >= ts - pre_window) & (df["__ts"] < ts)
            post_mask = (df["__ts"] > ts) & (df["__ts"] <= ts + post_window)
            candidates = [a for a in analog_cols if tag_stage.get(a) == ev.stage]
            for a in candidates:
                pre_stats = robust_stats(df.loc[pre_mask, a])
                post_stats = robust_stats(df.loc[post_mask, a])
                if (pre_stats is None) or (post_stats is None):
                    continue
                direction, delta, thr, score = effect_direction(pre_stats, post_stats)
                analog_ctx.append({
                    "tag": a,
                    "pre": pre_stats.__dict__,
                    "post": post_stats.__dict__,
                    "direction": direction,
                    "delta": delta,
                    "threshold": thr,
                    "score": score
                })

        analog_ctx = sorted(analog_ctx, key=lambda x: x["score"], reverse=True)[:max(0, int(top_k_analog))]

        for ctx in analog_ctx:
            a = ctx["tag"]
            pre = ctx["pre"]; post = ctx["post"]
            pre_range_label = f"{a}∈[{pre['q25']:.2f},{pre['q75']:.2f}] (pre {int(pre_s)}s)"
            pre_range_id = add_node(nodes, added, "precondition", pre_range_label)
            edges.append({"from": pre_range_id, "to": act_id, "type": "AND"})
            preconditions.append(pre_range_id)

            if ctx["direction"] != "stable":
                post_eff_label = f"{a} {ctx['direction']} (Δ≈{ctx['delta']:.2f} in {int(post_s)}s)"
                post_eff_id = add_node(nodes, added, "postcondition", post_eff_label)
                edges.append({"from": act_id, "to": post_eff_id, "type": "CAUSES"})
                postconditions.append(post_eff_id)

        if analog_ctx:
            raw = float(np.mean([c["score"] for c in analog_ctx]))
            confidence = float(1 - math.exp(-raw))
        else:
            confidence = 0.5

        units.append({
            "timestamp": ev.timestamp.isoformat() if isinstance(ev.timestamp, datetime) else None,
            "tag": ev.tag,
            "stage": ev.stage,
            "preconditions": preconditions,
            "action": act_id,
            "postconditions": postconditions,
            "context": {
                "pre_window_s": int(pre_s),
                "post_window_s": int(post_s),
                "analog_tags": analog_ctx
            },
            "confidence": confidence,
            "note": "Enhanced unit with analog range (pre) and effect (post)"
        })

    return {
        "schema": "cpag-enhanced-0.2",
        "windows": {"pre_s": int(pre_s), "post_s": int(post_s)},
        "nodes": nodes, "edges": edges, "units": units
    }

# --------------------- Visualization ---------------------
def visualize_cpag(cpag: Dict, out_png: Path, seed: int = 42):
    """Render a CPAG dict to a PNG file using matplotlib + networkx."""
    global plt, nx  # use (and possibly set) the module-level objects
    # Lazy import fallback if not imported at module import time
    if plt is None or nx is None:
        try:
            if plt is None:
                import matplotlib.pyplot as _plt  # noqa: F401
                plt = _plt
            if nx is None:
                import networkx as _nx  # noqa: F401
                nx = _nx
        except Exception as e:
            raise RuntimeError("Visualization requires matplotlib and networkx to be installed.") from e

    G = nx.DiGraph()
    for n in cpag.get("nodes", []):
        G.add_node(n["id"], **n)
    for e in cpag.get("edges", []):
        G.add_edge(e["from"], e["to"], **e)

    pos = nx.spring_layout(G, seed=seed, k=0.7, iterations=200)

    pre_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "precondition"]
    act_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "action"]
    post_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "postcondition"]

    plt.figure(figsize=(20, 20))
    nx.draw_networkx_nodes(G, pos, nodelist=pre_nodes, node_shape="o")
    nx.draw_networkx_nodes(G, pos, nodelist=act_nodes, node_shape="s")
    nx.draw_networkx_nodes(G, pos, nodelist=post_nodes, node_shape="^")
    nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle="-|>", arrowsize=12)

    labels = {n: G.nodes[n].get("label", n) for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=7)

    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker="o", linestyle="None", label="Precondition"),
        Line2D([0], [0], marker="s", linestyle="None", label="Action"),
        Line2D([0], [0], marker="^", linestyle="None", label="Postcondition"),
    ]
    plt.legend(handles=legend_elements, loc="best")
    plt.title("CPAG Visualization")
    plt.tight_layout()
    plt.savefig(out_png, dpi=220, bbox_inches="tight")
    plt.close()

# --------------------- CPAG build pipelines ---------------------
def minimal_pipeline(df: pd.DataFrame, per_tag: int):
    _, signal_cols = split_meta_signal_cols(df)
    binary_cols, _ = detect_binary_and_analog(df, signal_cols)
    events = detect_binary_events(df, binary_cols, limit_per_tag=per_tag)
    cpag_min = minimal_cpag_from_events(events)
    return cpag_min

def enhanced_pipeline(df: pd.DataFrame, per_tag: int, pre_s: int, post_s: int, top_k_analog: int):
    _, signal_cols = split_meta_signal_cols(df)
    binary_cols, analog_cols = detect_binary_and_analog(df, signal_cols)
    events = detect_binary_events(df, binary_cols, limit_per_tag=per_tag)
    cpag_enh = enhanced_cpag_from_events(df, events, analog_cols, pre_s=pre_s, post_s=post_s, top_k_analog=top_k_analog)
    return cpag_enh

# --------------------- Main ---------------------
def run(csv_path: Path, out_dir: Path, build_minimal: bool, build_enhanced: bool,
        pre_s: int, post_s: int, per_tag: int, top_k_analog: int, visualize: bool):
    out_dir.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(csv_path, low_memory=False)
    ts = df["Timestamp"].apply(parse_ts) if "Timestamp" in df.columns else pd.Series([None]*len(df))
    df = df.assign(__ts=ts).sort_values("__ts").reset_index(drop=True)

    if build_minimal:
        cpag_min = minimal_pipeline(df, per_tag=per_tag)
        cpag_min["source_csv"] = csv_path.name
        cpag_min["generated_at"] = datetime.utcnow().isoformat() + "Z"
        (out_dir / "cpag_minimal.json").write_text(json.dumps(cpag_min, ensure_ascii=False, indent=2), encoding="utf-8")
        if visualize:
            visualize_cpag(cpag_min, out_dir / "cpag_minimal.png", seed=42)

    if build_enhanced:
        cpag_enh = enhanced_pipeline(df, per_tag=per_tag, pre_s=pre_s, post_s=post_s, top_k_analog=top_k_analog)
        cpag_enh["source_csv"] = csv_path.name
        cpag_enh["generated_at"] = datetime.utcnow().isoformat() + "Z"
        (out_dir / "cpag_enhanced.json").write_text(json.dumps(cpag_enh, ensure_ascii=False, indent=2), encoding="utf-8")
        if visualize:
            visualize_cpag(cpag_enh, out_dir / "cpag_enhanced.png", seed=7)

def main():
    parser = argparse.ArgumentParser(description="Build CPAG (minimal/enhanced) from CSV and visualize.")
    parser.add_argument("--csv", required=True, type=Path, help="Input CSV file path")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    parser.add_argument("--minimal", action="store_true", help="Build minimal CPAG")
    parser.add_argument("--enhanced", action="store_true", help="Build enhanced CPAG with analog context")
    parser.add_argument("--pre", type=int, default=20, help="Pre-window seconds for enhanced CPAG")
    parser.add_argument("--post", type=int, default=20, help="Post-window seconds for enhanced CPAG")
    parser.add_argument("--per-tag", type=int, default=5, help="Max events per binary tag")
    parser.add_argument("--top-k-analog", type=int, default=3, help="Max analog contexts per event")
    parser.add_argument("--visualize", action="store_true", help="Render PNG visualization(s)")
    args = parser.parse_args()

    if not (args.minimal or args.enhanced):
        args.minimal = True

    run(
        csv_path=args.csv,
        out_dir=args.out,
        build_minimal=args.minimal,
        build_enhanced=args.enhanced,
        pre_s=args.pre,
        post_s=args.post,
        per_tag=args.per_tag,
        top_k_analog=args.top_k_analog,
        visualize=args.visualize
    )

if __name__ == "__main__":
    main()
