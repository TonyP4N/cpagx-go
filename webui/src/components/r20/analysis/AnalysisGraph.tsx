import React, { useEffect, useMemo, useRef, useState } from 'react';
import { positionGraph, Row } from '../analysisModel';
import { control } from './widgets';

export function Graph({ nodes, edges, labels, selectedIds, inspect }: { nodes: Row[]; edges: Row[]; labels: Map<string, string>; selectedIds: Set<string>; inspect: (node: Row) => void }) {
  const canvas = useRef<HTMLCanvasElement>(null), wrapper = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(900), [height, setHeight] = useState(420), [drawMs, setDrawMs] = useState(0);
  const positions = useMemo(() => positionGraph(nodes), [nodes]);
  const worldHeight = Math.max(420, ...positions.map(point => point.y + 40));
  const canvasHeight = nodes.length <= 80 ? Math.min(worldHeight, 2400) : height;
  useEffect(() => { if (!wrapper.current) return; const observer = new ResizeObserver(entries => setWidth(Math.max(200, Math.round(entries[0].contentRect.width)))); observer.observe(wrapper.current); return () => observer.disconnect(); }, []);
  useEffect(() => {
    const start = performance.now(), target = canvas.current; if (!target) return;
    const ratio = Math.min(window.devicePixelRatio || 1, 2); target.width = width * ratio; target.height = canvasHeight * ratio;
    const context = target.getContext('2d'); if (!context) return; context.scale(ratio, ratio); context.clearRect(0, 0, width, canvasHeight);
    const host = target.parentElement ?? target;
    const token = (name: string, fallback: string) => getComputedStyle(host).getPropertyValue(name).trim() || fallback;
    const select = token('--select', '#b45309'), net = token('--net', '#2f5f8a'), change = token('--change', '#5b4db8'), sample = token('--sample', '#64748b'), edgeColor = token('--edge', '#d5dbe3'), ink = token('--ink', '#15202b');
    const points = new Map(positions.map(point => [point.node.id, point])); context.lineWidth = 0.7;
    edges.forEach(edge => { const a = points.get(edge.source), b = points.get(edge.target); if (!a || !b) return; context.strokeStyle = selectedIds.has(edge.claim_id ?? edge.id) || (selectedIds.has(edge.source) && selectedIds.has(edge.target)) ? select : edgeColor; context.beginPath(); context.moveTo(a.x * width / 1000, a.y * canvasHeight / worldHeight); context.lineTo(b.x * width / 1000, b.y * canvasHeight / worldHeight); context.stroke(); });
    positions.forEach(({ node, x, y }) => { const selected = selectedIds.has(node.event_id ?? node.id); context.fillStyle = selected ? select : node.kind === 'network' ? net : node.kind === 'process' ? sample : change; context.beginPath(); context.arc(x * width / 1000, y * canvasHeight / worldHeight, selected ? 5 : 3, 0, Math.PI * 2); context.fill(); if (nodes.length <= 80) { context.fillStyle = ink; context.font = '11px system-ui'; const label = labels.get(node.event_id ?? node.id) ?? `${node.kind} · ${String(node.event_id ?? node.id).slice(0, 16)}`; context.fillText(label.length > 27 ? label.slice(0, 26) + '…' : label, x * width / 1000 + 9, y * canvasHeight / worldHeight + 4, Math.max(35, width * 0.28)); } });
    setDrawMs(Number((performance.now() - start).toFixed(2)));
  }, [positions, edges, selectedIds, width, canvasHeight, worldHeight, labels, nodes]);
  function click(event: React.MouseEvent<HTMLCanvasElement>) {
    const rect = event.currentTarget.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
    let nearest: typeof positions[number] | undefined, distance = 144;
    positions.forEach(point => { const next = (point.x * width / 1000 - x) ** 2 + (point.y * canvasHeight / worldHeight - y) ** 2; if (next < distance) { distance = next; nearest = point; } });
    if (nearest) inspect(nearest.node);
  }
  return <div ref={wrapper} className="min-w-0" data-testid="analysis-graph" data-nodes={nodes.length} data-edges={edges.length} data-draw-ms={drawMs}>
    <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs"><p><span className="wb-legend-net">● 网络</span>　<span className="wb-legend-change">● 变化</span>　<span className="wb-legend-sample">● 过程采样</span>　<span className="wb-legend-select">● 已选关联</span></p>{nodes.length > 80 && <button className={control} type="button" onClick={() => setHeight(value => value === 420 ? Math.min(worldHeight, 2400) : 420)}>{height === 420 ? '展开图高' : '适应图高'}</button>}</div>
    <div className="wb-graph-well max-h-[480px] overflow-auto rounded-lg border"><canvas ref={canvas} onClick={click} style={{ width, height: canvasHeight, display: 'block', touchAction: 'manipulation' }} role="img" aria-label={`关系图，${nodes.length} 个节点，${edges.length} 条候选连线。可通过下方节点列表键盘选择。`} /></div><p className="mt-2 text-xs text-slate-500">连线表示候选假设。点击节点或使用节点列表，联动查看时间、候选和原始记录。</p>
  </div>;
}
