import React, { useEffect, useMemo, useRef, useState } from 'react';
import { aggregate, boundedGraph, EMPTY_FILTER, Filter, idOf, intervalOf, kindOf, LIMITS, matches, positionGraph, relatedSelection, Row, Selection, stateOf } from './analysisModel';

const control = 'min-h-[40px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 hover:border-slate-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal-700 disabled:cursor-not-allowed disabled:opacity-40';
const panel = 'min-w-0 rounded-xl border border-slate-200 bg-white p-4 space-y-3';
type Data = { metadata: Row; nodes: Row[]; edges: Row[]; operations: Row[]; changes: Row[]; candidates: Row[]; totals: Record<string, number>; compact: boolean; replay: boolean };
async function read(base: string, path: string, signal: AbortSignal): Promise<Row> {
  const response = await fetch(base + path, { credentials: 'same-origin', cache: 'no-store', signal });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`${response.status} ${value.error?.code ?? 'request_failed'}：${value.error?.message ?? '读取失败'}`);
  return value;
}
async function pages(base: string, root: string, path: (string | number)[], cap: number, signal: AbortSignal) {
  const items: Row[] = []; let total = 0;
  do {
    const query = new URLSearchParams({ action: 'page', logical_root: root, path: JSON.stringify(path), offset: String(items.length), limit: String(Math.min(100, cap - items.length)) });
    const value = await read(base, '/shared-query?' + query, signal);
    if (!Array.isArray(value.items) || !Number.isSafeInteger(value.total) || value.total < 0 || value.items.length > Math.min(100, cap - items.length) || (value.total > items.length && !value.items.length)) throw new Error('分页结果不完整，请重新核验读取。');
    total = value.total; items.push(...value.items);
  } while (items.length < Math.min(total, cap));
  return { items, total };
}
const utcTime = new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3, hourCycle: 'h23', timeZone: 'UTC' });
function timeText(row: Row) {
  const time = intervalOf(row);
  return time ? time.map(value => utcTime.format(new Date(value * 1000)) + ' UTC').join(' — ') : '时间依据不足';
}
function Pager({ page, count, change }: { page: number; count: number; change: (page: number) => void }) {
  return <nav aria-label="记录分页" className="flex items-center gap-2 text-xs tabular-nums"><button type="button" className={control} disabled={page <= 0} onClick={() => change(page - 1)}>上一页</button><span>{count ? page * LIMITS.page + 1 : 0}–{Math.min((page + 1) * LIMITS.page, count)} / {count}</span><button type="button" className={control} disabled={(page + 1) * LIMITS.page >= count} onClick={() => change(page + 1)}>下一页</button></nav>;
}
function JsonDetails({ value, label }: { value: unknown; label: string }) {
  const [open, setOpen] = useState(false);
  return <details onToggle={event => setOpen(event.currentTarget.open)}><summary className="cursor-pointer rounded text-sm text-teal-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal-700">{label}</summary>{open && <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 text-xs">{JSON.stringify(value, null, 2)}</pre>}</details>;
}
function Graph({ nodes, edges, labels, selectedIds, inspect }: { nodes: Row[]; edges: Row[]; labels: Map<string, string>; selectedIds: Set<string>; inspect: (node: Row) => void }) {
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
    const points = new Map(positions.map(point => [point.node.id, point])); context.lineWidth = 0.7;
    edges.forEach(edge => { const a = points.get(edge.source), b = points.get(edge.target); if (!a || !b) return; context.strokeStyle = selectedIds.has(edge.claim_id ?? edge.id) || (selectedIds.has(edge.source) && selectedIds.has(edge.target)) ? '#b45309' : '#cbd5e1'; context.beginPath(); context.moveTo(a.x * width / 1000, a.y * canvasHeight / worldHeight); context.lineTo(b.x * width / 1000, b.y * canvasHeight / worldHeight); context.stroke(); });
    positions.forEach(({ node, x, y }) => { const selected = selectedIds.has(node.event_id ?? node.id); context.fillStyle = selected ? '#b45309' : node.kind === 'network' ? '#0f766e' : node.kind === 'process' ? '#64748b' : '#2563eb'; context.beginPath(); context.arc(x * width / 1000, y * canvasHeight / worldHeight, selected ? 5 : 3, 0, Math.PI * 2); context.fill(); if (nodes.length <= 80) { context.fillStyle = '#334155'; context.font = '11px system-ui'; const label = labels.get(node.event_id ?? node.id) ?? `${node.kind} · ${String(node.event_id ?? node.id).slice(0, 16)}`; context.fillText(label.length > 27 ? label.slice(0, 26) + '…' : label, x * width / 1000 + 9, y * canvasHeight / worldHeight + 4, Math.max(35, width * 0.28)); } });
    setDrawMs(Number((performance.now() - start).toFixed(2)));
  }, [positions, edges, selectedIds, width, canvasHeight, worldHeight, labels]);
  function click(event: React.MouseEvent<HTMLCanvasElement>) {
    const rect = event.currentTarget.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
    let nearest: typeof positions[number] | undefined, distance = 144;
    positions.forEach(point => { const next = (point.x * width / 1000 - x) ** 2 + (point.y * canvasHeight / worldHeight - y) ** 2; if (next < distance) { distance = next; nearest = point; } });
    if (nearest) inspect(nearest.node);
  }
  return <div ref={wrapper} className="min-w-0" data-testid="analysis-graph" data-nodes={nodes.length} data-edges={edges.length} data-draw-ms={drawMs}>
    <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs"><p><span className="text-teal-800">● 网络</span>　<span className="text-blue-700">● 变化</span>　<span className="text-slate-600">● 过程采样</span>　<span className="text-amber-800">● 已选关联</span></p>{nodes.length > 80 && <button className={control} type="button" onClick={() => setHeight(value => value === 420 ? Math.min(worldHeight, 2400) : 420)}>{height === 420 ? '展开图高' : '适应图高'}</button>}</div>
    <div className="max-h-[600px] overflow-auto rounded-lg border border-slate-200 bg-slate-50"><canvas ref={canvas} onClick={click} style={{ width, height: canvasHeight, display: 'block', touchAction: 'manipulation' }} role="img" aria-label={`关系图，${nodes.length} 个节点，${edges.length} 条候选连线。可通过下方节点列表键盘选择。`} /></div><p className="mt-2 text-xs text-slate-500">连线表示候选假设。点击节点或使用节点列表，联动查看时间、候选和原始记录。</p>
  </div>;
}

export default function Analysis({ runId, datasetId, onError }: { runId: string; datasetId: string; onError: (message: string) => void }) {
  const [locationSearch, setLocationSearch] = useState<string | null>(null);
  const route = useMemo(() => new URLSearchParams(locationSearch ?? ''), [locationSearch]);
  useEffect(() => {
    const restore = () => {
      const url = new URL(window.location.href);
      ['a_q', 'a_from', 'a_to', 'a_focus'].forEach(key => url.searchParams.delete(key));
      if (url.search !== window.location.search) window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash);
      setLocationSearch(url.search);
    };
    restore(); window.addEventListener('popstate', restore);
    return () => window.removeEventListener('popstate', restore);
  }, [runId, datasetId]);
  const [data, setData] = useState<Data | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0), [large, setLarge] = useState(false), [snapshot, setSnapshot] = useState(''), [snapshotDraft, setSnapshotDraft] = useState('');
  const [filter, setFilter] = useState<Filter>(EMPTY_FILTER), [draft, setDraft] = useState<Filter>(EMPTY_FILTER), [dimension, setDimension] = useState<'state' | 'asset' | 'minute'>('state');
  const [selection, setSelection] = useState<Selection | null>(null), [evidence, setEvidence] = useState<Row | null>(null), [evidenceBusy, setEvidenceBusy] = useState(false);
  const [timelinePage, setTimelinePage] = useState(0), [candidatePage, setCandidatePage] = useState(0), [nodePage, setNodePage] = useState(0), [groupPage, setGroupPage] = useState(0);
  const generation = useRef(0), evidenceGeneration = useRef(0), errorHandler = useRef(onError), evidenceAbort = useRef<AbortController | null>(null);
  errorHandler.current = onError;
  const base = `/api/v3/runs/${encodeURIComponent(runId)}`;
  function fail(reason: unknown) {
    const message = reason instanceof Error ? reason.message : String(reason);
    setData(null); setEvidence(null); setSelection(null); setError(message); setEvidenceBusy(false); evidenceGeneration.current++; evidenceAbort.current?.abort(); errorHandler.current(message);
  }
  function syncUrl(values: Record<string, string>) {
    const url = new URL(window.location.href);
    ['a_q', 'a_from', 'a_to', 'a_focus'].forEach(key => url.searchParams.delete(key));
    Object.entries(values).forEach(([key, value]) => { if (value) url.searchParams.set(key, value); else url.searchParams.delete(key); });
    window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash);
    setLocationSearch(url.search);
  }
  useEffect(() => {
    if (locationSearch === null) return;
    const get = (key: string) => route.get(key) ?? '';
    const safe = { kind: ['operation', 'change', 'candidate'].includes(get('a_kind')) ? get('a_kind') : '', state: /^[a-z][a-z0-9_]{0,63}$/.test(get('a_state')) ? get('a_state') : '' };
    setFilter(previous => ({ ...previous, ...safe })); setDraft(previous => ({ ...previous, ...safe }));
    const snap = /^\d+$/.test(get('a_snapshot')) ? get('a_snapshot') : ''; setSnapshot(snap); setSnapshotDraft(snap);
    const group = get('a_group'); setDimension(group === 'asset' || group === 'minute' ? group : 'state');
    setTimelinePage(0); setCandidatePage(0); setNodePage(0); setGroupPage(0);
  }, [locationSearch === null, route.get('a_kind'), route.get('a_state'), route.get('a_snapshot'), route.get('a_group')]);
  useEffect(() => {
    const ticket = ++generation.current, controller = new AbortController(); evidenceGeneration.current++; evidenceAbort.current?.abort();
    setData(null); setEvidence(null); setSelection(null); setError(''); setBusy(true); setEvidenceBusy(false);
    const capNodes = large ? LIMITS.nodes : 200, capEdges = large ? LIMITS.edges : 600, capRows = large ? LIMITS.rows : 100;
    async function load() {
      const binding = (await read(base, '', controller.signal)).run;
      if (binding?.dataset_id !== datasetId || binding.state !== 'succeeded') throw new Error('运行与当前数据集不匹配或尚未成功完成，请重新选择已完成运行。');
      const metadata = await read(base, '/result', controller.signal), compact = metadata.storage_format === 'shared-observation-dag-6', replay = binding.mode === 'dual_source_replay';
      if (snapshot && !replay) throw new Error('当前运行没有回放快照，请切换到终态。');
      const totals: Record<string, number> = {}; const kinds = ['nodes', 'edges', 'operations', 'changes', 'candidates']; let values: Row[][];
      if (compact) {
        if (typeof metadata.synthetic !== 'boolean' || metadata.synthetic !== metadata.manifest?.synthetic) throw new Error('结果来源标记不一致，请核查运行产物。');
        const output = await Promise.all(kinds.map((kind, index) => pages(base, snapshot ? 'history/snapshots' : index < 2 ? 'graph.json' : 'analysis.json', snapshot ? [Number(snapshot), index < 2 ? 'graph' : 'analysis', kind] : [kind], index < 2 ? index ? capEdges : capNodes : capRows, controller.signal)));
        values = output.map((page, index) => { totals[kinds[index]] = page.total; return page.items; });
      } else {
        const output = snapshot ? await read(base, '/snapshots/' + encodeURIComponent(snapshot), controller.signal) : metadata;
        const body = output.data ?? output.snapshot ?? output, analysis = body.analysis ?? body.result, graph = body.graph;
        if (!analysis || !graph || typeof analysis.synthetic !== 'boolean' || graph.synthetic !== analysis.synthetic || (metadata.synthetic !== undefined && metadata.synthetic !== analysis.synthetic)) throw new Error('已核验结果结构或来源不一致，请核查运行产物。');
        values = kinds.map((kind, index) => { const rows = (index < 2 ? graph : analysis)[kind]; if (!Array.isArray(rows)) throw new Error('结果缺少必要观测列表。'); totals[kind] = rows.length; return rows.slice(0, index < 2 ? index ? capEdges : capNodes : capRows); });
      }
      if (generation.current === ticket && !controller.signal.aborted) {
        setData({ metadata, compact, replay, nodes: values[0], edges: values[1], operations: values[2], changes: values[3], candidates: values[4], totals });
        errorHandler.current('');
      }
    }
    void load().catch(reason => { if (generation.current === ticket && !controller.signal.aborted) { fail(reason); controller.abort(); } }).finally(() => { if (generation.current === ticket) setBusy(false); });
    return () => { generation.current++; controller.abort(); evidenceGeneration.current++; evidenceAbort.current?.abort(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base, datasetId, large, snapshot, refresh]);
  async function inspect(next: Selection, offset = 0) {
    const current = generation.current, ticket = ++evidenceGeneration.current; evidenceAbort.current?.abort(); const controller = new AbortController(); evidenceAbort.current = controller;
    setSelection(next); setEvidence(null); setEvidenceBusy(false); setError('');
    if (!data || next.kind === 'node') return;
    const candidate = next.kind === 'candidate' ? data.candidates.find(row => idOf(row) === next.id) ?? data.edges.find(row => (row.claim_id ?? row.id) === next.id) : null;
    const selector: Record<string, string> = next.kind === 'change' ? { change: next.id } : { operation: candidate?.operation_id ?? candidate?.source ?? next.id };
    if (next.kind === 'candidate' && !candidate) { setError('候选不在当前已读取范围，请在完整分页核查中定位，或扩展视图。'); return; }
    const linkedId = candidate?.operation_id ?? candidate?.source ?? next.id;
    const index = timeline.findIndex(row => idOf(row) === linkedId); if (index >= 0) setTimelinePage(Math.floor(index / LIMITS.page));
    const linkedIndex = candidates.findIndex(row => row.operation_id === next.id || row.change_id === next.id || idOf(row) === next.id); if (linkedIndex >= 0) setCandidatePage(Math.floor(linkedIndex / LIMITS.page));
    const query = new URLSearchParams({ ...selector, ref_offset: String(offset), ref_limit: '25' }); if (snapshot) query.set(data.compact ? 'snapshot' : 'revision', snapshot); setEvidenceBusy(true);
    try { const value = await read(base, '/evidence?' + query, controller.signal); if (current === generation.current && ticket === evidenceGeneration.current) { if (typeof value.synthetic !== 'boolean' || value.synthetic !== (data.metadata.synthetic ?? data.metadata.data?.analysis?.synthetic)) throw new Error('原始证据来源标记与当前结果不一致。'); setEvidence(value); } }
    catch (reason) { if (current === generation.current && ticket === evidenceGeneration.current && !controller.signal.aborted) fail(reason); }
    finally { if (current === generation.current && ticket === evidenceGeneration.current) setEvidenceBusy(false); }
  }
  const rows = useMemo(() => data ? [...data.operations, ...data.changes] : [], [data]);
  const timeline = useMemo(() => rows.filter(row => matches(row, filter)).sort((a, b) => (intervalOf(a)?.[0] ?? Infinity) - (intervalOf(b)?.[0] ?? Infinity) || idOf(a).localeCompare(idOf(b))), [rows, filter]);
  const candidates = useMemo(() => (data?.candidates ?? []).filter(row => matches(row, { ...filter, kind: filter.kind === 'candidate' ? 'candidate' : '' })), [data, filter]);
  const graph = useMemo(() => boundedGraph(data?.nodes ?? [], data?.edges ?? [], [...rows, ...(data?.candidates ?? [])], filter, large ? LIMITS.nodes : 200, large ? LIMITS.edges : 600), [data, rows, filter, large]);
  const groups = useMemo(() => aggregate(timeline, dimension), [timeline, dimension]);
  const selected = selection?.kind === 'operation' ? data?.operations.find(row => idOf(row) === selection.id) ?? evidence?.selection?.operation : selection?.kind === 'change' ? data?.changes.find(row => idOf(row) === selection.id) ?? evidence?.selection?.change : selection?.kind === 'candidate' ? data?.candidates.find(row => idOf(row) === selection.id) : data?.nodes.find(row => row.id === selection?.id);
  const selectedIds = useMemo(() => { const ids = new Set<string>(); if (selection) ids.add(selection.id); if (selected) { if (selected.operation_id) ids.add(selected.operation_id); if (selected.change_id) ids.add(selected.change_id); if (selected.response?.event_id) ids.add(selected.response.event_id); } (data?.candidates ?? []).filter(row => row.operation_id === selection?.id || row.change_id === selection?.id || row.candidate_id === selection?.id).forEach(row => { ids.add(row.candidate_id); ids.add(row.operation_id); ids.add(row.change_id); }); return ids; }, [selection, selected, data]);
  const nodeLabels = useMemo(() => {
    const labels = new Map<string, string>();
    data?.operations.forEach(row => { labels.set(row.operation_id, `网络 · ${row.mapping?.asset_id ?? row.destination_endpoint ?? ''} ${row.operation ?? ''}`); if (row.response?.event_id) labels.set(row.response.event_id, `响应 · ${row.response.state ?? '未知'}`); });
    data?.changes.forEach(row => labels.set(row.event_id, `变化 · ${row.result?.asset_id ?? ''} ${row.result?.tag ?? ''}`));
    data?.nodes.forEach(row => { if (!labels.has(row.event_id ?? row.id)) labels.set(row.event_id ?? row.id, `${row.kind === 'process' ? '采样' : row.kind === 'network' ? '网络' : '派生'} · ${String(row.event_id ?? row.id).slice(0, 16)}`); });
    return labels;
  }, [data]);
  const states = useMemo(() => Array.from(new Set([...rows, ...(data?.candidates ?? [])].map(stateOf))).sort(), [rows, data]);
  function apply(event: React.FormEvent) {
    event.preventDefault(); if ((draft.from && !Number.isFinite(Date.parse(draft.from))) || (draft.to && !Number.isFinite(Date.parse(draft.to))) || (draft.from && draft.to && Date.parse(draft.from) > Date.parse(draft.to))) { setError('请填写有效时间，且开始时间不晚于结束时间。'); return; }
    setFilter(draft); setTimelinePage(0); setCandidatePage(0); setNodePage(0); setGroupPage(0); setError(''); syncUrl({ a_kind: draft.kind, a_state: draft.state });
  }
  const slice = (values: Row[], page: number) => values.slice(page * LIMITS.page, (page + 1) * LIMITS.page);
  return <section aria-label="分析工作区" className="space-y-5" data-testid="analysis-workspace">
    <header className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-xl font-semibold text-slate-900">分析工作区</h2><p className="mt-1 text-sm text-slate-600">从观测关系定位时间与候选，回到可核查的原始证据。</p></div><button type="button" className={control} disabled={busy} onClick={() => setRefresh(value => value + 1)}>重新核验</button></header>
    {!data && snapshot && <button type="button" className={control} onClick={() => { setSnapshot(''); setSnapshotDraft(''); syncUrl({ a_snapshot: '', a_focus: '' }); }}>返回终态核验</button>}{busy && <p role="status" className="rounded-lg bg-slate-100 p-4 text-sm">正在核验并读取当前视图…</p>}{error && <p role="alert" className="break-words rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">{error} {!data && '可信结果已清除，请核查权限、来源与产物后重新核验。'}</p>}
    {data && <><div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-950"><p>{(data.metadata.synthetic ?? data.metadata.data?.analysis?.synthetic) === true ? '合成软件验证' : '真实来源声明，适用性未验证'} · {snapshot ? `历史快照 ${snapshot}` : '终态观测'}</p><p className="mt-1">协议响应不证明物理成功；候选关系不证明因果或攻击。未知原因、支持和反证保留在记录中。</p></div>
      {data.replay && <form className="flex flex-wrap items-end gap-2" onSubmit={event => { event.preventDefault(); if (snapshotDraft && (!/^\d+$/.test(snapshotDraft) || (data.metadata.final_snapshot_number != null && Number(snapshotDraft) > data.metadata.final_snapshot_number))) { setError('快照编号超出历史范围。'); return; } setSnapshot(snapshotDraft); syncUrl({ a_snapshot: snapshotDraft, a_focus: '' }); }}><label className="text-sm">历史快照（空白查看终态）<input className={control + ' ml-2 w-28'} name="analysis-snapshot" autoComplete="off" type="number" min="0" max={data.metadata.final_snapshot_number} value={snapshotDraft} onChange={event => setSnapshotDraft(event.target.value)} /></label><button className={control} type="submit">读取快照</button><span className="text-xs text-slate-500">终态编号 {data.metadata.final_snapshot_number ?? '见历史核查'}</span></form>}
      <a className={control + ' inline-block text-teal-800'} href={data.replay ? `/replay/?run=${encodeURIComponent(runId)}` : `/dual-source/?backend=v3&run=${encodeURIComponent(runId)}`}>完整分页核查与受控下载 →</a>
      <form onSubmit={apply} className={panel} aria-label="分析筛选"><div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <label className="space-y-1 text-xs text-slate-600"><span>记录、端点、资产或标签</span><input className={control + ' w-full'} name="analysis-query" autoComplete="off" spellCheck={false} placeholder="例如 P101…" value={draft.text} onChange={event => setDraft({ ...draft, text: event.target.value })} /></label>
        <label className="space-y-1 text-xs text-slate-600"><span>观测类型</span><select className={control + ' w-full'} value={draft.kind} onChange={event => setDraft({ ...draft, kind: event.target.value })}><option value="">全部类型</option><option value="operation">网络操作</option><option value="change">过程变化</option><option value="candidate">候选关联</option></select></label>
        <label className="space-y-1 text-xs text-slate-600"><span>判断状态</span><select className={control + ' w-full'} value={draft.state} onChange={event => setDraft({ ...draft, state: event.target.value })}><option value="">全部状态</option>{states.map(state => <option key={state}>{state}</option>)}</select></label>
        <label className="space-y-1 text-xs text-slate-600"><span>开始时间（浏览器本地时区）</span><input name="analysis-from" autoComplete="off" type="datetime-local" step="1" className={control + ' w-full'} value={draft.from} onChange={event => setDraft({ ...draft, from: event.target.value })} /></label>
        <label className="space-y-1 text-xs text-slate-600"><span>结束时间（浏览器本地时区）</span><input name="analysis-to" autoComplete="off" type="datetime-local" step="1" className={control + ' w-full'} value={draft.to} onChange={event => setDraft({ ...draft, to: event.target.value })} /></label>
      </div><div className="flex flex-wrap items-center gap-2"><button type="submit" className={control + ' border-teal-700 text-teal-900'}>应用筛选</button><button type="button" className={control} onClick={() => { setDraft(EMPTY_FILTER); setFilter(EMPTY_FILTER); setTimelinePage(0); setCandidatePage(0); setNodePage(0); setGroupPage(0); syncUrl({ a_kind: '', a_state: '' }); }}>清除筛选</button><button type="button" className={control} onClick={() => { setLarge(value => !value); setTimelinePage(0); setCandidatePage(0); setNodePage(0); }}>{large ? '恢复概览 200 / 600' : '扩展视图 1000 / 3000'}</button></div><p className="text-xs text-slate-500">筛选与聚合针对已读取范围；未知时间不纳入有限时间筛选。自由文本与时间筛选只保存在当前页面，不写入地址。</p></form>
      <section className={panel} aria-label="关系图"><div className="flex flex-wrap justify-between gap-2"><h3 className="font-semibold">观测关系图</h3><p className="text-xs tabular-nums" aria-live="polite">显示 {graph.nodes.length} / {data.totals.nodes} 个节点 · {graph.edges.length} / {data.totals.edges} 条连线</p></div><p className="text-xs text-slate-600" data-testid="analysis-clipping">已读取节点 {data.nodes.length} / {data.totals.nodes}、连线 {data.edges.length} / {data.totals.edges}；图外或因筛选隐藏的连线不会显示。{(['nodes', 'edges', 'operations', 'changes', 'candidates'] as const).some(key => data[key].length < data.totals[key]) ? '当前为局部视图，不代表完整结果；可扩展视图，更多记录请使用完整核查入口。' : '本次读取范围内的记录已完整载入。'}</p>
        <Graph nodes={graph.nodes} edges={graph.edges} labels={nodeLabels} selectedIds={selectedIds} inspect={node => void inspect(relatedSelection(node, data.operations, data.changes))} />
        <details><summary className="cursor-pointer rounded text-sm text-teal-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal-700">节点列表（键盘选择）</summary><div className="mt-3 max-h-96 space-y-2 overflow-auto pr-1">{slice(graph.nodes, nodePage).map(node => <button type="button" key={node.id} className={control + ' block w-full break-all text-left'} onClick={() => void inspect(relatedSelection(node, data.operations, data.changes))}>{node.kind} · {node.event_id ?? node.id}</button>)}<Pager page={nodePage} count={graph.nodes.length} change={setNodePage} /></div></details>
      </section>
      <div className="grid items-start gap-4 xl:grid-cols-2"><section className={panel} aria-label="联动时间线"><div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">时间线</h3><span className="text-xs">操作 {data.operations.length}/{data.totals.operations} · 变化 {data.changes.length}/{data.totals.changes}</span></div><ol className="max-h-[32rem] space-y-2 overflow-auto pr-1">{slice(timeline, timelinePage).map(row => <li key={idOf(row)}><button type="button" aria-pressed={selectedIds.has(idOf(row))} className={control + ' w-full border-l-4 text-left ' + (selectedIds.has(idOf(row)) ? 'border-amber-600 bg-amber-50' : kindOf(row) === 'operation' ? 'border-l-teal-700' : 'border-l-blue-600')} onClick={() => void inspect({ kind: kindOf(row) as Selection['kind'], id: idOf(row) })}><span className="block text-xs tabular-nums">{timeText(row)}</span><span className="mt-1 block break-words">{row.operation ?? row.result?.tag ?? '过程变化'} · {stateOf(row)}</span><span className="mt-1 block break-all font-mono text-[10px] text-slate-500">{idOf(row)}</span></button></li>)}</ol>{!timeline.length && <p className="py-6 text-sm text-slate-500">当前范围没有符合筛选的操作或变化。</p>}<Pager page={timelinePage} count={timeline.length} change={setTimelinePage} /></section>
        <section className={panel} aria-label="联动候选"><div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">候选、支持与反证</h3><span className="text-xs">已读取 {data.candidates.length}/{data.totals.candidates}</span></div><ul className="max-h-[32rem] space-y-2 overflow-auto pr-1">{slice(candidates, candidatePage).map(row => <li key={idOf(row)}><button type="button" aria-pressed={selection?.id === idOf(row)} className={control + ' w-full break-words text-left ' + (selectedIds.has(idOf(row)) ? 'border-amber-600 bg-amber-50' : '')} onClick={() => void inspect({ kind: 'candidate', id: idOf(row) })}><span className="block">{stateOf(row)} · 规则 {row.rule_id ?? '未知'} / {row.rule_version ?? '未知版本'}</span><span className="mt-1 block break-all font-mono text-[10px] text-slate-500">{idOf(row)}</span><span className="mt-1 block text-xs">支持 {row.support?.length ?? 0} · 反证 {row.counterevidence?.length ?? 0} · 未知 {row.unknown_reasons?.length ?? 0}</span></button></li>)}</ul>{!candidates.length && <p className="py-6 text-sm text-slate-500">当前范围没有符合筛选的候选。</p>}<Pager page={candidatePage} count={candidates.length} change={setCandidatePage} /></section></div>
      <section className={panel} aria-label="范围内聚合"><div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">当前筛选范围聚合</h3><label className="text-sm">聚合维度<select className={control + ' ml-2'} value={dimension} onChange={event => { const value = event.target.value as typeof dimension; setDimension(value); setGroupPage(0); syncUrl({ a_group: value }); }}><option value="state">判断状态</option><option value="asset">资产</option><option value="minute">分钟（UTC）</option></select></label></div><table className="w-full table-fixed text-sm"><caption className="pb-2 text-left text-xs text-slate-500">只统计已载入且符合筛选的操作与变化，共 {timeline.length} 项。</caption><thead><tr className="border-b text-left"><th className="py-2">分组</th><th className="w-24 py-2 text-right">数量</th></tr></thead><tbody>{slice(groups, groupPage).map(group => <tr key={group.key} className="border-b border-slate-100"><td className="break-words py-2">{group.key}</td><td className="py-2 text-right tabular-nums">{group.count}</td></tr>)}</tbody></table>{!groups.length && <p className="text-sm text-slate-500">没有可聚合的记录。</p>}<Pager page={groupPage} count={groups.length} change={setGroupPage} /></section>
      <section className={panel} aria-label="联动原始证据" aria-busy={evidenceBusy}><h3 className="font-semibold">选中项与原始证据</h3>{!selection && <p className="py-4 text-sm text-slate-500">选择图节点、时间线记录或候选，查看其原始证据。</p>}{selection && <><p className="break-all font-mono text-xs">{selection.kind} · {selection.id}</p>{selected && <><p className="text-sm break-words">状态：{stateOf(selected)} · 规则 {selected.rule_id ?? selected.mapping?.rule_ids?.join('、') ?? '不适用'} / {selected.rule_version ?? selected.mapping?.config_version ?? '未知版本'}</p><p className="text-sm">时间：{timeText(selected)}</p>{selected.candidate_id && <div className="flex flex-wrap gap-2"><button className={control} type="button" onClick={() => void inspect({ kind: 'operation', id: selected.operation_id })}>查看关联网络操作</button><button className={control} type="button" onClick={() => void inspect({ kind: 'change', id: selected.change_id })}>查看关联过程变化</button></div>}<p className="text-sm break-words">未知原因：{selected.unknown_reasons?.join('、') || '见完整记录'}；支持 {selected.support?.length ?? 0}，反证 {selected.counterevidence?.length ?? 0}。</p><JsonDetails value={selected} label="完整观测、支持、反证与未知原因" /></>}{selection.kind === 'node' && <p className="text-sm text-slate-600">当前已读取范围没有关联的操作或变化。上方记录包含来源引用；尚未核验其原始内容，请使用完整分页核查定位相关操作。</p>}{evidenceBusy && <p role="status" className="text-sm">正在核验原始记录…</p>}{evidence && <><p className="text-sm" aria-live="polite">已核验原始记录：本页 {evidence.verified_original_evidence?.length ?? 0} 条{evidence.evidence_page ? ` / 共 ${evidence.evidence_page.total} 条` : ''}</p><JsonDetails value={{ selection: evidence.selection, time_configuration: evidence.time_configuration, source_ranges: evidence.source_ranges, quality: evidence.quality, config_version: evidence.config_version, config_fingerprint: evidence.config_fingerprint, limitations: evidence.limitations }} label="时间依据、配置版本与质量说明" /><div className="space-y-2">{(evidence.verified_original_evidence ?? []).slice(0, 25).map((row: Row, index: number) => <div className="rounded border border-slate-200 p-3" key={index}><p className="mb-2 break-all text-xs">文件 SHA-256：{row.source_ref?.file_sha256 ?? '未提供'} · 帧 {row.source_ref?.frame_number ?? '—'} · 记录 {row.source_ref?.record_number ?? '—'} · 列 {row.source_ref?.column ?? '—'}</p><JsonDetails value={row} label={`原始记录 ${(evidence.evidence_page?.offset ?? 0) + index + 1}`} /></div>)}</div>{evidence.evidence_page && <div className="flex flex-wrap gap-2"><button className={control} type="button" disabled={!evidence.evidence_page.offset} onClick={() => void inspect(selection, Math.max(0, evidence.evidence_page.offset - 25))}>上一页原始证据</button><button className={control} type="button" disabled={!evidence.evidence_page.has_more} onClick={() => void inspect(selection, evidence.evidence_page.offset + evidence.evidence_page.returned)}>下一页原始证据</button></div>}{!evidence.evidence_page && (evidence.verified_original_evidence?.length ?? 0) > 25 && <p className="text-sm text-slate-600">旧接口返回超过 25 条原始记录，此处展示前 25 条；完整核查请使用核查入口。</p>}</>}</>}</section>
      <p className="text-xs text-slate-500">当前视图的裁剪与聚合不会修改保存的观测；完整结果可通过核查入口分页读取。</p>
    </>}
  </section>;
}
