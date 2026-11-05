import React, { useEffect, useMemo, useRef, useState } from 'react';
import { aggregate, boundedGraph, EMPTY_FILTER, Filter, idOf, intervalOf, LIMITS, filterAnalysisRows, groupMembers, relatedSelection, Row, Selection, selectionInView, stateOf } from './analysisModel';
import { AggregatePane } from './analysis/AggregatePane';
import { Graph } from './analysis/AnalysisGraph';
import { CandidateList, TimelineList } from './analysis/AnalysisLists';
import { AnalysisToolbar } from './analysis/AnalysisToolbar';
import { EvidenceInspector } from './analysis/EvidenceInspector';
import { control, DataNatureBar, Pager } from './analysis/widgets';

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
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null), [memberPage, setMemberPage] = useState(0);
  const groupRegionId = React.useId();
  const generation = useRef(0), evidenceGeneration = useRef(0), errorHandler = useRef(onError), evidenceAbort = useRef<AbortController | null>(null);
  errorHandler.current = onError;
  const base = `/api/v3/runs/${encodeURIComponent(runId)}`;
  function clearSelection() {
    evidenceGeneration.current++; evidenceAbort.current?.abort();
    setSelection(null); setEvidence(null); setEvidenceBusy(false);
  }
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
      if (replay && !compact) {
        const count = metadata.data?.replay?.snapshot_count;
        if (!Number.isSafeInteger(count) || count < 1 || count > 65000) throw new Error('旧回放缺少有效快照总数，无法核验终态。');
        metadata.final_snapshot_number = count - 1;
        if (snapshot && Number(snapshot) > metadata.final_snapshot_number) throw new Error('快照编号超出历史范围。');
      }
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
    const query = new URLSearchParams({ ...selector, ref_offset: String(offset), ref_limit: '25' });
    const evidenceSnapshot = data.replay ? snapshot || (!data.compact ? String(data.metadata.final_snapshot_number) : '') : '';
    if (evidenceSnapshot) query.set(data.compact ? 'snapshot' : 'revision', evidenceSnapshot);
    setEvidenceBusy(true);
    try { const value = await read(base, '/evidence?' + query, controller.signal); if (current === generation.current && ticket === evidenceGeneration.current) { if (typeof value.synthetic !== 'boolean' || value.synthetic !== (data.metadata.synthetic ?? data.metadata.data?.analysis?.synthetic)) throw new Error('原始证据来源标记与当前结果不一致。'); setEvidence(value); } }
    catch (reason) { if (current === generation.current && ticket === evidenceGeneration.current && !controller.signal.aborted) fail(reason); }
    finally { if (current === generation.current && ticket === evidenceGeneration.current) setEvidenceBusy(false); }
  }
  const rows = useMemo(() => data ? [...data.operations, ...data.changes] : [], [data]);
  const projection = useMemo(() => filterAnalysisRows(data?.operations ?? [], data?.changes ?? [], data?.candidates ?? [], filter), [data, filter]);
  const timeline = useMemo(() => [...projection.timeline].sort((a, b) => (intervalOf(a)?.[0] ?? Infinity) - (intervalOf(b)?.[0] ?? Infinity) || idOf(a).localeCompare(idOf(b))), [projection]);
  const candidates = projection.candidates;
  const graph = useMemo(() => boundedGraph(data?.nodes ?? [], data?.edges ?? [], [...rows, ...(data?.candidates ?? [])], filter, large ? LIMITS.nodes : 200, large ? LIMITS.edges : 600, projection), [data, rows, filter, large, projection]);
  const groups = useMemo(() => aggregate(timeline, dimension), [timeline, dimension]);
  const members = useMemo(() => expandedGroup === null ? [] : groupMembers(timeline, dimension, expandedGroup), [timeline, dimension, expandedGroup]);
  useEffect(() => { setExpandedGroup(null); setMemberPage(0); }, [filter, dimension, data]);
  useEffect(() => {
    if (selection && !selectionInView(selection, timeline, candidates, graph.nodes)) clearSelection();
    // Revalidate an existing selection only when the filter/read scope changes.
    // New clicks may inspect a candidate's legitimate graph endpoint context.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, large, filter.text, filter.kind, filter.state, filter.from, filter.to]);
  function changeFilter(next: Filter) {
    const changed = (Object.keys(EMPTY_FILTER) as (keyof Filter)[]).some(key => next[key] !== filter[key]);
    if (changed && selection && data) {
      const nextRows = filterAnalysisRows(data.operations, data.changes, data.candidates, next);
      const nextGraph = boundedGraph(data.nodes, data.edges, [...data.operations, ...data.changes, ...data.candidates], next, large ? LIMITS.nodes : 200, large ? LIMITS.edges : 600, nextRows);
      // Invalidate the request synchronously, before a late response can publish.
      if (!selectionInView(selection, nextRows.timeline, nextRows.candidates, nextGraph.nodes)) clearSelection();
    }
    setFilter(next); setTimelinePage(0); setCandidatePage(0); setNodePage(0); setGroupPage(0); setExpandedGroup(null); setMemberPage(0);
  }

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
    changeFilter(draft); setError(''); syncUrl({ a_kind: draft.kind, a_state: draft.state });
  }
  const slice = (values: Row[], page: number) => values.slice(page * LIMITS.page, (page + 1) * LIMITS.page);
  const synthetic = data ? (data.metadata.synthetic ?? data.metadata.data?.analysis?.synthetic) === true : false;
  return <section aria-label="分析工作区" className="wb-analysis" data-testid="analysis-workspace">
    <AnalysisToolbar
      draft={draft}
      setDraft={setDraft}
      states={states}
      busy={busy}
      large={large}
      selectionCount={selection ? 1 : 0}
      replay={Boolean(data?.replay)}
      snapshotDraft={snapshotDraft}
      setSnapshotDraft={setSnapshotDraft}
      finalSnapshot={data?.metadata.final_snapshot_number}
      onApply={apply}
      onClearFilter={() => { setDraft(EMPTY_FILTER); changeFilter(EMPTY_FILTER); syncUrl({ a_kind: '', a_state: '' }); }}
      onToggleLarge={() => { setLarge(value => !value); setTimelinePage(0); setCandidatePage(0); setNodePage(0); }}
      onRefresh={() => setRefresh(value => value + 1)}
      onClearSelection={clearSelection}
      onReadSnapshot={event => { event.preventDefault(); if (snapshotDraft && (!/^\d+$/.test(snapshotDraft) || (data?.metadata.final_snapshot_number != null && Number(snapshotDraft) > data.metadata.final_snapshot_number))) { setError('快照编号超出历史范围。'); return; } setSnapshot(snapshotDraft); syncUrl({ a_snapshot: snapshotDraft, a_focus: '' }); }}
      verifyHref={data ? (data.replay ? `/replay/?run=${encodeURIComponent(runId)}` : `/dual-source/?backend=v3&run=${encodeURIComponent(runId)}`) : undefined}
    />
    {!data && snapshot && <button type="button" className={control} onClick={() => { setSnapshot(''); setSnapshotDraft(''); syncUrl({ a_snapshot: '', a_focus: '' }); }}>返回终态核验</button>}
    {busy && <p role="status" className="rounded-lg bg-slate-100 p-4 text-sm">正在核验并读取当前视图…</p>}
    {error && <p role="alert" className="break-words rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">{error} {!data && '可信结果已清除，请核查权限、来源与产物后重新核验。'}</p>}
    {data && <>
      <DataNatureBar>
        <p>{synthetic ? '合成软件验证' : '真实来源声明，适用性未验证'} · {snapshot ? `历史快照 ${snapshot}` : '终态观测'}</p>
        <p>协议响应不证明物理成功；候选关系不证明因果或攻击。未知原因、支持和反证保留在记录中。</p>
      </DataNatureBar>
      <div className="wb-analysis-grid">
        <div className="wb-analysis-stage">
          <section className="wb-card space-y-3" aria-label="关系图">
            <div className="flex flex-wrap justify-between gap-2"><h3 className="font-semibold">观测关系图</h3><p className="text-xs tabular-nums" aria-live="polite">显示 {graph.nodes.length} / {data.totals.nodes} 个节点 · {graph.edges.length} / {data.totals.edges} 条连线</p></div>
            <p className="text-xs text-slate-600" data-testid="analysis-clipping">已读取节点 {data.nodes.length} / {data.totals.nodes}、连线 {data.edges.length} / {data.totals.edges}；图外或因筛选隐藏的连线不会显示。{(['nodes', 'edges', 'operations', 'changes', 'candidates'] as const).some(key => data[key].length < data.totals[key]) ? '当前为局部视图，不代表完整结果；可扩展视图，更多记录请使用完整核查入口。' : '本次读取范围内的记录已完整载入。'}</p>
            <Graph nodes={graph.nodes} edges={graph.edges} labels={nodeLabels} selectedIds={selectedIds} inspect={node => void inspect(relatedSelection(node, data.operations, data.changes))} />
            <details><summary className="wb-link cursor-pointer rounded text-sm">节点列表（键盘选择）</summary><div className="mt-3 max-h-96 space-y-2 overflow-auto pr-1">{slice(graph.nodes, nodePage).map(node => <button type="button" key={node.id} className={control + ' block w-full break-all text-left'} onClick={() => void inspect(relatedSelection(node, data.operations, data.changes))}>{node.kind} · {node.event_id ?? node.id}</button>)}<Pager page={nodePage} count={graph.nodes.length} change={setNodePage} /></div></details>
          </section>
          <div className="wb-analysis-lists">
            <TimelineList rows={slice(timeline, timelinePage)} page={timelinePage} count={timeline.length} meta={`操作 ${data.operations.length}/${data.totals.operations} · 变化 ${data.changes.length}/${data.totals.changes}`} selectedIds={selectedIds} onInspect={next => void inspect(next)} onPage={setTimelinePage} />
            <CandidateList rows={slice(candidates, candidatePage)} page={candidatePage} count={candidates.length} totalLabel={`已读取 ${data.candidates.length}/${data.totals.candidates}`} selectedIds={selectedIds} selectionId={selection?.id} onInspect={next => void inspect(next)} onPage={setCandidatePage} />
          </div>
        </div>
        <EvidenceInspector selection={selection} selected={selected} evidence={evidence} evidenceBusy={evidenceBusy} onInspect={(next, offset) => void inspect(next, offset)} onClear={clearSelection} />
      </div>
      <AggregatePane
        groups={groups}
        dimension={dimension}
        timelineCount={timeline.length}
        expandedGroup={expandedGroup}
        members={members}
        memberPage={memberPage}
        groupPage={groupPage}
        groupRegionId={groupRegionId}
        selection={selection}
        onDimension={value => { setDimension(value); setGroupPage(0); syncUrl({ a_group: value }); }}
        onToggleGroup={key => { setExpandedGroup(key); setMemberPage(0); }}
        onMemberPage={setMemberPage}
        onGroupPage={page => { setGroupPage(page); setExpandedGroup(null); setMemberPage(0); }}
        onInspect={next => void inspect(next)}
      />
      <p className="text-xs text-slate-500">当前视图的裁剪与聚合不会修改保存的观测；完整结果可通过核查入口分页读取。</p>
    </>}
  </section>;
}
