import React, { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';

const API = '/api/v2/cpag';
type Json = Record<string, any>;
type Selection = { kind: 'operation' | 'change' | 'candidate'; id: string; operationId?: string };

class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function request(path: string, init?: RequestInit): Promise<Json> {
  const response = await fetch(API + path, init);
  const text = await response.text();
  let value: any;
  try { value = JSON.parse(text); } catch { value = { detail: text }; }
  if (!response.ok) {
    const detail = value?.detail ?? value?.error ?? response.statusText;
    throw new ApiError(response.status, typeof detail === 'string' ? detail : JSON.stringify(detail));
  }
  return value;
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return `${error.status}：${error.message}`;
  return error instanceof Error ? error.message : String(error);
}

function timeLabel(interval?: number[] | null): string {
  if (!interval || interval.length !== 2) return '时间依据不足';
  return interval.map(value => Number.isFinite(value) ? new Date(value * 1000).toISOString() : '未知').join(' — ');
}

function ReasonList({ values, empty = '无' }: { values?: any[]; empty?: string }) {
  return values?.length ? <ul className="list-disc pl-5 break-words">{values.map((value, index) => <li key={index}>{typeof value === 'string' ? value : JSON.stringify(value)}</li>)}</ul> : <span className="text-slate-500">{empty}</span>;
}

function RawReference({ value }: { value: Json }) {
  return <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 break-all">
    <dl className="grid gap-x-3 gap-y-1 sm:grid-cols-[8rem_1fr] text-xs">
      <dt className="font-medium">文件 SHA-256</dt><dd>{value.file_sha256 ?? '未知'}</dd>
      <dt className="font-medium">帧号</dt><dd>{value.frame_number ?? '—'}</dd>
      <dt className="font-medium">记录号</dt><dd>{value.record_number ?? '—'}</dd>
      <dt className="font-medium">列名</dt><dd>{value.column ?? '—'}</dd>
      <dt className="font-medium">原始时间</dt><dd>{value.raw_time == null ? '—' : String(value.raw_time)}</dd>
    </dl>
  </div>;
}

function GraphCanvas({ graph, inspect, operations, changes }: { graph: Json; inspect: (selection: Selection) => void; operations: Json[]; changes: Json[] }) {
  const nodes = (graph.nodes ?? []) as Json[];
  const edges = (graph.edges ?? []) as Json[];
  const left = nodes.filter(node => operations.some(op => op.operation_id === node.event_id));
  const right = nodes.filter(node => changes.some(change => change.event_id === node.event_id));
  const known = new Set([...left, ...right].map(node => node.id));
  const other = nodes.filter(node => !known.has(node.id));
  const positioned = [...left.map((node, index) => ({ node, x: 120, y: 55 + index * 88 })),
    ...right.map((node, index) => ({ node, x: 660, y: 55 + index * 88 })),
    ...other.map((node, index) => ({ node, x: 390, y: 55 + index * 88 }))];
  const points = new Map(positioned.map(item => [item.node.id, item]));
  const height = Math.max(160, 100 + Math.max(left.length, right.length, other.length) * 88);
  const selectNode = (node: Json) => {
    const operation = operations.find(op => op.operation_id === node.event_id || op.response?.event_id === node.event_id);
    const change = changes.find(item => item.event_id === node.event_id || [item.result?.before_event_id, item.result?.after_event_id].includes(node.event_id));
    if (operation) inspect({ kind: 'operation', id: operation.operation_id });
    else if (change) inspect({ kind: 'change', id: change.event_id });
  };
  return <div className="overflow-auto rounded-xl border border-slate-200 bg-slate-50"><svg viewBox={`0 0 780 ${height}`} className="min-w-[780px] w-full" role="img" aria-label="双源关系图：左侧网络操作，右侧过程变化；连线为假设性关联候选">
    <text x="35" y="24" className="fill-slate-600 text-xs">网络操作</text><text x="585" y="24" className="fill-slate-600 text-xs">过程变化</text>
    {edges.map(edge => { const source = points.get(edge.source), target = points.get(edge.target); if (!source || !target) return null;
      const action = () => inspect({ kind: 'candidate', id: edge.claim_id ?? edge.id, operationId: source.node.event_id });
      return <g key={edge.id} role="button" tabIndex={0} aria-label={`查看候选连线 ${edge.claim_id ?? edge.id}，状态 ${edge.candidate_state ?? '未知'}`} onClick={action} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); action(); } }} className="cursor-pointer focus:outline-none">
        <line x1={source.x + 75} y1={source.y} x2={target.x - 75} y2={target.y} stroke="#d97706" strokeWidth="3" />
        <line x1={source.x + 75} y1={source.y} x2={target.x - 75} y2={target.y} stroke="transparent" strokeWidth="24" />
        <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 7} textAnchor="middle" className="fill-amber-900 text-[10px]">{edge.candidate_state ?? '假设'}</text>
      </g>;
    })}
    {positioned.map(({ node, x, y }) => { const actionable = operations.some(op => op.operation_id === node.event_id || op.response?.event_id === node.event_id) || changes.some(change => change.event_id === node.event_id || [change.result?.before_event_id, change.result?.after_event_id].includes(node.event_id));
      return <g key={node.id} role={actionable ? 'button' : undefined} tabIndex={actionable ? 0 : undefined} aria-label={`查看${node.kind}节点 ${node.event_id}`} onClick={() => selectNode(node)} onKeyDown={event => { if (actionable && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); selectNode(node); } }} className={actionable ? 'cursor-pointer' : ''}>
        <rect x={x - 75} y={y - 24} width="150" height="48" rx="9" fill={node.kind === 'network' ? '#d1fae5' : '#dbeafe'} stroke={node.kind === 'network' ? '#10b981' : '#3b82f6'} />
        <text x={x} y={y - 3} textAnchor="middle" className="fill-slate-800 text-xs">{node.kind}</text>
        <text x={x} y={y + 13} textAnchor="middle" className="fill-slate-600 text-[9px]">{String(node.event_id).slice(0, 19)}…</text>
      </g>;
    })}
  </svg></div>;
}

export default function DualSourcePage() {
  const [files, setFiles] = useState<Record<string, File>>({});
  const [confirmed, setConfirmed] = useState(false);
  const [lookupId, setLookupId] = useState('');
  const [taskId, setTaskId] = useState('');
  const [task, setTask] = useState<Json | null>(null);
  const [result, setResult] = useState<Json | null>(null);
  const [artifacts, setArtifacts] = useState<Json | null>(null);
  const [evidence, setEvidence] = useState<Json | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const activeTask = useRef('');
  const taskGeneration = useRef(0);
  const evidenceSequence = useRef(0);
  const analysis = result?.data?.analysis as Json | undefined;

  const clearPublished = useCallback(() => {
    setResult(null); setArtifacts(null); setEvidence(null); setSelection(null);
  }, []);
  const handleError = useCallback((reason: unknown) => {
    if (reason instanceof ApiError && reason.status === 409) {
      taskGeneration.current += 1;
      evidenceSequence.current += 1;
      clearPublished();
      setEvidenceBusy(false);
    }
    setError(errorMessage(reason));
  }, [clearPublished]);

  const refresh = useCallback(async (id: string) => {
    const generation = taskGeneration.current;
    try {
      const status = await request(`/status/${encodeURIComponent(id)}`);
      if (activeTask.current !== id || taskGeneration.current !== generation) return;
      setTask(status);
      if (status.status === 'completed') {
        const [output, inventory] = await Promise.all([
          request(`/result/${encodeURIComponent(id)}/json`),
          request(`/artifacts/${encodeURIComponent(id)}`),
        ]);
        if (activeTask.current !== id || taskGeneration.current !== generation) return;
        if (output?.data?.analysis?.synthetic !== true || output?.task_kind !== 'synthetic_dual_source') {
          clearPublished();
          throw new Error('该任务不是合成双源验证结果。');
        }
        setResult(output); setArtifacts(inventory); setError('');
      } else {
        clearPublished();
        if (status.status === 'failed') setError(`任务失败：${status.error ?? '原因未提供'}`);
        else setError('');
      }
    } catch (reason) { if (activeTask.current === id && taskGeneration.current === generation) handleError(reason); }
  }, [clearPublished, handleError]);

  useEffect(() => {
    if (!taskId) return;
    void refresh(taskId);
    if (['completed', 'failed'].includes(task?.status)) return;
    const timer = window.setInterval(() => void refresh(taskId), 2000);
    return () => window.clearInterval(timer);
  }, [taskId, task?.status, refresh]);

  async function submit() {
    const generation = ++taskGeneration.current;
    activeTask.current = '';
    evidenceSequence.current += 1;
    setBusy(true); setError(''); clearPublished(); setTask(null); setTaskId('');
    try {
      const body = new FormData();
      for (const field of ['network_file', 'process_file', 'profile_file']) body.append(field, files[field]);
      body.append('synthetic_confirmed', 'true');
      const created = await request('/dual-source', { method: 'POST', body });
      if (taskGeneration.current !== generation) return;
      const id = created.id ?? created.task_id;
      if (!id) throw new Error('服务器未返回任务 ID。');
      activeTask.current = id;
      setTask(created); setTaskId(id); setLookupId(id);
    } catch (reason) { if (taskGeneration.current === generation) handleError(reason); }
    finally { if (taskGeneration.current === generation) setBusy(false); }
  }

  function openTask() {
    const id = lookupId.trim();
    if (!id) return;
    activeTask.current = id;
    taskGeneration.current += 1;
    evidenceSequence.current += 1;
    clearPublished(); setTask(null); setError(''); setTaskId(id);
    if (id === taskId) void refresh(id);
  }

  async function inspect(next: Selection) {
    if (!taskId) return;
    const idAtStart = taskId;
    const sequence = ++evidenceSequence.current;
    setSelection(next); setEvidence(null); setEvidenceBusy(true); setError('');
    const key = next.kind === 'change' ? 'change' : 'operation';
    const id = next.kind === 'candidate' ? next.operationId : next.id;
    try {
      const value = await request(`/dual-source/${encodeURIComponent(taskId)}/evidence?${key}=${encodeURIComponent(id ?? '')}`);
      if (activeTask.current === idAtStart && evidenceSequence.current === sequence) setEvidence(value);
    } catch (reason) { if (activeTask.current === idAtStart && evidenceSequence.current === sequence) handleError(reason); }
    finally { if (activeTask.current === idAtStart && evidenceSequence.current === sequence) setEvidenceBusy(false); }
  }

  async function download(filename: string) {
    if (!taskId) return;
    const idAtStart = taskId;
    try {
      const response = await fetch(`${API}/download/${encodeURIComponent(taskId)}/${encodeURIComponent(filename)}`);
      if (!response.ok) {
        let detail = await response.text();
        try { detail = JSON.parse(detail)?.detail ?? detail; } catch { /* retain response text */ }
        throw new ApiError(response.status, detail);
      }
      if (activeTask.current !== idAtStart) return;
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (reason) { if (activeTask.current === idAtStart) handleError(reason); }
  }

  const operations = (analysis?.operations ?? []) as Json[];
  const changes = (analysis?.changes ?? []) as Json[];
  const candidates = (analysis?.candidates ?? []) as Json[];
  const graph = result?.data?.graph as Json | undefined;
  const timeline = [
    { label: '网络操作', items: (analysis?.network ?? []).map((row: Json) => ({ id: row.event?.event_id, interval: row.time?.interval, detail: `${row.observation?.operation ?? '网络事件'} · ${row.observation?.direction ?? '方向未知'}`, selection: operations.find(op => op.operation_id === row.event?.event_id || op.response?.event_id === row.event?.event_id) })) },
    { label: '过程采样', items: (analysis?.process ?? []).map((row: Json) => ({ id: row.event?.event_id, interval: row.time?.interval, detail: `${row.event?.asset_id ?? '资产未知'} / ${row.event?.tag ?? '标签未知'} = ${row.event?.value ?? '缺失'}`, selection: changes.find(change => [change.result?.before_event_id, change.result?.after_event_id].includes(row.event?.event_id)) })) },
  ];

  return <div className="min-h-screen bg-gradient-to-br from-slate-50 via-emerald-50 to-teal-50 text-slate-800">
    <header className="bg-white/90 border-b border-slate-200 shadow-sm"><div className="max-w-7xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-3">
      <div><h1 className="text-2xl font-bold">合成双源验证</h1><p className="text-sm text-slate-500">网络报文与过程采样的可核查关联候选</p></div>
      <Link href="/" className="rounded-xl px-4 py-2 bg-emerald-100 text-emerald-900 hover:bg-emerald-200">返回 CPAG 首页</Link>
    </div></header>
    <main className="max-w-7xl mx-auto p-6 space-y-6">
      <section className="rounded-2xl border border-amber-300 bg-amber-50 p-5 text-amber-950" aria-label="合成验证范围">
        <strong>仅限合成验证。</strong> 这里展示观测事实与假设性关联候选，不作因果、攻击识别或物理动作成功判断。协议成功响应仅表示协议服务响应成功；端点地址不证明操作主体。时间偏移由配置提供，采样间隔不能确定动作发生时刻。
      </section>
      <section className="bg-white/80 rounded-2xl shadow-xl border border-slate-200 p-6 space-y-4" aria-label="提交合成双源任务">
        <h2 className="text-xl font-semibold">提交合成测试输入</h2>
        <div className="grid md:grid-cols-3 gap-4">{([
          ['network_file', '网络原始报文', '.pcap,.pcapng'], ['process_file', '过程采样 CSV', '.csv'], ['profile_file', '合成配置 JSON', '.json'],
        ] as const).map(([field, label, accept]) => <label key={field} className="text-sm font-medium">{label}<input type="file" aria-label={label} accept={accept} className="block mt-2 w-full text-sm" onChange={event => {
          const file = event.target.files?.[0]; setFiles(old => { const next = { ...old }; if (file) next[field] = file; else delete next[field]; return next; });
        }} /></label>)}</div>
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} /><span>我确认三份输入均为合成测试数据，配置文件声明 synthetic=true。</span></label>
        <button type="button" disabled={busy || !confirmed || !['network_file', 'process_file', 'profile_file'].every(field => files[field])} onClick={submit} className="rounded-xl px-5 py-3 bg-emerald-700 text-white disabled:bg-slate-300">{busy ? '提交中…' : '运行合成双源验证'}</button>
      </section>
      <section className="bg-white/80 rounded-2xl shadow-xl border border-slate-200 p-6 space-y-3" aria-label="打开已有任务">
        <h2 className="text-xl font-semibold">查看已有任务</h2>
        <div className="flex flex-wrap gap-3"><input aria-label="合成双源任务 ID" value={lookupId} onChange={event => setLookupId(event.target.value)} placeholder="粘贴任务 ID" className="flex-1 min-w-60 rounded-lg border border-slate-300 px-3 py-2" /><button type="button" onClick={openTask} className="rounded-lg bg-slate-700 text-white px-4 py-2">读取任务</button><button type="button" disabled={!taskId} onClick={() => void refresh(taskId)} className="rounded-lg border border-slate-300 px-4 py-2 disabled:text-slate-400">刷新当前任务</button></div>
        {taskId && <p className="text-sm break-all">任务 ID：{taskId}</p>}
        {task && <p aria-live="polite" className="text-sm">状态：{task.status}{task.error ? ` · ${task.error}` : ''}</p>}
        {error && <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-red-700 break-words">{error}{error.startsWith('409') && ' 已清除页面上的旧结果；请核查原始文件与发布清单。'}</p>}
      </section>

      {analysis && <>
        <section className="grid sm:grid-cols-4 gap-3" aria-label="双源结果摘要">{[['网络操作', operations.length], ['过程变化', changes.length], ['关联候选', candidates.length], ['孤立过程变化', analysis.orphan_change_ids?.length ?? 0]].map(([label, count]) => <div key={label} className="bg-white rounded-xl border border-slate-200 p-4"><p className="text-sm text-slate-500">{label}</p><p className="text-2xl font-semibold">{count}</p></div>)}</section>
        <section className="bg-white/80 rounded-2xl shadow-xl border border-slate-200 p-6 space-y-4" aria-label="双源时间线"><h2 className="text-xl font-semibold">双源时间线</h2><p className="text-sm text-slate-600">各行显示配置时钟修正后的可能时间区间；区间重叠仅供比较。</p><div className="grid md:grid-cols-2 gap-4">{timeline.map(lane => <div key={lane.label} className="rounded-xl border border-slate-200 p-4"><h3 className="font-semibold mb-3">{lane.label}</h3><ol className="space-y-2 max-h-72 overflow-auto">{lane.items.length ? lane.items.map((item: Json, index: number) => <li key={item.id ?? index} className="border-l-4 border-teal-500 bg-slate-50 px-3 py-2 text-sm">{item.selection ? <button type="button" onClick={() => void inspect({ kind: lane.label === '网络操作' ? 'operation' : 'change', id: lane.label === '网络操作' ? item.selection.operation_id : item.selection.event_id })} className="w-full text-left hover:underline focus:ring-2 focus:ring-teal-500" aria-label={`查看${lane.label}证据 ${item.id}`}><span className="font-medium">{item.detail}</span><br /><span className="text-xs break-all">{timeLabel(item.interval)}</span></button> : <><span className="font-medium">{item.detail}</span><br /><span className="text-xs break-all">{timeLabel(item.interval)}</span></>}</li>) : <li className="text-sm text-slate-500">无可展示事件</li>}</ol></div>)}</div></section>
        <section className="bg-white/80 rounded-2xl shadow-xl border border-slate-200 p-6 space-y-4" aria-label="双源关联图"><h2 className="text-xl font-semibold">关联图</h2><p className="text-sm text-slate-600">选择网络操作、过程变化或候选连线以核查原始证据。所有连线均为假设。</p>{graph && <GraphCanvas graph={graph} inspect={selection => void inspect(selection)} operations={operations} changes={changes} />}<div className="grid md:grid-cols-2 gap-4"><div><h3 className="font-semibold mb-2">网络操作节点</h3><div className="space-y-2">{operations.map(op => <button type="button" key={op.operation_id} onClick={() => void inspect({ kind: 'operation', id: op.operation_id })} className="w-full text-left rounded-lg border border-emerald-300 bg-emerald-50 p-3 hover:bg-emerald-100 focus:ring-2 focus:ring-emerald-500"><span className="font-medium">{op.operation ?? '操作未知'}</span><span className="block text-xs break-all">{op.operation_id}</span><span className="block text-xs">评估：{op.assessment ?? '未知'} · 响应：{op.response?.state ?? '未知'}</span></button>)}{!operations.length && <p className="text-sm text-slate-500">无网络操作</p>}</div></div><div><h3 className="font-semibold mb-2">过程变化节点</h3><div className="space-y-2">{changes.map(change => <button type="button" key={change.event_id} onClick={() => void inspect({ kind: 'change', id: change.event_id })} className="w-full text-left rounded-lg border border-blue-300 bg-blue-50 p-3 hover:bg-blue-100 focus:ring-2 focus:ring-blue-500"><span className="font-medium">{change.result?.asset_id} / {change.result?.tag}: {String(change.result?.before)} → {String(change.result?.after)}</span><span className="block text-xs break-all">{change.event_id}</span><span className="block text-xs">{timeLabel(change.result?.interval)}</span></button>)}{!changes.length && <p className="text-sm text-slate-500">无过程变化</p>}</div></div></div><div><h3 className="font-semibold mb-2">候选连线</h3><div className="space-y-2">{candidates.map(candidate => <button type="button" key={candidate.candidate_id} onClick={() => void inspect({ kind: 'candidate', id: candidate.candidate_id, operationId: candidate.operation_id })} className="w-full text-left rounded-lg border border-amber-300 bg-amber-50 p-3 hover:bg-amber-100 focus:ring-2 focus:ring-amber-500"><span className="font-medium">{candidate.state} · 假设性关联</span><span className="block text-xs break-all">{candidate.operation_id} → {candidate.change_id}</span></button>)}{!candidates.length && <p className="text-sm text-slate-500">无关联候选；查看未知原因及孤立变化。</p>}</div></div></section>
        <section className="grid lg:grid-cols-2 gap-4" aria-label="候选判断和未知原因"><div className="bg-white rounded-2xl border border-slate-200 p-6 space-y-4"><h2 className="text-xl font-semibold">候选依据与歧义</h2>{candidates.map(candidate => <article key={candidate.candidate_id} className="rounded-lg border p-3 text-sm space-y-2"><h3 className="font-semibold break-all">{candidate.state} · {candidate.candidate_id}</h3><div>支持依据：<ReasonList values={candidate.support} /></div><div>反证：<ReasonList values={candidate.counterevidence} /></div><div>未知原因：<ReasonList values={candidate.unknown_reasons} /></div><div>替代操作：<ReasonList values={candidate.alternative_operation_ids} /></div><div>替代变化：<ReasonList values={candidate.alternative_change_ids} /></div></article>)}{!candidates.length && <p className="text-sm text-slate-500">无候选依据。</p>}</div><div className="bg-white rounded-2xl border border-slate-200 p-6 space-y-4"><h2 className="text-xl font-semibold">缺失与质量原因</h2><div className="text-sm"><h3 className="font-medium">全局未知原因</h3><ReasonList values={analysis.quality?.unknown_reasons} /></div>{operations.map(op => <div key={op.operation_id} className="text-sm border-t pt-2"><p className="font-medium break-all">操作 {op.operation_id}</p><div>未知：<ReasonList values={op.unknown_reasons} /></div><div>反证：<ReasonList values={op.counterevidence} /></div></div>)}<details className="text-sm"><summary className="cursor-pointer">完整质量记录与来源区间</summary><pre className="overflow-auto text-xs bg-slate-50 p-3 mt-2">{JSON.stringify(analysis.quality, null, 2)}</pre></details></div></section>
        <section className="bg-white/80 rounded-2xl shadow-xl border border-slate-200 p-6 space-y-4" aria-label="证据核查"><h2 className="text-xl font-semibold">原始证据核查</h2>{selection ? <p className="text-sm break-all">已选择：{selection.kind} · {selection.id}</p> : <p className="text-sm text-slate-500">选择上方节点或连线。</p>}{evidenceBusy && <p aria-live="polite">正在核查原始证据…</p>}{evidence && <><p className="text-sm">核查后的原始记录：{evidence.verified_original_evidence?.length ?? 0}；核查后的网络字段：{evidence.verified_network_fields?.length ?? 0}</p><ol className="space-y-2">{(evidence.verified_original_evidence ?? []).map((entry: Json, index: number) => <li key={index} className="rounded-lg border border-slate-200 p-3"><h3 className="font-medium text-sm mb-2">原始记录 {index + 1}</h3><RawReference value={entry.source_ref ?? {}} /><details className="text-xs mt-2"><summary className="cursor-pointer">查看原始内容</summary><pre className="overflow-auto whitespace-pre-wrap break-all bg-slate-50 p-2">{JSON.stringify(entry.original, null, 2)}</pre></details></li>)}</ol><details className="text-sm"><summary className="cursor-pointer">查看核查后的网络字段</summary><pre className="overflow-auto text-xs bg-slate-50 p-3">{JSON.stringify(evidence.verified_network_fields, null, 2)}</pre></details><details className="text-sm"><summary className="cursor-pointer">查看选中项、时钟配置和局限</summary><pre className="overflow-auto text-xs bg-slate-50 p-3">{JSON.stringify({ selection: evidence.selection, time_configuration: evidence.time_configuration, limitations: evidence.limitations }, null, 2)}</pre></details></>}</section>
        {artifacts && <section className="bg-white/80 rounded-2xl shadow-xl border border-slate-200 p-6 space-y-3" aria-label="结果文件"><h2 className="text-xl font-semibold">可下载结果</h2><div className="flex flex-wrap gap-2">{(artifacts.files ?? []).map((entry: Json | string) => { const filename = typeof entry === 'string' ? entry : entry.filename; return <button type="button" key={filename} onClick={() => void download(filename)} className="rounded-lg border border-emerald-300 px-3 py-2 text-sm text-emerald-900 hover:bg-emerald-50">下载 {filename}</button>; })}</div><details className="text-sm"><summary className="cursor-pointer">查看文件清单与校验信息</summary><pre className="overflow-auto text-xs bg-slate-50 p-3">{JSON.stringify(artifacts, null, 2)}</pre></details></section>}
      </>}
    </main>
  </div>;
}
