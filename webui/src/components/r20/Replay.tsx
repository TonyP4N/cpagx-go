import React, { useEffect, useRef, useState } from 'react';
import { HistoryProps, Row, historicalBacklog, historySelection, normalizeRevisions, number, request, sharedPath, snapshotCount, time, visibleBacklog, writeHistorySelection } from './historyModel';

const labels: Row = { operations: '网络操作', changes: '工艺变化', candidates: '候选与反证' };
const statuses: Row = { pending_response: '等待响应', warming_up: '预热中', wait_process: '等待工艺窗口', closed: '窗口已关闭', normal: '当前条件满足', ambiguous: '存在歧义', unknown: '证据不足', counterevidence_present: '存在反证', late: '允许范围内迟到', too_late: '超出迟到范围，已排除', input_exhausted: '输入耗尽', clock_advanced: '时钟推进', accepted: '记录到达' };
export default function Replay({ runId, datasetId, onError }: HistoryProps) {
  const [result, setResult] = useState<Row | null>(null), [snapshot, setSnapshot] = useState<Row | null>(null);
  const [selected, setSelected] = useState('0'), [draft, setDraft] = useState('0'), [kind, setKind] = useState('operations');
  const [page, setPage] = useState<Row | null>(null), [offset, setOffset] = useState(0), [revisions, setRevisions] = useState<Row | null>(null), [revisionOffset, setRevisionOffset] = useState(0);
  const [backlog, setBacklog] = useState<Row | null>(null), [evidence, setEvidence] = useState<Row | null>(null), [evidenceSelector, setEvidenceSelector] = useState<Row | null>(null);
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [refresh, setRefresh] = useState(0);
  const epoch = useRef(0), evidenceEpoch = useRef(0), report = useRef(onError); report.current = onError;
  const base = `/runs/${encodeURIComponent(runId)}`, shared = result?.storage_format === 'shared-observation-dag-6';
  const fail = (reason: unknown) => { const message = (reason as Error).message; epoch.current++; evidenceEpoch.current++; setSnapshot(null); setPage(null); setEvidence(null); setEvidenceBusy(false); setBacklog(null); setRevisions(null); setResult(null); setBusy(false); setEvidenceBusy(false); setError(message); report.current(message); };
  useEffect(() => {
    const controller = new AbortController(); setResult(null); setSnapshot(null); setEvidence(null); setEvidenceBusy(false); setPage(null); setRevisions(null); setSelected('0'); setDraft('0'); setOffset(0); setRevisionOffset(0); setError('');
    if (!runId) return;
    request(base + '/result', controller.signal).then(value => { if (controller.signal.aborted) return; const saved = historySelection(location.search, 'snapshot', runId, datasetId); const chosen = saved && Number(saved) < snapshotCount(value) ? saved : '0'; setSelected(chosen); setDraft(chosen); setResult(value); report.current(''); }).catch(reason => { if (!controller.signal.aborted) fail(reason); });
    return () => { controller.abort(); epoch.current++; evidenceEpoch.current++; };
  }, [runId, datasetId, refresh]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const restore = () => { const value = historySelection(location.search, 'snapshot', runId, datasetId) || '0'; if (result && Number(value) < snapshotCount(result) && value !== selected) { clearSelection(); setSelected(value); setDraft(value); setOffset(0); } };
    window.addEventListener('popstate', restore); return () => window.removeEventListener('popstate', restore);
  }, [runId, datasetId, result, selected]);
  useEffect(() => {
    const ticket = ++epoch.current, controller = new AbortController(); evidenceEpoch.current++;
    setSnapshot(null); setPage(null); setEvidence(null); setEvidenceBusy(false); setBacklog(null);
    if (!result) return;
    setError('');
    setBusy(true);
    (async () => {
      const read = (suffix: string) => request(base + suffix, controller.signal);
      let snap: Row, data: Row;
      if (shared) {
        const fields = ['snapshot_number', 'available_at', 'arrival_seq', 'revision_number', 'status', 'trigger', 'config_version'];
        const values = await Promise.all(fields.map(field => read(sharedPath('get', 'history/snapshots', [Number(selected), field]))));
        snap = Object.fromEntries(fields.map((field, index) => [field, values[index]]));
        data = await read(sharedPath('page', 'history/snapshots', [Number(selected), 'analysis', kind], offset));
        const first = await read(sharedPath('page', 'metrics.json', ['backlog', 'samples'], 0, 1));
        const sample = await historicalBacklog(first.total, snap, index => read(sharedPath('get', 'metrics.json', ['backlog', 'samples', index])));
        if (ticket === epoch.current) setBacklog(sample);
      } else {
        snap = await read(`/snapshots/${selected}`); snap = snap.data ?? snap;
        const all = snap.analysis?.[kind] ?? [];
        data = { items: all.slice(offset, offset + 10), offset, returned: Math.min(10, Math.max(0, all.length - offset)), total: all.length, has_more: offset + 10 < all.length };
        const metrics = await read('/artifacts/metrics.json/download');
        if (ticket === epoch.current) setBacklog(visibleBacklog(metrics.backlog?.samples ?? [], snap) ?? null);
      }
      if (ticket === epoch.current) { setSnapshot(snap); setPage(data); report.current(''); }
    })().catch(reason => { if (!controller.signal.aborted && ticket === epoch.current) { setSnapshot(null); setPage(null); setBacklog(null); fail(reason); } }).finally(() => { if (ticket === epoch.current) setBusy(false); });
    return () => { controller.abort(); };
  }, [result, selected, kind, offset]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const controller = new AbortController(); setRevisions(null); if (!result) return;
    request(base + `/revisions?after=${revisionOffset}&limit=5`, controller.signal).then(value => { if (!controller.signal.aborted) setRevisions(normalizeRevisions(value)); }).catch(reason => { if (!controller.signal.aborted) fail(reason); });
    return () => controller.abort();
  }, [result, revisionOffset]); // eslint-disable-line react-hooks/exhaustive-deps
  async function inspect(selector: Row, next = 0) {
    const ticket = epoch.current, query = ++evidenceEpoch.current; setEvidence(null); setEvidenceBusy(false); setEvidenceSelector(selector); setEvidenceBusy(true);
    const params = new URLSearchParams({ ...selector, ...(shared ? { action: 'evidence', snapshot: selected } : { revision: selected }), ref_offset: String(next), ref_limit: '10' });
    try { const value = await request(base + (shared ? '/shared-query?' : '/evidence?') + params); if (ticket === epoch.current && query === evidenceEpoch.current) { setEvidence(value); report.current(''); } }
    catch (reason) { if (ticket === epoch.current && query === evidenceEpoch.current) { setSnapshot(null); setPage(null); setBacklog(null); fail(reason); } }
    finally { if (ticket === epoch.current && query === evidenceEpoch.current) setEvidenceBusy(false); }
  }
  function clearSelection() { setEvidenceBusy(false); epoch.current++; evidenceEpoch.current++; setSnapshot(null); setPage(null); setBacklog(null); setEvidence(null); setEvidenceBusy(false); }
  function choose(value: string) { if (value !== selected) clearSelection(); setSelected(value); setDraft(value); setOffset(0); writeHistorySelection('snapshot', value, runId, datasetId); }
  const total = result ? snapshotCount(result) : 0;
  return <div className="space-y-6 min-w-0">
    <header><p className="text-xs font-semibold uppercase tracking-widest text-teal-700">Replay / Arrived Prefix</p><h2 className="mt-2 text-2xl font-semibold">顺序回放</h2><p className="mt-2 text-sm text-slate-600">按到达顺序查看历史证据。窗口关闭、响应成功和候选关联均不代表物理执行、因果或攻击确认。</p></header>
    {!runId ? <p className="rounded-xl border border-dashed p-8 text-slate-600">先选择一个回放运行。</p> : <>
      <p className="text-xs text-slate-500 break-all" translate="no">数据集 {datasetId} · 运行 {runId}</p>
      {error && <div role="alert" className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800">{error}。已清除受影响的可信视图。<button type="button" className="ml-3 underline" onClick={() => setRefresh(v => v + 1)}>重新核验</button></div>}
      {!result && !error && <p role="status">正在核验回放产物…</p>}
      {result && <><p className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm">{(result.manifest?.synthetic ?? result.synthetic ?? result.data?.analysis?.synthetic) === true ? '合成软件验证；不代表真实工业数据验收。' : '来源适用性未验证；不代表真实工业数据验收。'}</p><div className="rounded-xl border bg-white p-5 space-y-4"><div className="flex flex-wrap items-end gap-3"><form onSubmit={event => { event.preventDefault(); if (/^\d+$/.test(draft) && Number(draft) < total) choose(String(Number(draft))); }} className="flex flex-wrap items-end gap-3"><label className="text-sm">快照编号（0—{Math.max(0, total - 1)}）<input className="mt-1 block w-36 rounded-lg border px-3 py-2" type="number" name="replay-snapshot" min="0" max={Math.max(0, total - 1)} required value={draft} onChange={event => setDraft(event.target.value)} /></label><button type="submit" className="rounded-lg bg-teal-700 px-4 py-2 text-white">查看该时刻</button></form><button type="button" disabled={Number(selected) <= 0 || busy} className="rounded-lg border px-3 py-2 disabled:opacity-40" onClick={() => choose(String(Number(selected) - 1))}>上一步</button><button type="button" disabled={Number(selected) + 1 >= total || busy} className="rounded-lg border px-3 py-2 disabled:opacity-40" onClick={() => choose(String(Number(selected) + 1))}>下一步</button></div><p className="text-xs text-slate-500">快照包含每次到达或时钟推进；只有事实变化才增加修订号。此页面读取已校验的历史产物。</p></div>
      {busy && <p role="status">正在核验选中快照与原始到达前缀…</p>}
      {snapshot && <><section aria-label="选中时刻" className="rounded-xl border border-teal-200 bg-teal-50 p-5"><div className="flex flex-wrap justify-between gap-4"><div><h3 className="font-semibold">快照 {selected} · 修订 {number(snapshot.revision_number)}</h3><p className="mt-1 text-sm">{time(snapshot.available_at)} · 到达序号 {number(snapshot.arrival_seq)}</p></div><span className="text-sm">{statuses[snapshot.status] ?? snapshot.status}</span></div><p className="mt-3 text-sm">该时刻只展示已经到达的记录；后续记录不参与此处判断。</p><button type="button" className="mt-3 text-sm underline" onClick={() => void inspect({ trigger: 'true' })}>核查本次触发原件</button></section>
      <section aria-label="选中时刻积压" className="grid gap-3 sm:grid-cols-3">{[['未解析到达记录', backlog?.unparsed_records], ['等待前置条件的操作', backlog?.prerequisite_waiting_operations ?? backlog?.waiting_operations], ['仍开放窗口的操作', backlog?.open_window_operations]].map(([label, value]) => <div key={label} className="rounded-xl border bg-white p-4"><p className="text-xs text-slate-500">{label}</p><p className="mt-2 text-2xl font-semibold tabular-nums">{number(value)}</p></div>)}</section><p className="text-xs text-slate-500">积压取不晚于该时刻、到达序号的最近采样；不计未来计划记录。初始快照没有采样时显示未提供。</p>
      <section className="space-y-3" aria-label="历史事实"><label className="text-sm">查看内容<select className="ml-3 rounded-lg border bg-white p-2" value={kind} onChange={event => { clearSelection(); setKind(event.target.value); setOffset(0); }}>{Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><p className="text-sm text-slate-500">本页 {number(page?.returned)} 项 / 该时刻共 {number(page?.total)} 项</p>{page?.items?.length === 0 && <p className="rounded-xl border border-dashed p-6 text-sm text-slate-500">该时刻尚无此类事实。</p>}{(page?.items ?? []).map((row: Row, index: number) => <article key={row.operation_id ?? row.event_id ?? row.candidate_id ?? index} className="rounded-xl border bg-white p-4 space-y-2"><div className="flex flex-wrap justify-between gap-2"><h4 className="font-medium">{row.operation ?? row.result?.tag ?? row.state ?? labels[kind]}</h4><span className="text-sm text-teal-800">{statuses[row.replay?.status] ?? row.replay?.status ?? row.assessment ?? row.state}</span></div><p className="text-xs break-all" translate="no">{row.operation_id ?? row.event_id ?? row.candidate_id}</p><p className="text-sm">响应：{row.response?.state ?? '不适用'} · 等待：{row.replay?.waiting_for?.join('、') || '无已声明等待'} · 窗口：{row.replay?.closed === true ? '已关闭' : row.replay ? '开放' : '不适用'}</p><p className="text-sm text-slate-600">未知原因：{row.unknown_reasons?.join('、') || '无已声明原因'}</p>{(row.operation_id || (kind === 'changes' && row.event_id)) && <button type="button" className="text-sm underline" onClick={() => void inspect(kind === 'changes' ? { change: row.event_id } : { operation: row.operation_id })}>查看支持、反证与原始记录</button>}<details><summary className="cursor-pointer text-sm text-slate-500">完整事实与证据引用</summary><pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(row, null, 2)}</pre></details></article>)}<div className="flex gap-3"><button type="button" disabled={!offset || busy} className="rounded-lg border px-3 py-2 disabled:opacity-40" onClick={() => setOffset(Math.max(0, offset - 10))}>上一页事实</button><button type="button" disabled={!page?.has_more || busy} className="rounded-lg border px-3 py-2 disabled:opacity-40" onClick={() => setOffset(offset + 10)}>下一页事实</button></div></section></>}
      <section aria-label="不可变修订历史" className="rounded-xl border bg-white p-5 space-y-3"><h3 className="font-semibold">不可变修订</h3><p className="text-xs text-slate-500">修订时间线来自完整历史，可点击跳转；选中时刻事实保持独立。</p>{(revisions?.items ?? []).map((row: Row) => <article key={row.revision_id} className="border-t pt-3"><button type="button" className="text-left underline text-sm" onClick={() => choose(String(row.new_snapshot_number))}>修订 {row.revision_number} · {statuses[row.reason] ?? row.reason} · {time(row.available_at)}</button><p className="mt-1 text-xs text-slate-500">快照 {row.old_snapshot_number} → {row.new_snapshot_number} · 触发 {row.trigger?.kind}</p><details><summary className="text-xs cursor-pointer">修订依据</summary><pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(row, null, 2)}</pre></details></article>)}{revisions?.total === 0 && <p className="text-sm text-slate-500">没有语义修订。</p>}<div className="flex gap-3"><button type="button" disabled={!revisionOffset} className="text-sm underline disabled:opacity-40" onClick={() => setRevisionOffset(Math.max(0, revisionOffset - 5))}>上一页修订</button><button type="button" disabled={!revisions || revisionOffset + revisions.returned >= revisions.total} className="text-sm underline disabled:opacity-40" onClick={() => setRevisionOffset(revisionOffset + 5)}>下一页修订</button></div></section>
      {evidenceBusy && <p role="status">正在核验该历史前缀中的原始记录…</p>}
      {evidence && <section aria-label="历史原始证据" className="rounded-xl border border-teal-200 bg-white p-5 space-y-3"><h3 className="font-semibold">快照 {selected} 的已核验原件</h3><p className="text-sm">本页 {number(evidence.verified_original_evidence?.length)} 条；原件只解析至本快照到达前缀。</p><pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(evidence, null, 2)}</pre>{evidence.evidence_page?.has_more && <button type="button" className="underline text-sm" onClick={() => void inspect(evidenceSelector!, evidence.evidence_page.offset + evidence.evidence_page.returned)}>下一页原始证据</button>}</section>}
      </>}
    </>}
  </div>;
}
