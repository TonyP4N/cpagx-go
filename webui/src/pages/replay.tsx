import React, { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import SharedRun from '../components/SharedRun';
import { useRouter } from 'next/router';

type Row = Record<string, any>;
const API = '/api/v3';
async function read(path: string): Promise<Row> {
  const response = await fetch(API + path, { credentials: 'same-origin' });
  const value = await response.json();
  if (!response.ok) throw new Error(`${response.status} ${value.error?.code ?? 'request_failed'}：${value.error?.message ?? '请求失败'}`);
  return value;
}

export default function ReplayPage() {
  const router = useRouter();
  const run = typeof router.query.run === 'string' ? router.query.run : '';
  const [result, setResult] = useState<Row | null>(null);
  const [revisions, setRevisions] = useState<Row[]>([]);
  const [snapshot, setSnapshot] = useState<Row | null>(null);
  const [revision, setRevision] = useState('');
  const [evidence, setEvidence] = useState<Row | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const snapshotRequest = useRef(0);
  const evidenceRequest = useRef(0);
  const clear = () => { setResult(null); setSnapshot(null); setEvidence(null); setRevisions([]); setRevision(''); };
  useEffect(() => {
    const ticket = ++generation.current;
    snapshotRequest.current++; evidenceRequest.current++;
    clear(); setError('');
    if (!run) return;
    setBusy(true);
    read(`/runs/${encodeURIComponent(run)}/result`).then(async output => {
      const history = output.storage_format === 'shared-observation-dag-6' ? { revisions: [] } : await read(`/runs/${encodeURIComponent(run)}/revisions`);
      if (ticket !== generation.current) return;
      setResult(output); setRevisions(history.revisions ?? []);
    }).catch(reason => { if (ticket === generation.current) { clear(); setError(String(reason.message)); } })
      .finally(() => { if (ticket === generation.current) setBusy(false); });
    return () => { generation.current++; snapshotRequest.current++; evidenceRequest.current++; };
  }, [run]);

  async function choose(value: string) {
    const task = generation.current, ticket = ++snapshotRequest.current;
    evidenceRequest.current++;
    setRevision(value); setSnapshot(null); setEvidence(null); setError('');
    if (!value) return;
    try {
      const output = await read(`/runs/${encodeURIComponent(run)}/snapshots/${encodeURIComponent(value)}`);
      if (task === generation.current && ticket === snapshotRequest.current) setSnapshot(output.data ?? output);
    } catch (reason) { if (task === generation.current && ticket === snapshotRequest.current) { clear(); setError((reason as Error).message); } }
  }
  async function inspect(kind: string, id: string) {
    const task = generation.current, selected = snapshotRequest.current, ticket = ++evidenceRequest.current;
    setEvidence(null); setError('');
    try {
      const value = await read(`/runs/${encodeURIComponent(run)}/evidence?revision=${encodeURIComponent(revision)}&${kind}=${encodeURIComponent(id)}`);
      if (task === generation.current && selected === snapshotRequest.current && ticket === evidenceRequest.current) setEvidence(value);
    } catch (reason) { if (task === generation.current && ticket === evidenceRequest.current) { clear(); setError((reason as Error).message); } }
  }
  async function download(name: string) {
    const task = generation.current;
    try {
      const response = await fetch(`${API}/runs/${encodeURIComponent(run)}/artifacts/${name}/download`, { credentials: 'same-origin' });
      if (!response.ok) { const value = await response.json(); throw new Error(`${response.status} ${value.error?.code}：${value.error?.message}`); }
      const blob = await response.blob(); if (task !== generation.current) return;
      const url = URL.createObjectURL(blob), link = document.createElement('a');
      link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (reason) { if (task === generation.current) { clear(); setError((reason as Error).message); } }
  }
  const analysis = snapshot?.analysis ?? snapshot?.result ?? snapshot?.snapshot?.analysis;
  const synthetic = result?.manifest?.synthetic ?? result?.synthetic ?? result?.data?.analysis?.synthetic;
  return <main className="max-w-6xl mx-auto p-6 space-y-5 text-slate-800">
    <header className="flex flex-wrap justify-between gap-4"><h1 className="text-2xl font-bold">双源顺序回放 · 历史证据核查</h1><Link href="/workspace" className="underline">返回工作台</Link></header>
    <p className="rounded border border-amber-300 bg-amber-50 p-4" aria-label="回放范围">{synthetic === false ? '真实来源声明，适用性未验证。' : synthetic === true ? '合成软件验证。' : '来源标记加载中，尚未核验。'} 此处查看已校验终态产物中的历史版本；pending、窗口关闭和协议响应都不表示物理成功、因果成立或攻击确认。</p>
    <p className="text-sm break-all">运行：{run || '未选择'}</p>
    {busy && <p role="status">正在校验回放产物…</p>}
    {error && <p role="alert" className="border border-red-300 bg-red-50 p-4">{error} 已清除可信结果，请核查来源、权限与完整性。</p>}
    {result?.storage_format === 'shared-observation-dag-6' && <SharedRun run={run} metadata={result} />}
    {result && result.storage_format !== 'shared-observation-dag-6' && <>
      <section className="border rounded p-4 space-y-3" aria-label="回放修订历史"><h2 className="text-xl font-semibold">不可变修订历史</h2>
        <label>历史版本<select aria-label="历史版本" value={revision} onChange={e => void choose(e.target.value)} className="ml-3 p-2 border rounded"><option value="">选择快照</option>{revisions.map((row, index) => { const id = String(row.new_snapshot_number ?? row.revision_number ?? index + 1); return <option key={id} value={id}>版本 {id} · {row.reason ?? row.trigger?.kind ?? '语义修订'} · {row.available_at ?? row.trigger?.available_at}</option>; })}</select></label>
        <details><summary>查看完整修订依据</summary><pre className="text-xs overflow-auto">{JSON.stringify(revisions, null, 2)}</pre></details>
      </section>
      {analysis && <>
        <section aria-label="当前历史状态" className="border rounded p-4 space-y-3"><h2 className="text-xl font-semibold">版本 {revision} 的可见事实</h2><p>当前状态：{analysis.replay?.phase ?? snapshot?.status ?? '见操作状态'}；候选数量：{analysis.candidates?.length ?? 0}</p><button type="button" onClick={() => void inspect('trigger', 'true')} className="underline">查询本次到达原始证据</button>
          {(analysis.operations ?? []).map((op: Row) => <article key={op.operation_id} className="bg-emerald-50 border rounded p-3 space-y-1"><p>操作：{op.operation} · {op.replay?.status ?? op.assessment}</p><p>响应：{op.response?.state ?? '未观察到'}；判断：{op.assessment}</p><p>未知原因：{(op.unknown_reasons ?? []).join('、') || '无'}</p><button type="button" onClick={() => void inspect('operation', op.operation_id)} className="underline">查询操作原始证据 {op.operation_id}</button></article>)}
          {(analysis.changes ?? []).map((change: Row) => <article key={change.event_id} className="bg-blue-50 border rounded p-3"><p>工艺变化：{change.result?.tag} {String(change.result?.before)} → {String(change.result?.after)}</p><button type="button" className="underline" onClick={() => void inspect('change', change.event_id)}>查询变化原始证据 {change.event_id}</button></article>)}
          <details><summary>查看快照、状态、图和未知原因</summary><pre className="text-xs overflow-auto">{JSON.stringify(snapshot, null, 2)}</pre></details>
        </section>
      </>}
      {evidence && <section aria-label="回放原始证据" className="border rounded p-4"><h2 className="text-xl font-semibold">该历史版本的原始证据</h2><p>记录数：{evidence.verified_original_evidence?.length ?? 0}</p>{(evidence.verified_original_evidence ?? []).map((item: Row, index: number) => <details key={index} className="border rounded p-3 mt-2"><summary>原始记录 {index + 1}</summary><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(item, null, 2)}</pre></details>)}</section>}
      <section aria-label="回放产物下载" className="border rounded p-4"><h2 className="text-xl font-semibold">受控下载</h2><div className="flex flex-wrap gap-3 mt-3">{['snapshots.jsonl', 'revisions.jsonl', 'arrivals.jsonl', 'metrics.json', 'runtime_metrics.json', 'analysis.json'].map(name => <button type="button" key={name} onClick={() => void download(name)} className="border rounded p-2">下载 {name}</button>)}</div></section>
    </>}
  </main>;
}
