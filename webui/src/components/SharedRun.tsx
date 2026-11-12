import React, { useEffect, useRef, useState } from 'react';
type Row = Record<string, any>;
const FORMAT = 'shared-observation-dag-6';
export default function SharedRun({ run, metadata }: { run: string; metadata: Row }) {
  const [kind, setKind] = useState('operations');
  const [snapshot, setSnapshot] = useState('');
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Row | null>(null);
  const [evidence, setEvidence] = useState<Row | null>(null);
  const [files, setFiles] = useState<Row[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const generation = useRef(0);
  const evidenceGeneration = useRef(0);
  const base = `/api/v3/runs/${encodeURIComponent(run)}`;
  const replay = metadata.mode === 'replay';
  async function read(path: string) {
    const response = await fetch(base + path, { credentials: 'same-origin' });
    const value = await response.json();
    if (!response.ok) throw new Error(`${response.status} ${value.error?.code ?? 'request_failed'}：${value.error?.message ?? '请求被拒绝'}`);
    return value;
  }
  useEffect(() => {
    const ticket = ++generation.current; evidenceGeneration.current++;
    setPage(null); setEvidence(null); setFiles([]); setError(''); setBusy(true);
    const graph = kind === 'nodes' || kind === 'edges';
    let root = graph ? 'graph.json' : kind === 'events' ? 'events.json' : kind === 'revisions' ? 'history/revisions' : 'analysis.json';
    let path: (string | number)[] = graph ? [kind] : ['events', 'revisions'].includes(kind) ? [] : [kind];
    if (snapshot !== '' && kind !== 'revisions') {
      root = 'history/snapshots'; path = [Number(snapshot), ...(graph ? ['graph', kind] : kind === 'events' ? ['events'] : ['analysis', kind])];
    }
    const params = new URLSearchParams({ action: 'page', logical_root: root, path: JSON.stringify(path), offset: String(offset), limit: kind === 'revisions' ? '1' : '10' });
    Promise.all([read('/shared-query?' + params), read('/artifacts')]).then(([value, inventory]) => {
      if (ticket !== generation.current) return;
      setPage(value); setFiles(inventory.artifacts ?? []);
    }).catch(reason => { if (ticket === generation.current) { setPage(null); setEvidence(null); setFiles([]); setError(reason.message); } })
      .finally(() => { if (ticket === generation.current) setBusy(false); });
    return () => { generation.current++; evidenceGeneration.current++; };
    // Every selection change clears the previous result before requesting a new page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run, kind, snapshot, offset, refresh]);
  async function inspect(row: Row, next = 0) {
    const ticket = generation.current, query = ++evidenceGeneration.current;
    setEvidence(null); setError('');
    const params = new URLSearchParams({ action: 'evidence', ref_offset: String(next), ref_limit: '100' });
    if (row.operation_id) params.set('operation', row.operation_id);
    else if (row.event_id && kind === 'changes') params.set('change', row.event_id);
    else return;
    if (snapshot !== '') params.set('snapshot', snapshot);
    try { const value = await read('/shared-query?' + params); if (ticket === generation.current && query === evidenceGeneration.current) setEvidence({ ...value, selected_row: row }); }
    catch (reason) { if (ticket === generation.current && query === evidenceGeneration.current) { setPage(null); setFiles([]); setError((reason as Error).message); } }
  }
  const items = page?.items ?? [];
  return <section aria-label="共享产物分页核查" className="border rounded p-4 space-y-4">
    <h2 className="text-xl font-semibold">共享产物 · 有界分页核查</h2>
    <p>{metadata.manifest?.synthetic === true ? '合成软件验证。' : '真实来源声明，适用性未验证。'} 协议成功不是物理执行成功；候选关联不是已确认因果或攻击。</p>
    <p className="text-sm break-all">{FORMAT} · 终态总量：操作 {metadata.counts?.operations} · 变化 {metadata.counts?.changes} · 候选 {metadata.counts?.candidates} · 快照 {metadata.counts?.snapshots ?? 0}</p>
    {replay && <label className="block">历史快照（留空查看终态）<input aria-label="共享历史快照" className="border rounded p-1 ml-2" type="number" min="0" max={metadata.final_snapshot_number} value={snapshot} onChange={event => { setSnapshot(event.target.value); setOffset(0); }} /></label>}
    <label className="block">查看内容<select aria-label="共享产物内容" className="border rounded p-1 ml-2" value={kind} onChange={event => { setKind(event.target.value); setOffset(0); }}>
      {Object.entries({ operations: '网络操作', changes: '工艺变化', candidates: '候选、反证与未知', nodes: '图节点', edges: '图连线', events: '标准事件', ...(replay ? { revisions: '修订记录' } : {}) }).map(([value, label]) => <option value={value} key={value}>{label}</option>)}
    </select></label>
    {busy && <p role="status">正在核验当前文件并读取分页…</p>}
    {error && <p role="alert" className="text-red-700">{error} 已清除本页可信结果。<button className="ml-2 underline" onClick={() => setRefresh(v => v + 1)}>重新核验读取</button></p>}
    {page && <><p>当前 {page.returned ? page.offset + 1 : 0}—{page.offset + page.returned}，共 {page.total} 项；超限时会明确拒绝，不截断为完整结果。</p>
      <div className="flex gap-3"><button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - (kind === 'revisions' ? 1 : 10)))} className="underline disabled:opacity-50">上一页</button><button disabled={!page.has_more} onClick={() => setOffset(offset + page.returned)} className="underline disabled:opacity-50">下一页</button></div>
      {items.map((row: Row, index: number) => <article key={index} className="border rounded p-3 space-y-2"><p>{row.operation ?? row.event_type ?? row.reason ?? row.state ?? row.kind ?? '观测记录'} · {row.replay?.status ?? row.assessment ?? row.state ?? ''}</p><p>响应：{row.response?.state ?? '不适用'}；未知：{(row.unknown_reasons ?? []).join('、') || '见完整记录'}</p>
        {(row.operation_id || (kind === 'changes' && row.event_id)) && <button className="underline" onClick={() => void inspect(row)}>查询该项原始证据</button>}
        <details><summary>完整记录、支持与反证</summary><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(row, null, 2)}</pre></details></article>)}
    </>}
    {evidence && <section aria-label="共享原始证据"><h3 className="font-semibold">核验后的原始记录</h3><p>本页 {evidence.verified_original_evidence?.length ?? 0} 条</p>{(evidence.verified_original_evidence ?? []).map((row: Row, index: number) => <details key={index}><summary>原始记录 {index + 1}</summary><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(row, null, 2)}</pre></details>)}{evidence.evidence_page?.has_more && <button className="underline" onClick={() => void inspect(evidence.selected_row, evidence.evidence_page.offset + evidence.evidence_page.returned)}>下一页原始证据</button>}</section>}
    {!!files.length && <section aria-label="共享物理产物下载"><h3 className="font-semibold">受控流式下载（完整物理文件）</h3><p className="text-sm">下载共享库和清单，不展开为巨大JSON。</p><ul>{files.map(file => <li key={file.path}><a className="underline" href={`${base}/artifacts/${file.path.split('/').map(encodeURIComponent).join('/')}/download`}>{file.path} · {file.size ?? file.size_bytes} 字节</a></li>)}</ul></section>}
  </section>;
}
