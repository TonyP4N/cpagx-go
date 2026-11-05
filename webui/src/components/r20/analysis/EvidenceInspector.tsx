import React, { useEffect, useState } from 'react';
import { Row, Selection, stateOf } from '../analysisModel';
import { control, JsonDetails, timeText } from './widgets';

const kindLabel: Record<Selection['kind'], string> = { operation: '网络操作', change: '过程变化', candidate: '候选', node: '节点' };

function shortHash(value: string) {
  return value.length > 16 ? value.slice(0, 8) + '…' + value.slice(-4) : value;
}

function brief(item: unknown) {
  if (typeof item === 'string' || typeof item === 'number') return String(item);
  if (item && typeof item === 'object') {
    const row = item as Row;
    return String(row.reason ?? row.id ?? row.kind ?? row.tag ?? row.source ?? row.summary ?? '见完整记录');
  }
  return String(item ?? '');
}

function humanPairs(row: Row): [string, string][] {
  const pairs: [string, string][] = [];
  const ref = row.source_ref ?? {};
  if (ref.source_slot) pairs.push(['来源槽', String(ref.source_slot)]);
  if (ref.frame_number != null) pairs.push(['帧', String(ref.frame_number)]);
  if (ref.record_number != null) pairs.push(['记录', String(ref.record_number)]);
  if (ref.column) pairs.push(['列', String(ref.column)]);
  const body = row.record ?? row.values ?? row.fields;
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    Object.entries(body).slice(0, 8).forEach(([key, value]) => {
      if (value == null || typeof value === 'object') return;
      pairs.push([key, String(value)]);
    });
  }
  return pairs;
}

export function EvidenceInspector({ selection, selected, evidence, evidenceBusy, onInspect, onClear }: {
  selection: Selection | null;
  selected: Row | undefined;
  evidence: Row | null;
  evidenceBusy: boolean;
  onInspect: (next: Selection, offset?: number) => void;
  onClear: () => void;
}) {
  const [place, setPlace] = useState<'summary' | 'evidence' | 'tech'>('summary');
  const [hashNote, setHashNote] = useState('');
  const [narrow, setNarrow] = useState(false);
  const [sheetOpen, setSheetOpen] = useState(true);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 1024px)');
    const sync = () => setNarrow(media.matches);
    sync();
    media.addEventListener('change', sync);
    return () => media.removeEventListener('change', sync);
  }, []);
  useEffect(() => {
    if (!narrow) return;
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setSheetOpen(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [narrow]);
  async function copyHash(sha: string) {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('clipboard_unavailable');
      await navigator.clipboard.writeText(sha);
      setHashNote('已复制文件哈希。');
    } catch {
      setHashNote('无法写入剪贴板。请展开完整记录复制哈希。');
    }
  }
  function focusPlace(next: 'summary' | 'evidence' | 'tech') {
    setPlace(next);
    const id = next === 'summary' ? 'wb-inspector-summary' : next === 'evidence' ? 'wb-inspector-evidence' : 'wb-inspector-tech';
    window.setTimeout(() => document.getElementById(id)?.scrollIntoView({ block: 'nearest' }), 0);
  }
  const reasons: string[] = selected?.unknown_reasons ?? [];
  const support = selected?.support ?? [];
  const counter = selected?.counterevidence ?? [];
  return <>
    {narrow && !sheetOpen && <button type="button" className="wb-sheet-reopen wb-card" onClick={() => setSheetOpen(true)}>打开证据</button>}
    <section className="wb-card wb-inspector space-y-3" aria-label="联动原始证据" aria-busy={evidenceBusy} hidden={narrow && !sheetOpen}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-semibold">选中项与原始证据</h3>
        {narrow && <button type="button" className="wb-sheet-close" onClick={() => setSheetOpen(false)}>关闭证据</button>}
      </div>
      {!selection && <div className="wb-empty" key="empty"><p>在图、时间线或候选中点选一项</p><p>选择图节点、时间线记录或候选，查看其原始证据。</p></div>}
      {selection && <div key={selection.id} className="wb-fade space-y-3">
        <div className="wb-tabs" aria-label="证据阅读">
          <button type="button" className={control} aria-current={place === 'summary' ? 'true' : undefined} onClick={() => focusPlace('summary')}>概要</button>
          <button type="button" className={control} aria-current={place === 'evidence' ? 'true' : undefined} onClick={() => focusPlace('evidence')}>证据</button>
          <button type="button" className={control} aria-current={place === 'tech' ? 'true' : undefined} aria-expanded={place === 'tech'} onClick={() => focusPlace('tech')}>技术</button>
        </div>
        <p className="break-all font-mono text-xs">{selection.kind} · {selection.id}</p>
        <div id="wb-inspector-summary" className="space-y-2">
          <span className="wb-chip">{kindLabel[selection.kind]}</span>
          {selected && <>
            <dl className="wb-kv">
              <dt>状态</dt><dd>{stateOf(selected)}</dd>
              <dt>时间</dt><dd>{timeText(selected)}</dd>
              <dt>规则</dt><dd>{selected.rule_id ?? selected.mapping?.rule_ids?.join('、') ?? '不适用'} / {selected.rule_version ?? selected.mapping?.config_version ?? '未知版本'}</dd>
              {(selected.mapping?.asset_id || selected.result?.asset_id) && <><dt>资产</dt><dd>{selected.mapping?.asset_id ?? selected.result?.asset_id}</dd></>}
              {(selected.destination_endpoint || selected.source_endpoint) && <><dt>端点</dt><dd>{[selected.source_endpoint, selected.destination_endpoint].filter(Boolean).join(' → ')}</dd></>}
              {(selected.mapping?.tag || selected.result?.tag || selected.operation) && <><dt>标签</dt><dd>{selected.operation ?? selected.mapping?.tag ?? selected.result?.tag}</dd></>}
            </dl>
            <p className="text-sm break-words">未知原因：{reasons.join('、') || '见完整记录'}；支持 {support.length}，反证 {counter.length}。</p>
            {!!reasons.length && <div className="wb-chip-row">{reasons.map(reason => <span className="wb-chip wb-chip-muted" key={reason}>{reason}</span>)}</div>}
            {!!support.length && <div><p className="text-xs text-slate-500">支持</p><ul className="mt-1 space-y-1 text-sm">{support.slice(0, 8).map((item: unknown, index: number) => <li key={index}>{brief(item)}</li>)}</ul></div>}
            {!!counter.length && <div><p className="text-xs text-slate-500">反证</p><ul className="mt-1 space-y-1 text-sm">{counter.slice(0, 8).map((item: unknown, index: number) => <li key={index}>{brief(item)}</li>)}</ul></div>}
            <p className="text-sm break-words">状态：{stateOf(selected)} · 规则 {selected.rule_id ?? selected.mapping?.rule_ids?.join('、') ?? '不适用'} / {selected.rule_version ?? selected.mapping?.config_version ?? '未知版本'}</p>
            <p className="text-sm">时间：{timeText(selected)}</p>
          </>}
          <div className="flex flex-wrap gap-2">
            {selected?.candidate_id && <>
              <button className={control} type="button" onClick={() => onInspect({ kind: 'operation', id: selected.operation_id })}>查看关联网络操作</button>
              <button className={control} type="button" onClick={() => onInspect({ kind: 'change', id: selected.change_id })}>查看关联过程变化</button>
            </>}
            <button className={control} type="button" onClick={onClear}>清除选择</button>
          </div>
          {selected && <JsonDetails value={selected} label="完整观测、支持、反证与未知原因" />}
          {selection.kind === 'node' && <p className="text-sm text-slate-600">当前已读取范围没有关联的操作或变化。上方记录包含来源引用；尚未核验其原始内容，请使用完整分页核查定位相关操作。</p>}
        </div>
        <div id="wb-inspector-evidence" className="space-y-2">
          {evidenceBusy && <p role="status" className="text-sm">正在核验原始记录…</p>}
          {evidence && <>
            <p className="text-sm" aria-live="polite">已核验原始记录：本页 {evidence.verified_original_evidence?.length ?? 0} 条{evidence.evidence_page ? ` / 共 ${evidence.evidence_page.total} 条` : ''}</p>
            {hashNote && <p role="status" className="text-xs">{hashNote}</p>}
            <div className="space-y-2">{(evidence.verified_original_evidence ?? []).slice(0, 25).map((row: Row, index: number) => {
              const sha = row.source_ref?.file_sha256 as string | undefined;
              const pairs = humanPairs(row);
              return <div className="rounded border border-slate-200 p-3" key={index}>
                <p className="mb-2 break-all text-xs">{sha ? '文件 SHA-256：' + sha : '来源文件槽：' + (row.source_ref?.source_slot ?? '未提供')} · 帧 {row.source_ref?.frame_number ?? '—'} · 记录 {row.source_ref?.record_number ?? '—'} · 列 {row.source_ref?.column ?? '—'}</p>
                {sha && <p className="mb-2 text-xs">哈希 {shortHash(sha)} <button type="button" className="underline" onClick={() => void copyHash(sha)}>复制文件哈希</button></p>}
                {!!pairs.length && <dl className="wb-kv">{pairs.map(([key, value]) => <React.Fragment key={key}><dt>{key}</dt><dd className="break-all">{value}</dd></React.Fragment>)}</dl>}
                <JsonDetails value={row} label={`原始记录 ${(evidence.evidence_page?.offset ?? 0) + index + 1}`} />
              </div>;
            })}</div>
            {evidence.evidence_page && <div className="flex flex-wrap gap-2"><button className={control} type="button" disabled={!evidence.evidence_page.offset} onClick={() => onInspect(selection, Math.max(0, evidence.evidence_page.offset - 25))}>上一页原始证据</button><button className={control} type="button" disabled={!evidence.evidence_page.has_more} onClick={() => onInspect(selection, evidence.evidence_page.offset + evidence.evidence_page.returned)}>下一页原始证据</button></div>}
            {!evidence.evidence_page && (evidence.verified_original_evidence?.length ?? 0) > 25 && <p className="text-sm text-slate-600">旧接口返回超过 25 条原始记录，此处展示前 25 条；完整核查请使用核查入口。</p>}
          </>}
        </div>
        {place === 'tech' && <div id="wb-inspector-tech">
          {evidence ? <JsonDetails value={{ selection: evidence.selection, time_configuration: evidence.time_configuration, source_ranges: evidence.source_ranges, quality: evidence.quality, config_version: evidence.config_version, config_fingerprint: evidence.config_fingerprint, limitations: evidence.limitations }} label="时间依据、配置版本与质量说明" /> : <p className="text-sm text-slate-500">选择带原始记录的操作、变化或候选后，可查看时间依据与配置指纹。</p>}
        </div>}
      </div>}
    </section>
  </>;
}
