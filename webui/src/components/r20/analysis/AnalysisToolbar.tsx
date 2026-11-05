import React, { useState } from 'react';
import { Filter } from '../analysisModel';
import { control } from './widgets';

export function AnalysisToolbar({
  draft,
  setDraft,
  states,
  busy,
  large,
  selectionCount,
  replay,
  snapshotDraft,
  setSnapshotDraft,
  finalSnapshot,
  onApply,
  onClearFilter,
  onToggleLarge,
  onRefresh,
  onClearSelection,
  onReadSnapshot,
  verifyHref,
}: {
  draft: Filter;
  setDraft: (filter: Filter) => void;
  states: string[];
  busy: boolean;
  large: boolean;
  selectionCount: number;
  replay: boolean;
  snapshotDraft: string;
  setSnapshotDraft: (value: string) => void;
  finalSnapshot?: number;
  onApply: (event: React.FormEvent) => void;
  onClearFilter: () => void;
  onToggleLarge: () => void;
  onRefresh: () => void;
  onClearSelection: () => void;
  onReadSnapshot: (event: React.FormEvent) => void;
  verifyHref?: string;
}) {
  const [more, setMore] = useState(Boolean(draft.from || draft.to));
  return <div className="space-y-2">
    <form onSubmit={onApply} className="wb-toolbar" aria-label="分析筛选">
      <label><span>记录、端点、资产或标签</span><input className={control + ' w-full'} name="analysis-query" autoComplete="off" spellCheck={false} placeholder="例如 P101…" value={draft.text} onChange={event => setDraft({ ...draft, text: event.target.value })} /></label>
      <label><span>观测类型</span><select className={control + ' w-full'} value={draft.kind} onChange={event => setDraft({ ...draft, kind: event.target.value })}><option value="">全部类型</option><option value="operation">网络操作</option><option value="change">过程变化</option><option value="candidate">候选关联</option></select></label>
      <label><span>判断状态</span><select className={control + ' w-full'} value={draft.state} onChange={event => setDraft({ ...draft, state: event.target.value })}><option value="">全部状态</option>{states.map(state => <option key={state}>{state}</option>)}</select></label>
      <button type="submit" className={control + ' wb-link'}>应用筛选</button>
      <button type="button" className={control} onClick={onClearFilter}>清除筛选</button>
      <button type="button" className={control} onClick={onToggleLarge}>{large ? '恢复概览 200 / 600' : '扩展视图 1000 / 3000'}</button>
      <button type="button" className={control} disabled={busy} onClick={onRefresh}>重新核验</button>
      <button type="button" className={control} aria-expanded={more} onClick={() => setMore(value => !value)}>{more ? '收起时间筛选' : '更多筛选'}</button>
      {selectionCount > 0 && <span className="text-xs text-slate-600">已选 {selectionCount} 项 · <button type="button" className="underline" onClick={onClearSelection}>清除选择</button></span>}
      {verifyHref && <a className={control + ' wb-link inline-flex items-center'} href={verifyHref}>完整分页核查与受控下载 →</a>}
      {more && <div className="flex flex-wrap gap-3 basis-full">
        <label><span>开始时间（浏览器本地时区）</span><input name="analysis-from" autoComplete="off" type="datetime-local" step="1" className={control + ' w-full'} value={draft.from} onChange={event => setDraft({ ...draft, from: event.target.value })} /></label>
        <label><span>结束时间（浏览器本地时区）</span><input name="analysis-to" autoComplete="off" type="datetime-local" step="1" className={control + ' w-full'} value={draft.to} onChange={event => setDraft({ ...draft, to: event.target.value })} /></label>
      </div>}
      <p className="wb-toolbar-note">筛选与聚合针对已读取范围，候选按保存ID关联操作与变化；图保留关联端点上下文，时间线仅列直接匹配的记录。未知时间不纳入有限时间筛选。自由文本与时间筛选只保存在当前页面，不写入地址。</p>
    </form>
    {replay && <form className="wb-toolbar" onSubmit={onReadSnapshot}>
      <label className="text-sm text-slate-600">历史快照（空白查看终态）<input className={control + ' w-28'} name="analysis-snapshot" autoComplete="off" type="number" min="0" max={finalSnapshot} value={snapshotDraft} onChange={event => setSnapshotDraft(event.target.value)} /></label>
      <button className={control} type="submit">读取快照</button>
      <span className="text-xs text-slate-500">终态编号 {finalSnapshot ?? '见历史核查'}</span>
    </form>}
  </div>;
}
