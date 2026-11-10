import React from 'react';
import { idOf, kindOf, Row, Selection, stateOf } from '../analysisModel';
import { control, Pager, timeText } from './widgets';

export function TimelineList({ rows, page, count, meta, selectedIds, onInspect, onPage }: { rows: Row[]; page: number; count: number; meta: string; selectedIds: Set<string>; onInspect: (next: Selection) => void; onPage: (page: number) => void }) {
  return <section className="wb-card space-y-3" aria-label="联动时间线">
    <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">时间线</h3><span className="text-xs">{meta}</span></div>
    <ol className="space-y-2 overflow-auto pr-1">{rows.map(row => <li key={idOf(row)}><button type="button" aria-pressed={selectedIds.has(idOf(row))} className={control + ' w-full border-l-4 text-left ' + (selectedIds.has(idOf(row)) ? 'wb-selected-row' : kindOf(row) === 'operation' ? 'wb-bar-net' : 'wb-bar-change')} onClick={() => onInspect({ kind: kindOf(row) as Selection['kind'], id: idOf(row) })}><span className="block text-xs tabular-nums">{timeText(row)}</span><span className="mt-1 block break-words">{row.operation ?? row.result?.tag ?? '过程变化'} · {stateOf(row)}</span><span className="mt-1 block break-all font-mono text-[10px] text-slate-500">{idOf(row)}</span></button></li>)}</ol>
    {!count && <p className="wb-empty py-6">当前范围没有符合筛选的操作或变化。</p>}
    <Pager page={page} count={count} change={onPage} />
  </section>;
}

export function CandidateList({ rows, page, count, totalLabel, selectedIds, selectionId, onInspect, onPage }: { rows: Row[]; page: number; count: number; totalLabel: string; selectedIds: Set<string>; selectionId?: string; onInspect: (next: Selection) => void; onPage: (page: number) => void }) {
  return <section className="wb-card space-y-3" aria-label="联动候选">
    <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">候选、支持与反证</h3><span className="text-xs">{totalLabel}</span></div>
    <ul className="space-y-2 overflow-auto pr-1">{rows.map(row => <li key={idOf(row)}><button type="button" aria-pressed={selectionId === idOf(row)} className={control + ' w-full break-words text-left ' + (selectedIds.has(idOf(row)) ? 'wb-selected-row' : '')} onClick={() => onInspect({ kind: 'candidate', id: idOf(row) })}><span className="block">{stateOf(row)} · 规则 {row.rule_id ?? '未知'} / {row.rule_version ?? '未知版本'}</span><span className="mt-1 block break-all font-mono text-[10px] text-slate-500">{idOf(row)}</span><span className="wb-chip-row"><span className="wb-chip">支持 {row.support?.length ?? 0}</span><span className="wb-chip wb-chip-warn">反证 {row.counterevidence?.length ?? 0}</span><span className="wb-chip wb-chip-muted">未知 {row.unknown_reasons?.length ?? 0}</span></span></button></li>)}</ul>
    {!count && <p className="wb-empty py-6">当前范围没有符合筛选的候选。</p>}
    <Pager page={page} count={count} change={onPage} />
  </section>;
}
