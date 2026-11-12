import React from 'react';
import { idOf, kindOf, LIMITS, Row, Selection } from '../analysisModel';
import { control, Pager, timeText } from './widgets';

export function AggregatePane({
  groups,
  dimension,
  timelineCount,
  expandedGroup,
  members,
  memberPage,
  groupPage,
  groupRegionId,
  selection,
  onDimension,
  onToggleGroup,
  onMemberPage,
  onGroupPage,
  onInspect,
}: {
  groups: { key: string; count: number }[];
  dimension: 'state' | 'asset' | 'minute';
  timelineCount: number;
  expandedGroup: string | null;
  members: Row[];
  memberPage: number;
  groupPage: number;
  groupRegionId: string;
  selection: Selection | null;
  onDimension: (value: 'state' | 'asset' | 'minute') => void;
  onToggleGroup: (key: string | null) => void;
  onMemberPage: (page: number) => void;
  onGroupPage: (page: number) => void;
  onInspect: (next: Selection) => void;
}) {
  const slice = groups.slice(groupPage * LIMITS.page, (groupPage + 1) * LIMITS.page);
  const memberSlice = members.slice(memberPage * LIMITS.page, (memberPage + 1) * LIMITS.page);
  const dimensionLabel = dimension === 'asset' ? '资产' : dimension === 'minute' ? '分钟（UTC）' : '判断状态';
  const preview = groups.slice(0, 5);
  const hiddenGroups = Math.max(0, groups.length - preview.length);
  return <section className="wb-card space-y-3" aria-label="范围内聚合">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="font-semibold">当前筛选范围聚合 <span className="wb-aggregate-keys">{preview.map(group => <span key={group.key}>{group.key}</span>)}</span></h3>
      <label className="text-sm">聚合维度<select className={control + ' ml-2'} value={dimension} onChange={event => onDimension(event.target.value as 'state' | 'asset' | 'minute')}><option value="state">判断状态</option><option value="asset">资产</option><option value="minute">分钟（UTC）</option></select></label>
    </div>
    <details>
      <summary>
        <span>当前维度 {dimensionLabel}</span>
        <span className="wb-aggregate-keys">{preview.map(group => <span key={group.key}>{group.key}</span>)}</span>
        <span>{hiddenGroups ? `另有 ${hiddenGroups} 组 · ` : ''}共 {groups.length} 组 / {timelineCount} 项</span>
      </summary>
      <table className="w-full table-fixed text-sm"><caption className="pb-2 text-left text-xs text-slate-500">只统计已载入且符合筛选的操作与变化，共 {timelineCount} 项。</caption><thead><tr className="border-b text-left"><th className="py-2">分组</th><th className="w-24 py-2 text-right">数量</th></tr></thead><tbody>{slice.map((group, index) => {
        const expanded = expandedGroup === group.key, regionId = `${groupRegionId}-${groupPage * LIMITS.page + index}`;
        return <React.Fragment key={group.key}><tr className="border-b border-slate-100"><th scope="row" className="py-2 text-left font-normal"><button type="button" className={control + ' max-w-full break-words text-left'} aria-expanded={expanded} aria-controls={regionId} aria-label={`${expanded ? '收起' : '展开'}分组 ${group.key} · ${group.count}`} onClick={() => onToggleGroup(expanded ? null : group.key)}><span aria-hidden="true">{expanded ? '▾' : '▸'} </span>{group.key}</button></th><td className="py-2 text-right tabular-nums">{group.count}</td></tr>
          {expanded && <tr id={regionId}><td colSpan={2} className="border-b border-slate-200 bg-slate-50 p-3"><section aria-label={`${group.key} 分组成员`} className="space-y-3"><p className="text-xs text-slate-600">当前已载入范围内 {members.length} 条成员；选择成员可定位其观测和原始证据。</p><ul className="max-h-96 space-y-2 overflow-auto">{memberSlice.map(row => {
            const kind = kindOf(row) as 'operation' | 'change', label = kind === 'operation' ? '网络操作' : '过程变化';
            return <li key={idOf(row)}><button type="button" className={control + ' block w-full break-words text-left'} aria-label={`定位${label} ${idOf(row)}`} aria-pressed={selection?.kind === kind && selection.id === idOf(row)} onClick={() => onInspect({ kind, id: idOf(row) })}><span className="block">定位{label} · {row.operation ?? row.result?.tag ?? '观测记录'}</span><span className="block text-xs tabular-nums">{timeText(row)}</span><span className="block break-all font-mono text-[10px] text-slate-500">{idOf(row)}</span></button></li>;
          })}</ul><Pager page={memberPage} count={members.length} change={onMemberPage} /></section></td></tr>}
        </React.Fragment>;
      })}</tbody></table>
      {!groups.length && <p className="text-sm text-slate-500">没有可聚合的记录。</p>}
      <Pager page={groupPage} count={groups.length} change={onGroupPage} />
    </details>
  </section>;
}
