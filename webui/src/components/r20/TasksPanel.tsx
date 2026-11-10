import React, { useEffect, useMemo, useState } from 'react';
import { PageToolbar } from './PageToolbar';
import { stateLabels } from './navigation';
import { StatusChip } from './StatusChip';

type History = { exited_at?: string };
export type TaskRun = {
  id: string;
  state: string;
  attempt?: number;
  mode?: string;
  last_error?: string;
  created_at?: string;
  attempt_history?: History[];
  progress?: { phase?: string; max_attempts?: number };
};

const active = new Set(['queued', 'running', 'claimed', 'compute_registered', 'awaiting_publication', 'source_verification', 'cancelling']);
const terminal = new Set(['succeeded', 'failed', 'cancelled']);

function dateText(value?: string) {
  return value ? new Date(value).toLocaleString('zh-CN') : '—';
}
function modeText(mode?: string) {
  return mode === 'dual_source_replay' ? '顺序回放' : '离线分析';
}
function phaseText(run: TaskRun) {
  return stateLabels[run.progress?.phase || run.state] || run.state;
}
function shortId(id: string) {
  return id.length > 12 ? id.slice(0, 8) + '…' : id;
}

export function TasksPanel({
  runs,
  selected,
  loading,
  error,
  canEdit,
  busy,
  realSource,
  onRefresh,
  onOpenDatasets,
  onOpen,
  onCancel,
  onRetry,
  onOpenResult,
  onCopy,
}: {
  runs: TaskRun[];
  selected: TaskRun | null;
  loading: boolean;
  error: string;
  canEdit: boolean;
  busy: boolean;
  realSource: boolean;
  onRefresh: () => void;
  onOpenDatasets: () => void;
  onOpen: (id: string) => void;
  onCancel: () => void;
  onRetry: () => void;
  onOpenResult: () => void;
  onCopy: (id: string) => void;
}) {
  const [stateFilter, setStateFilter] = useState('');
  const [phaseFilter, setPhaseFilter] = useState('');
  const [modeFilter, setModeFilter] = useState('');
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [narrow, setNarrow] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(true);
  useEffect(() => { setConfirmCancel(false); }, [selected?.id, selected?.state]);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 1024px)');
    const sync = () => setNarrow(media.matches);
    sync();
    media.addEventListener('change', sync);
    return () => media.removeEventListener('change', sync);
  }, []);
  useEffect(() => {
    const node = document.querySelector<HTMLElement>('[data-wb-drawer="tasks"]');
    if (!node) return;
    const close = () => {
      setDrawerOpen(false);
      document.querySelector<HTMLElement>('.wb-run-table tr.is-selected')?.focus();
    };
    node.addEventListener('wb-close', close);
    return () => node.removeEventListener('wb-close', close);
  }, [selected?.id, narrow, drawerOpen]);
  const filtered = useMemo(() => runs.filter(run => (!stateFilter || run.state === stateFilter) && (!phaseFilter || run.progress?.phase === phaseFilter) && (!modeFilter || (run.mode || 'dual_source') === modeFilter)), [runs, stateFilter, phaseFilter, modeFilter]);
  const live = filtered.filter(run => active.has(run.state));
  const history = filtered.filter(run => !active.has(run.state)).sort((a, b) => Date.parse(b.created_at || '') - Date.parse(a.created_at || ''));
  const detailOpen = Boolean(selected) && (!narrow || drawerOpen);
  return <section className="wb-tasks-wrap" aria-label="运行与历史">
    <PageToolbar title="任务中心">
    <div className="wb-tasks-toolbar">
      <button type="button" onClick={onRefresh} disabled={busy}>刷新历史</button>
      <label>状态<select aria-label="按状态筛选" value={stateFilter} onChange={event => setStateFilter(event.target.value)}><option value="">全部状态</option>{Object.entries(stateLabels).filter(([value]) => ['queued', 'running', 'cancelling', 'cancelled', 'failed', 'succeeded'].includes(value)).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>阶段<select aria-label="按阶段筛选" value={phaseFilter} onChange={event => setPhaseFilter(event.target.value)}><option value="">全部阶段</option>{Object.entries(stateLabels).filter(([value]) => ['claimed', 'compute_registered', 'awaiting_publication', 'source_verification'].includes(value)).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>模式<select aria-label="按模式筛选" value={modeFilter} onChange={event => setModeFilter(event.target.value)}><option value="">全部模式</option><option value="dual_source">离线分析</option><option value="dual_source_replay">顺序回放</option></select></label>
      <button type="button" onClick={onOpenDatasets}>选择输入与配置</button>
    </div>
    </PageToolbar>
    <details className="wb-budget">
      <summary>执行预算摘要 · 默认最多 4 个抓包、合计 16 MiB</summary>
      <p>默认预算：最多4个抓包、合计16 MiB/10000帧，CSV 2 MiB/1000逻辑记录；显式工程版本按服务端绑定的资源与配置预算执行，目前仅承诺已验S100范围，M/L未完成、不承诺支持。上传接收限额不等于执行限额。</p>
    </details>
    {realSource && <p className="wb-nature">真实来源保持待核验。仅在来源、授权、时间和映射材料齐全，且选择明确支持真实来源的软件配置时可运行；完成计算不表示真实适用性通过。</p>}
    {error && <p role="alert" className="wb-alert">刷新或读取失败。{error} 请重新核验访问权限；临时网络失败时保留的列表不代表最新状态。</p>}
    <div className="wb-tasks">
      <div>
        {loading ? <div className="wb-state" role="status"><span className="wb-pulse" aria-hidden="true" />{Array.from({ length: 5 }, (_, index) => <span key={index} className="wb-skeleton" />)}<p>正在读取运行…</p></div> : !filtered.length ? <div className="wb-empty"><p>{runs.length ? '当前筛选没有运行。' : '尚无运行。'}</p><button type="button" className="wb-primary" onClick={onOpenDatasets}>选择输入与配置</button></div> : <>
          <Group title="进行中" rows={live} selectedId={selected?.id || ''} onOpen={onOpen} />
          <Group title="历史" rows={history} selectedId={selected?.id || ''} onOpen={onOpen} />
        </>}
        {runs.length >= 200 && <p className="wb-clip">此列表显示最近 200 个运行。历史链接仍可按运行身份打开。</p>}
      </div>
      {narrow && selected && !drawerOpen && <button type="button" className="wb-sheet-reopen" onClick={() => setDrawerOpen(true)}>打开运行详情</button>}
      <section className="wb-card wb-run-detail" aria-label="运行详情" data-wb-drawer="tasks" data-open={narrow && detailOpen ? 'true' : 'false'} hidden={narrow && !detailOpen}>
        {!selected ? <p className="wb-empty">在左侧选择一次运行</p> : <Detail run={selected} canEdit={canEdit} busy={busy} confirmCancel={confirmCancel} narrow={narrow} onCopy={onCopy} onAskCancel={() => setConfirmCancel(true)} onKeep={() => setConfirmCancel(false)} onConfirmCancel={() => { setConfirmCancel(false); onCancel(); }} onRetry={onRetry} onOpenResult={onOpenResult} onClose={() => setDrawerOpen(false)} />}
      </section>
    </div>
  </section>;
}

function Group({ title, rows, selectedId, onOpen }: { title: string; rows: TaskRun[]; selectedId: string; onOpen: (id: string) => void }) {
  if (!rows.length) return null;
  return <div>
    <p className="wb-group-title">{title}</p>
    <div className="wb-table-wrap"><table className="wb-run-table">
      <thead><tr><th>状态</th><th>模式</th><th>创建</th><th>尝试</th><th>阶段</th><th>ID</th><th>操作</th></tr></thead>
      <tbody>{rows.map(run => <tr key={run.id} tabIndex={-1} className={run.id === selectedId ? 'is-selected' : ''} onClick={() => onOpen(run.id)}>
        <td><StatusChip state={run.state} label={stateLabels[run.state] || run.state} /></td>
        <td>{modeText(run.mode)}</td>
        <td>{dateText(run.created_at)}</td>
        <td className="tabular-nums">{run.attempt ?? 0}</td>
        <td className="wb-phase-cell">{run.progress?.phase && run.progress.phase !== run.state ? phaseText(run) : "—"}</td>
        <td><code title={run.id}>{shortId(run.id)}</code></td>
        <td><button type="button" aria-label={`查看运行 ${run.id}`} onClick={event => { event.stopPropagation(); onOpen(run.id); }}>详情</button></td>
      </tr>)}</tbody>
    </table></div>
  </div>;
}

function Detail({ run, canEdit, busy, confirmCancel, narrow, onCopy, onAskCancel, onKeep, onConfirmCancel, onRetry, onOpenResult, onClose }: {
  run: TaskRun;
  canEdit: boolean;
  busy: boolean;
  confirmCancel: boolean;
  narrow: boolean;
  onCopy: (id: string) => void;
  onAskCancel: () => void;
  onKeep: () => void;
  onConfirmCancel: () => void;
  onRetry: () => void;
  onOpenResult: () => void;
  onClose: () => void;
}) {
  const label = stateLabels[run.state] || run.state;
  const registered = run.attempt_history?.length ?? 0;
  const exited = run.attempt_history?.filter(item => item.exited_at).length ?? 0;
  const running = !terminal.has(run.state);
  return <div className="space-y-2 text-sm">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3>运行详情</h3>
      {narrow && <button type="button" className="wb-sheet-close" onClick={onClose}>关闭</button>}
    </div>
    <p><StatusChip state={run.state} label={phaseText(run)} /> {modeText(run.mode)}</p>
    <p className="break-all">{run.id} · {label} · attempt {run.attempt ?? 0} <button type="button" onClick={() => onCopy(run.id)}>复制运行标识</button></p>
    <p>阶段 · {phaseText(run)}。已登记 {registered} 次执行，已确认退出 {exited} 次。{run.progress?.max_attempts != null && <>本任务最多 {run.progress.max_attempts} 次执行。</>} 计算期间无实时帧或行计数，发布后可查看实际观测数。</p>
    {run.last_error && <p role="alert">{run.last_error}</p>}
    {running && canEdit && !confirmCancel && <button type="button" onClick={onAskCancel}>请求取消</button>}
    {running && canEdit && confirmCancel && <div role="group" aria-label="确认取消"><p>取消后将等待本次执行退出。确认取消这个任务？</p><button type="button" onClick={onConfirmCancel}>确认取消任务</button><button type="button" onClick={onKeep}>保留任务</button></div>}
    {running && !canEdit && <p className="wb-cta-reason">当前账号不能取消这个任务。</p>}
    {canEdit && (run.state === 'failed' || run.state === 'cancelled') && <button type="button" className="wb-primary" disabled={busy} onClick={onRetry}>重试此运行</button>}
    {run.state === 'succeeded' && <button type="button" className="wb-primary" onClick={onOpenResult}>{run.mode === 'dual_source_replay' ? '打开顺序回放' : '查看分析结果'}</button>}
    <details><summary>固定抓包顺序与尝试历史</summary><pre>{JSON.stringify(run, null, 2)}</pre></details>
  </div>;
}
