import React, { useEffect, useState } from 'react';
import { sections, Section, workbenchURL } from './navigation';
import { ContextBar, ContextRun } from './ContextBar';
import { DatasetRail } from './DatasetRail';

const resultViews = new Set<Section>(['analysis', 'replay', 'evaluation']);

export function WorkbenchShell({
  user,
  busy,
  view,
  onLogout,
  datasetId,
  linkDataset,
  linkRun,
  datasetName,
  datasetDetail,
  configLabel,
  configDetail,
  configTitle,
  run,
  phaseLabel,
  onNavigate,
  onOpenTasks,
  onClearRun,
  onCopyRun,
  onCopyLink,
  directory,
  children,
}: {
  user: { username: string; role: string } | null;
  busy: boolean;
  view: Section;
  onLogout: () => void;
  datasetId?: string;
  linkDataset?: string;
  linkRun?: string;
  datasetName: string;
  datasetDetail?: string;
  configLabel: string;
  configDetail?: string;
  configTitle?: string;
  run: ContextRun | null;
  phaseLabel: string;
  onNavigate: (view: Section) => void;
  onOpenTasks: () => void;
  onClearRun: () => void;
  onCopyRun: () => void;
  onCopyLink: () => void;
  directory: React.ReactNode;
  children: React.ReactNode;
}) {
  const preferCollapsed = resultViews.has(view);
  const [manual, setManual] = useState<boolean | null>(null);
  const [entering, setEntering] = useState(false);
  useEffect(() => { setManual(null); }, [view]);
  useEffect(() => {
    setEntering(true);
    const timer = window.setTimeout(() => setEntering(false), 240);
    return () => window.clearTimeout(timer);
  }, [view]);
  useEffect(() => {
    const editable = (target: EventTarget | null) => Boolean((target as HTMLElement | null)?.closest('input, textarea, select, [contenteditable="true"]'));
    const onKey = (event: KeyboardEvent) => {
      if (editable(event.target)) return;
      if (event.key === '/') {
        const field = view === 'analysis' ? document.querySelector<HTMLElement>('input[name="analysis-query"]') : view === 'replay' ? document.querySelector<HTMLElement>('input[name="replay-snapshot"]') : null;
        if (!field) return;
        event.preventDefault();
        field.focus();
        return;
      }
      if (event.key !== 'Escape') return;
      const drawer = document.querySelector<HTMLElement>('[data-wb-drawer][data-open="true"]');
      if (drawer) { event.preventDefault(); drawer.dispatchEvent(new Event('wb-close')); return; }
      const boundary = document.querySelector<HTMLDetailsElement>('.wb-boundary');
      if (boundary?.open) { event.preventDefault(); boundary.open = false; boundary.querySelector('summary')?.focus(); return; }
      document.dispatchEvent(new Event('wb-clear-selection'));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [view]);
  const collapsed = manual ?? preferCollapsed;
  function openDirectory() {
    setManual(false);
    window.setTimeout(() => document.getElementById('wb-dataset-search')?.focus(), 0);
  }
  return <>
    <header className="border-b"><div className="wb-header-bar">
      <div className="wb-brand"><span className="wb-mark" aria-hidden="true">C</span><div><h1>CPAG 分析工作台</h1><p className="text-sm">网络操作与工艺观测</p></div></div>
      <div className="flex items-center gap-3 text-sm">{user ? <><span aria-label="当前用户">{user.username} · {user.role}</span><button type="button" onClick={onLogout} disabled={busy}>退出登录</button></> : <span>请登录</span>}</div>
    </div></header>
    <details className="wb-boundary" aria-label="研究范围说明">
      <summary>研究判读边界 · 任务完成表示软件执行成功。候选关系保留支持、反证与未知 — 展开全文</summary>
      <p>协议响应与工艺观测分别取证。协议响应不证明物理成功；时间接近不证明因果；候选关系保留支持、反证与未知，不证明攻击。物理效果需独立核验。任务完成只表示软件执行完成。</p>
    </details>
    {user && <>
      <nav className="wb-nav" aria-label="工作区导航">{(Object.keys(sections) as Section[]).filter(key => key !== 'access' || user.role === 'admin').map(key =>
        <a key={key} href={workbenchURL(key, linkDataset || datasetId, linkRun || run?.id)} aria-current={key === view ? 'page' : undefined} onClick={event => {
          if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
          event.preventDefault();
          onNavigate(key);
        }}>{sections[key]}</a>)}
      </nav>
      <ContextBar datasetName={datasetName} datasetDetail={datasetDetail} configLabel={configLabel} configDetail={configDetail} configTitle={configTitle} run={run} phaseLabel={phaseLabel} onOpenDirectory={openDirectory} onOpenTasks={onOpenTasks} onClearRun={onClearRun} onCopyRun={onCopyRun} onCopyLink={onCopyLink} />
      <div className={`wb-shell${collapsed ? ' is-collapsed' : ''}`}>
        <DatasetRail collapsed={collapsed} onToggle={() => setManual(!collapsed)}>{directory}</DatasetRail>
        <main id="wb-main" tabIndex={-1} data-view={view} className={entering ? 'wb-main is-entering' : 'wb-main'}>
          {!resultViews.has(view) && <div className="wb-heading"><h2>{sections[view]}</h2></div>}
          {children}
        </main>
      </div>
    </>}
    {!user && <main id="wb-main" tabIndex={-1} className="wb-main">{children}</main>}
  </>;
}
