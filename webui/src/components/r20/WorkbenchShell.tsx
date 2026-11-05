import React, { useCallback, useEffect, useState } from 'react';
import { Section } from './navigation';
import { ContextRun } from './ContextBar';
import { DatasetDrawer } from './DatasetDrawer';
import { NavRail } from './NavRail';
import { TopBar } from './TopBar';

export function WorkbenchShell({
  user,
  busy,
  view,
  onLogout,
  datasetId,
  linkDataset,
  linkRun,
  datasetName,
  configLabel,
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
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [boundaryOpen, setBoundaryOpen] = useState(false);
  const [entering, setEntering] = useState(false);
  const closeDrawer = useCallback(() => {
    setDrawerOpen(false);
    document.getElementById('wb-open-dataset')?.focus();
  }, []);
  useEffect(() => {
    try { setNavCollapsed(window.localStorage.getItem('wb-nav-collapsed') === '1'); } catch { /* storage may be blocked */ }
  }, []);
  useEffect(() => {
    setEntering(true);
    const timer = window.setTimeout(() => setEntering(false), 240);
    return () => window.clearTimeout(timer);
  }, [view]);
  useEffect(() => { if (view === 'datasets' && user) setDrawerOpen(true); }, [view, user]);
  useEffect(() => {
    const open = () => setDrawerOpen(true);
    document.addEventListener('wb-open-datasets', open);
    return () => document.removeEventListener('wb-open-datasets', open);
  }, []);
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
      if (drawer) {
        event.preventDefault();
        drawer.dispatchEvent(new Event('wb-close'));
        if (drawer.dataset.wbDrawer === 'datasets') document.getElementById('wb-open-dataset')?.focus();
        return;
      }
      if (boundaryOpen) { event.preventDefault(); setBoundaryOpen(false); document.getElementById('wb-boundary-toggle')?.focus(); return; }
      document.dispatchEvent(new Event('wb-clear-selection'));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [view, boundaryOpen]);
  function toggleNav() {
    setNavCollapsed(value => {
      const next = !value;
      try { window.localStorage.setItem('wb-nav-collapsed', next ? '1' : '0'); } catch { /* ignore */ }
      return next;
    });
  }
  return <div className="wb-app">
    <TopBar user={user} busy={busy} datasetName={datasetName} configLabel={configLabel} run={run} phaseLabel={phaseLabel} boundaryOpen={boundaryOpen} onLogout={onLogout} onOpenDatasets={() => setDrawerOpen(true)} onOpenTasks={onOpenTasks} onClearRun={onClearRun} onCopyRun={onCopyRun} onCopyLink={onCopyLink} onToggleBoundary={() => setBoundaryOpen(value => !value)} />
    {boundaryOpen && <div className="wb-boundary" role="region" aria-label="研究范围说明" data-wb-boundary="true" data-open="true">
      <p>研究判读边界 · 任务完成表示软件执行成功。协议响应与工艺观测分别取证。协议响应不证明物理成功；时间接近不证明因果；候选关系保留支持、反证与未知，不证明攻击。物理效果需独立核验。</p>
    </div>}
    <div className={navCollapsed ? 'wb-frame is-nav-collapsed' : 'wb-frame'}>
      {user && <NavRail view={view} collapsed={navCollapsed} admin={user.role === 'admin'} datasetId={linkDataset || datasetId} runId={linkRun || run?.id} onNavigate={onNavigate} onToggle={toggleNav} />}
      <main id="wb-main" tabIndex={-1} data-view={view} className={entering ? 'wb-main is-entering' : 'wb-main'}>{children}</main>
    </div>
    {user && <DatasetDrawer open={drawerOpen} onClose={closeDrawer}>{directory}</DatasetDrawer>}
  </div>;
}
