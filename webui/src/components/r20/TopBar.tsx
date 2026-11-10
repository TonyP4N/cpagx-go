import React from 'react';
import { ContextRun } from './ContextBar';
import { StatusChip } from './StatusChip';

export function TopBar({
  user,
  busy,
  datasetName,
  configLabel,
  run,
  phaseLabel,
  boundaryOpen,
  onLogout,
  onOpenDatasets,
  onOpenTasks,
  onClearRun,
  onCopyRun,
  onCopyLink,
  onToggleBoundary,
}: {
  user: { username: string; role: string } | null;
  busy: boolean;
  datasetName: string;
  configLabel: string;
  run: ContextRun | null;
  phaseLabel: string;
  boundaryOpen: boolean;
  onLogout: () => void;
  onOpenDatasets: () => void;
  onOpenTasks: () => void;
  onClearRun: () => void;
  onCopyRun: () => void;
  onCopyLink: () => void;
  onToggleBoundary: () => void;
}) {
  return <header className="wb-topbar">
    <div className="wb-brand"><span className="wb-mark" aria-hidden="true">C</span><h1>CPAG</h1></div>
    {user && <div className="wb-context-compact" aria-label="当前工作上下文">
      <button type="button" id="wb-open-dataset" onClick={onOpenDatasets}>{datasetName} ▾</button>
      <span className="wb-context-config" title={configLabel}>{configLabel}</span>
      <span className="wb-context-run" title={run?.id || ''}>{run ? run.id.slice(0, 8) + (run.id.length > 8 ? '…' : '') : '无运行'}</span>
      {run && <button type="button" onClick={onCopyRun}>复制</button>}
      <StatusChip state={run?.state || 'idle'} label={phaseLabel} />
      <button type="button" onClick={onClearRun} disabled={!run}>清运行</button>
      <button type="button" onClick={onCopyLink}>复制深链</button>
      <button type="button" onClick={onOpenTasks}>开任务</button>
    </div>}
    <div className="wb-top-actions">
      <button type="button" id="wb-boundary-toggle" aria-expanded={boundaryOpen} title="判读边界" onClick={onToggleBoundary}>判读边界</button>
      {user ? <><span aria-label="当前用户">{user.username}</span><button type="button" onClick={onLogout} disabled={busy}>退出</button></> : <span>请登录</span>}
    </div>
  </header>;
}
