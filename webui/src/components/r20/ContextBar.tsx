import React from 'react';

export type ContextRun = {
  id: string;
  mode?: string;
  state: string;
  attempt?: number;
  progress?: { phase?: string };
};

export function ContextBar({
  datasetName,
  datasetDetail,
  configLabel,
  configDetail,
  configTitle,
  run,
  phaseLabel,
  onOpenDirectory,
  onOpenTasks,
  onClearRun,
  onCopyRun,
  onCopyLink,
}: {
  datasetName: string;
  datasetDetail?: string;
  configLabel: string;
  configDetail?: string;
  configTitle?: string;
  run: ContextRun | null;
  phaseLabel: string;
  onOpenDirectory: () => void;
  onOpenTasks: () => void;
  onClearRun: () => void;
  onCopyRun: () => void;
  onCopyLink: () => void;
}) {
  const mode = !run ? '尚未选择' : run.mode === 'dual_source_replay' ? '顺序回放' : '离线分析';
  return <section className="wb-context" aria-label="当前工作上下文">
    <div>
      <button type="button" className="wb-context-hit" onClick={onOpenDirectory}>
        <span>数据集 / 批次</span>
        <strong>{datasetName}</strong>
        {datasetDetail && <small>{datasetDetail}</small>}
      </button>
    </div>
    <div>
      <span>配置</span>
      <strong>{configLabel}</strong>
      {configDetail && <small title={configTitle || configDetail}>{configDetail}</small>}
    </div>
    <div>
      <span>当前运行</span>
      <strong>{mode}</strong>
      {run && <span className="wb-id-row"><code className="wb-id" title={run.id}>{run.id}</code><button type="button" onClick={onCopyRun}>复制运行标识</button></span>}
    </div>
    <div>
      <span>运行阶段</span>
      <strong>{phaseLabel}</strong>
      {run && <small>第 {run.attempt ?? 0} 次执行</small>}
    </div>
    <div className="wb-context-actions">
      <button type="button" onClick={onOpenTasks}>打开任务</button>
      <button type="button" onClick={onClearRun} disabled={!run}>清除运行选择</button>
      <button type="button" onClick={onCopyLink}>复制深链</button>
    </div>
  </section>;
}
