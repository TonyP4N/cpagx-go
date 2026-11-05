import React, { useState } from 'react';

function dragSize(start: number, min: number, max: number, invert: boolean, event: React.PointerEvent, setSize: (value: number) => void) {
  const origin = event.clientX;
  const move = (ev: PointerEvent) => {
    const delta = ev.clientX - origin;
    const next = start + (invert ? -delta : delta);
    setSize(Math.min(max, Math.max(min, next)));
  };
  const up = () => {
    window.removeEventListener('pointermove', move);
    window.removeEventListener('pointerup', up);
  };
  window.addEventListener('pointermove', move);
  window.addEventListener('pointerup', up);
}

export function AnalysisBoard({
  timeline,
  candidates,
  timelineLabel = '时间线',
  candidatesLabel = '候选',
  extraTabs,
  stage,
  inspector,
  aggregate,
}: {
  timeline: React.ReactNode;
  candidates: React.ReactNode;
  timelineLabel?: string;
  candidatesLabel?: string;
  extraTabs?: { id: string; label: string; body: React.ReactNode }[];
  stage: React.ReactNode;
  inspector: React.ReactNode;
  aggregate?: React.ReactNode;
}) {
  const [dock, setDock] = useState(280);
  const [inspectorWidth, setInspectorWidth] = useState(360);
  const [tab, setTab] = useState('timeline');
  const [aggregateOpen, setAggregateOpen] = useState(false);
  const tabs = [{ id: 'timeline', label: timelineLabel }, { id: 'candidates', label: candidatesLabel }, ...(extraTabs ?? []).map(item => ({ id: item.id, label: item.label }))];
  return <div className="wb-board" style={{ ['--wb-dock' as string]: dock + 'px', ['--wb-insp' as string]: inspectorWidth + 'px' }}>
    <section className="wb-dock" aria-label="列表面板">
      <div className="wb-board-tabs" role="tablist">{tabs.map(item => <button key={item.id} type="button" role="tab" aria-selected={tab === item.id} onClick={() => setTab(item.id)}>{item.label}</button>)}</div>
      <div className="wb-dock-body" hidden={tab !== 'timeline'}>{timeline}</div>
      <div className="wb-dock-body" hidden={tab !== 'candidates'}>{candidates}</div>
      {(extraTabs ?? []).map(item => <div key={item.id} className="wb-dock-body" hidden={tab !== item.id}>{item.body}</div>)}
      <div className="wb-resize" role="separator" aria-orientation="vertical" aria-label="调整列表宽度" onPointerDown={event => dragSize(dock, 240, 360, false, event, setDock)} />
    </section>
    <section className="wb-stage">
      <div className="wb-stage-body">{stage}</div>
      {aggregate && <div className={aggregateOpen ? 'wb-agg is-open' : 'wb-agg'}>
        <button type="button" className="wb-agg-toggle" aria-expanded={aggregateOpen} onClick={() => setAggregateOpen(value => !value)}>{aggregateOpen ? '收起聚合' : '范围内聚合'}</button>
        {aggregate}
      </div>}
    </section>
    <section className="wb-insp">
      <div className="wb-resize wb-resize-insp" role="separator" aria-orientation="vertical" aria-label="调整证据宽度" onPointerDown={event => dragSize(inspectorWidth, 320, 420, true, event, setInspectorWidth)} />
      {inspector}
    </section>
  </div>;
}
