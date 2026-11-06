import React, { useState, useEffect, useRef, useId } from 'react';

function dragSize(start: number, min: number, max: number, invert: boolean, event: React.PointerEvent, setSize: (value: number) => void) {
  const origin = event.clientX;
  const move = (ev: PointerEvent) => setSize(Math.min(max, Math.max(min, start + (invert ? -1 : 1) * (ev.clientX - origin))));
  const up = () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); };
  window.addEventListener('pointermove', move); window.addEventListener('pointerup', up);
}
function Resize({ value, min, max, label, invert = false, onChange }: { value: number; min: number; max: number; label: string; invert?: boolean; onChange: (n: number) => void }) {
  return <div className={'wb-resize' + (invert ? ' wb-resize-insp' : '')} role="separator" aria-orientation="vertical" aria-label={label} tabIndex={0} aria-valuemin={min} aria-valuemax={max} aria-valuenow={value} onPointerDown={event => dragSize(value, min, max, invert, event, onChange)} onKeyDown={event => {
    const next = event.key === 'ArrowLeft' ? value - 20 : event.key === 'ArrowRight' ? value + 20 : event.key === 'Home' ? min : event.key === 'End' ? max : null;
    if (next !== null) { event.preventDefault(); onChange(Math.max(min, Math.min(max, next))); }
  }} />;
}
export function AnalysisBoard({ timeline, candidates, timelineLabel = '时间线', candidatesLabel = '候选', extraTabs, stage, inspector, aggregate, inspectorKey, contentFirst = false }: {
  timeline: React.ReactNode; candidates: React.ReactNode; timelineLabel?: string; candidatesLabel?: string;
  extraTabs?: { id: string; label: string; body: React.ReactNode }[];
  stage: React.ReactNode; inspector: React.ReactNode; aggregate?: React.ReactNode; inspectorKey?: string; contentFirst?: boolean;
}) {
  const uid = useId();
  const [dock, setDock] = useState(280), [inspectorWidth, setInspectorWidth] = useState(360);
  const [tab, setTab] = useState('timeline'), [aggregateOpen, setAggregateOpen] = useState(false), [inspectorOpen, setInspectorOpen] = useState(false);
  const inspectorRef = useRef<HTMLElement>(null), reopenRef = useRef<HTMLButtonElement>(null);
  const close = () => { setInspectorOpen(false); window.setTimeout(() => reopenRef.current?.focus(), 0); };
  useEffect(() => { if (inspectorKey) setInspectorOpen(true); }, [inspectorKey]);
  useEffect(() => { const node = inspectorRef.current; node?.addEventListener('wb-close', close); return () => node?.removeEventListener('wb-close', close); }, []);
  const tabs = [{ id: 'timeline', label: timelineLabel, body: timeline }, { id: 'candidates', label: candidatesLabel, body: candidates }, ...(extraTabs ?? [])];
  return <div className={`wb-board${!inspectorOpen ? ' inspector-closed' : ''}${contentFirst ? ' content-first' : ''}`} style={{ ['--wb-dock' as string]: dock + 'px', ['--wb-insp' as string]: inspectorWidth + 'px' }}>
    <section className="wb-dock" aria-label="列表面板">
      <div className="wb-board-tabs" role="tablist" aria-label="分析内容">{tabs.map((item, index) => <button key={item.id} id={`${uid}-${item.id}-tab`} type="button" role="tab" aria-controls={`${uid}-${item.id}-panel`} tabIndex={tab === item.id ? 0 : -1} aria-selected={tab === item.id} onClick={() => setTab(item.id)} onKeyDown={event => {
        const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : -1;
        if (next >= 0) { event.preventDefault(); setTab(tabs[next].id); document.getElementById(`${uid}-${tabs[next].id}-tab`)?.focus(); }
      }}>{item.label}</button>)}</div>
      {tabs.map(item => <div key={item.id} id={`${uid}-${item.id}-panel`} aria-labelledby={`${uid}-${item.id}-tab`} role="tabpanel" tabIndex={0} className="wb-dock-body" hidden={tab !== item.id}>{item.body}</div>)}
      <Resize value={dock} min={240} max={360} label="调整列表宽度" onChange={setDock} />
    </section>
    <section className="wb-stage"><div className="wb-stage-body">{stage}</div>{aggregate && <div className={aggregateOpen ? 'wb-agg is-open' : 'wb-agg'}><button type="button" className="wb-agg-toggle" aria-expanded={aggregateOpen} onClick={() => setAggregateOpen(value => !value)}>{aggregateOpen ? '收起聚合' : '范围内聚合'}</button>{aggregate}</div>}</section>
    <button ref={reopenRef} className="wb-evidence-reopen" type="button" hidden={inspectorOpen} onClick={() => setInspectorOpen(true)}>打开证据</button>
    <section ref={inspectorRef} className="wb-insp" hidden={!inspectorOpen} data-wb-drawer="inspector" data-open={inspectorOpen ? 'true' : 'false'} aria-label="证据面板">
      <button className="wb-evidence-close" type="button" onClick={close}>关闭证据</button>
      <Resize value={inspectorWidth} min={320} max={420} label="调整证据宽度" invert onChange={setInspectorWidth} />{inspector}
    </section>
  </div>;
}
