import React from 'react';
import { Section, sections, workbenchURL } from './navigation';

const marks: Record<Section, string> = {
  datasets: '数',
  tasks: '任',
  analysis: '析',
  replay: '回',
  evaluation: '评',
  access: '授',
};

export function NavRail({
  view,
  collapsed,
  admin,
  datasetId,
  runId,
  onNavigate,
  onToggle,
}: {
  view: Section;
  collapsed: boolean;
  admin: boolean;
  datasetId?: string;
  runId?: string;
  onNavigate: (view: Section) => void;
  onToggle: () => void;
}) {
  const keys = (Object.keys(sections) as Section[]).filter(key => key !== 'access' || admin);
  return <nav className={collapsed ? 'wb-navrail is-collapsed' : 'wb-navrail'} aria-label="工作区导航">
    {keys.map(key => <a key={key} href={workbenchURL(key, datasetId, runId)} aria-current={key === view ? 'page' : undefined} title={sections[key]} onClick={event => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      onNavigate(key);
    }}><span className="wb-nav-mark" aria-hidden="true">{marks[key]}</span><span className="wb-nav-label">{sections[key]}</span></a>)}
    <button type="button" className="wb-nav-pin" aria-pressed={collapsed} onClick={onToggle}>{collapsed ? '展开导航' : '收起导航'}</button>
  </nav>;
}
