import React, { useEffect, useRef } from 'react';

export function DatasetDrawer({ open, onClose, children }: { open: boolean; onClose: () => void; children: React.ReactNode }) {
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    const node = panel.current;
    if (!node || !open) return;
    const backgrounds = Array.from(document.querySelectorAll<HTMLElement>('.wb-topbar, .wb-frame, .wb-boundary'));
    const prior = backgrounds.map(el => el.inert);
    backgrounds.forEach(el => { el.inert = true; });
    const close = () => { backgrounds.forEach((el, i) => { el.inert = prior[i]; }); onClose(); };
    const key = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); return; }
      if (event.key !== 'Tab') return;
      const items = Array.from(node.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), a[href], [tabindex="0"]')).filter(el => el.getClientRects().length);
      const first = items[0], last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    node.addEventListener('keydown', key);
    node.addEventListener('wb-close', close);
    const field = node.querySelector<HTMLElement>('#wb-dataset-search');
    field?.focus();
    return () => { node.removeEventListener('wb-close', close); node.removeEventListener('keydown', key); backgrounds.forEach((el, i) => { el.inert = prior[i]; }); document.getElementById('wb-open-dataset')?.focus(); };
  }, [open, onClose]);
  if (!open) return null;
  return <>
    <button type="button" className="wb-drawer-mask" aria-label="关闭数据集目录" onClick={onClose} />
    <aside ref={panel} className="wb-drawer" role="dialog" aria-modal="true" aria-label="数据目录" data-wb-drawer="datasets" data-open="true">
      <div className="wb-drawer-head"><p className="wb-section-label">数据目录</p><button type="button" onClick={onClose}>关闭</button></div>
      {children}
    </aside>
  </>;
}
