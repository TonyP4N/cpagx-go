import React, { useEffect, useRef } from 'react';

export function DatasetDrawer({ open, onClose, children }: { open: boolean; onClose: () => void; children: React.ReactNode }) {
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    const node = panel.current;
    if (!node || !open) return;
    const close = () => onClose();
    node.addEventListener('wb-close', close);
    const field = node.querySelector<HTMLElement>('#wb-dataset-search');
    field?.focus();
    return () => node.removeEventListener('wb-close', close);
  }, [open, onClose]);
  if (!open) return null;
  return <>
    <button type="button" className="wb-drawer-mask" aria-label="关闭数据集目录" onClick={onClose} />
    <aside ref={panel} className="wb-drawer" aria-label="数据目录" data-wb-drawer="datasets" data-open="true">
      <div className="wb-drawer-head"><p className="wb-section-label">数据目录</p><button type="button" onClick={onClose}>关闭</button></div>
      {children}
    </aside>
  </>;
}
