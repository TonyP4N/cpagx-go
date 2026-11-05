import React from 'react';

export function DatasetRail({ collapsed, onToggle, children }: { collapsed: boolean; onToggle: () => void; children: React.ReactNode }) {
  if (collapsed) {
    return <aside className="wb-rail" aria-label="数据目录">
      <button type="button" aria-expanded={false} onClick={onToggle}>数据目录 · 展开</button>
    </aside>;
  }
  return <aside className="wb-sidebar space-y-5" aria-label="数据目录">
    <div className="flex items-center justify-between gap-2">
      <p className="wb-section-label">数据目录</p>
      <button type="button" className="text-sm underline" aria-expanded={true} onClick={onToggle}>收起</button>
    </div>
    {children}
  </aside>;
}
