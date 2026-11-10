import React, { useState } from 'react';
import { intervalOf, LIMITS, Row } from '../analysisModel';

export const control = 'min-h-[40px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 hover:border-slate-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-40';

const utcTime = new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3, hourCycle: 'h23', timeZone: 'UTC' });

export function timeText(row: Row) {
  const time = intervalOf(row);
  return time ? time.map(value => utcTime.format(new Date(value * 1000)) + ' UTC').join(' — ') : '时间依据不足';
}

export function Pager({ page, count, change }: { page: number; count: number; change: (page: number) => void }) {
  return <nav aria-label="记录分页" className="flex items-center gap-2 text-xs tabular-nums"><button type="button" className={control} disabled={page <= 0} onClick={() => change(page - 1)}>上一页</button><span>{count ? page * LIMITS.page + 1 : 0}–{Math.min((page + 1) * LIMITS.page, count)} / {count}</span><button type="button" className={control} disabled={(page + 1) * LIMITS.page >= count} onClick={() => change(page + 1)}>下一页</button></nav>;
}

export function JsonDetails({ value, label }: { value: unknown; label: string }) {
  const [open, setOpen] = useState(false);
  return <details onToggle={event => setOpen(event.currentTarget.open)}><summary className="wb-link cursor-pointer rounded text-sm">{label}</summary>{open && <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded p-3 text-xs">{JSON.stringify(value, null, 2)}</pre>}</details>;
}

export function DataNatureBar({ children }: { children: React.ReactNode }) {
  return <div className="wb-nature" role="note">{children}</div>;
}
