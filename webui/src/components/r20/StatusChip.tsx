const active = new Set(['queued', 'running', 'claimed', 'compute_registered', 'awaiting_publication', 'source_verification']);

function tone(state: string) {
  if (state === 'succeeded') return 'ok';
  if (state === 'failed') return 'danger';
  if (state === 'cancelling') return 'warn';
  if (active.has(state)) return 'active';
  return 'muted';
}

/** Stage text plus a tone. Succeeded means the software run finished, not a physical or attack result. */
export function StatusChip({ state, label }: { state: string; label: string }) {
  return <span className={`wb-chip wb-chip-${tone(state)}`}>{label}</span>;
}
