export type Row = Record<string, any>;
export type HistoryProps = { runId: string; datasetId: string; onError: (message: string) => void };
export const number = (value: unknown) => typeof value === 'number' ? new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 5 }).format(value) : '未提供';
export const time = (value: unknown) => {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) return '未提供';
  return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(value)) + ' UTC';
};
export function snapshotCount(result: Row) {
  return result.counts?.snapshots ?? result.data?.replay?.snapshot_count ?? result.replay?.snapshot_count ?? 0;
}
export function visibleBacklog(samples: Row[], snapshot: Row) {
  return [...samples].reverse().find(row => row.arrival_seq <= snapshot.arrival_seq && Date.parse(row.available_at) <= Date.parse(snapshot.available_at));
}
export async function historicalBacklog(total: number, snapshot: Row, read: (index: number) => Promise<Row>) {
  let low = 0, high = total, selected: Row | null = null;
  while (low < high) {
    const middle = Math.floor((low + high) / 2), row = await read(middle);
    if (row.arrival_seq <= snapshot.arrival_seq && Date.parse(row.available_at) <= Date.parse(snapshot.available_at)) {
      selected = row; low = middle + 1;
    } else high = middle;
  }
  return selected;
}
export function normalizeRevisions(value: Row) {
  return { items: value.items ?? value.revisions ?? [], total: value.total ?? 0, returned: value.returned ?? (value.revisions?.length ?? 0) };
}
export function historySelection(search: string, key: 'snapshot' | 'evaluation', run: string, dataset: string) {
  const query = new URLSearchParams(search);
  if ([key, 'run', 'dataset'].some(name => query.getAll(name).length !== 1)) return '';
  if (query.get('run') !== run || query.get('dataset') !== dataset) return '';
  const value = query.get(key) ?? '';
  return (key === 'snapshot' ? /^(0|[1-9]\d{0,4})$/.test(value) && Number(value) < 65000 : /^[A-Za-z0-9_-]{1,100}$/.test(value)) ? value : '';
}
export function writeHistorySelection(key: 'snapshot' | 'evaluation', value: string, run: string, dataset: string) {
  const url = new URL(window.location.href);
  if (url.searchParams.get('run') !== run || url.searchParams.get('dataset') !== dataset) return;
  url.searchParams.set(key, value);
  if (url.href !== window.location.href) window.history.pushState(null, '', url);
}
export async function request(path: string, signal?: AbortSignal): Promise<any> {
  const response = await fetch('/api/v3' + path, { credentials: 'same-origin', signal });
  const value = await response.json();
  if (!response.ok) throw new Error(`${response.status} ${value.error?.code ?? 'request_failed'}：${value.error?.message ?? '请求失败，请重新核验'}`);
  return value;
}
export function sharedPath(action: string, logical: string, path: (string | number)[], offset = 0, limit = 10) {
  return '/shared-query?' + new URLSearchParams({ action, logical_root: logical, path: JSON.stringify(path), offset: String(offset), limit: String(limit) });
}

// Evaluation bundles retain the IDs of unmatched/reference events. Earlier
// versions may embed the event itself. Both forms address the same evidence API.
export function evaluationEvidenceTargets(row: Row, category: string) {
  const target = (key: string) => typeof key === 'string' && key ? {id: key} : undefined;
  const referenceOnly = category === 'false_negatives' || category === 'disputed_references';
  const event = target(row.event?.id ?? row.event_id);
  return {
    prediction: target(row.prediction?.id ?? row.prediction_id) ?? (!referenceOnly ? event : undefined),
    reference: target(row.reference?.id ?? row.reference_id) ?? (referenceOnly ? event : undefined),
  };
}
