/** Bounded client projection; never establishes source trust or changes server facts. */
export type Row = Record<string, any>;
export type Selection = { kind: 'operation' | 'change' | 'candidate' | 'node'; id: string };
export type Filter = { text: string; kind: string; state: string; from: string; to: string };
export const EMPTY_FILTER: Filter = { text: '', kind: '', state: '', from: '', to: '' };
export const LIMITS = { nodes: 1000, edges: 3000, rows: 1000, page: 25 };
export const idOf = (row: Row) => String(row.candidate_id ?? row.operation_id ?? row.event_id ?? row.id ?? '');
export const stateOf = (row: Row) => String(row.replay?.status ?? row.assessment ?? row.state ?? row.candidate_state ?? 'unknown');
export const kindOf = (row: Row) => row.operation_id && !row.candidate_id ? 'operation' : row.candidate_id ? 'candidate' : 'change';
export function intervalOf(row: Row): number[] | null {
  const value = row.time?.interval ?? row.result?.interval ?? row.interval ?? row.window;
  if (Array.isArray(value) && value.length === 2 && value.every(Number.isFinite)) return value;
  const start = Date.parse(row.time_range?.start), end = Date.parse(row.time_range?.end);
  return Number.isFinite(start) && Number.isFinite(end) ? [start / 1000, end / 1000] : null;
}
export function matches(row: Row, filter: Filter): boolean {
  if (filter.kind && kindOf(row) !== filter.kind) return false;
  if (filter.state && stateOf(row) !== filter.state) return false;
  if (filter.text) {
    const haystack = [idOf(row), row.operation, row.source_endpoint, row.destination_endpoint, row.mapping?.asset_id, row.mapping?.tag, row.result?.asset_id, row.result?.tag, row.rule_id, ...(row.unknown_reasons ?? [])].join(' ').toLowerCase();
    if (!haystack.includes(filter.text.toLowerCase())) return false;
  }
  const from = filter.from ? Date.parse(filter.from) / 1000 : null, to = filter.to ? Date.parse(filter.to) / 1000 : null;
  if (from !== null || to !== null) {
    const time = intervalOf(row);
    // Unknown time cannot be silently included in a finite time selection.
    if (!time || (from !== null && time[1] < from) || (to !== null && time[0] > to)) return false;
  }
  return true;
}
export function boundedGraph(nodes: Row[], edges: Row[], rows: Row[], filter: Filter, nodeCap = 200, edgeCap = 600) {
  const filtering = Object.values(filter).some(Boolean);
  const ids = new Set<string>(), directEvents = new Set<string>();
  if (filtering) rows.filter(row => matches(row, filter)).forEach(row => {
    ids.add(idOf(row));
    if (!row.candidate_id) directEvents.add(idOf(row));
    if (row.candidate_id) { ids.add(row.operation_id); ids.add(row.change_id); }
    if (row.response?.event_id) ids.add(row.response.event_id);
    if (row.result) { ids.add(row.result.before_event_id); ids.add(row.result.after_event_id); }
  });
  const eligible = filtering ? nodes.filter(node => ids.has(node.event_id ?? node.id)) : nodes;
  const visible = eligible.slice(0, Math.min(nodeCap, LIMITS.nodes));
  const visibleIds = new Set(visible.map(node => node.id));
  const eligibleEdges = edges.filter(edge => visibleIds.has(edge.source) && visibleIds.has(edge.target) && (!filtering || ids.has(edge.claim_id ?? edge.id) || directEvents.has(edge.source) || directEvents.has(edge.target)) && (!filter.state || edge.candidate_state === filter.state || ids.has(edge.claim_id ?? edge.id)));
  return { nodes: visible, edges: eligibleEdges.slice(0, Math.min(edgeCap, LIMITS.edges)), eligibleNodes: eligible.length, eligibleEdges: eligibleEdges.length, clippedNodes: Math.max(0, eligible.length - visible.length), clippedEdges: Math.max(0, eligibleEdges.length - Math.min(edgeCap, LIMITS.edges)) };
}
export function aggregate(rows: Row[], dimension: 'state' | 'asset' | 'minute') {
  const groups = new Map<string, number>();
  rows.forEach(row => {
    const time = intervalOf(row);
    const key = dimension === 'state' ? stateOf(row) : dimension === 'asset' ? String(row.mapping?.asset_id ?? row.result?.asset_id ?? '未知资产') : time ? new Date(Math.floor(time[0] / 60) * 60000).toISOString() : '时间未知';
    groups.set(key, (groups.get(key) ?? 0) + 1);
  });
  return Array.from(groups, ([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}
/** Fixed lanes, linear cost, and no force-layout / animation work. */
export function positionGraph(nodes: Row[]) {
  const counters = [0, 0, 0];
  return nodes.map(node => {
    const lane = node.kind === 'network' ? 0 : node.kind === 'process' ? 2 : 1;
    const n = counters[lane]++, columns = nodes.length <= 80 ? 1 : 4;
    return { node, x: 90 + lane * 330 + (n % columns) * 45, y: 55 + Math.floor(n / columns) * (columns === 1 ? 40 : 30) };
  });
}
export function relatedSelection(node: Row, operations: Row[], changes: Row[]): Selection {
  const id = node.event_id ?? node.id;
  const op = operations.find(row => row.operation_id === id || row.response?.event_id === id);
  if (op) return { kind: 'operation', id: op.operation_id };
  const change = changes.find(row => row.event_id === id || [row.result?.before_event_id, row.result?.after_event_id].includes(id));
  return change ? { kind: 'change', id: change.event_id } : { kind: 'node', id: node.id };
}
