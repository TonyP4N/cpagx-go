export const sections = {
  datasets: '数据与配置',
  tasks: '任务中心',
  analysis: '分析结果',
  replay: '顺序回放',
  evaluation: '独立评估',
  access: '用户与授权',
} as const;
export type Section = keyof typeof sections;

export function workbenchURL(view: Section, dataset = '', run = '') {
  const query = new URLSearchParams({view});
  if (dataset) query.set('dataset', dataset);
  if (run && dataset) query.set('run', run);
  return '/workbench/?' + query;
}

export function readLocation(search: string) {
  const query = new URLSearchParams(search);
  const raw = query.get('view') || '';
  const view = Object.prototype.hasOwnProperty.call(sections, raw) ? raw as Section : 'datasets';
  const id = (key: string) => /^[a-zA-Z0-9_-]{1,128}$/.test(query.get(key) || '') ? query.get(key)! : '';
  return {view, dataset: id('dataset'), run: id('run')};
}

export const stateLabels: Record<string, string> = {
  claimed: '已领取，准备计算', compute_registered: '计算已登记，等待退出', awaiting_publication: '计算已退出，等待核验发布', source_verification: '来源核验中', queued: '排队中', running: '执行中', cancelling: '等待执行退出', cancelled: '已取消',
  failed: '执行失败', succeeded: '执行完成',
};
