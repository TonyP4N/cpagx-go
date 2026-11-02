import React, { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import Head from 'next/head';
import dynamic from 'next/dynamic';
const Analysis = dynamic(() => import('../components/r20/Analysis'), { loading: () => <p role="status">正在打开分析结果…</p> });
const Replay = dynamic(() => import('../components/r20/Replay'), { loading: () => <p role="status">正在打开回放…</p> });
const Evaluation = dynamic(() => import('../components/r20/Evaluation'), { loading: () => <p role="status">正在打开评估…</p> });
import ConfigDetails from '../components/r20/ConfigDetails';
import { sections, Section, readLocation, workbenchURL, stateLabels } from '../components/r20/navigation';

type Row = Record<string, any>;
type User = { id: string; username: string; role: 'admin' | 'analyst' | 'viewer' };
type Dataset = { id: string; name: string; source_kind: 'synthetic' | 'real'; verification_status?: string; source?: string; batch?: string; authorization_ref?: string; access?: string; created_at?: string };
type FileRow = { id: string; role: string; filename?: string; name?: string; sha256: string; size_bytes: number };
type Config = { id: string; kind: 'intake' | 'dual'; version: number; profile_sha256?: string; config_fingerprint?: string; created_at?: string };
type Run = { id: string; dataset_id: string; state: string; attempt?: number; config_version_id?: string; mode?: string; last_error?: string; attempt_history?: Row[]; progress?: {phase: string; attempts_registered: number; executions_exited: number; max_attempts: number; processed_records: null}; network_file_ids?: string[]; created_at?: string };
type Preflight = { id: string; config_version_id?: string; snapshot_status?: string; snapshot_sha256?: string; snapshot_reason?: string; created_at?: string; report?: Row; snapshot?: Row };

const API = '/api/v3';

class RequestError extends Error {
  constructor(public status: number, public code: string, message: string, public data?: Row) { super(message); }
}

async function request<T = Row>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(API + path, { ...init, credentials: 'same-origin', headers: { ...(init.body && typeof init.body === 'string' ? { 'Content-Type': 'application/json' } : {}), ...init.headers } });
  const raw = await response.text();
  let value: any;
  try { value = raw ? JSON.parse(raw) : {}; } catch { value = { error: { message: raw || response.statusText } }; }
  if (!response.ok) {
    if (response.status === 401 && path !== '/session') window.dispatchEvent(new Event('cpag-session-expired'));
    throw new RequestError(response.status, value?.error?.code ?? 'request_failed', value?.error?.message ?? response.statusText, value);
  }
  return value as T;
}

const remedies: Record<string, string> = {
  retry_binding_unverified: '旧运行缺少原始提交门禁记录，请先进行预检，再创建新运行。',
  retry_conflict: '无法重试。请刷新执行历史，检查终态、退出证明和剩余执行次数。',
  retry_input_invalid: '原件、配置或执行策略校验失败。请核对固定输入后再提交。',
  preflight_stale: '预检对应的原件已经变更，请重新运行接收预检。',
  preflight_required: '请先选择接收配置，运行预检，再选择双源配置提交。',
  forbidden: '当前账号无写入权限。请联系管理员核对数据集授权。',
  not_found: '记录不可访问。请核对数据集、运行和当前账号授权。',
};
function message(error: unknown): string {
  if (error instanceof RequestError && remedies[error.code]) return remedies[error.code] + ' (' + error.status + ' ' + error.code + ')';
  if (error instanceof RequestError) return `${error.status} ${error.code}：${error.message}`;
  return error instanceof Error ? error.message : String(error);
}

function json(document: unknown): RequestInit { return { method: 'POST', body: JSON.stringify(document) }; }
function date(value?: string): string { return value ? new Date(value).toLocaleString('zh-CN') : '—'; }
function codeText(value?: string): string { return value || '未提供'; }

export default function WorkspacePage() { return <Workspace />; }

export function Workspace({workbench = false}: {workbench?: boolean}) {
  const [view, setView] = useState<Section>('datasets');
  const [creating, setCreating] = useState(false);
  const [loadingDataset, setLoadingDataset] = useState(false);
  const [loadingRun, setLoadingRun] = useState(false);
  const dataVersion = useRef(0);
  const runVersion = useRef(0);
  const [configError, setConfigError] = useState('');
  const [directoryFilter, setDirectoryFilter] = useState('');
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [dataset, setDataset] = useState<Dataset | null>(null);
  const [files, setFiles] = useState<FileRow[]>([]);
  const [configs, setConfigs] = useState<Config[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [selectedRun, setSelectedRun] = useState<Run | null>(null);
  const [preflight, setPreflight] = useState<Row | null>(null);
  const [preflightId, setPreflightId] = useState('');
  const [preflightConfigId, setPreflightConfigId] = useState('');
  const [preflights, setPreflights] = useState<Preflight[]>([]);
  const [historicalPreflight, setHistoricalPreflight] = useState<Row | null>(null);
  const [name, setName] = useState('');
  const [sourceKind, setSourceKind] = useState<'synthetic' | 'real'>('synthetic');
  const [source, setSource] = useState('');
  const [batch, setBatch] = useState('');
  const [authorizationRef, setAuthorizationRef] = useState('');
  const [uploadRole, setUploadRole] = useState<'network' | 'process'>('network');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [configKind, setConfigKind] = useState<'intake' | 'dual'>('intake');
  const [configText, setConfigText] = useState('');
  const [configId, setConfigId] = useState('');
  const [runMode, setRunMode] = useState('dual_source');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [users, setUsers] = useState<User[]>([]);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<User['role']>('viewer');
  const [aclUserId, setAclUserId] = useState('');
  const [aclAccess, setAclAccess] = useState<'viewer' | 'analyst'>('viewer');
  const selectedDataset = useRef('');
  const selectedRunId = useRef('');

  const canEdit = Boolean(user && user.role !== 'viewer' && dataset && (user.role === 'admin' || (dataset.access === 'analyst' || dataset.access === 'owner')));
  const canCreateDataset = Boolean(user && user.role !== 'viewer');

  const loadDatasets = useCallback(async () => {
    const value = await request<{ datasets: Dataset[] }>('/datasets');
    setDatasets(value.datasets ?? []);
  }, []);

  const loadDataset = useCallback(async (id: string, keepPreflight = false) => {
    const generation = ++dataVersion.current;
    ++runVersion.current;
    setLoadingDataset(true); setLoadingRun(false); setConfirmCancel(false);
    setPreflights([]); setHistoricalPreflight(null); setConfigError('');
    if (selectedDataset.current !== id) {setConfigText(''); setUploadFile(null); setNotice('');}
    selectedDataset.current = id;
    selectedRunId.current = '';
    setDataset(null); setFiles([]); setConfigs([]); setRuns([]); setSelectedRun(null); setConfigId(''); setError('');
    if (!keepPreflight) { setPreflight(null); setPreflightId(''); setPreflightConfigId(''); setHistoricalPreflight(null); }
    try {
      const [detail, history, checks] = await Promise.all([
        request<{ dataset: Dataset; files: FileRow[]; configs: Config[] }>(`/datasets/${encodeURIComponent(id)}`),
        request<{ runs: Run[] }>(`/runs?dataset_id=${encodeURIComponent(id)}`),
        request<{ preflights: Preflight[] }>(`/datasets/${encodeURIComponent(id)}/preflights`),
      ]);
      if (dataVersion.current !== generation) return;
      if (detail.dataset.id !== id) throw new Error('数据集响应身份不一致，请重新选择。');
      setDataset(detail.dataset); setFiles(detail.files ?? []); setConfigs(detail.configs ?? []); setRuns(history.runs ?? []); setPreflights(checks.preflights ?? []);
    } catch (cause) { if (dataVersion.current === generation) setError(message(cause)); }
    finally { if (dataVersion.current === generation) setLoadingDataset(false); }
  }, []);

  const loadRun = useCallback(async (id: string) => {
    const generation = ++runVersion.current;
    const expectedDataset = selectedDataset.current;
    if (selectedRunId.current !== id) {setSelectedRun(null); setConfirmCancel(false); setError('');}
    setLoadingRun(true);
    selectedRunId.current = id;
    try {
      const value = await request<{ run: Run }>(`/runs/${encodeURIComponent(id)}`);
      if (runVersion.current !== generation || selectedDataset.current !== expectedDataset) return;
      if (value.run.dataset_id !== expectedDataset) throw new Error('运行与所选数据集不匹配，请从任务列表重新选择。');
      setSelectedRun(value.run);
      setRuns(previous => previous.map(item => item.id === id ? {...item, ...value.run} : item));
    } catch (cause) { if (runVersion.current === generation) {setSelectedRun(null); setError(message(cause));} }
    finally { if (runVersion.current === generation) setLoadingRun(false); }
  }, []);

  useEffect(() => {
    let active = true;
    request<{ user: User }>('/session').then(value => {
      if (!active) return;
      setUser(value.user);
      void loadDatasets().catch(cause => setError(message(cause)));
    }).catch(cause => { if (active && !(cause instanceof RequestError && cause.status === 401)) setError(message(cause)); }).finally(() => { if (active) setChecking(false); });
    return () => { active = false; };
  }, [loadDatasets]);

  useEffect(() => {
    if (!user || user.role !== 'admin') return;
    request<{ users: User[] }>('/users').then(value => setUsers(value.users ?? [])).catch(cause => setError(message(cause)));
  }, [user]);

  useEffect(() => {
    if (!selectedRun || ['succeeded', 'failed', 'cancelled'].includes(selectedRun.state)) return;
    const timer = window.setInterval(() => { void loadRun(selectedRun.id); }, 2000);
    return () => window.clearInterval(timer);
  }, [selectedRun, loadRun]);

  function navigate(next: Section, ds = selectedDataset.current, run = selectedRunId.current) {
    if (!workbench) return;
    const nextURL = workbenchURL(next, ds, run);
    if (location.pathname + location.search !== nextURL) history.pushState(null, '', nextURL);
    setView(next); setError(''); setNotice('');
  }

  function openDataset(id: string) {
    if (workbench && selectedDataset.current !== id && configText.trim() &&
        !window.confirm('当前配置草稿尚未保存。切换数据集并放弃草稿？')) return;
    navigate(['analysis', 'replay', 'evaluation'].includes(view) ? 'tasks' : view, id, '');
    setCreating(false);
    void loadDataset(id);
  }

  function openRun(id: string) {
    navigate('tasks', selectedDataset.current, id);
    void loadRun(id);
  }

  useEffect(() => {
    if (!workbench || !user) return;
    let alive = true;
    const restore = async () => {
      const target = readLocation(location.search);
      setView(target.view); setError(''); setNotice(''); setCreating(false);
      if (!target.dataset) {
        ++dataVersion.current; ++runVersion.current;
        selectedDataset.current = ''; selectedRunId.current = '';
        setDataset(null); setSelectedRun(null); setRuns([]); setLoadingDataset(false); setLoadingRun(false); setConfigId(''); setFiles([]); setConfigs([]); setPreflight(null); setPreflightId(''); setPreflights([]);
        return;
      }
      const pending = loadDataset(target.dataset);
      const version = dataVersion.current;
      await pending;
      if (alive && dataVersion.current === version && target.run) await loadRun(target.run);
    };
    void restore();
    window.addEventListener('popstate', restore);
    return () => {alive = false; window.removeEventListener('popstate', restore);};
  }, [workbench, user, loadDataset, loadRun]);

  useEffect(() => {
    if (!workbench || !dataset || !user) return;
    const id = dataset.id;
    const check = async () => {
      const generation = dataVersion.current;
      try {
        const value = await request<{dataset: Dataset}>(`/datasets/${encodeURIComponent(id)}`);
        if (selectedDataset.current === id && generation === dataVersion.current) setDataset(value.dataset);
      } catch (cause) {
        if (selectedDataset.current !== id || generation !== dataVersion.current) return;
        ++dataVersion.current; ++runVersion.current;
        selectedDataset.current = ''; selectedRunId.current = '';
        setSelectedRun(null); setDataset(null); setRuns([]); setDatasets([]); setError(message(cause));
        if (cause instanceof RequestError && cause.status === 401) setUser(null);
      }
    };
    window.addEventListener('focus', check);
    return () => window.removeEventListener('focus', check);
  }, [workbench, dataset?.id, user]);

  async function refreshRuns() {
    const id = selectedDataset.current;
    if (!id) return;
    await act('刷新历史', async () => {
      let value;
      try { value = await request<{runs: Run[]}>(`/runs?dataset_id=${encodeURIComponent(id)}`); }
      catch (cause) {
        if (selectedDataset.current === id) { ++runVersion.current; selectedRunId.current = ''; setRuns([]); setSelectedRun(null); }
        throw cause;
      }
      if (selectedDataset.current !== id) return;
      setRuns(value.runs || []);
      if (selectedRunId.current) await loadRun(selectedRunId.current);
    });
  }

  useEffect(() => {
    const expired = () => {
      ++dataVersion.current; ++runVersion.current;
      selectedDataset.current = ''; selectedRunId.current = '';
      setUser(null); setDataset(null); setSelectedRun(null); setRuns([]); setDatasets([]); setFiles([]);
      setError('登录已过期。请重新登录后检查数据集权限。');
    };
    window.addEventListener('cpag-session-expired', expired);
    return () => window.removeEventListener('cpag-session-expired', expired);
  }, []);

  async function retryRun() {
    if (!selectedRun) return;
    const {id, attempt} = selectedRun;
    await act('重新排队', async () => {
      await request(`/runs/${encodeURIComponent(id)}/retry`, json({expected_attempt: attempt}));
      if (selectedRunId.current !== id) return;
      await loadRun(id);
      setNotice('原任务已重新排队。Worker 领取时登记下一次执行。');
    });
  }

  useEffect(() => {
    if (!workbench || !configText.trim()) return;
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = ''; };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [workbench, configText]);

  async function act(label: string, action: () => Promise<void>) {
    setBusy(label); setError(''); setNotice('');
    try { await action(); } catch (cause) { setError(message(cause)); }
    finally { setBusy(''); }
  }

  async function login(event: React.FormEvent) {
    event.preventDefault();
    await act('登录', async () => {
      const value = await request<{ user: User }>('/session', json({ username, password }));
      setUser(value.user); setPassword(''); setNotice(`已登录：${value.user.username}`);
      await loadDatasets();
    });
  }

  async function logout() {
    await act('退出登录', async () => {
      await request('/session', { method: 'DELETE' });
      ++dataVersion.current; ++runVersion.current; selectedDataset.current = ''; selectedRunId.current = ''; navigate('datasets', '', ''); setUser(null); setDatasets([]); setDataset(null); setFiles([]); setConfigs([]); setRuns([]); setSelectedRun(null); setPreflight(null); setPreflightId(''); setPreflightConfigId(''); setPreflights([]); setHistoricalPreflight(null); setUsers([]);
      setNotice('已退出登录。');
    });
  }

  async function createDataset(event: React.FormEvent) {
    event.preventDefault();
    await act('创建数据集', async () => {
      const value = await request<{ dataset: Dataset }>('/datasets', json({ name, source_kind: sourceKind, source, batch, authorization_ref: authorizationRef }));
      setName(''); setSource(''); setBatch(''); setAuthorizationRef('');
      navigate('datasets', value.dataset.id, ''); setCreating(false); await loadDatasets(); await loadDataset(value.dataset.id); setNotice('数据集已创建；来源状态仍需预检与人工核验。');
    });
  }

  async function upload(event: React.FormEvent) {
    event.preventDefault();
    if (!dataset || !uploadFile) return;
    const id = dataset.id;
    await act('上传文件', async () => {
      if (!window.crypto?.subtle) throw new Error('当前浏览器无法计算 SHA-256。');
      const digest = await window.crypto.subtle.digest('SHA-256', await uploadFile.arrayBuffer());
      const sha256 = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
      const query = new URLSearchParams({ role: uploadRole, name: uploadFile.name });
      await request(`/datasets/${encodeURIComponent(id)}/files?${query}`, { method: 'POST', body: uploadFile, headers: { 'Content-Type': 'application/octet-stream', 'X-Content-SHA256': sha256, 'Idempotency-Key': window.crypto.randomUUID() } });
      if (selectedDataset.current !== id) return; setUploadFile(null); navigate('datasets', id, ''); await loadDataset(id); setNotice('原件已上传并校验哈希；请对当前文件重新预检。');
    });
  }

  async function createConfig(event: React.FormEvent) {
    event.preventDefault();
    if (!dataset) return;
    const id = dataset.id;
    await act('保存配置', async () => {
      let document: Row;
      try { document = JSON.parse(configText); setConfigError(''); } catch { setConfigError('配置必须是有效 JSON。请检查引号与逗号。'); throw new Error('配置必须是有效 JSON。'); }
      if (!document || Array.isArray(document) || typeof document !== 'object') throw new Error('配置必须是 JSON 对象。');
      const value = await request<{ config: Config }>(`/datasets/${encodeURIComponent(id)}/configs`, json({ kind: configKind, document }));
      if (selectedDataset.current !== id) return; if (workbench) setConfigText(''); navigate('datasets', id, ''); await loadDataset(id, configKind === 'dual'); setConfigId(value.config.id); setNotice(`已保存不可变配置版本 ${value.config.version}。`);
    });
  }

  async function validate() {
    if (!dataset || !configId || configs.find(item => item.id === configId)?.kind !== 'intake') return;
    const id = dataset.id;
    await act('预检', async () => {
      try {
        const value = await request<{ report: Row; preflight_id: string }>(`/datasets/${encodeURIComponent(id)}/preflight`, json({ config_version_id: configId }));
        if (selectedDataset.current !== id) return;
        setPreflight({ ...value.report, preflight_id: value.preflight_id }); setPreflightId(value.preflight_id); setPreflightConfigId(configId);
        setNotice('预检已完成；报告中的待核事项仍需处理。');
      } catch (cause) {
        if (selectedDataset.current !== id) return;
        if (cause instanceof RequestError && cause.data?.preflight_id && cause.data?.report) {
          setPreflight({ ...cause.data.report, preflight_id: cause.data.preflight_id });
          setPreflightId(cause.data.preflight_id); setPreflightConfigId(configId);
        }
        throw cause;
      } finally {
        try {
          const checks = await request<{ preflights: Preflight[] }>(`/datasets/${encodeURIComponent(id)}/preflights`);
          if (selectedDataset.current === id) setPreflights(checks.preflights ?? []);
        } catch { /* preserve the original preflight response and its reason */ }
      }
    });
  }

  async function showHistoricalPreflight(id: string) {
    if (!dataset) return;
    await act('查看历史预检', async () => {
      const value = await request<{ preflight: Preflight }>(`/datasets/${encodeURIComponent(dataset.id)}/preflights/${encodeURIComponent(id)}`);
      if (selectedDataset.current !== dataset.id) return;
      setHistoricalPreflight({ ...value.preflight?.report, preflight_id: id, snapshot_status: value.preflight?.snapshot_status, snapshot_sha256: value.preflight?.snapshot_sha256, snapshot_reason: value.preflight?.snapshot_reason, snapshot: value.preflight?.snapshot });
    });
  }

  async function submitRun() {
    if (!dataset || !configId) return;
    const id = dataset.id;
    await act('提交运行', async () => {
      const value = await request<{ run: Run }>('/runs', json({ dataset_id: id, config_version_id: configId, preflight_id: preflightId, mode: runMode }));
      if (selectedDataset.current !== id) return; navigate('tasks', id, value.run.id); await loadDataset(id, true); await loadRun(value.run.id); setNotice(`运行已提交：${value.run.id}`);
    });
  }

  async function cancelRun() {
    if (!selectedRun) return;
    const id = selectedRun.id;
    await act('取消运行', async () => { await request(`/runs/${encodeURIComponent(id)}/cancel`, json({})); if (selectedRunId.current === id) {await loadRun(id); setNotice('取消请求已提交。');} });
  }

  async function download(path: string, filename: string) {
    await act('下载', async () => {
      const response = await fetch(API + path, { credentials: 'same-origin' });
      if (!response.ok) {
        let detail: Row = {};
        try { detail = await response.json(); } catch { /* server error may be plain text */ }
        throw new RequestError(response.status, detail?.error?.code ?? 'download_failed', detail?.error?.message ?? response.statusText);
      }
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }

  async function createUser(event: React.FormEvent) {
    event.preventDefault();
    await act('创建用户', async () => {
      await request('/users', json({ username: newUsername, password: newPassword, role: newRole }));
      const value = await request<{ users: User[] }>('/users'); setUsers(value.users ?? []);
      setNewUsername(''); setNewPassword(''); setNotice('用户已创建。');
    });
  }

  async function grantAcl(event: React.FormEvent) {
    event.preventDefault();
    if (!dataset) return;
    await act('授权数据集', async () => {
      await request(`/datasets/${encodeURIComponent(dataset.id)}/acl`, json({ user_id: aclUserId, access: aclAccess }));
      setNotice('数据集权限已更新。');
    });
  }

  if (checking) return <main className="min-h-screen grid place-items-center text-slate-700" aria-live="polite">正在检查登录状态…</main>;

  const showData = !workbench || view === 'datasets';
  const showTasks = !workbench || view === 'tasks';
  const showAccess = !workbench || view === 'access';
  const visibleDatasets = workbench ? datasets.filter(item => [item.name,item.batch,item.source].some(value => value?.toLowerCase().includes(directoryFilter.trim().toLowerCase()))) : datasets;
  const currentConfig = configs.find(item => item.id === (selectedRun?.config_version_id || configId));
  return <div className={`min-h-screen bg-slate-50 text-slate-800 ${workbench ? 'workbench' : ''}`}>
    <Head><title>{workbench ? 'CPAG · 双源分析工作台' : 'CPAG 研究工作台'}</title></Head>
    {workbench && <a className="wb-skip" href="#wb-main">跳至主工作区</a>}
    <header className="border-b border-slate-200 bg-white"><div className="mx-auto max-w-7xl px-5 py-4 flex flex-wrap items-center justify-between gap-3">
      <div className="wb-brand">{workbench && <span className="wb-mark" aria-hidden="true">C</span>}<div><h1 className="text-2xl font-bold">{workbench ? 'CPAG 分析工作台' : 'CPAG 研究工作台'}</h1><p className="text-sm text-slate-500">{workbench ? '网络操作与工艺观测' : '数据接收、证据核查与有界双源运行'}</p></div></div>
      {!workbench && <Link href="/workbench/" className="rounded border px-4 py-2 text-emerald-800">进入统一分析工作台 →</Link>}
      <div className="flex items-center gap-3 text-sm">{user ? <><span aria-label="当前用户">{user.username} · {user.role}</span><button type="button" onClick={logout} disabled={Boolean(busy)} className="rounded-lg border px-3 py-2">退出登录</button></> : <span>请登录</span>}</div>
    </div></header>
    <main id="wb-main" tabIndex={-1} className="mx-auto max-w-7xl px-5 py-6 space-y-5">
      {workbench && user && <>
        <nav className="wb-nav" aria-label="工作区导航">{(Object.keys(sections) as Section[]).filter(k => k !== 'access' || user.role === 'admin').map(k =>
          <a key={k} href={workbenchURL(k, dataset?.id, selectedRun?.id)} aria-current={k===view ? 'page' : undefined} onClick={e => {
            if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
            e.preventDefault(); navigate(k, dataset?.id, selectedRun?.id);
          }}>{sections[k]}</a>)}</nav>
        <section className="wb-context" aria-label="当前工作上下文">
          <div><span>数据集 / 批次</span><strong>{dataset?.name || '请选择数据集'}</strong>{dataset && <small>{dataset.batch || '批次未声明'} · {dataset.source_kind === 'synthetic' ? '合成数据' : '真实来源 · 适用性未验证'}</small>}</div>
          <div><span>当前运行</span><strong>{selectedRun ? (selectedRun.mode === 'dual_source_replay' ? '顺序回放' : '离线分析') : '尚未选择'}</strong>{selectedRun && <code>{selectedRun.id}</code>}</div>
          <div><span>{selectedRun ? '运行绑定配置' : '待提交配置'}</span><strong>{currentConfig ? currentConfig.kind+' · v'+currentConfig.version : '尚未选择'}</strong></div>
          <div><span>运行阶段</span><strong>{selectedRun ? stateLabels[selectedRun.progress?.phase || selectedRun.state] || selectedRun.state : '—'}</strong>{selectedRun && <small>第 {selectedRun.attempt ?? 0} 次执行</small>}</div>
        </section>
      </>}
      {error && <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-red-800 break-all">{error}{workbench && <span className="block">检查当前选择和数据权限后重试。</span>}</p>}
      {notice && <p role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-emerald-900 break-all">{notice}</p>}
      {!user ? <section className="mx-auto max-w-md rounded-xl border bg-white p-6 space-y-4" aria-label="登录"><h2 className="text-xl font-semibold">登录</h2><form onSubmit={login} className="space-y-3">
        <label className="block text-sm">用户名<input aria-label="用户名" name="username" spellCheck={false} required value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" className="mt-1 w-full rounded border p-2" /></label>
        <label className="block text-sm">密码<input aria-label="密码" name="password" required type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" className="mt-1 w-full rounded border p-2" /></label>
        <button type="submit" disabled={Boolean(busy)} className="rounded bg-emerald-700 px-4 py-2 text-white disabled:bg-slate-400">登录</button>
      </form></section> : <>
        <section className="wb-boundary rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm" aria-label="研究范围说明">{workbench ? '研究判读边界 · 任务完成表示软件执行成功。协议响应与工艺观测分别取证，候选关系保留支持、反证与未知。物理效果、因果和攻击均需独立核验。' : '真实文件可接收并检查元数据与完整性；运行须满足服务端来源、授权、映射和时间门禁，真实适用性仍待验证。预检通过不代表来源、设备映射或工业结果已核验。关系候选只说明证据支持情况。'}</section>
        <div className="grid gap-5 lg:grid-cols-[20rem_1fr]">
          <aside className="space-y-5 wb-sidebar">
            {workbench && <p className="wb-section-label">数据目录</p>}
            <section className="rounded-xl border bg-white p-4 space-y-3" aria-label="数据集列表"><div className="flex items-center justify-between"><h2 className="text-lg font-semibold">数据集</h2><button type="button" onClick={() => void loadDatasets().catch(cause => setError(message(cause)))} className="text-sm underline">刷新</button></div>
              {workbench && datasets.length >= 500 && <p>目录最多列出最近 500 个可访问数据集。</p>}{workbench && datasets.length > 0 && <label className="block text-xs">查找批次或数据集<input type="search" name="dataset-search" autoComplete="off" placeholder="输入名称或批次…" value={directoryFilter} onChange={e => setDirectoryFilter(e.target.value)} className="mt-1 w-full rounded border p-2 text-sm" /></label>}
              {visibleDatasets.length ? <ul className="space-y-2">{visibleDatasets.map(item => <li key={item.id}><button type="button" aria-label={`打开数据集 ${item.name}`} onClick={() => openDataset(item.id)} className={`w-full rounded-lg border p-3 text-left text-sm ${dataset?.id === item.id ? 'border-emerald-500 bg-emerald-50' : 'border-slate-200'}`}><span className="block font-medium">{item.name}</span><span className="block text-slate-500">{workbench ? (item.source_kind === 'synthetic' ? '合成数据' : '真实来源 · 待核验') : item.source_kind + ' · ' + (item.verification_status ?? '待核验')}</span></button></li>)}</ul> : <p className="text-sm text-slate-500">{directoryFilter ? '没有匹配项，请更换搜索词。' : '暂无可访问数据集。'}</p>}
            </section>
            {workbench && canCreateDataset && <button type="button" className="wb-add" aria-expanded={creating} onClick={() => setCreating(!creating)}>{creating ? '收起创建表单' : '＋ 创建数据集'}</button>}
            {canCreateDataset && (!workbench || creating) && <section className="rounded-xl border bg-white p-4" aria-label="创建数据集"><h2 className="text-lg font-semibold mb-3">创建数据集</h2><form onSubmit={createDataset} className="space-y-3 text-sm">
              <label className="block">名称<input aria-label="数据集名称" name="dataset-name" autoComplete="off" required value={name} onChange={e => setName(e.target.value)} className="mt-1 w-full rounded border p-2" /></label>
              <label className="block">来源类型<select aria-label="来源类型" value={sourceKind} onChange={e => setSourceKind(e.target.value as 'synthetic' | 'real')} className="mt-1 w-full rounded border p-2"><option value="synthetic">合成</option><option value="real">真实待核验</option></select></label>
              <label className="block">来源说明<input aria-label="来源说明" name="source" autoComplete="off" value={source} onChange={e => setSource(e.target.value)} placeholder="运行前须补齐依据…" className="mt-1 w-full rounded border p-2" /></label>
              <label className="block">批次<input aria-label="批次" name="batch" autoComplete="off" value={batch} onChange={e => setBatch(e.target.value)} placeholder="运行前须补齐依据…" className="mt-1 w-full rounded border p-2" /></label>
              <label className="block">授权依据引用<input aria-label="授权依据引用" name="authorization-ref" autoComplete="off" value={authorizationRef} onChange={e => setAuthorizationRef(e.target.value)} className="mt-1 w-full rounded border p-2" /></label>
              <button type="submit" disabled={Boolean(busy)} className="rounded bg-emerald-700 px-3 py-2 text-white disabled:bg-slate-400">创建数据集</button>
            </form></section>}
          </aside>
          <div className="space-y-5 wb-content">
            {workbench && <div className="wb-heading"><p className="wb-section-label">分析工作区</p><h2>{sections[view]}</h2></div>}
            {!dataset ? <section className="rounded-xl border bg-white p-6 text-slate-500">{loadingDataset ? <p role="status">正在读取数据集…</p> : workbench ? <><h3 className="font-semibold text-slate-800">选择工作批次</h3><p className="mt-1 text-sm">选择数据集后，可以核对输入、提交运行或打开已有证据。</p>{datasets.length > 0 && <ul className="wb-recent" aria-label="可打开的数据集">{datasets.slice(0,4).map(item => <li key={item.id}><button onClick={() => openDataset(item.id)}><strong>{item.name}</strong><span>{item.batch || '批次未声明'} · {item.source_kind === 'synthetic' ? '合成' : '真实待核验'}</span></button></li>)}</ul>}{!datasets.length && <p className="mt-3 text-sm">{canCreateDataset ? '选择“创建数据集”登记第一个批次。' : '请联系管理员授予数据集只读权限。'}</p>}</> : '选择左侧数据集查看文件、配置与运行。'}</section> : <>
              {showData && <><section className="rounded-xl border bg-white p-5 space-y-2" aria-label="数据集详情"><h2 className="text-xl font-semibold">{dataset.name}</h2><dl className="grid gap-2 text-sm sm:grid-cols-2"><div><dt className="text-slate-500">来源类型 / 状态</dt><dd>{dataset.source_kind} / {dataset.verification_status ?? '待核验'}</dd></div><div><dt className="text-slate-500">访问权限</dt><dd>{dataset.access ?? user.role}</dd></div><div><dt className="text-slate-500">来源 / 批次</dt><dd>{codeText(dataset.source)} / {codeText(dataset.batch)}</dd></div><div><dt className="text-slate-500">授权依据引用</dt><dd>{codeText(dataset.authorization_ref)}</dd></div></dl><p className="text-xs text-slate-500 break-all">ID {dataset.id}</p></section>
              <section className="rounded-xl border bg-white p-5 space-y-3" aria-label="原始文件"><h2 className="text-lg font-semibold">原始文件</h2>{files.length ? <ul className="space-y-2 text-sm">{files.map(file => <li key={file.id} className="rounded border p-3"><span className="font-medium">{file.role} · {file.filename ?? file.name}</span><span className="block text-xs text-slate-500 break-all">{file.size_bytes} 字节 · SHA-256 {file.sha256}</span>{workbench ? <a className="block text-emerald-800 underline" href={API + `/datasets/${encodeURIComponent(dataset.id)}/files/${encodeURIComponent(file.id)}/download`} download>下载原件</a> : <button type="button" onClick={() => void download(`/datasets/${encodeURIComponent(dataset.id)}/files/${encodeURIComponent(file.id)}/download`, file.filename ?? file.name ?? 'source')} className="mt-2 text-emerald-800 underline">下载原件</button>}</li>)}</ul> : <p className="text-sm text-slate-500">尚无原始文件。</p>}
                {canEdit && <form onSubmit={upload} className="grid gap-3 border-t pt-3 text-sm sm:grid-cols-[8rem_1fr_auto]"><label>文件角色<select aria-label="文件角色" value={uploadRole} onChange={e => setUploadRole(e.target.value as 'network' | 'process')} className="mt-1 w-full rounded border p-2"><option value="network">网络</option><option value="process">工艺</option></select></label><label>选择原始文件<input aria-label="选择原始文件" type="file" required accept={uploadRole === 'network' ? '.pcap,.pcapng' : '.csv,.xls,.xlsx'} onChange={e => { setUploadFile(e.target.files?.[0] ?? null); if (e.target.files?.[0]) { setPreflight(null); setPreflightId(''); setPreflightConfigId(''); } }} className="mt-1 block w-full text-sm" /></label><button type="submit" disabled={Boolean(busy) || !uploadFile} className="self-end rounded bg-emerald-700 px-3 py-2 text-white disabled:bg-slate-400">上传并校验</button></form>}
              </section>
              <section className="rounded-xl border bg-white p-5 space-y-3" aria-label="版本配置与预检"><h2 className="text-lg font-semibold">版本配置与预检</h2><p className="text-sm text-slate-500">保存后生成不可变版本。工艺 Excel 是接收格式，不代表可直接分析。</p>
                {canEdit && <form onSubmit={createConfig} className="space-y-3 text-sm">{workbench && <label className="block">从配置文件填入草稿<input type="file" name="config-file" accept=".json,application/json" onChange={async e => {
                  const file = e.target.files?.[0]; if (!file) return;
                  const current = dataVersion.current;
                  if (file.size > 16 * 1024 * 1024) { setConfigError('配置超过 16 MiB，请选择正确的版本文件。'); return; }
                  try { const text = await file.text(); if (current === dataVersion.current) { setConfigText(text); setConfigError(''); } }
                  catch { if (current === dataVersion.current) setConfigError('无法读取配置文件，请重新选择。'); }
                }} className="mt-1 block" /></label>}<label className="block">配置类型<select aria-label="配置类型" value={configKind} onChange={e => setConfigKind(e.target.value as 'intake' | 'dual')} className="mt-1 rounded border p-2"><option value="intake">接收预检</option><option value="dual">双源分析</option></select></label><label className="block">配置 JSON<textarea aria-label="配置 JSON" aria-invalid={!!configError} aria-describedby={configError ? "wb-config-error" : undefined} required value={configText} onChange={e => { setConfigText(e.target.value); setConfigError(''); }} rows={7} spellCheck={false} className="mt-1 w-full rounded border p-2 font-mono text-xs" /></label>{configError && <p id="wb-config-error" role="alert">{configError}</p>}<button type="submit" disabled={Boolean(busy)} className="rounded bg-slate-700 px-3 py-2 text-white disabled:bg-slate-400">保存新版本</button></form>}
                <label className="block text-sm">选择配置版本<select aria-label="选择配置版本" value={configId} onChange={e => { const next = e.target.value; setConfigId(next); if (configs.find(item => item.id === next)?.kind === 'intake' && next !== preflightConfigId) { setPreflight(null); setPreflightId(''); setPreflightConfigId(''); } }} className="mt-1 w-full rounded border p-2"><option value="">选择版本</option>{configs.map(config => <option key={config.id} value={config.id}>{config.kind} v{config.version} · {config.id}</option>)}</select></label>
                {workbench && configId && <ConfigDetails key={configId} datasetId={dataset.id} configId={configId} />}{configId && <p className="text-xs text-slate-500 break-all">配置指纹：{configs.find(item => item.id === configId)?.config_fingerprint ?? '未提供'}</p>}
                {canEdit && <button type="button" onClick={() => void validate()} disabled={Boolean(busy) || !configId || configs.find(item => item.id === configId)?.kind !== 'intake'} className="rounded border border-emerald-700 px-3 py-2 text-sm text-emerald-900 disabled:text-slate-400">运行接收预检</button>}
                {preflight && <div className="rounded border border-amber-200 bg-amber-50 p-3 text-sm" aria-label="预检报告"><p className="font-medium">预检状态：{preflight.status ?? '未说明'}</p><p>错误：{(preflight.errors ?? []).length} · 材料缺口：{(preflight.material_gaps ?? []).length}</p>{workbench && <p>覆盖范围 · {preflight.collection_range_status === 'unknown' ? '待核验' : preflight.collection_range_status}　原件已核验 {preflight.verified_file_count ?? 0} 件　待补材料 · {(preflight.material_gaps || []).join('、') || '无已报告缺口'}</p>}<details><summary className="cursor-pointer">查看完整预检报告</summary><pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(preflight, null, 2)}</pre></details></div>}
                <label className="block text-sm">运行模式<select aria-label="运行模式" value={runMode} onChange={e => setRunMode(e.target.value)} className="ml-2 border rounded p-2"><option value="dual_source">离线双源分析（默认）</option><option value="dual_source_replay">顺序回放（显式配置）</option></select></label><p className="text-xs text-slate-600">回放需选择包含版本化 replay 参数的配置；历史快照只在任务完成并校验后提供。</p><p className="text-xs text-slate-600 break-all" aria-label="当前运行预检">运行将提交预检 ID：{preflightId || '未选择；由服务端判定'}</p>
                <div className="border-t pt-3 text-sm" aria-label="历史预检报告"><h3 className="font-semibold">历史预检报告</h3>{preflights.length ? <ul className="mt-2 space-y-2">{preflights.map(item => <li key={item.id} className="flex flex-wrap items-center gap-2 rounded border p-2"><span className="break-all">{item.report?.status ?? '未说明'} · 快照 {item.snapshot_status ?? '待核'} · {item.id} · {date(item.created_at)}</span><button type="button" onClick={() => void showHistoricalPreflight(item.id)} className="underline">查看历史预检 {item.id}</button>{canEdit && <button type="button" onClick={() => { setPreflightId(item.id); setPreflightConfigId(item.config_version_id ?? ''); setPreflight({ ...item.report, preflight_id: item.id }); setNotice('已显式选择历史预检；服务端将核对当前文件与配置，过期记录会被拒绝。'); }} className="rounded border px-2 py-1">选择运行预检 {item.id}</button>}</li>)}</ul> : <p className="mt-2 text-slate-500">暂无历史预检。</p>}{historicalPreflight && <div className="mt-3 rounded border border-slate-200 p-3" aria-label="历史预检详情"><p>历史状态：{historicalPreflight.status ?? '未说明'} · 快照 {historicalPreflight.snapshot_status ?? '待核'}</p><pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(historicalPreflight, null, 2)}</pre></div>}</div>
              </section>
              {workbench && canEdit && <button className="wb-primary" disabled={Boolean(busy) || configs.find(item => item.id===configId)?.kind!=='dual'} onClick={() => void submitRun()}>提交双源运行</button>}
              </>}
              {showTasks && <section className="rounded-xl border bg-white p-5 space-y-3" aria-label="运行与历史"><h2 className="text-lg font-semibold">运行与历史</h2><p className="text-xs text-slate-600">默认预算：最多4个抓包、合计16 MiB/10000帧，CSV 2 MiB/1000逻辑记录；显式工程版本按服务端绑定的资源与配置预算执行，目前仅承诺已验S100范围，M/L未完成、不承诺支持。上传接收限额不等于执行限额。</p><div className="flex flex-wrap gap-2">{workbench && <button onClick={() => navigate('datasets')}>选择输入与配置</button>}{canEdit && !workbench && <button type="button" onClick={() => void submitRun()} disabled={Boolean(busy) || !configId || configs.find(item => item.id === configId)?.kind !== 'dual'} className="rounded bg-emerald-700 px-3 py-2 text-sm text-white disabled:bg-slate-400">提交双源运行</button>}<button type="button" onClick={() => void refreshRuns()} className="rounded border px-3 py-2 text-sm">刷新历史</button></div>
                {dataset.source_kind === 'real' && <p className="text-sm text-amber-800">真实来源保持待核验。仅在来源、授权、时间和映射材料齐全，且选择明确支持真实来源的软件配置时可运行；完成计算不表示真实适用性通过。</p>}
                {workbench && runs.length >= 200 && <p>此列表显示最近 200 个运行。历史链接仍可按运行身份打开。</p>}{runs.length ? <ul className="space-y-2 text-sm">{runs.map(run => <li key={run.id}><button type="button" aria-label={`查看运行 ${run.id}`} onClick={() => openRun(run.id)} className="w-full rounded border p-3 text-left"><span className="font-medium">{workbench ? stateLabels[run.state] || run.state : run.state}</span><span className="block break-all">{run.id}</span><span className="text-xs text-slate-500">{date(run.created_at)} · attempt {run.attempt ?? 0}</span></button></li>)}</ul> : <p className="text-sm text-slate-500">尚无运行。</p>}
                {selectedRun && <div role="region" className="rounded border border-slate-300 p-4 space-y-2 text-sm" aria-label="运行详情"><h3 className="font-semibold">运行详情</h3><p className="break-all">{selectedRun.id} · {workbench ? stateLabels[selectedRun.state] || selectedRun.state : selectedRun.state} · attempt {selectedRun.attempt ?? 0}</p>{selectedRun.last_error && <p role="alert" className="text-red-700">{selectedRun.last_error}</p>}{!['succeeded', 'failed', 'cancelled'].includes(selectedRun.state) && canEdit && <button type="button" onClick={() => workbench ? setConfirmCancel(true) : void cancelRun()} className="rounded border px-3 py-2">请求取消</button>}{workbench && confirmCancel && <div role="group" aria-label="确认取消"><p>取消后将等待本次执行退出。确认取消这个任务？</p><button onClick={() => {setConfirmCancel(false); void cancelRun();}}>确认取消任务</button><button onClick={() => setConfirmCancel(false)}>保留任务</button></div>}
                {workbench && canEdit && ['failed','cancelled'].includes(selectedRun.state) && <button disabled={Boolean(busy)} onClick={() => void retryRun()}>重试此运行</button>}
                {workbench && <p>阶段 · {stateLabels[selectedRun.progress?.phase || selectedRun.state] || selectedRun.state}。已登记 {selectedRun.attempt_history?.length ?? 0} 次执行，已确认退出 {selectedRun.attempt_history?.filter(a => a.exited_at).length ?? 0} 次。{selectedRun.progress && <>本任务最多 {selectedRun.progress.max_attempts} 次执行。</>} 计算期间无实时帧或行计数，发布后可查看实际观测数。</p>}
                {workbench && selectedRun.state === 'succeeded' && <button className="wb-primary" onClick={() => navigate(selectedRun.mode === 'dual_source_replay' ? 'replay' : 'analysis')}>查看分析结果</button>}
                {selectedRun.state === 'succeeded' && !workbench && <Link href={selectedRun.mode === 'dual_source_replay' ? `/replay?run=${encodeURIComponent(selectedRun.id)}` : `/dual-source?backend=v3&run=${encodeURIComponent(selectedRun.id)}`} className="inline-block rounded bg-emerald-700 px-3 py-2 text-white">查看关联图与原始证据</Link>}<details><summary className="cursor-pointer">固定抓包顺序与尝试历史</summary><pre className="overflow-auto text-xs">{JSON.stringify(selectedRun.network_file_ids ?? [], null, 2)}</pre><pre className="overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(selectedRun.attempt_history ?? [], null, 2)}</pre></details></div>}
              </section>
              }
              {workbench && ['analysis','replay','evaluation'].includes(view) && <section className="wb-panel" aria-label="结果内容">
                {loadingRun && !selectedRun ? <p role="status">正在读取运行…</p> : !selectedRun || selectedRun.state !== 'succeeded' ? <><h3>尚无可查看的运行结果</h3><p>在任务中心选择已完成的运行。失败或已取消的任务保留执行记录。</p><button onClick={() => navigate('tasks')}>打开任务中心</button></> : view === 'replay' ? selectedRun.mode === 'dual_source_replay'
                  ? <Replay key={selectedRun.id} datasetId={dataset.id} runId={selectedRun.id} onError={setError} />
                  : <p>当前为离线运行。请在任务中心选择顺序回放任务查看历史。</p>
                  : view === 'evaluation' ? <Evaluation canImport={canEdit} key={selectedRun.id} datasetId={dataset.id} runId={selectedRun.id} onError={setError} />
                  : <Analysis key={selectedRun.id} datasetId={dataset.id} runId={selectedRun.id} onError={setError} />}
              </section>}
              {workbench && view === 'access' && user.role !== 'admin' && <p role="alert">仅管理员可管理用户与授权。请联系数据集管理员。</p>}{showAccess && user.role === 'admin' && <section className="rounded-xl border bg-white p-5 space-y-3" aria-label="数据集授权"><h2 className="text-lg font-semibold">数据集授权</h2><form onSubmit={grantAcl} className="flex flex-wrap gap-2 text-sm"><select aria-label="授权用户" required value={aclUserId} onChange={e => setAclUserId(e.target.value)} className="rounded border p-2"><option value="">选择用户</option>{users.filter(item => item.role !== 'admin').map(item => <option key={item.id} value={item.id}>{item.username}</option>)}</select><select aria-label="授权级别" value={aclAccess} onChange={e => setAclAccess(e.target.value as 'viewer' | 'analyst')} className="rounded border p-2"><option value="viewer">只读</option><option value="analyst">分析</option></select><button type="submit" disabled={Boolean(busy) || !aclUserId} className="rounded bg-slate-700 px-3 py-2 text-white disabled:bg-slate-400">保存授权</button></form></section>}
            </>}
          </div>
        </div>
        {showAccess && user.role === 'admin' && <section className="rounded-xl border bg-white p-5 space-y-3" aria-label="用户管理"><h2 className="text-lg font-semibold">用户管理</h2><form onSubmit={createUser} className="flex flex-wrap gap-3 text-sm"><label>新用户名<input aria-label="新用户名" name="new-username" autoComplete="off" spellCheck={false} required value={newUsername} onChange={e => setNewUsername(e.target.value)} className="ml-2 rounded border p-2" /></label><label>初始密码<input aria-label="初始密码" name="initial-password" autoComplete="new-password" required type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} className="ml-2 rounded border p-2" /></label><label>角色<select aria-label="新用户角色" value={newRole} onChange={e => setNewRole(e.target.value as User['role'])} className="ml-2 rounded border p-2"><option value="viewer">只读者</option><option value="analyst">分析员</option><option value="admin">管理员</option></select></label><button type="submit" disabled={Boolean(busy)} className="rounded bg-slate-700 px-3 py-2 text-white disabled:bg-slate-400">创建用户</button></form><p className="text-xs text-slate-500">数据集访问仍需单独授权。</p></section>}
      </>}
    </main>
  </div>;
}
