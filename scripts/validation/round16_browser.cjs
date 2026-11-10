// R16 public Go application browser acceptance. No mocks or environment startup.
// Usage: node scripts/validation/round16_browser.cjs PRIVATE/state.json OUTPUT_DIR
// state: {url,restored_url?,username,password,fixture_dir,run_id?,restored_run_id?,
//         viewer_username?,viewer_password?}. Never copy state.json into OUTPUT_DIR.
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const crypto = require('crypto');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const statePath = path.resolve(process.argv[2] || '');
const out = path.resolve(process.argv[3] || 'output/playwright/round16');
if (!process.argv[2] || !process.argv[3]) throw new Error('usage: round16_browser.cjs PRIVATE/state.json OUTPUT_DIR');
fs.mkdirSync(out, { recursive: true, mode: 0o700 });
const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
for (const key of ['url', 'username', 'password', 'fixture_dir']) if (!state[key]) throw new Error(`missing state field ${key}`);
const privateValues = [state.password, state.viewer_password].filter(Boolean);
const scrub = value => {
  let text = String(value);
  for (const secret of privateValues) text = text.split(secret).join('[redacted]');
  return text.replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').replace(/cpag_session=[^;\s]+/gi, 'cpag_session=[redacted]');
};
const fixture = name => {
  for (const candidate of [path.join(state.fixture_dir, name), path.join(state.fixture_dir, 'success', name),
    path.join(state.fixture_dir, 'inputs', 'success', name), path.join(state.fixture_dir, 'inputs', name)])
    if (fs.existsSync(candidate)) return candidate;
  throw new Error(`missing fixture ${name}`);
};
const profile = JSON.parse(fs.readFileSync(fixture('profile.json'), 'utf8'));
assert.equal(profile.synthetic, true, 'dual profile must be explicitly synthetic');
const runName = `r16-browser-${crypto.randomBytes(4).toString('hex')}`;
const report = { synthetic_only: true, status: 'running', checks: {}, page_errors: [], screenshot_files: [] };
const errors = report.page_errors;
let browser;

async function shot(page, name) {
  const file = `${name}.png`;
  // A failed login/user-creation screenshot must not capture a typed password.
  await page.locator('input[type="password"]').evaluateAll(inputs => inputs.forEach(input => { input.value = ''; }));
  await page.screenshot({ path: path.join(out, file), fullPage: false });
  report.screenshot_files.push(file);
}
function watch(page) { page.on('pageerror', error => errors.push(scrub(error))); }
async function login(page, username, password) {
  await page.getByLabel('用户名', { exact: true }).fill(username);
  await page.getByLabel('密码', { exact: true }).fill(password);
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await page.getByRole('region', { name: '数据集列表', exact: true }).waitFor();
  assert(!(await page.locator('body').innerText()).includes(password), 'password rendered after login');
  const exposed = await page.evaluate(() => ({
    cookie: document.cookie,
    local: JSON.stringify({ ...localStorage }),
    session: JSON.stringify({ ...sessionStorage }),
  }));
  assert(!exposed.cookie.includes('cpag_session='), 'session cookie visible to JavaScript');
  assert(!Object.values(exposed).some(value => value.includes(password)), 'credential left in browser storage');
}
async function newPage(context, url, username, password) {
  const page = await context.newPage(); watch(page); page.setDefaultTimeout(60000);
  await page.goto(url);
  await page.getByRole('heading', { name: 'CPAG 研究工作台', exact: true }).waitFor();
  if (await page.getByLabel('用户名', { exact: true }).count()) await login(page, username, password);
  return page;
}
async function createdBy(page, matcher, click) {
  // Start consuming the body as soon as the response arrives; Chromium may evict
  // a short POST body from its inspector cache while the UI rerenders.
  const pending = page.waitForResponse(response => matcher(response) && response.request().method() === 'POST')
    .then(async response => ({ status: response.status(), pathname: new URL(response.url()).pathname, value: await response.json() }));
  await click();
  const response = await pending;
  assert(response.status >= 200 && response.status < 300, `request failed: ${response.status} ${response.pathname}`);
  return response.value;
}
async function upload(page, datasetId, role, file) {
  await page.getByLabel('文件角色', { exact: true }).selectOption(role);
  await page.getByLabel('选择原始文件', { exact: true }).setInputFiles(file);
  // The raw upload may finish after Chromium has evicted its POST response body.
  // Never retry a successful mutation solely because inspector body retrieval failed.
  const pending = page.waitForResponse(response => /\/api\/v3\/datasets\/[^/]+\/files\?/.test(response.url()) && response.request().method() === 'POST')
    .then(response => ({ status: response.status(), pathname: new URL(response.url()).pathname }));
  await page.getByRole('button', { name: '上传并校验', exact: true }).click();
  const posted = await pending;
  assert(posted.status >= 200 && posted.status < 300, `upload failed: ${posted.status} ${posted.pathname}`);
  await page.getByRole('status').filter({ hasText: '原件已上传并校验哈希' }).waitFor();
  const bytes = fs.readFileSync(file);
  const expected = crypto.createHash('sha256').update(bytes).digest('hex');
  const response = await page.request.get(new URL(`/api/v3/datasets/${encodeURIComponent(datasetId)}/files`, page.url()).toString());
  assert(response.ok(), `file catalog lookup failed: ${response.status()}`);
  const listed = (await response.json()).files || [];
  assert(listed.some(entry => entry.role === role && entry.sha256 === expected && entry.size_bytes === bytes.length && entry.filename === path.basename(file)),
    `uploaded ${role} file absent from verified catalog`);
  assert(await page.getByRole('region', { name: '原始文件', exact: true }).getByText(expected, { exact: false }).count(),
    `uploaded ${role} hash absent from UI`);
}
async function saveConfig(page, kind, document) {
  await page.getByLabel('配置类型', { exact: true }).selectOption(kind);
  await page.getByLabel('配置 JSON', { exact: true }).fill(JSON.stringify(document));
  const value = await createdBy(page, response => /\/api\/v3\/datasets\/[^/]+\/configs$/.test(response.url()),
    () => page.getByRole('button', { name: '保存新版本', exact: true }).click());
  assert.equal(value.config.kind, kind);
  assert(value.config.id && value.config.version >= 1 && value.config.config_fingerprint);
  await page.getByLabel('选择配置版本', { exact: true }).selectOption(value.config.id);
  return value.config.id;
}
async function inspectFour(page, prefix, expectedRun) {
  const location = new URL(page.url());
  if (location.pathname.replace(/\/$/, '') !== '/dual-source' || location.searchParams.get('backend') !== 'v3' || location.searchParams.get('run') !== expectedRun)
    await page.goto(`${new URL('/dual-source', page.url())}?backend=v3&run=${encodeURIComponent(expectedRun)}`);
  await page.getByRole('region', { name: '双源结果摘要', exact: true }).waitFor({ timeout: 180000 });
  await page.getByRole('region', { name: '双源关联图', exact: true }).waitFor();
  await page.getByRole('button', { name: /查看network节点/ }).first().click();
  await page.getByText('核查后的原始记录：4；核查后的网络字段：2', { exact: true }).waitFor();
  assert.equal(await page.getByRole('heading', { name: /^原始记录 [1-4]$/ }).count(), 4);
  report.checks[`${prefix}_four_original_refs`] = true;
  await shot(page, `${prefix}-four-evidence`);
  await page.getByRole('button', { name: /查看候选连线/ }).first().click();
  await page.getByRole('region', { name: '证据核查', exact: true }).getByText(/已选择：candidate/).waitFor();
  await page.getByText('核查后的原始记录：4；核查后的网络字段：2', { exact: true }).waitFor();
  report.checks[`${prefix}_graph_candidate`] = true;
  await shot(page, `${prefix}-graph`);
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: '下载 analysis.json', exact: true }).click();
  const saved = await download;
  const file = path.join(out, `${prefix}-analysis.json`);
  await saved.saveAs(file);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).synthetic, true);
  report.checks[`${prefix}_controlled_download`] = true;
}

(async () => {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 960 }, acceptDownloads: true });
  const page = await newPage(context, state.url, state.username, state.password);
  try {
    const creation = await createdBy(page, response => /\/api\/v3\/datasets$/.test(response.url()), async () => {
      await page.getByLabel('数据集名称', { exact: true }).fill(runName);
      await page.getByLabel('来源类型', { exact: true }).selectOption('synthetic');
      await page.getByLabel('来源说明', { exact: true }).fill('independent synthetic browser fixture');
      await page.getByLabel('批次', { exact: true }).fill('round16');
      await page.getByLabel('授权依据引用', { exact: true }).fill('generated-fixture');
      await page.getByRole('button', { name: '创建数据集', exact: true }).click();
    });
    const datasetId = creation.dataset.id;
    assert(datasetId);
    await page.getByRole('region', { name: '数据集详情', exact: true }).waitFor();
    report.checks.dataset_created = true;
    await shot(page, 'dataset-created');

    await upload(page, datasetId, 'network', fixture('network.pcap'));
    await upload(page, datasetId, 'process', fixture('process.csv'));
    assert.equal(await page.getByRole('region', { name: '原始文件', exact: true }).locator('li').count(), 2);
    report.checks.raw_upload_sha256 = true;

    const intake = {
      dataset_id: datasetId, synthetic: true,
      authorization: { allowed_use: 'synthetic test', evidence_ref: 'generated-fixture', reviewer: 'test' },
      time_basis: { timezone: 'UTC', precision: 'microsecond', synchronization: 'synthetic', evidence_ref: 'generated-fixture' },
      mapping: { field_units_ref: 'generated-fixture', device_map_ref: 'generated-fixture', effective_period_ref: 'generated-fixture' },
    };
    await saveConfig(page, 'intake', intake);
    const preflight = await createdBy(page, response => /\/api\/v3\/datasets\/[^/]+\/preflight$/.test(response.url()),
      () => page.getByRole('button', { name: '运行接收预检', exact: true }).click());
    assert.equal(preflight.report.errors.length, 0);
    assert.equal(preflight.report.verified_file_count, 2);
    await page.getByLabel('预检报告', { exact: true }).waitFor();
    report.checks.metadata_preflight = preflight.report.status;
    await shot(page, 'preflight');

    await saveConfig(page, 'dual', profile);
    const submission = await createdBy(page, response => /\/api\/v3\/runs$/.test(response.url()),
      () => page.getByRole('button', { name: '提交双源运行', exact: true }).click());
    const runId = submission.run.id;
    assert(runId && submission.run.state === 'queued');
    report.submitted_run_id = runId;
    await page.getByRole('link', { name: '查看关联图与原始证据', exact: true }).waitFor({ timeout: 180000 });
    report.checks.submitted_run_succeeded = true;
    await page.getByRole('link', { name: '查看关联图与原始证据', exact: true }).click();
    await inspectFour(page, 'new-run', runId);

    if (state.run_id) await inspectFour(page, 'prebuilt-run', state.run_id);
    if (state.restored_url && state.restored_run_id) {
      // 127.0.0.1 ports share the same cookie scope. Separate BrowserContexts
      // keep the restored database login from replacing the source session.
      const restoredContext = await browser.newContext({ viewport: { width: 1440, height: 960 }, acceptDownloads: true });
      try {
        const restored = await newPage(restoredContext, state.restored_url, state.username, state.password);
        await inspectFour(restored, 'restored-run', state.restored_run_id);
        report.checks.restored_session_isolated = true;
      } finally { await restoredContext.close(); }
    } else report.checks.restored_run = 'not supplied';

    await page.goto(state.url);
    await page.getByRole('heading', { name: 'CPAG 研究工作台', exact: true }).waitFor();
    await page.getByRole('button', { name: `打开数据集 ${runName}`, exact: true }).click();
    await page.getByRole('region', { name: '数据集详情', exact: true }).waitFor();
    let viewerName = state.viewer_username;
    let viewerPassword = state.viewer_password;
    if (!viewerName) {
      assert(await page.getByRole('region', { name: '用户管理', exact: true }).count(), 'admin account required to create viewer');
      viewerName = `r16-viewer-${crypto.randomBytes(4).toString('hex')}`;
      viewerPassword = crypto.randomBytes(18).toString('base64url');
      privateValues.push(viewerPassword);
      await page.getByLabel('新用户名', { exact: true }).fill(viewerName);
      await page.getByLabel('初始密码', { exact: true }).fill(viewerPassword);
      await page.getByLabel('新用户角色', { exact: true }).selectOption('viewer');
      await page.getByRole('button', { name: '创建用户', exact: true }).click();
      await page.getByRole('status').filter({ hasText: '用户已创建' }).waitFor();
      report.checks.viewer_created = true;
    }
    await page.getByLabel('授权用户', { exact: true }).selectOption({ label: viewerName });
    await page.getByLabel('授权级别', { exact: true }).selectOption('viewer');
    await page.getByRole('button', { name: '保存授权', exact: true }).click();
    await page.getByRole('status').filter({ hasText: '数据集权限已更新' }).waitFor();
    await page.getByRole('button', { name: '退出登录', exact: true }).click();
    await login(page, viewerName, viewerPassword);
    await page.getByRole('button', { name: `打开数据集 ${runName}`, exact: true }).click();
    await page.getByRole('region', { name: '数据集详情', exact: true }).waitFor();
    for (const label of ['创建数据集', '上传并校验', '保存新版本', '运行接收预检', '提交双源运行'])
      assert.equal(await page.getByRole('button', { name: label, exact: true }).count(), 0, `viewer can see write control ${label}`);
    for (const label of ['创建数据集', '数据集授权', '用户管理'])
      assert.equal(await page.getByRole('region', { name: label, exact: true }).count(), 0, `viewer can see write section ${label}`);
    const forbidden = await page.evaluate(async dataset => {
      const response = await fetch('/api/v3/datasets/' + encodeURIComponent(dataset) + '/configs', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind: 'intake', document: { dataset_id: dataset, synthetic: true } }),
      });
      return response.status;
    }, datasetId);
    assert.equal(forbidden, 403, 'viewer write request was not rejected by service');
    report.checks.viewer_write_denied = true;
    const sourceDownload = page.waitForEvent('download');
    await page.getByRole('button', { name: '下载原件', exact: true }).first().click();
    await (await sourceDownload).saveAs(path.join(out, 'viewer-source.bin'));
    await page.getByRole('button', { name: `查看运行 ${runId}`, exact: true }).click();
    await page.getByRole('link', { name: '查看关联图与原始证据', exact: true }).click();
    await inspectFour(page, 'viewer-run', runId);
    report.checks.viewer_read_and_download = true;
    assert.deepEqual(errors, [], 'page errors');
    report.status = 'passed';
  } catch (error) {
    report.status = 'failed'; report.error = scrub(error);
    try { await shot(page, 'failure'); } catch { /* page may have closed */ }
    throw error;
  } finally {
    const serialized = JSON.stringify(report, null, 2);
    assert(!privateValues.some(secret => serialized.includes(secret)), 'secret in public report');
    fs.writeFileSync(path.join(out, 'browser-results.json'), serialized + '\n', { mode: 0o600 });
    await browser.close();
  }
})().catch(error => { console.error(scrub(error)); process.exitCode = 1; });
