// R16 supplementary gate acceptance through ordinary workspace clicks.
// Usage: node scripts/validation/round16_supplement_browser.cjs PRIVATE/state.json OUTPUT_DIR
// state: {url,username,password,fixture_dir}. Services and fixtures are prepared by the caller.
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const crypto = require('crypto');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

if (!process.argv[2] || !process.argv[3]) throw new Error('usage: round16_supplement_browser.cjs PRIVATE/state.json OUTPUT_DIR');
const state = JSON.parse(fs.readFileSync(path.resolve(process.argv[2]), 'utf8'));
for (const key of ['url', 'username', 'password', 'fixture_dir']) if (!state[key]) throw new Error(`missing state field ${key}`);
const out = path.resolve(process.argv[3]);
fs.mkdirSync(out, { recursive: true, mode: 0o700 });
const fixture = name => {
  for (const candidate of [path.join(state.fixture_dir, name), path.join(state.fixture_dir, 'success', name),
    path.join(state.fixture_dir, 'inputs', 'success', name), path.join(state.fixture_dir, 'inputs', name)])
    if (fs.existsSync(candidate)) return candidate;
  throw new Error(`missing fixture ${name}`);
};
const profile = JSON.parse(fs.readFileSync(fixture('profile.json'), 'utf8'));
assert.equal(profile.synthetic, true);
const report = { synthetic_only: true, status: 'running', checks: {}, page_errors: [], screenshots: [] };
const scrub = value => String(value).split(state.password).join('[redacted]').replace(/cpag_session=[^;\s]+/gi, 'cpag_session=[redacted]');
let browser;
async function shot(page, name) {
  const file = `${name}.png`;
  await page.locator('input[type="password"]').evaluateAll(inputs => inputs.forEach(input => { input.value = ''; }));
  await page.screenshot({ path: path.join(out, file), fullPage: false });
  report.screenshots.push(file);
}
async function posted(page, pathname, click) {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === pathname && response.request().method() === 'POST')
    .then(async response => ({ status: response.status(), value: await response.json().catch(() => null) }));
  await click();
  return pending;
}
async function createDataset(page, suffix, metadata = {}) {
  const name = `r16-gate-${suffix}-${crypto.randomBytes(4).toString('hex')}`;
  await page.getByLabel('数据集名称', { exact: true }).fill(name);
  await page.getByLabel('来源类型', { exact: true }).selectOption('synthetic');
  await page.getByLabel('来源说明', { exact: true }).fill(metadata.source ?? 'generated fixture');
  await page.getByLabel('批次', { exact: true }).fill(metadata.batch ?? 'round16');
  await page.getByLabel('授权依据引用', { exact: true }).fill(metadata.authorization_ref ?? 'generated-fixture');
  const response = await posted(page, '/api/v3/datasets', () => page.getByRole('button', { name: '创建数据集', exact: true }).click());
  assert.equal(response.status, 201);
  assert(response.value?.dataset?.id);
  await page.getByRole('region', { name: '数据集详情', exact: true }).waitFor();
  return { name, id: response.value.dataset.id };
}
async function upload(page, role, file, basename) {
  await page.getByLabel('文件角色', { exact: true }).selectOption(role);
  await page.getByLabel('选择原始文件', { exact: true }).setInputFiles(basename
    ? { name: basename, mimeType: role === 'process' ? 'text/csv' : 'application/octet-stream', buffer: fs.readFileSync(file) }
    : file);
  const pending = page.waitForResponse(response => /\/api\/v3\/datasets\/[^/]+\/files\?/.test(response.url()) && response.request().method() === 'POST')
    .then(response => response.status());
  await page.getByRole('button', { name: '上传并校验', exact: true }).click();
  assert.equal(await pending, 201);
  await page.getByRole('status').filter({ hasText: '原件已上传并校验哈希' }).waitFor();
}
function intakeDoc(datasetId, overrides = {}) {
  return {
    dataset_id: datasetId, synthetic: true,
    authorization: { allowed_use: 'synthetic test', evidence_ref: 'generated-fixture', reviewer: 'test' },
    time_basis: { timezone: 'UTC', precision: 'microsecond', synchronization: 'synthetic', evidence_ref: 'generated-fixture' },
    mapping: { field_units_ref: 'generated-fixture', device_map_ref: 'generated-fixture', effective_period_ref: 'generated-fixture' },
    ...overrides,
  };
}
async function config(page, kind, document) {
  await page.getByLabel('配置类型', { exact: true }).selectOption(kind);
  await page.getByLabel('配置 JSON', { exact: true }).fill(JSON.stringify(document));
  const pathname = new URL(page.url()).origin;
  const pending = page.waitForResponse(response => response.url().startsWith(pathname + '/api/v3/datasets/') && /\/configs$/.test(new URL(response.url()).pathname) && response.request().method() === 'POST')
    .then(async response => ({ status: response.status(), value: await response.json().catch(() => null) }));
  await page.getByRole('button', { name: '保存新版本', exact: true }).click();
  const response = await pending;
  assert.equal(response.status, 201);
  assert(response.value?.config?.id);
  await page.getByLabel('选择配置版本', { exact: true }).selectOption(response.value.config.id);
  return response.value.config.id;
}
async function preflight(page, expectedStatus = 200) {
  const pending = page.waitForResponse(response => /\/api\/v3\/datasets\/[^/]+\/preflight$/.test(new URL(response.url()).pathname) && response.request().method() === 'POST')
    .then(async response => ({ status: response.status(), value: await response.json().catch(() => null) }));
  await page.getByRole('button', { name: '运行接收预检', exact: true }).click();
  const response = await pending;
  assert.equal(response.status, expectedStatus);
  await page.getByLabel('预检报告', { exact: true }).waitFor();
  assert(response.value?.preflight_id);
  return response.value;
}
async function runRejected(page, datasetId, code, status) {
  const before = await page.request.get(new URL(`/api/v3/runs?dataset_id=${encodeURIComponent(datasetId)}`, page.url()).toString());
  assert(before.ok());
  const count = (await before.json()).runs.length;
  const response = await posted(page, '/api/v3/runs', () => page.getByRole('button', { name: '提交双源运行', exact: true }).click());
  assert.equal(response.status, status);
  assert.equal(response.value?.error?.code, code);
  await page.getByRole('alert').filter({ hasText: code }).waitFor();
  const after = await page.request.get(new URL(`/api/v3/runs?dataset_id=${encodeURIComponent(datasetId)}`, page.url()).toString());
  assert(after.ok());
  assert.equal((await after.json()).runs.length, count, `rejected ${code} created a run`);
  report.checks[code] = { status, queued_delta: 0 };
  await shot(page, code);
}

(async () => {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  const page = await context.newPage(); page.setDefaultTimeout(60000);
  page.on('pageerror', error => report.page_errors.push(scrub(error)));
  try {
    await page.goto(state.url);
    await page.getByLabel('用户名', { exact: true }).fill(state.username);
    await page.getByLabel('密码', { exact: true }).fill(state.password);
    await page.getByRole('button', { name: '登录', exact: true }).click();
    await page.getByRole('region', { name: '数据集列表', exact: true }).waitFor();

    // 1. A missing provenance field is reportable but cannot queue a run.
    const missing = await createDataset(page, 'missing', { authorization_ref: '' });
    await upload(page, 'network', fixture('network.pcap'));
    await upload(page, 'process', fixture('process.csv'));
    await config(page, 'intake', intakeDoc(missing.id));
    const gap = await preflight(page);
    assert(gap.report.material_gaps.includes('authorization'));
    await config(page, 'dual', profile);
    await runRejected(page, missing.id, 'preflight_incomplete', 422);

    // 2. A batch/dataset identity conflict is retained as a historical report.
    const conflict = await createDataset(page, 'conflict');
    await upload(page, 'network', fixture('network.pcap'));
    await upload(page, 'process', fixture('process.csv'));
    await config(page, 'intake', intakeDoc('another-dataset-id'));
    const bad = await preflight(page, 409);
    assert(bad.report.errors.includes('batch_conflict'));
    await config(page, 'dual', profile);
    await runRejected(page, conflict.id, 'batch_conflict', 409);

    // 3. A complete intake check cannot rescue a dual profile without mapping/time basis.
    const basis = await createDataset(page, 'basis');
    await upload(page, 'network', fixture('network.pcap'));
    await upload(page, 'process', fixture('process.csv'));
    await config(page, 'intake', intakeDoc(basis.id));
    const ready = await preflight(page);
    assert.equal(ready.report.status, 'ready_for_manual_review');
    const incompleteProfile = { ...profile, mappings: [] };
    await config(page, 'dual', incompleteProfile);
    await runRejected(page, basis.id, 'insufficient_basis', 422);
    report.checks.missing_mapping_refused = true;
    const missingTime = JSON.parse(JSON.stringify(profile));
    missingTime.clocks.process.basis = '';
    await config(page, 'dual', missingTime);
    await runRejected(page, basis.id, 'insufficient_basis', 422);
    report.checks.missing_time_refused = true;

    // 4. Single-source intake, later completion, then another upload: both old
    // reports remain readable, while an explicitly selected old ID is stale.
    const changed = await createDataset(page, 'changed');
    await upload(page, 'network', fixture('network.pcap'));
    const intakeId = await config(page, 'intake', intakeDoc(changed.id));
    const first = await preflight(page);
    assert.equal(first.report.status, 'single_source_review');
    await upload(page, 'process', fixture('process.csv'));
    await page.getByLabel('选择配置版本', { exact: true }).selectOption(intakeId);
    const second = await preflight(page);
    assert.equal(second.report.status, 'ready_for_manual_review');
    const history = page.getByLabel('历史预检报告', { exact: true });
    await history.getByRole('button', { name: `查看历史预检 ${first.preflight_id}`, exact: true }).click();
    await page.getByLabel('历史预检详情', { exact: true }).getByText(/^历史状态：single_source_review/).waitFor();
    await history.getByRole('button', { name: `查看历史预检 ${second.preflight_id}`, exact: true }).click();
    await page.getByLabel('历史预检详情', { exact: true }).getByText(/^历史状态：ready_for_manual_review/).waitFor();
    report.checks.two_historical_reports_readable = true;
    await shot(page, 'two-history-reports');
    const dualId = await config(page, 'dual', profile);
    await upload(page, 'process', fixture('process.csv'), 'process-added.csv');
    await page.getByLabel('选择配置版本', { exact: true }).selectOption(dualId);
    await page.getByLabel('当前运行预检', { exact: true }).getByText('未选择；由服务端判定').waitFor();
    await history.getByRole('button', { name: `选择运行预检 ${second.preflight_id}`, exact: true }).click();
    await runRejected(page, changed.id, 'preflight_stale', 409);

    assert.deepEqual(report.page_errors, []);
    report.status = 'passed';
  } catch (error) {
    report.status = 'failed'; report.error = scrub(error);
    try { await shot(page, 'failure'); } catch { /* page may be closed */ }
    throw error;
  } finally {
    const serialized = JSON.stringify(report, null, 2);
    assert(!serialized.includes(state.password), 'password in report');
    fs.writeFileSync(path.join(out, 'browser-results.json'), serialized + '\n', { mode: 0o600 });
    await browser.close();
  }
})().catch(error => { console.error(scrub(error)); process.exitCode = 1; });
