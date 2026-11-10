// R18 ordinary UI interactions against verified terminal replay history.
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const crypto = require('crypto');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
if (!process.argv[2] || !process.argv[3]) throw new Error('usage: round18_browser.cjs PRIVATE/state.json OUTPUT_DIR');
const state = JSON.parse(fs.readFileSync(path.resolve(process.argv[2]), 'utf8'));
const out = path.resolve(process.argv[3]);fs.mkdirSync(out, { recursive: true, mode: 0o700 });
const secrets = [state.password, state.viewer_password].filter(Boolean);
const scrub = value => secrets.reduce((text, secret) => text.split(secret).join('[redacted]'), String(value))
  .replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').replace(/cpag_session=[^;\s]+/gi, 'cpag_session=[redacted]');
const report = { status: 'running', scope: 'synthetic replay history only; no industrial validation', checks: {}, page_errors: [], screenshot_files: [] };
let browser, currentPage;
async function shot(page, name) {
  await page.locator('input[type="password"]').evaluateAll(inputs => inputs.forEach(input => { input.value = ''; }));
  await page.screenshot({ path: path.join(out, `${name}.png`), fullPage: false });report.screenshot_files.push(`${name}.png`);
}
async function login(page, url, viewer = false) {
  currentPage = page;
  page.setDefaultTimeout(60000);page.on('pageerror', error => report.page_errors.push(scrub(error)));
  await page.goto(url);
  await page.getByRole('heading', { name: 'CPAG 研究工作台', exact: true }).waitFor();
  await page.getByLabel('用户名', { exact: true }).fill(viewer ? state.viewer_username : state.username);
  await page.getByLabel('密码', { exact: true }).fill(viewer ? state.viewer_password : state.password);
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await page.getByRole('region', { name: '数据集列表', exact: true }).waitFor();
}
async function openRun(page, metadata) {
  await page.getByRole('button', { name: `打开数据集 ${metadata.dataset_name}`, exact: true }).click();
  await page.getByRole('region', { name: '数据集详情', exact: true }).waitFor();
  await page.getByRole('button', { name: `查看运行 ${metadata.run_id}`, exact: true }).click();
  await page.getByRole('link', { name: '查看关联图与原始证据', exact: true }).click();
  await page.getByRole('heading', { name: '双源顺序回放 · 历史证据核查', exact: true }).waitFor();
  assert.equal(new URL(page.url()).pathname.replace(/\/$/, ''), '/replay');
}
async function select(page, number) {
  await page.getByLabel('历史版本', { exact: true }).selectOption(String(number));
  await page.getByRole('heading', { name: `版本 ${number} 的可见事实`, exact: true }).waitFor();
}
async function inspect(page, kind, number) {
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return response.request().method() === 'GET' && url.pathname.endsWith('/evidence') && url.searchParams.get('revision') === String(number) && url.searchParams.has(kind);
  }).then(async response => { assert(response.ok(), `evidence status ${response.status()}`);return response.json(); });
  const name = kind === 'operation' ? /^查询操作原始证据/ : kind === 'change' ? /^查询变化原始证据/ : '查询本次到达原始证据';
  await page.getByRole('button', { name }).first().click();
  return pending;
}
async function history(page, metadata, prefix, unknown = false) {
  await page.locator('[aria-label="回放范围"]').filter({ hasText: '合成软件验证' }).waitFor();
  await select(page, metadata.pending);
  const region = page.getByRole('region', { name: '当前历史状态', exact: true });
  await region.locator('article p').filter({ hasText: /pending_response/ }).waitFor();
  assert((await region.innerText()).includes('候选数量：0'));
  let result = await inspect(page, 'operation', metadata.pending);
  assert.equal(result.verified_original_evidence.length, 1);
  assert.equal(result.verified_original_evidence[0].source_ref.source_slot, 'network-0');
  assert.equal(result.verified_network_fields.length, 1);
  const pendingTrigger = await inspect(page, 'trigger', metadata.pending);
  assert.equal(pendingTrigger.verified_original_evidence.length, 1);
  assert.deepEqual(pendingTrigger.verified_original_evidence[0].source_ref, result.verified_original_evidence[0].source_ref);
  report.checks[`${prefix}_pending_trigger_one_arrived_frame`] = true;
  await page.getByRole('region', { name: '回放原始证据', exact: true }).getByText('记录数：1', { exact: true }).waitFor();
  await region.scrollIntoViewIfNeeded();await shot(page, `${prefix}-pending-no-future`);
  report.checks[`${prefix}_pending_one_arrived_frame_no_future`] = true;
  await select(page, metadata.revised);
  if (unknown) {
    await region.locator('article p').filter({ hasText: /response_clock_validity_outside/ }).waitFor();
    assert((await region.innerText()).includes('判断：unknown'));
    assert((await region.innerText()).includes('候选数量：0'));
  } else {
    await region.locator('article p').filter({ hasText: /expected_change_observed/ }).waitFor();
    assert((await region.innerText()).includes('候选数量：1'));
  }
  result = await inspect(page, 'operation', metadata.revised);
  assert.equal(result.verified_original_evidence.length, unknown ? 2 : 4);
  assert.equal(result.verified_network_fields.length, 2);
  for (const entry of result.verified_original_evidence) assert(!('file_sha256' in entry.source_ref));
  await page.getByRole('region', { name: '回放原始证据', exact: true }).getByText(`记录数：${unknown ? 2 : 4}`, { exact: true }).waitFor();
  await region.scrollIntoViewIfNeeded();await shot(page, `${prefix}-${unknown ? 'unknown' : 'normal-revision'}`);
  report.checks[`${prefix}_${unknown ? 'unknown_no_candidate_success_preserved' : 'revised_candidate_originals'}`] = true;
  const revisedTrigger = await inspect(page, 'trigger', metadata.revised);
  assert.equal(revisedTrigger.verified_original_evidence.length, 1);
  assert.equal(revisedTrigger.verified_original_evidence[0].source_ref.record_number, 4);
  assert.equal(revisedTrigger.verified_original_evidence[0].original.pump, '1');
  report.checks[`${prefix}_revised_trigger_one_original_csv_record`] = true;
  const changed = await inspect(page, 'change', metadata.revised);
  assert.equal(changed.verified_original_evidence.length, 2);
  assert.deepEqual(changed.verified_original_evidence.map(entry => entry.source_ref.record_number).sort(), [3, 4]);
  const evidence = page.getByRole('region', { name: '回放原始证据', exact: true });
  await evidence.getByText('记录数：2', { exact: true }).waitFor();
  await evidence.getByText('原始记录 1', { exact: true }).click();
  await evidence.scrollIntoViewIfNeeded();await shot(page, `${prefix}-process-originals`);
  report.checks[`${prefix}_process_original_rows_3_4`] = true;
  await select(page, metadata.pending);
  assert((await region.innerText()).includes('pending_response'));
  report.checks[`${prefix}_old_pending_still_queryable`] = true;
  const pending = page.waitForEvent('download');
  await page.getByRole('button', { name: '下载 snapshots.jsonl', exact: true }).click();
  const saved = await pending;const filename = path.join(out, `${prefix}-snapshots.jsonl`);await saved.saveAs(filename);
  const bytes = fs.readFileSync(filename);
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), metadata.hashes['snapshots.jsonl']);
  report.checks[`${prefix}_controlled_history_download`] = true;
  const pendingMetrics = page.waitForEvent('download');
  await page.getByRole('button', { name: '下载 metrics.json', exact: true }).click();
  const metricsDownload = await pendingMetrics;const metricsFile = path.join(out, `${prefix}-metrics.json`);await metricsDownload.saveAs(metricsFile);
  const metricsBytes = fs.readFileSync(metricsFile);
  assert.equal(crypto.createHash('sha256').update(metricsBytes).digest('hex'), metadata.hashes['metrics.json']);
  const metrics = JSON.parse(metricsBytes.toString('utf8'));
  assert(metrics.backlog.samples.every(row => row.waiting_operations === row.prerequisite_waiting_operations && Number.isInteger(row.open_window_operations)));
  report.checks[`${prefix}_controlled_metrics_download_with_window_backlog`] = true;
}
(async () => {
  browser = await chromium.launch({ headless: true });
  try {
    const sourceContext = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const page = await sourceContext.newPage();
    try {
      await login(page, state.url);
      await page.getByRole('button', { name: `打开数据集 ${state.normal.dataset_name}`, exact: true }).click();
      await page.getByRole('region', { name: '数据集详情', exact: true }).waitFor();
      await page.getByLabel('运行模式', { exact: true }).selectOption('dual_source_replay');
      await page.getByLabel('选择配置版本', { exact: true }).selectOption(state.normal.config_id);
      await page.getByRole('button', { name: `选择运行预检 ${state.normal.preflight_id}`, exact: true }).click();
      const submitted = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v3/runs' && response.request().method() === 'POST')
        .then(async response => { assert.equal(response.status(), 201);return response.json(); });
      await page.getByRole('button', { name: '提交双源运行', exact: true }).click();
      const run = await submitted;assert(run.run.id);
      report.ui_submitted_run_id = run.run.id;
      await Promise.race([
        page.getByRole('link', { name: '查看关联图与原始证据', exact: true }).waitFor({ timeout: 180000 }),
        page.locator('[aria-label="运行详情"]').getByRole('alert').waitFor({ timeout: 180000 }).then(async () => { throw new Error(`Submitted replay failed: ${await page.locator('[aria-label="运行详情"]').getByRole('alert').innerText()}`); }),
      ]);
      await page.getByRole('link', { name: '查看关联图与原始证据', exact: true }).click();
      await page.getByRole('heading', { name: '双源顺序回放 · 历史证据核查', exact: true }).waitFor();
      await history(page, state.normal, 'ui-submitted-normal');
      report.checks.workspace_replay_mode_submitted_real_worker_run = true;
      await page.goto(state.url);await page.getByRole('region', { name: '数据集列表', exact: true }).waitFor();
      await openRun(page, state.unknown);await history(page, state.unknown, 'source-response-unknown', true);
    } catch (error) {
      try { if (currentPage && !currentPage.isClosed()) await shot(currentPage, 'source-failure'); } catch { /* preserve error */ }
      throw error;
    } finally { await sourceContext.close(); }
    const restoredContext = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    try {
      const page = await restoredContext.newPage();await login(page, state.restored_url);await openRun(page, state.normal);
      await history(page, state.normal, 'restored-normal');
      await page.goto(state.restored_url);await page.getByRole('region', { name: '数据集列表', exact: true }).waitFor();
      await openRun(page, state.unknown);await history(page, state.unknown, 'restored-response-unknown', true);
    } catch (error) {
      try { if (currentPage && !currentPage.isClosed()) await shot(currentPage, 'restored-failure'); } catch { /* preserve error */ }
      throw error;
    } finally { await restoredContext.close(); }
    const viewerContext = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    try {
      const page = await viewerContext.newPage();await login(page, state.url, true);
      await page.getByRole('button', { name: `打开数据集 ${state.normal.dataset_name}`, exact: true }).click();
      assert.equal(await page.getByRole('button', { name: '提交双源运行', exact: true }).count(), 0);
      await page.getByRole('button', { name: `查看运行 ${state.normal.run_id}`, exact: true }).click();
      await page.getByRole('link', { name: '查看关联图与原始证据', exact: true }).click();
      await history(page, state.normal, 'viewer-normal');report.checks.viewer_history_read_without_write_controls = true;
    } catch (error) {
      try { if (currentPage && !currentPage.isClosed()) await shot(currentPage, 'viewer-failure'); } catch { /* preserve error */ }
      throw error;
    } finally { await viewerContext.close(); }
    assert.deepEqual(report.page_errors, []);report.status = 'passed';
  } catch (error) {
    report.status = 'failed';report.error = scrub(error);
    try { if (currentPage && !currentPage.isClosed()) await shot(currentPage, 'failure'); } catch { /* preserve original error */ }
    throw error;
  }
  finally {
    const text = JSON.stringify(report, null, 2);assert(!secrets.some(secret => text.includes(secret)));
    fs.writeFileSync(path.join(out, 'browser-results.json'), text + '\n', { mode: 0o600 });await browser.close();
  }
})().catch(error => { console.error(scrub(error));process.exitCode = 1; });
