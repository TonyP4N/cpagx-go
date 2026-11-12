// Response-clock supplement: ordinary clicks against source and restored V3 UI.
// Private state is never copied to the public output directory.
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const crypto = require('crypto');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

if (!process.argv[2] || !process.argv[3]) throw new Error('usage: round17_response_browser.cjs PRIVATE/state.json OUTPUT_DIR');
const state = JSON.parse(fs.readFileSync(path.resolve(process.argv[2]), 'utf8'));
const out = path.resolve(process.argv[3]);
fs.mkdirSync(out, { recursive: true, mode: 0o700 });
for (const key of ['url', 'restored_url', 'username', 'password', 'dataset_name', 'run_id', 'restored_run_id', 'operation_id', 'change_id', 'network_hashes', 'analysis_download_sha256', 'process_hash'])
  assert(state[key], `missing private state ${key}`);
const scrub = value => String(value).split(state.password).join('[redacted]')
  .replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').replace(/cpag_session=[^;\s]+/gi, 'cpag_session=[redacted]');
const report = { status: 'running', synthetic_only: true, scope: 'generated response-clock boundary; no industrial validation', checks: {}, page_errors: [], screenshot_files: [] };
let browser;

async function shot(page, name) {
  await page.locator('input[type="password"]').evaluateAll(inputs => inputs.forEach(input => { input.value = ''; }));
  await page.screenshot({ path: path.join(out, `${name}.png`), fullPage: false });
  report.screenshot_files.push(`${name}.png`);
}
async function evidenceByClick(page, selection, id, click) {
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return response.request().method() === 'GET' && url.pathname.endsWith('/evidence') && url.searchParams.get(selection) === id;
  }).then(async response => {
    assert(response.ok(), `evidence read failed: ${response.status()}`);
    return response.json();
  });
  await click();
  return pending;
}
async function inspect(context, url, runId, prefix) {
  const page = await context.newPage();
  page.setDefaultTimeout(60000);
  page.on('pageerror', error => report.page_errors.push(scrub(error)));
  try {
    await page.goto(url);
    await page.getByRole('heading', { name: 'CPAG 研究工作台', exact: true }).waitFor();
    await page.getByLabel('用户名', { exact: true }).fill(state.username);
    await page.getByLabel('密码', { exact: true }).fill(state.password);
    await page.getByRole('button', { name: '登录', exact: true }).click();
    await page.getByRole('region', { name: '数据集列表', exact: true }).waitFor();
    await page.getByRole('button', { name: `打开数据集 ${state.dataset_name}`, exact: true }).click();
    await page.getByRole('region', { name: '数据集详情', exact: true }).waitFor();
    await page.getByRole('button', { name: `查看运行 ${runId}`, exact: true }).click();
    await page.getByRole('link', { name: '查看关联图与原始证据', exact: true }).click();
    await page.getByRole('region', { name: '双源结果摘要', exact: true }).waitFor();
    const graph = page.getByRole('region', { name: '双源关联图', exact: true });
    await graph.waitFor();
    await page.getByText('无关联候选；查看未知原因及孤立变化。', { exact: true }).waitFor();
    await page.getByText('response_clock_validity_outside', { exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name: /查看候选连线/ }).count(), 0);
    const operationButton = graph.getByRole('button').filter({ hasText: '评估：unknown · 响应：success' });
    assert.equal(await operationButton.count(), 1);
    report.checks[`${prefix}_unknown_visible_without_candidates`] = true;
    await page.getByRole('region', { name: '候选判断和未知原因', exact: true }).scrollIntoViewIfNeeded();
    await shot(page, `${prefix}-unknown-no-candidate`);

    const operation = await evidenceByClick(page, 'operation', state.operation_id,
      () => graph.getByRole('button', { name: `查看network节点 ${state.operation_id}`, exact: true }).click());
    assert.equal(operation.selection.operation.assessment, 'unknown');
    assert(operation.selection.operation.unknown_reasons.includes('response_clock_validity_outside'));
    assert.equal(operation.selection.operation.response.state, 'success');
    assert.equal(operation.verified_original_evidence.length, 2);
    assert.equal(operation.verified_network_fields.length, 2);
    const networkHashes = operation.verified_original_evidence.map(entry => entry.source_ref.file_sha256).sort();
    assert.deepEqual(networkHashes, [...state.network_hashes].sort());
    assert(operation.verified_original_evidence.every(entry => entry.source_ref.frame_number === 1 && entry.original.integrity === 'file_and_frame_sha256_verified'));
    await page.getByText('核查后的原始记录：2；核查后的网络字段：2', { exact: true }).waitFor();
    const evidence = page.getByRole('region', { name: '证据核查', exact: true });
    assert.equal(await evidence.getByRole('heading', { name: /^原始记录 [12]$/ }).count(), 2);
    await evidence.scrollIntoViewIfNeeded();
    {
      const original = evidence.locator('details').filter({ has: page.getByText('查看原始内容', { exact: true }) }).first();
      if (await original.getAttribute('open') === null) await original.getByText('查看原始内容', { exact: true }).click();
    }
    await shot(page, `${prefix}-operation-original-network`);
    report.checks[`${prefix}_operation_two_original_network_refs`] = true;

    const changed = await evidenceByClick(page, 'change', state.change_id,
      () => graph.getByRole('button', { name: `查看derived_event节点 ${state.change_id}`, exact: true }).click());
    assert.equal(changed.verified_original_evidence.length, 2);
    assert.equal(changed.verified_network_fields.length, 0);
    assert(changed.verified_original_evidence.every(entry => entry.source_ref.frame_number === null && Number.isInteger(entry.source_ref.record_number) && entry.source_ref.file_sha256 === state.process_hash));
    assert.deepEqual(changed.verified_original_evidence.map(entry => entry.source_ref.record_number).sort(), [2, 3]);
    for (const entry of changed.verified_original_evidence) {
      const expected = entry.source_ref.record_number === 2 ? ['2026-01-01T00:00:10.500000Z', '0'] : ['2026-01-01T00:00:12Z', '1'];
      assert.equal(entry.source_ref.column, 'pump');
      assert.equal(entry.source_ref.raw_time, expected[0]);
      assert.equal(entry.original.time, expected[0]);
      assert.equal(entry.original.pump, expected[1]);
    }
    await page.getByText('核查后的原始记录：2；核查后的网络字段：0', { exact: true }).waitFor();
    await evidence.scrollIntoViewIfNeeded();
    {
      const original = evidence.locator('details').filter({ has: page.getByText('查看原始内容', { exact: true }) }).first();
      if (await original.getAttribute('open') === null) await original.getByText('查看原始内容', { exact: true }).click();
    }
    await shot(page, `${prefix}-change-original-process`);
    report.checks[`${prefix}_separate_change_two_original_process_refs`] = true;
    report.checks[`${prefix}_combined_original_refs`] = 4;

    const pending = page.waitForEvent('download');
    await page.getByRole('button', { name: '下载 analysis.json', exact: true }).click();
    const download = await pending;
    const filename = path.join(out, `${prefix}-analysis.json`);
    await download.saveAs(filename);
    const bytes = fs.readFileSync(filename);
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), state.analysis_download_sha256);
    const analysis = JSON.parse(bytes.toString('utf8'));
    assert.equal(analysis.analysis_version, 'bounded-dual-source-2');
    assert.equal(analysis.network.length, 2);
    assert.equal(analysis.process.length, 5);
    assert.equal(analysis.changes.length, 1);
    assert.equal(analysis.candidates.length, 0);
    assert.equal(analysis.operations[0].assessment, 'unknown');
    assert.deepEqual(analysis.quality.operation_time_issues, [{ operation_id: state.operation_id, reasons: ['response_clock_validity_outside'] }]);
    assert.deepEqual(analysis.quality.unknown_reasons, []);
    report.checks[`${prefix}_controlled_download_matches_verified_artifact`] = true;
  } catch (error) {
    try { await shot(page, `${prefix}-failure`); } catch { /* the original error is retained */ }
    throw error;
  } finally {
    await page.close();
  }
}

(async () => {
  browser = await chromium.launch({ headless: true });
  try {
    // Separate contexts preserve the source/restored same-host cookie isolation.
    for (const [url, runId, prefix] of [[state.url, state.run_id, 'source'], [state.restored_url, state.restored_run_id, 'restored']]) {
      const context = await browser.newContext({ viewport: { width: 1440, height: 960 }, acceptDownloads: true });
      try { await inspect(context, url, runId, prefix); } finally { await context.close(); }
    }
    assert.deepEqual(report.page_errors, []);
    report.checks.source_and_restore_sessions_isolated = true;
    report.status = 'passed';
  } catch (error) {
    report.status = 'failed'; report.error = scrub(error);
    throw error;
  } finally {
    const serialized = JSON.stringify(report, null, 2);
    assert(!serialized.includes(state.password), 'secret in public report');
    fs.writeFileSync(path.join(out, 'browser-results.json'), serialized + '\n', { mode: 0o600 });
    await browser.close();
  }
})().catch(error => { console.error(scrub(error)); process.exitCode = 1; });
