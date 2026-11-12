/** Explicit injected synthetic browser probe, not backend or industrial acceptance.
 * Usage: node scripts/validation/round20_analysis_browser.cjs PRIVATE_STATE_JSON OUTPUT_DIR
 * Private state supplies isolated test-service URL and test-account credentials; never printed.
 */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { chromium } = require(process.env.R20_PLAYWRIGHT || 'playwright');
const state = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const output = path.resolve(process.argv[3]); fs.mkdirSync(output, { recursive: true });
const now = 1700000000;
const operations = Array.from({ length: 500 }, (_, i) => ({ operation_id: `op-${i}`, operation: 'write', time: { interval: [now + i, now + i + 0.1] }, mapping: { asset_id: `asset-${i % 20}`, tag: 'RUN', config_version: 'fixture-1' }, assessment: 'unknown', response: { state: 'success' }, support: ['observed_protocol_response'], counterevidence: [], unknown_reasons: ['synthetic_fixture_only'] }));
const changes = Array.from({ length: 500 }, (_, i) => ({ event_id: `change-${i}`, result: { interval: [now + i, now + i + 1], asset_id: `asset-${i % 20}`, tag: 'RUN', before: 0, after: 1 }, unknown_reasons: ['sampling_time_uncertain'] }));
const candidates = Array.from({ length: 1000 }, (_, i) => ({ candidate_id: `candidate-${i}`, operation_id: `op-${i % 500}`, change_id: `change-${i % 500}`, state: 'unknown', rule_id: 'fixture-rule', rule_version: 'fixture-v1', window: [now + i % 500, now + i % 500 + 1], support: ['mapping', 'window'], counterevidence: [], unknown_reasons: ['hypothetical_only'] }));
const nodes = operations.flatMap((op, i) => [{ id: op.operation_id, event_id: op.operation_id, kind: 'network' }, { id: changes[i].event_id, event_id: changes[i].event_id, kind: 'derived_event' }]);
const edges = Array.from({ length: 3000 }, (_, i) => ({ id: `edge-${i}`, claim_id: `candidate-${i % 1000}`, source: `op-${i % 500}`, target: `change-${(i + Math.floor(i / 500)) % 500}`, candidate_state: 'unknown' }));
// Distinct candidate claims sharing endpoints must remain independently filterable.
edges[1000] = { ...edges[1000], claim_id: 'candidate-500', source: 'op-0', target: 'change-0' };
const metadata = { storage_format: 'shared-observation-dag-6', synthetic: true, mode: 'offline', manifest: { synthetic: true }, counts: { operations: 500, changes: 500, candidates: 1000, snapshots: 0 } };
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.R20_CHROME || (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  assert.equal((await context.request.post(state.url + '/api/v3/session', { data: { username: state.username, password: state.password } })).status(), 200);
  const binding = (await (await context.request.get(state.url + '/api/v3/runs/' + state.offline_run_id)).json()).run;
  const page = await context.newPage(), cdp = await context.newCDPSession(page), errors = [], requests = [];
  page.on('pageerror', error => errors.push(error.message));
  await cdp.send('HeapProfiler.collectGarbage'); const baseline = (await cdp.send('Runtime.getHeapUsage')).usedSize;
  let refuse = false, delayedResolve;
  const fulfill = (route, value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
  await page.route('**/api/v3/runs/' + state.offline_run_id + '/**', async route => {
    const url = new URL(route.request().url()), suffix = url.pathname.split(state.offline_run_id)[1];
    requests.push(suffix + url.search);
    if (refuse && suffix === '/evidence') return fulfill(route, { error: { code: 'result_changed', message: 'injected synthetic integrity failure' } }, 409);
    if (suffix === '/result') return fulfill(route, metadata);
    if (suffix === '/artifacts') return fulfill(route, { artifacts: [] });
    if (suffix === '/shared-query') {
      if (url.searchParams.get('action') === 'metadata') return fulfill(route, metadata);
      const part = JSON.parse(url.searchParams.get('path') || '[]').at(-1), arrays = { nodes, edges, operations, changes, candidates };
      const rows = arrays[part] || [], offset = Number(url.searchParams.get('offset') || 0), limit = Number(url.searchParams.get('limit') || 100);
      assert(limit <= 100 && limit >= 1); return fulfill(route, { items: rows.slice(offset, offset + limit), total: rows.length, offset, limit, returned: rows.slice(offset, offset + limit).length, has_more: offset + limit < rows.length });
    }
    if (suffix === '/evidence') {
      const id = url.searchParams.get('operation'), change = url.searchParams.get('change'), row = id ? operations.find(row => row.operation_id === id) : changes.find(row => row.event_id === change);
      if (!row) return fulfill(route, { error: { code: 'unknown_selection', message: 'not in fixture' } }, 422);
      if (id === 'op-7') await new Promise(resolve => { delayedResolve = resolve; setTimeout(resolve, 800); });
      const offset = Number(url.searchParams.get('ref_offset') || 0), limit = Number(url.searchParams.get('ref_limit') || 25), originals = Array.from({ length: 30 }, (_, i) => ({ source_ref: { file_sha256: 'f'.repeat(64), frame_number: id ? i + 1 : null, record_number: id ? null : i + 1, column: 'RUN', raw_time: now }, original: { fixture: true, selected_id: id || change, value: i } }));
      return fulfill(route, { synthetic: true, selection: id ? { operation: row } : { change: row }, verified_original_evidence: originals.slice(offset, offset + limit), evidence_page: { offset, limit, total: 30, returned: originals.slice(offset, offset + limit).length, has_more: offset + limit < 30 }, config_version: 'fixture-1', limitations: ['Injected synthetic fixture; not verified source bytes'] });
    }
    return route.continue();
  });
  const report = { scope: 'injected synthetic frontend-only; not backend capacity or source verification', osVersion: process.platform === 'darwin' ? execFileSync('sw_vers', ['-productVersion'], {encoding:'utf8'}).trim() : require('node:os').release(), osBuild: process.platform === 'darwin' ? execFileSync('sw_vers', ['-buildVersion'], {encoding:'utf8'}).trim() : require('node:os').version(), node: process.version, browser: browser.version(), platform: process.platform + '/' + process.arch, viewport: { width: 1440, height: 1000 }, preregistration: 'docs/refactor/round20-acceptance.md', measurements: {}, checks: {} };
  const root = page.getByTestId('analysis-workspace');
  let start = performance.now();
  await page.goto(state.url + '/workbench/?view=analysis&dataset=' + binding.dataset_id + '&run=' + state.offline_run_id);
  await root.getByTestId('analysis-graph').waitFor(); report.measurements.firstReadyMs = performance.now() - start;
  report.servedBuildId = await page.evaluate(() => JSON.parse(document.getElementById('__NEXT_DATA__').textContent).buildId);
  if (process.env.R20_STATIC_ROOT) {
    const html = fs.readFileSync(path.join(process.env.R20_STATIC_ROOT, 'workbench/index.html'), 'utf8');
    report.expectedBuildId = JSON.parse(html.match(/<script id="__NEXT_DATA__" type="application\/json">(.*?)<\/script>/s)[1]).buildId;
    assert.equal(report.servedBuildId, report.expectedBuildId, 'served export must match frozen candidate disk');
    report.checks.frozenBuildIdentity = true;
  }
  report.candidateScripts = await page.locator('script[src]').evaluateAll(elements => elements.map(element => element.src));
  report.candidateScriptsSha256 = crypto.createHash('sha256').update(JSON.stringify(report.candidateScripts)).digest('hex');
  assert.equal(await root.getByTestId('analysis-graph').getAttribute('data-nodes'), '200');
  assert.match(await root.getByTestId('analysis-clipping').innerText(), /局部视图/);
  start = performance.now(); await root.getByRole('button', { name: '扩展视图 1000 / 3000', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('[data-testid="analysis-graph"]')?.dataset.edges === '3000');
  report.measurements.expandReadyMs = performance.now() - start;
  const graph = root.getByTestId('analysis-graph');
  report.measurements.fullDrawMs = Number(await graph.getAttribute('data-draw-ms'));
  report.measurements.fullNodes = Number(await graph.getAttribute('data-nodes')); report.measurements.fullEdges = Number(await graph.getAttribute('data-edges'));
  report.measurements.domNodes = await page.locator('*').count();
  await cdp.send('HeapProfiler.collectGarbage'); const heap = await cdp.send('Runtime.getHeapUsage');
  report.measurements.jsHeapUsedBytes = heap.usedSize; report.measurements.jsHeapBaselineBytes = baseline; report.measurements.jsHeapDeltaBytes = heap.usedSize - baseline;
  fs.writeFileSync(path.join(output, 'analysis-browser-partial.json'), JSON.stringify(report, null, 2));
  await page.screenshot({ path: path.join(output, 'analysis-1000-3000.png'), fullPage: true });
  await root.getByLabel('记录、端点、资产或标签', {exact:true}).fill('candidate-0');
  await root.getByRole('button', {name:'应用筛选',exact:true}).click();
  await page.waitForFunction(() => document.querySelector('[data-testid="analysis-graph"]')?.dataset.edges === '1');
  report.checks.candidateFilterExcludesSiblingEdges = true;
  await root.getByRole('button', {name:'清除筛选',exact:true}).click();
  // Native buttons provide graph keyboard access and update the shared selection.
  await root.getByText('节点列表（键盘选择）', { exact: true }).click();
  const nodeButton = root.getByRole('button', { name: 'network · op-0', exact: true });
  await nodeButton.focus(); start = performance.now(); await page.keyboard.press('Enter');
  const evidence = root.getByRole('region', { name: '联动原始证据', exact: true });
  await evidence.getByText('已核验原始记录：本页 25 条 / 共 30 条', { exact: true }).waitFor(); report.measurements.selectEvidenceMs = performance.now() - start;
  assert.match(await evidence.innerText(), /operation · op-0/);
  await evidence.getByRole('button', { name: '下一页原始证据', exact: true }).click(); await evidence.getByText('已核验原始记录：本页 5 条 / 共 30 条', { exact: true }).waitFor();
  report.checks.rawEvidencePagination = true;
  const candidateRegion = root.getByRole('region', { name: '联动候选', exact: true });
  await candidateRegion.getByRole('button').filter({ hasText: 'candidate-0' }).click();
  await evidence.getByRole('button', { name: '查看关联过程变化', exact: true }).waitFor();
  await evidence.getByRole('button', { name: '查看关联过程变化', exact: true }).click();
  await evidence.getByText('change · change-0', { exact: true }).waitFor(); report.checks.candidateChangeLink = true;
  // Race: the later selection must win even when an old request resolves later.
  const timeline = root.getByRole('region', { name: '联动时间线', exact: true });
  await timeline.getByRole('button').filter({ hasText: /^.*op-7$/s }).click();
  await timeline.getByRole('button').filter({ hasText: /^.*op-8$/s }).click();
  if (delayedResolve) delayedResolve();
  await evidence.getByText('operation · op-8', { exact: true }).waitFor(); await page.waitForTimeout(850);
  assert.match(await evidence.innerText(), /operation · op-8/); assert.doesNotMatch(await evidence.innerText(), /operation · op-7/); report.checks.staleSelectionRejected = true;
  await root.getByLabel('记录、端点、资产或标签', { exact: true }).fill('10.42.0.17 sensitive-fixture-field');
  await root.getByRole('button', { name: '应用筛选', exact: true }).click();
  assert.equal(page.url().includes('10.42.0.17'), false); assert.equal(page.url().includes('sensitive-fixture-field'), false); report.checks.sensitiveFilterStaysOffUrl = true;
  await root.getByLabel('记录、端点、资产或标签', { exact: true }).fill('asset-1'); start = performance.now();
  await root.getByRole('button', { name: '应用筛选', exact: true }).click();
  await page.waitForFunction(() => Number(document.querySelector('[data-testid="analysis-graph"]')?.dataset.nodes) < 1000);
  report.measurements.filterMs = performance.now() - start;
  const url = new URL(page.url()); assert.equal(url.searchParams.get('dataset'), binding.dataset_id); assert.equal(url.searchParams.get('run'), state.offline_run_id); assert.equal(url.searchParams.get('view'), 'analysis'); assert.equal(url.searchParams.get('a_q'), null); assert.equal(page.url().includes('asset-1'), false); report.checks.routeContextPreserved = true;
  fs.writeFileSync(path.join(output, 'analysis-browser-partial.json'), JSON.stringify(report, null, 2));
  await root.getByRole('region', { name: '范围内聚合' }).locator('select').selectOption('asset'); assert.match(await root.getByRole('region', { name: '范围内聚合' }).innerText(), /asset-1/); report.checks.aggregation = true;
  await page.setViewportSize({ width: 390, height: 844 }); await page.waitForTimeout(100); report.measurements.mobileHorizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth); await page.screenshot({ path: path.join(output, 'analysis-mobile.png'), fullPage: true });
  await root.getByRole('button', { name: '清除筛选', exact: true }).click();
  // Reproduce workspace native-history navigation from an initially empty Next query.
  await page.goto(state.url + '/workbench/');
  await page.evaluate(target => { history.pushState(null, '', target); dispatchEvent(new PopStateEvent('popstate')); }, '/workbench/?view=analysis&dataset=' + binding.dataset_id + '&run=' + state.offline_run_id);
  await root.getByTestId('analysis-graph').waitFor();
  await root.getByLabel('记录、端点、资产或标签', { exact: true }).fill('10.42.0.17 sensitive-fixture-field');
  await root.getByRole('button', { name: '应用筛选', exact: true }).click();
  const nativeUrl = new URL(page.url()); assert.equal(nativeUrl.searchParams.get('dataset'), binding.dataset_id); assert.equal(nativeUrl.searchParams.get('run'), state.offline_run_id); assert.equal(nativeUrl.searchParams.get('view'), 'analysis'); assert.equal(nativeUrl.searchParams.get('a_q'), null); assert.equal(page.url().includes('10.42.0.17'), false); report.checks.nativeHistoryContextPreserved = true;
  await root.getByRole('button', { name: '清除筛选', exact: true }).click();
  refuse = true; await timeline.getByRole('button').filter({ hasText: /^.*op-0$/s }).click();
  await root.getByRole('alert').filter({ hasText: '409 result_changed' }).waitFor(); assert.equal(await root.getByTestId('analysis-graph').count(), 0); report.checks.integrityClearsTrustedData = true;
  refuse = false; await root.getByRole('button', {name:'重新核验',exact:true}).click();
  await root.getByTestId('analysis-graph').waitFor();
  await page.waitForFunction(() => document.querySelectorAll('.workbench [role="alert"]').length === 0);
  report.checks.parentErrorClearedAfterSuccessfulReverify = true;
  report.postRecoveryAlerts = await page.getByRole('alert').evaluateAll(elements => elements.map(element => ({ id: element.id, text: element.textContent, insideWorkbench: Boolean(element.closest('.workbench')) })));
  report.measurements.pageErrors = errors; report.measurements.apiRequests = requests.length;
  report.checks.budgets = report.measurements.firstReadyMs <= 5000 && report.measurements.fullDrawMs <= 1000 && report.measurements.selectEvidenceMs <= 1000 && report.measurements.filterMs <= 1000 && report.measurements.domNodes <= 2500 && report.measurements.jsHeapUsedBytes <= 192 * 1024 * 1024 && report.measurements.jsHeapDeltaBytes <= 128 * 1024 * 1024 && !errors.length;
  fs.writeFileSync(path.join(output, 'analysis-browser-measurement.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify(report));
  await browser.close(); assert.equal(report.checks.budgets, true, 'registered browser performance budgets');
})().catch(error => { console.error(error); process.exit(1); });
