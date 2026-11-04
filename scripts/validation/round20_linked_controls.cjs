/** Ordinary-click/keyboard regression for linked filtering and aggregate members.
 * node scripts/validation/round20_linked_controls.cjs PUBLIC_CONTEXT_JSON OUTPUT_DIR [STORAGE_STATE]
 * Public context: {url,datasetId,runId,asset?,snapshot?,staticRoot?}.
 * STORAGE_STATE is passed to Playwright only; credentials are never printed.
 * Uses the formal service throughout and delays one actual evidence response.
 */
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict'), crypto = require('node:crypto');
const { chromium } = require(process.env.R20_PLAYWRIGHT || 'playwright');
const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')), output = path.resolve(process.argv[3]);
assert(config.url && config.datasetId && config.runId, 'public context requires url, datasetId, runId');
for (const key of Object.keys(config)) assert(!/password|secret|token|cookie/i.test(key), 'public context must not contain credentials');
fs.mkdirSync(output, { recursive: true });
config.staticRoot ??= process.env.R20_STATIC_ROOT;
const origin = new URL(config.url).origin, base = '/api/v3/runs/' + encodeURIComponent(config.runId);
const report = { version: 'r20-linked-controls-1', status: 'running', boundary: 'ordinary browser controls against an isolated formal synthetic service; one real evidence response delayed; no industrial acceptance', checks: {}, api: [], uncaught: [], source: { script_sha256: hash(fs.readFileSync(__filename)) } };
function hash(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function save(name, value) { fs.writeFileSync(path.join(output, name), JSON.stringify(value, null, 2) + '\n'); }
async function bounded(promise, label, milliseconds = 15000) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out after ${milliseconds}ms`)), milliseconds); })]); }
  finally { clearTimeout(timer); }
}
const refs = value => value.map(row => JSON.stringify([row.source_slot, row.file_sha256 ?? null, row.frame_number, row.record_number, row.column, row.record_sha256 ?? null])).sort();
const subset = (wanted, actual) => refs(wanted).every(key => refs(actual).includes(key));
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.R20_CHROME || (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1100 }, reducedMotion: 'reduce', ...(process.argv[4] ? { storageState: process.argv[4] } : {}) });
  const page = await context.newPage(); page.setDefaultTimeout(12000);
  let releaseDelayed, delayedSeen, delayedFailed, delayedDone, delayArmed = false;
  const held = new Promise((resolve, reject) => { delayedSeen = resolve; delayedFailed = reject; }), delivered = new Promise(resolve => { delayedDone = resolve; });
  await page.route('**' + base + '/evidence**', async route => {
    const url = new URL(route.request().url());
    if (!delayArmed || url.pathname !== base + '/evidence') return route.continue();
    delayArmed = false;
    try {
      const response = await route.fetch(); assert.equal(response.status(), 200, 'delayed response must be an actual successful formal evidence response');
      const value = await response.json();
      report.delayed = { query: Object.fromEntries(url.searchParams), response_status: response.status(), selection: value.selection };
      save('delayed-evidence.json', value); delayedSeen(value);
      await new Promise(resolve => { releaseDelayed = resolve; });
      try { await route.fulfill({ response }); report.delayed.delivery = 'released'; }
      catch { report.delayed.delivery = 'discarded after browser abort'; }
    } catch (error) { delayedFailed(error); }
    finally { delayedDone(); }
  });
  page.on('pageerror', error => report.uncaught.push(error.message));
  page.on('response', response => { const url = new URL(response.url()); if (url.pathname === base + '/evidence') report.api.push({ status: response.status(), query: Object.fromEntries(url.searchParams) }); });
  try {
    const response = await context.request.get(origin + base + '/result'); assert.equal(response.status(), 200, 'formal result must already be verified');
    const metadata = await response.json();
    const last = config.snapshot ?? config.lastSnapshot ?? metadata.final_snapshot_number ?? metadata.data?.replay?.final_snapshot_number ?? (metadata.data?.replay?.snapshot_count - 1);
    assert(Number.isSafeInteger(Number(last)) && Number(last) >= 0, 'provide selected formal spool snapshot');
    config.snapshot = String(last); const picked = await context.request.get(origin + base + '/snapshots/' + last); assert.equal(picked.status(), 200);
    const snapshot = await picked.json();
    const contract = { result: metadata, last: Number(last), lastSnapshot: snapshot };
    save('actual-go-service-contract.json', contract);
    const analysis = snapshot.analysis, candidate = analysis.candidates.find(row => row.operation_id && row.change_id);
    assert(candidate, 'fixture must carry a saved linked candidate');
    const operation = analysis.operations.find(row => row.operation_id === candidate.operation_id), change = analysis.changes.find(row => row.event_id === candidate.change_id);
    assert(operation && change); const edge = snapshot.graph.edges.find(row => (row.claim_id ?? row.id) === candidate.candidate_id);
    assert(edge && edge.source === operation.operation_id && edge.target === change.event_id, 'saved edge, candidate and timeline member IDs must agree');
    const asset = config.asset ?? operation.mapping.asset_id; assert.equal(change.result.asset_id, asset);
    assert.equal(analysis.operations.filter(row => row.mapping?.asset_id === asset).length, 1); assert.equal(analysis.changes.filter(row => row.result?.asset_id === asset).length, 1);
    report.source.saved_ids = { operation: operation.operation_id, change: change.event_id, candidate: candidate.candidate_id, edge: edge.id, claim: edge.claim_id, asset };
    save('selected-snapshot.json', snapshot);
    const url = new URL('/workbench/', origin); url.search = new URLSearchParams({ view: 'analysis', dataset: config.datasetId, run: config.runId, a_snapshot: String(config.snapshot) });
    await page.goto(url.href);
    const root = page.getByRole('region', { name: '分析工作区', exact: true }), graph = root.getByTestId('analysis-graph'); await graph.waitFor();
    report.build_id = await page.locator('#__NEXT_DATA__').evaluate(element => JSON.parse(element.textContent).buildId);
    if (config.staticRoot) { const html = fs.readFileSync(path.join(config.staticRoot, 'workbench/index.html'), 'utf8'); const expected = JSON.parse(html.match(/<script id="__NEXT_DATA__" type="application\/json">(.*?)<\/script>/s)[1]).buildId; assert.equal(report.build_id, expected); report.checks.fixed_build_identity = true; }
    const timeline = root.getByRole('region', { name: '联动时间线', exact: true }), candidates = root.getByRole('region', { name: '联动候选', exact: true }), evidence = root.getByRole('region', { name: '联动原始证据', exact: true }), aggregate = root.getByRole('region', { name: '范围内聚合', exact: true });
    async function filter(text) { await root.getByLabel('记录、端点、资产或标签', { exact: true }).fill(text); await root.getByRole('button', { name: '应用筛选', exact: true }).click(); }
    async function counts(t, c, e) { await page.waitForFunction(({ t, c, e }) => { const root = document.querySelector('[data-testid="analysis-workspace"]'); return root?.querySelector('[aria-label="联动时间线"] ol')?.children.length === t && root?.querySelector('[aria-label="联动候选"] ul')?.children.length === c && Number(root?.querySelector('[data-testid="analysis-graph"]')?.getAttribute('data-edges')) === e; }, { t, c, e }); }
    async function selected(button, kind, id) {
      const pending = page.waitForResponse(response => { const q = new URL(response.url()); return q.pathname === base + '/evidence' && q.searchParams.get(kind === 'change' ? 'change' : 'operation') === (kind === 'candidate' ? operation.operation_id : id); });
      await button.click(); const response = await pending; assert.equal(response.status(), 200); const value = await response.json();
      await evidence.getByText(`${kind} · ${id}`, { exact: true }).waitFor(); await evidence.getByText(/已核验原始记录：本页 [1-9]/).waitFor();
      const selectedRow = value.selection?.[kind === 'candidate' ? 'operation' : kind]; assert.equal(selectedRow?.[kind === 'change' ? 'event_id' : 'operation_id'], kind === 'candidate' ? operation.operation_id : id);
      const expectedRefs = kind === 'change' ? change.evidence_refs : [...(operation.request_evidence ?? []), ...(operation.response?.evidence_refs ?? [])];
      assert(subset(expectedRefs, value.verified_original_evidence.map(row => row.source_ref)), 'selected member must resolve its own saved references');
      const detail = evidence.getByText('原始记录 1', { exact: true }); if ((await detail.locator('..').getAttribute('open')) === null) await detail.click(); const rendered = JSON.parse(await detail.locator('..').locator('pre').innerText()); assert.deepEqual(rendered, value.verified_original_evidence[0]);
      save(kind + '-evidence.json', value); contract[kind === 'change' ? 'withChange' : 'withNumber'] = value; save('actual-go-service-contract.json', contract); return value;
    }
    await filter(asset); await counts(2, 1, 1);
    const ids = await timeline.locator('li button').allTextContents(); assert(ids.some(text => text.includes(operation.operation_id)) && ids.some(text => text.includes(change.event_id)));
    assert((await candidates.locator('li button').innerText()).includes(candidate.candidate_id));
    report.checks.asset_filter_two_timeline_one_candidate_one_saved_edge = true;
    await selected(candidates.locator('li button'), 'candidate', candidate.candidate_id);
    await page.screenshot({ path: path.join(output, 'linked-ids.png'), fullPage: true });
    const typeControl = root.getByRole('form', { name: '分析筛选', exact: true }).locator('select').first();
    await typeControl.selectOption('candidate'); await filter(asset);
    await selected(candidates.locator('li button'), 'candidate', candidate.candidate_id);
    await selected(evidence.getByRole('button', { name: '查看关联网络操作', exact: true }), 'operation', operation.operation_id);
    await selected(candidates.locator('li button'), 'candidate', candidate.candidate_id);
    await selected(evidence.getByRole('button', { name: '查看关联过程变化', exact: true }), 'change', change.event_id);
    report.checks.candidate_kind_allows_deliberate_member_drilldown = true;
    await typeControl.selectOption(''); await filter(asset); await counts(2, 1, 1);
    delayArmed = true; await timeline.locator('li button').filter({ hasText: operation.operation_id }).click(); await bounded(held, 'actual evidence interception');
    await filter('no-match-fixed-regression-key'); await counts(0, 0, 0);
    await evidence.getByText('选择图节点、时间线记录或候选，查看其原始证据。', { exact: true }).waitFor();
    assert.equal(await evidence.getByText(/已核验原始记录：本页/).count(), 0); releaseDelayed(); await bounded(delivered, 'delayed evidence release'); await page.waitForTimeout(200);
    assert.equal(await evidence.getByText(/已核验原始记录：本页/).count(), 0); assert(!((await evidence.innerText()).includes(operation.operation_id)));
    report.checks.filtered_selection_and_late_verified_response_revoked = true;
    await page.screenshot({ path: path.join(output, 'late-response-remains-cleared.png'), fullPage: true });
    await root.getByRole('button', { name: '清除筛选', exact: true }).click(); await counts(2, 1, 1);
    await selected(timeline.locator('li button').filter({ hasText: change.event_id }), 'change', change.event_id); report.checks.clear_filter_allows_reselection = true;
    await aggregate.getByRole('combobox').selectOption('asset');
    const toggle = aggregate.getByRole('button', { name: new RegExp('分组 ' + asset + ' · 2$') });
    assert.equal(await toggle.getAttribute('aria-expanded'), 'false'); const controls = await toggle.getAttribute('aria-controls'); assert(controls, 'aggregate requires a controlled member region');
    const members = aggregate.locator(`[id=${JSON.stringify(controls)}]`);
    await toggle.click(); await members.getByRole('button', { name: `定位网络操作 ${operation.operation_id}`, exact: true }).waitFor(); assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
    await toggle.click(); assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
    await toggle.focus(); await page.keyboard.press('Enter'); assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
    await page.keyboard.press('Space'); assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
    await page.keyboard.press('Enter'); await members.getByRole('button', { name: `定位过程变化 ${change.event_id}`, exact: true }).waitFor();
    assert.equal(await members.getByRole('button', { name: /^定位/ }).count(), 2); report.checks.aggregate_mouse_and_keyboard_expand_collapse = true;
    await selected(members.getByRole('button', { name: `定位网络操作 ${operation.operation_id}`, exact: true }), 'operation', operation.operation_id);
    await selected(members.getByRole('button', { name: `定位过程变化 ${change.event_id}`, exact: true }), 'change', change.event_id);
    report.checks.aggregate_each_saved_member_resolves_own_originals = true;
    await page.screenshot({ path: path.join(output, 'aggregate-two-members-and-change-original.png'), fullPage: true });
    assert.deepEqual(report.uncaught, []); report.status = 'passed'; save('linked-controls-report.json', report); console.log(JSON.stringify({ status: report.status, build_id: report.build_id, checks: report.checks }));
  } catch (error) { report.status = 'failed'; report.failure = error.message; await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true }).catch(() => {}); save('linked-controls-report.json', report); throw error; }
  finally { releaseDelayed?.(); await context.close(); await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
