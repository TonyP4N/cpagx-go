/** Real authorized service display probe. No response bodies or credentials are logged.
 * node round20_analysis_service.cjs PRIVATE_STATE OUTPUT_DIR [RUN_ID] [STATIC_ROOT]
 */
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { chromium } = require(process.env.R20_PLAYWRIGHT || 'playwright');
const state = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')), output = path.resolve(process.argv[3]), runId = process.argv[4] || state.run_id;
fs.mkdirSync(output, { recursive: true });
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.R20_CHROME || (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  assert.equal((await context.request.post(state.url + '/api/v3/session', {data:{username:state.username,password:state.password}})).status(), 200);
  const bindingResponse = await context.request.get(state.url + '/api/v3/runs/' + encodeURIComponent(runId)); assert.equal(bindingResponse.status(),200); const binding = (await bindingResponse.json()).run;
  const page = await context.newPage(), cdp = await context.newCDPSession(page), responses = [], errors = [];
  page.on('pageerror', error => errors.push(error.message)); page.on('response', response => { if (response.url().includes('/api/v3/runs/')) responses.push({path:new URL(response.url()).pathname + new URL(response.url()).search,status:response.status()}); });
  await cdp.send('HeapProfiler.collectGarbage'); const baseline = (await cdp.send('Runtime.getHeapUsage')).usedSize;
  const report = { scope:'Actual authorized verified S100 synthetic replay service view; no API interception, no source reanalysis, no reference-environment or real-industrial-data acceptance', runId, browser:browser.version(), platform:process.platform+'/'+process.arch, baselineHeapBytes:baseline, measurements:{}, checks:{} };
  const save = () => fs.writeFileSync(path.join(output,'service-browser-measurement.json'),JSON.stringify({...report,responses,errors},null,2)+'\n');
  try {
    const root = page.getByTestId('analysis-workspace'), graph = root.getByTestId('analysis-graph');
    let start = performance.now();
    await page.goto(state.url+'/workbench/?view=analysis&dataset='+encodeURIComponent(binding.dataset_id)+'&run='+encodeURIComponent(runId));
    report.servedBuildId = await page.evaluate(() => JSON.parse(document.getElementById('__NEXT_DATA__').textContent).buildId);
    if (process.argv[5]) { const html=fs.readFileSync(path.join(process.argv[5],'workbench/index.html'),'utf8');report.expectedBuildId=JSON.parse(html.match(/<script id="__NEXT_DATA__" type="application\/json">(.*?)<\/script>/s)[1]).buildId;assert.equal(report.servedBuildId,report.expectedBuildId);report.checks.frozenBuild=true; }
    await graph.waitFor({timeout:60000}); report.measurements.defaultReadyMs=performance.now()-start;
    report.measurements.defaultNodes=Number(await graph.getAttribute('data-nodes')); report.measurements.defaultEdges=Number(await graph.getAttribute('data-edges'));
    await cdp.send('HeapProfiler.collectGarbage');report.measurements.defaultHeapBytes=(await cdp.send('Runtime.getHeapUsage')).usedSize;save();
    await page.screenshot({path:path.join(output,'s100-default.png'),fullPage:true});
    start=performance.now();await root.getByRole('button',{name:'扩展视图 1000 / 3000',exact:true}).click();
    await page.waitForFunction(() => { const graph=document.querySelector('[data-testid="analysis-graph"]'); return graph?.dataset.nodes === '399' && graph?.dataset.edges === '2596'; }, {timeout:120000});
    report.measurements.expandedReadyMs=performance.now()-start;report.measurements.expandedNodes=Number(await graph.getAttribute('data-nodes'));report.measurements.expandedEdges=Number(await graph.getAttribute('data-edges'));report.measurements.fullDrawMs=Number(await graph.getAttribute('data-draw-ms'));
    await cdp.send('HeapProfiler.collectGarbage');report.measurements.expandedHeapBytes=(await cdp.send('Runtime.getHeapUsage')).usedSize;report.measurements.expandedHeapDeltaBytes=report.measurements.expandedHeapBytes-baseline;report.measurements.domNodes=await page.locator('*').count();save();
    assert.equal(report.measurements.expandedNodes,399);assert.equal(report.measurements.expandedEdges,2596);report.checks.actualGraphCounts=true;
    await page.screenshot({path:path.join(output,'s100-expanded.png'),fullPage:true});
    const timeline=root.getByRole('region',{name:'联动时间线',exact:true}), candidate=root.getByRole('region',{name:'联动候选',exact:true}), evidence=root.getByRole('region',{name:'联动原始证据',exact:true});
    start=performance.now();await timeline.getByRole('button').first().click();await evidence.getByText(/已核验原始记录/).waitFor({timeout:60000});report.measurements.selectEvidenceMs=performance.now()-start;
    report.checks.selectedRawEvidence=true;
    await candidate.getByRole('button',{name:'下一页',exact:true}).click();assert.match(await candidate.innerText(),/26–50/);report.checks.candidateSecondPage=true;
    await candidate.getByRole('button',{name:'上一页',exact:true}).click();
    await candidate.getByRole('button').filter({hasText:/规则/}).first().click();await evidence.getByRole('button',{name:'查看关联过程变化',exact:true}).waitFor({timeout:60000});report.checks.candidateEvidenceLink=true;
    report.checks.displayedBounds=true; report.status='passed selected display/pagination checks';save();
    console.log(JSON.stringify(report));
  } catch(error) {report.status='failed';report.failure=error.message;save();await page.screenshot({path:path.join(output,'s100-failure.png'),fullPage:true}).catch(()=>{});throw error;}
  finally {await browser.close();}
})().catch(error=>{console.error(error);process.exit(1)});
