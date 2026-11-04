/** Defensive metadata fault injection, distinct from real legacy replay acceptance.
 * All authentication and other responses use the real service; only count is changed.
 * node round20_legacy_replay_boundaries.cjs RUN_CONTEXT STORAGE_STATE EXTERNAL_OUTPUT
 */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require(process.env.R20_PLAYWRIGHT||'playwright');
const info=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),output=path.resolve(process.argv[4]);fs.mkdirSync(output,{recursive:true,mode:0o700});
const result={scope:'defensive browser count-field injection only, not a real one-snapshot task acceptance',checks:{},pageErrors:[]};
const save=()=>fs.writeFileSync(path.join(output,'verification.json'),JSON.stringify(result,null,2)+'\n');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.R20_CHROME});
 try{
  const context=await browser.newContext({storageState:process.argv[3],viewport:{width:1440,height:1000}}),page=await context.newPage();page.setDefaultTimeout(12000);page.on('pageerror',e=>result.pageErrors.push(e.message));
  let probe={};
  const pathname=`/api/v3/runs/${info.runId}/result`;
  await page.route('**'+pathname,async route=>{
   const response=await route.fetch();assert.equal(response.status(),200);const document=await response.json();
   if(probe.missing)delete document.data.replay.snapshot_count;else document.data.replay.snapshot_count=probe.count;
   await route.fulfill({response,json:document});
  });
  for(const test of [{label:'count-one',count:1},{label:'missing-count',missing:true},{label:'zero-count',count:0},{label:'fractional-count',count:1.5},{label:'string-count',count:'16'}]){
   probe=test;await page.goto(info.url+`/workbench/?view=analysis&dataset=${info.datasetId}&run=${info.runId}`);
   const root=page.getByRole('region',{name:'分析工作区',exact:true}),graph=root.getByTestId('analysis-graph');
   result.buildId=await page.locator('#__NEXT_DATA__').evaluate(el=>JSON.parse(el.textContent).buildId);if(process.env.R20_EXPECT_BUILD)assert.equal(result.buildId,process.env.R20_EXPECT_BUILD);
   if(test.label==='count-one'){
    await graph.waitFor();assert.equal(await root.locator('input[name=analysis-snapshot]').getAttribute('max'),'0');
    const pending=page.waitForResponse(r=>new URL(r.url()).pathname===`/api/v3/runs/${info.runId}/evidence`);
    await root.getByRole('region',{name:'联动时间线',exact:true}).locator('li button').first().click();const response=await pending,query=Object.fromEntries(new URL(response.url()).searchParams);assert.equal(query.revision,'0');
    // Actual snapshot0 has no operation: the real backend must still reject it.
    assert.equal(response.status(),409);await root.getByRole('alert').waitFor();assert.equal(await graph.count(),0);
    result.checks[test.label]={status:'passed',terminalNumber:0,revision:query.revision,actualBackendStatus:response.status(),inconsistentSelectionRejected:true};
   }else{
    await root.getByRole('alert').filter({hasText:'旧回放缺少有效快照总数'}).waitFor();assert.equal(await graph.count(),0);assert.equal(await root.getByRole('region',{name:'联动原始证据',exact:true}).count(),0);
    result.checks[test.label]={status:'passed',trustedGraphAndEvidenceAbsent:true};
   }
   await page.screenshot({path:path.join(output,test.label+'.png'),fullPage:false});save();
  }
  assert.equal(result.pageErrors.length,0);result.status='passed';save();console.log(JSON.stringify(result));
 }catch(error){result.status='failed';result.failure=error.message;save();throw error;}finally{await browser.close();}
})().catch(error=>{console.error(error.message);process.exitCode=1});
