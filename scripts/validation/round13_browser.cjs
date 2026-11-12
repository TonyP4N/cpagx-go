// Real browser acceptance against round13_celery.py --serve; no API mocks.
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const workspace = path.resolve(process.argv[2]);
const out = path.resolve(process.argv[3] || 'output/playwright/round13');
fs.mkdirSync(out, {recursive:true});
const run = JSON.parse(fs.readFileSync(path.join(workspace, 'results.json')));
(async () => {
 const browser = await chromium.launch({headless:true});
 const page = await browser.newPage({viewport:{width:1440,height:1000},acceptDownloads:true});
 const failures=[];page.on('pageerror',e=>failures.push(String(e)));
 const report={synthetic:true,checks:{},page_errors:failures};
 const body=()=>page.locator('body').innerText();
 const shot=async name=>page.screenshot({path:path.join(out,name+'.png'),fullPage:false});
 try {
  await page.goto((process.env.R13_UI_URL || run.ui_url)+'dual-source/');
  await page.getByRole('heading',{name:'合成双源验证',exact:true}).waitFor();
  fs.writeFileSync(path.join(out,'initial-dom.txt'),await page.locator('body').ariaSnapshot());
  const submit=page.getByRole('button',{name:'运行合成双源验证',exact:true});assert(await submit.isDisabled());
  for(const [label,name] of [['网络原始报文','network.pcap'],['过程采样 CSV','process.csv'],['合成配置 JSON','profile.json']])
   await page.getByLabel(label,{exact:true}).setInputFiles(path.join(workspace,'inputs/success',name));
  assert(await submit.isDisabled());await page.getByRole('checkbox').check();assert(await submit.isEnabled());
  const posted=page.waitForResponse(r=>r.url().endsWith('/cpag/dual-source') && r.request().method()==='POST');
  await submit.click();const response=await posted;assert.equal(response.status(),202);const created=await response.json();
  await page.getByRole('region',{name:'双源结果摘要',exact:true}).waitFor({timeout:90000});
  report.submitted_task_id=created.task_id;report.checks.actual_upload_complete=true;
  await page.getByRole('button',{name:/查看network节点/}).first().click();
  await page.getByText('核查后的原始记录：4；核查后的网络字段：2',{exact:true}).waitFor();
  assert.equal(await page.getByRole('heading',{name:/^原始记录 [1-4]$/}).count(),4);
  await page.getByRole('region',{name:'证据核查',exact:true}).getByText('查看原始内容',{exact:true}).first().click();
  await page.getByRole('region',{name:'证据核查',exact:true}).scrollIntoViewIfNeeded();await shot('normal-evidence');
  report.checks.four_original_references=true; assert((await body()).includes('仅协议响应，非物理成功')); assert((await body()).includes('192.0.2.1')); report.checks.readable_operation_summary=true;
  await page.getByRole('button',{name:/查看候选连线/}).first().click();
  await page.getByRole('region',{name:'证据核查',exact:true}).getByText(/已选择：candidate/).waitFor();
  await page.getByRole('region',{name:'双源关联图',exact:true}).scrollIntoViewIfNeeded();await shot('normal-graph');
  await page.getByRole('region',{name:'双源时间线',exact:true}).getByRole('button').first().click();
  await page.getByRole('region',{name:'证据核查',exact:true}).getByText(/已选择：operation/).waitFor();report.checks.graph_timeline_evidence_link=true;
  const download=page.waitForEvent('download');await page.getByRole('button',{name:'下载 analysis.json',exact:true}).click();const downloaded=await download;await downloaded.saveAs(path.join(out,'downloaded-analysis.json'));
  assert.equal(JSON.parse(fs.readFileSync(path.join(out,'downloaded-analysis.json'))).synthetic,true);report.checks.controlled_download=true;
  async function open(id){await page.getByLabel('合成双源任务 ID',{exact:true}).fill(id);await page.getByRole('button',{name:'读取任务',exact:true}).click();}
  for(const [name,needle] of [['error','counterevidence_present'],['missing_response','response_missing'],['mapping_missing','mapping_missing'],['mapping_conflict','mapping_conflict'],['ambiguous','ambiguous']]){
   await open(run.tasks[name]);await page.getByRole('region',{name:'双源结果摘要',exact:true}).waitFor();assert((await body()).includes(needle));
   await page.getByRole('button',{name:/查看network节点/}).first().click();await page.getByText(/核查后的原始记录：/).waitFor();
   fs.writeFileSync(path.join(out,name+'-dom.txt'),await page.locator('body').ariaSnapshot());report.checks[name]=needle;
   if(name==='ambiguous'){assert.equal(await page.getByRole('button',{name:/查看候选连线/}).count(),2);await page.getByRole('region',{name:'双源关联图',exact:true}).scrollIntoViewIfNeeded();await shot(name);}
  }
  await open(run.tasks.invalid);await page.getByRole('alert').filter({hasText:'任务失败'}).waitFor();assert.equal(await page.getByRole('region',{name:'双源结果摘要',exact:true}).count(),0);report.checks.invalid_failed=true;
  const file=path.join(workspace,'outputs',run.tasks.success,'analysis.json');const raw=fs.readFileSync(file);
  for(const mode of ['missing','tampered']){
   await open(run.tasks.success);await page.getByRole('region',{name:'双源结果摘要',exact:true}).waitFor();
   try {
    if(mode==='missing')fs.unlinkSync(file);else fs.writeFileSync(file,Buffer.concat([raw,Buffer.from(' ')]));
    await page.getByRole('button',{name:'刷新当前任务',exact:true}).click();await page.getByRole('alert').filter({hasText:'409'}).waitFor();
    assert.equal(await page.getByRole('region',{name:'双源结果摘要',exact:true}).count(),0);assert.equal(await page.getByText(/核查后的原始记录：/).count(),0);
    report.checks[mode+'_clears_untrusted_result']=true;await page.getByRole('alert').filter({hasText:'409'}).scrollIntoViewIfNeeded();await shot(mode);
   } finally {fs.writeFileSync(file,raw);}
  }
  await open('not-a-task');await page.getByRole('alert').filter({hasText:'400'}).waitFor();report.checks.invalid_task_id=true;
  await open(run.tasks.success);await page.getByRole('region',{name:'双源结果摘要',exact:true}).waitFor();
  await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));report.checks.mobile_page_no_horizontal_overflow=true;await page.getByRole('heading',{name:'合成双源验证',exact:true}).scrollIntoViewIfNeeded();await shot('mobile');
  assert.deepEqual(failures,[]);report.status='passed';
 } catch(e){report.status='failed';report.error=String(e);await shot('failure');throw e;}
 finally {fs.writeFileSync(path.join(out,'browser-results.json'),JSON.stringify(report,null,2));await browser.close();}
})();
