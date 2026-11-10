// Existing dual-source UI: restored task first, then explicit persistent submission.
const fs=require('fs'),path=require('path'),assert=require('assert');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const workspace=process.argv[2],out=process.argv[3];fs.mkdirSync(out,{recursive:true});
 const run=JSON.parse(fs.readFileSync(path.join(workspace,'ready.json')));
 const browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}});page.setDefaultTimeout(60000);
 const errors=[];page.on('pageerror',error=>errors.push(String(error)));const report={synthetic_only:true,checks:{},page_errors:errors};
 const shot=name=>page.screenshot({path:path.join(out,name+'.png'),fullPage:true});
 async function open(id){await page.getByLabel('合成双源任务 ID',{exact:true}).fill(id);await page.getByRole('button',{name:'读取任务',exact:true}).click();await page.getByRole('region',{name:'双源结果摘要',exact:true}).waitFor();}
 async function evidence(){await page.getByRole('button',{name:/查看network节点/}).first().click();await page.getByText('核查后的原始记录：4；核查后的网络字段：2',{exact:false}).waitFor();}
 try{
  await page.goto(run.ui_url);assert.equal(await page.getByLabel('执行路径',{exact:true}).inputValue(),'celery');
  await page.getByLabel('执行路径',{exact:true}).selectOption('persistent');await open(run.job);await evidence();
  report.checks.restored_task_four_original_refs=true;await shot('restored-evidence');
  await page.getByRole('button',{name:/查看候选连线/}).first().click();await evidence();report.checks.graph_candidate_and_evidence=true;
  const download=page.waitForEvent('download');await page.getByRole('button',{name:'下载 analysis.json',exact:true}).click();await (await download).saveAs(path.join(out,'restored-analysis.json'));report.checks.controlled_download=true;
  const file=path.join(run.shared_root,'jobs',run.job,'attempt-1','dual','sources','process.csv');const original=fs.readFileSync(file);const originalMode=fs.statSync(file).mode & 0o777;const parentMode=fs.statSync(path.dirname(file)).mode & 0o777;
  for(const mode of ['missing','tampered']){
   try{
    // Fault injection only in the disposable restored tree; production stays sealed.
    fs.chmodSync(path.dirname(file),0o700);fs.chmodSync(file,0o600);
    if(mode==='missing')fs.unlinkSync(file);else fs.writeFileSync(file,Buffer.concat([original,Buffer.from('tampered')]));
    await page.getByRole('button',{name:'刷新当前任务',exact:true}).click();await page.getByRole('alert').filter({hasText:'409'}).waitFor();assert.equal(await page.getByRole('region',{name:'双源结果摘要',exact:true}).count(),0);report.checks[mode+'_refused']=true;await shot(mode);
   }finally{fs.writeFileSync(file,original);fs.chmodSync(file,originalMode);fs.chmodSync(path.dirname(file),parentMode);}
   await open(run.job);
  }
  const fixtures=path.join(run.source_shared_root,'inputs');
  await page.getByLabel('网络原始报文',{exact:true}).setInputFiles(path.join(fixtures,'network.pcap'));
  await page.getByLabel('过程采样 CSV',{exact:true}).setInputFiles(path.join(fixtures,'process.csv'));
  await page.getByLabel('合成配置 JSON',{exact:true}).setInputFiles(path.join(fixtures,'profile.json'));
  await page.getByRole('checkbox').check();await page.getByRole('button',{name:'运行合成双源验证',exact:true}).click();
  await page.getByRole('region',{name:'双源结果摘要',exact:true}).waitFor({timeout:180000});await evidence();report.checks.upload_isolated_task_four_refs=true;await shot('new-task-evidence');
  fs.writeFileSync(path.join(out,'dom.txt'),await page.locator('body').ariaSnapshot());
  assert.deepEqual(errors,[]);report.status='passed';
 }catch(error){report.status='failed';report.error=String(error);await shot('failure');throw error;}
 finally{fs.writeFileSync(path.join(out,'browser-results.json'),JSON.stringify(report,null,2));await browser.close();}
})();
