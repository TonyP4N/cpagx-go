// Ordinary workbench click acceptance. Does not inject API requests or sessions.
// node round20_browser.cjs PRIVATE/state.json EXTERNAL_OUTPUT [main|roles|s100]
const fs=require('fs'),path=require('path'),assert=require('assert'),crypto=require('crypto');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const state=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const out=path.resolve(process.argv[3]),mode=process.argv[4]||'main';fs.mkdirSync(out,{recursive:true,mode:0o700});
const secrets=[state.password,state.viewer_password].filter(Boolean);
const scrub=x=>secrets.reduce((v,s)=>v.split(s).join('[redacted]'),String(x)).replace(/cpag_session=[^;\s]+/gi,'cpag_session=[redacted]');
const report={status:'running',synthetic_only:true,mode,checks:{},failures:[],page_errors:[],screenshots:[],responses:[]};
let browser,page,context;
const save=()=>fs.writeFileSync(path.join(out,'report.json'),JSON.stringify(report,null,2));
async function shot(name,p=page){await p.locator('input[type=password]').evaluateAll(a=>a.forEach(x=>x.value=''));await p.screenshot({path:path.join(out,name+'.png'),fullPage:false});report.screenshots.push(name+'.png');save();}
async function stage(name,fn){report.active_check=name;save();console.log('CHECK '+name);try{await fn();report.checks[name]={status:'passed'};}catch(e){report.failures.push({check:name,error:scrub(e)});await shot('failed-'+name).catch(()=>{});}save();}
async function posted(p,pattern,fn){const pending=p.waitForResponse(r=>r.request().method()==='POST'&&pattern.test(new URL(r.url()).pathname)).then(async r=>({status:r.status(),value:await r.json().catch(()=>({}))}));await fn();return pending;}
async function login(p,user,password){await p.getByLabel('用户名',{exact:true}).fill(user);await p.getByLabel('密码',{exact:true}).fill(password);await p.getByRole('button',{name:'登录',exact:true}).click();await p.getByRole('navigation',{name:'工作区导航'}).waitFor();assert(!(await p.locator('body').innerText()).includes(password));const storage=await p.evaluate(()=>({cookie:document.cookie,local:JSON.stringify({...localStorage}),session:JSON.stringify({...sessionStorage})}));assert(!storage.cookie.includes('cpag_session='));assert(!Object.values(storage).some(x=>x.includes(password)));}
async function nav(name,p=page){await p.getByRole('navigation',{name:'工作区导航'}).getByRole('link',{name,exact:true}).click();}
async function selectDataset(name,p=page){await nav('数据与配置',p);await p.getByRole('button',{name:'打开数据集 '+name,exact:true}).click();await p.getByRole('region',{name:'数据集详情',exact:true}).waitFor();}
async function openRun(name,id,p=page){await selectDataset(name,p);await nav('任务中心',p);await p.getByRole('button',{name:'查看运行 '+id,exact:true}).click();await p.getByLabel('运行详情',{exact:true}).waitFor();}
async function trusted(p=page){
 const region=p.getByRole('region',{name:'关系图',exact:true});
 for(let i=0;i<60;i++){
  if(await region.count())return;
  const errors=(await p.getByRole('alert').allTextContents()).map(s=>s.trim()).filter(Boolean);
  if(errors.length&& !errors.every(s=>/verification_pending|来源|核验|409/.test(s)))throw Error(errors.join(';'));
  const b=p.getByRole('button',{name:'重新核验',exact:true});
  if(await b.count()&&await b.first().isEnabled())await b.first().click();
  await p.waitForTimeout(1000);
 }
 throw Error('trusted analysis did not become available: '+await p.locator('body').innerText());
}
async function inspectAnalysis(name,id,prefix){
 await openRun(name,id);await nav('分析结果');await trusted();
 const timeline=page.getByRole('region',{name:'联动时间线',exact:true});
 await timeline.getByRole('button').first().click();
 const evidence=page.getByRole('region',{name:'联动原始证据',exact:true});
 await evidence.getByText(/已核验原始记录：本页 4 条/).waitFor();
 assert.equal(await evidence.locator('summary').filter({hasText:/^原始记录 [1-4]$/}).count(),4);
 await evidence.scrollIntoViewIfNeeded();await shot(prefix+'-evidence');
 const candidate=page.getByRole('region',{name:'联动候选',exact:true}).getByRole('button').filter({hasText:/规则/}).first();
 await candidate.click();await evidence.getByRole('button',{name:'查看关联过程变化',exact:true}).waitFor();
 await evidence.getByRole('button',{name:'查看关联过程变化',exact:true}).click();await evidence.getByText(/已核验原始记录：本页 2 条/).waitFor();
 await page.getByLabel('记录、端点、资产或标签',{exact:true}).fill('definitely-no-synthetic-match');
 await page.getByRole('button',{name:'应用筛选',exact:true}).click();
 await timeline.getByText('当前范围没有符合筛选的操作或变化。',{exact:true}).waitFor();
 assert.equal(await page.getByRole('region',{name:'关系图',exact:true}).getByTestId('analysis-graph').getAttribute('data-nodes'),'0');
 await page.getByRole('button',{name:'清除筛选',exact:true}).click();
 await page.getByLabel('聚合维度').selectOption('asset');
 await page.getByRole('region',{name:'范围内聚合',exact:true}).getByText('synthetic-pump',{exact:true}).waitFor();
 await page.getByRole('region',{name:'关系图',exact:true}).scrollIntoViewIfNeeded();await shot(prefix+'-analysis');
 const url=page.url();await page.reload();await trusted();assert.equal(page.url(),url);
}
async function main(){
 await stage('restored-offline-linked-evidence',()=>inspectAnalysis('R19 formal backup-offline',state.offline_run_id,'restored-offline'));
 await stage('multi-device-and-time-order',async()=>{
  const run=state.ui_cases['multi-device'];await openRun('R20 UI multi-device',run.run_id);await nav('分析结果');await trusted();
  await page.getByLabel('聚合维度').selectOption('asset');
  const groups=page.getByRole('region',{name:'范围内聚合',exact:true});await groups.getByText('synthetic-valve',{exact:true}).waitFor();await groups.getByText('synthetic-pump',{exact:true}).waitFor();await shot('multi-device');
  const order=state.ui_cases.out_of_order;await openRun('R20 UI out_of_order',order.run_id);await nav('分析结果');await trusted();
  const text=await page.getByRole('region',{name:'联动时间线',exact:true}).innerText();assert(text.indexOf('00:00:10.000 UTC')>=0&&text.indexOf('00:00:10.500 UTC')>=0&&text.indexOf('00:00:10.000 UTC')<text.indexOf('00:00:10.500 UTC'));await shot('out-of-order');
 });
 await stage('empty-candidates-and-failed-over-limit',async()=>{
  await openRun('R20 UI no_change',state.ui_cases.no_change.run_id);await nav('分析结果');await trusted();
  await page.getByRole('region',{name:'联动候选',exact:true}).getByText('当前范围没有符合筛选的候选。',{exact:true}).waitFor();await shot('no-change-empty-candidates');
  for(const c of ['empty-process','replay-limit']){
   await openRun('R20 UI '+c,state.ui_cases[c].run_id);const detail=page.getByLabel('运行详情',{exact:true});assert(/failed|执行失败/.test(await detail.innerText()));
   await shot(c+'-failed');
   const response=await posted(page,/\/runs\/[^/]+\/retry$/,()=>page.getByRole('button',{name:'重试此运行',exact:true}).click());assert.equal(response.status,409);assert.equal(response.value.error.code,'retry_conflict');
   await page.getByRole('alert').filter({hasText:'retry_conflict'}).waitFor();
   await nav('分析结果');await page.getByRole('heading',{name:'尚无可查看的运行结果',exact:true}).waitFor();
  }
 });
 await stage('restored-replay-prefix-and-revisions',async()=>{
  await openRun('R19 formal backup-replay',state.replay_run_id);await nav('顺序回放');
  const input=page.locator('input[name=replay-snapshot]');for(let i=0;i<90;i++){if(await input.count())break;const retry=page.getByRole('button',{name:'重新核验',exact:true});if(await retry.count()&&await retry.first().isEnabled())await retry.first().click();await page.waitForTimeout(1000);}await input.waitFor();
  for(let i=0;i<50;i++){if(await page.getByRole('region',{name:'选中时刻',exact:true}).count())break;const b=page.getByRole('button',{name:'重新核验',exact:true});if(await b.count())await b.first().click();await page.waitForTimeout(1000);}
  await input.fill('0');await page.getByRole('button',{name:'查看该时刻',exact:true}).click();await page.getByRole('region',{name:'选中时刻',exact:true}).getByRole('heading',{name:/快照 0 ·/}).waitFor();
  await page.getByRole('region',{name:'历史事实',exact:true}).getByText('该时刻尚无此类事实。',{exact:true}).waitFor();assert.equal(await page.getByRole('alert').filter({hasText:'verification_pending'}).count(),0,'successful replay retained pending-error banner');await page.getByRole('region',{name:'选中时刻',exact:true}).scrollIntoViewIfNeeded();await shot('replay-zero-prefix');
  const max=await input.getAttribute('max');await input.fill(max);await page.getByRole('button',{name:'查看该时刻',exact:true}).click();await page.getByRole('region',{name:'历史事实',exact:true}).getByRole('button',{name:'查看支持、反证与原始记录',exact:true}).first().waitFor();
  await page.getByRole('region',{name:'历史事实',exact:true}).getByRole('button',{name:'查看支持、反证与原始记录',exact:true}).first().click();await page.getByRole('region',{name:'历史原始证据',exact:true}).waitFor();
  await page.getByRole('region',{name:'不可变修订历史',exact:true}).getByRole('button',{name:/^修订 /}).first().click();await shot('replay-revision-and-evidence');
  const url=page.url();await page.reload();await input.waitFor();assert.equal(page.url(),url);
 });
 await stage('restored-independent-evaluation',async()=>{
  await openRun('R19 formal backup-replay',state.replay_run_id);await nav('独立评估');await page.getByRole('region',{name:'指标与分母',exact:true}).waitFor();
  await page.getByRole('region',{name:'评估适用范围',exact:true}).getByText('合成软件计算',{exact:true}).waitFor();
  const selector=page.getByLabel('查看类型');await selector.selectOption('matches');
  const prediction=page.getByRole('button',{name:'核验预测原件',exact:true});if(await prediction.count()){await prediction.first().click();await page.getByRole('region',{name:'评估原始证据',exact:true}).waitFor();}
  const reference=page.getByRole('button',{name:'核验独立参考原件',exact:true});if(await reference.count()){await reference.first().click();await page.getByRole('region',{name:'评估原始证据',exact:true}).waitFor();}
  await page.getByRole('region',{name:'指标与分母',exact:true}).scrollIntoViewIfNeeded();await shot('evaluation-frozen-versions-and-denominators');
  const download=page.waitForEvent('download');await page.getByRole('link',{name:'下载完整已核验评估包',exact:true}).click();await (await download).saveAs(path.join(out,'restored-evaluation.json'));
 });
 await stage('narrow-screen-and-keyboard',async()=>{
  await page.setViewportSize({width:390,height:844});await page.goto(state.url+'/workbench/');await page.getByRole('navigation',{name:'工作区导航'}).waitFor();
  const sizes=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));assert(sizes.scroll<=sizes.width+1,'horizontal page overflow: '+JSON.stringify(sizes));await shot('narrow-navigation');await openRun('R19 formal backup-offline',state.offline_run_id);await nav('分析结果');await trusted();await page.getByRole('region',{name:'关系图',exact:true}).scrollIntoViewIfNeeded();const resultSizes=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));assert(resultSizes.scroll<=resultSizes.width+1,'narrow result overflow: '+JSON.stringify(resultSizes));await shot('narrow-analysis');
  await page.keyboard.press('Tab');assert(await page.locator(':focus').count());await page.setViewportSize({width:1440,height:960});
 });
}
async function ordinarySubmission(mode){
 const replay=mode==='replay';await selectDataset('R19 formal backup-'+mode);
 const historical=page.getByRole('button',{name:/^选择运行预检 /}).first();await historical.click();
 const versions=page.getByLabel('选择配置版本',{exact:true});const dual=versions.locator('option').filter({hasText:/^dual v/}).first();const id=await dual.getAttribute('value');assert(id);await versions.selectOption(id);
 await page.getByLabel('运行模式',{exact:true}).selectOption(replay?'dual_source_replay':'dual_source');
 const response=await posted(page,/\/runs$/,()=>page.getByRole('button',{name:'提交双源运行',exact:true}).click());assert.equal(response.status,201);const run=response.value.run.id;
 await page.getByRole('button',{name:'查看运行 '+run,exact:true}).click();const detail=page.getByLabel('运行详情',{exact:true});await detail.getByText(new RegExp(run+' · (succeeded|执行完成) · attempt 1')).waitFor({timeout:150000});await detail.getByText(/已登记 1 次执行，已确认退出 1 次/).waitFor();await shot('ordinary-new-'+mode+'-attempt1-succeeded');
 await nav('分析结果');await trusted();await page.getByRole('region',{name:'联动时间线',exact:true}).getByRole('button').first().click();await page.getByRole('region',{name:'联动原始证据',exact:true}).getByText(/已核验原始记录：本页 4 条/).waitFor();await shot('ordinary-new-'+mode+'-four-raw-references');
 report.ordinary_new_runs=report.ordinary_new_runs||{};report.ordinary_new_runs[mode]={run_id:run,state:'succeeded',attempt:1,ordinary_click_submission:true,verified_original_refs:4};
}
async function crossRun(){
 await openRun('R19 formal backup-offline',state.offline_run_id);await nav('分析结果');await trusted();
 const firstTimeline=page.getByRole('region',{name:'联动时间线',exact:true}).getByRole('button').first();
 let release,observed;const gate=new Promise(r=>release=r),ready=new Promise(r=>observed=r);let held=false,delivered=false;
 const pattern='**/api/v3/runs/'+state.offline_run_id+'/evidence?*';
 await page.route(pattern,async route=>{const response=await route.fetch();held=true;observed();await gate;try{await route.fulfill({response});delivered=true;}catch(e){if(!/closed|cancel|disposed|already handled|Invalid InterceptionId|Target page/.test(String(e)))throw e;}});
 try{
  await firstTimeline.click();await ready;
  const target={run_id:state.replay_run_id};await openRun('R19 formal backup-replay',target.run_id);await nav('分析结果');await trusted();
  await page.getByRole('region',{name:'联动时间线',exact:true}).getByRole('button').first().click();const evidence=page.getByRole('region',{name:'联动原始证据',exact:true});await evidence.getByText(/已核验原始记录：本页 4 条/).waitFor();
  const before=await evidence.innerText();assert.equal(new URL(page.url()).searchParams.get('run'),target.run_id);release();await page.waitForTimeout(700);assert.equal(await evidence.innerText(),before,'late A evidence replaced B selection');assert.equal(new URL(page.url()).searchParams.get('run'),target.run_id);await shot('cross-run-late-A-cannot-replace-B');
  for(let i=0;i<7;i++){await page.goBack();const url=new URL(page.url());if(url.searchParams.get('run')===state.offline_run_id&&url.searchParams.get('view')==='analysis')break;}
  assert.equal(new URL(page.url()).searchParams.get('run'),state.offline_run_id);await page.reload();await trusted();assert.equal(new URL(page.url()).searchParams.get('run'),state.offline_run_id);assert((await page.locator('.wb-context').innerText()).includes(state.offline_run_id));await shot('cross-run-back-and-reload-A-context');
  report.cross_run={actual_A_response_held:held,actual_A_response_delivered_or_request_cancelled:held,late_response_fulfilled:delivered,B_selection_unchanged:true,back_refresh_A_context:true};
 }finally{release();await page.unroute(pattern);}
}
async function security(){
 await selectDataset('R19 formal backup-offline');await nav('用户与授权');
 const analystName='r20-analyst-'+crypto.randomBytes(3).toString('hex'),password=crypto.randomBytes(24).toString('hex');secrets.push(password);
 await page.getByLabel('新用户名',{exact:true}).fill(analystName);await page.getByLabel('初始密码',{exact:true}).fill(password);await page.getByLabel('新用户角色',{exact:true}).selectOption('analyst');
 const created=await posted(page,/\/users$/,()=>page.getByRole('button',{name:'创建用户',exact:true}).click());assert.equal(created.status,201);
 await page.getByLabel('授权用户',{exact:true}).selectOption({label:analystName});await page.getByLabel('授权级别',{exact:true}).selectOption('analyst');const granted=await posted(page,/\/datasets\/[^/]+\/acl$/,()=>page.getByRole('button',{name:'保存授权',exact:true}).click());assert(granted.status>=200&&granted.status<300);
 const ac=await browser.newContext({viewport:{width:1440,height:960}}),ap=await ac.newPage();ap.setDefaultTimeout(30000);ap.on('dialog',d=>d.accept());
 try{
  await ap.goto(state.url+'/workbench/');await login(ap,analystName,password);await selectDataset('R19 formal backup-offline',ap);assert.equal(await ap.getByRole('button',{name:'上传并校验',exact:true}).count(),1);assert.equal(await ap.getByRole('navigation',{name:'工作区导航'}).getByRole('link',{name:'用户与授权',exact:true}).count(),0);
  await ap.getByLabel('配置类型',{exact:true}).selectOption('dual');await ap.getByLabel('配置 JSON',{exact:true}).fill(fs.readFileSync(path.join(state.fixture_dir,'profile.json'),'utf8'));const saved=await posted(ap,/\/datasets\/[^/]+\/configs$/,()=>ap.getByRole('button',{name:'保存新版本',exact:true}).click());assert.equal(saved.status,201);await shot('analyst-native-config-write-allowed',ap);report.analyst={created_native:true,grant:'analyst',configuration_write_status:saved.status,admin_navigation_hidden:true};
 }finally{await ac.close();}
 const vc=await browser.newContext({viewport:{width:1440,height:960}}),vp=await vc.newPage();vp.setDefaultTimeout(30000);
 try{
  await vp.goto(state.url+'/workbench/');await login(vp,state.viewer_username,state.viewer_password);await openRun('R19 formal backup-offline',state.offline_run_id,vp);await nav('独立评估',vp);await vp.getByLabel('已保存评估').waitFor();assert.equal(await vp.locator('input[name=evaluation-bundle]').count(),0);await shot('viewer-no-evaluation-import',vp);
  const url=state.url+'/api/v3/runs/'+state.ui_cases['multi-device'].run_id+'/artifacts/shared/shared.sqlite3/download';const refused=await vp.goto(url);assert([403,404].includes(refused.status()));const text=await vp.locator('body').innerText();assert(/forbidden|not_found/.test(text));await shot('viewer-ungranted-download-rejected',vp);report.viewer_download={status:refused.status(),artifact_body_delivered:false};
 }finally{await vc.close();}
 const anon=await browser.newContext(),anonPage=await anon.newPage();try{const denied=await anonPage.goto(state.url+'/api/v3/runs/'+state.offline_run_id+'/artifacts/shared/shared.sqlite3/download');assert.equal(denied.status(),401);report.anonymous_download={status:401,artifact_body_delivered:false};}finally{await anon.close();}
}
async function semantics(){
 for(const key of ['ambiguous','error','missing_response']){
  await openRun('R20 UI '+key,state.ui_cases[key].run_id);await nav('分析结果');await trusted();
  const candidates=page.getByRole('region',{name:'联动候选',exact:true});const buttons=candidates.getByRole('button').filter({hasText:/规则/});
  if(key==='ambiguous'){assert.equal(await buttons.count(),2);assert((await candidates.innerText()).includes('ambiguous'));}
  if(key==='error'){assert(/反证 [1-9]/.test(await candidates.innerText()),'error response must retain counterevidence');}
  if(key==='missing_response'){await page.getByRole('region',{name:'联动时间线',exact:true}).getByRole('button').first().click();const evidence=page.getByRole('region',{name:'联动原始证据',exact:true});await evidence.getByText(/未知原因：/).waitFor();assert(/response|unknown|missing|响应|未知/.test(await evidence.innerText()));}
  if(await buttons.count()){await buttons.first().click();await page.getByRole('region',{name:'联动原始证据',exact:true}).getByText(/已核验原始记录：本页/).waitFor();}
  await page.getByRole('region',{name:'联动候选',exact:true}).scrollIntoViewIfNeeded();await shot(key+'-uncertainty-counterevidence');
 }
}
async function replayCheck(){
  await openRun('R19 formal backup-replay',state.replay_run_id);await nav('顺序回放');
  const input=page.locator('input[name=replay-snapshot]');for(let i=0;i<90;i++){if(await input.count())break;const retry=page.getByRole('button',{name:'重新核验',exact:true});if(await retry.count()&&await retry.first().isEnabled())await retry.first().click();await page.waitForTimeout(1000);}await input.waitFor();
  for(let i=0;i<50;i++){if(await page.getByRole('region',{name:'选中时刻',exact:true}).count())break;const b=page.getByRole('button',{name:'重新核验',exact:true});if(await b.count())await b.first().click();await page.waitForTimeout(1000);}
  await input.fill('0');await page.getByRole('button',{name:'查看该时刻',exact:true}).click();await page.getByRole('region',{name:'选中时刻',exact:true}).getByRole('heading',{name:/快照 0 ·/}).waitFor();
  await page.getByRole('region',{name:'历史事实',exact:true}).getByText('该时刻尚无此类事实。',{exact:true}).waitFor();assert.equal(await page.getByRole('alert').filter({hasText:'verification_pending'}).count(),0,'successful replay retained pending-error banner');await page.getByRole('region',{name:'选中时刻',exact:true}).scrollIntoViewIfNeeded();await shot('replay-zero-prefix');
  const max=await input.getAttribute('max');await input.fill(max);await page.getByRole('button',{name:'查看该时刻',exact:true}).click();await page.getByRole('region',{name:'历史事实',exact:true}).getByRole('button',{name:'查看支持、反证与原始记录',exact:true}).first().waitFor();
  await page.getByRole('region',{name:'历史事实',exact:true}).getByRole('button',{name:'查看支持、反证与原始记录',exact:true}).first().click();await page.getByRole('region',{name:'历史原始证据',exact:true}).waitFor();
  await page.getByRole('region',{name:'不可变修订历史',exact:true}).getByRole('button',{name:/^修订 /}).first().click();await shot('replay-revision-and-evidence');
  const url=page.url();await page.reload();await input.waitFor();assert.equal(page.url(),url);
}
async function multiDevice(){
 await openRun('R20 UI multi-device',state.ui_cases['multi-device'].run_id);await nav('分析结果');await trusted();
 await page.getByLabel('聚合维度').selectOption('asset');const groups=page.getByRole('region',{name:'范围内聚合',exact:true});await groups.getByText('synthetic-pump',{exact:true}).waitFor();await groups.getByText('synthetic-valve',{exact:true}).waitFor();
 const rows=page.getByRole('region',{name:'联动时间线',exact:true});const evidence=page.getByRole('region',{name:'联动原始证据',exact:true});report.multi_device=[];
 for(const [tag,asset] of [['pump_state','synthetic-pump'],['valve_state','synthetic-valve']]){
  await rows.getByRole('button').filter({hasText:tag+' ·'}).click();await evidence.getByText(/已核验原始记录：本页 2 条/).waitFor();
  const selectedDetails=evidence.locator('details').filter({has:page.locator('summary').filter({hasText:'完整观测、支持、反证与未知原因'})});if(await selectedDetails.getAttribute('open')===null)await selectedDetails.locator('summary').click();const selected=JSON.parse(await selectedDetails.locator('pre').innerText());assert.equal(selected.result.asset_id,asset);assert.equal(selected.result.tag,tag);
  const rawDetails=evidence.locator('details').filter({has:page.locator('summary').filter({hasText:/^原始记录 1$/})});if(await rawDetails.getAttribute('open')===null)await rawDetails.locator('summary').click();const first=JSON.parse(await rawDetails.locator('pre').innerText());assert(first.source_ref.record_number);await evidence.scrollIntoViewIfNeeded();await shot('multi-device-'+asset+'-own-originals');report.multi_device.push({asset,tag,change_id:selected.event_id,record_number:first.source_ref.record_number,verified_refs:2});
 }
 const order=state.ui_cases.out_of_order;await openRun('R20 UI out_of_order',order.run_id);await nav('分析结果');await trusted();const text=await page.getByRole('region',{name:'联动时间线',exact:true}).innerText();assert(text.indexOf('00:00:10.000 UTC')>=0&&text.indexOf('00:00:10.500 UTC')>=0&&text.indexOf('00:00:10.000 UTC')<text.indexOf('00:00:10.500 UTC'));await shot('out-of-order-sorted-timeline');
}
async function evaluationErrors(){
 await openRun('R19 formal backup-replay',state.replay_run_id);await nav('独立评估');for(let i=0;i<90;i++){if(await page.getByRole('region',{name:'指标与分母',exact:true}).count())break;const refresh=page.getByRole('button',{name:'刷新列表',exact:true});const loading=page.getByRole('status').filter({hasText:'正在核验评估与当前发布绑定'});if(await refresh.count()&&!(await loading.count()))await refresh.click();await page.waitForTimeout(1000);}await page.getByRole('region',{name:'指标与分母',exact:true}).waitFor();
 const metrics=await page.getByRole('region',{name:'指标与分母',exact:true}).innerText();assert(/TP 1 · FP 1 · FN 1/.test(metrics));const types=page.getByLabel('查看类型');report.evaluation_error_trace={tp:1,fp:1,fn:1};
 await types.selectOption('false_positives');await page.getByRole('button',{name:'核验预测原件',exact:true}).first().click();const region=page.getByRole('region',{name:'评估原始证据',exact:true});await region.waitFor();let detail=JSON.parse(await region.locator('pre').innerText());assert(detail.evidence.verified_original_evidence.length>0);const refs=detail.evidence.verified_original_evidence;assert(refs.some(r=>r.source_ref.frame_number||r.source_ref.record_number));report.evaluation_error_trace.FP={verified_refs:refs.length,actual_locator:true};await region.scrollIntoViewIfNeeded();await shot('FP-prediction-originals-and-locators');
 await types.selectOption('false_negatives');await page.getByRole('button',{name:'核验独立参考原件',exact:true}).first().click();await region.waitFor();detail=JSON.parse(await region.locator('pre').innerText());assert.equal(detail.status,'reference_original_csv_record_verified');assert(detail.original.content_base64&&detail.original.sha256&&detail.resolved_record.values&&detail.resolved_record.record_number);const fragment=Buffer.from(detail.original.content_base64,'base64');assert.equal(crypto.createHash('sha256').update(fragment).digest('hex'),detail.original.sha256);assert.equal(detail.resolved_record.record_number,4);assert.equal(detail.resolved_record.values.time,'2026-01-01T00:00:14Z');const fragmentBytes=Buffer.from(detail.resolved_record.fragment.content_base64,'base64');assert.equal(crypto.createHash('sha256').update(fragmentBytes).digest('hex'),detail.resolved_record.fragment.sha256);assert(fragmentBytes.includes(Buffer.from('manual-transition')));report.evaluation_error_trace.FN={status:detail.status,actual_original:true,actual_locator:true,record_number:detail.resolved_record.record_number,sha256:detail.original.sha256};await region.scrollIntoViewIfNeeded();await shot('FN-independent-reference-original-fragment');
}
async function actualRetry(){
 await page.goto(state.url+'/workbench/');await page.getByRole('button',{name:'＋ 创建数据集',exact:true}).click();
 const name='R20 browser retry '+crypto.randomBytes(3).toString('hex');
 await page.getByLabel('数据集名称',{exact:true}).fill(name);await page.getByLabel('来源类型',{exact:true}).selectOption('synthetic');
 await page.getByLabel('来源说明',{exact:true}).fill('ordinary browser tiny fixture');await page.getByLabel('批次',{exact:true}).fill('r20-browser');await page.getByLabel('授权依据引用',{exact:true}).fill('synthetic-only');
 const created=await posted(page,/\/datasets$/,()=>page.getByRole('button',{name:'创建数据集',exact:true}).click());assert.equal(created.status,201);const ds=created.value.dataset.id;
 for(const [role,file] of [['network','network.pcap'],['process','process.csv']]){
  await page.getByLabel('文件角色',{exact:true}).selectOption(role);await page.getByLabel('选择原始文件',{exact:true}).setInputFiles(path.join(state.fixture_dir,file));
  const uploaded=await posted(page,/\/datasets\/[^/]+\/files$/,()=>page.getByRole('button',{name:'上传并校验',exact:true}).click());assert.equal(uploaded.status,201);
 }
 const intake={dataset_id:ds,synthetic:true,authorization:{allowed_use:'synthetic software testing',evidence_ref:'generated fixture',reviewer:'browser'},time_basis:{timezone:'UTC',precision:'microsecond',synchronization:'generated clock',evidence_ref:'fixture'},mapping:{field_units_ref:'fixture',device_map_ref:'fixture',effective_period_ref:'fixture'}};
 async function config(kind,document){await page.getByLabel('配置类型',{exact:true}).selectOption(kind);await page.getByLabel('配置 JSON',{exact:true}).fill(JSON.stringify(document));const v=await posted(page,/\/datasets\/[^/]+\/configs$/,()=>page.getByRole('button',{name:'保存新版本',exact:true}).click());assert.equal(v.status,201);await page.getByLabel('选择配置版本',{exact:true}).selectOption(v.value.config.id);}
 await config('intake',intake);const preflight=await posted(page,/\/datasets\/[^/]+\/preflight$/,()=>page.getByRole('button',{name:'运行接收预检',exact:true}).click());assert.equal(preflight.status,200);
 await config('dual',JSON.parse(fs.readFileSync(path.join(state.fixture_dir,'profile.json'),'utf8')));
 const submitted=await posted(page,/\/runs$/,()=>page.getByRole('button',{name:'提交双源运行',exact:true}).click());assert.equal(submitted.status,201);const run=submitted.value.run.id;
 await page.getByRole('button',{name:'查看运行 '+run,exact:true}).click();
 const detail=page.getByLabel('运行详情',{exact:true});await detail.getByText(new RegExp(run+' · (running|执行中) · attempt 1')).waitFor({timeout:30000});
 await page.getByRole('button',{name:'请求取消',exact:true}).click();await page.getByRole('button',{name:'确认取消任务',exact:true}).click();await detail.getByText(new RegExp(run+' · (cancelled|已取消) · attempt 1')).waitFor({timeout:60000});
 await detail.getByText(/已登记 1 次执行，已确认退出 1 次/).waitFor();await shot('actual-attempt1-cancelled-exited');
 const retried=await posted(page,/\/runs\/[^/]+\/retry$/,()=>page.getByRole('button',{name:'重试此运行',exact:true}).click());assert.equal(retried.status,200);assert.equal(retried.value.run.id,run);assert.equal(retried.value.run.attempt,1);
 await detail.getByText(new RegExp(run+' · (succeeded|执行完成) · attempt 2')).waitFor({timeout:120000});await detail.getByText(/已登记 2 次执行，已确认退出 2 次/).waitFor();await shot('same-run-attempt2-success-two-histories');
 report.actual_retry={run_id:run,first_attempt:1,first_state:'cancelled',first_exit_confirmed:true,retry_status:200,final_attempt:2,final_state:'succeeded',history_count:2,exit_count:2};
}
async function tamper(){
 const root=state.source_root;const raw=path.join(root,'jobs',state.offline_run_id,'attempt-1','sources','process.csv');
 const original=fs.readFileSync(raw),originalMode=fs.statSync(raw).mode&0o777;const proof={original_sha256:crypto.createHash('sha256').update(original).digest('hex'),same_size:true};
 fs.writeFileSync(path.join(out,'original-process-private.csv'),original,{mode:0o600});
 try{
  await openRun('R19 formal backup-offline',state.offline_run_id);await nav('分析结果');await trusted();
  await page.getByRole('region',{name:'联动时间线',exact:true}).getByRole('button').first().click();await page.getByRole('region',{name:'联动原始证据',exact:true}).getByText(/已核验原始记录：本页 4 条/).waitFor();
  const corrupted=Buffer.from(original);corrupted[corrupted.length-2]^=1;fs.chmodSync(raw,0o600);fs.writeFileSync(raw,corrupted);fs.chmodSync(raw,originalMode);
  await page.getByRole('button',{name:'重新核验',exact:true}).click();
  await page.getByRole('alert').filter({hasText:/409|422|mismatch|verification|source|integrity/}).first().waitFor();
  let rejection='';for(let i=0;i<90;i++){const alerts=(await page.getByRole('alert').allTextContents()).map(v=>v.trim()).filter(Boolean);rejection=alerts.join(';');if(rejection&&!rejection.includes('verification_pending'))break;await page.waitForTimeout(1000);const refresh=page.getByRole('button',{name:'重新核验',exact:true});if(await refresh.count()&&await refresh.first().isEnabled())await refresh.first().click();}
  assert(rejection&&!rejection.includes('verification_pending'),'tampered source never reached a final integrity rejection');proof.integrity_rejection=rejection;
  assert.equal(await page.getByRole('region',{name:'关系图',exact:true}).count(),0);assert.equal(await page.locator('summary').filter({hasText:/^原始记录 \d+$/}).count(),0);await shot('same-size-source-tamper-trusted-view-cleared');
  proof.trusted_result_cleared=true;
 }finally{fs.chmodSync(raw,0o600);fs.writeFileSync(raw,original);fs.chmodSync(raw,originalMode);assert.equal(crypto.createHash('sha256').update(fs.readFileSync(raw)).digest('hex'),proof.original_sha256);proof.original_restored=true;report.tamper=proof;save();}
}
async function roles(){
 await stage('ordinary-submit-cancel-attempt1-retry-attempt2',actualRetry);
 await stage('cancelled-queued-retry',async()=>{
  await selectDataset('R19 formal backup-replay');await nav('任务中心');
  const buttons=page.getByRole('button',{name:/^查看运行 /});let found=false;
  for(let i=0;i<await buttons.count();i++){const b=buttons.nth(i);if((await b.innerText()).includes('已取消')){await b.click();found=true;break;}}
  assert(found,'expected restored cancelled run');
  const detail=page.getByLabel('运行详情',{exact:true});const text=await detail.innerText();assert(text.includes('attempt 0'));
  const response=await posted(page,/\/runs\/[^/]+\/retry$/,()=>page.getByRole('button',{name:'重试此运行',exact:true}).click());assert.equal(response.status,200);assert.equal(response.value.run.state,'queued');assert.equal(response.value.run.attempt,0);
  await page.getByText('原任务已重新排队。Worker 领取时登记下一次执行。',{exact:true}).waitFor();
  await page.getByRole('button',{name:'请求取消',exact:true}).click();await page.getByRole('group',{name:'确认取消',exact:true}).waitFor();
  await page.getByRole('button',{name:'保留任务',exact:true}).click();assert.equal(await page.getByRole('group',{name:'确认取消',exact:true}).count(),0);
  await page.getByRole('button',{name:'请求取消',exact:true}).click();const cancel=await posted(page,/\/runs\/[^/]+\/cancel$/,()=>page.getByRole('button',{name:'确认取消任务',exact:true}).click());assert.equal(cancel.status,200);
  await shot('retry-and-confirm-cancellation');report.retry_response={status:response.status,state:response.value.run.state};
 });
 await stage('viewer-grant-and-read-only',async()=>{
  await selectDataset('R19 formal backup-offline');await nav('用户与授权');
  await page.getByLabel('授权用户',{exact:true}).selectOption({label:state.viewer_username});await page.getByLabel('授权级别',{exact:true}).selectOption('viewer');
  const response=await posted(page,/\/datasets\/[^/]+\/acl$/,()=>page.getByRole('button',{name:'保存授权',exact:true}).click());assert(response.status>=200&&response.status<300);
  const viewerContext=await browser.newContext({viewport:{width:1440,height:960}});const viewer=await viewerContext.newPage();viewer.setDefaultTimeout(45000);viewer.on('pageerror',e=>report.page_errors.push(scrub(e)));
  try{
   await viewer.goto(state.url+'/workbench/');await login(viewer,state.viewer_username,state.viewer_password);
   assert.equal(await viewer.getByRole('button',{name:'＋ 创建数据集',exact:true}).count(),0);
   await selectDataset('R19 formal backup-offline',viewer);assert.equal(await viewer.getByRole('button',{name:'上传并校验',exact:true}).count(),0);assert.equal(await viewer.getByRole('button',{name:'保存新版本',exact:true}).count(),0);
   await nav('任务中心',viewer);await viewer.getByRole('button',{name:'查看运行 '+state.offline_run_id,exact:true}).click();await nav('分析结果',viewer);await trusted(viewer);
   await viewer.getByRole('region',{name:'联动时间线',exact:true}).getByRole('button').first().click();await viewer.getByRole('region',{name:'联动原始证据',exact:true}).getByText(/已核验原始记录：本页 4 条/).waitFor();
   assert.equal(await viewer.getByRole('navigation',{name:'工作区导航'}).getByRole('link',{name:'用户与授权',exact:true}).count(),0);await shot('viewer-authorization-boundary',viewer);
   await viewer.goto(state.url+'/workbench/?view=analysis&dataset='+encodeURIComponent(state.ui_cases['multi-device'].dataset_id)+'&run='+encodeURIComponent(state.ui_cases['multi-device'].run_id));
   await viewer.getByRole('alert').filter({hasText:/403|404/}).waitFor();assert.equal(await viewer.getByRole('region',{name:'关系图',exact:true}).count(),0);await shot('viewer-forbidden-deep-link',viewer);
  }finally{await viewerContext.close();}
 });
}
(async()=>{
 browser=await chromium.launch({headless:true,executablePath:process.env.CPAG_CHROMIUM_PATH||undefined});context=await browser.newContext({viewport:{width:1440,height:960},acceptDownloads:true});page=await context.newPage();page.setDefaultTimeout(mode==='evaluation-errors'?12000:45000);page.on('dialog',dialog=>dialog.accept());
 page.on('pageerror',e=>{report.page_errors.push(scrub(e));save();});page.on('response',r=>{if(new URL(r.url()).pathname.startsWith('/api/v3/'))report.responses.push({method:r.request().method(),path:new URL(r.url()).pathname,status:r.status()});});
 try{await page.goto(state.url+'/workbench/');await login(page,state.username,state.password);await shot('workbench-login');if(mode==='main')await main();else if(mode==='roles')await roles();else if(mode==='submissions'){await stage('ordinary-new-offline-attempt1',()=>ordinarySubmission('offline'));await stage('ordinary-new-replay-attempt1',()=>ordinarySubmission('replay'));}else if(mode==='evaluation-errors')await stage('FP-prediction-and-FN-independent-original-trace',evaluationErrors);else if(mode==='multi')await stage('two-assets-same-time-own-originals-and-raw-order',multiDevice);else if(mode==='replay')await stage('restored-replay-prefix-and-revisions',replayCheck);else if(mode==='security')await stage('native-admin-analyst-viewer-and-denied-downloads',security);else if(mode==='semantics')await stage('ambiguity-counterevidence-unknown',semantics);else if(mode==='crossrun')await stage('actual-cross-run-delayed-response-and-back-refresh',crossRun);else if(mode==='tamper')await stage('same-size-source-tamper-trust-cleared',tamper);else throw Error('unsupported mode');report.status=report.failures.length||report.page_errors.length?'failed':'passed';if(report.status==='failed')process.exitCode=1;save();console.log(JSON.stringify(report));}
 catch(e){report.status='failed';report.failures.push({check:'fatal',error:scrub(e)});save();throw e;}
 finally{await browser.close();}
})().catch(e=>{console.error(scrub(e));process.exitCode=1});
