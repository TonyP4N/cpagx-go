/** Focused real-service legacy-spool UI acceptance; no response interception.
 * node round20_legacy_replay_browser.cjs RUN_CONTEXT STORAGE_STATE EXTERNAL_OUTPUT
 * Context contains url,datasetId,runId,lastSnapshot,pendingSnapshot,expectedPath.
 */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const {chromium}=require(process.env.R20_PLAYWRIGHT||'playwright');
if(process.argv.length<5)throw Error('usage: RUN_CONTEXT STORAGE_STATE EXTERNAL_OUTPUT');
const contextInfo=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),expected=JSON.parse(fs.readFileSync(contextInfo.expectedPath,'utf8'));
const output=path.resolve(process.argv[4]);fs.mkdirSync(output,{recursive:true,mode:0o700});
const result={scope:'real isolated Go/PG/Worker legacy replay ordinary browser; generated source bytes only',checks:{},requests:[],pageErrors:[]},observed={};
const save=()=>fs.writeFileSync(path.join(output,'verification.json'),JSON.stringify(result,null,2)+'\n');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.R20_CHROME});
 try{
  const context=await browser.newContext({storageState:process.argv[3],viewport:{width:1440,height:1000}}),page=await context.newPage();page.setDefaultTimeout(20000);
  page.on('pageerror',error=>result.pageErrors.push(error.message));
  await page.goto(contextInfo.url+'/workbench/');await page.getByRole('navigation',{name:'工作区导航'}).waitFor();
  result.buildId=await page.locator('#__NEXT_DATA__').evaluate(el=>JSON.parse(el.textContent).buildId);
  await page.getByRole('button',{name:'打开数据集 R20 legacy normal spool',exact:true}).click();
  const nav=name=>page.getByRole('navigation',{name:'工作区导航'}).getByRole('link',{name,exact:true}).click();
  await nav('任务中心');await page.getByRole('button',{name:'查看运行 '+contextInfo.runId,exact:true}).click();await nav('分析结果');
  const root=page.getByRole('region',{name:'分析工作区',exact:true}),graph=root.getByTestId('analysis-graph'),timeline=root.getByRole('region',{name:'联动时间线',exact:true}),evidence=root.getByRole('region',{name:'联动原始证据',exact:true});
  const input=root.locator('input[name=analysis-snapshot]');await graph.waitFor();assert.equal(await input.getAttribute('max'),String(contextInfo.lastSnapshot));
  async function inspect(label,snapshot){
   const responsePromise=page.waitForResponse(response=>new URL(response.url()).pathname===`/api/v3/runs/${contextInfo.runId}/evidence`);
   await timeline.locator('li button').first().click();const response=await responsePromise;assert.equal(response.status(),200);
   const query=Object.fromEntries(new URL(response.url()).searchParams),document=await response.json();result.requests.push({label,query,status:response.status()});
   assert.equal(query.revision,String(snapshot));assert(!('snapshot' in query));assert.equal(document.snapshot_id,expected.snapshots[snapshot].snapshot_id);
   const originals=expected.evidence[String(snapshot)].verified_original_evidence;assert.deepEqual(document.verified_original_evidence,originals);
   await evidence.getByText(new RegExp('已核验原始记录：本页 '+originals.length+' 条')).waitFor();const ui=[];
   for(let n=1;n<=originals.length;n++){
    const details=evidence.locator('details').filter({has:page.locator('summary').filter({hasText:new RegExp('^原始记录 '+n+'$')})});
    if(await details.getAttribute('open')===null)await details.locator('summary').click();
    const value=JSON.parse(await details.locator('pre').innerText());assert.deepEqual(value,originals[n-1]);ui.push(value);
   }
   observed[label]=ui;await evidence.scrollIntoViewIfNeeded();await page.screenshot({path:path.join(output,label+'.png'),fullPage:false});
   result.checks[label]={status:'passed',snapshot,verifiedRawReferences:ui.length};save();
  }
  assert.equal(await input.inputValue(),'');await inspect('terminal',contextInfo.lastSnapshot);
  await input.fill(String(contextInfo.lastSnapshot));await root.getByRole('button',{name:'读取快照',exact:true}).click();await graph.waitFor();await inspect('explicit-final',contextInfo.lastSnapshot);
  await input.fill(String(contextInfo.pendingSnapshot));await root.getByRole('button',{name:'读取快照',exact:true}).click();await graph.waitFor();await inspect('early-prefix',contextInfo.pendingSnapshot);
  assert.equal(Number(await graph.getAttribute('data-edges')),0);assert.equal(observed['early-prefix'].length,1);assert.equal(observed['early-prefix'][0].source_ref.source_slot,'network-0');
  assert.equal(await root.getByRole('region',{name:'联动候选',exact:true}).locator('li').count(),0);
  const rawFile=path.join(output,'observed-raw-private.json');fs.writeFileSync(rawFile,JSON.stringify(observed,null,2)+'\n',{mode:0o600});
  const oracle=`import json,sys\nfrom pathlib import Path\nfrom round19_core_oracle import check_raw_evidence\nroot=Path(sys.argv[2]);rows=json.loads(Path(sys.argv[1]).read_text())\nchecks={label:check_raw_evidence(refs,[root/'network.pcap',root/'response.pcap'],root/'process.csv') for label,refs in rows.items()}\nprint(json.dumps(checks))`;
  const audit=spawnSync(process.env.R20_PYTHON||'python3',['-c',oracle,rawFile,path.join(path.dirname(contextInfo.expectedPath),'fixture')],{env:{...process.env,PYTHONPATH:__dirname},encoding:'utf8'});
  assert.equal(audit.status,0,audit.stderr);result.independentRawByteAudit=JSON.parse(audit.stdout);
  assert.equal(result.pageErrors.length,0);result.status='passed';save();console.log(JSON.stringify({status:result.status,buildId:result.buildId,checks:result.checks,independentRawBytes:true}));
 }catch(error){result.status='failed';result.failure=error.message;save();throw error;}finally{await browser.close();}
})().catch(error=>{console.error(error.message);process.exitCode=1});
