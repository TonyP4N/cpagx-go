// CPAG_URL must be the isolated local test API. Seed only fixture data through HTTP.
// Submit each analysis through the workbench and read its result as an ordinary user.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

async function main() {
  const base = process.env.CPAG_URL || 'http://127.0.0.1:8095';
  assert(['localhost','127.0.0.1'].includes(new URL(base).hostname));
  const [fixture, offline, replay, output] = process.argv.slice(2);
  const browser = await chromium.launch({channel: process.env.CHROME_CHANNEL || 'chrome'});
  try {
    const page = await browser.newPage({acceptDownloads: true});
    const api = page.request;
    async function post(route, data, headers) {
      const response = await api.post(base + '/api/v3' + route, {data, headers});
      assert(response.ok(), route + ' ' + response.status() + ' ' + (response.ok() ? '' : await response.text()));
      return response.json();
    }
    await post('/session', {username:'lab-admin',password:process.env.CPAG_TEST_PASSWORD});
    const {dataset} = await post('/datasets', {name:'Resident worker acceptance', source_kind:'synthetic', source:'R21 synthetic sample',batch:'r21-https-browser',authorization_ref:'repository generated synthetic material'});
    const ds = '/datasets/' + dataset.id;
    const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
    for (const name of ['network.pcap','response.pcap','process.csv']) {
      const bytes = fs.readFileSync(path.join(fixture,name));
      const role = name.endsWith('.csv') ? 'process' : 'network';
      await post(ds+'/files?name='+name+'&role='+role,bytes,{'Content-Type':'application/octet-stream','X-Content-SHA256':sha(bytes),'Idempotency-Key':crypto.randomUUID()});
    }
    const {config:intake} = await post(ds+'/configs',{kind:'intake',document:{dataset_id:dataset.id,synthetic:true,authorization:{allowed_use:'synthetic testing',evidence_ref:'generated fixture',reviewer:'browser acceptance'},time_basis:{timezone:'UTC',precision:'microsecond',synchronization:'generated clocks',evidence_ref:'fixture'},mapping:{field_units_ref:'fixture',device_map_ref:'fixture',effective_period_ref:'fixture'}}});
    const {preflight_id} = await post(ds+'/preflight',{config_version_id:intake.id});
    const report = {dataset:dataset.id, runs:[]};
    const save = () => fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
    for (const [mode,profile] of [['dual_source',offline],['dual_source_replay',replay]]) {
      const {config} = await post(ds+'/configs',{kind:'dual',document:JSON.parse(fs.readFileSync(profile))});
      await page.goto(base+'/workbench/?view=datasets&dataset='+dataset.id);
      await page.getByLabel('选择配置版本',{exact:true}).selectOption(config.id);
      const preflight = page.getByRole('button',{name:'选择运行预检 '+preflight_id,exact:true});
      if (await preflight.count()) await preflight.click();
      await page.getByLabel('运行模式',{exact:true}).selectOption(mode);
      const posted = page.waitForResponse(r => r.request().method()==='POST' && new URL(r.url()).pathname==='/api/v3/runs');
      await page.getByRole('button',{name:'提交双源运行',exact:true}).click();
      const response = await posted;
      assert.equal(response.status(),201,await response.text());
      const {run} = await response.json();
      const record = {id:run.id,mode};
      report.runs.push(record); save();
      const runPath = base+'/api/v3/runs/'+run.id;
      let current;
      const deadline = Date.now() + 240000;
      do {
        current = (await (await api.get(runPath)).json()).run;
        if (['succeeded','failed','cancelled'].includes(current.state)) break;
        await new Promise(resolve => setTimeout(resolve, 500));
      } while (Date.now() < deadline);
      assert.equal(current.state,'succeeded',JSON.stringify(current)); record.attempt=current.attempt;
      await page.goto(base+'/workbench/?view='+(mode==='dual_source'?'analysis':'replay')+'&dataset='+dataset.id+'&run='+run.id);
      const ready = mode==='dual_source' ? page.getByRole('tab',{name:'候选',exact:true}) : page.locator('input[name=replay-snapshot]');
      for(let i=0;i<120 && !await ready.isVisible();i++) {
        const retry=page.getByRole('button',{name:'重新核验',exact:true}).first();
        if(await retry.isVisible() && await retry.isEnabled()) await retry.click();
        await page.waitForTimeout(1000);
      }
      if(mode==='dual_source'){
        await ready.click();
        await page.getByRole('region',{name:'联动候选'}).locator('ul button').first().click();
        await page.getByText('已核验原始记录：本页 4 条',{exact:false}).waitFor();
        record.originals=[];
        for(let n=1;n<=4;n++){
          const summary=page.locator('.wb-inspector summary').filter({hasText:new RegExp('^原始记录 '+n+'$')});
          await summary.click();
          record.originals.push(JSON.parse(await summary.locator('..').locator('pre').innerText()).source_ref);
        }
        await page.getByRole('link',{name:'完整分页核查与受控下载 →',exact:true}).click();
        const downloading=page.waitForEvent('download');
        await page.getByRole('region',{name:'共享物理产物下载'}).getByRole('link').filter({hasText:/^run_manifest.json/}).click();
        const bytes=fs.readFileSync(await (await downloading).path());
        const inventory=(await (await api.get(runPath+'/artifacts')).json()).artifacts;
        record.manifest_sha256=sha(bytes);
        assert.equal(record.manifest_sha256,inventory.find(row=>row.path==='run_manifest.json').sha256);
        assert.equal(JSON.parse(bytes).run_id,run.id);
      }else{
        await ready.fill('15');
        await page.getByRole('button',{name:'查看该时刻',exact:true}).click();
        await page.getByRole('heading',{name:'快照 15 · 修订 11',exact:true}).waitFor();
        record.snapshot=15;record.revision=11;
      }
      const result=await (await api.get(runPath+'/result')).json();
      for(const key of ['operations','changes','candidates']) assert.equal(result.manifest.counts[key],1);
      record.counts=result.manifest.counts;save();
    }
  }finally{await browser.close();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
