// Ordinary legacy workspace before inspection; no API/session injection.
const fs = require('fs');
const path = require('path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
(async()=>{
 const state=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
 const out=path.resolve(process.argv[3]);fs.mkdirSync(out,{recursive:true,mode:0o700});
 const browser=await chromium.launch({headless:true,executablePath:process.env.CPAG_CHROMIUM_PATH || undefined});
 try {
  const context=await browser.newContext({viewport:{width:1440,height:960}});
  const page=await context.newPage();
  const errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto(state.url+'/workspace/');
  await page.getByLabel('用户名',{exact:true}).fill(state.username);
  await page.getByLabel('密码',{exact:true}).fill(state.password);
  await page.getByRole('button',{name:'登录',exact:true}).click();
  await page.getByRole('region',{name:'数据集列表',exact:true}).waitFor();
  await page.screenshot({path:path.join(out,'before-workspace.png'),fullPage:false});
  const text=await page.locator('body').innerText();
  fs.writeFileSync(path.join(out,'before-workspace.txt'),text);
  fs.writeFileSync(path.join(out,'before-report.json'),JSON.stringify({url:page.url(),page_errors:errors,viewport:{width:1440,height:960},headings:await page.getByRole('heading').allTextContents(),body_characters:text.length,screenshot:'before-workspace.png'},null,2));
  console.log(JSON.stringify({url:page.url(),page_errors:errors,headings:await page.getByRole('heading').allTextContents(),body:text.slice(0,4500)}));
 } finally {await browser.close();}
})().catch(e=>{console.error(String(e));process.exitCode=1});
