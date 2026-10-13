import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
import { readFileSync, mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createClient } from '@supabase/supabase-js';
import WebSocket from 'ws';
const source=readFileSync('.env','utf8');
const config=Object.fromEntries(source.split('\n').filter(l=>l.includes('=')).map(l=>{const i=l.indexOf('=');return [l.slice(0,i),l.slice(i+1)];}));
const gateway=createServer(async(req,res)=>{
  let raw='';for await(const c of req)raw+=c;
  res.setHeader('Content-Type','application/json');
  if(req.url==='/v1/models'){res.end(JSON.stringify({data:[{id:'test-only-text-model'}]}));return;}
  const body=JSON.parse(raw);assert.ok(body.messages[0].content.includes('UNTRUSTED DATA'));
  const evidence=JSON.parse(body.messages[1].content.split('\n').slice(1).join('\n'));
  res.end(JSON.stringify({choices:[{message:{content:JSON.stringify({risk:evidence.incomplete?'unknown':'low',confidence:'medium',summary:'Respons gateway simulasi untuk pengujian alur aplikasi; bukan hasil pemindaian nyata.',findings:[],recommendations:['Verifikasi sumber file sebelum membuka.'],limitations:['Simulasi AI untuk pengujian.']})}}]}));
});
await new Promise(resolve=>gateway.listen(4001,'127.0.0.1',resolve));
const useStorage=process.env.KHERONYX_QA_STORAGE==='1';let testReportId;
const server=spawn(process.execPath,['node_modules/next/dist/bin/next','dev','--hostname','127.0.0.1','--port','3001'],{env:{...process.env,...config,AI_API_KEY:'qa-only-fake-key',AI_BASE_URL:'http://127.0.0.1:4001/v1',AI_MODEL:'test-only-text-model',SUPABASE_URL:useStorage?config.SUPABASE_URL:'',SUPABASE_SERVICE_ROLE_KEY:useStorage?config.SUPABASE_SERVICE_ROLE_KEY:''},stdio:'ignore'});
let browser;
try {
  for(let i=0;i<60;i++){try{if((await fetch('http://127.0.0.1:3001')).ok)break;}catch{}await new Promise(r=>setTimeout(r,500));}
  browser=await chromium.launch({headless:true,executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
  const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
  const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  mkdirSync('/private/tmp/kheronyx-qa',{recursive:true});
  await page.goto('http://127.0.0.1:3001/dashboard');await page.waitForURL('http://127.0.0.1:3001/');
  await page.screenshot({path:'/private/tmp/kheronyx-qa/landing-desktop.png',fullPage:true});
  await page.getByRole('button',{name:'Login',exact:true}).click();
  await page.getByLabel('Password akses',{exact:true}).fill('incorrect');await page.getByRole('button',{name:'Masuk ke dashboard'}).click();
  await page.locator('.form-error').waitFor();assert.match(await page.locator('.form-error').innerText(),/Password tidak cocok/);
  await page.getByLabel('Password akses',{exact:true}).fill(config.ACCESS_PASSWORD);await page.getByRole('button',{name:'Masuk ke dashboard'}).click();
  await page.waitForURL('**/dashboard');await page.getByText('Masih bersih di sini.').waitFor();
  await page.screenshot({path:'/private/tmp/kheronyx-qa/dashboard-desktop.png',fullPage:true});
  const cookies=await context.cookies();const session=cookies.find(c=>c.name==='kheronyx_session');assert.ok(session.httpOnly);assert.equal(session.sameSite,'Strict');
  const unauthorized=await fetch('http://127.0.0.1:3001/api/reports');assert.equal(unauthorized.status,401);
  const csrf=await fetch('http://127.0.0.1:3001/api/analyze',{method:'POST',headers:{cookie:`kheronyx_session=${session.value}`,origin:'https://unrelated.example','Content-Type':'application/json'},body:'{}'});assert.equal(csrf.status,403);
  await page.locator('input[type=file]').setInputFiles({name:'disk.img',mimeType:'application/octet-stream',buffer:Buffer.from('bad')});await page.locator('.error-notice').waitFor();assert.match(await page.locator('.error-notice').innerText(),/Format|Pilih file/);
  await page.locator('input[type=file]').setInputFiles({name:'picture.jpg',mimeType:'image/jpeg',buffer:readFileSync('tests/fixtures/one-pixel.jpg')});
  const analyzed=page.waitForResponse(r=>r.url().endsWith('/api/analyze') && r.request().method()==='POST');
  await page.getByRole('button',{name:'Mulai analisis'}).click();const analysisResponse=await analyzed;const analysis=await analysisResponse.json();assert.ok(analysisResponse.ok(),analysis.error || 'Analysis failed');testReportId=analysis.report.id;assert.equal(analysis.persisted,useStorage);await page.getByText('ANALYSIS REPORT',{exact:true}).waitFor({timeout:45000});
  await page.getByRole('button',{name:'Detail teknis file'}).click();await page.getByText('SHA-256',{exact:true}).waitFor();
  assert.match(await page.locator('.technical-details pre').innerText(),/dimensions/);
  const downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Unduh JSON'}).click();const download=await downloadPromise;assert.match(download.suggestedFilename(),/^kheronyx-.+\.json$/);
  await page.screenshot({path:'/private/tmp/kheronyx-qa/report-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});await page.evaluate(()=>window.scrollTo({top:0,behavior:'instant'}));await page.waitForTimeout(700);await page.screenshot({path:'/private/tmp/kheronyx-qa/dashboard-mobile.png',fullPage:true});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  await page.getByRole('button',{name:'Logout',exact:true}).click();await page.waitForURL('http://127.0.0.1:3001/');
  await page.screenshot({path:'/private/tmp/kheronyx-qa/landing-mobile.png',fullPage:true});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);assert.deepEqual(errors,[]);
  console.log('Browser QA passed: password failure/success, protected routes, CSRF, cookie flags, format rejection, full analysis flow with local mock gateway, report details/download, logout, desktop/mobile overflow.');
}finally{await browser?.close();server.kill('SIGTERM');await new Promise(r=>gateway.close(r));if(useStorage && testReportId){const db=createClient(config.SUPABASE_URL,config.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false},realtime:{transport:WebSocket}});const {error}=await db.from('kheronyx_reports').delete().eq('id',testReportId);assert.equal(error,null);console.log('Mock QA report removed from Supabase.');}}
