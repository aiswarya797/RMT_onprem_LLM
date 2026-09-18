#!/usr/bin/env node
// Real same-machine preview smoke; no inference, mocks or installed-service changes.
// PLAYWRIGHT_MODULE points to an existing Playwright installation.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { pathToFileURL } from 'node:url';

process.umask(0o077);
const root = process.cwd();
const bin = path.resolve(process.env.RMT_PREVIEW_BIN || '.work/local-preview/bin');
const run = crypto.randomBytes(4).toString('hex');
const output = path.join(root, '.work/local-preview', run);
const home = path.join(output, 'home');
const runtime = path.join(root, '.work', `lp-${run}`);
for (const dir of [output, home, runtime]) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
const env = { ...process.env, LLM_MONITOR_EXPERIMENTAL: '' };
const hubBinary = path.join(bin, 'llm-monitor');
const collectorBinary = path.join(bin, 'llm-monitor-collector');
const listener = net.createServer();
await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise(resolve => listener.close(resolve));
const origin = `http://127.0.0.1:${port}`;
const common = ['--installation-root', home, '--runtime-dir', runtime, '--listen', `127.0.0.1:${port}`];
function cli(args) {
  const r = spawnSync(hubBinary, [...common, ...args, '--json'], { env, encoding: 'utf8', timeout: 15000 });
  assert.equal(r.status, 0, `CLI ${args.join(' ')}: ${r.stderr}`);
  return JSON.parse(r.stdout);
}
async function stop(child) {
  if (!child || child.exitCode !== null) return;
  const exited = once(child, 'exit');
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
  await exited; clearTimeout(timer);
}
const checks = [];
const check = (condition, text) => { assert.ok(condition, text); checks.push(text); };
let hub, collector, browser, context;
const report = { run, status: 'failed', checks, inference_requests: 0, installed_services_changed: false };
const ownedLogs = [];
function start(binary, args, logName) {
 const fd = fs.openSync(path.join(output, logName), 'a', 0o600); ownedLogs.push(fd);
 return spawn(binary, args, { env, stdio: ['ignore', fd, fd] });
}
const before = {};
for (const endpoint of ['version','tags','ps']) {
 const response = await fetch(`http://127.0.0.1:11434/api/${endpoint}`, { signal: AbortSignal.timeout(3000) });
 assert.equal(response.status,200); before[endpoint] = await response.json();
}
try {
 cli(['setup', 'local', '--no-start']);
 hub = start(hubBinary, [...common, 'hub', 'serve'], 'hub.log');
 for (let n=0;n<30;n++) {
  try { if ((await fetch(origin+'/healthz')).ok) break; } catch {}
  await new Promise(resolve=>setTimeout(resolve,200));
 }
 const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href);
 browser = await chromium.launch({ executablePath: process.env.CHROME_BINARY || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true, args:['--disable-gpu','--single-process','--no-zygote','--js-flags=--max-old-space-size=32'] });
 context = await browser.newContext({ viewport:{width:1280,height:1100}, locale:'en-US' });
 const page = await context.newPage();
 page.setDefaultTimeout(20000);
 const errors=[]; page.on('pageerror',error=>errors.push(error.message));
 await page.goto(origin);
 const password = crypto.randomBytes(24).toString('base64url');
 await page.getByLabel('Administrator username').fill('preview-tester');
 await page.getByLabel('Password', { exact:true }).fill(password);
 await page.getByLabel('Confirm password').fill(password);
 await page.getByRole('button', { name:'Create administrator' }).click();
 await page.getByRole('heading',{name:'Live overview'}).waitFor();
 check(await page.getByText(/Same-machine preview/).count()===1,'Default preview banner visible');
 check(await page.getByText('Connect another Mac',{exact:true}).count()===0,'Remote pairing hidden');
 check(await page.getByText('Notification destinations',{exact:true}).count()===0,'External notifications hidden');
 collector = start(collectorBinary, ['--installation-root',home,'--runtime-dir',runtime,'serve'],'collector.log');
 await page.getByRole('heading',{name:'This Mac',exact:true}).waitFor();
 await page.getByRole('heading',{name:'Recent host CPU observations'}).waitFor();
 const readOverview = async () => (await context.request.get(origin+'/api/v1/overview')).json();
 let overview;
 for(let n=0;n<15;n++) {
  overview=await readOverview();
  if(overview.hosts[0]?.metrics.some(m=>m.metric==='host.cpu.busy_ratio' && m.value!==null) && overview.targets[0]?.models?.length) break;
  await new Promise(resolve=>setTimeout(resolve,1000));
 }
 check(overview.hosts.length===1 && overview.hosts[0].current_session_generation>0,'Real local collector activated');
 check(overview.hosts[0].metrics.some(m=>m.metric==='host.cpu.busy_ratio' && typeof m.value==='number'),'Measured CPU value present');
 check(overview.hosts[0].metrics.some(m=>m.metric==='host.memory.pressure_level' && m.value!==null),'Measured memory pressure present');
 const digests=before.tags.models.map(m=>m.digest.replace(/^sha256:/,''));
 check(overview.targets[0].models.some(m=>digests.includes((m.digest||'').replace(/^sha256:/,''))),'Dashboard model identity matches real Ollama inventory');
 check((await context.request.get(origin+'/api/v1/probes/runs/example')).status()===403,'Experimental API gated');
 await page.reload();
 await page.getByRole('heading',{name:'This Mac',exact:true}).waitFor();
 check(await page.getByText(/Same-machine preview/).count()===1,'Authenticated reload preserves live overview');
 await page.getByRole('button',{name:'Sign out'}).click();
 await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
 await page.getByLabel('Username',{exact:true}).fill('preview-tester');
 await page.getByLabel('Password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Sign in',exact:true}).press('Enter');
 await page.getByRole('heading',{name:'This Mac',exact:true}).waitFor();
 check(true,'Sign-out and keyboard sign-in passed');
 const firstGeneration=overview.hosts[0].current_session_generation;
 await stop(collector);
 collector=start(collectorBinary,['--installation-root',home,'--runtime-dir',runtime,'serve'],'collector-restarted.log');
 for(let n=0;n<20;n++) {
  overview=await readOverview(); if(overview.hosts[0].current_session_generation>firstGeneration) break;
  await new Promise(resolve=>setTimeout(resolve,500));
 }
 check(overview.hosts[0].current_session_generation>firstGeneration,'Collector restart preserves host and advances session');
 check(cli(['status']).hub_state==='running','CLI status works while hub is running');
 await page.reload(); await page.getByRole('heading',{name:'This Mac',exact:true}).waitFor();
 await page.getByRole('button',{name:'Sign out'}).focus();
 check(await page.getByRole('button',{name:'Sign out'}).evaluate(el=>el===document.activeElement && getComputedStyle(el).outlineStyle!=='none'),'Keyboard focus is visible');
 await page.locator('h1').focus(); await page.evaluate(()=>window.scrollTo(0,0));
 const screenshot=path.join(root,'docs/images/dashboard.png'); fs.mkdirSync(path.dirname(screenshot),{recursive:true});
 await page.screenshot({path:screenshot,fullPage:true,animations:'disabled'});
 check(errors.length===0,'No browser JavaScript errors');
 for(const endpoint of ['version','tags','ps']) {
  const after=await (await fetch(`http://127.0.0.1:11434/api/${endpoint}`)).json();
  check(JSON.stringify(after)===JSON.stringify(before[endpoint]),`Ollama ${endpoint} unchanged`);
 }
 report.status='passed'; report.ollama_version=before.version.version;
 report.hub_sha256=crypto.createHash('sha256').update(fs.readFileSync(hubBinary)).digest('hex');
 report.collector_sha256=crypto.createHash('sha256').update(fs.readFileSync(collectorBinary)).digest('hex');
 report.session_generation=overview.hosts[0].current_session_generation;
 report.screenshot='docs/images/dashboard.png';
} catch(error) { report.error=String(error); process.exitCode=1; }
finally {
 if(browser)await browser.close();
 await stop(collector); await stop(hub); ownedLogs.forEach(fd=>fs.closeSync(fd));
 report.cleanup='owned hub, collector and browser stopped; installed services preserved';
 fs.writeFileSync(path.join(output,'result.json'),JSON.stringify(report,null,2));
 console.log(JSON.stringify(report,null,2));
}
