// Actual browser mutations are confined to the explicitly prepared local fixture.
// No Playwright assertion diagnostics, bodies, cookies or credentials are logged.
import { chromium } from 'playwright';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile, lstat, realpath } from 'node:fs/promises';
import { dirname, join, relative, resolve, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixtureRoot = join(root, '.cache/sites-ui-fixture');
const origin = 'http://127.0.0.1:8084';
const runId = new Date().toISOString().replace(/[-:.Z]/g, '') + '-' + randomUUID().slice(0, 8);
const output = join(root, 'artifacts/sites', runId);
const visualOnly = process.argv.includes('--visual-only');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { checkCode: code }); };
let phase = 'prepare', browser, credential;
const report = { schema_version:1, evidence_kind:'observed_isolated_fixture_browser_qa', checked_at:new Date().toISOString(), origin,
  fixture_only:true, main_state_mutated:false, paid_provider_calls:0, compatibility_certified:false, remote_auth_qualified:false,
  native_os:process.platform, browser:'Isolated Playwright Chromium', passed:false, workflow:{}, viewports:[], public_preview:{}, sources:{} };

async function directory(path) {
  const parts = relative(root,path).split(sep);
  check(!isAbsolute(relative(root,path)) && parts.every(p=>p && p!=='..'), 'output_escape');
  let current = await realpath(root);
  for (const part of parts) {
    current = join(current,part); try { await mkdir(current); } catch(error) { if(error.code!=='EEXIST')throw error; }
    const st = await lstat(current); check(st.isDirectory() && !st.isSymbolicLink() && await realpath(current)===current,'output_not_regular');
  }
}
async function boundedFile(path, maximum, ancestor=root) {
  const rel = relative(ancestor,path); check(rel && !isAbsolute(rel) && !rel.split(sep).includes('..'),'input_escape');
  let current=await realpath(ancestor);
  for(const part of rel.split(sep)) {
    current=join(current,part); const st=await lstat(current);
    check(!st.isSymbolicLink() && await realpath(current)===current,'input_link');
  }
  const st=await lstat(current); check(st.isFile() && st.nlink===1 && st.size>0 && st.size<=maximum,'input_not_bounded_regular');
  const bytes=await readFile(current); check(bytes.length===st.size && bytes.length<=maximum,'input_changed'); return bytes;
}
async function api(context,path,{method='GET',data,csrf,expected=200}={}) {
  const response=await context.request.fetch(origin+path,{method,data,headers:{Origin:origin,Accept:'application/json',...(data!==undefined?{'Content-Type':'application/json'}:{}),...(csrf?{'X-CSRF-Token':csrf}:{})},timeout:10000,maxRedirects:0});
  check(response.status()===expected,'fixture_api_status_'+response.status());
  const bytes=await response.body(); check(bytes.length<=1<<20,'fixture_api_response_bound'); return JSON.parse(bytes.toString('utf8'));
}
async function nav(page,id) {
  const target=page.getByTestId('nav-'+id);
  if(!await target.isVisible())await page.getByRole('button',{name:'Open navigation',exact:true}).click();
  await target.click();
}
async function noOverflow(page) {
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1 && document.body.scrollWidth<=innerWidth+1),'horizontal_overflow');
}
async function shot(page,name) {
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  await noOverflow(page);
  await page.screenshot({path:join(output,name),fullPage:!name.includes('dialog'),timeout:15000});
}
async function login(page) {
  await nav(page,'websites'); await page.getByLabel('Operator access key',{exact:true}).waitFor();
  check(await page.getByLabel('Operator access key',{exact:true}).getAttribute('type')==='password','key_input_not_password');
  await page.getByLabel('Operator access key',{exact:true}).fill(credential);
  await page.getByRole('button',{name:'Sign in locally',exact:true}).click();
  await page.getByRole('button',{name:'Sign out locally',exact:true}).waitFor();
  check(await page.evaluate(key=>!document.body.innerText.includes(key) && !Object.values(localStorage).some(v=>v.includes(key)),credential),'credential_persisted_or_displayed');
}
async function contextFor(viewport,theme,publicView=false) {
  const context=await browser.newContext({viewport,colorScheme:theme,reducedMotion:'reduce'});
  await context.addInitScript(t=>localStorage.setItem('sifruno-theme',t),theme);
  const health={page_errors:0,console_errors:0,failed_requests:0,external_blocked:0,unexpected_mutations:0,private_requests:0,http_errors:[]};
  await context.route('**/*',async route=>{
    const request=route.request(),url=new URL(request.url());
    const local=url.origin===(publicView?'http://127.0.0.1:8081':origin);
    const preview=url.protocol==='http:' && url.port==='8082' && /^site-[a-f0-9]{32}\.localhost$/.test(url.hostname);
    if(!local && !preview){health.external_blocked++;return route.abort('blockedbyclient');}
    if(/^\/api\/v1\/(session|sites)(\/|$)/.test(url.pathname))health.private_requests++;
    if(!['GET','HEAD'].includes(request.method()) && (publicView || !local || !/^\/api\/v1\/(session\/(login|logout)|sites(?:\/[a-f0-9]{32}\/(?:file|state|backups|restore))?)$/.test(url.pathname))) {
      health.unexpected_mutations++;return route.abort('blockedbyclient');
    }
    return route.continue();
  });
  const page=await context.newPage(); page.setDefaultTimeout(15000); page.setDefaultNavigationTimeout(15000);
  page.on('pageerror',()=>health.page_errors++);
  page.on('console',message=>{if(message.type()==='error' && !/^Failed to load resource: the server responded with a status of (401|409)/.test(message.text()))health.console_errors++;});
  page.on('requestfailed',request=>{if(request.failure()?.errorText!=='net::ERR_ABORTED')health.failed_requests++;});
  page.on('response',response=>{if(response.status()>=400){const url=new URL(response.url());health.http_errors.push({path:url.pathname,status:response.status()});}});
  return {context,page,health};
}
function healthy(health) {
  check(health.page_errors===0 && health.console_errors===0 && health.failed_requests===0 && health.external_blocked===0 && health.unexpected_mutations===0,'browser_health_failure');
  check(health.http_errors.every(x=>[401,409].includes(x.status)),'unexpected_browser_http_error');
}

async function focusedVisualRun() {
  const latest=JSON.parse((await boundedFile(join(root,'artifacts/sites/latest.json'),8192)).toString('utf8'));
  const priorPath=join(root,latest.directory,'report.json'), priorBytes=await boundedFile(priorPath,1<<20,join(root,'artifacts/sites'));
  check(hash(priorBytes)===latest.report_sha256,'prior_report_hash'); const prior=JSON.parse(priorBytes.toString('utf8'));
  check(prior.passed && prior.fixture_id===report.fixture_id && /^[a-f0-9]{32}$/.test(prior.site_id),'prior_fixture_evidence_missing');
  report.evidence_kind='observed_focused_visual_and_input_bound_qa'; report.site_id=prior.site_id;
  report.workflow=prior.workflow?.evidence_kind==='prior_observed_browser_reference' ? prior.workflow : {evidence_kind:'prior_observed_browser_reference',report:relative(root,priorPath).split(sep).join('/'),sha256:hash(priorBytes)};
  const workflowBytes=await boundedFile(join(root,report.workflow.report),1<<20,join(root,'artifacts/sites'));
  const workflowReport=JSON.parse(workflowBytes.toString('utf8'));
  check(hash(workflowBytes)===report.workflow.sha256 && workflowReport.passed && workflowReport.site_id===prior.site_id && workflowReport.workflow.restore===true,'original_workflow_evidence_invalid');
  report.site_store_mutations=0; report.visual_only=true;
  for(const width of [390,768,1440])for(const theme of ['light','dark']) {
    phase='focused_'+width+'_'+theme; const v=await contextFor({width,height:width===390?844:1000},theme);
    await v.page.goto(origin); await nav(v.page,'websites'); await v.page.getByLabel('Operator access key',{exact:true}).waitFor();
    await shot(v.page,width+'-'+theme+'-login.png'); await login(v.page);
    const site=await api(v.context,'/api/v1/sites/'+prior.site_id);
    await v.page.getByRole('button',{name:'Open website '+site.name,exact:true}).click(); await v.page.getByTestId('website-details').waitFor();
    check(await v.page.getByTestId('website-details').getAttribute('data-site-id')===prior.site_id,'focused_site_selection');
    await v.page.getByLabel('Domain',{exact:true}).fill('bound-fixture.example');
    await v.page.getByLabel('Website name',{exact:true}).fill('é'.repeat(41));
    check(await v.page.getByRole('button',{name:'Create website',exact:true}).isDisabled() && await v.page.getByLabel('Website name',{exact:true}).getAttribute('aria-invalid')==='true','utf8_82_byte_name_not_denied');
    await v.page.getByLabel('Website name',{exact:true}).fill('é'.repeat(40));
    check(await v.page.getByRole('button',{name:'Create website',exact:true}).isEnabled(),'utf8_80_byte_name_not_admitted');
    await v.page.getByLabel('Website name',{exact:true}).fill(''); await v.page.getByLabel('Domain',{exact:true}).fill('');
    const filename=width+'-'+theme+'-websites.png'; await shot(v.page,filename);
    if(width===390 && theme==='light' || width===1440 && theme==='light') {
      const restore=v.page.getByRole('button',{name:/^Restore backup /}).first(); await restore.click();
      await v.page.getByRole('dialog',{name:'Restore ZIP backup?',exact:true}).waitFor(); await shot(v.page,width+'-'+theme+'-restore-dialog.png');
      await v.page.getByRole('button',{name:'Cancel restore',exact:true}).click();
    }
    healthy(v.health); report.viewports.push({width,theme,screenshot:filename,login_screenshot:width+'-'+theme+'-login.png',overflow:false,name_utf8_bytes_bound:{denied:82,admitted:80},health:v.health});
    await v.page.getByRole('button',{name:'Sign out locally',exact:true}).click(); await v.page.getByLabel('Operator access key',{exact:true}).waitFor(); await v.context.close();
  }
  phase='focused public privacy'; const p=await contextFor({width:1440,height:1000},'light',true);
  await p.page.goto('http://127.0.0.1:8081'); await p.page.getByTestId('server-overview').waitFor();
  check(await p.page.getByTestId('nav-websites').count()===0 && p.health.private_requests===0,'focused_public_exposes_sites');
  await shot(p.page,'1440-light-public.png'); healthy(p.health); report.public_preview={websites_nav_absent:true,private_fetches:0,screenshot:'1440-light-public.png'}; await p.context.close();
}

try {
  await directory(output);
  const metadata=JSON.parse((await boundedFile(join(fixtureRoot,'current.json'),8192)).toString('utf8'));
  check(metadata.origin===origin && metadata.sites_origin==='http://127.0.0.1:8082' && metadata.main_state_mutated===false && metadata.paid_provider_calls===0 && Number.isInteger(metadata.pid),'fixture_metadata_invalid');
  const state=resolve(root,metadata.state); check(relative(fixtureRoot,state).split(sep).length===2 && state.endsWith(sep+'private-state'),'fixture_state_not_exact');
  const key=await boundedFile(join(state,'operator/access.key'),44,fixtureRoot);
  check(key.length===44 && /^[A-Za-z0-9_-]{43}\n$/.test(key.toString('ascii')),'fixture_key_format'); credential=key.toString('ascii').trim();
  const binary=resolve(root,metadata.binary); report.binary_sha256=hash(await boundedFile(binary,32<<20)); check(report.binary_sha256===metadata.binary_sha256,'fixture_binary_hash_mismatch');
  report.fixture_id=metadata.id; report.fixture_pid=metadata.pid;
  for(const path of ['web/dist/index.html','web/src/Websites.tsx','web/src/lib/sites-api.ts','web/src/websites.css','web/src/index.css','internal/api/sites.go','internal/operator/operator.go'])report.sources[path]=hash(await boundedFile(join(root,path),2<<20));
  browser=await chromium.launch({headless:true});
  if(visualOnly) { await focusedVisualRun(); report.passed=true; }
  else {
  phase='initial login'; const main=await contextFor({width:1440,height:1000},'light'); const {context,page,health}=main;
  await page.goto(origin); await page.getByTestId('server-overview').waitFor();
  check(health.private_requests===0,'overview_fetched_private_sites');
  await nav(page,'websites'); await page.getByLabel('Operator access key',{exact:true}).waitFor(); await shot(page,'1440-light-login.png');
  await login(page); const session=await api(context,'/api/v1/session'); check(session.authenticated && session.csrf_token?.length===43,'fixture_session_contract');
  const cookies=await context.cookies(); const cookie=cookies.find(x=>x.name==='sifruno_operator'); check(cookie?.httpOnly && cookie.sameSite==='Strict' && !cookie.secure,'fixture_cookie_policy');
  phase='actual create'; const name='Sifruno UI '+runId.slice(-8);
  await page.getByLabel('Website name',{exact:true}).fill(name); await page.getByLabel('Domain',{exact:true}).fill('ui-'+runId.slice(-8)+'.example');
  await page.getByRole('button',{name:'Create website',exact:true}).click(); await page.getByText('Created '+name+'.',{exact:true}).waitFor();
  const id=await page.getByTestId('website-details').getAttribute('data-site-id'); check(/^[a-f0-9]{32}$/.test(id),'created_site_id'); report.site_id=id;
  const base='/api/v1/sites/'+id, seed=await api(context,base+'/file?path=index.html'); check(seed.content && seed.sha256?.length===64,'actual_seed_missing');
  await page.getByLabel('Search websites',{exact:true}).fill(name); check(await page.getByRole('button',{name:'Open website '+name,exact:true}).count()===1,'website_search_actual');
  await page.getByLabel('Search websites',{exact:true}).fill('NoMatch'+runId); await page.getByText('No matching websites.',{exact:true}).waitFor(); await page.getByLabel('Search websites',{exact:true}).fill('');
  phase='actual save and draft persistence'; const saved='<!doctype html><title>Isolated Sifruno fixture</title><h1>Saved baseline '+runId+'</h1>';
  const editor=page.getByLabel('File content',{exact:true}); await editor.fill(saved); await page.getByRole('button',{name:'Save file',exact:true}).click(); await page.getByText('Saved index.html.',{exact:true}).waitFor();
  check((await api(context,base+'/file?path=index.html')).content===saved,'actual_save_not_persisted');
  const draft=saved+'\n<p>Preserved draft</p>'; await editor.fill(draft); await nav(page,'overview'); await nav(page,'websites'); await editor.waitFor(); check(await editor.inputValue()===draft,'navigation_discarded_draft');
  const sessionReload=page.waitForResponse(r=>r.url()===origin+'/api/v1/session' && r.status()===200);
  await page.getByRole('button',{name:'Refresh server data',exact:true}).click(); await sessionReload; check(await editor.inputValue()===draft,'refresh_discarded_draft');
  phase='real stale revision conflict'; const latest=await api(context,base+'/file?path=index.html');
  await api(context,base+'/file',{method:'PUT',csrf:session.csrf_token,data:{path:'index.html',content:saved+'\n<p>Out of band actual update</p>',expected_sha256:latest.sha256,expected_revision:latest.revision}});
  await page.getByRole('button',{name:'Save file',exact:true}).click(); await page.getByRole('button',{name:'Keep draft and use latest revision',exact:true}).waitFor();
  check(await editor.inputValue()===draft,'409_discarded_draft'); await shot(page,'1440-light-real-conflict.png');
  await page.getByRole('button',{name:'Keep draft and use latest revision',exact:true}).click(); check(await editor.inputValue()===draft,'conflict_rebase_discarded_draft');
  await page.getByRole('button',{name:'Save file',exact:true}).click(); await page.getByText('Saved index.html.',{exact:true}).waitFor(); check((await api(context,base+'/file?path=index.html')).content===draft,'rebased_save_not_persisted');
  phase='new actual file'; await page.getByRole('button',{name:'Add text file',exact:true}).click(); await page.getByLabel('Relative file path',{exact:true}).fill('assets/style.css'); await editor.fill('body { color: #185e55; }');
  await page.getByRole('button',{name:'Save file',exact:true}).click(); await page.getByText('Saved assets/style.css.',{exact:true}).waitFor();
  check((await api(context,base+'/files')).items.some(x=>x.path==='assets/style.css'),'new_file_not_persisted'); await page.getByRole('button',{name:'Edit index.html',exact:true}).click();
  phase='actual preview'; const popupPromise=page.waitForEvent('popup'); await page.getByRole('link',{name:'Local HTTP preview',exact:true}).click(); const preview=await popupPromise;
  await preview.waitForLoadState('domcontentloaded'); check(new URL(preview.url()).hostname==='site-'+id+'.localhost','preview_alias_invalid'); check((await preview.locator('body').innerText()).includes('Preserved draft'),'preview_not_actual_file'); await preview.close();
  phase='actual ZIP backup'; await page.getByRole('button',{name:'Create ZIP backup',exact:true}).click(); await page.getByText('Created ZIP backup with 2 files.',{exact:true}).waitFor();
  const site=await api(context,base),backups=await api(context,base+'/backups'); check(backups.items.length===1,'actual_backup_inventory'); const backup=backups.items[0];
  const archive=await boundedFile(join(state,'sites/data',id,'backups',backup.id+'.zip'),34<<20,fixtureRoot); check(hash(archive)===backup.sha256 && archive.length===backup.bytes && archive.subarray(0,2).toString('ascii')==='PK','actual_zip_hash_or_size');
  check(Number(await page.getByTestId('website-details').getAttribute('data-revision'))===site.revision,'backup_left_stale_ui_revision'); report.workflow.backup={sha256:backup.sha256,bytes:backup.bytes,files:backup.files};
  phase='actual state'; await page.getByRole('button',{name:'Suspend website',exact:true}).click(); await page.getByText('Website is suspended.',{exact:true}).waitFor(); check((await api(context,base)).state==='suspended','suspend_not_persisted');
  const suspended=await context.request.get('http://127.0.0.1:8082/',{headers:{Host:'site-'+id+'.localhost'},timeout:10000,maxRedirects:0}); check(suspended.status()===503,'suspended_site_still_served');
  await page.getByRole('button',{name:'Resume website',exact:true}).click(); await page.getByText('Website is active.',{exact:true}).waitFor();
  phase='actual restore'; await editor.fill(saved+'\n<p>To be restored</p>'); await page.getByRole('button',{name:'Save file',exact:true}).click(); await page.getByText('Saved index.html.',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Restore backup '+backup.id,exact:true}).click(); const dialog=page.getByRole('dialog',{name:'Restore ZIP backup?',exact:true}); await dialog.waitFor();
  check(await dialog.getByRole('button',{name:'Confirm restore',exact:true}).isDisabled(),'restore_missing_confirmation'); await shot(page,'1440-light-restore-dialog.png');
  await dialog.getByRole('checkbox',{name:'I understand that the current site files will be replaced.',exact:true}).check(); await dialog.getByRole('button',{name:'Confirm restore',exact:true}).click(); await page.getByText('Restored '+name+' from its ZIP backup.',{exact:true}).waitFor();
  check((await api(context,base+'/file?path=index.html')).content===draft,'restore_not_actual_backup_content');
  report.workflow={...report.workflow,create:true,search:true,seed:true,write:true,new_file:true,actual_preview:true,actual_409:true,draft_navigation_preserved:true,draft_refresh_preserved:true,draft_conflict_preserved:true,explicit_conflict_save:true,suspend:true,resume:true,restore_confirmation:true,restore:true};
  await shot(page,'1440-light-workflow.png'); healthy(health); report.workflow.health=health;
  phase='logout'; await page.getByRole('button',{name:'Sign out locally',exact:true}).click(); await page.getByLabel('Operator access key',{exact:true}).waitFor();
  await api(context,'/api/v1/sites',{expected:401}); check(!(await context.cookies()).some(x=>x.name==='sifruno_operator'),'logout_cookie_not_deleted'); report.workflow.logout=true; await context.close();
  for(const width of [390,768,1440])for(const theme of ['light','dark']) {
    phase='viewport_'+width+'_'+theme; const v=await contextFor({width,height:width===390?844:1000},theme); await v.page.goto(origin); await login(v.page);
    await v.page.getByRole('button',{name:'Open website '+name,exact:true}).click(); await v.page.getByTestId('website-details').waitFor();
    const filename=width+'-'+theme+'-websites.png'; await shot(v.page,filename);
    check(await v.page.getByTestId('website-details').getAttribute('data-site-id')===id,'viewport_selected_wrong_site'); healthy(v.health);
    report.viewports.push({width,theme,screenshot:filename,overflow:false,health:v.health});
    await v.page.getByRole('button',{name:'Sign out locally',exact:true}).click(); await v.page.getByLabel('Operator access key',{exact:true}).waitFor(); await v.context.close();
  }
  phase='public privacy'; const p=await contextFor({width:1440,height:1000},'light',true); await p.page.goto('http://127.0.0.1:8081'); await p.page.getByTestId('server-overview').waitFor();
  check(await p.page.getByTestId('nav-websites').count()===0 && p.health.private_requests===0,'public_view_exposes_websites');
  const statuses=[]; for(const path of ['/api/v1/session','/api/v1/session/login','/api/v1/sites']) { const r=await p.context.request.get('http://127.0.0.1:8081'+path,{timeout:10000,maxRedirects:0}); statuses.push(r.status()); check(r.status()===404,'public_private_route_not_404'); }
  await shot(p.page,'1440-light-public.png'); healthy(p.health); report.public_preview={websites_nav_absent:true,private_fetches:0,private_api_statuses:statuses,screenshot:'1440-light-public.png'}; await p.context.close();
  report.passed=true;
  }
  phase='final source fingerprint';
  for(const [path,digest] of Object.entries(report.sources))check(hash(await boundedFile(join(root,path),2<<20))===digest,'source_changed_during_qa');
} catch(error) {
  report.failure={phase,code:error.checkCode||'bounded_browser_step_failed'};
  process.exitCode=1;
} finally {
  credential=undefined; if(browser)await browser.close().catch(()=>{});
  await directory(output); await writeFile(join(output,'report.json'),JSON.stringify(report,null,2)+'\n');
  await writeFile(join(root,'artifacts/sites/latest.json'),JSON.stringify({run_id:runId,directory:relative(root,output).split(sep).join('/'),passed:report.passed,report_sha256:hash(await readFile(join(output,'report.json')))},null,2)+'\n');
  console.log(JSON.stringify({run_id:runId,passed:report.passed,phase:report.failure?.phase,code:report.failure?.code,viewports:report.viewports.length,main_state_mutated:false,paid_provider_calls:0}));
}
