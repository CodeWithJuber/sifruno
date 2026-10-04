// Actual native archive smoke test. Uses isolated fixtures, no hosting/provider calls.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile, lstat } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import http from 'node:http';
import os from 'node:os';
import { configure, Uint8ArrayReader, Uint8ArrayWriter, ZipReader } from '@zip.js/zip.js';

let phase='archive validation';
async function main(){
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const hash=x=>createHash('sha256').update(x).digest('hex');
if(process.platform!=='win32'||process.arch!=='x64')throw new Error('This native archive check requires Windows amd64; other targets need their own native host.');
const latest=JSON.parse(await readFile(join(root,'deliverables/runtime-builds/latest.json'),'utf8'));
const index=JSON.parse(await readFile(join(root,latest.directory,'index.json'),'utf8'));
assert.equal(hash(JSON.stringify(index,null,2)+'\n'),latest.index_sha256,'Build index integrity failure');
const archived=index.archives.find(x=>x.file.endsWith('windows-amd64.zip'));
assert(archived,'Windows amd64 archive missing');
const bytes=await readFile(join(root,archived.file));assert.equal(hash(bytes),archived.sha256,'Archive checksum failure');
const work=join(root,'.cache/runtime-verification',randomBytes(8).toString('hex'));
await mkdir(work,{recursive:true});configure({useWebWorkers:false});
const reader=new ZipReader(new Uint8ArrayReader(bytes),{useWebWorkers:false});
const extracted=new Map();
for(const entry of await reader.getEntries()){
 const name=entry.filename;assert(/^[A-Za-z0-9_./@-]+$/.test(name)&&!name.includes('..')&&!name.startsWith('/')&&!name.split('/').some(x=>x.startsWith('.')),'Unexpected archive path');
 const data=await entry.getData(new Uint8ArrayWriter(),{checkSignature:true});const target=join(work,name);await mkdir(dirname(target),{recursive:true});await writeFile(target,data);extracted.set(name,data);
}
await reader.close();const manifest=JSON.parse(new TextDecoder().decode(extracted.get('manifest.json')));
for(const file of manifest.files){assert(extracted.has(file.path),'Manifest file missing');assert.equal(hash(extracted.get(file.path)),file.sha256,'Extracted file integrity failure')}
assert.equal(extracted.size,manifest.files.length+1,'Unmanifested file');
const environment={};for(const key of ['SYSTEMROOT','SystemRoot','WINDIR','TEMP','TMP','USERPROFILE','LOCALAPPDATA','PATH','Path'])if(process.env[key]!==undefined)environment[key]=process.env[key];
const cli=join(work,'bin/panelctl.exe'), state=join(work,'private-state');
function command(args,{fail=false,json=true}={}){
 const r=spawnSync(cli,args,{cwd:work,env:environment,windowsHide:true,shell:false,encoding:'utf8',timeout:15000,maxBuffer:2<<20});
 if(r.error)throw new Error('Native CLI could not execute');
 if(fail){assert.notEqual(r.status,0,'Expected failure escaped guard');return}
 assert.equal(r.status,0,'Native CLI failed');return json?JSON.parse(r.stdout):r.stdout;
}
const run=args=>command(['--state',state,...args]);
phase='native original TAR backup characterization';
const originalFixture=join(root,'.cache/cpanel-backup-qualification',latest.run_id+'-'+randomBytes(4).toString('hex'));
const python=join(process.env.LOCALAPPDATA??'','Programs/Python/Python312/python.exe');
const generated=spawnSync(python,['-I',join(root,'lab/cpanel_backup_fixture.py'),originalFixture],{cwd:root,env:environment,windowsHide:true,shell:false,encoding:'utf8',timeout:15000,maxBuffer:65536});
assert.equal(generated.status,0,'Independent synthetic TAR producer failed');
const originalExpected=JSON.parse(await readFile(join(originalFixture,'expected.json'),'utf8'));
assert.equal(originalExpected.kind,'synthetic');
for(const sourceName of ['synthetic.tar','synthetic.tar.gz']){
 const input=join(originalFixture,sourceName),output=join(originalFixture,sourceName+'.jsonl');
 const before=await readFile(input),result=command(['backup','inspect','--from',input,'--out',output]);
 assert.equal(result.complete,true);assert.equal(result.compatibility_certified,false);assert.equal(result.reference_observed,false);assert.equal(result.restore_implemented,false);
 assert.equal(result.archive_sha256,originalExpected.source_sha256[sourceName]);assert.equal(result.archive_bytes,before.length);assert.equal(result.entries,originalExpected.entries);assert(result.blocker_count>=3);
 const catalog=await readFile(output);assert(catalog.length<1048576);assert(!catalog.includes(Buffer.from('SIFRUNO_SYNTHETIC_PRIVATE_PAYLOAD_DO_NOT_PRINT_91f783')),'Private synthetic content appeared in catalog');
 const rows=catalog.toString('utf8').split('\n');assert.equal(rows.pop(),'');const footer=JSON.parse(rows.pop());
 assert.equal(footer.type,'footer');assert.deepEqual(footer.summary,result);assert.equal(result.catalog_sha256,hash(Buffer.from(rows.join('\n')+'\n')));
 const records=rows.map(line=>JSON.parse(line));assert.equal(records[0].evidence_kind,'local_archive_characterization');
 const entries=records.slice(1).map(record=>{assert.equal(record.type,'entry');return record.entry});
 for(const file of originalExpected.files){const item=entries.find(entry=>Buffer.from(entry.name_base64,'base64').toString('utf8')===file.name);assert(item,'Expected original logical entry absent');assert.equal(item.sha256,file.sha256);assert.equal(item.size,file.bytes);assert.equal(item.uid,1234);assert.equal(item.gid,2345);assert.equal(item.mode,0o640);assert.equal(item.type,'file');assert.equal(item.physical_type_flag,48);}
 assert(entries.some(entry=>entry.type==='symlink'));assert(entries.some(entry=>entry.type==='hardlink'));assert(entries.some(entry=>entry.type==='fifo'));
 command(['backup','inspect','--from',input,'--out',output],{fail:true});assert.equal(hash(await readFile(output)),hash(catalog),'Existing catalog overwritten');assert.equal(hash(await readFile(input)),hash(before),'Original archive changed');
}
for(const sourceName of ['bad-crc.tar.gz','truncated.tar','trailing.tar']){
 const output=join(originalFixture,sourceName+'.jsonl');command(['backup','inspect','--from',join(originalFixture,sourceName),'--out',output],{fail:true});
 let present=false;try{await lstat(output);present=true}catch(error){if(error.code!=='ENOENT')throw error};assert.equal(present,false,'Failed catalog was not cleaned up');
}
for(const directory of [join(work,'.state'),state]){let present=false;try{await lstat(directory);present=true}catch(error){if(error.code!=='ENOENT')throw error};assert.equal(present,false,'Read-only backup inspection initialized private state');}
phase='native CLI status and evidence';
const report=command(['status']);assert.equal(report.ready,false);assert.equal(report.untested,30);command(['status','--require-ready'],{fail:true});
const diff=command(['evidence','compare','fixtures/synthetic-reference.json','fixtures/synthetic-candidate.json']);assert.equal(diff.kind,'synthetic');assert.equal(diff.matching,1);assert.equal(diff.different,1);assert.equal(diff.certifies_compatibility,false);
const files=join(work,'fixture-files');await mkdir(files);await writeFile(join(files,'site.conf'),'before\n');
phase='native CLI file recovery';
const change=run(['trail','checkpoint','--root',files,'--paths','site.conf','--reason','Native archive verification fixture','--actor','Local verification']);
await writeFile(join(files,'site.conf'),'after\n');run(['trail','seal',change.id]);run(['trail','rollback',change.id]);run(['trail','verify']);assert.equal(await readFile(join(files,'site.conf'),'utf8'),'before\n');
const operation=hash('Isolated no-provider budget verification fixture');
phase='native CLI budget guards';
const grant=run(['budget','approve','--operation',operation,'--revision','fixture1','--actor','Local verification','--max-micros','1000000']);
run(['budget','reserve','--id','fixture-call','--approval',grant.id,'--operation',operation,'--revision','fixture1','--micros','1000000']);
command(['--state',state,'budget','reserve','--id','replay','--approval',grant.id,'--operation',operation,'--revision','fixture1','--micros','1'],{fail:true});
command(['--state',state,'budget','settle','--id','fixture-call','--actual-micros','1500000'],{fail:true});
const budget=run(['budget','status']);assert.equal(budget.reconciliation_required,true);assert.equal(budget.spent_usd_micros,1500000);assert.equal(budget.remaining_usd_micros,0);
const port=await new Promise((yes,no)=>{const s=net.createServer();s.once('error',no);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>yes(p))})});
const sitePort=await new Promise((yes,no)=>{const s=net.createServer();s.once('error',no);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>yes(p))})});
const startServer=()=>spawn(join(work,'bin/sifruno.exe'),['--listen',`127.0.0.1:${port}`,'--sites-listen',`127.0.0.1:${sitePort}`,'--state',state,'--ui',join(work,'web/dist')],{cwd:work,env:environment,windowsHide:true,shell:false,stdio:'ignore'});
let server=startServer();
try{
 phase='native HTTP startup and guards';
 const url=`http://127.0.0.1:${port}`;let response;
 for(let i=0;i<100;i++){try{response=await fetch(url+'/api/v1/status');if(response.ok)break}catch{};await new Promise(r=>setTimeout(r,50))}
 assert(response?.ok,'Native server did not become ready');assert.equal((await response.json()).ready,false);
 assert.equal((await fetch(url+'/')).status,200);assert.equal((await fetch(url+'/openapi.json')).status,200);
 const hostGuard=await new Promise((yes,no)=>{const req=http.request(url+'/api/v1/status',{headers:{Host:'evil.example'}},res=>{res.resume();yes(res.statusCode)});req.once('error',no);req.end()});assert.equal(hostGuard,403);
 assert.equal((await fetch(url+'/api/v1/status',{headers:{Origin:'https://evil.example'}})).status,403);
 assert.equal((await fetch(url+'/api/v1/budget',{method:'POST'})).status,405);
 assert.equal((await fetch(url+'/cpsess1234567890/json-api/createacct')).status,501);
 assert.equal((await fetch(url+'/.state/key')).status,404);
 const trail=await(await fetch(url+'/api/v1/trail')).json();assert.equal(trail.items.length,1);assert.equal(trail.items[0].state,'rolled_back');
 const costs=await(await fetch(url+'/api/v1/budget')).json();assert.equal(costs.reconciliation_required,true);assert.equal(costs.remaining_usd_micros,0);
 const platform=await(await fetch(url+'/api/v1/platform')).json();assert.equal(platform.os,'windows');assert.equal(platform.profiles.length,6);
 phase='native authenticated website create edit backup restore and serving';
 assert.equal((await fetch(url+'/api/v1/sites')).status,401);
 const siteCommand=argv=>command(['--state',state,'--panel-url',url,'sites',...argv]);
 let site=siteCommand(['create','--name','Native website verification fixture','--domain','native-fixture.example']);
 let file=siteCommand(['read','--id',site.id,'--path','index.html']);
 const pageFile=join(work,'fixture-files/page.html'),pageContent='<!doctype html><title>Native fixture</title><p>Saved website content</p>';
 await writeFile(pageFile,pageContent);
 site=siteCommand(['write','--id',site.id,'--path','index.html','--from',pageFile,'--revision',String(file.revision),'--sha256',file.sha256]);
 const backup=siteCommand(['backup','--id',site.id,'--revision',String(site.revision)]);
 phase='native ZIP CLI export and import';
 const exportFile=join(work,'native-site-export.zip');
 const exported=siteCommand(['export','--id',site.id,'--backup',backup.id,'--out',exportFile]);
 const exportedBytes=await readFile(exportFile);
 assert.equal(exported.sha256,backup.sha256,'Export did not match the recorded backup');
 assert.equal(hash(exportedBytes),backup.sha256,'Exported ZIP bytes changed');
 assert.equal(exported.bytes,backup.bytes,'Exported ZIP size changed');
 command(['--state',state,'--panel-url',url,'sites','export','--id',site.id,'--backup',backup.id,'--out',exportFile],{fail:true});
 assert.equal(hash(await readFile(exportFile)),backup.sha256,'Existing export file was overwritten');
 const imported=siteCommand(['import','--name','Native imported archive','--domain','native-import.test','--from',exportFile]);
 assert.notEqual(imported.id,site.id,'Import reused the original target');
 assert.equal(siteCommand(['read','--id',imported.id,'--path','index.html']).content,pageContent,'Imported content differs from backup');
 assert.equal(siteCommand(['backups','--id',imported.id]).items.length,0,'Import fabricated source backup history');
 file=siteCommand(['read','--id',site.id,'--path','index.html']);
 await writeFile(pageFile,'<p>Changed after backup</p>');
 site=siteCommand(['write','--id',site.id,'--path','index.html','--from',pageFile,'--revision',String(file.revision),'--sha256',file.sha256]);
 site=siteCommand(['restore','--id',site.id,'--backup',backup.id,'--revision',String(site.revision)]);
 assert.equal(siteCommand(['read','--id',site.id,'--path','index.html']).content,pageContent,'Restored website bytes differ');
 const getWebsite=(host=site.preview_host)=>new Promise((yes,no)=>{const req=http.request(`http://127.0.0.1:${sitePort}/`,{headers:{Host:host}},res=>{let body='';res.setEncoding('utf8');res.on('data',chunk=>{body+=chunk;if(body.length>8192)req.destroy()});res.on('end',()=>yes({status:res.statusCode,body}))});req.once('error',no);req.setTimeout(5000,()=>req.destroy());req.end()});
 let preview=await getWebsite();assert.equal(preview.status,200);assert.equal(preview.body,pageContent);
 assert.equal((await getWebsite(imported.preview_host)).body,pageContent,'Imported HTTP content differs');
 site=siteCommand(['state','--id',site.id,'--state','suspended','--revision',String(site.revision)]);assert.notEqual((await getWebsite()).status,200);
 site=siteCommand(['state','--id',site.id,'--state','active','--revision',String(site.revision)]);assert.equal((await getWebsite()).body,pageContent);
 command(['--state',state,'--panel-url',url,'sites','write','--id',site.id,'--path','index.html','--from',pageFile,'--revision',String(file.revision),'--sha256',file.sha256],{fail:true});
 phase='native website process restart persistence';
 await new Promise((yes,no)=>{const timer=setTimeout(()=>no(new Error('Isolated test child did not stop')),5000);server.once('exit',()=>{clearTimeout(timer);yes()});server.kill()});
 server=startServer();let restarted=false;
 for(let i=0;i<100;i++){try{if((await fetch(url+'/api/v1/status',{signal:AbortSignal.timeout(1000)})).ok){restarted=true;break}}catch{};await new Promise(r=>setTimeout(r,50))}
 assert(restarted,'Restarted native server did not become ready');assert.equal(siteCommand(['read','--id',site.id,'--path','index.html']).content,pageContent);assert.equal((await getWebsite()).body,pageContent);assert.equal(siteCommand(['backups','--id',site.id]).items.length,1);
 assert.equal(siteCommand(['read','--id',imported.id,'--path','index.html']).content,pageContent,'Imported files did not survive restart');
 assert.equal((await getWebsite(imported.preview_host)).body,pageContent,'Imported HTTP content did not survive restart');
 const {chromium}=await import('playwright');const browser=await chromium.launch({headless:true,env:environment});
 phase='native UI fixture states';
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',()=>errors.push('pageerror'));page.on('console',m=>{if(m.type()==='error')errors.push('consoleerror')});
  await page.goto(url);await page.getByRole('heading',{name:'Server overview',exact:true}).waitFor();
  await page.getByTestId('nav-trail').click();await page.getByText('Native archive verification fixture',{exact:true}).waitFor();
  await page.getByTestId('nav-budget').click();await page.getByText('Spending needs attention',{exact:true}).waitFor();
  const artifacts=join(root,'artifacts/runtime');await mkdir(artifacts,{recursive:true});await page.screenshot({path:join(artifacts,'native-budget-alert.png'),fullPage:true});assert.equal(errors.length,0,'Native UI errors');
 }finally{await browser.close()}
 const evidence={checked_at:new Date().toISOString(),host:os.version(),os:'windows',arch:'amd64',run_id:latest.run_id,archive_sha256:archived.sha256,source_fingerprint:index.source_fingerprint,verifier_sha256:hash(await readFile(fileURLToPath(import.meta.url))),archive_integrity:true,manifest_files:manifest.files.length,original_backup_characterization:true,original_backup_fixture_kind:'synthetic',independent_tar_producer:'Python standard tarfile/gzip',original_backup_producer_sha256:hash(await readFile(join(root,'lab/cpanel_backup_fixture.py'))),original_backup_source_fixture_sha256:originalExpected.source_sha256,original_backup_tar_gzip_hashes:true,original_backup_metadata_fidelity:true,original_backup_private_payload_excluded:true,original_backup_bad_stream_cleanup:true,original_backup_no_state_creation:true,original_backup_restore_implemented:false,original_backup_reference_observed:false,server_startup:true,read_only_http_guards:true,cli_recovery:true,approval_replay_rejected:true,budget_reconciliation_guard:true,authenticated_website_cli:true,website_backup_restore_bytes:true,native_zip_cli_export_import:true,native_zip_hash_match:true,native_zip_output_overwrite_refused:true,native_zip_import_http_restart:true,website_suspend_resume:true,website_process_restart_persistence:true,populated_trail_ui:true,budget_alert_ui:true,paid_provider_calls:0,compatibility_certified:false,other_os_runtime_verified:false};
 const runEvidence=join(root,'artifacts/runtime/native-runs',latest.run_id);await mkdir(runEvidence,{recursive:true});
 await writeFile(join(runEvidence,'native-windows.json'),JSON.stringify(evidence,null,2)+'\n');
 await mkdir(join(root,'artifacts/runtime'),{recursive:true});await writeFile(join(root,'artifacts/runtime/native-windows.json'),JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify(evidence,null,2));
}finally{server.kill()}
}
main().catch(error=>{const location=error.stack?.match(/verify-runtime\.mjs:\d+:\d+/)?.[0]??'';const numeric=typeof error.actual==='number'?` (actual ${error.actual}, expected ${error.expected})`:'';console.error(`Native archive verification failed during ${phase}: ${error.name} ${location}${numeric}. Sensitive diagnostic values are suppressed.`);process.exitCode=1});
