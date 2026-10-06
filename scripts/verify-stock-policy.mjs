// Offline signed-image observation. Imports do not execute tools or guests.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';

const OWN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PRIMARY = path.resolve(OWN, '../..');
const CANDIDATE = path.join(PRIMARY, '.worktrees/stock-preflight-integration');
const BASE = 'cebd86fa9ec12a24e6e597e88d5185d76540c685';
const IMAGE = '.tools/linuxguest/alma9/AlmaLinux-9-GenericCloud-9.8-20260810.x86_64.qcow2';
const IMAGE_SHA = '6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b';
const QDIR = '.tools/linuxguest/qemu-20260811';
const PYTHON = 'C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python.exe';
const STATIC = {
 'scripts/alma-account-iso.py': '160ce339cefa1b58866dc2816b0356acb63abe47a623fec29abbdf05b3d03293',
 'scripts/go.ps1': '743ebc069474966efecd831a522695d295ab1570660e62270070ef0fa59443b9',
 '.tools/go/bin/go.exe': 'd3ccdb604eafa6031133aefe1a3db24f0bb7362b857bc2125ac4e4c178b4b490',
 '.tools/linuxguest/prepared.json': '211e7d98ce793a4302be5f4826b9f61dcfcce0fb410e18ff551835d517456914',
 '.tools/linuxguest/alma9/verified.json': '1feae2b3ddf046edc6ab4ff65d57b78f9d1c9428174fc79eabe0c34de246368f',
 '.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl': '1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e',
};
const HEX = /^[0-9a-f]{64}$/;
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const norm = value => path.resolve(value).toLowerCase();
const relative = (root, file) => path.relative(root, file).replaceAll('\\', '/');
export function keys(value, names) {
 assert(value && typeof value === 'object' && !Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(), [...names].sort());
}
export function canonicalJSON(raw) {
 assert(Buffer.byteLength(raw) <= 65536 && !raw.includes('\r'));
 const value = JSON.parse(raw);
 // The guest emits compact ASCII JSON; exact roundtrip rejects nested duplicates,
 // alternate escapes, trailing bytes, nonfinite numbers and ambiguous encodings.
 assert.equal(JSON.stringify(value), raw.trim());
 return value;
}
export function admitted(root, file, maximum=64*1024*1024) {
 const name = path.resolve(file); const rel = path.relative(root, name);
 assert(rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel), 'input_outside_admitted_root');
 for(let current=name;;current=path.dirname(current)) {
  const info=fs.lstatSync(current); assert(!info.isSymbolicLink() && norm(fs.realpathSync(current))===norm(current), 'input_link');
  if(norm(current)===norm(root)) break;
 }
 const info=fs.lstatSync(name); assert(info.isFile() && info.nlink===1 && info.size<=maximum, 'input_metadata');
 return name;
}
function pin(root, name, namespace, maximum) {
 const file=admitted(root,path.join(root,name),maximum), bytes=fs.readFileSync(file);
 return {namespace, path: name.replaceAll('\\','/'), bytes:bytes.length, sha256:digest(bytes)};
}
function readPin(entry) {
 const roots={primary:PRIMARY, baseline:OWN, candidate:CANDIDATE, go:path.join(PRIMARY,'.tools/go'), modules:path.join(PRIMARY,'.cache/go-mod'), python:path.dirname(PYTHON)};
 return pin(roots[entry.namespace], entry.path,entry.namespace, Math.max(entry.bytes,1));
}
function stable(catalog) { return catalog.every(item => { try { return JSON.stringify(readPin(item))===JSON.stringify(item); } catch { return false; } }); }
function sorted(catalog) {
 catalog.sort((a,b)=>`${a.namespace}/${a.path}`.localeCompare(`${b.namespace}/${b.path}`,'en'));
 assert.equal(new Set(catalog.map(x=>x.namespace+'/'+x.path)).size,catalog.length,'duplicate_catalog_path');
 return catalog;
}
function walk(root, name, accept) {
 const files=[]; const visit=directory=>{
  const info=fs.lstatSync(directory); assert(info.isDirectory()&&!info.isSymbolicLink()&&norm(fs.realpathSync(directory))===norm(directory));
  for(const entry of fs.readdirSync(directory,{withFileTypes:true})) {
   const file=path.join(directory,entry.name); assert(!entry.isSymbolicLink());
   if(entry.isDirectory())visit(file); else if(accept(file))files.push(relative(root,file));
  }
 }; visit(path.join(root,name)); return files.sort();
}
function sourceCatalog(root, namespace) {
 return sorted(['go.mod','go.sum',...walk(root,'cmd',p=>p.endsWith('.go')),...walk(root,'internal',p=>p.endsWith('.go'))].map(name=>pin(root,name,namespace)));
}
function mkdirOwned(name) {
 const target=path.resolve(OWN,name), rel=path.relative(OWN,target);assert(!rel.startsWith('..')&&!path.isAbsolute(rel));
 let current=OWN;
 for(const part of rel.split(path.sep)) {
  assert(part&&part!=='.'&&part!=='..');current=path.join(current,part);
  if(!fs.existsSync(current))fs.mkdirSync(current);
  assert(fs.lstatSync(current).isDirectory()&&!fs.lstatSync(current).isSymbolicLink()&&norm(fs.realpathSync(current))===norm(current));
 }return target;
}
function write(file, value) { fs.writeFileSync(file,typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(value,null,2)+'\n',{flag:'wx'}); }
function environment(temp) {
 const env={}; for(const key of ['SYSTEMROOT','SystemRoot','WINDIR'])if(process.env[key])env[key]=process.env[key];
 assert(env.SystemRoot||env.SYSTEMROOT);
 env.PATH=[path.join(PRIMARY,'.tools/go/bin'),path.join(PRIMARY,QDIR),path.join(env.SystemRoot||env.SYSTEMROOT,'System32')].join(path.delimiter);
 return {...env,OS:'Windows_NT',PATHEXT:'.COM;.EXE;.BAT;.CMD',TEMP:temp,TMP:temp,GOENV:'off',GOPROXY:'off',GOSUMDB:'off',GOTOOLCHAIN:'local',CGO_ENABLED:'0',GOOS:'linux',GOARCH:'amd64',GOFLAGS:'',PYTHONDONTWRITEBYTECODE:'1'};
}
export async function child(command,args,{cwd=OWN,env,timeout=60000,maximum=2*1024*1024,onChunk}={}) {
 const processChild=spawn(command,args,{cwd,env,windowsHide:true,stdio:['ignore','pipe','pipe']});
 let size=0,limit=false,timedout=false,error=false;const out=[],err=[];
 const capture=(target,chunk)=>{if(limit)return;size+=chunk.length;if(size>maximum){limit=true;processChild.kill();return;}target.push(chunk);onChunk?.(chunk);};
 processChild.stdout.on('data',chunk=>capture(out,chunk));processChild.stderr.on('data',chunk=>capture(err,chunk));
 const timer=setTimeout(()=>{timedout=true;processChild.kill();},timeout);
 let result;
 try { result=await new Promise(resolve=>{processChild.once('error',()=>{error=true;});processChild.once('close',(code,signal)=>resolve({code,signal}));}); }
 finally { clearTimeout(timer);if(processChild.exitCode===null&&processChild.signalCode===null)processChild.kill(); }
 return {...result,error,timedout,output_limit:limit,bytes:size,stdout:Buffer.concat(out),stderr:Buffer.concat(err),owned_child_exited:processChild.exitCode!==null||processChild.signalCode!==null||error};
}
function successful(result) { assert(!result.error&&!result.timedout&&!result.output_limit&&result.code===0&&result.owned_child_exited,'bounded_child_failed'); }
function toolCatalog() {
 const catalog=Object.entries(STATIC).map(([name,expected])=>{const item=pin(PRIMARY,name,'primary');assert.equal(item.sha256,expected,'pinned_tool_mismatch');return item;});
 const python=pin(path.dirname(PYTHON),path.basename(PYTHON),'python');assert.equal(python.sha256,'4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a');catalog.push(python);
 const image=pin(PRIMARY,IMAGE,'primary',700*1024*1024);assert.equal(image.sha256,IMAGE_SHA);catalog.push(image);
 const verified=JSON.parse(fs.readFileSync(admitted(PRIMARY,path.join(PRIMARY,'.tools/linuxguest/alma9/verified.json')),'utf8'));
 assert(verified.checksum_signature_verified===true&&verified.signer_fingerprint==='BF18AC2876178908D6E71267D36CB86CB86B3716'&&verified.sha256===IMAGE_SHA&&verified.bytes===image.bytes);
 const prepared=JSON.parse(fs.readFileSync(admitted(PRIMARY,path.join(PRIMARY,'.tools/linuxguest/prepared.json')),'utf8'));assert(prepared.schema_version===1&&prepared.files.length===125);
 for(const file of prepared.files){keys(file,['path','bytes','sha256']);assert(file.path.startsWith('.tools/linuxguest/')&&HEX.test(file.sha256));const item=pin(PRIMARY,file.path,'primary');assert.equal(item.bytes,file.bytes);assert.equal(item.sha256,file.sha256);if(!catalog.some(old=>old.namespace===item.namespace&&old.path===item.path))catalog.push(item);}
 for(const name of walk(PRIMARY,'.tools/go/pkg/tool',()=>true))catalog.push(pin(PRIMARY,name,'primary'));
 return sorted(catalog);
}
function harnessCatalog() { return sorted(['scripts/verify-stock-policy.mjs',...walk(OWN,'lab/stock-policy-guest',()=>true)].map(name=>pin(OWN,name,'baseline'))); }
function objects(raw) {
 const values=[];let start=-1,depth=0,quoted=false,escape=false;
 for(let i=0;i<raw.length;i++){const c=raw[i];if(quoted){if(escape)escape=false;else if(c==='\\')escape=true;else if(c==='"')quoted=false;}else if(c==='"')quoted=true;else if(c==='{'){if(depth++===0)start=i;}else if(c==='}'&&--depth===0){values.push(JSON.parse(raw.slice(start,i+1)));start=-1;}else if(depth===0)assert(/\s/.test(c));}
 assert(depth===0&&!quoted&&start===-1&&values.length>0);return values;
}
async function linkedCatalog(root, namespace, env) {
 const ps=path.join(env.SystemRoot||env.SYSTEMROOT,'System32/WindowsPowerShell/v1.0/powershell.exe');
 const result=await child(ps,['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(PRIMARY,'scripts/go.ps1'),'list','-mod=readonly','-deps','-json','./cmd/hostbroker'],{cwd:root,env,timeout:120000});successful(result);assert.equal(result.stderr.length,0);
 const entries=new Map();
 const roots=[[root,namespace],[path.join(PRIMARY,'.tools/go'),'go'],[path.join(PRIMARY,'.cache/go-mod'),'modules']];
 for(const pkg of objects(result.stdout.toString('utf8'))){assert(!pkg.Error&&!pkg.DepsErrors&&typeof pkg.Dir==='string');for(const key of ['GoFiles','CgoFiles','SFiles','HFiles','SysoFiles','EmbedFiles'])for(const name of pkg[key]||[]){const file=path.resolve(pkg.Dir,name),match=roots.find(([base])=>{const rel=path.relative(base,file);return rel&&!rel.startsWith('..')&&!path.isAbsolute(rel);});assert(match,'linked_source_outside_admission');const item=pin(match[0],relative(match[0],file),match[1]);entries.set(item.namespace+'/'+item.path,item);}if(pkg.Module?.GoMod){const file=pkg.Module.GoMod,match=roots.find(([base])=>{const rel=path.relative(base,file);return rel&&!rel.startsWith('..')&&!path.isAbsolute(rel);});assert(match);const item=pin(match[0],relative(match[0],file),match[1]);entries.set(item.namespace+'/'+item.path,item);}}
 return sorted([...entries.values()]);
}
function merge(...catalogs) { const items=new Map();for(const catalog of catalogs)for(const item of catalog){const id=item.namespace+'/'+item.path;if(items.has(id))assert.deepEqual(items.get(id),item);items.set(id,item);}return sorted([...items.values()]); }
async function buildBaseline(tools,harness) {
 const id=`baseline-${Date.now()}-${randomBytes(4).toString('hex')}`,work=mkdirOwned('.cache/stock-policy-build/'+id),env=environment(work),ps=path.join(env.SystemRoot||env.SYSTEMROOT,'System32/WindowsPowerShell/v1.0/powershell.exe');
 // The primary wrapper's normal shared compilation cache is explicitly allowed;
 // dependency/module/tool inputs stay read-only. Outputs and TEMP/TMP are owned.
 const guard=await child('C:/Program Files/Git/cmd/git.exe',['diff','--exit-code',BASE,'--','cmd','internal','go.mod','go.sum'],{env,maximum:65536});successful(guard);assert.equal(guard.stdout.length,0);
 const before=merge(sourceCatalog(OWN,'baseline'),await linkedCatalog(OWN,'baseline',env));
 const output=path.join(work,'hostbroker-baseline-linux-amd64');
 const result=await child(ps,['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(PRIMARY,'scripts/go.ps1'),'build','-mod=readonly','-trimpath','-buildvcs=false','-o',output,'./cmd/hostbroker'],{env,timeout:180000});successful(result);assert.equal(result.stdout.length+result.stderr.length,0);
 assert(stable(before)&&stable(tools)&&stable(harness),'build_inputs_changed');
 const binary=pin(OWN,relative(OWN,output),'baseline');assert.equal(fs.readFileSync(output).subarray(0,4).toString('hex'),'7f454c46');
 const manifest={schema_version:1,scope:'offline_unchanged_baseline_linux_build',source_base:BASE,source_catalog:before,source_catalog_sha256:digest(JSON.stringify(before)),tools_catalog_sha256:digest(JSON.stringify(tools)),binary,commands:[['go.ps1','list','-mod=readonly','-deps','-json','./cmd/hostbroker'],['go.ps1','build','-mod=readonly','-trimpath','-buildvcs=false','-o','OWNED_BINARY','./cmd/hostbroker']],go_environment:{GOOS:'linux',GOARCH:'amd64',CGO_ENABLED:'0',GOPROXY:'off',GOSUMDB:'off',GOTOOLCHAIN:'local',module_inputs:'primary_read_only',compilation_cache:'primary_wrapper_default_allowed',temp_and_output:'owned'},exits:{source_guard:guard.code,list:0,build:result.code},inputs_unchanged:true};
 write(path.join(work,'manifest.json'),manifest);console.log(JSON.stringify({mode:'baseline_build',passed:true,native_observation:false,manifest:relative(OWN,path.join(work,'manifest.json')),manifest_sha256:digest(fs.readFileSync(path.join(work,'manifest.json'))),binary_sha256:binary.sha256,linked_inputs:before.length}));
}
export function validateCheck(value) {
 keys(value,['schema_version','scope','platform','supported','read_only','checks','restrictions']);assert.equal(value.schema_version,1);assert.equal(value.scope,'native_linux_account_host_policy');assert.equal(value.platform,'linux');assert.equal(value.supported,false);assert.equal(value.read_only,true);assert.deepEqual(value.restrictions,['host_policy_only','controller_paths_state_not_checked','no_stock_host_or_cpanel_certification']);
 assert(Array.isArray(value.checks)&&value.checks.length===3);const ids=['utilities','nss','useradd_defaults'],reasons=['trusted_utilities_required','files_only_nss_required','mail_disabled_defaults_required'];
 value.checks.forEach((check,i)=>{keys(check,['id','status','reason']);assert.equal(check.id,ids[i]);assert(check.status==='pass'&&check.reason==='satisfied'||check.status==='refused'&&check.reason===reasons[i]);});assert(value.checks.some(x=>x.status==='refused'));return value;
}
export function validateGuest(value,binding) {
 keys(value,['schema_version','scope','nonce','passed','profile','binary_sha256','controller','policy_before','policy_after','check_host','check_host_exit','baseline','candidate','listeners_before','listeners_after','policy_unchanged','inputs_unchanged','account_created','policy_rewritten','owned_children_exited']);
 assert.equal(value.schema_version,1);assert.equal(value.scope,'disposable_stock_linux_policy_observation');assert.equal(value.nonce,binding.nonce);assert.equal(value.passed,true);assert.deepEqual(value.binary_sha256,binding.hashes);
 keys(value.profile,['distribution','version','kernel','machine']);assert.equal(value.profile.distribution,'almalinux');assert.equal(value.profile.version,'9.8');assert.equal(value.profile.machine,'x86_64');assert(/^[A-Za-z0-9._+\-]{1,128}$/.test(value.profile.kernel));
 keys(value.controller,['uid','matching_local_passwd_records','account_created']);assert.deepEqual(value.controller,{uid:65534,matching_local_passwd_records:1,account_created:false});
 const ids=['nss','nss_authselect','useradd_defaults','login_defaults','passwd_metadata','group_metadata','groupadd','useradd','usermod','passwd_utility','chage','nologin'];
 assert(Array.isArray(value.policy_before)&&value.policy_before.length===ids.length);
 value.policy_before.forEach((item,i)=>{keys(item,['id','kind','mode','bytes','sha256']);assert.equal(item.id,ids[i]);assert(['file','symlink','missing'].includes(item.kind)&&/^[0-7]{4}$/.test(item.mode)&&Number.isSafeInteger(item.bytes)&&item.bytes>=0&&item.bytes<=4*1024*1024);assert(item.kind==='missing'?item.sha256===null&&item.bytes===0&&item.mode==='0000':HEX.test(item.sha256));if(item.id==='nss'||item.id==='useradd_defaults'||item.id==='passwd_metadata')assert(item.kind!=='missing');});assert.deepEqual(value.policy_after,value.policy_before);
 validateCheck(value.check_host);assert.equal(value.check_host_exit,1);
 for(const [name,exists,modes] of [['baseline',[true,true,true],['0700','0755','0755']],['candidate',[false,false,false],[null,null,null]]]){keys(value[name],['exit_code','declared_directory_exists','declared_directory_modes','socket_exists','store_created','owned_child_exited']);assert.deepEqual(value[name],{exit_code:1,declared_directory_exists:exists,declared_directory_modes:modes,socket_exists:false,store_created:false,owned_child_exited:true});}
 keys(value.listeners_before,['count','sha256']);assert(Number.isSafeInteger(value.listeners_before.count)&&value.listeners_before.count>=0&&value.listeners_before.count<=4096&&HEX.test(value.listeners_before.sha256));assert.deepEqual(value.listeners_after,value.listeners_before);
 for(const name of ['policy_unchanged','inputs_unchanged','owned_children_exited'])assert.equal(value[name],true);for(const name of ['account_created','policy_rewritten'])assert.equal(value[name],false);return value;
}
export function parseSerial(raw,binding) {
 assert(Buffer.byteLength(raw)<=2*1024*1024);const text=raw.replaceAll('\r\n','\n');
 // Boot bytes remain opaque. Nothing, including ANSI/CR, is stripped from
 // the exact marker lines or the raw nonce-framed JSON segment.
 const markers=text.split('\n').filter(line=>line.includes('SIFRUNO_STOCK_'));
 const begin='SIFRUNO_STOCK_REPORT_BEGIN_'+binding.nonce,end='SIFRUNO_STOCK_REPORT_END_'+binding.nonce,exit='SIFRUNO_STOCK_FIXTURE_EXIT_'+binding.nonce+'_0';assert.deepEqual(markers,[begin,end,exit]);
 const segment=text.slice(text.indexOf(begin+'\n')+begin.length+1,text.indexOf('\n'+end));assert(segment.length>0&&!segment.includes('\n')&&!segment.includes('\r')&&!segment.includes('\x1b'));
 return validateGuest(canonicalJSON(segment),binding);
}
async function runGuest(options,tools,harness) {
 assert(HEX.test(options['candidate-sha'])&&HEX.test(options['candidate-source-sha']),'candidate_freeze_required');
 const candidateFile=admitted(CANDIDATE,options['candidate-binary']);assert(relative(CANDIDATE,candidateFile).startsWith('.cache/'),'candidate_not_owned_build');
 const candidatePin=pin(CANDIDATE,relative(CANDIDATE,candidateFile),'candidate');assert.equal(candidatePin.sha256,options['candidate-sha']);assert.equal(fs.readFileSync(candidateFile).subarray(0,4).toString('hex'),'7f454c46');
 const manifestFile=admitted(OWN,options['baseline-manifest']);assert(relative(OWN,manifestFile).startsWith('.cache/stock-policy-build/'));const manifest=JSON.parse(fs.readFileSync(manifestFile,'utf8'));
 keys(manifest,['schema_version','scope','source_base','source_catalog','source_catalog_sha256','tools_catalog_sha256','binary','commands','go_environment','exits','inputs_unchanged']);assert(manifest.schema_version===1&&manifest.scope==='offline_unchanged_baseline_linux_build'&&manifest.source_base===BASE&&manifest.inputs_unchanged===true);assert.equal(digest(JSON.stringify(manifest.source_catalog)),manifest.source_catalog_sha256);assert.equal(digest(JSON.stringify(tools)),manifest.tools_catalog_sha256);assert(stable(manifest.source_catalog)&&stable([manifest.binary]));
 const baseline=admitted(OWN,path.join(OWN,manifest.binary.path));assert.equal(manifest.binary.namespace,'baseline');
 const nonce=randomBytes(16).toString('hex'),run='stock-'+new Date().toISOString().replace(/[-:.]/g,'')+'-'+nonce.slice(0,8),rel='.cache/alma9-qualification/'+run,work=mkdirOwned(rel),artifacts=mkdirOwned('artifacts/stock-policy/'+run),env=environment(work);
 const candidateSources=sourceCatalog(CANDIDATE,'candidate');assert.equal(digest(JSON.stringify(candidateSources)),options['candidate-source-sha'],'candidate_source_freeze_mismatch');
 const candidateManifest=pin(CANDIDATE,'.cache/stock-preflight/go-source-inputs.json','candidate');assert.equal(candidateManifest.sha256,'344deb12f8d4500c19e5c45f2d2aafd5ae711efd58d417267bbb5f365356dc69');
 const frozenFiles=JSON.parse(fs.readFileSync(path.join(CANDIDATE,candidateManifest.path),'utf8'));assert(Array.isArray(frozenFiles)&&frozenFiles.length===248);
 const fullCandidateFreeze=frozenFiles.map(file=>{keys(file,['path','bytes','sha256']);assert((file.path.endsWith('.go')||['go.mod','go.sum'].includes(file.path))&&HEX.test(file.sha256)&&Number.isSafeInteger(file.bytes)&&file.bytes>=0);const item=pin(CANDIDATE,file.path,'candidate');assert.equal(item.bytes,file.bytes);assert.equal(item.sha256,file.sha256);return item;});sorted(fullCandidateFreeze);
 const inputs=merge(tools,harness,manifest.source_catalog,candidateSources,fullCandidateFreeze,await linkedCatalog(CANDIDATE,'candidate',env),[candidatePin,candidateManifest,pin(OWN,relative(OWN,manifestFile),'baseline'),manifest.binary]);
 write(path.join(work,'host-harness-source.mjs'),fs.readFileSync(path.join(OWN,'scripts/verify-stock-policy.mjs')));
 const hashes={baseline:manifest.binary.sha256,candidate:candidatePin.sha256,fixture:harness.find(x=>x.path==='lab/stock-policy-guest/fixture.py').sha256};
 const binding={nonce,hashes};const entries=[];
 const add=(name,destination)=>{const item=pin(OWN,rel+'/'+name,'baseline');entries.push({source:rel+'/'+name,destination,bytes:item.bytes,sha256:item.sha256});};
 for(const [name,source,destination] of [['baseline-hostbroker',baseline,'payload/panelctl'],['candidate-hostbroker',candidateFile,'payload/hostbroker'],['fixture.py',path.join(OWN,'lab/stock-policy-guest/fixture.py'),'payload/qualifier.py']]){write(path.join(work,name),fs.readFileSync(source));add(name,destination);}
 const script=`#!/bin/sh\nset -eu\nexec >/dev/ttyS0 2>&1\ntrap '/sbin/poweroff' EXIT\nmkdir -m 0700 /opt/sifruno-stock-policy\nmkdir -p /mnt/sifruno-stock-payload\nmount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-stock-payload\ncp /mnt/sifruno-stock-payload/payload/panelctl /opt/sifruno-stock-policy/baseline-hostbroker\ncp /mnt/sifruno-stock-payload/payload/hostbroker /opt/sifruno-stock-policy/candidate-hostbroker\ncp /mnt/sifruno-stock-payload/payload/qualifier.py /opt/sifruno-stock-policy/fixture.py\nchmod 0555 /opt/sifruno-stock-policy/*\nprintf '${nonce}\\n' >/run/sifruno-stock-policy-admission\nchmod 0600 /run/sifruno-stock-policy-admission\nset +e\necho SIFRUNO_STOCK_REPORT_BEGIN_${nonce}\nenv -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -B /opt/sifruno-stock-policy/fixture.py --disposable-stock-policy --nonce ${nonce} --baseline-sha ${hashes.baseline} --candidate-sha ${hashes.candidate} --fixture-sha ${hashes.fixture}\nstatus=$?\necho SIFRUNO_STOCK_REPORT_END_${nonce}\necho SIFRUNO_STOCK_FIXTURE_EXIT_${nonce}_$status\nexit 0\n`;
 write(path.join(work,'meta-data'),`instance-id: ${run}\nlocal-hostname: sifruno-stock-policy\n`);write(path.join(work,'network-config'),'version: 2\nethernets: {}\n');
 // Suppress default cloud-user creation and SSH key generation/import. No
 // password/root-account/NSS/useradd defaults are requested by this payload.
 write(path.join(work,'user-data'),'#cloud-config\nusers: []\nssh_genkeytypes: []\nssh_deletekeys: false\nwrite_files:\n  - path: /root/sifruno-stock-policy-proof.sh\n    owner: root:root\n    permissions: "0700"\n    content: |\n'+script.split('\n').map(line=>'      '+line).join('\n')+'\nruncmd:\n  - ["/bin/sh", "/root/sifruno-stock-policy-proof.sh"]\n');
 for(const name of ['user-data','meta-data','network-config'])add(name,name);
 write(path.join(work,'payload-plan.json'),{schema_version:1,entries});const payloadPins=entries.map(x=>pin(OWN,x.source,'baseline'));payloadPins.push(pin(OWN,rel+'/payload-plan.json','baseline'));
 const adapter=`import importlib.util, pathlib, sys\np=pathlib.Path(sys.argv[1]); s=importlib.util.spec_from_file_location('pinned_iso',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\nm.ROOT=pathlib.Path(sys.argv[2]); m.WHEEL=pathlib.Path(sys.argv[3]); sys.argv=[str(p),'--plan',sys.argv[4]]; m.main()\n`;
 let guest=null,result=null,failure=null,isoResult=null,unchanged=false,phase='iso_generation';
 const started=new Date().toISOString();
 try {
  const made=await child(PYTHON,['-I','-B','-c',adapter,path.join(PRIMARY,'scripts/alma-account-iso.py'),OWN,path.join(PRIMARY,'.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'),rel+'/payload-plan.json'],{env,timeout:90000,maximum:65536});successful(made);assert.equal(made.stderr.length,0);isoResult=JSON.parse(made.stdout.toString());keys(isoResult,['entries','bytes','sha256']);assert.equal(isoResult.entries,6);assert(HEX.test(isoResult.sha256));assert.equal(pin(OWN,rel+'/payload.iso','baseline',256*1024*1024).sha256,isoResult.sha256);
  phase='overlay_creation';const overlay=path.join(work,'guest.qcow2');const created=await child(path.join(PRIMARY,QDIR,'qemu-img.exe'),['create','-f','qcow2','-F','qcow2','-b',path.join(PRIMARY,IMAGE),overlay],{env,timeout:30000,maximum:65536});successful(created);
  assert(stable(inputs)&&stable(payloadPins),'input_changed_before_execution');
  const args=['-L',path.join(PRIMARY,QDIR,'share'),'-machine','pc','-accel','tcg,thread=single','-cpu','max','-smp','1','-m','1536','-nodefaults','-no-user-config','-nic','none','-display','none','-vga','none','-monitor','none','-serial','stdio','-no-reboot','-object','rng-builtin,id=rng0','-device','virtio-rng-pci,rng=rng0','-drive',`file=${overlay},if=virtio,format=qcow2,index=0`,'-drive',`file=${path.join(work,'payload.iso')},media=cdrom,format=raw,readonly=on,index=2`];
  phase='qemu_execution';const chunks=[];result=await child(path.join(PRIMARY,QDIR,'qemu-system-x86_64.exe'),args,{cwd:path.join(PRIMARY,QDIR),env,timeout:600000,onChunk:chunk=>chunks.push(chunk)});
  // Serial remains private in the owned ignored cache; the published receipt
  // never copies boot logs, tool diagnostics, host paths or environment values.
  write(path.join(work,'serial-private.log'),Buffer.concat(chunks));successful(result);phase='serial_admission';guest=parseSerial(Buffer.concat(chunks).toString('utf8'),binding);
 }catch { failure=phase+'_failed'; }
 finally { unchanged=stable(inputs)&&stable(payloadPins); }
 const passed=!failure&&guest?.passed===true&&unchanged&&result?.owned_child_exited===true;
 const receipt={schema_version:1,scope:'signed_alma_stock_policy_refusal_order_observation',run_id:run,started_at:started,completed_at:new Date().toISOString(),passed,native_observation:guest?.passed===true,failure,source_base:BASE,candidate_build_commit:'6494e272c61b533231db0cc889e5a604a5a980e0',candidate_build_authority:'root_supplied_frozen_binary_and_source_manifest',candidate_build_manifest_sha256:candidateManifest.sha256,image_sha256:IMAGE_SHA,image_signature_verified:true,source_catalog:inputs,source_catalog_sha256:digest(JSON.stringify(inputs)),candidate_source_catalog_sha256:options['candidate-source-sha'],harness_catalog_sha256:digest(JSON.stringify(harness)),binary_sha256:hashes,iso_sha256:isoResult?.sha256??null,payload_plan_sha256:payloadPins.at(-1).sha256,role_mapping:{'payload/panelctl':'baseline-hostbroker','payload/hostbroker':'candidate-hostbroker','payload/qualifier.py':'new-stock-policy-fixture'},preparation:{cloud_init:'owned_payload_staging_default_user_and_ssh_key_creation_suppressed',iso_tool:'exact_hash_pinned_existing_pycdlib_helper_owned_ROOT_primary_read_only_WHEEL',guest_policy_snapshot_boundary:'after_cloud_init_staging_before_broker_execution',harness_and_fixture_bytes:'retained_in_owned_private_run_cache'},limits:{qemu_seconds:600,qemu_output_bytes:2097152,broker_seconds:20,broker_output_bytes:16384,check_host_output_bytes:8192},external_nic:false,host_shares:false,shared_dependency_inputs_read_only:true,primary_compilation_cache:'wrapper_default_explicitly_allowed',inputs_unchanged:unchanged,qemu:result?{exit_code:result.code,signal:result.signal,timed_out:result.timedout,output_limit:result.output_limit,output_bytes:result.bytes,owned_child_exited:result.owned_child_exited}:null,guest,cleanup:{owned_qemu_exited:result?.owned_child_exited===true,no_live_process_mutation:true,no_host_listener_created:true,disposable_overlay_retained:true},scope_limits:['stock_policy_remains_refused','no_account_provisioning','no_cloudlinux_or_cpanel_certification','no_reboot_or_hostile_guest_certification','no_atomic_host_policy_stability_claim']};
 write(path.join(artifacts,'report.json'),receipt);console.log(JSON.stringify({passed,native_observation:receipt.native_observation,run_id:run,report:relative(OWN,path.join(artifacts,'report.json')),report_sha256:digest(fs.readFileSync(path.join(artifacts,'report.json'))),inputs_unchanged:unchanged,owned_qemu_exited:receipt.cleanup.owned_qemu_exited}));if(!passed)process.exitCode=1;
}
async function main() {
 assert.equal(norm(OWN),norm(path.join(PRIMARY,'.worktrees/stock-preflight-cli-sol')),'wrong_owned_worktree');
 const options={};for(let i=2;i<process.argv.length;i++){const key=process.argv[i];assert(key.startsWith('--')&&!Object.hasOwn(options,key.slice(2)));const name=key.slice(2);if(['check-only','build-baseline','run'].includes(name))options[name]=true;else{assert(['candidate-binary','candidate-sha','candidate-source-sha','baseline-manifest'].includes(name)&&process.argv[i+1]&&!process.argv[i+1].startsWith('--'));options[name]=process.argv[++i];}}
 assert.equal(['check-only','build-baseline','run'].filter(x=>options[x]).length,1);
 const tools=toolCatalog(),harness=harnessCatalog();
 if(options['check-only']){assert.equal(Object.keys(options).length,1);console.log(JSON.stringify({mode:'check_only',passed:true,native_observation:false,tools:tools.length,harness:harness.length,tools_catalog_sha256:digest(JSON.stringify(tools)),harness_catalog_sha256:digest(JSON.stringify(harness)),candidate_source_catalog_sha256:digest(JSON.stringify(sourceCatalog(CANDIDATE,'candidate')))}));}
 else if(options['build-baseline']){assert.equal(Object.keys(options).length,1);await buildBaseline(tools,harness);}
 else{assert.equal(Object.keys(options).length,5);await runGuest(options,tools,harness);}
}
if(process.argv[1]&&norm(process.argv[1])===norm(fileURLToPath(import.meta.url)))main().catch(()=>{console.error('Stock-policy verifier admission failed');process.exitCode=1;});
