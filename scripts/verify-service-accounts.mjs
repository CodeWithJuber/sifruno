// Offline signed-image observation. Imports do not execute tools or guests.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';

const OWN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PRIMARY = path.resolve(OWN, '../..');
const CANDIDATE = path.join(PRIMARY, '.worktrees/service-accounts-integration');
const BASE = '392700489d49f13810923586a94eef6b48ec9cf6';
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
const NSS_LITERAL = 'passwd: files\ngroup: files\nshadow: files\nhosts: files\n';
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
 assert.equal(JSON.stringify(value), raw);
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
 for(const name of walk(PRIMARY,'.tools/go/pkg/include',()=>true))catalog.push(pin(PRIMARY,name,'primary'));
 return sorted(catalog);
}
function harnessCatalog() { return sorted(['scripts/verify-service-accounts.mjs',...walk(OWN,'lab/service-accounts-guest',()=>true)].map(name=>pin(OWN,name,'baseline'))); }
function objects(raw) {
 const values=[];let start=-1,depth=0,quoted=false,escape=false;
 for(let i=0;i<raw.length;i++){const c=raw[i];if(quoted){if(escape)escape=false;else if(c==='\\')escape=true;else if(c==='"')quoted=false;}else if(c==='"')quoted=true;else if(c==='{'){if(depth++===0)start=i;}else if(c==='}'&&--depth===0){values.push(JSON.parse(raw.slice(start,i+1)));start=-1;}else if(depth===0)assert(/\s/.test(c));}
 assert(depth===0&&!quoted&&start===-1&&values.length>0);return values;
}
async function linkedCatalog(root, namespace, env, tests=false) {
 const ps=path.join(env.SystemRoot||env.SYSTEMROOT,'System32/WindowsPowerShell/v1.0/powershell.exe');
 const result=await child(ps,['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(PRIMARY,'scripts/go.ps1'),'list','-mod=readonly',...(tests?['-test']:[]),'-deps','-json',tests?'./internal/hostaccounts':'./cmd/hostbroker'],{cwd:root,env,timeout:120000});successful(result);assert.equal(result.stderr.length,0);
 const entries=new Map();
 const roots=[[root,namespace],[path.join(PRIMARY,'.tools/go'),'go'],[path.join(PRIMARY,'.cache/go-mod'),'modules']];
 for(const pkg of objects(result.stdout.toString('utf8'))){assert(!pkg.Error&&!pkg.DepsErrors&&typeof pkg.Dir==='string');if(tests&&pkg.ImportPath==='sifruno/internal/hostaccounts.test'){assert(pkg.Name==='main');continue;}for(const key of ['GoFiles','CgoFiles','SFiles','HFiles','SysoFiles','EmbedFiles'])for(const name of pkg[key]||[]){const file=path.resolve(pkg.Dir,name),match=roots.find(([base])=>{const rel=path.relative(base,file);return rel&&!rel.startsWith('..')&&!path.isAbsolute(rel);});assert(match,'linked_source_outside_admission');const item=pin(match[0],relative(match[0],file),match[1]);entries.set(item.namespace+'/'+item.path,item);}if(pkg.Module?.GoMod){const file=pkg.Module.GoMod,match=roots.find(([base])=>{const rel=path.relative(base,file);return rel&&!rel.startsWith('..')&&!path.isAbsolute(rel);});assert(match);const item=pin(match[0],relative(match[0],file),match[1]);entries.set(item.namespace+'/'+item.path,item);}}
 return sorted([...entries.values()]);
}
function merge(...catalogs) { const items=new Map();for(const catalog of catalogs)for(const item of catalog){const id=item.namespace+'/'+item.path;if(items.has(id))assert.deepEqual(items.get(id),item);items.set(id,item);}return sorted([...items.values()]); }
async function buildBaseline(tools,harness) {
 const id=`baseline-${Date.now()}-${randomBytes(4).toString('hex')}`,work=mkdirOwned('.cache/service-accounts-build/'+id),env=environment(work),ps=path.join(env.SystemRoot||env.SYSTEMROOT,'System32/WindowsPowerShell/v1.0/powershell.exe');
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
export function validateCheck(value,statuses,candidate=false) {
 keys(value,['schema_version','scope','platform','supported','read_only','checks','restrictions']);assert.equal(value.schema_version,1);assert.equal(value.scope,'native_linux_account_host_policy');assert.equal(value.platform,'linux');assert.equal(value.supported,!statuses.includes('refused'));assert.equal(value.read_only,true);assert.deepEqual(value.restrictions,['host_policy_only','controller_paths_state_not_checked','no_stock_host_or_cpanel_certification']);
 assert(Array.isArray(value.checks)&&value.checks.length===3);const ids=['utilities','nss','useradd_defaults'],reasons=['trusted_utilities_required','files_only_nss_required',candidate?'supported_service_account_defaults_required':'mail_disabled_defaults_required'];
 value.checks.forEach((check,i)=>{keys(check,['id','status','reason']);assert.equal(check.id,ids[i]);assert.equal(check.status,statuses[i]);assert.equal(check.reason,statuses[i]==='pass'?'satisfied':reasons[i]);});return value;
}
export function validateReviewAuthority(value,binary,reviewNames) {
 assert.equal(value.passed,true);assert.equal(value.linux_challenges.compiled,true);assert.equal(value.linux_challenges.executed,false);assert.deepEqual(value.linux_challenges.test_names,reviewNames);keys(value.linux_challenges.binary,['path','bytes','sha256']);assert.deepEqual(value.linux_challenges.binary,{path:'artifacts/service-accounts-review/build/independent.test',bytes:binary.bytes,sha256:binary.sha256});return value;
}
function integer(value,minimum=0,maximum=Number.MAX_SAFE_INTEGER){assert(Number.isSafeInteger(value)&&value>=minimum&&value<=maximum);}
function calendarDay(value){assert(typeof value==='string'&&/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value));const epoch=Date.parse(value+'T00:00:00Z');assert(Number.isFinite(epoch)&&new Date(epoch).toISOString().slice(0,10)===value&&value>='1970-01-01');return value;}
function metadata(value,ids){assert(Array.isArray(value)&&value.length===ids.length);value.forEach((item,i)=>{keys(item,['id','kind','mode','bytes','sha256','uid','gid','inode','device','nlink']);assert.equal(item.id,ids[i]);assert(['file','symlink','missing'].includes(item.kind)&&/^[0-7]{4}$/.test(item.mode));integer(item.bytes,0,4*1024*1024);if(item.kind==='missing')assert(item.bytes===0&&item.sha256===null&&item.mode==='0000');else assert(HEX.test(item.sha256));for(const name of ['uid','gid'])integer(item[name]);for(const name of ['inode','device','nlink'])integer(item[name],item.kind==='missing'?0:1);});}
const POLICY_IDS=['nss','nss_authselect','useradd_defaults','login_defaults','passwd_metadata','group_metadata','groupadd','useradd','usermod','passwd_utility','chage','nologin'];
function native(value,account,expiry){
 keys(value,['uid','gid','private_group','supplementary_groups','password_locked','shell','password_aging','last_password_change','account_expiry','directories','status_sha256','aging_sha256']);assert.equal(value.uid,account.uid);assert.equal(value.gid,account.gid);assert.equal(value.private_group,true);assert.equal(value.supplementary_groups,0);assert.equal(value.password_locked,true);assert.equal(value.shell,'nologin');assert.equal(value.password_aging,'disabled');assert.equal(value.account_expiry,expiry);assert(HEX.test(value.status_sha256)&&HEX.test(value.aging_sha256));
 assert(Array.isArray(value.directories)&&value.directories.length===2);value.directories.forEach((directory,i)=>{keys(directory,['id','uid','gid','mode','inode','device']);assert.equal(directory.id,['home','public_html'][i]);assert.equal(directory.uid,account.uid);assert.equal(directory.gid,account.gid);assert.equal(directory.mode,'0750');integer(directory.inode,1);integer(directory.device,1);});
}
function mail(value){assert(Array.isArray(value)&&value.length===3);value.forEach((item,i)=>{keys(item,['id','kind','entries','own_spool_absent']);assert.equal(item.id,['configured','var_mail','var_spool_mail'][i]);assert(['missing','directory'].includes(item.kind));assert.equal(item.own_spool_absent,true);assert(Array.isArray(item.entries)&&item.entries.length<=128);let previous='';for(const entry of item.entries){keys(entry,['name_sha256','mode','uid','gid','inode','device','bytes','mtime_ns']);assert(HEX.test(entry.name_sha256)&&/^[0-7]{4}$/.test(entry.mode));assert(!previous||entry.name_sha256!==previous);previous=entry.name_sha256;for(const field of ['uid','gid','bytes'])integer(entry[field]);for(const field of ['inode','device'])integer(entry[field],1);assert(typeof entry.mtime_ns==='string'&&/^[0-9]{1,20}$/.test(entry.mtime_ns));}assert.equal(new Set(item.entries.map(x=>x.name_sha256)).size,item.entries.length);if(item.kind==='missing')assert.equal(item.entries.length,0);});}
function tests(value,names){keys(value,['exit_code','stdout_sha256','stdout_bytes','test_names','skipped','owned_child_exited']);assert.equal(value.exit_code,0);assert(HEX.test(value.stdout_sha256));integer(value.stdout_bytes,1,65536);assert.deepEqual(value.test_names,names);assert.equal(value.skipped,false);assert.equal(value.owned_child_exited,true);}
export function validateGuest(value,binding){
 keys(value,['schema_version','scope','nonce','passed','profile','binary_sha256','controller','policy_before','policy_adapted','policy_after','adaptation','original_checks','nss_adapted_checks','baseline_startup','clock_days','lifecycle','refusal_evidence','shutdowns','mail_before','mail_after','subids_before','subids_after','unrelated_identities_before','unrelated_identities_after','core_tests','review_tests','listeners_before','listeners_after','stock_mail_defaults_unchanged','inputs_unchanged','account_created','account_mutation_requests','accepted_account_mutations','stock_provisioning_qualified','owned_children_exited']);assert.equal(value.schema_version,1);assert.equal(value.scope,'NSS_ADAPTED_stock_mail_service_account_lifecycle');assert.equal(value.nonce,binding.nonce);assert.equal(value.passed,true);assert.deepEqual(value.binary_sha256,binding.hashes);
 keys(value.profile,['distribution','version','kernel','machine']);assert.equal(value.profile.distribution,'almalinux');assert.equal(value.profile.version,'9.8');assert.equal(value.profile.machine,'x86_64');assert(/^[A-Za-z0-9._+\-]{1,128}$/.test(value.profile.kernel));keys(value.controller,['uid','matching_local_passwd_records','account_created']);assert.deepEqual(value.controller,{uid:65534,matching_local_passwd_records:1,account_created:false});
 for(const phase of ['policy_before','policy_adapted','policy_after'])metadata(value[phase],POLICY_IDS);
 const changed=value.policy_adapted.filter((entry,i)=>JSON.stringify(entry)!==JSON.stringify(value.policy_before[i])).map(x=>x.id);assert.deepEqual(changed,['nss']);keys(value.adaptation,['id','sha256','mode','root_owned_regular']);assert.deepEqual(value.adaptation,{id:'nss',sha256:digest(NSS_LITERAL),mode:'0644',root_owned_regular:true});assert.equal(value.policy_adapted[0].id,'nss');assert.equal(value.policy_adapted[0].kind,'file');assert.equal(value.policy_adapted[0].mode,'0644');assert.equal(value.policy_adapted[0].bytes,Buffer.byteLength(NSS_LITERAL));assert.equal(value.policy_adapted[0].sha256,value.adaptation.sha256);assert.equal(value.policy_adapted[0].uid,0);assert.equal(value.policy_adapted[0].gid,0);assert.equal(value.policy_adapted[0].nlink,1);
 value.policy_after.forEach((entry,i)=>{if(!['passwd_metadata','group_metadata'].includes(entry.id))assert.deepEqual(entry,value.policy_adapted[i]);});
 keys(value.original_checks,['baseline','candidate']);keys(value.nss_adapted_checks,['baseline','candidate']);validateCheck(value.original_checks.baseline,['pass','refused','refused']);validateCheck(value.original_checks.candidate,['pass','refused','pass'],true);validateCheck(value.nss_adapted_checks.baseline,['pass','pass','refused']);validateCheck(value.nss_adapted_checks.candidate,['pass','pass','pass'],true);
 keys(value.baseline_startup,['exit_code','added_paths','owned_child_exited']);assert.deepEqual(value.baseline_startup,{exit_code:1,added_paths:[],owned_child_exited:true});
 keys(value.clock_days,['before_create','after_reopen']);calendarDay(value.clock_days.before_create);calendarDay(value.clock_days.after_reopen);assert(value.clock_days.before_create<=value.clock_days.after_reopen);assert(Array.isArray(value.lifecycle)&&value.lifecycle.length===6);const operations=['create','duplicate','suspend','stale','activate','reopen'],states=['active','active','suspended','suspended','active','active'],revisions=[1,1,2,2,3,3];let first;
 value.lifecycle.forEach((phase,i)=>{keys(phase,['operation','http_status','account','native']);assert.equal(phase.operation,operations[i]);assert.equal(phase.http_status,[200,409,200,409,200,200][i]);keys(phase.account,['id','uid','gid','state','revision']);assert(/^[0-9a-f]{32}$/.test(phase.account.id));integer(phase.account.uid,20000,60000);assert.equal(phase.account.gid,phase.account.uid);assert.equal(phase.account.state,states[i]);assert.equal(phase.account.revision,revisions[i]);if(first)for(const key of ['id','uid','gid'])assert.equal(phase.account[key],first.account[key]);else first=phase;native(phase.native,phase.account,states[i]==='active'?'never':'1970-01-02');const last=phase.native.last_password_change;if(last==='never')assert.equal(value.clock_days.before_create+value.clock_days.after_reopen,'1970-01-011970-01-01');else{calendarDay(last);assert(last>='1970-01-02'&&last>=value.clock_days.before_create&&last<=value.clock_days.after_reopen);}if(i){assert.deepEqual(phase.native.directories,first.native.directories);assert.equal(last,first.native.last_password_change);}});
 assert(Array.isArray(value.refusal_evidence)&&value.refusal_evidence.length===2);value.refusal_evidence.forEach((entry,i)=>{keys(entry,['operation','before_sha256','after_sha256','account_revision']);assert.equal(entry.operation,['duplicate','stale'][i]);assert(HEX.test(entry.before_sha256));assert.equal(entry.after_sha256,entry.before_sha256);assert.equal(entry.account_revision,i+1);});assert(Array.isArray(value.shutdowns)&&value.shutdowns.length===2);for(const shutdown of value.shutdowns){keys(shutdown,['sigterm_sent','exit_code','socket_removed','owned_child_exited']);assert.deepEqual(shutdown,{sigterm_sent:true,exit_code:0,socket_removed:true,owned_child_exited:true});}
 mail(value.mail_before);mail(value.mail_after);assert.deepEqual(value.mail_after,value.mail_before);metadata(value.subids_before,['subuid','subgid']);metadata(value.subids_after,['subuid','subgid']);assert.deepEqual(value.subids_after,value.subids_before);
 assert(Array.isArray(value.unrelated_identities_before)&&value.unrelated_identities_before.length===2);value.unrelated_identities_before.forEach((entry,i)=>{keys(entry,['id','count','sha256']);assert.equal(entry.id,['passwd','group'][i]);integer(entry.count,1,4096);assert(HEX.test(entry.sha256));});assert.deepEqual(value.unrelated_identities_after,value.unrelated_identities_before);
 tests(value.core_tests,binding.coreNames);tests(value.review_tests,binding.reviewNames);keys(value.listeners_before,['count','sha256']);integer(value.listeners_before.count,0,4096);assert(HEX.test(value.listeners_before.sha256));assert.deepEqual(value.listeners_after,value.listeners_before);
 for(const key of ['stock_mail_defaults_unchanged','inputs_unchanged','account_created','owned_children_exited'])assert.equal(value[key],true);assert.equal(value.account_mutation_requests,5);assert.equal(value.accepted_account_mutations,3);assert.equal(value.stock_provisioning_qualified,false);return value;
}

export function parseSerial(raw,binding) {
 assert(Buffer.byteLength(raw)<=2*1024*1024);const text=raw.replaceAll('\r\n','\n');
 // Boot bytes remain opaque. Nothing, including ANSI/CR, is stripped from
 // the exact marker lines or the raw nonce-framed JSON segment.
 const markers=text.split('\n').filter(line=>line.includes('SIFRUNO_SERVICE_'));
 const begin='SIFRUNO_SERVICE_REPORT_BEGIN_'+binding.nonce,end='SIFRUNO_SERVICE_REPORT_END_'+binding.nonce,exit='SIFRUNO_SERVICE_FIXTURE_EXIT_'+binding.nonce+'_0';assert.deepEqual(markers,[begin,end,exit]);
 const segment=text.slice(text.indexOf(begin+'\n')+begin.length+1,text.indexOf('\n'+end));assert(segment.length>0&&!segment.includes('\n')&&!segment.includes('\r')&&!segment.includes('\x1b'));
 return validateGuest(canonicalJSON(segment),binding);
}
async function runGuest(options,tools,harness) {
 for(const name of ['candidate-sha','candidate-source-sha','candidate-manifest-sha','core-test-sha','review-test-sha','review-manifest-sha'])assert(HEX.test(options[name]),'candidate_freeze_required');assert(/^[0-9a-f]{40}$/.test(options['candidate-commit']));
 const reviewNames=options['review-test-names'].split(',');assert(reviewNames.length>=1&&reviewNames.length<=16&&reviewNames.every(x=>/^[A-Za-z][A-Za-z0-9_]{1,127}$/.test(x)));assert.deepEqual(reviewNames,[...new Set(reviewNames)].sort());
 const coreNames=options['core-test-names'].split(',');assert(coreNames.length>=1&&coreNames.length<=16&&coreNames.every(x=>/^[A-Za-z][A-Za-z0-9_]{1,127}$/.test(x)));assert.deepEqual(coreNames,[...new Set(coreNames)].sort());
 const candidateFile=admitted(CANDIDATE,options['candidate-binary']);assert.equal(relative(CANDIDATE,candidateFile),'.cache/service-accounts/hostbroker-linux','candidate_not_owned_build');
 const candidatePin=pin(CANDIDATE,relative(CANDIDATE,candidateFile),'candidate');assert.equal(candidatePin.sha256,options['candidate-sha']);assert.equal(fs.readFileSync(candidateFile).subarray(0,4).toString('hex'),'7f454c46');
 const coreFile=admitted(CANDIDATE,options['core-test-binary']);assert(/^\.cache\/service-accounts\/[A-Za-z0-9_-]+\.test$/.test(relative(CANDIDATE,coreFile)));const corePin=pin(CANDIDATE,relative(CANDIDATE,coreFile),'candidate');assert.equal(corePin.sha256,options['core-test-sha']);
 const reviewPin=pin(CANDIDATE,'.cache/service-accounts/independent.test','candidate');assert.equal(reviewPin.sha256,options['review-test-sha']);const reviewManifest=pin(CANDIDATE,'.cache/service-accounts/independent-authority.json','candidate');assert.equal(reviewManifest.sha256,options['review-manifest-sha']);for(const file of [coreFile,path.join(CANDIDATE,reviewPin.path)])assert.equal(fs.readFileSync(file).subarray(0,4).toString('hex'),'7f454c46');
 validateReviewAuthority(JSON.parse(fs.readFileSync(path.join(CANDIDATE,reviewManifest.path),'utf8')),reviewPin,reviewNames);
 const manifestFile=admitted(OWN,options['baseline-manifest']);assert(relative(OWN,manifestFile).startsWith('.cache/service-accounts-build/'));const manifest=JSON.parse(fs.readFileSync(manifestFile,'utf8'));
 keys(manifest,['schema_version','scope','source_base','source_catalog','source_catalog_sha256','tools_catalog_sha256','binary','commands','go_environment','exits','inputs_unchanged']);assert(manifest.schema_version===1&&manifest.scope==='offline_unchanged_baseline_linux_build'&&manifest.source_base===BASE&&manifest.inputs_unchanged===true);assert.equal(digest(JSON.stringify(manifest.source_catalog)),manifest.source_catalog_sha256);assert.equal(digest(JSON.stringify(tools)),manifest.tools_catalog_sha256);assert(stable(manifest.source_catalog)&&stable([manifest.binary]));
 const baseline=admitted(OWN,path.join(OWN,manifest.binary.path));assert.equal(manifest.binary.namespace,'baseline');
 const nonce=randomBytes(16).toString('hex'),run='service-accounts-'+new Date().toISOString().replace(/[-:.]/g,'')+'-'+nonce.slice(0,8),rel='.cache/alma9-qualification/'+run,work=mkdirOwned(rel),artifacts=mkdirOwned('artifacts/service-accounts/'+run),env=environment(work);
 const candidateSources=sourceCatalog(CANDIDATE,'candidate');assert.equal(digest(JSON.stringify(candidateSources)),options['candidate-source-sha'],'candidate_source_freeze_mismatch');
 const candidateManifest=pin(CANDIDATE,'.cache/service-accounts/go-source-inputs.json','candidate');assert.equal(candidateManifest.sha256,options['candidate-manifest-sha']);
 const frozenFiles=JSON.parse(fs.readFileSync(path.join(CANDIDATE,candidateManifest.path),'utf8'));assert(Array.isArray(frozenFiles)&&frozenFiles.length>=candidateSources.length&&frozenFiles.length<=4096);
 const fullCandidateFreeze=frozenFiles.map(file=>{keys(file,['path','bytes','sha256']);assert((file.path.endsWith('.go')||['go.mod','go.sum'].includes(file.path))&&HEX.test(file.sha256)&&Number.isSafeInteger(file.bytes)&&file.bytes>=0);const item=pin(CANDIDATE,file.path,'candidate');assert.equal(item.bytes,file.bytes);assert.equal(item.sha256,file.sha256);return item;});sorted(fullCandidateFreeze);
 const inputs=merge(tools,harness,manifest.source_catalog,candidateSources,fullCandidateFreeze,await linkedCatalog(CANDIDATE,'candidate',env),await linkedCatalog(CANDIDATE,'candidate',env,true),[candidatePin,corePin,reviewPin,reviewManifest,candidateManifest,pin(OWN,relative(OWN,manifestFile),'baseline'),manifest.binary]);
 write(path.join(work,'host-harness-source.mjs'),fs.readFileSync(path.join(OWN,'scripts/verify-service-accounts.mjs')));
 const hashes={baseline:manifest.binary.sha256,candidate:candidatePin.sha256,fixture:harness.find(x=>x.path==='lab/service-accounts-guest/fixture.py').sha256,core_test:corePin.sha256,review_test:reviewPin.sha256};
 const binding={nonce,hashes,reviewNames,coreNames};const entries=[];
 const add=(name,destination)=>{const item=pin(OWN,rel+'/'+name,'baseline');entries.push({source:rel+'/'+name,destination,bytes:item.bytes,sha256:item.sha256});};
 for(const [name,source,destination] of [['baseline-hostbroker',baseline,'payload/panelctl'],['candidate-hostbroker',candidateFile,'payload/hostbroker'],['fixture.py',path.join(OWN,'lab/service-accounts-guest/fixture.py'),'payload/qualifier.py'],['core.test',coreFile,'payload/core.test'],['authority.test',path.join(CANDIDATE,reviewPin.path),'payload/authority.test']]){write(path.join(work,name),fs.readFileSync(source));add(name,destination);}
 const script=`#!/bin/sh\nset -eu\nexec >/dev/ttyS0 2>&1\ntrap '/sbin/poweroff' EXIT\nmkdir -m 0700 /opt/sifruno-service-accounts\nmkdir -p /mnt/sifruno-paths-payload\nmount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-paths-payload\ncp /mnt/sifruno-paths-payload/payload/panelctl /opt/sifruno-service-accounts/baseline-hostbroker\ncp /mnt/sifruno-paths-payload/payload/hostbroker /opt/sifruno-service-accounts/candidate-hostbroker\ncp /mnt/sifruno-paths-payload/payload/qualifier.py /opt/sifruno-service-accounts/fixture.py\ncp /mnt/sifruno-paths-payload/payload/core.test /opt/sifruno-service-accounts/core.test\ncp /mnt/sifruno-paths-payload/payload/authority.test /opt/sifruno-service-accounts/authority.test\nchmod 0555 /opt/sifruno-service-accounts/*\nprintf '${nonce}\\n' >/run/sifruno-service-accounts-admission\nchmod 0600 /run/sifruno-service-accounts-admission\nset +e\necho SIFRUNO_SERVICE_REPORT_BEGIN_${nonce}\nenv -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -B /opt/sifruno-service-accounts/fixture.py --disposable-service-accounts --nonce ${nonce} --baseline-sha ${hashes.baseline} --candidate-sha ${hashes.candidate} --fixture-sha ${hashes.fixture} --core-test-sha ${hashes.core_test} --review-test-sha ${hashes.review_test} --core-test-names ${coreNames.join(',')} --review-test-names ${reviewNames.join(',')}\nstatus=$?\necho SIFRUNO_SERVICE_REPORT_END_${nonce}\necho SIFRUNO_SERVICE_FIXTURE_EXIT_${nonce}_$status\nexit 0\n`;
 write(path.join(work,'meta-data'),`instance-id: ${run}\nlocal-hostname: sifruno-service-accounts\n`);write(path.join(work,'network-config'),'version: 2\nethernets: {}\n');
 // Suppress default cloud-user creation and SSH key generation/import. No
 // password/root-account changes are requested by cloud-init. The new fixture
 // explicitly adapts only the disposable overlay NSS policy later.
 write(path.join(work,'user-data'),'#cloud-config\nusers: []\nssh_genkeytypes: []\nssh_deletekeys: false\nwrite_files:\n  - path: /root/sifruno-service-accounts-proof.sh\n    owner: root:root\n    permissions: "0700"\n    content: |\n'+script.split('\n').map(line=>'      '+line).join('\n')+'\nruncmd:\n  - ["/bin/sh", "/root/sifruno-service-accounts-proof.sh"]\n');
 for(const name of ['user-data','meta-data','network-config'])add(name,name);
 write(path.join(work,'payload-plan.json'),{schema_version:1,entries});const payloadPins=entries.map(x=>pin(OWN,x.source,'baseline'));payloadPins.push(pin(OWN,rel+'/payload-plan.json','baseline'));
 const adapter=`import importlib.util, pathlib, sys\np=pathlib.Path(sys.argv[1]); s=importlib.util.spec_from_file_location('pinned_iso',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\nm.ROOT=pathlib.Path(sys.argv[2]); m.WHEEL=pathlib.Path(sys.argv[3]); sys.argv=[str(p),'--plan',sys.argv[4]]; m.main()\n`;
 let guest=null,result=null,failure=null,isoResult=null,unchanged=false,phase='iso_generation';
 const started=new Date().toISOString();
 try {
  const made=await child(PYTHON,['-I','-B','-c',adapter,path.join(PRIMARY,'scripts/alma-account-iso.py'),OWN,path.join(PRIMARY,'.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'),rel+'/payload-plan.json'],{env,timeout:90000,maximum:65536});successful(made);assert.equal(made.stderr.length,0);isoResult=JSON.parse(made.stdout.toString());keys(isoResult,['entries','bytes','sha256']);assert.equal(isoResult.entries,8);assert(HEX.test(isoResult.sha256));assert.equal(pin(OWN,rel+'/payload.iso','baseline',256*1024*1024).sha256,isoResult.sha256);
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
 const receipt={schema_version:1,scope:'NSS_ADAPTED_stock_mail_service_account_lifecycle',run_id:run,started_at:started,completed_at:new Date().toISOString(),passed,native_observation:guest?.passed===true,failure,source_base:BASE,candidate_build_commit:options['candidate-commit'],candidate_build_authority:'root_supplied_frozen_binary_and_source_manifest',candidate_build_manifest_sha256:candidateManifest.sha256,independent_builder_receipt_sha256:reviewManifest.sha256,independent_source_authority:'root_supplied_pinned_independent_builder_receipt_not_recompiled_here',independent_expected_test_names:reviewNames,compiler_generated_test_main:'generated_by_pinned_Go_tools_from_pinned_test_sources_not_separately_catalogued',assembler_headers:'all_five_installed_pkg_include_files_pinned_before_baseline_build_and_native_run',entire_go_distribution_verified:false,image_sha256:IMAGE_SHA,image_signature_verified:true,source_catalog:inputs,source_catalog_sha256:digest(JSON.stringify(inputs)),candidate_source_catalog_sha256:options['candidate-source-sha'],harness_catalog_sha256:digest(JSON.stringify(harness)),binary_sha256:hashes,iso_sha256:isoResult?.sha256??null,payload_plan_sha256:payloadPins.at(-1).sha256,role_mapping:{'payload/panelctl':'baseline-hostbroker','payload/hostbroker':'candidate-hostbroker','payload/qualifier.py':'new-NSS-only-service-account-fixture','payload/core.test':'reviewed-root-core-tests','payload/authority.test':'independent-review-tests'},preparation:{cloud_init:'owned_payload_staging_default_user_and_ssh_key_creation_suppressed',iso_tool:'exact_hash_pinned_existing_pycdlib_helper_owned_ROOT_primary_read_only_WHEEL',guest_policy_snapshot_boundary:'original_then_NSS_only_adaptation_stock_mail_defaults_unchanged',qualification:'NSS_ADAPTED_service_identity_only_never_full_stock_provisioning',harness_and_fixture_bytes:'retained_in_owned_private_run_cache'},limits:{qemu_seconds:600,qemu_output_bytes:2097152,broker_seconds:60,broker_output_bytes:16384,check_host_output_bytes:8192,test_output_bytes:65536,test_seconds:20},external_nic:false,host_shares:false,shared_dependency_inputs_read_only:true,primary_compilation_cache:'wrapper_default_explicitly_allowed',inputs_unchanged:unchanged,qemu:result?{exit_code:result.code,signal:result.signal,timed_out:result.timedout,output_limit:result.output_limit,output_bytes:result.bytes,owned_child_exited:result.owned_child_exited}:null,guest,cleanup:{owned_qemu_exited:result?.owned_child_exited===true,no_live_process_mutation:true,no_host_listener_created:true,disposable_overlay_retained:true},scope_limits:['NSS_ADAPTED_service_account_lifecycle_only','unmodified_stock_policy_refused','one_owned_disposable_service_account_no_delete_or_migration','no_cloudlinux_or_cpanel_certification','no_reboot_or_hostile_guest_certification','no_atomic_host_policy_stability_claim']};
 write(path.join(artifacts,'report.json'),receipt);console.log(JSON.stringify({passed,native_observation:receipt.native_observation,run_id:run,report:relative(OWN,path.join(artifacts,'report.json')),report_sha256:digest(fs.readFileSync(path.join(artifacts,'report.json'))),inputs_unchanged:unchanged,owned_qemu_exited:receipt.cleanup.owned_qemu_exited}));if(!passed)process.exitCode=1;
}
async function main() {
 assert.equal(norm(OWN),norm(path.join(PRIMARY,'.worktrees/service-accounts-guest-sol')),'wrong_owned_worktree');
 const options={};for(let i=2;i<process.argv.length;i++){const key=process.argv[i];assert(key.startsWith('--')&&!Object.hasOwn(options,key.slice(2)));const name=key.slice(2);if(['check-only','build-baseline','run'].includes(name))options[name]=true;else{assert(['candidate-binary','candidate-sha','candidate-source-sha','baseline-manifest','candidate-manifest-sha','candidate-commit','core-test-binary','core-test-sha','core-test-names','review-test-sha','review-manifest-sha','review-test-names'].includes(name)&&process.argv[i+1]&&!process.argv[i+1].startsWith('--'));options[name]=process.argv[++i];}}
 assert.equal(['check-only','build-baseline','run'].filter(x=>options[x]).length,1);
 const tools=toolCatalog(),harness=harnessCatalog();
 if(options['check-only']){assert.equal(Object.keys(options).length,1);console.log(JSON.stringify({mode:'check_only',passed:true,native_observation:false,tools:tools.length,harness:harness.length,tools_catalog_sha256:digest(JSON.stringify(tools)),harness_catalog_sha256:digest(JSON.stringify(harness)),candidate_source_catalog_sha256:digest(JSON.stringify(sourceCatalog(CANDIDATE,'candidate')))}));}
 else if(options['build-baseline']){assert.equal(Object.keys(options).length,1);await buildBaseline(tools,harness);}
 else{assert.equal(Object.keys(options).length,13);await runGuest(options,tools,harness);}
}
if(process.argv[1]&&norm(process.argv[1])===norm(fileURLToPath(import.meta.url)))main().catch(()=>{console.error('NSS_ADAPTED service-account verifier admission failed');process.exitCode=1;});
