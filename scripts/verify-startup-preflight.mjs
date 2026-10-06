// Offline signed-image observation. Imports do not execute tools or guests.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';

const OWN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PRIMARY = path.resolve(OWN, '../..');
const CANDIDATE = path.join(PRIMARY, '.worktrees/startup-preflight-integration');
const BASE = '67d527c76b8880f41b5481effc34003307de9df8';
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
export const LIMITS = {qemu_seconds:600,qemu_output_bytes:2097152,broker_seconds:60,broker_output_bytes:16384,peer_request_seconds:10,peer_socket_seconds:5,check_host_seconds:20,check_host_output_bytes:8192,startup_report_seconds:10,startup_report_output_bytes:8192,test_output_bytes:65536,test_seconds:20};
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
function harnessCatalog() { return sorted(['scripts/verify-startup-preflight.mjs','scripts/verify-service-accounts.mjs','lab/service-accounts-guest/fixture.py',...walk(OWN,'lab/startup-preflight-guest',()=>true)].map(name=>pin(OWN,name,'baseline'))); }
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
 const id=`baseline-${Date.now()}-${randomBytes(4).toString('hex')}`,work=mkdirOwned('.cache/startup-preflight-build/'+id),env=environment(work),ps=path.join(env.SystemRoot||env.SYSTEMROOT,'System32/WindowsPowerShell/v1.0/powershell.exe');
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
 assert.equal(value.passed,true);assert.equal(value.linux_challenges.compiled,true);assert.equal(value.linux_challenges.executed,false);assert.deepEqual(value.linux_challenges.test_names,reviewNames);keys(value.linux_challenges.binary,['path','bytes','sha256']);assert.deepEqual(value.linux_challenges.binary,{path:'artifacts/startup-preflight-review/build/independent.test',bytes:binary.bytes,sha256:binary.sha256});return value;
}
function integer(value,minimum=0,maximum=Number.MAX_SAFE_INTEGER){assert(Number.isSafeInteger(value)&&value>=minimum&&value<=maximum);}
function metadata(value,ids){assert(Array.isArray(value)&&value.length===ids.length);value.forEach((item,i)=>{keys(item,['id','kind','mode','bytes','sha256','uid','gid','inode','device','nlink']);assert.equal(item.id,ids[i]);assert(['file','symlink','missing'].includes(item.kind)&&/^[0-7]{4}$/.test(item.mode));integer(item.bytes,0,4*1024*1024);if(item.kind==='missing')assert(item.bytes===0&&item.sha256===null&&item.mode==='0000');else assert(HEX.test(item.sha256));for(const name of ['uid','gid'])integer(item[name]);for(const name of ['inode','device','nlink'])integer(item[name],item.kind==='missing'?0:1);});}
const POLICY_IDS=['nss','nss_authselect','useradd_defaults','login_defaults','passwd_metadata','group_metadata','groupadd','useradd','usermod','passwd_utility','chage','nologin'];
function mail(value){assert(Array.isArray(value)&&value.length===3);value.forEach((item,i)=>{keys(item,['id','kind','entries','own_spool_absent']);assert.equal(item.id,['configured','var_mail','var_spool_mail'][i]);assert(['missing','directory'].includes(item.kind));assert.equal(item.own_spool_absent,true);assert(Array.isArray(item.entries)&&item.entries.length<=128);let previous='';for(const entry of item.entries){keys(entry,['name_sha256','mode','uid','gid','inode','device','bytes','mtime_ns']);assert(HEX.test(entry.name_sha256)&&/^[0-7]{4}$/.test(entry.mode));assert(!previous||entry.name_sha256!==previous);previous=entry.name_sha256;for(const field of ['uid','gid','bytes'])integer(entry[field]);for(const field of ['inode','device'])integer(entry[field],1);assert(typeof entry.mtime_ns==='string'&&/^[0-9]{1,20}$/.test(entry.mtime_ns));}assert.equal(new Set(item.entries.map(x=>x.name_sha256)).size,item.entries.length);if(item.kind==='missing')assert.equal(item.entries.length,0);});}
function tests(value,names){keys(value,['exit_code','stdout_sha256','stdout_bytes','test_names','skipped','owned_child_exited']);assert.equal(value.exit_code,0);assert(HEX.test(value.stdout_sha256));integer(value.stdout_bytes,1,65536);assert.deepEqual(value.test_names,names);assert.equal(value.skipped,false);assert.equal(value.owned_child_exited,true);}
export function validateISOObservation(value,entries) {
 keys(value,['volume_label','directories','entries']);assert.equal(value.volume_label,'CIDATA');assert.deepEqual(value.directories,['/payload']);assert.equal(entries.length,8);assert.deepEqual(entries.map(x=>x.destination).sort(),['meta-data','network-config','payload/authority.test','payload/core.test','payload/hostbroker','payload/panelctl','payload/qualifier.py','user-data']);
 assert(Array.isArray(value.entries)&&value.entries.length===8);value.entries.forEach((entry,i)=>{keys(entry,['destination','bytes','sha256','mode','links']);assert.deepEqual(entry,{destination:entries[i].destination,bytes:entries[i].bytes,sha256:entries[i].sha256,mode:'100444',links:1});});return value;
}
export const STARTUP_IDS=['configuration','privilege','controller','utilities','nss_file','nss_policy','useradd_defaults','paths','fresh_state'];
export const STARTUP_REASONS=['dedicated_paths_and_nonroot_uid_required','root_required','unique_local_controller_uid_required','trusted_utilities_required','trusted_bounded_regular_nss_file_required','files_only_nss_required','supported_service_account_defaults_required','dedicated_path_and_socket_admission_required','persisted_state_recovery_not_checked'];
export const STARTUP_RESTRICTIONS=['fresh_setup_admission_only','host_snapshot_not_startup_grant','persisted_state_recovery_not_checked','no_stock_host_or_cpanel_certification'];
export const NEGATIVE_CASES=['missing_uid','root_uid','state_file','homes_file','homes_symlink','homes_dangling_symlink','ancestor_untrusted_nontraversable','setgid_parent','socket_file','socket_bound','socket_dangling_symlink','nonempty_state','unknown_private_argument'];
export function validateStartup(value,refusal=null,persisted=false) {
 keys(value,['schema_version','scope','platform','supported','read_only','checks','restrictions']);
 assert.equal(value.schema_version,1);assert.equal(value.scope,'native_linux_broker_startup_admission');assert.equal(value.platform,'linux');assert.equal(value.read_only,true);assert.equal(value.supported,refusal===null);assert.deepEqual(value.restrictions,STARTUP_RESTRICTIONS);
 assert(Array.isArray(value.checks)&&value.checks.length===9);
 value.checks.forEach((check,i)=>{keys(check,['id','status','reason']);assert.equal(check.id,STARTUP_IDS[i]);let status='pass',reason='satisfied';if(refusal!==null&&i===refusal){status=persisted?'not_checked':'refused';reason=STARTUP_REASONS[i];}else if(refusal!==null&&i>refusal){status='not_checked';reason='prerequisite_refused';}assert.equal(check.status,status);assert.equal(check.reason,reason);});return value;
}
function observation(value,refusal=null,persisted=false,grammar=false) {
 keys(value,['exit_code','report','before_sha256','after_sha256','added_paths','missing_paths','owned_child_exited']);
 assert.equal(value.exit_code,grammar?2:refusal===null?0:1);assert(HEX.test(value.before_sha256));assert.equal(value.after_sha256,value.before_sha256);assert.deepEqual(value.added_paths,[]);assert.equal(value.owned_child_exited,true);
 assert(Array.isArray(value.missing_paths));const ids=['state','homes','socket_parent','socket'];assert.deepEqual(value.missing_paths,ids.filter(id=>value.missing_paths.includes(id)));
 if(grammar)assert.equal(value.report,null);else validateStartup(value.report,refusal,persisted);
}
export function validateNSSProfiles(value) {
 assert(Array.isArray(value)&&value.length===3);const allowed=['files','sss','systemd','compat','nis','nisplus','db','ldap','winbind','unknown'];
 value.forEach((entry,i)=>{keys(entry,['id','row_count','providers','actions_present','unknown_provider']);assert.equal(entry.id,['passwd','group','shadow'][i]);integer(entry.row_count,0,64);assert(Array.isArray(entry.providers)&&entry.providers.length<=64&&entry.providers.every(token=>typeof token==='string'&&allowed.includes(token)));assert(typeof entry.actions_present==='boolean');assert.equal(entry.unknown_provider,entry.providers.includes('unknown'));if(entry.row_count===0)assert(entry.providers.length===0&&!entry.actions_present);});return value;
}
export function validateGuest(value,binding) {
 keys(value,['schema_version','scope','nonce','passed','profile','binary_sha256','controller','original_nss_profiles','policy_before','policy_adapted','policy_after','original_check','adapted_check','negative_cases','host_policy_check','broker_smoke','mail_before','mail_after','subids_before','subids_after','listeners_before','listeners_after','core_tests','review_tests','inputs_unchanged','account_mutation_requests','accepted_account_mutations','stock_provisioning_qualified','owned_children_exited']);
 assert.equal(value.schema_version,1);assert.equal(value.scope,'read_only_stock_then_NSS_only_adapted_fresh_startup_admission');assert.equal(value.nonce,binding.nonce);assert.equal(value.passed,true);assert.deepEqual(value.binary_sha256,binding.hashes);
 keys(value.profile,['distribution','version','kernel','machine']);assert.equal(value.profile.distribution,'almalinux');assert.equal(value.profile.version,'9.8');assert.equal(value.profile.machine,'x86_64');assert(typeof value.profile.kernel==='string'&&/^[A-Za-z0-9._+\-]{1,128}$/.test(value.profile.kernel));keys(value.controller,['uid','matching_local_passwd_records','account_created']);assert.deepEqual(value.controller,{uid:65534,matching_local_passwd_records:1,account_created:false});
 validateNSSProfiles(value.original_nss_profiles);
 for(const phase of ['policy_before','policy_adapted','policy_after'])metadata(value[phase],POLICY_IDS);
 const stock=value.policy_before[0];assert.equal(stock.kind,'file');assert.equal(stock.mode,'0644');assert.equal(stock.bytes,2124);assert.equal(stock.sha256,'c1cc473688f64942669ee7eb72b262103db75498d9236356bdf25289828f5b46');assert.equal(stock.uid,0);assert.equal(stock.gid,0);assert.equal(stock.nlink,1);assert.equal(value.policy_before[1].kind,'missing');
 assert.deepEqual(value.policy_adapted.filter((entry,i)=>JSON.stringify(entry)!==JSON.stringify(value.policy_before[i])).map(x=>x.id),['nss']);
 const adapted=value.policy_adapted[0];assert.equal(adapted.kind,'file');assert.equal(adapted.mode,'0644');assert.equal(adapted.bytes,54);assert.equal(adapted.sha256,digest(NSS_LITERAL));assert.equal(adapted.uid,0);assert.equal(adapted.gid,0);assert.equal(adapted.nlink,1);assert.deepEqual(value.policy_after,value.policy_adapted);
 observation(value.original_check,5);observation(value.adapted_check);for(const key of ['original_check','adapted_check'])assert.deepEqual(value[key].missing_paths,['state','homes','socket_parent','socket']);
 assert(Array.isArray(value.negative_cases)&&value.negative_cases.length===NEGATIVE_CASES.length);
 value.negative_cases.forEach((entry,i)=>{keys(entry,['case','fixture_setup_owned','ancestor','observation']);assert.equal(entry.case,NEGATIVE_CASES[i]);assert.equal(entry.fixture_setup_owned,true);if(entry.case==='ancestor_untrusted_nontraversable')assert.deepEqual(entry.ancestor,{uid:65534,gid:65534,mode:'0000'});else assert.equal(entry.ancestor,null);const grammar=['root_uid','unknown_private_argument'].includes(entry.case),persisted=entry.case==='nonempty_state',refusal=entry.case==='missing_uid'?2:persisted?8:7;observation(entry.observation,refusal,persisted,grammar);const missing=entry.case==='state_file'||persisted?['homes','socket_parent','socket']:entry.case.startsWith('homes_')?['state','socket_parent','socket']:entry.case.startsWith('socket_')?['state','homes']:['state','homes','socket_parent','socket'];assert.deepEqual(entry.observation.missing_paths,missing);});
 validateCheck(value.host_policy_check,['pass','pass','pass'],true);
 const smoke=value.broker_smoke;keys(smoke,['fixture_setup_owned','inventory','shutdowns','persisted_admission','account_mutation_requests']);assert.equal(smoke.fixture_setup_owned,true);assert.equal(smoke.account_mutation_requests,0);assert(Array.isArray(smoke.inventory)&&smoke.inventory.length===2);smoke.inventory.forEach(entry=>{keys(entry,['peer_uid','http_status','account_count','body_sha256']);assert.equal(entry.peer_uid,65534);assert.equal(entry.http_status,200);assert.equal(entry.account_count,0);assert(HEX.test(entry.body_sha256));});assert.deepEqual(smoke.inventory[0],smoke.inventory[1]);assert(Array.isArray(smoke.shutdowns)&&smoke.shutdowns.length===2);for(const shutdown of smoke.shutdowns){keys(shutdown,['sigterm_sent','exit_code','socket_removed','owned_child_exited']);assert.deepEqual(shutdown,{sigterm_sent:true,exit_code:0,socket_removed:true,owned_child_exited:true});}observation(smoke.persisted_admission,8,true);assert.deepEqual(smoke.persisted_admission.missing_paths,['socket']);
 mail(value.mail_before);mail(value.mail_after);assert.deepEqual(value.mail_after,value.mail_before);metadata(value.subids_before,['subuid','subgid']);metadata(value.subids_after,['subuid','subgid']);assert.deepEqual(value.subids_after,value.subids_before);keys(value.listeners_before,['count','sha256']);integer(value.listeners_before.count,0,4096);assert(HEX.test(value.listeners_before.sha256));assert.deepEqual(value.listeners_after,value.listeners_before);
 tests(value.core_tests,binding.coreNames);tests(value.review_tests,binding.reviewNames);for(const key of ['inputs_unchanged','owned_children_exited'])assert.equal(value[key],true);assert.equal(value.account_mutation_requests,0);assert.equal(value.accepted_account_mutations,0);assert.equal(value.stock_provisioning_qualified,false);return value;
}
export function parseSerial(raw,binding) {
 assert(Buffer.byteLength(raw)<=2*1024*1024);const text=raw.replaceAll('\r\n','\n');
 // Boot bytes remain opaque. Nothing, including ANSI/CR, is stripped from
 // the exact marker lines or the raw nonce-framed JSON segment.
 const markers=text.split('\n').filter(line=>line.includes('SIFRUNO_STARTUP_'));
 const begin='SIFRUNO_STARTUP_REPORT_BEGIN_'+binding.nonce,end='SIFRUNO_STARTUP_REPORT_END_'+binding.nonce,exit='SIFRUNO_STARTUP_FIXTURE_EXIT_'+binding.nonce+'_0';assert.deepEqual(markers,[begin,end,exit]);
 const segment=text.slice(text.indexOf(begin+'\n')+begin.length+1,text.indexOf('\n'+end));assert(segment.length>0&&!segment.includes('\n')&&!segment.includes('\r')&&!segment.includes('\x1b'));
 return validateGuest(canonicalJSON(segment),binding);
}
async function runGuest(options,tools,harness) {
 for(const name of ['candidate-sha','candidate-source-sha','candidate-manifest-sha','core-test-sha','review-test-sha','review-manifest-sha'])assert(HEX.test(options[name]),'candidate_freeze_required');assert(/^[0-9a-f]{40}$/.test(options['candidate-commit']));
 const reviewNames=options['review-test-names'].split(',');assert(reviewNames.length>=1&&reviewNames.length<=16&&reviewNames.every(x=>/^[A-Za-z][A-Za-z0-9_]{1,127}$/.test(x)));assert.deepEqual(reviewNames,[...new Set(reviewNames)].sort());
 const coreNames=options['core-test-names'].split(',');assert(coreNames.length>=1&&coreNames.length<=16&&coreNames.every(x=>/^[A-Za-z][A-Za-z0-9_]{1,127}$/.test(x)));assert.deepEqual(coreNames,[...new Set(coreNames)].sort());
 const candidateFile=admitted(CANDIDATE,options['candidate-binary']);assert.equal(relative(CANDIDATE,candidateFile),'.cache/startup-preflight/hostbroker-linux','candidate_not_owned_build');
 const candidatePin=pin(CANDIDATE,relative(CANDIDATE,candidateFile),'candidate');assert.equal(candidatePin.sha256,options['candidate-sha']);assert.equal(fs.readFileSync(candidateFile).subarray(0,4).toString('hex'),'7f454c46');
 assert.deepEqual(coreNames,['TestStartupNativeFreshStateObservation','TestStartupNativeGuardComposition']);assert.deepEqual(reviewNames,['TestIndependentStartupCancellation','TestIndependentStartupFreshAuthority','TestIndependentStartupProtocol']);
 const coreFile=admitted(CANDIDATE,options['core-test-binary']);assert.equal(relative(CANDIDATE,coreFile),'.cache/startup-preflight/core.test');const corePin=pin(CANDIDATE,relative(CANDIDATE,coreFile),'candidate');assert.equal(corePin.sha256,options['core-test-sha']);
 const reviewPin=pin(CANDIDATE,'.cache/startup-preflight/independent.test','candidate');assert.equal(reviewPin.sha256,options['review-test-sha']);const reviewManifest=pin(CANDIDATE,'.cache/startup-preflight/independent-authority.json','candidate');assert.equal(reviewManifest.sha256,options['review-manifest-sha']);for(const file of [coreFile,path.join(CANDIDATE,reviewPin.path)])assert.equal(fs.readFileSync(file).subarray(0,4).toString('hex'),'7f454c46');
 validateReviewAuthority(JSON.parse(fs.readFileSync(path.join(CANDIDATE,reviewManifest.path),'utf8')),reviewPin,reviewNames);
 const manifestFile=admitted(OWN,options['baseline-manifest']);assert(relative(OWN,manifestFile).startsWith('.cache/startup-preflight-build/'));const manifest=JSON.parse(fs.readFileSync(manifestFile,'utf8'));
 keys(manifest,['schema_version','scope','source_base','source_catalog','source_catalog_sha256','tools_catalog_sha256','binary','commands','go_environment','exits','inputs_unchanged']);assert(manifest.schema_version===1&&manifest.scope==='offline_unchanged_baseline_linux_build'&&manifest.source_base===BASE&&manifest.inputs_unchanged===true);assert.equal(digest(JSON.stringify(manifest.source_catalog)),manifest.source_catalog_sha256);assert.equal(digest(JSON.stringify(tools)),manifest.tools_catalog_sha256);assert(stable(manifest.source_catalog)&&stable([manifest.binary]));
 const baseline=admitted(OWN,path.join(OWN,manifest.binary.path));assert.equal(manifest.binary.namespace,'baseline');
 const nonce=randomBytes(16).toString('hex'),run='startup-preflight-'+new Date().toISOString().replace(/[-:.]/g,'')+'-'+nonce.slice(0,8),rel='.cache/alma9-qualification/'+run,work=mkdirOwned(rel),artifacts=mkdirOwned('artifacts/startup-preflight/'+run),env=environment(work);
 const candidateSources=sourceCatalog(CANDIDATE,'candidate');assert.equal(digest(JSON.stringify(candidateSources)),options['candidate-source-sha'],'candidate_source_freeze_mismatch');
 const candidateManifest=pin(CANDIDATE,'.cache/startup-preflight/go-source-inputs.json','candidate');assert.equal(candidateManifest.sha256,options['candidate-manifest-sha']);
 const frozenFiles=JSON.parse(fs.readFileSync(path.join(CANDIDATE,candidateManifest.path),'utf8'));assert(Array.isArray(frozenFiles)&&frozenFiles.length>=candidateSources.length&&frozenFiles.length<=4096);
 const fullCandidateFreeze=frozenFiles.map(file=>{keys(file,['path','bytes','sha256']);assert((file.path.endsWith('.go')||['go.mod','go.sum'].includes(file.path))&&HEX.test(file.sha256)&&Number.isSafeInteger(file.bytes)&&file.bytes>=0);const item=pin(CANDIDATE,file.path,'candidate');assert.equal(item.bytes,file.bytes);assert.equal(item.sha256,file.sha256);return item;});sorted(fullCandidateFreeze);
 const inputs=merge(tools,harness,manifest.source_catalog,candidateSources,fullCandidateFreeze,await linkedCatalog(CANDIDATE,'candidate',env),await linkedCatalog(CANDIDATE,'candidate',env,true),[candidatePin,corePin,reviewPin,reviewManifest,candidateManifest,pin(OWN,relative(OWN,manifestFile),'baseline'),manifest.binary]);
 write(path.join(work,'host-harness-source.mjs'),fs.readFileSync(path.join(OWN,'scripts/verify-startup-preflight.mjs')));
 const hashes={baseline:manifest.binary.sha256,candidate:candidatePin.sha256,fixture:harness.find(x=>x.path==='lab/startup-preflight-guest/fixture.py').sha256,core_test:corePin.sha256,review_test:reviewPin.sha256};
 const binding={nonce,hashes,reviewNames,coreNames};const entries=[];
 const add=(name,destination)=>{const item=pin(OWN,rel+'/'+name,'baseline');entries.push({source:rel+'/'+name,destination,bytes:item.bytes,sha256:item.sha256});};
 for(const [name,source,destination] of [['baseline-hostbroker',baseline,'payload/panelctl'],['candidate-hostbroker',candidateFile,'payload/hostbroker'],['fixture.py',path.join(OWN,'lab/startup-preflight-guest/fixture.py'),'payload/qualifier.py'],['core.test',coreFile,'payload/core.test'],['authority.test',path.join(CANDIDATE,reviewPin.path),'payload/authority.test']]){write(path.join(work,name),fs.readFileSync(source));add(name,destination);}
 const script=`#!/bin/sh\nset -eu\nexec >/dev/ttyS0 2>&1\ntrap '/sbin/poweroff' EXIT\nmkdir -m 0700 /opt/sifruno-startup-preflight\nmkdir -p /mnt/sifruno-paths-payload\nmount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-paths-payload\ncp /mnt/sifruno-paths-payload/payload/panelctl /opt/sifruno-startup-preflight/baseline-hostbroker\ncp /mnt/sifruno-paths-payload/payload/hostbroker /opt/sifruno-startup-preflight/candidate-hostbroker\ncp /mnt/sifruno-paths-payload/payload/qualifier.py /opt/sifruno-startup-preflight/fixture.py\ncp /mnt/sifruno-paths-payload/payload/core.test /opt/sifruno-startup-preflight/core.test\ncp /mnt/sifruno-paths-payload/payload/authority.test /opt/sifruno-startup-preflight/authority.test\nchmod 0555 /opt/sifruno-startup-preflight/*\nprintf '${nonce}\\n' >/run/sifruno-startup-preflight-admission\nchmod 0600 /run/sifruno-startup-preflight-admission\nset +e\necho SIFRUNO_STARTUP_REPORT_BEGIN_${nonce}\nenv -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -B /opt/sifruno-startup-preflight/fixture.py --disposable-startup-preflight --nonce ${nonce} --baseline-sha ${hashes.baseline} --candidate-sha ${hashes.candidate} --fixture-sha ${hashes.fixture} --core-test-sha ${hashes.core_test} --review-test-sha ${hashes.review_test} --core-test-names ${coreNames.join(',')} --review-test-names ${reviewNames.join(',')}\nstatus=$?\necho SIFRUNO_STARTUP_REPORT_END_${nonce}\necho SIFRUNO_STARTUP_FIXTURE_EXIT_${nonce}_$status\nexit 0\n`;
 write(path.join(work,'meta-data'),`instance-id: ${run}\nlocal-hostname: sifruno-startup-preflight\n`);write(path.join(work,'network-config'),'version: 2\nethernets: {}\n');
 // Suppress default cloud-user creation and SSH key generation/import. No
 // password/root-account changes are requested by cloud-init. The new fixture
 // explicitly adapts only the disposable overlay NSS policy later.
 write(path.join(work,'user-data'),'#cloud-config\nusers: []\nssh_genkeytypes: []\nssh_deletekeys: false\nwrite_files:\n  - path: /root/sifruno-startup-preflight-proof.sh\n    owner: root:root\n    permissions: "0700"\n    content: |\n'+script.split('\n').map(line=>'      '+line).join('\n')+'\nruncmd:\n  - ["/bin/sh", "/root/sifruno-startup-preflight-proof.sh"]\n');
 for(const name of ['user-data','meta-data','network-config'])add(name,name);
 write(path.join(work,'payload-plan.json'),{schema_version:1,entries});const payloadPins=entries.map(x=>pin(OWN,x.source,'baseline'));payloadPins.push(pin(OWN,rel+'/payload-plan.json','baseline'));
 const adapter=`import importlib.util, pathlib, sys\np=pathlib.Path(sys.argv[1]); s=importlib.util.spec_from_file_location('pinned_iso',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\nm.ROOT=pathlib.Path(sys.argv[2]); m.WHEEL=pathlib.Path(sys.argv[3]); sys.argv=[str(p),'--plan',sys.argv[4]]; m.main()\n`;
 let guest=null,result=null,failure=null,isoResult=null,isoAudit=null,unchanged=false,phase='iso_generation';
 const started=new Date().toISOString();
 try {
  const made=await child(PYTHON,['-I','-B','-c',adapter,path.join(PRIMARY,'scripts/alma-account-iso.py'),OWN,path.join(PRIMARY,'.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'),rel+'/payload-plan.json'],{env,timeout:90000,maximum:65536});successful(made);assert.equal(made.stderr.length,0);isoResult=JSON.parse(made.stdout.toString());keys(isoResult,['entries','bytes','sha256']);assert.equal(isoResult.entries,8);assert(HEX.test(isoResult.sha256));assert.equal(pin(OWN,rel+'/payload.iso','baseline',256*1024*1024).sha256,isoResult.sha256);
  phase='iso_contents_admission';
  const auditCode=`import hashlib,io,json,pathlib,stat,sys\nwheel=pathlib.Path(sys.argv[1]); assert hashlib.sha256(wheel.read_bytes()).hexdigest()=='1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e'\nsys.path.insert(0,str(wheel)); import pycdlib\nplan=json.loads(pathlib.Path(sys.argv[2]).read_text()); iso=pycdlib.PyCdlib(); iso.open(sys.argv[3]); files=[]; dirs=[]; records=[]\ntry:\n assert iso.pvd.volume_identifier.decode('ascii').strip()=='CIDATA'\n for folder,children,leaves in iso.walk(rr_path='/'):\n  dirs.extend(folder.rstrip('/')+'/'+name for name in children); files.extend((folder.rstrip('/')+'/'+name).lstrip('/') for name in leaves)\n assert sorted(dirs)==['/payload'] and sorted(files)==sorted(e['destination'] for e in plan['entries']) and len(files)==8\n assert iso.get_record(rr_path='/payload').rock_ridge.dr_entries.px_record.posix_file_mode==0o40555\n for entry in plan['entries']:\n  name=entry['destination']; record=iso.get_record(rr_path='/'+name); px=record.rock_ridge.dr_entries.px_record; assert px.posix_file_mode==0o100444 and px.posix_file_links==1\n  stream=io.BytesIO(); iso.get_file_from_iso_fp(stream,rr_path='/'+name); data=stream.getvalue(); assert len(data)==entry['bytes'] and hashlib.sha256(data).hexdigest()==entry['sha256']\n  records.append({'destination':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':'100444','links':1})\nfinally: iso.close()\nprint(json.dumps({'volume_label':'CIDATA','directories':sorted(dirs),'entries':records},separators=(',',':')))\n`;
  const audited=await child(PYTHON,['-I','-B','-c',auditCode,path.join(PRIMARY,'.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'),path.join(work,'payload-plan.json'),path.join(work,'payload.iso')],{env,timeout:90000,maximum:65536});successful(audited);assert.equal(audited.stderr.length,0);isoAudit=validateISOObservation(JSON.parse(audited.stdout.toString()),entries);write(path.join(work,'iso-contents.json'),isoAudit);
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
 const receipt={schema_version:1,scope:'read_only_stock_then_NSS_only_adapted_fresh_startup_admission',run_id:run,started_at:started,completed_at:new Date().toISOString(),passed,native_observation:guest?.passed===true,failure,source_base:BASE,candidate_build_commit:options['candidate-commit'],candidate_build_authority:'root_supplied_frozen_binary_and_source_manifest',candidate_build_manifest_sha256:candidateManifest.sha256,independent_builder_receipt_sha256:reviewManifest.sha256,independent_source_authority:'root_supplied_pinned_independent_builder_receipt_not_recompiled_here',independent_expected_test_names:reviewNames,compiler_generated_test_main:'generated_by_pinned_Go_tools_from_pinned_test_sources_not_separately_catalogued',assembler_headers:'all_five_installed_pkg_include_files_pinned_before_baseline_build_and_native_run',entire_go_distribution_verified:false,image_sha256:IMAGE_SHA,image_signature_verified:true,source_catalog:inputs,source_catalog_sha256:digest(JSON.stringify(inputs)),candidate_source_catalog_sha256:options['candidate-source-sha'],harness_catalog_sha256:digest(JSON.stringify(harness)),binary_sha256:hashes,iso_sha256:isoResult?.sha256??null,iso_contents:isoAudit,payload_plan_sha256:payloadPins.at(-1).sha256,role_mapping:{'payload/panelctl':'baseline-hostbroker','payload/hostbroker':'candidate-hostbroker','payload/qualifier.py':'new-NSS-only-startup-admission-fixture','payload/core.test':'reviewed-root-core-tests','payload/authority.test':'independent-review-tests'},preparation:{cloud_init:'owned_payload_staging_default_user_and_ssh_key_creation_suppressed',iso_tool:'exact_hash_pinned_existing_pycdlib_helper_owned_ROOT_primary_read_only_WHEEL',guest_policy_snapshot_boundary:'original_then_NSS_only_adaptation_stock_mail_defaults_unchanged',qualification:'fresh_admission_snapshot_and_separate_read_only_broker_smoke',harness_and_fixture_bytes:'retained_in_owned_private_run_cache'},limits:LIMITS,external_nic:false,host_shares:false,shared_dependency_inputs_read_only:true,primary_compilation_cache:'wrapper_default_explicitly_allowed',inputs_unchanged:unchanged,qemu:result?{exit_code:result.code,signal:result.signal,timed_out:result.timedout,output_limit:result.output_limit,output_bytes:result.bytes,owned_child_exited:result.owned_child_exited}:null,guest,cleanup:{owned_qemu_exited:result?.owned_child_exited===true,no_live_process_mutation:true,no_host_listener_created:true,disposable_overlay_retained:true},scope_limits:['fresh_setup_admission_only','unmodified_stock_policy_refused','no_account_mutation_requests','no_cloudlinux_or_cpanel_certification','no_reboot_or_hostile_guest_certification','no_atomic_host_policy_stability_claim']};
 write(path.join(artifacts,'report.json'),receipt);console.log(JSON.stringify({passed,native_observation:receipt.native_observation,run_id:run,report:relative(OWN,path.join(artifacts,'report.json')),report_sha256:digest(fs.readFileSync(path.join(artifacts,'report.json'))),inputs_unchanged:unchanged,owned_qemu_exited:receipt.cleanup.owned_qemu_exited}));if(!passed)process.exitCode=1;
}
async function main() {
 assert.equal(norm(OWN),norm(path.join(PRIMARY,'.worktrees/startup-preflight-guest-sol')),'wrong_owned_worktree');
 const options={};for(let i=2;i<process.argv.length;i++){const key=process.argv[i];assert(key.startsWith('--')&&!Object.hasOwn(options,key.slice(2)));const name=key.slice(2);if(['check-only','build-baseline','run'].includes(name))options[name]=true;else{assert(['candidate-binary','candidate-sha','candidate-source-sha','baseline-manifest','candidate-manifest-sha','candidate-commit','core-test-binary','core-test-sha','core-test-names','review-test-sha','review-manifest-sha','review-test-names'].includes(name)&&process.argv[i+1]&&!process.argv[i+1].startsWith('--'));options[name]=process.argv[++i];}}
 assert.equal(['check-only','build-baseline','run'].filter(x=>options[x]).length,1);
 const tools=toolCatalog(),harness=harnessCatalog();
 if(options['check-only']){assert.equal(Object.keys(options).length,1);console.log(JSON.stringify({mode:'check_only',passed:true,native_observation:false,tools:tools.length,harness:harness.length,tools_catalog_sha256:digest(JSON.stringify(tools)),harness_catalog_sha256:digest(JSON.stringify(harness)),candidate_source_catalog_sha256:digest(JSON.stringify(sourceCatalog(CANDIDATE,'candidate')))}));}
 else if(options['build-baseline']){assert.equal(Object.keys(options).length,1);await buildBaseline(tools,harness);}
 else{assert.equal(Object.keys(options).length,13);await runGuest(options,tools,harness);}
}
if(process.argv[1]&&norm(process.argv[1])===norm(fileURLToPath(import.meta.url)))main().catch(()=>{console.error('Startup preflight verifier admission failed');process.exitCode=1;});
