// Build only reviewed workspace code with the already-installed Go toolchain.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {digest,regular} from '../hostwebruntime-mechanics/admission.mjs';

const owner=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
export function jsonObjects(raw) {
  const values=[];let start=-1,depth=0,string=false,escaped=false;
  for(let i=0;i<raw.length;i++) {
    const c=raw[i];
    if(start<0){if(/\s/.test(c))continue;assert.equal(c,'{');start=i;depth=1;continue;}
    if(string){if(escaped)escaped=false;else if(c==='\\')escaped=true;else if(c==='"')string=false;continue;}
    if(c==='"')string=true;else if(c==='{')depth++;else if(c==='}'&&--depth===0){values.push(JSON.parse(raw.slice(start,i+1)));start=-1;}
  }
  assert.equal(start,-1,'Truncated Go package metadata');assert(values.length>0);return values;
}
export function layout(primary) {
  assert(path.isAbsolute(primary));primary=path.resolve(primary);
  assert.equal(fs.realpathSync(primary).toLowerCase(),primary.toLowerCase());
  const allowed=[primary,...['web-crash-integration'].map(v=>path.join(primary,'.worktrees',v))];
  assert(allowed.some(v=>v.toLowerCase()===owner.toLowerCase()),'Unassigned build owner');
  assert.equal(fs.readFileSync(regular(owner,'go.mod',65536),'utf8').split(/\r?\n/)[0],'module sifruno');
  return primary;
}
function command(exe,args,env,limit=16*1024*1024) {
  const r=spawnSync(exe,args,{cwd:owner,env,windowsHide:true,timeout:120000,maxBuffer:limit,encoding:'utf8'});
  assert(!r.error&&r.status===0,'Pinned Go command failed: '+args[0]);return r.stdout;
}
export function build(primary) {
  primary=layout(primary);const work=path.join(owner,'.cache/hostwebruntime-crash-build');
  fs.mkdirSync(work,{recursive:true});assert.equal(fs.realpathSync(work).toLowerCase(),work.toLowerCase());
  const go=regular(primary,'.tools/go/bin/go.exe',32*1024*1024);
  const env={};for(const k of ['SYSTEMROOT','SystemRoot','WINDIR','TEMP','TMP','LOCALAPPDATA','USERPROFILE','APPDATA','COMSPEC','ComSpec','ProgramFiles','ProgramData','PSModulePath'])if(process.env[k])env[k]=process.env[k];
  env.PATH=path.dirname(go)+';'+path.join(env.SystemRoot||env.SYSTEMROOT,'System32');
  Object.assign(env,{GOCACHE:path.join(work,'go-cache'),GOMODCACHE:path.join(primary,'.cache/go-mod'),GOPROXY:'off',GOSUMDB:'off',GOFLAGS:'-mod=readonly',CGO_ENABLED:'0',GOOS:'linux',GOARCH:'amd64',GOTOOLCHAIN:'local'});
  const wrapper=regular(primary,'scripts/go.ps1',65536);
  const powershell=path.join(env.SystemRoot||env.SYSTEMROOT,'System32/WindowsPowerShell/v1.0/powershell.exe');
  // Windows PowerShell suppresses this wrapper's output under a stripped
  // environment on this host. Use ordinary inherited startup for this read-only
  // three-value probe; compilation below keeps the explicit offline environment.
  const authority=command(powershell,['-NoProfile','-File',wrapper,'env','GOVERSION','GOROOT','GOTOOLDIR'],undefined,16384).trim().split(/\r?\n/);
  assert.equal(authority.length,3);assert.equal(path.resolve(authority[1]).toLowerCase(),path.join(primary,'.tools/go').toLowerCase());
  const files=new Map();
  function add(abs) {
    abs=path.resolve(abs);let root,base;
    if(abs.toLowerCase().startsWith(owner.toLowerCase()+path.sep)){root='source';base=owner;}
    else {root='primary';base=primary;assert(abs.toLowerCase().startsWith(primary.toLowerCase()+path.sep));}
    const rel=path.relative(base,abs).replaceAll('\\','/');
    assert(root==='source'?/^(?:internal|lab\/hostwebruntime-crash-driver)\/[A-Za-z0-9_./-]+$|^go\.(?:mod|sum)$|^\.cache\/hostwebruntime-crash-build\/go-cache\/[a-f0-9]{2}\/[a-f0-9]{64}-d$/.test(rel):/^\.tools\/go\/[A-Za-z0-9_./-]+$|^\.cache\/go-mod\/(?:golang.org\/x\/sys@v0.48.0|go.etcd.io\/bbolt@v1.5.0)\/[A-Za-z0-9_./-]+$/.test(rel),'Unexpected build input '+rel);
    const b=fs.readFileSync(regular(path.dirname(abs),path.basename(abs),64*1024*1024));
    files.set(root+':'+rel,{root,path:rel,bytes:b.length,sha256:digest(b)});
  }
  for(const file of ['go.mod','go.sum'])add(path.join(owner,file));add(go);
  for(const tool of ['compile.exe','link.exe','asm.exe'])add(path.join(authority[2],tool));
  const raw=command(go,['list','-deps','-test','-json','./lab/hostwebruntime-crash-driver','./internal/hostwebruntime'],env);
  fs.writeFileSync(path.join(work,'dependencies.json'),raw);
  const packages=jsonObjects(raw);for(const p of packages){assert(!p.Error&&!p.Incomplete);if(!p.Dir)continue;
    for(const field of ['GoFiles','CgoFiles','CFiles','CXXFiles','MFiles','HFiles','FFiles','SFiles','SysoFiles','EmbedFiles','TestGoFiles','XTestGoFiles'])for(const f of p[field]||[])add(path.resolve(p.Dir,f));
  }
  const pinned=[...files.values()].sort((a,b)=>(a.root+':'+a.path).localeCompare(b.root+':'+b.path));
  // Reopen exact admitted paths; '@' is allowed only inside the fixed module roots.
  function verify(){for(const f of pinned){const abs=path.join(f.root==='source'?owner:primary,...f.path.split('/'));const b=fs.readFileSync(regular(path.dirname(abs),path.basename(abs),64*1024*1024));assert.equal(b.length,f.bytes);assert.equal(digest(b),f.sha256);}}
  verify();
  const driver=path.join(work,'qualification-driver'),test=path.join(work,'serving-linux.test');
  command(go,['build','-trimpath','-o',driver,'./lab/hostwebruntime-crash-driver'],env);
  command(go,['test','-c','-trimpath','-o',test,'./lab/hostwebruntime-crash-driver'],env);verify();
  const reapingTest=path.join(work,'reaping-linux.test');
  command(go,['test','-c','-trimpath','-o',reapingTest,'./internal/hostwebruntime'],env);verify();
  const artifact=p=>{const b=fs.readFileSync(regular(work,path.basename(p),32*1024*1024));assert.deepEqual([...b.subarray(0,5)],[127,69,76,70,2]);assert.equal(b.readUInt16LE(18),62);return {path:path.relative(owner,p).replaceAll('\\','/'),sha256:digest(b),bytes:b.length};};
  const target=packages.find(p=>p.ImportPath==='sifruno/lab/hostwebruntime-crash-driver');
  assert(target&&target.TestGoFiles.length>=3);
  const testSources=target.TestGoFiles.map(f=>fs.readFileSync(regular(target.Dir,f,128*1024)));
  const tests=[...Buffer.concat(testSources).toString().matchAll(/^func (Test[A-Za-z0-9_]+)\(/gm)].map(v=>v[1]).sort();assert(tests.length>=6&&new Set(tests).size===tests.length);
  const reapingNames=['TestNamespaceReopenedHandlesReapOriginalChild'];
  assert(packages.some(p=>p.ImportPath==='sifruno/internal/hostwebruntime'&&p.TestGoFiles.some(f=>fs.readFileSync(path.join(p.Dir,f),'utf8').includes('func '+reapingNames[0]+'('))));
  const catalog={schema_version:1,kind:'current-native-web-controller-crash-build',baseline_commit:'18a97432be0c843ea8a26c76bf04047b0efa5a88',source_inputs:pinned,package_count:packages.length,dependency_metadata_sha256:digest(raw),go_version:authority[0],go_tool_sha256:digest(fs.readFileSync(go)),build_environment:{GOOS:'linux',GOARCH:'amd64',CGO_ENABLED:'0',GOPROXY:'off',GOSUMDB:'off',GOFLAGS:'-mod=readonly'},commands:[['env','GOVERSION','GOROOT','GOTOOLDIR'],['list','-deps','-test','-json','./lab/hostwebruntime-crash-driver'],['build','-trimpath','-o','<owned-driver>','./lab/hostwebruntime-crash-driver'],['test','-c','-trimpath','-o','<owned-test>','./lab/hostwebruntime-crash-driver']],wrapper_cache_exception:'Read-only primary wrapper establishes installed tool authority; pinned canonical tool uses an owned build cache and read-only offline module inputs.',driver:artifact(driver),test:artifact(test),required_tests:tests,native_execution:false,original_compatibility_certified:false};
  catalog.reaping_test=artifact(reapingTest);catalog.required_reaping_tests=reapingNames;
  catalog.commands[1].push('./internal/hostwebruntime');catalog.commands.push(['test','-c','-trimpath','-o','<owned-reaping-test>','./internal/hostwebruntime']);
  const output=path.join(work,'source_catalog.json');fs.writeFileSync(output,JSON.stringify(catalog)+'\n');
  return {path:output,sha256:digest(fs.readFileSync(output)),inputs:pinned.length,tests};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))try{assert.equal(process.argv.length,3);console.log(JSON.stringify(build(process.argv[2])));}catch(e){console.error(String(e.message));process.exitCode=1;}
