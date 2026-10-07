// Source/tool/ELF freeze and isolated offline execution. No live service access.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {admitted, child, digest} from '../../scripts/verify-startup-preflight.mjs';
import {decodeInputSerial} from './report.mjs';

const OWN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PRIMARY = path.resolve(OWN, '../..');
const PYTHON = 'C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python.exe';
const PWSH = 'C:/Users/Administrator/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/powershell/pwsh.exe';
const IMAGE = '.tools/linuxguest/alma9/AlmaLinux-9-GenericCloud-9.8-20260810.x86_64.qcow2';
const IMAGE_SHA = '6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b';
const QDIR = path.join(PRIMARY, '.tools/linuxguest/qemu-20260811');
// Imports must never interpret the importing process's command-line arguments.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
const args = process.argv.slice(2);
assert(args.length === 0 || (args.length===1 && ['--check','--run'].includes(args[0])), 'Only --check or --run is accepted');
if(args[0]!=='--run'){console.log(JSON.stringify({mode:'check_only',native_observation:false,requires_explicit_run:true}));} else {
assert.equal(digest(fs.readFileSync(path.join(OWN,'scripts/verify-startup-preflight.mjs'))),'d3d1f93291975db5b4bd22dd67ef3d1c8c113521ac141abfc050392b0d743f3a');
assert.equal(digest(fs.readFileSync(path.join(OWN,'lab/startup-preflight-guest/fixture.py'))),'f4ddbb78d8a33d3fc17447d0deb494d57ce544442be2befd931de6056043fc85');
assert.equal(digest(fs.readFileSync(path.join(OWN,'lab/controller-layout-guest/make_iso.py'))),'cd4e867d8adc7026735b35b2e86dfbd257bff1c3028d2164d3a20024eb082db9');
const run = 'inputs-' + new Date().toISOString().replace(/[-:.TZ]/g, '') + '-' + randomBytes(4).toString('hex');
const nonce = randomBytes(16).toString('hex');
const work = path.join(OWN, '.cache/runtime-input', run);
fs.mkdirSync(work, {recursive:true});
for(let current = work; current !== OWN; current = path.dirname(current)) assert(fs.lstatSync(current).isDirectory() && !fs.lstatSync(current).isSymbolicLink());
const write = (name, value) => fs.writeFileSync(path.join(work, name), typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value, null, 2) + '\n', {flag:'wx'});
const relative = file => path.relative(OWN, file).replaceAll('\\', '/');
const pin = (root, name, maximum) => { const file = admitted(root, path.join(root, name), maximum); const data = fs.readFileSync(file); return {root, path:name, bytes:data.length, sha256:digest(data)}; };
const scan = (dir, accepted) => fs.readdirSync(dir,{withFileTypes:true}).flatMap(e => { assert(!e.isSymbolicLink()); const file=path.join(dir,e.name); return e.isDirectory() ? scan(file,accepted) : accepted(file) ? [file] : []; });
const sources = ['go.mod','go.sum',...scan(path.join(OWN,'internal'),p=>p.endsWith('.go')).map(relative),...scan(path.join(OWN,'cmd'),p=>p.endsWith('.go')).map(relative), ...scan(path.join(OWN,'config'),()=>true).map(relative), ...scan(path.join(OWN,'lab/runtime-input-guest'),()=>true).map(relative),'lab/startup-preflight-guest/fixture.py','scripts/verify-startup-preflight.mjs','lab/controller-layout-guest/make_iso.py'].sort().map(p=>pin(OWN,p));
const tools = ['scripts/go.ps1','.tools/go/bin/go.exe','.tools/linuxguest/prepared.json','.tools/linuxguest/alma9/verified.json','.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'].map(p=>pin(PRIMARY,p));
// Independent identities anchor the inventories before their contents are trusted.
const requiredToolPins = {
 '.tools/linuxguest/prepared.json':'211e7d98ce793a4302be5f4826b9f61dcfcce0fb410e18ff551835d517456914',
 '.tools/linuxguest/alma9/verified.json':'1feae2b3ddf046edc6ab4ff65d57b78f9d1c9428174fc79eabe0c34de246368f',
 '.tools/linuxguest/qemu-20260811/qemu-system-x86_64.exe':'47d57a6072e0bb3bd98f87926eb129eb1736dfe818c67b3b81ef7ce4edd0b3cd',
 '.tools/linuxguest/qemu-20260811/qemu-img.exe':'9d930582d0d574bb106d89982c547688e10b8f356192d302cc3d0ae4e8674534',
};
for(const [name, expected] of Object.entries(requiredToolPins)) {
 const actual=pin(PRIMARY,name);assert.equal(actual.sha256,expected,'fixed_tool_identity');
 if(!tools.some(p=>p.path===name))tools.push(actual);
}
const prepared = JSON.parse(fs.readFileSync(path.join(PRIMARY,'.tools/linuxguest/prepared.json')));
assert(prepared.schema_version === 1 && prepared.files.length === 125);
for(const p of prepared.files) { const actual=pin(PRIMARY,p.path); assert(actual.bytes===p.bytes && actual.sha256===p.sha256); if(!tools.some(x=>x.path===p.path))tools.push(actual); }
const verified = JSON.parse(fs.readFileSync(path.join(PRIMARY,'.tools/linuxguest/alma9/verified.json')));
assert(verified.checksum_signature_verified === true && verified.signer_fingerprint === 'BF18AC2876178908D6E71267D36CB86CB86B3716' && verified.sha256 === IMAGE_SHA);
const image = pin(PRIMARY, IMAGE, 700*1024*1024); assert.equal(image.sha256,IMAGE_SHA); tools.push(image);
for(const file of [...scan(path.join(PRIMARY,'.tools/go/pkg/tool'),()=>true), ...scan(path.join(PRIMARY,'.tools/go/pkg/include'),()=>true)]) tools.push(pin(PRIMARY,path.relative(PRIMARY,file)));
tools.push(pin(path.dirname(PYTHON),path.basename(PYTHON)), pin(path.dirname(PWSH),path.basename(PWSH)));
assert.equal(tools.find(t=>t.path===path.basename(PYTHON)).sha256,'4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a');
assert.equal(tools.find(t=>t.path==='.tools/go/bin/go.exe').sha256,'d3ccdb604eafa6031133aefe1a3db24f0bb7362b857bc2125ac4e4c178b4b490');
const PREPARED_IMAGE='.cache/alma-web-runtime/web-install-1791171040494-b6fc674b/guest.qcow2';
const provenance = [
[PREPARED_IMAGE,'f362d8658bb7981b151b63110c41ffa71b09ec742a777bb3ca731e2d96b65c86'],
['artifacts/runtime/alma-web-runs/web-install-1791171040494-b6fc674b/host-report.json','7ae52365e2f4d0fb6c6751ffd3093ecaa23a59ce1fa7c991957e93f9afb1e0e1'],
['.cache/alma-web-runtime/web-install-1791171040494-b6fc674b/install-report.json','75c0311ccda8880f6fc0f8a4efb4c1316ac7a47d73902ab291fe74491c66b1f9'],
['.cache/alma-web-repositories/webrepo-20261005-php83/payload/package-manifest.json','ff13a63fa4c09047ff2c32edea8ebfb866ba2fb0aa847ed0c2364325f431ea3c']];
for(const [name,sha] of provenance){const p=pin(PRIMARY,name,2*1024*1024*1024);assert.equal(p.sha256,sha);tools.push(p);}
const installed=JSON.parse(fs.readFileSync(path.join(PRIMARY,provenance[1][0])));
assert(installed.passed&&installed.phase==='install'&&installed.input_stable&&installed.external_nic===false&&installed.host_shares===false&&installed.image_sha256===IMAGE_SHA&&installed.overlay_sha256===provenance[0][1]);
const packages=JSON.parse(fs.readFileSync(path.join(PRIMARY,provenance[3][0])));
assert(packages.packages.length===18&&packages.cloud_image_sha256===IMAGE_SHA&&packages.signing_key_fingerprint==='BF18AC2876178908D6E71267D36CB86CB86B3716');
for(const pkg of packages.packages){assert(/^packages\/[A-Za-z0-9_.+-]+\.rpm$/.test(pkg.file));const p=pin(PRIMARY,'.cache/alma-web-repositories/webrepo-20261005-php83/'+pkg.file);assert(p.sha256===pkg.checksum_sha256&&p.bytes===pkg.size);tools.push(p);}
const stable = pins => pins.every(p => { try { const actual=pin(p.root,p.path,Math.max(p.bytes,1)); return JSON.stringify(actual)===JSON.stringify(p); }catch{return false;} });
const env = {}; for(const key of ['SYSTEMROOT','SystemRoot','WINDIR']) if(process.env[key]) env[key]=process.env[key];
assert(env.SystemRoot || env.SYSTEMROOT);
env.PATH = [path.join(PRIMARY,'.tools/go/bin'),QDIR,path.join(env.SystemRoot??env.SYSTEMROOT,'System32')].join(path.delimiter);
Object.assign(env,{TEMP:work,TMP:work,OS:'Windows_NT',PATHEXT:'.COM;.EXE;.BAT;.CMD',GOENV:'off',GOPROXY:'off',GOSUMDB:'off',GOTOOLCHAIN:'local',GOOS:'linux',GOARCH:'amd64',CGO_ENABLED:'0',GOFLAGS:'',PYTHONDONTWRITEBYTECODE:'1'});
const go = async args => { const r=await child(PWSH,['-NoProfile','-File',path.join(PRIMARY,'scripts/go.ps1'),...args],{cwd:OWN,env,timeout:120000,maximum:16*1024*1024}); assert(r.code===0&&!r.error&&!r.timedout&&!r.output_limit&&r.owned_child_exited,'Go build failed');return r; };
const start = new Date().toISOString();
let phase = 'build', guest = null, qemu = null, iso = null, failure = null; let linked=[];
const targets=['hostsetup','runtime.test'];
function objects(raw) {
 const values=[];let start=-1,depth=0,quoted=false,escape=false;
 for(let i=0;i<raw.length;i++){const c=raw[i];if(quoted){if(escape)escape=false;else if(c==='\\')escape=true;else if(c==='"')quoted=false;}else if(c==='"')quoted=true;else if(c==='{'){if(depth++===0)start=i;}else if(c==='}'&&--depth===0){values.push(JSON.parse(raw.slice(start,i+1)));start=-1;}else if(depth===0)assert(/\s/.test(c));}
 assert(depth===0&&!quoted&&start===-1&&values.length>0);return values;
}

try {
  const chain=await child(path.join(QDIR,'qemu-img.exe'),['info','--backing-chain','--output=json',path.join(PRIMARY,PREPARED_IMAGE)],{cwd:OWN,env,timeout:30000});
  assert(chain.code===0&&!chain.error&&!chain.timedout&&!chain.output_limit&&chain.owned_child_exited);
  const layers=JSON.parse(chain.stdout.toString());assert(layers.length===2&&layers.every(x=>x.format==='qcow2'));
  assert.equal(path.resolve(layers[0].filename).toLowerCase(),path.resolve(PRIMARY,PREPARED_IMAGE).toLowerCase());
  assert.equal(path.resolve(layers[1].filename).toLowerCase(),path.resolve(PRIMARY,IMAGE).toLowerCase());
  write('backing-chain.json',layers);
  const listed=await go(['list','-mod=readonly','-test','-deps','-json','./cmd/hostsetup','./internal/hostwebruntime']);
  const packages=objects(listed.stdout.toString('utf8'));
  const roots=[OWN,path.join(PRIMARY,'.tools/go'),path.join(PRIMARY,'.cache/go-mod')];
  const linkedMap=new Map();
  const generatedRoot=path.join(PRIMARY,'.cache/go-build');
  const expectedTestMains=new Set(['sifruno/cmd/hostsetup.test','sifruno/internal/hostwebruntime.test']);
  const admittedTestMains=new Set();
  for(const pkg of packages){
   assert(!pkg.Error&&!pkg.DepsErrors&&typeof pkg.Dir==='string');
   for(const key of ['GoFiles','CgoFiles','SFiles','HFiles','SysoFiles','EmbedFiles'])for(const name of pkg[key]??[]){
    const file=path.resolve(pkg.Dir,name);
    const root=roots.find(root=>{const r=path.relative(root,file);return r&&!r.startsWith('..')&&!path.isAbsolute(r)});
    let p;
    if(root){p=pin(root,path.relative(root,file));}else{
     // Only go list's generated main for these two named test packages may
     // escape source roots. Never admit arbitrary package files from GOCACHE.
     assert(key==='GoFiles'&&pkg.Name==='main'&&expectedTestMains.has(pkg.ImportPath));
     assert(pkg.GoFiles.length===1&&path.isAbsolute(name)&&path.normalize(name)===file);
     assert(['CgoFiles','SFiles','HFiles','SysoFiles','EmbedFiles'].every(k=>!(pkg[k]?.length)));
     assert(!admittedTestMains.has(pkg.ImportPath));
     const cacheName=path.relative(generatedRoot,file).replaceAll('\\','/');
     const match=/^([a-f0-9]{2})\/([a-f0-9]{64})-d$/.exec(cacheName);
     assert(match&&match[1]===match[2].slice(0,2),'generated_testmain_cache_path');
     p=pin(generatedRoot,cacheName,1024*1024);
     assert.equal(p.sha256,match[2],'generated_testmain_content_address');
     const data=fs.readFileSync(file);
     assert(data.subarray(0,64).toString('utf8').startsWith("\n// Code generated by 'go test'. DO NOT EDIT.\n"),'generated_testmain_header');
     assert.equal(digest(data),p.sha256);admittedTestMains.add(pkg.ImportPath);
    }
    linkedMap.set(file,p);
   }
   if(pkg.Module?.GoMod){
    const file=path.resolve(pkg.Module.GoMod),root=roots.find(root=>{const r=path.relative(root,file);return r&&!r.startsWith('..')&&!path.isAbsolute(r)});
    assert(root);linkedMap.set(file,pin(root,path.relative(root,file)));
   }
  }
  assert.deepEqual([...admittedTestMains].sort(),[...expectedTestMains].sort());
  linked=[...linkedMap.values()];write('linked-inputs.json',linked);
  await go(['build','-mod=readonly','-trimpath','-buildvcs=false','-o',path.join(work,'hostsetup'),'./cmd/hostsetup']);
  await go(['test','-c','-mod=readonly','-trimpath','-buildvcs=false','-o',path.join(work,'runtime.test'),'./internal/hostwebruntime']);
  assert(stable(sources)&&stable(tools)&&stable(linked),'Inputs changed during build');
  const binary = targets.map(p=>pin(OWN,relative(path.join(work,p))));
  for(const p of binary)assert.equal(fs.readFileSync(path.join(OWN,p.path)).subarray(0,4).toString('hex'),'7f454c46');
  write('source-tool-binary-manifest.json',{schema_version:1,source_base:'f77ed89',sources,tools,linked,binary,go_distribution_fully_verified:false});
  write('fixture.py',fs.readFileSync(path.join(OWN,'lab/runtime-input-guest/fixture.py')));
  write('startup_helpers.py',fs.readFileSync(path.join(OWN,'lab/startup-preflight-guest/fixture.py')));
  const expected=Object.fromEntries([...targets,'fixture.py','startup_helpers.py'].map(leaf=>[leaf,digest(fs.readFileSync(path.join(work,leaf)))]));
  write('expected.json',expected);
  const script = `#!/bin/sh\nset -eu\nexec >/dev/ttyS0 2>&1\ntrap '/sbin/poweroff' EXIT\numask 077\nmkdir -m 0755 /opt/sifruno-runtime-input-proof\nmkdir -p /mnt/sifruno-runtime-input-payload\nmount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-runtime-input-payload\ncp /mnt/sifruno-runtime-input-payload/payload/* /opt/sifruno-runtime-input-proof/\nchmod 0555 /opt/sifruno-runtime-input-proof/hostsetup /opt/sifruno-runtime-input-proof/runtime.test\nprintf '${nonce}\\n' >/run/sifruno-runtime-input-admission\nchmod 0600 /run/sifruno-runtime-input-admission\nset +e\nenv -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 -B /opt/sifruno-runtime-input-proof/fixture.py ${nonce} /opt/sifruno-runtime-input-proof/expected.json >/opt/sifruno-runtime-input-proof/report.json\nstatus=$?\necho SIFRUNO_RUNTIME_INPUT_BEGIN_${nonce}\ncat /opt/sifruno-runtime-input-proof/report.json\necho SIFRUNO_RUNTIME_INPUT_END_${nonce}\necho SIFRUNO_RUNTIME_INPUT_EXIT_${nonce}_$status\nexit 0\n`;
  write('meta-data',`instance-id: ${run}\nlocal-hostname: sifruno-runtime-input-proof\n`);
  write('network-config','version: 2\nethernets: {}\n');
  write('user-data','#cloud-config\nusers: []\nssh_genkeytypes: []\nssh_deletekeys: false\nssh_pwauth: false\ndisable_root: true\nwrite_files:\n  - path: /root/sifruno-runtime-input-proof.sh\n    owner: root:root\n    permissions: "0700"\n    content: |\n'+script.split('\n').map(l=>'      '+l).join('\n')+'\nruncmd:\n  - ["/bin/sh", "/root/sifruno-runtime-input-proof.sh"]\n');
  const entries=['user-data','meta-data','network-config',...targets,'fixture.py','startup_helpers.py','expected.json'].map(name=>{const p=pin(OWN,relative(path.join(work,name)));return {source:path.join(OWN,p.path),destination:['user-data','meta-data','network-config'].includes(name)?name:'payload/'+name,bytes:p.bytes,sha256:p.sha256};});
  write('payload-plan.json',{schema_version:1,entries});
  phase='iso_build'; const made=await child(PYTHON,['-I',path.join(OWN,'lab/runtime-input-guest/make_iso.py'),path.join(work,'payload-plan.json')],{cwd:OWN,env,timeout:90000}); write('iso-build-transcript.json',{...made,stdout:made.stdout.toString(),stderr:made.stderr.toString()}); assert(made.code===0&&!made.error&&!made.timedout&&!made.output_limit);
  iso = JSON.parse(fs.readFileSync(path.join(work,'iso-readback.json')));assert(iso.passed&&iso.entries.length===8);
  phase='overlay'; const overlay=path.join(work,'guest.qcow2'); const overlayResult=await child(path.join(QDIR,'qemu-img.exe'),['create','-f','qcow2','-F','qcow2','-b',path.join(PRIMARY,PREPARED_IMAGE),overlay],{cwd:OWN,env,timeout:30000}); assert(overlayResult.code===0&&!overlayResult.timedout&&!overlayResult.output_limit);
  const qemuArgs=['-L',path.join(QDIR,'share'),'-machine','pc','-accel','tcg,thread=single','-cpu','max','-smp','1','-m','1536','-nodefaults','-no-user-config','-nic','none','-display','none','-vga','none','-monitor','none','-serial','stdio','-no-reboot','-object','rng-builtin,id=rng0','-device','virtio-rng-pci,rng=rng0','-drive',`file=${overlay},if=virtio,format=qcow2,index=0`,'-drive',`file=${path.join(work,'payload.iso')},media=cdrom,format=raw,readonly=on,index=2`];
  write('qemu-args.json',qemuArgs); phase='native';console.log(JSON.stringify({started:true,run_id:run,source_files:sources.length,external_nic:false,host_shares:false}));
  qemu=await child(path.join(QDIR,'qemu-system-x86_64.exe'),qemuArgs,{cwd:QDIR,env,timeout:600000,maximum:2*1024*1024}); const serial=Buffer.concat([qemu.stdout,qemu.stderr]);write('serial-private.log',serial);
  assert(qemu.code===0&&!qemu.error&&!qemu.timedout&&!qemu.output_limit&&qemu.owned_child_exited,'Guest did not exit cleanly');
  phase='decode';guest=decodeInputSerial(serial,nonce,expected);
  assert(stable(sources)&&stable(tools)&&stable(linked)&&stable(binary));
}catch(error){failure=phase+'_failed';write('failure-private.txt',String(error.stack??error)+'\n');}
const report={schema_version:1,scope:'native_runtime_installation_inputs',run_id:run,nonce,started_at:start,checked_at:new Date().toISOString(),passed:failure===null,native_observation:guest?.passed===true,failure,sources,tools,guest,iso_sha256:iso?.iso_sha256??null,source_tool_binary_manifest_sha256:fs.existsSync(path.join(work,'source-tool-binary-manifest.json'))?digest(fs.readFileSync(path.join(work,'source-tool-binary-manifest.json'))):null,qemu:qemu?{code:qemu.code,signal:qemu.signal,error:qemu.error,timedout:qemu.timedout,output_limit:qemu.output_limit,owned_child_exited:qemu.owned_child_exited,bytes:qemu.bytes}:null,external_nic:false,host_shares:false,image_sha256:IMAGE_SHA,prepared_image_sha256:provenance[0][1],image_signature_verified:true,inputs_unchanged:stable(sources)&&stable(tools)&&stable(linked),limits:['Prepared offline Alma9.8 PHP8.3 overlay only; no unmodified stock or additional OS claim.','Actual fixed installed binaries/modules; explicitly synthetic CA fixture bytes, no certificate validity.','Targeted input tests only; no Runtime.Open/bootstrap/serving/account/NSS changes.','No full compiler distribution or hostile-root attestation.']};
write('report.json',report);console.log(JSON.stringify({passed:report.passed,native_observation:report.native_observation,run_id:run,evidence:relative(path.join(work,'report.json')),report_sha256:digest(fs.readFileSync(path.join(work,'report.json'))),failure}));if(!report.passed)process.exitCode=1;

}

}
