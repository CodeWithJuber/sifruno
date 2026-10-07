// Source/tool/ELF freeze and isolated offline execution. No live service access.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {admitted, child, digest} from '../../scripts/verify-startup-preflight.mjs';
import {decodePreviewSerial} from './report.mjs';
import {admitToolPins} from './tool-pins.mjs';

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
const run = 'preview-' + new Date().toISOString().replace(/[-:.TZ]/g, '') + '-' + randomBytes(4).toString('hex');
const nonce = randomBytes(16).toString('hex');
const work = path.join(OWN, '.cache/native-web-preview', run);
fs.mkdirSync(work, {recursive:true});
for(let current = work; current !== OWN; current = path.dirname(current)) assert(fs.lstatSync(current).isDirectory() && !fs.lstatSync(current).isSymbolicLink());
const write = (name, value) => fs.writeFileSync(path.join(work, name), typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value, null, 2) + '\n', {flag:'wx'});
const relative = file => path.relative(OWN, file).replaceAll('\\', '/');
const pin = (root, name, maximum) => { const file = admitted(root, path.join(root, name), maximum); const data = fs.readFileSync(file); return {root, path:name, bytes:data.length, sha256:digest(data)}; };
const scan = (dir, accepted) => fs.readdirSync(dir,{withFileTypes:true}).flatMap(e => { assert(!e.isSymbolicLink()); const file=path.join(dir,e.name); return e.isDirectory() ? scan(file,accepted) : accepted(file) ? [file] : []; });
const sources = ['go.mod','go.sum',...scan(path.join(OWN,'internal'),p=>p.endsWith('.go')).map(relative),...scan(path.join(OWN,'cmd'),p=>p.endsWith('.go')).map(relative), ...scan(path.join(OWN,'config'),()=>true).map(relative), ...scan(path.join(OWN,'lab/native-web-preview-guest'),()=>true).map(relative),'lab/startup-preflight-guest/fixture.py','scripts/verify-startup-preflight.mjs','lab/controller-layout-guest/make_iso.py'].sort().map(p=>pin(OWN,p));
// Admit independent authority identities before parsing either catalogue.
const authorities = admitToolPins(name=>pin(PRIMARY,name));
const tools = [...authorities, ...['scripts/go.ps1','.tools/go/bin/go.exe','.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'].map(p=>pin(PRIMARY,p))];
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
const stable = pins => pins.every(p => { try { const actual=pin(p.root,p.path,Math.max(p.bytes,1)); return JSON.stringify(actual)===JSON.stringify(p); }catch{return false;} });
const env = {}; for(const key of ['SYSTEMROOT','SystemRoot','WINDIR']) if(process.env[key]) env[key]=process.env[key];
assert(env.SystemRoot || env.SYSTEMROOT);
env.PATH = [path.join(PRIMARY,'.tools/go/bin'),QDIR,path.join(env.SystemRoot??env.SYSTEMROOT,'System32')].join(path.delimiter);
Object.assign(env,{TEMP:work,TMP:work,OS:'Windows_NT',PATHEXT:'.COM;.EXE;.BAT;.CMD',GOENV:'off',GOPROXY:'off',GOSUMDB:'off',GOTOOLCHAIN:'local',GOOS:'linux',GOARCH:'amd64',CGO_ENABLED:'0',GOFLAGS:'',PYTHONDONTWRITEBYTECODE:'1'});
const go = async args => { const r=await child(PWSH,['-NoProfile','-File',path.join(PRIMARY,'scripts/go.ps1'),...args],{cwd:OWN,env,timeout:120000,maximum:16*1024*1024}); assert(r.code===0&&!r.error&&!r.timedout&&!r.output_limit&&r.owned_child_exited,'Go build failed');return r; };
const start = new Date().toISOString();
let phase = 'build', guest = null, qemu = null, iso = null, failure = null; let linked=[];
const targets=['hostsetup','hostbroker','sifruno','panelctl'];
function objects(raw) {
 const values=[];let start=-1,depth=0,quoted=false,escape=false;
 for(let i=0;i<raw.length;i++){const c=raw[i];if(quoted){if(escape)escape=false;else if(c==='\\')escape=true;else if(c==='"')quoted=false;}else if(c==='"')quoted=true;else if(c==='{'){if(depth++===0)start=i;}else if(c==='}'&&--depth===0){values.push(JSON.parse(raw.slice(start,i+1)));start=-1;}else if(depth===0)assert(/\s/.test(c));}
 assert(depth===0&&!quoted&&start===-1&&values.length>0);return values;
}

try {
  const listed=await go(['list','-mod=readonly','-deps','-json',...targets.map(x=>'./cmd/'+x)]);
  const packages=objects(listed.stdout.toString('utf8'));
  const roots=[OWN,path.join(PRIMARY,'.tools/go'),path.join(PRIMARY,'.cache/go-mod')];
  const linkedMap=new Map();
  for(const pkg of packages){assert(!pkg.Error&&!pkg.DepsErrors&&typeof pkg.Dir==='string');for(const key of ['GoFiles','CgoFiles','SFiles','HFiles','SysoFiles','EmbedFiles'])for(const name of pkg[key]??[]){const file=path.resolve(pkg.Dir,name),root=roots.find(root=>{const r=path.relative(root,file);return r&&!r.startsWith('..')&&!path.isAbsolute(r)});assert(root);const p=pin(root,path.relative(root,file));linkedMap.set(file,p);}if(pkg.Module?.GoMod){const file=path.resolve(pkg.Module.GoMod),root=roots.find(root=>{const r=path.relative(root,file);return r&&!r.startsWith('..')&&!path.isAbsolute(r)});assert(root);linkedMap.set(file,pin(root,path.relative(root,file)));}}
  linked=[...linkedMap.values()];write('linked-inputs.json',linked);
  for(const target of targets)await go(['build','-mod=readonly','-trimpath','-buildvcs=false','-o',path.join(work,target),'./cmd/'+target]);
  assert(stable(sources)&&stable(tools)&&stable(linked),'Inputs changed during build');
  const binary = targets.map(p=>pin(OWN,relative(path.join(work,p))));
  for(const p of binary)assert.equal(fs.readFileSync(path.join(OWN,p.path)).subarray(0,4).toString('hex'),'7f454c46');
  write('source-tool-binary-manifest.json',{schema_version:1,source_base:'af03646f59a274c322ad28b51a10b51189c6fed2',sources,tools,linked,binary,go_distribution_fully_verified:false});
  write('fixture.py',fs.readFileSync(path.join(OWN,'lab/native-web-preview-guest/fixture.py')));
  write('startup_helpers.py',fs.readFileSync(path.join(OWN,'lab/startup-preflight-guest/fixture.py')));
  const expected=Object.fromEntries([...targets,'fixture.py','startup_helpers.py'].map(leaf=>[leaf,digest(fs.readFileSync(path.join(work,leaf)))]));
  write('expected.json',expected);
  const script = `#!/bin/sh\nset -eu\nexec >/dev/ttyS0 2>&1\ntrap '/sbin/poweroff' EXIT\numask 077\nmkdir -m 0755 /opt/sifruno-web-preview-proof\nmkdir -p /mnt/sifruno-web-preview-payload\nmount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-web-preview-payload\ncp /mnt/sifruno-web-preview-payload/payload/* /opt/sifruno-web-preview-proof/\nchmod 0555 /opt/sifruno-web-preview-proof/hostsetup /opt/sifruno-web-preview-proof/hostbroker /opt/sifruno-web-preview-proof/sifruno /opt/sifruno-web-preview-proof/panelctl\nprintf '${nonce}\\n' >/run/sifruno-web-preview-admission\nchmod 0600 /run/sifruno-web-preview-admission\nset +e\nenv -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 -B /opt/sifruno-web-preview-proof/fixture.py ${nonce} /opt/sifruno-web-preview-proof/expected.json >/opt/sifruno-web-preview-proof/report.json\nstatus=$?\necho SIFRUNO_WEB_PREVIEW_BEGIN_${nonce}\ncat /opt/sifruno-web-preview-proof/report.json\necho SIFRUNO_WEB_PREVIEW_END_${nonce}\necho SIFRUNO_WEB_PREVIEW_EXIT_${nonce}_$status\nexit 0\n`;
  write('meta-data',`instance-id: ${run}\nlocal-hostname: sifruno-web-preview-proof\n`);
  write('network-config','version: 2\nethernets: {}\n');
  write('user-data','#cloud-config\nusers: []\nssh_genkeytypes: []\nssh_deletekeys: false\nssh_pwauth: false\ndisable_root: true\nwrite_files:\n  - path: /root/sifruno-web-preview-proof.sh\n    owner: root:root\n    permissions: "0700"\n    content: |\n'+script.split('\n').map(l=>'      '+l).join('\n')+'\nruncmd:\n  - ["/bin/sh", "/root/sifruno-web-preview-proof.sh"]\n');
  const entries=['user-data','meta-data','network-config',...targets,'fixture.py','startup_helpers.py','expected.json'].map(name=>{const p=pin(OWN,relative(path.join(work,name)));return {source:path.join(OWN,p.path),destination:['user-data','meta-data','network-config'].includes(name)?name:'payload/'+name,bytes:p.bytes,sha256:p.sha256};});
  write('payload-plan.json',{schema_version:1,entries});
  phase='iso_build'; const made=await child(PYTHON,['-I',path.join(OWN,'lab/native-web-preview-guest/make_iso.py'),path.join(work,'payload-plan.json')],{cwd:OWN,env,timeout:90000}); write('iso-build-transcript.json',{...made,stdout:made.stdout.toString(),stderr:made.stderr.toString()}); assert(made.code===0&&!made.error&&!made.timedout&&!made.output_limit);
  iso = JSON.parse(fs.readFileSync(path.join(work,'iso-readback.json')));assert(iso.passed&&iso.entries.length===10);
  phase='overlay'; const overlay=path.join(work,'guest.qcow2'); const overlayResult=await child(path.join(QDIR,'qemu-img.exe'),['create','-f','qcow2','-F','qcow2','-b',path.join(PRIMARY,IMAGE),overlay],{cwd:OWN,env,timeout:30000}); assert(overlayResult.code===0&&!overlayResult.timedout&&!overlayResult.output_limit);
  const qemuArgs=['-L',path.join(QDIR,'share'),'-machine','pc','-accel','tcg,thread=single','-cpu','max','-smp','1','-m','1536','-nodefaults','-no-user-config','-nic','none','-display','none','-vga','none','-monitor','none','-serial','stdio','-no-reboot','-object','rng-builtin,id=rng0','-device','virtio-rng-pci,rng=rng0','-drive',`file=${overlay},if=virtio,format=qcow2,index=0`,'-drive',`file=${path.join(work,'payload.iso')},media=cdrom,format=raw,readonly=on,index=2`];
  write('qemu-args.json',qemuArgs); phase='native';console.log(JSON.stringify({started:true,run_id:run,source_files:sources.length,external_nic:false,host_shares:false}));
  qemu=await child(path.join(QDIR,'qemu-system-x86_64.exe'),qemuArgs,{cwd:QDIR,env,timeout:600000,maximum:2*1024*1024}); const serial=Buffer.concat([qemu.stdout,qemu.stderr]);write('serial-private.log',serial);
  assert(qemu.code===0&&!qemu.error&&!qemu.timedout&&!qemu.output_limit&&qemu.owned_child_exited,'Guest did not exit cleanly');
  phase='decode';guest=decodePreviewSerial(serial,nonce,expected);
  assert(stable(sources)&&stable(tools)&&stable(linked)&&stable(binary));
}catch(error){failure=phase+'_failed';write('failure-private.txt',String(error.stack??error)+'\n');}
const report={schema_version:1,scope:'populated_native_web_preview_composition',run_id:run,nonce,started_at:start,checked_at:new Date().toISOString(),passed:failure===null,native_observation:guest?.passed===true,failure,sources,tools,guest,iso_sha256:iso?.iso_sha256??null,source_tool_binary_manifest_sha256:fs.existsSync(path.join(work,'source-tool-binary-manifest.json'))?digest(fs.readFileSync(path.join(work,'source-tool-binary-manifest.json'))):null,qemu:qemu?{code:qemu.code,signal:qemu.signal,error:qemu.error,timedout:qemu.timedout,output_limit:qemu.output_limit,owned_child_exited:qemu.owned_child_exited,bytes:qemu.bytes}:null,external_nic:false,host_shares:false,image_sha256:IMAGE_SHA,image_signature_verified:true,inputs_unchanged:stable(sources)&&stable(tools)&&stable(linked),limits:['Disposable NSS-adapted Alma9.8 only; actual guest accounts and isolated broker/controller HTTP/CLI; no host browser connection.','No generated config installation, runtime activation, crash exercise, installer, reboot, CloudLinux or vendor qualification.','Snapshot verification may persist broker recovery on deliberately drifted owned account home mode.','All source closure including embeds is pinned; full Go distribution qualification is not claimed.']};
write('report.json',report);console.log(JSON.stringify({passed:report.passed,native_observation:report.native_observation,run_id:run,evidence:relative(path.join(work,'report.json')),report_sha256:digest(fs.readFileSync(path.join(work,'report.json'))),failure}));if(!report.passed)process.exitCode=1;

}

}
