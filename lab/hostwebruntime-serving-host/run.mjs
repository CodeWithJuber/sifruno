import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {digest, regular, pin, qemuArgs, createCapture} from '../hostwebruntime-mechanics/admission.mjs';
import {layout, filePin, preparedPackages, validateLineage, verifySources, buildAdmission} from './inputs.mjs';
import {parseServingSerial} from './parser.mjs';

const here = path.dirname(fileURLToPath(import.meta.url)), owner = path.resolve(here, '../..');
const pins = JSON.parse(fs.readFileSync(path.join(here, 'pins.json')));
const tools = JSON.parse(fs.readFileSync(path.join(here, '../hostwebruntime-mechanics/pins.json')));
function environment(qdir) {
  const env = {};
  for (const key of ['SYSTEMROOT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'LOCALAPPDATA']) if (process.env[key]) env[key] = process.env[key];
  assert(env.LOCALAPPDATA && (env.SystemRoot || env.SYSTEMROOT));
  env.PATH = qdir + ';' + path.join(env.SystemRoot || env.SYSTEMROOT, 'System32');
  return env;
}
function command(exe, args, cwd, env, timeout) {
  const r = spawnSync(exe, args, {cwd, env, windowsHide: true, timeout, maxBuffer: 65536, encoding: 'utf8'});
  assert(!r.error && r.status === 0, 'Serving preparation command failed');
  return r.stdout;
}
export function admit(primary) {
  assert.equal(process.platform, 'win32');
  primary = layout(primary, owner, here);
  const inventory = [], self = [];
  const add = (entry, max) => { const result = filePin(primary, entry, max); inventory.push(result); return result; };
  self.push(pin(owner, {path:'lab/hostwebruntime-mechanics/admission.mjs',sha256:pins.mechanics_admission_sha256}));
  self.push(pin(owner, {path:'lab/hostwebruntime-mechanics/pins.json',sha256:pins.mechanics_tool_catalog_sha256}));
  for (const key of ['prepared', 'verified', 'qemu_img', 'qemu', 'wheel']) add(tools[key]);
  add(tools.image, 700 * 1024 * 1024);
  for (const key of ['prepared_image', 'prepared_host_report', 'prepared_install_report', 'package_manifest', 'serving_manifest', 'driver', 'test_elf', 'helper', 'guest_manifest']) add(pins[key],key==='prepared_image'?80*1024*1024:undefined);
  const read = entry => JSON.parse(fs.readFileSync(regular(primary, entry.path), 'utf8'));
  const verified = read(tools.verified);
  assert(verified.checksum_signature_verified === true && verified.sha256 === tools.image.sha256 && verified.signer_fingerprint === 'BF18AC2876178908D6E71267D36CB86CB86B3716');
  const prepared = read(tools.prepared);
  assert(prepared.schema_version === 1 && prepared.files.length > 50 && prepared.files.length < 300);
  for (const f of prepared.files.filter(f => f.path.startsWith('.tools/linuxguest/qemu-20260811/'))) add(f);
  const originalPackages = read(pins.package_manifest), packages = preparedPackages(originalPackages);
  assert.equal(originalPackages.cloud_image_sha256, tools.image.sha256);
  const host = read(pins.prepared_host_report), install = read(pins.prepared_install_report);
  validateLineage(host, install, pins, tools.image);
  const expected = packages.packages.map(p => p.nevra).sort();
  assert.deepEqual(install.installed.map(p => p.nevra).sort(), expected);
  assert.deepEqual(install.signatures.map(p => p.nevra).sort(), expected);
  for (const p of originalPackages.packages) add({path:p.source,sha256:p.checksum_sha256,bytes:p.bytes});
  verifySources(primary, pins, add);
  const guestManifest = read(pins.guest_manifest);
  assert(guestManifest.kind === 'prepared-alma9-serving-guest-candidate' && guestManifest.freeze === 1 && guestManifest.native_execution === false && guestManifest.files.length === 3);
  assert(guestManifest.runtime_pins_unchanged === true && guestManifest.driver_pins_unchanged === true);
  assert.equal(guestManifest.canonical_helper_sha256,pins.helper.sha256);assert.equal(guestManifest.driver_source_catalog_sha256,pins.serving_manifest.sha256);assert.equal(guestManifest.driver_elf_sha256,pins.driver.sha256);assert.equal(guestManifest.test_elf_sha256,pins.test_elf.sha256);
  for (const f of guestManifest.files) {
    assert(/^lab\/hostwebruntime-serving-guest\/[A-Za-z0-9_.-]+$/.test(f.path));
    add({...f,path:'.worktrees/native-web-executor-sol/'+f.path});
  }
  const fixture = guestManifest.files.filter(f => f.path.endsWith('/serving_guest.py'));
  assert.equal(fixture.length,1); assert.equal(fixture[0].sha256,pins.fixture.sha256); add(pins.fixture);
  for (const entry of [pins.driver,pins.test_elf]) {
    const b=fs.readFileSync(regular(primary,entry.path));
    assert(b.subarray(0,4).equals(Buffer.from([0x7f,0x45,0x4c,0x46])) && b[4]===2 && b[5]===1 && b.readUInt16LE(18)===62);
  }
  for (const name of ['run.mjs','inputs.mjs','parser.mjs','make_iso.py','pins.json']) {
    const rel='lab/hostwebruntime-serving-host/'+name;self.push({path:rel,sha256:digest(fs.readFileSync(regular(owner,rel)))});
  }
  return {primary,inventory,self,packages,pythonSHA:guestManifest.python_tool_sha256};
}
function unchanged(state) {
  for (const p of state.inventory) filePin(state.primary,p,p.path===tools.image.path?700*1024*1024:p.path===pins.prepared_image.path?80*1024*1024:64*1024*1024);
  for (const p of state.self) filePin(owner,p);
}
async function main() {
  const args=process.argv.slice(2);
  assert(args.length===3 && args[0]==='--primary-root' && ['--check-only','--prepare-only','--run'].includes(args[2]));
  const state=admit(args[1]);
  if(args[2]==='--check-only') {unchanged(state);console.log(JSON.stringify({admitted:true,qemu_launched:false,scope:pins.scope,source_inputs:state.inventory,runner_sources:state.self}));return;}
  const nonce=randomBytes(12).toString('hex'),run=`serving-${Date.now()}-${nonce}`;
  const parent=path.join(owner,'.cache/hostwebruntime-serving-host');fs.mkdirSync(parent,{recursive:true});assert.equal(fs.realpathSync(parent).toLowerCase(),parent.toLowerCase());
  const work=path.join(parent,run);fs.mkdirSync(work);fs.mkdirSync(path.join(work,'packages'));
  const qdir=path.join(state.primary,'.tools/linuxguest/qemu-20260811'),env=environment(qdir);
  const python=path.join(env.LOCALAPPDATA,'Programs/Python/Python312/python.exe');
  assert(fs.lstatSync(python).isFile() && fs.realpathSync(python).toLowerCase()===python.toLowerCase());
  assert.equal(digest(fs.readFileSync(regular(path.dirname(python),path.basename(python)))),state.pythonSHA,'Pinned builder Python required');
  const image=regular(state.primary,pins.prepared_image.path,64*1024*1024+8*1024*1024);
  const imageInfo=JSON.parse(command(regular(state.primary,tools.qemu_img.path),['info','--output=json',image],work,env,10000));
  assert(imageInfo.format==='qcow2' && imageInfo['backing-filename-format']==='qcow2' && imageInfo['dirty-flag']===false && imageInfo['format-specific'].data.corrupt===false);
  assert.equal(path.resolve(imageInfo['full-backing-filename']).toLowerCase(),regular(state.primary,tools.image.path,700*1024*1024).toLowerCase());
  const entries=[];
  const write=(name,data)=>{fs.writeFileSync(path.join(work,...name.split('/')),data,{flag:'wx'});entries.push({name,bytes:Buffer.byteLength(data),sha256:digest(data)});};
  for(const [name,entry] of [['serving_guest.py',pins.fixture],['web_runtime_fixture.py',pins.helper],['qualification-driver',pins.driver],['serving-linux.test',pins.test_elf],['source_catalog.json',pins.serving_manifest]]) write(name,fs.readFileSync(regular(state.primary,entry.path)));
  for(const pkg of state.packages.packages) write('packages/'+pkg.filename,fs.readFileSync(regular(state.primary,'.cache/alma-web-repositories/webrepo-20261005-php83/packages/'+pkg.filename)));
  const packageBytes=JSON.stringify(state.packages)+'\n';write('prepared-packages.json',packageBytes);
  const admission=buildAdmission(pins,nonce,packageBytes);
  write('admission.json',JSON.stringify(admission)+'\n');
  const script=`#!/bin/sh\nset -eu\nexec >/dev/ttyS0 2>&1\ntrap '/sbin/poweroff -f' EXIT\nmkdir -p /mnt/sifruno-serving /opt/sifruno-runtime-fixture/packages\nmount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-serving\nfor name in serving_guest.py web_runtime_fixture.py qualification-driver serving-linux.test source_catalog.json prepared-packages.json; do cp /mnt/sifruno-serving/$name /opt/sifruno-runtime-fixture/$name; done\ncp /mnt/sifruno-serving/packages/*.rpm /opt/sifruno-runtime-fixture/packages/\ncp /mnt/sifruno-serving/admission.json /run/sifruno-runtime-serving-admission\nchmod 0700 /opt/sifruno-runtime-fixture /opt/sifruno-runtime-fixture/packages\nchmod 0600 /opt/sifruno-runtime-fixture/*.py /opt/sifruno-runtime-fixture/*.json /opt/sifruno-runtime-fixture/packages/*.rpm /run/sifruno-runtime-serving-admission\nchmod 0700 /opt/sifruno-runtime-fixture/qualification-driver /opt/sifruno-runtime-fixture/serving-linux.test\nset +e\nenv -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I /opt/sifruno-runtime-fixture/serving_guest.py\nstatus=$?\necho SIFRUNO_RUNTIME_SERVING_EXIT ${nonce} $status\nexit $status\n`;
  write('user-data','#cloud-config\nusers: []\nssh_pwauth: false\ndisable_root: true\nwrite_files:\n  - path: /root/sifruno-runtime-serving.sh\n    permissions: \'0700\'\n    owner: root:root\n    content: |\n'+script.split('\n').map(l=>'      '+l).join('\n')+'\nruncmd:\n  - [sh, /root/sifruno-runtime-serving.sh]\n');
  write('meta-data',`instance-id: ${run}\nlocal-hostname: sifruno-runtime-serving\n`);write('network-config','version: 2\nethernets: {}\n');
  fs.writeFileSync(path.join(work,'payload-plan.json'),JSON.stringify({schema_version:1,entries}),{flag:'wx'});
  unchanged(state);
  const readback=JSON.parse(command(python,['-I',path.join(here,'make_iso.py'),state.primary,work],work,env,90000));assert(readback.entries===28 && readback.iso_readback.length===28);
  command(regular(state.primary,tools.qemu_img.path),['create','-f','qcow2','-F','qcow2','-b',image,path.join(work,'overlay.qcow2')],work,env,30000);
  const isoSHA=digest(fs.readFileSync(regular(work,'payload.iso',128*1024*1024)));
  const report={schema_version:1,run,nonce,scope:pins.scope,passed:false,native_serving_qualified:false,qemu_launched:false,evidence_kind:'preparation-only',production_activated:false,cpanel_compatibility_certified:false,source_inputs:state.inventory,runner_sources:state.self,python_tool_sha256:state.pythonSHA,payload:entries,admission,iso_readback:readback.iso_readback,iso_sha256:isoSHA,guest:null};
  const reportPath=path.join(work,'report.json');
  if(args[2]==='--prepare-only') {unchanged(state);fs.writeFileSync(reportPath,JSON.stringify(report,null,2),{flag:'wx'});console.log(reportPath);return;}
  unchanged(state);report.qemu_launched=true;report.evidence_kind='disposable-alma9-native-runtime-serving';
  const fd=fs.openSync(path.join(work,'serial.log'),'wx');let timedOut=false;
  const child=spawn(regular(state.primary,tools.qemu.path),qemuArgs(qdir,work),{cwd:qdir,env,windowsHide:true,stdio:['ignore','pipe','pipe']});
  const kill=()=>{try{if(child.exitCode===null)child.kill();}catch(e){report.cleanup_error=String(e.code||e.name||'ChildKillError');}};
  const abort=()=>{report.interrupted=true;kill();};process.on('SIGINT',abort);process.on('SIGTERM',abort);
  const timer=setTimeout(()=>{timedOut=true;kill();},600000);
  const capture=createCapture(b=>fs.writeSync(fd,b),kill);child.stdout.on('data',capture.accept);child.stderr.on('data',capture.accept);
  try {
    const exit=await new Promise(resolve=>{child.once('error',e=>{report.qemu_error=String(e.code||e.name||'ChildError');kill();});child.once('close',(code,signal)=>resolve({code,signal}));});
    report.qemu_exit=exit;report.timed_out=timedOut;report.output_limited=capture.outputLimited;report.capture_error=capture.error;
    assert(exit.code===0 && !timedOut && !capture.outputLimited && !capture.error && !report.interrupted && !report.qemu_error && !report.cleanup_error,'Serving guest/capture did not finish cleanly');
    unchanged(state);assert.equal(digest(fs.readFileSync(regular(work,'payload.iso',128*1024*1024))),isoSHA);
    for(const e of entries) pin(work,{path:e.name,sha256:e.sha256,bytes:e.bytes});
    report.guest=parseServingSerial(capture.data.toString('utf8'),nonce,pins,admission,state.packages);
    report.passed=true;report.native_serving_qualified=true;report.source_pins_unchanged=true;
  } catch(e) {report.failure=String(e.message).slice(0,500);process.exitCode=1;}
  finally {kill();clearTimeout(timer);process.off('SIGINT',abort);process.off('SIGTERM',abort);fs.closeSync(fd);report.serial_sha256=digest(capture.data);report.serial_bytes=capture.data.length;report.capture_error=capture.error;fs.writeFileSync(reportPath,JSON.stringify(report,null,2),{flag:'wx'});}
  console.log(reportPath);
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{console.error('Serving host admission/preparation failed');process.exitCode=1;});
