import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {digest, relative, regular, pin, portableSource, validateLayout, parseSerial, qemuArgs, createCapture} from './admission.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const pins = JSON.parse(fs.readFileSync(path.join(here, 'pins.json')));
const nonce = 'a'.repeat(24);
const output = t => [...t.required.flatMap(n => ['=== RUN   '+n, '--- PASS: '+n+' (0.01s)']), ...t.allowed_skips.flatMap(n => ['=== RUN   '+n, '--- SKIP: '+n+' (0.00s)']), 'PASS', ''].join('\n');
const guest = () => ({schema_version:1, nonce, kind: pins.scope, passed: true, daemon_serving_qualified:false,
  facts: {os: {ID: 'almalinux', VERSION_ID: '9.8'}, architecture: 'x86_64', kernel:'5.14.0-fixture', uid: [0,0,0,0], gid: [0,0,0,0], boot_id:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', selinux_enforce:'1', process_status:{Uid:'0 0 0 0',Gid:'0 0 0 0',Groups:'0',CapInh:'0'.repeat(16),CapPrm:'0'.repeat(16),CapEff:'0'.repeat(16),CapBnd:'0'.repeat(16),CapAmb:'0'.repeat(16),NoNewPrivs:'0',Seccomp:'0'}, filesystems:['/','/tmp','/opt/sifruno-runtime-mechanics'].map(p=>({path:p,type_options:'xfs rw',block_size:4096,available_bytes:1e9}))},
  tests: pins.tests.map(t => ({id:t.id, elf_sha256:t.sha256, exit_code:0, passed:true, passes:t.required, skips:t.allowed_skips, output_sha256:digest(output(t)), output_bytes:Buffer.byteLength(output(t)), arguments:['-test.v','-test.count=1','-test.timeout='+t.timeout,...(t.run?['-test.run',t.run]:[])], timed_out:false, output_limited:false}))});
const serial = g => 'boot\n'+pins.tests.map(t=>`SIFRUNO_RUNTIME_TEST_BEGIN_${nonce}_${t.id}\n${output(t)}SIFRUNO_RUNTIME_TEST_END_${nonce}_${t.id}\n`).join('')+`SIFRUNO_RUNTIME_REPORT_BEGIN_${nonce}\n${JSON.stringify(g)}\nSIFRUNO_RUNTIME_REPORT_END_${nonce}\nSIFRUNO_RUNTIME_EXIT_${nonce}_0\npoweroff\n`;
test('strict nonce-bound complete two-ELF report admits', () => assert.equal(parseSerial(serial(guest()), nonce, pins).passed, true));
test('echoed or duplicated report cannot pass', () => {
  assert.throws(() => parseSerial(serial(guest()) + serial(guest()), nonce, pins));
  assert.throws(() => parseSerial('PASS\n', nonce, pins));
  assert.throws(() => parseSerial(serial(guest()).replace(nonce, 'c'.repeat(24)), nonce, pins));
});
test('failed missing duplicate or skipped required test rejects', () => {
  for (const alter of [g => g.tests[0].exit_code = 1, g => g.tests[0].passes = g.tests[0].passes.slice(1), g => g.tests[1].passes = [...g.tests[1].passes, g.tests[1].passes[0]], g => g.tests[0].skips = [...g.tests[0].skips, pins.tests[0].required[0]], g => g.tests.pop(), g => g.tests[0].timed_out = true, g => g.tests[1].output_limited = true]) {
    const g=guest(); alter(g); assert.throws(() => parseSerial(serial(g), nonce, pins));
  }
});
test('wrong guest identity privilege or ELF rejects', () => {
  for (const alter of [g => g.facts.os.VERSION_ID = '8', g => g.facts.uid[1] = 1000, g => g.facts.gid[2] = 1000, g => g.facts.architecture = 'aarch64', g => g.tests[1].elf_sha256 = '0'.repeat(64)]) {
    const g=guest(); alter(g); assert.throws(() => parseSerial(serial(g), nonce, pins));
  }
});
test('schema, scope, canonical JSON and exact test arguments are mandatory', () => {
  for(const alter of [g=>delete g.schema_version,g=>g.schema_version=2,g=>g.daemon_serving_qualified=true,g=>g.extra=true,g=>g.tests[0].arguments.push('-test.run','^Nothing'),g=>g.tests[0].output_sha256='z'.repeat(64),g=>g.tests[0].output_bytes=524289]) { const g=guest();alter(g);assert.throws(()=>parseSerial(serial(g),nonce,pins)); }
  assert.throws(()=>parseSerial(serial(guest()).replace('"passed":true','"passed":false,"passed":true'),nonce,pins));
});
test('host recomputes raw transcript hashes and mandatory test outcomes', () => {
  const s=serial(guest());
  assert.throws(()=>parseSerial(s.replace('--- PASS: TestNamespaceRegistration','--- SKIP: TestNamespaceRegistration'),nonce,pins));
  assert.throws(()=>parseSerial(s.replace(`SIFRUNO_RUNTIME_TEST_BEGIN_${nonce}_worker\n`,''),nonce,pins));
  assert.throws(()=>parseSerial(s.replace('PASS\n','FAIL\n'),nonce,pins));
});
test('exit suffix and report framing are exact', () => {
  for (const text of [serial(guest()).replace(/_0\n/, '_1\n'), serial(guest()).replace(/_0\n/, '_00\n'), serial(guest()).replace('boot\n', `SIFRUNO_RUNTIME_EXIT_${nonce}_0\n`), serial(guest()).replace('"nonce"', '\n"nonce"')]) assert.throws(() => parseSerial(text, nonce, pins));
});
test('oversized serial rejects before parsing', () => assert.throws(() => parseSerial('x'.repeat(2*1024*1024+1), nonce, pins)));
test('path grammar refuses traversal absolute backslash and option injection', () => {
  for (const p of ['', '../file', '/file', 'a/../b', 'a//b', 'C:/file', 'a\\b', 'a\nfile', 'a,b']) assert.throws(() => relative(p));
  assert.equal(relative('.tools/linuxguest/qemu-20260811/share/bios.bin'), '.tools/linuxguest/qemu-20260811/share/bios.bin');
});
test('recorded absolute source is translated only to bounded logical sources', () => {
  const root='C:\\old\\workspace';
  assert.equal(portableSource(root, root+'\\internal\\hostaccounts\\store.go'), 'internal/hostaccounts/store.go');
  for(const p of ['C:\\outside\\store.go', root+'\\.state\\keys', root+'\\scripts\\evil.mjs']) assert.throws(() => portableSource(root,p));
});
test('actual hardlink and size/hash drift denied', () => {
  const parent = path.resolve(here, '../../.cache/hostwebruntime-mechanics-tests'); fs.mkdirSync(parent,{recursive:true});
  const dir=fs.mkdtempSync(path.join(parent,'admission-'));
  fs.writeFileSync(path.join(dir,'input'), 'frozen');
  assert.equal(pin(dir,{path:'input',sha256:digest('frozen')}).bytes,6);
  assert.throws(() => pin(dir,{path:'input',sha256:digest('changed')}));
  assert.throws(() => regular(dir,'input',5));
  fs.linkSync(path.join(dir,'input'),path.join(dir,'alias'));
  assert.throws(() => regular(dir,'input')); assert.throws(() => regular(dir,'alias'));
});
test('fixed QEMU profile has no NIC display shared folder or interactive monitor', () => {
  const args=qemuArgs('QEMU','OWNED');
  for(const flag of ['-nic','-display','-vga','-monitor']) assert.equal(args[args.indexOf(flag)+1],'none');
  assert(args.includes('-nodefaults') && args.includes('-no-user-config') && args.includes('-no-reboot'));
  assert.equal(args.filter(a=>a==='-drive').length,2);
  assert(!args.some(a=>/virtfs|fsdev|smb|hostfwd|tap|vnc|spice/.test(a)));
  assert(args.some(a=>a.includes('readonly=on')));
});
test('fresh portable canonical and exact assigned layout admitted without arbitrary roots', () => {
  const parent = path.resolve(here,'../../.cache/hostwebruntime-mechanics-tests');fs.mkdirSync(parent,{recursive:true});
  const primary=fs.mkdtempSync(path.join(parent,'layout-'));
  fs.writeFileSync(path.join(primary,'go.mod'),'module sifruno\n\ngo 1.27.0\n');
  const lab=path.join(primary,'lab/hostwebruntime-mechanics');fs.mkdirSync(lab,{recursive:true});
  assert.equal(validateLayout(primary,primary,lab),primary);
  const assigned=path.join(primary,'.worktrees/release-plan-sol'), worklab=path.join(assigned,'lab/hostwebruntime-mechanics');fs.mkdirSync(worklab,{recursive:true});
  fs.writeFileSync(path.join(assigned,'go.mod'),'module sifruno\n\ngo 1.27.0\n');
  assert.equal(validateLayout(primary,assigned,worklab),primary);
  assert.throws(()=>validateLayout(primary,path.join(primary,'.worktrees/other'),lab));
  assert.throws(()=>validateLayout(primary,primary,path.join(primary,'scripts')));
  fs.writeFileSync(path.join(primary,'go.mod'),'module sifruno\nmodule another\n');
  assert.throws(()=>validateLayout(primary,primary,lab));
});
test('actual directory junction is rejected without traversing its target', () => {
  const parent=path.resolve(here,'../../.cache/hostwebruntime-mechanics-tests');fs.mkdirSync(parent,{recursive:true});
  const dir=fs.mkdtempSync(path.join(parent,'junction-'));
  fs.mkdirSync(path.join(dir,'real'));fs.writeFileSync(path.join(dir,'real/input'),'frozen');
  fs.symlinkSync(path.join(dir,'real'),path.join(dir,'redirect'),'junction');
  assert.throws(()=>regular(dir,'redirect/input'));
});
test('serial disk-full and short writes cannot escape or leave owned child running', () => {
  for (const write of [()=>{throw Object.assign(new Error('fault injection'),{code:'ENOSPC'});},b=>b.length-1]) {
    let killed=0, writes=0;
    const capture=createCapture(b=>{writes++;return write(b);},()=>{killed++;});
    assert.doesNotThrow(()=>capture.accept(Buffer.from('incoming')));
    assert(capture.error);assert.equal(killed,1);assert.equal(capture.data.length,0);
    capture.accept(Buffer.from('later'));assert.equal(writes,1);assert.equal(killed,1);
  }
});
test('serial capture is bounded and stops only injected owned process callback', () => {
  let killed=0;
  const capture=createCapture(b=>b.length,()=>{killed++;},8);
  capture.accept(Buffer.from('12345678'));capture.accept(Buffer.from('9'));capture.accept(Buffer.from('ignored'));
  assert.equal(capture.data.toString(),'12345678');assert.equal(capture.outputLimited,true);assert.equal(capture.error,null);assert.equal(killed,1);
});
