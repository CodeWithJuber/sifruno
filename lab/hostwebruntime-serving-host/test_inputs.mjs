import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {layout,logicalSource,preparedPackages,validateLineage,filePin,verifySources} from './inputs.mjs';
const here=path.dirname(fileURLToPath(import.meta.url)),owner=path.resolve(here,'../..'),primary=path.dirname(owner).endsWith('.worktrees')?path.resolve(owner,'../..'):owner;
const pins=JSON.parse(fs.readFileSync(path.join(here,'pins.json'))),tools=JSON.parse(fs.readFileSync(path.join(here,'../hostwebruntime-mechanics/pins.json')));
const read=p=>JSON.parse(fs.readFileSync(path.join(primary,p)));
test('actual pinned18 package manifest and prepared lineage admitted',()=>{
  const p=preparedPackages(read(pins.package_manifest.path));assert.equal(p.packages.length,18);
  validateLineage(read(pins.prepared_host_report.path),read(pins.prepared_install_report.path),pins,tools.image);
});
test('package count name/hash/byte/path duplicates cannot grant payload authority',()=>{
  for(const change of [m=>m.packages.pop(),m=>m.packages[0].file='packages/../evil.rpm',m=>m.packages[0].source='.state/key',m=>m.packages[0].checksum_sha256='z'.repeat(64),m=>m.packages[0].bytes++,m=>m.packages[1]=m.packages[0],m=>m.signing_key_fingerprint='foreign']) {
    const m=read(pins.package_manifest.path);change(m);assert.throws(()=>preparedPackages(m));
  }
});
test('changed backing image package lineage NIC policy or signatures closes admission',()=>{
  for(const change of [h=>h.passed=false,h=>h.overlay_sha256='0'.repeat(64),h=>h.external_nic=true,h=>h.host_shares=true,h=>h.production_mutated=true,h=>h.package_manifest.packages=17]){
    const h=read(pins.prepared_host_report.path);change(h);assert.throws(()=>validateLineage(h,read(pins.prepared_install_report.path),pins,tools.image));
  }
  for(const change of [i=>i.privilege_profile.after.selinux_enforce=0,i=>i.privilege_profile.before.network_capabilities_present=['CAP_NET_ADMIN'],i=>i.signatures[0].key_id='FOREIGN',i=>i.installed.pop()]){
    const i=read(pins.prepared_install_report.path);change(i);assert.throws(()=>validateLineage(read(pins.prepared_host_report.path),i,pins,tools.image));
  }
});
test('recorded source roots include only fixed canonical/executor/module paths',()=>{
  const root='C:\\past\\primary';
  assert.equal(logicalSource(root,root+'\\.cache\\go-mod\\golang.org\\x\\sys@v0.48.0\\unix\\syscall.go'),'.cache/go-mod/golang.org/x/sys@v0.48.0/unix/syscall.go');
  for(const p of [root+'\\.state\\key',root+'\\scripts\\evil.mjs','C:\\foreign\\main.go',root+'\\.cache\\go-mod\\golang.org\\x\\sys@v9\\unix\\evil.go'])assert.throws(()=>logicalSource(root,p));
});
test('actual serving sources donor overlay and selected dependency bytes checked',()=>{
  let count=0;const m=verifySources(primary,pins,p=>{filePin(primary,p);count++;});assert.equal(m.dependency_count,90);assert.equal(count,132);
});
test('portable exact canonical and assigned layout admitted, alternate roots refused',()=>{
  const parent=path.join(owner,'.cache/hostwebruntime-serving-host-tests');fs.mkdirSync(parent,{recursive:true});const p=fs.mkdtempSync(path.join(parent,'layout-'));fs.writeFileSync(path.join(p,'go.mod'),'module sifruno\n');
  const canonical=path.join(p,'lab/hostwebruntime-serving-host');fs.mkdirSync(canonical,{recursive:true});assert.equal(layout(p,p,canonical),p);
  const work=path.join(p,'.worktrees/release-plan-sol'),lab=path.join(work,'lab/hostwebruntime-serving-host');fs.mkdirSync(lab,{recursive:true});fs.writeFileSync(path.join(work,'go.mod'),'module sifruno\n');assert.equal(layout(p,work,lab),p);
  assert.throws(()=>layout(p,path.join(p,'.worktrees/other'),lab));assert.throws(()=>layout(p,p,path.join(p,'scripts')));
  fs.writeFileSync(path.join(p,'go.mod'),'module other\n');assert.throws(()=>layout(p,p,canonical));
});
