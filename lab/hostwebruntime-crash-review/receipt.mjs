// Independent file-only audit. This cannot create or certify a native run.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const hash = b => createHash('sha256').update(b).digest('hex');
const digest = value => hash(JSON.stringify(value));
const hex = x => assert.equal(typeof x === 'string' && /^[a-f0-9]{64}$/.test(x), true);
const id = x => assert.equal(typeof x === 'string' && /^[a-f0-9]{32}$/.test(x), true);
const same = (a,b) => assert.deepEqual(a,b);
const integer = (n,min=0,max=Number.MAX_SAFE_INTEGER) => assert(Number.isSafeInteger(n)&&n>=min&&n<=max);
const ROOT='/opt/sifruno-runtime-fixture';
export const digestJSON=digest;
export function expectedFixture() {
  const profile={Name:'restricted-chroot-v1',ManagedRoot:ROOT+'/managed',ManagedHomeRoot:ROOT+'/homes',FrontChroot:ROOT+'/front-jail',ApacheModuleRoot:'/usr/lib64/httpd/modules',BackendChrootRoot:ROOT+'/backend-jails',RuntimeRoot:ROOT+'/runtime',ApacheBinary:'/usr/sbin/httpd',FPMBinary:'/usr/sbin/php-fpm',TLSRoot:ROOT+'/tls',CAFile:ROOT+'/tls/ca.pem',FrontendIP:'127.0.0.1',FrontendPort:18082,BackendPort:18443,FrontUID:48,FrontGID:48,ControllerUID:2000};
  const active=[['a','webalpha','alpha.test',20001],['b','webbravo','bravo.test',20002]].map(([i,username,domain,uid])=>({id:i.repeat(32),username,domain,home:ROOT+'/homes/'+username,public_html:ROOT+'/homes/'+username+'/public_html',state:'active',uid,gid:uid,revision:1,created_at:'2026-10-05T00:00:00Z',updated_at:'2026-10-05T00:00:00Z'}));
  const current=structuredClone(active);current[1].state='suspended';current[1].revision=2;current[1].updated_at='2026-10-05T00:00:00.000000001Z';
  return {profile,active,current,profileSHA:digest(profile),activeSHA:digest(active),currentSHA:digest(current)};
}
function exact(x, fields) {
  assert(x && typeof x === 'object' && !Array.isArray(x));
  same(Object.keys(x).sort(), [...fields].sort());
}
function ordered(x,fields) {exact(x,fields);same(Object.keys(x),fields);}
function identity(x) {
  ordered(x, ['generation_id','profile_sha256','snapshot_sha256','bundle_sha256','denied']);
  assert(x.generation_id === '' || /^[a-f0-9]{32}$/.test(x.generation_id));
  for(const k of ['profile_sha256','snapshot_sha256','bundle_sha256']) hex(x[k]);
  assert.equal(typeof x.denied, 'boolean');
}
function inspection(n) {
  const base=['state_sha256','revision','last_operation_id','configured'];
  exact(n,[...base,...['pending','completed','observed','completed_apply'].filter(k=>k in n)]);
  hex(n.state_sha256);integer(n.revision,0,3);id(n.last_operation_id);identity(n.configured);
  assert(!('pending' in n),'No native pending work in this completed/dead-window lab');
  if('observed' in n)identity(n.observed);
  if('completed_apply' in n)applyCompletion(n.completed_apply);
  if('completed' in n)repairBinding(n.completed);
}
function applyIntent(b) {
  return digest({Domain:'sifruno-apply-completion-v1',Version:b.version,Kind:b.kind,
    OperationID:b.operation_id,OriginalRevision:b.original_revision,
    NativeBaseRevision:b.native_base_revision,Before:b.before,After:b.after,
    AdmittedStateSHA256:b.admitted_state_sha256,InputsSHA256:b.inputs_sha256,BootID:b.boot_id});
}
function applyCompletion(c) {
  ordered(c,['binding','result_revision']); const b=c.binding;
  ordered(b,['version','kind','operation_id','original_revision','native_base_revision','before','after','intent_sha256','admitted_state_sha256','inputs_sha256','boot_id']);
  assert.equal(b.version,1);assert.equal(b.kind,'apply');id(b.operation_id);
  identity(b.before);identity(b.after);assert.notEqual(b.before.generation_id,b.after.generation_id);
  for(const k of ['intent_sha256','admitted_state_sha256','inputs_sha256'])hex(b[k]);
  assert(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(b.boot_id));
  assert.equal(b.intent_sha256,applyIntent(b));
  assert.equal(b.original_revision,b.native_base_revision);
  assert.equal(c.result_revision,b.native_base_revision+1);
}
function repairBinding(b) {
  ordered(b,['operation_id','attempt_id','original_revision','base_revision','before','after','source','target','intent_sha256','admitted_state_sha256']);
  id(b.operation_id);id(b.attempt_id);for(const k of ['before','after','source','target'])identity(b[k]);
  assert.equal(b.target.denied,true);hex(b.intent_sha256);hex(b.admitted_state_sha256);
  assert.equal(b.intent_sha256,digest({Domain:'sifruno-denied-repair-v1',OperationID:b.operation_id,
    OriginalRevision:b.original_revision,AttemptID:b.attempt_id,BaseRevision:b.base_revision,
    Before:b.before,After:b.after,Source:b.source,Target:b.target}));
}
function history(h) {
  assert(Array.isArray(h) && h.length>=6 && h.length<=128);
  let previous='';
  for(const [i,e] of h.entries()) {
    const base=['sequence','operation_id','phase','revision','before','after','actor','reason','at','previous_sha256','sha256'];
    exact(e,[...base,...('repair' in e ? ['repair']:[]),...('apply_checkpoint' in e ? ['apply_checkpoint']:[])]);
    assert.equal(e.sequence,i+1);assert.equal(e.previous_sha256,previous);hex(e.sha256);
    id(e.operation_id);identity(e.before);identity(e.after);
    for(const [k,max]of [['actor',120],['reason',500]])assert(typeof e[k]==='string'&&e[k].length>0&&e[k].length<=max&&e[k].trim()===e[k]&&!/[\x00-\x1f\x7f]/.test(e[k]));
    assert(typeof e.at==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(e.at)&&!Number.isNaN(Date.parse(e.at)));
    // The Event struct's field order is part of Go's hashed JSON encoding.
    const canonical=Object.fromEntries([...base,...('repair' in e ? ['repair']:[]),...('apply_checkpoint' in e ? ['apply_checkpoint']:[])].map(k=>[k,k==='sha256'?'':e[k]]));
    assert.equal(e.sha256,digest(canonical),'Independent journal hash');previous=e.sha256;
    if(e.apply_checkpoint) {
      ordered(e.apply_checkpoint,['completion','inspected_state_sha256','counter_advance_only','counter_advanced']);
      applyCompletion(e.apply_checkpoint.completion);hex(e.apply_checkpoint.inspected_state_sha256);
    }
    if(e.repair) {
      ordered(e.repair,['binding',...('committed_revision' in e.repair?['committed_revision']:[]),...('counter_advance_only' in e.repair?['counter_advance_only']:[])]);
      repairBinding(e.repair.binding);
    }
  }
}
export function auditDriver(r, pins) {
  exact(r,['schema_version','fixture_only','execution_kind','run_id','nonce','driver_sha256','input_sha256','profile_sha256','intended_generations','observations','probes','crash','checkpoints','history','inventory_sha256','source_catalog_sha256','prerequisites','stage','passed','shutdown_passed','close_passed','listeners_extinct','input_stable','selinux_stable','worker_evidence','observed_namespace_ids','namespaces_extinct']);
  assert.equal(r.schema_version,2);assert.equal(r.fixture_only,true);
  assert.equal(r.execution_kind,'native-linux-controller-crash-driver');assert.equal(r.stage,'complete');
  for(const k of ['passed','shutdown_passed','close_passed','listeners_extinct','input_stable','selinux_stable','namespaces_extinct'])assert.equal(r[k],true);
  for(const k of ['driver_sha256','input_sha256','profile_sha256','source_catalog_sha256','inventory_sha256'])hex(r[k]);
  id(r.run_id);id(r.nonce);
  exact(pins,['nonce','driverSHA','catalogSHA','inputSHA']);
  assert(/^[a-f0-9]{24}$/.test(pins.nonce));for(const k of ['driverSHA','catalogSHA','inputSHA'])hex(pins[k]);
  assert.equal(r.run_id,hash('sifruno-crash:'+pins.nonce).slice(0,32));
  assert.equal(r.driver_sha256,pins.driverSHA);assert.equal(r.source_catalog_sha256,pins.catalogSHA);assert.equal(r.input_sha256,pins.inputSHA);
  const expected=expectedFixture();assert.equal(r.profile_sha256,expected.profileSHA);assert.equal(r.inventory_sha256,expected.currentSHA);
  exact(r.prerequisites,['selinux_enforce','NoNewPrivs','CapEff','CapPrm','CapBnd','CapAmb','CapInh','network_admin_raw_absent','kernel_release']);
  assert.equal(r.prerequisites.selinux_enforce,'1');assert.equal(r.prerequisites.network_admin_raw_absent,'true');assert(['0','1'].includes(r.prerequisites.NoNewPrivs));
  assert(typeof r.prerequisites.kernel_release==='string'&&/^[\x20-\x7e]{1,128}$/.test(r.prerequisites.kernel_release));
  for(const k of ['CapEff','CapPrm','CapBnd','CapAmb','CapInh']) {const x=r.prerequisites[k];assert(typeof x==='string'&&/^[a-fA-F0-9]{16}$/.test(x));assert.equal(BigInt('0x'+x)&((1n<<12n)|(1n<<13n)),0n);}
  const death=r.crash,b=death.boundary,n=b.native,a=n.completed_apply;
  exact(death,['boundary','parent_pid','child_pid','child_start','owned_child','signal','wait_signaled','native_metadata_stable','journal_before_sha256','journal_after_sha256','strict_observe_rejected','listeners_extinct','namespaces_extinct']);
  exact(b,['nonce','pid','start','operation_id','before','after','native']);inspection(n);
  for(const k of ['owned_child','wait_signaled','native_metadata_stable','strict_observe_rejected','listeners_extinct','namespaces_extinct'])assert.equal(death[k],true);
  assert.equal(death.signal,9);assert(Number.isSafeInteger(death.parent_pid)&&death.parent_pid>1);
  assert(Number.isSafeInteger(death.child_pid)&&death.child_pid>1);assert.notEqual(death.child_pid,death.parent_pid);
  assert.equal(b.pid,death.child_pid);assert.equal(b.start,death.child_start);assert(/^[1-9][0-9]{0,19}$/.test(b.start));
  assert.equal(b.nonce,r.nonce);hex(death.journal_before_sha256);same(death.journal_before_sha256,death.journal_after_sha256);
  applyCompletion(a);assert.equal(a.result_revision,1);assert.equal(a.binding.native_base_revision,0);
  same(a.binding.before,b.before);same(a.binding.after,b.after);assert.equal(a.binding.operation_id,b.operation_id);
  same(n.configured,b.after);same(n.observed,b.after);assert.equal(n.revision,1);assert.equal(n.last_operation_id,b.operation_id);
  assert(!n.pending&&!n.completed);hex(n.state_sha256);
  assert.equal(b.before.generation_id,'');assert.equal(b.before.denied,true);assert.equal(b.after.denied,false);
  for(const x of [b.before,b.after]) {assert.equal(x.profile_sha256,expected.profileSHA);assert.equal(x.snapshot_sha256,expected.activeSHA);}
  history(r.history);const h=r.history;
  const old=h.filter(e=>e.operation_id===b.operation_id),cpEvents=old.filter(e=>e.phase==='apply_checkpoint');
  assert.equal(cpEvents.length,1);assert.equal(old[0].phase,'intended');assert.equal(old[0].revision,0);
  same(old[0].before,b.before);same(old[0].after,b.after);
  assert(!old.some(e=>e.phase==='committed'),'Original active target must remain uncommitted');
  const cp=cpEvents[0];assert.equal(cp.revision,1);same(cp.apply_checkpoint.completion,a);
  same(cp.apply_checkpoint.inspected_state_sha256,n.state_sha256);
  assert.equal(cp.apply_checkpoint.counter_advance_only,true);assert.equal(cp.apply_checkpoint.counter_advanced,true);
  const repair=old.filter(e=>e.phase==='repair_completed');assert.equal(repair.length,1);
  const repaired=repair[0];assert.equal(repaired.revision,2);assert.equal(repaired.repair.committed_revision,2);
  const rb=repaired.repair.binding;assert.equal(rb.base_revision,1);assert.equal(rb.original_revision,0);
  assert.equal(rb.admitted_state_sha256,n.state_sha256);
  same(rb.before,b.before);same(rb.after,b.after);same(rb.source,b.after);same(rb.target,repaired.after);
  assert.notEqual(rb.target.generation_id,b.after.generation_id);assert.equal(rb.target.snapshot_sha256,r.inventory_sha256);
  const finish=h.at(-1);assert.equal(finish.phase,'committed');assert.equal(finish.revision,3);
  assert.notEqual(finish.operation_id,b.operation_id);same(finish.before,rb.target);
  assert.equal(finish.after.denied,false);assert.equal(finish.after.snapshot_sha256,r.inventory_sha256);
  assert.notEqual(finish.after.generation_id,rb.target.generation_id);
  same(h.map(e=>e.phase),['intended','apply_checkpoint','repair_intended','recovery_required','recovery_required','recovery_required','repair_completed','intended','committed']);
  same(h.map(e=>e.revision),[0,1,1,1,1,1,2,2,3]);
  for(const e of h.slice(0,7)){same(e.before,b.before);assert.equal(e.operation_id,b.operation_id);}
  const retained=cp.apply_checkpoint;
  for(const e of h.slice(2,7)){same(e.apply_checkpoint,retained);assert(e.repair);same(e.repair.binding,rb);}
  assert(!h[7].repair&&!h[7].apply_checkpoint&&!finish.repair&&!finish.apply_checkpoint);
  same(h[7].before,rb.target);same(h[7].after,finish.after);assert.equal(h[7].operation_id,finish.operation_id);
  const stages=['after_kill','apply_checkpoint','repeated_checkpoint','reopened_checkpoint','stale_refused','denied_repaired','healthy_repair_refused','reopened_denied','selective_apply'];
  assert.equal(r.checkpoints.length,stages.length);
  for(const [i,c] of r.checkpoints.entries()) {
    exact(c,['stage','coordinator','native','history_sha256']);inspection(c.native);
    exact(c.coordinator,['revision','phase',...(i<5?['pending_operation']:['current'])]);
    assert.equal(c.stage,stages[i]);hex(c.history_sha256);
    assert.equal(c.history_sha256,digest(h.slice(0,[1,4,5,6,6,7,7,7,9][i])),'Checkpoint must bind exact durable history prefix');
    const rev=i===0?0:i<5?1:i<8?2:3;
    assert.equal(c.coordinator.revision,rev);assert.equal(c.native.revision,i===0?1:rev);
    if(i<5) {
      assert.equal(c.coordinator.phase,i===0?'applying':'recovery_required');
      assert(!c.coordinator.current);assert.equal(c.coordinator.pending_operation,b.operation_id);
      assert.equal(c.native.state_sha256,n.state_sha256);same(c.native.completed_apply,a);assert(!c.native.observed);
      same(c.native.configured,b.after);assert.equal(c.native.last_operation_id,b.operation_id);assert(!c.native.completed);
    } else {
      assert.equal(c.coordinator.phase,'idle');
      assert(!c.coordinator.pending_operation);same(c.coordinator.current,i<8?rb.target:finish.after);
      same(c.native.observed,c.coordinator.current);same(c.native.configured,c.coordinator.current);
      if(i<8) {same(c.native.completed,rb);assert(!c.native.completed_apply);assert.equal(c.native.last_operation_id,b.operation_id);}
      else {applyCompletion(c.native.completed_apply);const next=c.native.completed_apply.binding;assert.equal(next.native_base_revision,2);same(next.before,rb.target);same(next.after,finish.after);assert.equal(next.operation_id,finish.operation_id);assert.equal(next.admitted_state_sha256,r.checkpoints[7].native.state_sha256);assert.equal(next.inputs_sha256,a.binding.inputs_sha256);assert.equal(next.boot_id,a.binding.boot_id);assert.equal(c.native.completed_apply.result_revision,3);assert.equal(c.native.last_operation_id,finish.operation_id);assert(!c.native.completed);}
    }
  }
  same(r.checkpoints[5].native,r.checkpoints[6].native);same(r.checkpoints[5].native,r.checkpoints[7].native);
  same(r.intended_generations,[b.before,b.after,rb.target,finish.after]);
  for(const g of r.intended_generations)assert.equal(g.profile_sha256,expected.profileSHA);
  same(r.observations,[{stage:'before_kill',identity:b.after},...stages.slice(5).map(stage=>({stage,identity:stage==='selective_apply'?finish.after:rb.target}))]);
  assert(Array.isArray(r.probes)&&r.probes.length===10);
  for(const [i,p] of r.probes.entries()) {
    exact(p,['account_id','kind','status','bytes','sha256','contract_passed','namespace_pid']);
    const j=i%5, stage=i<5?'repair_denied':'selective',a=expected.active[Math.floor(j/2)];
    assert.equal(p.kind,stage+(j===4?'/foreign.test':j%2===0?'/index.html':'/probe.php'));assert.equal(p.account_id,j===4?'':a.id);
    assert.equal(p.contract_passed,true);integer(p.bytes,1,128*1024);hex(p.sha256);
    if(i===5||i===6) {
      assert.equal(p.status,200);let body;
      if(i===5){assert.equal(p.namespace_pid,0);body='SIFRUNO_STATIC_webalpha\n';}
      else {integer(p.namespace_pid,2,4194304);body=`SIFRUNO_PHP_webalpha\nSELF=readable\nHOST=denied\nSIBLING=denied\nPID=${p.namespace_pid}\n`;}
      assert.equal(p.bytes,Buffer.byteLength(body));assert.equal(p.sha256,hash(body));
    } else {assert.equal(p.status,403);assert.equal(p.namespace_pid,0);}
  }
  assert(Array.isArray(r.worker_evidence)&&r.worker_evidence.length===1);
  const w=r.worker_evidence[0];exact(w,['account_id','host_pid','namespace_pid','namespace','uid','gid','groups','capabilities','root','start']);
  assert.equal(w.account_id,expected.active[0].id);integer(w.host_pid,2,4194304);integer(w.namespace_pid,2,4194304);assert.equal(w.namespace_pid,r.probes[6].namespace_pid);
  integer(w.namespace,1);same(w.uid,[20001,20001,20001,20001]);same(w.gid,[20001,20001,20001,20001]);
  assert(w.groups===null||Array.isArray(w.groups)&&w.groups.length<=1&&w.groups.every(n=>n===20001));
  exact(w.capabilities,['CapEff','CapPrm','CapInh','CapAmb']);for(const x of Object.values(w.capabilities))assert.equal(x,'0000000000000000');
  assert.equal(w.root,ROOT+'/backend-jails/'+expected.active[0].id);assert(typeof w.start==='string'&&/^[1-9][0-9]{0,19}$/.test(w.start));
  assert(Array.isArray(r.observed_namespace_ids)&&r.observed_namespace_ids.length===9);
  r.observed_namespace_ids.forEach(n=>integer(n,1));assert.equal(new Set(r.observed_namespace_ids).size,r.observed_namespace_ids.length);assert(r.observed_namespace_ids.includes(w.namespace));
  return r;
}

if(process.argv[1]===fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length,4,'Usage: node receipt.mjs <exact-driver-report.json> <audit-pins.json>');
  const raw=fs.readFileSync(process.argv[2]);assert(raw.length>0&&raw.length<=65536);
  const text=raw.toString('utf8'),r=JSON.parse(text);assert.equal(JSON.stringify(r),text,'Compact duplicate-free exact report required');
  const pins=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
  auditDriver(r,pins);console.log(JSON.stringify({classification:'independent-file-only-receipt-audit',native_execution_performed:false,passed:true,driver_report_sha256:hash(raw)}));
}
