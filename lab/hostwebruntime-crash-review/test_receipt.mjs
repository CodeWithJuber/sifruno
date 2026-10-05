// Synthetic protocol tests only. None of these values are native observations.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createHash} from 'node:crypto';
import {auditDriver,expectedFixture,digestJSON as digest} from './receipt.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
// A report is JSON: repeated checkpoint values are independent decoded objects.
const clone=x=>JSON.parse(JSON.stringify(x));
export function synthetic() {
  const f=expectedFixture(),nonce='a'.repeat(24),op='c'.repeat(32),later='e'.repeat(32),attempt='f'.repeat(32);
  const identity=(generation_id,snapshot_sha256,denied)=>({generation_id,profile_sha256:f.profileSHA,snapshot_sha256,bundle_sha256:hash('synthetic-bundle-'+generation_id),denied});
  const before=identity('',f.activeSHA,true),after=identity('1'.repeat(32),f.activeSHA,false),denied=identity('2'.repeat(32),f.currentSHA,true),selective=identity('3'.repeat(32),f.currentSHA,false);
  function completion(operation_id,revision,before,after) {
    const b={version:1,kind:'apply',operation_id,original_revision:revision,native_base_revision:revision,before,after,intent_sha256:'',admitted_state_sha256:hash('synthetic-admitted-'+revision),inputs_sha256:hash('synthetic-inputs'),boot_id:'11111111-1111-1111-1111-111111111111'};
    b.intent_sha256=digest({Domain:'sifruno-apply-completion-v1',Version:b.version,Kind:b.kind,OperationID:b.operation_id,OriginalRevision:b.original_revision,NativeBaseRevision:b.native_base_revision,Before:b.before,After:b.after,AdmittedStateSHA256:b.admitted_state_sha256,InputsSHA256:b.inputs_sha256,BootID:b.boot_id});
    return {binding:b,result_revision:revision+1};
  }
  const completed=completion(op,0,before,after),final=completion(later,2,denied,selective),stateSHA=hash('synthetic-active-state');
  const rb={operation_id:op,attempt_id:attempt,original_revision:0,base_revision:1,before,after,source:after,target:denied,intent_sha256:'',admitted_state_sha256:stateSHA};
  rb.intent_sha256=digest({Domain:'sifruno-denied-repair-v1',OperationID:op,OriginalRevision:0,AttemptID:attempt,BaseRevision:1,Before:before,After:after,Source:after,Target:denied});
  const checkpoint={completion:completed,inspected_state_sha256:stateSHA,counter_advance_only:true,counter_advanced:true};
  const h=[];
  function event(phase,revision,current,repair=false,cp=false) {
    const e={sequence:h.length+1,operation_id:h.length<7?op:later,phase,revision,before:h.length<7?before:denied,after:current,actor:'fixture-root',reason:'synthetic parser-only receipt',at:'2026-10-05T00:00:00Z',previous_sha256:h.at(-1)?.sha256||'',sha256:''};
    if(repair)e.repair={binding:rb,...(phase==='repair_completed'?{committed_revision:2}:{})};
    if(cp)e.apply_checkpoint=checkpoint;
    e.sha256=digest(e);h.push(e);
  }
  event('intended',0,after);event('apply_checkpoint',1,after,false,true);
  event('repair_intended',1,denied,true,true);for(let i=0;i<3;i++)event('recovery_required',1,after,true,true);
  event('repair_completed',2,denied,true,true);event('intended',2,selective);event('committed',3,selective);
  const native={state_sha256:stateSHA,revision:1,last_operation_id:op,configured:after,completed_apply:completed};
  const stages=['after_kill','apply_checkpoint','repeated_checkpoint','reopened_checkpoint','stale_refused','denied_repaired','healthy_repair_refused','reopened_denied','selective_apply'];
  const checkpoints=stages.map((stage,i)=>({stage,coordinator:i<5?{revision:i===0?0:1,pending_operation:op,phase:i===0?'applying':'recovery_required'}:{revision:i<8?2:3,current:i<8?denied:selective,phase:'idle'},native:i<5?native:i<8?{state_sha256:hash('synthetic-denied-state'),revision:2,last_operation_id:op,configured:denied,completed:rb,observed:denied}:{state_sha256:hash('synthetic-selective-state'),revision:3,last_operation_id:later,configured:selective,observed:selective,completed_apply:final},history_sha256:digest(h.slice(0,[1,4,5,6,6,7,7,7,9][i]))}));
  const probes=Array.from({length:10},(_,i)=>{
    const j=i%5,stage=i<5?'repair_denied':'selective',a=f.active[Math.floor(j/2)];
    const p={account_id:j===4?'':a.id,kind:stage+(j===4?'/foreign.test':j%2===0?'/index.html':'/probe.php'),status:403,bytes:1,sha256:hash('synthetic-denied-body'),contract_passed:true,namespace_pid:0};
    if(i===5||i===6){const b=i===5?'SIFRUNO_STATIC_webalpha\n':'SIFRUNO_PHP_webalpha\nSELF=readable\nHOST=denied\nSIBLING=denied\nPID=7\n';p.status=200;p.bytes=Buffer.byteLength(b);p.sha256=hash(b);p.namespace_pid=i===6?7:0;}return p;
  });
  const r={schema_version:2,fixture_only:true,execution_kind:'native-linux-controller-crash-driver',run_id:hash('sifruno-crash:'+nonce).slice(0,32),nonce:'b'.repeat(32),driver_sha256:hash('synthetic-driver'),input_sha256:hash('synthetic-input'),profile_sha256:f.profileSHA,intended_generations:[before,after,denied,selective],observations:[{stage:'before_kill',identity:after},...stages.slice(5).map(stage=>({stage,identity:stage==='selective_apply'?selective:denied}))],probes,crash:{boundary:{nonce:'b'.repeat(32),pid:101,start:'123',operation_id:op,before,after,native:{...native,observed:after}},parent_pid:100,child_pid:101,child_start:'123',owned_child:true,signal:9,wait_signaled:true,native_metadata_stable:true,journal_before_sha256:hash('synthetic-db'),journal_after_sha256:hash('synthetic-db'),strict_observe_rejected:true,listeners_extinct:true,namespaces_extinct:true},checkpoints,history:h,inventory_sha256:f.currentSHA,source_catalog_sha256:hash('synthetic-catalog'),prerequisites:{selinux_enforce:'1',NoNewPrivs:'0',CapEff:'0'.repeat(16),CapPrm:'0'.repeat(16),CapBnd:'0'.repeat(16),CapAmb:'0'.repeat(16),CapInh:'0'.repeat(16),network_admin_raw_absent:'true',kernel_release:'synthetic-no-native-run'},stage:'complete',passed:true,shutdown_passed:true,close_passed:true,listeners_extinct:true,input_stable:true,selinux_stable:true,worker_evidence:[{account_id:f.active[0].id,host_pid:200,namespace_pid:7,namespace:1005,uid:[20001,20001,20001,20001],gid:[20001,20001,20001,20001],groups:null,capabilities:{CapEff:'0'.repeat(16),CapPrm:'0'.repeat(16),CapInh:'0'.repeat(16),CapAmb:'0'.repeat(16)},root:'/opt/sifruno-runtime-fixture/backend-jails/'+f.active[0].id,start:'456'}],observed_namespace_ids:[1001,1002,1003,1004,1005],namespaces_extinct:true};
  return {r:clone(r),pins:{nonce,driverSHA:r.driver_sha256,catalogSHA:r.source_catalog_sha256,inputSHA:r.input_sha256}};
}
test('synthetic complete success schema passes; does not execute a guest',()=>{const {r,pins}=synthetic();assert.equal(auditDriver(r,pins),r);});
const mutations={
  'stale driver source':r=>r.driver_sha256='0'.repeat(64),
  'stale catalog':r=>r.source_catalog_sha256='0'.repeat(64),
  'stale input':r=>r.input_sha256='0'.repeat(64),
  'unbound host run':r=>r.run_id='0'.repeat(32),
  'unknown top field':r=>r.extra=true,
  'signal was TERM':r=>r.crash.signal=15,
  'unowned child':r=>r.crash.owned_child=false,
  'PID reuse':r=>r.crash.boundary.start='124',
  'nonce substitution':r=>r.crash.boundary.nonce='c'.repeat(32),
  'journal moved at death':r=>r.crash.journal_after_sha256='0'.repeat(64),
  'native not terminal':r=>r.crash.boundary.native.pending={},
  'native fake intent':r=>r.crash.boundary.native.completed_apply.binding.intent_sha256='0'.repeat(64),
  'aliased native field':r=>r.crash.boundary.native.Revision=1,
  'original active adopted':r=>r.checkpoints[1].coordinator.current=r.intended_generations[1],
  'counter advanced twice':r=>r.checkpoints[2].coordinator.revision=2,
  'checkpoint consumed-only missing':r=>r.history[1].apply_checkpoint.counter_advance_only=false,
  'wrong prefix proof':r=>r.checkpoints[3].history_sha256=r.checkpoints[2].history_sha256,
  'broken event digest':r=>r.history[4].sha256='0'.repeat(64),
  'reopen native changed':r=>r.checkpoints[7].native.state_sha256='0'.repeat(64),
  'stale current inventory':r=>r.inventory_sha256=r.intended_generations[1].snapshot_sha256,
  'all-denied repair serves tenant':r=>r.probes[0].status=200,
  'selective bravo serves tenant':r=>r.probes[8].status=200,
  'unknown host serves tenant':r=>r.probes[9].status=200,
  'selective PHP hash forged':r=>r.probes[6].sha256='0'.repeat(64),
  'selective PHP PID unbound':r=>r.probes[6].namespace_pid=8,
  'final worker root leaked':r=>r.worker_evidence[0].root='/',
  'final worker UID leaked':r=>r.worker_evidence[0].uid[3]=0,
  'final worker capability leaked':r=>r.worker_evidence[0].capabilities.CapAmb='0'.repeat(15)+'1',
  'worker namespace not retained':r=>r.observed_namespace_ids=[1,2,3,4,5],
  'duplicate namespace':r=>r.observed_namespace_ids.push(r.observed_namespace_ids[0]),
  'cleanup failed':r=>r.namespaces_extinct=false,
  'crash namespace remained':r=>r.crash.namespaces_extinct=false,
  'network capability inherited':r=>r.prerequisites.CapBnd='0000000000001000',
};
for(const [name,mutation]of Object.entries(mutations))test('reject '+name,()=>{const {r,pins}=synthetic();mutation(r);assert.throws(()=>auditDriver(r,pins));});
function rechain(r) {
  r.history.forEach((e,i)=>{e.previous_sha256=i?r.history[i-1].sha256:'';e.sha256='';e.sha256=digest(e);});
  r.checkpoints.forEach((c,i)=>c.history_sha256=digest(r.history.slice(0,[1,4,5,6,6,7,7,7,9][i])));
}
test('forged consumed checkpoint refused even with recomputed valid event chain',()=>{
  const {r,pins}=synthetic();for(const e of r.history)if(e.apply_checkpoint)e.apply_checkpoint.counter_advance_only=false;
  rechain(r);assert.throws(()=>auditDriver(r,pins));
});
test('original commit refused even with recomputed valid event chain',()=>{
  const {r,pins}=synthetic();r.history[0].phase='committed';rechain(r);assert.throws(()=>auditDriver(r,pins));
});
