// Pure failure decoder challenges; historical success builder remains unchanged.
import assert from 'node:assert/strict';
import * as h from '../../../startup-preflight-guest-sol/scripts/verify-startup-preflight.mjs';
const nonce='b'.repeat(32),binding={nonce},copy=x=>structuredClone(x);
let checks=0;const check=f=>{f();checks++;},refuse=f=>check(()=>assert.throws(f));
const failed={schema_version:1,scope:'read_only_stock_then_NSS_only_adapted_fresh_startup_admission',nonce,passed:false,failure:'startup_order_reason',diagnostic:{phase:'ancestor_untrusted_nontraversable',check_index:0,status:'refused',reason:h.STARTUP_REASONS[0]}};
const frame=v=>`opaque boot\nSIFRUNO_STARTUP_REPORT_BEGIN_${nonce}\n${JSON.stringify(v)}\nSIFRUNO_STARTUP_REPORT_END_${nonce}\nSIFRUNO_STARTUP_FIXTURE_EXIT_${nonce}_1\n`;
check(()=>assert.deepEqual(h.decodeFailureSerial(frame(failed),binding),failed));
check(()=>assert.deepEqual(h.decodeFailureSerial(frame(failed).replaceAll('\n','\r\n'),binding),failed));
const generic=copy(failed);Object.assign(generic.diagnostic,{phase:'core_tests',check_index:null,status:null,reason:null});check(()=>h.validateFailure(generic,binding));
const historical=copy(failed);delete historical.diagnostic;check(()=>h.validateFailure(historical,binding));
for(const change of [v=>v.passed=true,v=>v.nonce='c'.repeat(32),v=>v.schema_version=true,v=>v.failure='private_code',v=>v.raw='/private',v=>v.diagnostic.phase='/private',v=>v.diagnostic.check_index=true,v=>v.diagnostic.check_index=-1,v=>v.diagnostic.check_index=9,v=>v.diagnostic.status='/private',v=>v.diagnostic.reason='/private',v=>v.diagnostic.extra='/private',v=>v.diagnostic.check_index=null]){const v=copy(failed);change(v);refuse(()=>h.validateFailure(v,binding));}
const raw=frame(failed);
for(const bad of [raw+raw,raw.replace('REPORT_BEGIN','REPORT_\rBEGIN'),raw.replace('REPORT_END','REPORT_END_EXTRA'),raw.replace('_1\n','_0\n'),raw.replace(nonce,'c'.repeat(32)),raw.replace('"passed":false','"passed":false,"passed":false'),raw.replace('{"schema_version"',' {"schema_version"'),raw.replace('{"schema_version"','\x1b[0m{"schema_version"'),raw.replace('\nSIFRUNO_STARTUP_REPORT_END','\n\nSIFRUNO_STARTUP_REPORT_END')])refuse(()=>h.decodeFailureSerial(bad,binding));
refuse(()=>h.parseSerial(raw,binding));
// Existing independent pure success challenges include all previous schema joins.
await import('./decoder-challenges.mjs');
console.log(JSON.stringify({passed:true,checks,synthetic:true,native_observation:false}));
