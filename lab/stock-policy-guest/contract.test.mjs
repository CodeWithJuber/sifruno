// Pure synthetic receipt/admission tests; imports never launch a native guest.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {canonicalJSON,validateCheck,validateGuest,parseSerial,admitted,child} from '../../scripts/verify-stock-policy.mjs';

const nonce='1'.repeat(32),hash='2'.repeat(64),binding={nonce,hashes:{baseline:hash,candidate:hash,fixture:hash}};
const check={schema_version:1,scope:'native_linux_account_host_policy',platform:'linux',supported:false,read_only:true,checks:[{id:'utilities',status:'pass',reason:'satisfied'},{id:'nss',status:'refused',reason:'files_only_nss_required'},{id:'useradd_defaults',status:'refused',reason:'mail_disabled_defaults_required'}],restrictions:['host_policy_only','controller_paths_state_not_checked','no_stock_host_or_cpanel_certification']};
function guest(){const policies=['nss','nss_authselect','useradd_defaults','login_defaults','passwd_metadata','group_metadata','groupadd','useradd','usermod','passwd_utility','chage','nologin'].map(id=>({id,kind:'file',mode:'0644',bytes:123,sha256:hash}));return {schema_version:1,scope:'disposable_stock_linux_policy_observation',nonce,passed:true,profile:{distribution:'almalinux',version:'9.8',kernel:'synthetic-test-only',machine:'x86_64'},binary_sha256:{...binding.hashes},controller:{uid:65534,matching_local_passwd_records:1,account_created:false},policy_before:policies,policy_after:structuredClone(policies),check_host:structuredClone(check),check_host_exit:1,baseline:{exit_code:1,declared_directory_exists:[true,true,true],declared_directory_modes:['0700','0755','0755'],socket_exists:false,store_created:false,owned_child_exited:true},candidate:{exit_code:1,declared_directory_exists:[false,false,false],declared_directory_modes:[null,null,null],socket_exists:false,store_created:false,owned_child_exited:true},listeners_before:{count:1,sha256:hash},listeners_after:{count:1,sha256:hash},policy_unchanged:true,inputs_unchanged:true,account_created:false,policy_rewritten:false,owned_children_exited:true};}
const frame=value=>`synthetic boot\nSIFRUNO_STOCK_REPORT_BEGIN_${nonce}\n${JSON.stringify(value)}\nSIFRUNO_STOCK_REPORT_END_${nonce}\nSIFRUNO_STOCK_FIXTURE_EXIT_${nonce}_0\n`;
test('canonical JSON rejects nested duplicates, trailing bytes and truncation',()=>{
 for(const raw of ['{"check":{"id":"nss","id":"nss"}}','{"passed":true,"passed":true}','{"passed":true} false','{"passed":','{"v":NaN}'])assert.throws(()=>canonicalJSON(raw));
 assert.deepEqual(canonicalJSON('{"safe":true}\n'),{safe:true});
});
test('check DTO binds order/refusal/scope and exact fields',()=>{
 assert.equal(validateCheck(check),check);
 for(const mutate of [x=>x.checks.reverse(),x=>x.supported=true,x=>x.checks[1].reason='satisfied',x=>x.raw_policy='forbidden',x=>x.restrictions.pop(),x=>x.checks[0].username='forbidden',x=>x.read_only=false]){const copy=structuredClone(check);mutate(copy);assert.throws(()=>validateCheck(copy));}
});
test('strict nonce framing refuses foreign marker aliases/duplicates/exit mismatches',()=>{
 const valid=frame(guest());assert.equal(parseSerial(valid,binding).passed,true);
 for(const raw of [valid+`SIFRUNO_STOCK_FIXTURE_EXIT_${nonce}_0\n`,valid.replace(nonce,'f'.repeat(32)),valid.replace('_0\n','_1\n'),valid.replace('REPORT_BEGIN_','REPORT_BEGIN_ALIAS_'),valid.replace(`\nSIFRUNO_STOCK_REPORT_END_${nonce}`,'')])assert.throws(()=>parseSerial(raw,binding));
 assert.equal(parseSerial('\x1b[32mdecorated boot\x1b[0m\n'+valid,binding).passed,true);
 assert.equal(parseSerial(valid.replaceAll('\n','\r\n'),binding).passed,true);
 for(const raw of [valid.replace('REPORT_BEGIN_','REPORT_BEG\rIN_'),valid.replace('"passed":true','"pas\rsed":true'),valid.replace('"almalinux"','"alma\rlinux"'),valid.replace('"passed":true','"passed":\rtrue'),valid.replace(`REPORT_END_${nonce}`,`REPORT_END_${nonce.slice(0,16)}\r${nonce.slice(16)}`)])assert.throws(()=>parseSerial(raw,binding));
 assert.throws(()=>parseSerial(valid.replace('"passed":true','"passed":\x1b[32mtrue'),binding));
 assert.throws(()=>parseSerial(valid.replace(JSON.stringify(guest()),'\x1b[32m'+JSON.stringify(guest())+'\x1b[0m'),binding));
});
test('report fails closed on identity, hash, policy mutation and child cleanup',()=>{
 for(const mutate of [x=>x.nonce='f'.repeat(32),x=>x.binary_sha256.candidate='3'.repeat(64),x=>x.policy_after[2].sha256='3'.repeat(64),x=>x.controller.matching_local_passwd_records=2,x=>x.controller.uid=0,x=>x.candidate.declared_directory_exists[0]=true,x=>x.baseline.store_created=true,x=>x.owned_children_exited=false,x=>x.candidate.owned_child_exited=false,x=>x.listeners_after.count=2,x=>x.policy_before[0].bytes=Infinity,x=>x.profile.untrusted_extra=true]){const value=guest();mutate(value);assert.throws(()=>validateGuest(value,binding));}
});
test('filesystem admission rejects traversal/link/oversize and requires single regular file',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'stock-policy-synthetic-'));try{const okay=path.join(root,'owned.txt');fs.writeFileSync(okay,'safe');assert.equal(admitted(root,okay),okay);assert.throws(()=>admitted(root,path.join(root,'../foreign.txt')));assert.throws(()=>admitted(root,okay,2));fs.linkSync(okay,path.join(root,'alias.txt'));assert.throws(()=>admitted(root,okay));assert.throws(()=>admitted(root,root));}finally{fs.rmSync(root,{recursive:true});}
});
test('bounded owned Node child exits on output cap and timeout',async()=>{
 const env={SystemRoot:process.env.SystemRoot||process.env.SYSTEMROOT};
 const good=await child(process.execPath,['-e','process.stdout.write("synthetic")'],{env,timeout:5000,maximum:128});assert.equal(good.code,0);assert(good.owned_child_exited);
 const capped=await child(process.execPath,['-e','process.stdout.write("x".repeat(100000))'],{env,timeout:5000,maximum:64});assert(capped.output_limit&&capped.owned_child_exited);
 const timed=await child(process.execPath,['-e','setTimeout(()=>{},5000)'],{env,timeout:50});assert(timed.timedout&&timed.owned_child_exited);
});
