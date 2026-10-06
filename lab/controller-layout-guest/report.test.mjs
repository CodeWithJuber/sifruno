import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {CASES, ROLES, ROOT_TESTS, decodeLayoutSerial} from './report.mjs';

const nonce = '12'.repeat(16), pin = '34'.repeat(32);
const log = ROOT_TESTS.map(name => `--- PASS: ${name} (0.01s)`).join('\n') + '\nPASS\n';
function fixture() {
  const unchanged = {before_sha256:pin, after_sha256:pin};
  return {schema_version:1, scope:'fresh_existing_controller_layout_NSS_only_adapted_Alma9_8', nonce, passed:true,
    stock:{...unchanged,exit_code:1,report:{ready:false}}, plan:{...unchanged,exit_code:0,report:{read_only:true}},
    apply:{exit_code:0,report:{read_only:false,directories:ROLES.map(role=>({role,action:'created'}))}},
    prepared_directories:ROLES.map((role,i)=>({role,uid:i===3?65534:0,mode:['0700','0755','0755','0700'][i],empty:true})),
    repeat:{...unchanged,exit_code:0,report:{directories:ROLES.map(role=>({role,action:'admitted_existing'}))}},
    conflicts:CASES.map(name=>({...unchanged,case:name,exit_code:name==='unknown_argument'?2:1,owned_child_exited:true})),
    core_tests:{exit_code:0,skips:0,required:ROOT_TESTS,stdout_sha256:createHash('sha256').update(log).digest('hex'),stdout_base64:Buffer.from(log).toString('base64')},
    stock_mail_and_identities_unchanged:true,inputs_unchanged:true,account_created:false,socket_created:false};
}
const frame = raw => `boot\nSIFRUNO_LAYOUT_BEGIN_${nonce}\n${raw}\nSIFRUNO_LAYOUT_END_${nonce}\nSIFRUNO_LAYOUT_EXIT_${nonce}_0\nhalt\n`;
test('synthetic valid receipt survives exact framing and canonical logs',()=>assert.equal(decodeLayoutSerial(frame(JSON.stringify(fixture())),nonce).passed,true));
test('duplicate, early, malformed or failing same-nonce exit is refused',()=>{
  const serial=frame(JSON.stringify(fixture()));
  for(const value of [serial+`SIFRUNO_LAYOUT_EXIT_${nonce}_0\n`, `SIFRUNO_LAYOUT_EXIT_${nonce}_0\n`+serial,
    serial.replace(`SIFRUNO_LAYOUT_EXIT_${nonce}_0`,`SIFRUNO_LAYOUT_EXIT_${nonce}_1`), serial+`SIFRUNO_LAYOUT_EXIT_${nonce}_0_suffix\n`,
    serial.replace(`SIFRUNO_LAYOUT_EXIT_${nonce}_0\n`,'' ).replace('boot\n',`boot\nSIFRUNO_LAYOUT_EXIT_${nonce}_0\n`)]) assert.throws(()=>decodeLayoutSerial(value,nonce));
});
test('duplicate or reordered report frames and duplicate JSON keys are refused',()=>{
  const raw=JSON.stringify(fixture()),serial=frame(raw);
  for(const value of [serial+serial,serial.replace(`SIFRUNO_LAYOUT_BEGIN_${nonce}`,`SIFRUNO_LAYOUT_END_${nonce}`),frame(raw.replace('"passed":true','"passed":false,"passed":true'))]) assert.throws(()=>decodeLayoutSerial(value,nonce));
});
test('noncanonical Base64, skipped native tests and missing final PASS are refused',()=>{
  for(const text of [log.replace('--- PASS:', '--- SKIP:'),log.replace('\nPASS\n','\n'),log.replace(ROOT_TESTS[0],'Injected-'+ROOT_TESTS[0])]) {
    const f=fixture();f.core_tests.stdout_base64=Buffer.from(text).toString('base64');f.core_tests.stdout_sha256=createHash('sha256').update(text).digest('hex');assert.throws(()=>decodeLayoutSerial(frame(JSON.stringify(f)),nonce));
  }
  const f=fixture();f.core_tests.stdout_base64+=' ';assert.throws(()=>decodeLayoutSerial(frame(JSON.stringify(f)),nonce));
});
test('missing roles, altered owned state, and identity/network side effects are refused',()=>{
  for(const mutate of [f=>f.apply.report.directories.pop(),f=>f.repeat.after_sha256='56'.repeat(32),f=>f.conflicts[0].after_sha256='56'.repeat(32),f=>f.account_created=true,f=>f.socket_created=true,f=>f.prepared_directories[3].uid=0]) {
    const f=fixture();mutate(f);assert.throws(()=>decodeLayoutSerial(frame(JSON.stringify(f)),nonce));
  }
});
