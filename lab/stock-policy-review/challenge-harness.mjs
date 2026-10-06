// Independent synthetic challenge of the admitted producer parser only.
// No tool, guest, process, network or host-policy observation is performed.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';

const file=resolve(process.argv[2]);
const raw=readFileSync(file),sha=createHash('sha256').update(raw).digest('hex');
assert.match(process.argv[3],/^[0-9a-f]{64}$/);
assert.equal(sha,process.argv[3],'parser source changed before import');
const {parseSerial}=await import(pathToFileURL(file));
const nonce='0123456789abcdef0123456789abcdef';
const hashes={baseline:'1'.repeat(64),candidate:'2'.repeat(64),fixture:'3'.repeat(64)};
const ids=['nss','nss_authselect','useradd_defaults','login_defaults','passwd_metadata','group_metadata','groupadd','useradd','usermod','passwd_utility','chage','nologin'];
const before=ids.map(id=>({id,kind:'file',mode:'0644',bytes:12,sha256:'4'.repeat(64)}));
const guest={schema_version:1,scope:'disposable_stock_linux_policy_observation',nonce,passed:true,
 profile:{distribution:'almalinux',version:'9.8',kernel:'synthetic_kernel',machine:'x86_64'},binary_sha256:hashes,
 controller:{uid:65534,matching_local_passwd_records:1,account_created:false},policy_before:before,policy_after:structuredClone(before),
 check_host:{schema_version:1,scope:'native_linux_account_host_policy',platform:'linux',supported:false,read_only:true,
  checks:[{id:'utilities',status:'pass',reason:'satisfied'},{id:'nss',status:'refused',reason:'files_only_nss_required'},{id:'useradd_defaults',status:'refused',reason:'mail_disabled_defaults_required'}],
  restrictions:['host_policy_only','controller_paths_state_not_checked','no_stock_host_or_cpanel_certification']},check_host_exit:1,
 baseline:{exit_code:1,declared_directory_exists:[true,true,true],declared_directory_modes:['0700','0755','0755'],socket_exists:false,store_created:false,owned_child_exited:true},
 candidate:{exit_code:1,declared_directory_exists:[false,false,false],declared_directory_modes:[null,null,null],socket_exists:false,store_created:false,owned_child_exited:true},
 listeners_before:{count:0,sha256:'5'.repeat(64)},listeners_after:{count:0,sha256:'5'.repeat(64)},policy_unchanged:true,inputs_unchanged:true,account_created:false,policy_rewritten:false,owned_children_exited:true};
const begin=`SIFRUNO_STOCK_REPORT_BEGIN_${nonce}`,end=`SIFRUNO_STOCK_REPORT_END_${nonce}`,exit=`SIFRUNO_STOCK_FIXTURE_EXIT_${nonce}_0`;
const frame=(value=guest)=>`${begin}\n${JSON.stringify(value)}\n${end}\n${exit}\n`;
const binding={nonce,hashes};let passes=0;
for(const input of [frame(),frame().replaceAll('\n','\r\n'),`\x1b[32mboot\x1b[0m\n${frame()}`]){assert.deepEqual(parseSerial(input,binding),guest);passes++;}
const negatives=[];
const mutate=fn=>{const value=structuredClone(guest);fn(value);return frame(value);};
negatives.push(['duplicate_json',frame().replace('"passed":true','"passed":true,"passed":true')]);
negatives.push(['nested_duplicate',frame().replace('"id":"nss"','"id":"nss","id":"nss"')]);
negatives.push(['embedded_cr_marker',frame().replace('REPORT_BEGIN','REPORT_\rBEGIN')]);
negatives.push(['embedded_cr_report',frame().replace('"supported"','"supp\rorted"')]);
negatives.push(['ansi_report_prefix',frame().replace(`${begin}\n`,`${begin}\n\x1b[32m`).replace(`\n${end}`,`\x1b[0m\n${end}`)]);
negatives.push(['extra_marker',frame()+begin+'\n']);
negatives.push(['unknown_marker',frame()+`SIFRUNO_STOCK_UNKNOWN_${nonce}\n`]);
negatives.push(['nonzero_fixture_exit',frame().replace(exit,exit.slice(0,-1)+'1')]);
negatives.push(['unknown_raw_field',mutate(v=>{v.raw_configuration='synthetic_private';})]);
negatives.push(['wrong_nonce',mutate(v=>{v.nonce='0'.repeat(32);})]);
negatives.push(['wrong_binary',mutate(v=>{v.binary_sha256.candidate='f'.repeat(64);})]);
negatives.push(['wrong_policy_after',mutate(v=>{v.policy_after[0].sha256='f'.repeat(64);})]);
negatives.push(['duplicate_policy_id',mutate(v=>{v.policy_before[1].id='nss';v.policy_after=structuredClone(v.policy_before);})]);
negatives.push(['policy_size_bound',mutate(v=>{v.policy_before[0].bytes=4194305;v.policy_after=structuredClone(v.policy_before);})]);
negatives.push(['swapped_checks',mutate(v=>{v.check_host.checks.reverse();})]);
negatives.push(['candidate_directory_created',mutate(v=>{v.candidate.declared_directory_exists[0]=true;})]);
negatives.push(['owned_cleanup_false',mutate(v=>{v.owned_children_exited=false;})]);
negatives.push(['listeners_changed',mutate(v=>{v.listeners_after.count=1;})]);
const accepted=[];
for(const [name,input] of negatives){try{parseSerial(input,binding);accepted.push(name);}catch{passes++;}}
console.log(JSON.stringify({schema_version:1,kind:'independent_synthetic_stock_guest_parser_challenges',source_sha256:sha,positive_cases:3,negative_cases:negatives.length,passed_cases:passes,unexpectedly_admitted:accepted,native_observation:false}));
assert.deepEqual(accepted,[],'producer admitted invalid serial/report evidence');
