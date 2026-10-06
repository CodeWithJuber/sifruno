// Independent synthetic challenges. Importing the admitted driver never runs main.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const hash=raw=>createHash('sha256').update(raw).digest('hex');
const target=path.resolve(process.argv[2]);
assert.equal(hash(fs.readFileSync(target)),process.argv[3],'exact reviewed module bytes');
const {parseSerial,validateGuest,validateReviewAuthority,canonicalJSON}=await import(pathToFileURL(target).href);
const nonce='a'.repeat(32),sha='b'.repeat(64);
const core=['TestBrokerPathAdmissionFreshHomesReadOnly','TestBrokerPathAdmissionInvalidAndCancelledReadOnly','TestBrokerPathAdmissionLateFailuresReadOnly','TestBrokerPathAdmissionMissingUnderSetgidParentReadOnly','TestBrokerPathAdmissionOccupiedSocketReadOnly','TestBrokerPathAdmissionPositiveReadOnly','TestBrokerPathAdmissionReopenAndInterruptedBootstrap','TestDeclaredDirRejectsInheritedSetgidMode'];
const review=['TestIndependentBrokerDirectoryIdentity','TestIndependentBrokerFreshVersusNonemptyState','TestIndependentBrokerOptionBoundary','TestIndependentBrokerSetgidParent'];
const binding={nonce,hashes:{baseline:sha,candidate:sha,fixture:sha,core_test:sha,review_test:sha},reviewNames:review};
let next=1;
const item=(name,kind='directory',mode='0755',body=null)=>({path:name,kind,mode,uid:0,gid:0,inode:next++,device:1,nlink:kind==='directory'?2:1,bytes:body===null?4096:Buffer.byteLength(body),sha256:body===null?null:hash(body)});
const check=supported=>({schema_version:1,scope:'native_linux_account_host_policy',platform:'linux',supported,read_only:true,checks:[{id:'utilities',status:'pass',reason:'satisfied'},{id:'nss',status:supported?'pass':'refused',reason:supported?'satisfied':'files_only_nss_required'},{id:'useradd_defaults',status:supported?'pass':'refused',reason:supported?'satisfied':'mail_disabled_defaults_required'}],restrictions:['host_policy_only','controller_paths_state_not_checked','no_stock_host_or_cpanel_certification']});
function fixture(){
 const names=['homes_file','homes_symlink','homes_wrong_mode','unsafe_socket_parent','occupied_socket','fresh_shared_homes'];
 const conflicts=[];
 for(const name of names)for(const role of ['baseline','candidate']){
  const before=[item('.','directory','0700')];
  if(name==='homes_file')before.push(item('homes','file','0644','owned homes file sentinel\n'));
  if(name==='homes_symlink')before.push(item('homes','symlink','0777','/root/owned-fixture/target'),item('target'));
  if(name==='homes_wrong_mode')before.push(item('homes','directory','0700'));
  if(name==='unsafe_socket_parent')before.push(item('socket-parent','directory','0757'));
  if(name==='occupied_socket')before.push(item('socket-parent'),item('socket-parent/broker.sock','file','0644','owned occupied socket sentinel\n'));
  if(name==='fresh_shared_homes')before.push(item('homes'),item('homes/shared-home'),item('homes/shared-home/sentinel','file','0644','owned unrelated home sentinel\n'));
  const additions=role==='candidate'?[]:name.startsWith('homes_')?['state']:['unsafe_socket_parent','occupied_socket'].includes(name)?['homes','state']:['socket-parent','state','state/.sifruno-hostbroker','state/.sifruno-state','state/hostaccounts.db'];
  const after=structuredClone(before);
  for(const label of additions)after.push(item(label,label.includes('/')?'file':'directory',label.includes('/')?'0600':label==='state'?'0700':'0755',label.includes('/')?'synthetic metadata-only archive':null));
  if(additions.length)after[0].nlink++;
  after.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
  conflicts.push({name,role,adapted_policy:true,exit_code:1,before,after,added_paths:additions,preexisting_preserved:true,owned_child_exited:true});
 }
 const state=[item('.','directory','0700'),item('.sifruno-hostbroker','file','0600','synthetic marker'),item('.sifruno-state','file','0600','synthetic outer marker'),item('hostaccounts.db','file','0600','synthetic database')];
 const happy={adapted_policy:true,startup_socket_observed:true,inventory:{http_status:200,account_count:0,peer_uid:65534,response_sha256:hash('{"items":[]}\n')},sigterm_sent:true,exit_code:0,socket_removed:true,homes_empty:true,owned_children_exited:true,state_after:state};
 const ids=['nss','nss_authselect','useradd_defaults','login_defaults','passwd_metadata','group_metadata','groupadd','useradd','usermod','passwd_utility','chage','nologin'];
 const policies=ids.map(id=>({id,kind:'file',mode:'0644',bytes:10,sha256:sha}));
 const bytes={nss:'passwd: files\ngroup: files\nshadow: files\nhosts: files\n',useradd_defaults:'CREATE_MAIL_SPOOL=no\n'};
 const adapted=policies.map(row=>Object.hasOwn(bytes,row.id)?{id:row.id,kind:'file',mode:'0644',bytes:Buffer.byteLength(bytes[row.id]),sha256:hash(bytes[row.id])}:structuredClone(row));
 const tests=names=>({exit_code:0,stdout_sha256:sha,stdout_bytes:2048,test_names:names,skipped:false,owned_child_exited:true});
 return {schema_version:1,scope:'ADAPTED_disposable_linux_broker_path_observation',nonce,passed:true,profile:{distribution:'almalinux',version:'9.8',kernel:'synthetic-only',machine:'x86_64'},binary_sha256:{...binding.hashes},controller:{uid:65534,matching_local_passwd_records:1,account_created:false},policy_before:policies,policy_adapted:adapted,policy_after:structuredClone(adapted),adaptation:Object.entries(bytes).map(([id,body])=>({id,sha256:hash(body),mode:'0644',root_owned_regular:true})),stock_check:check(false),adapted_check:check(true),conflicts,happy_fresh_and_reopen:[happy,structuredClone(happy)],core_tests:tests([...core]),review_tests:tests([...review]),listeners_before:{count:14,sha256:sha},listeners_after:{count:14,sha256:sha},adapted_policy_unchanged:true,inputs_unchanged:true,account_created:false,account_mutation_requests:0,stock_provisioning_qualified:false,owned_children_exited:true};
}
const serial=row=>`opaque boot\nSIFRUNO_PATHS_REPORT_BEGIN_${nonce}\n${JSON.stringify(row)}\nSIFRUNO_PATHS_REPORT_END_${nonce}\nSIFRUNO_PATHS_FIXTURE_EXIT_${nonce}_0\n`;
let positive=0,negative=0;
const valid=fixture();assert(validateGuest(valid,binding).passed);positive++;
assert(parseSerial(serial(valid),binding).passed);positive++;
assert(parseSerial('\x1b[33mboot\x1b[0m\n'+serial(valid).replaceAll('\n','\r\n'),binding).passed);positive++;
const mutations=[
 ['stock alias',x=>x.scope='stock_linux_broker_path_observation'],
 ['foreign nonce',x=>x.nonce='c'.repeat(32)],
 ['foreign binary',x=>x.binary_sha256.review_test='c'.repeat(64)],
 ['raw content',x=>x.policy_text='unapproved raw policy'],
 ['policy side effect',x=>x.policy_after[3].sha256='c'.repeat(64)],
 ['third adaptation',x=>x.adaptation.push(structuredClone(x.adaptation[0]))],
 ['nonroot controller alias',x=>x.controller.uid=0],
 ['root request peer',x=>x.happy_fresh_and_reopen[0].inventory.peer_uid=0],
 ['inventory wrong body',x=>x.happy_fresh_and_reopen[0].inventory.response_sha256='c'.repeat(64)],
 ['no graceful shutdown',x=>x.happy_fresh_and_reopen[0].sigterm_sent=false],
 ['socket survives',x=>x.happy_fresh_and_reopen[1].socket_removed=false],
 ['marker drift',x=>x.happy_fresh_and_reopen[1].state_after[1].sha256='c'.repeat(64)],
 ['test skip',x=>x.review_tests.skipped=true],
 ['new missing setgid family',x=>x.review_tests.test_names.pop()],
 ['extra top-level test',x=>x.core_tests.test_names.push('TestUnrelated')],
 ['nonzero child',x=>x.core_tests.exit_code=1],
 ['cleanup failure',x=>x.conflicts[2].owned_child_exited=false],
 ['candidate root identity drift',x=>x.conflicts[1].after[0].inode++],
 ['candidate addition',x=>x.conflicts[1].after.push(item('state','directory','0700'))],
 ['wrong baseline additions',x=>x.conflicts[0].added_paths=[]],
 ['wrong role',x=>x.conflicts[0].role='candidate'],
 ['tree path alias',x=>x.conflicts[0].before[1].path='homes/../homes'],
 ['tree metadata unsafe integer',x=>x.conflicts[0].before[1].inode=Number.MAX_SAFE_INTEGER+1],
 ['fixed sentinel double drift',x=>{x.conflicts[0].before[1].sha256='c'.repeat(64);x.conflicts[0].after[1].sha256='c'.repeat(64);}],
 ['fixed sentinel double size drift',x=>{for(const rows of [x.conflicts[8].before,x.conflicts[8].after])rows.find(row=>row.path==='socket-parent/broker.sock').bytes++;}],
 ['listeners changed',x=>x.listeners_after.count++],
 ['provisioning overclaim',x=>x.stock_provisioning_qualified=true],
 ['account mutation',x=>x.account_mutation_requests=1],
];
for(const [name,mutate] of mutations){const value=structuredClone(valid);mutate(value);assert.throws(()=>validateGuest(value,binding),name);negative++;}
const raw=serial(valid);
for(const [name,changed] of [
 ['duplicate frame',raw+`SIFRUNO_PATHS_REPORT_BEGIN_${nonce}\n`],
 ['nonzero fixture exit',raw.replace('_0\n','_1\n')],
 ['unknown marker',raw+`SIFRUNO_PATHS_UNKNOWN_${nonce}\n`],
 ['embedded CR',raw.replace('REPORT_BEGIN','REPORT_BEG\rIN')],
 ['ANSI JSON',raw.replace(JSON.stringify(valid),'\x1b[32m'+JSON.stringify(valid)+'\x1b[0m')],
 ['duplicate nested field',raw.replace('"account_count":0','"account_count":0,"account_count":0')],
 ['case alias',raw.replace('"account_count":0','"Account_Count":0')],
 ['leading whitespace JSON',raw.replace(JSON.stringify(valid),' '+JSON.stringify(valid))],
 ['trailing whitespace JSON',raw.replace(JSON.stringify(valid),JSON.stringify(valid)+'\t')],
 ['missing end',raw.slice(0,raw.indexOf('SIFRUNO_PATHS_REPORT_END'))],
]){assert.throws(()=>parseSerial(changed,binding),name);negative++;}
for(const invalid of ['{"x":1,"x":1}','{"nested":{"x":1,"x":1}}','{"x":NaN}','{"x":Infinity}','{"x":1}garbage']){assert.throws(()=>canonicalJSON(invalid));negative++;}
const authority=JSON.parse(fs.readFileSync('lab/broker-paths-review/setgid-review.json','utf8'));
const originalBinary=authority.linux_challenges.binary;
assert.equal(validateReviewAuthority(authority,{bytes:originalBinary.bytes,sha256:originalBinary.sha256},review),authority);positive++;
for(const mutate of [x=>x.linux_challenges.binary.path='.cache/broker-paths/independent.test',x=>x.linux_challenges.binary.bytes++,x=>x.linux_challenges.binary.extra=true,x=>x.linux_challenges.executed=true,x=>x.linux_challenges.test_names.reverse(),x=>x.passed=false]){
 const changed=structuredClone(authority);mutate(changed);assert.throws(()=>validateReviewAuthority(changed,{bytes:originalBinary.bytes,sha256:originalBinary.sha256},review));negative++;
}
console.log(JSON.stringify({passed:true,synthetic:true,positive,negative,total:positive+negative,driver_sha256:process.argv[3],runtime_observed:false}));
