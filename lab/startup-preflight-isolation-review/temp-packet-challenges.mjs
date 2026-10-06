// Pure synthetic packet data validation; no subprocess or native execution.
import assert from 'node:assert/strict';
import * as h from '../../../startup-preflight-guest-sol/scripts/verify-startup-preflight.mjs';
import {sample,binding} from './temp-fixture-builder.mjs';
let checks=0;const findings=[];const check=fn=>{fn();checks++;},refuse=fn=>check(()=>assert.throws(fn));
const packet=(role,stdout=Buffer.from('safe\n'),stderr=Buffer.alloc(0))=>({schema_version:1,nonce:binding.nonce,role,exit_code:0,timed_out:false,output_limit:false,stdout_bytes:stdout.length,stderr_bytes:stderr.length,stdout_sha256:h.digest(stdout),stderr_sha256:h.digest(stderr),stdout_base64:stdout.toString('base64'),stderr_base64:stderr.toString('base64')});
const framePacket=(p,bytes=Buffer.from(JSON.stringify(p)))=>`SIFRUNO_NATIVE_LOG_BEGIN_${binding.nonce}_${p.role}\n${bytes.toString('base64')}\nSIFRUNO_NATIVE_LOG_END_${binding.nonce}_${p.role}\n`;
const reportFrame=v=>`SIFRUNO_STARTUP_REPORT_BEGIN_${binding.nonce}\n${JSON.stringify(v)}\nSIFRUNO_STARTUP_REPORT_END_${binding.nonce}\nSIFRUNO_STARTUP_FIXTURE_EXIT_${binding.nonce}_${v.passed?0:1}\n`;
const core=packet('core'),review=packet('review'),logs=framePacket(core)+framePacket(review),guest=sample();
for(const [role,p] of [['core',core],['review',review]])Object.assign(guest[role+'_tests'],{stdout_sha256:p.stdout_sha256,stdout_bytes:p.stdout_bytes});
check(()=>h.parseSerial(logs+reportFrame(guest),binding));
check(()=>assert.deepEqual(h.decodePrivateTestLogs(logs,binding).map(x=>x.role),['core','review']));
for(const edit of [p=>p.nonce='c'.repeat(32),p=>p.role='foreign',p=>p.schema_version=true,p=>p.exit_code='0',p=>p.timed_out=1,p=>p.output_limit=1,p=>p.stdout_bytes++,p=>p.stderr_bytes++,p=>p.stdout_sha256='a'.repeat(64),p=>p.stderr_sha256='a'.repeat(64),p=>p.stdout_base64+='=',p=>p.stdout_base64='!',p=>p.extra='private']){const p=structuredClone(core);edit(p);refuse(()=>h.decodePrivateTestLogs(framePacket(p),binding));}
for(const bad of [logs+logs,framePacket(review),framePacket(review)+framePacket(core),logs.replace('LOG_BEGIN','LOG_\rBEGIN'),logs.replace('LOG_END','LOG_END_EXTRA'),logs.replace('\nSIFRUNO_NATIVE_LOG_END','\n\nSIFRUNO_NATIVE_LOG_END')])refuse(()=>h.decodePrivateTestLogs(bad,binding));
for(const edit of [p=>p.exit_code=1,p=>p.timed_out=true,p=>p.output_limit=true,p=>{p.stderr_base64='eA==';p.stderr_bytes=1;p.stderr_sha256=h.digest('x');}]){const p=structuredClone(core);edit(p);refuse(()=>h.parseSerial(framePacket(p)+framePacket(review)+reportFrame(guest),binding));}
refuse(()=>h.parseSerial(reportFrame(guest),binding));
refuse(()=>h.parseSerial(framePacket(core)+reportFrame(guest),binding));
const failure={schema_version:1,scope:'read_only_stock_then_NSS_only_adapted_fresh_startup_admission',nonce:binding.nonce,passed:false,failure:'test_family_execution',diagnostic:{phase:'review_tests',check_index:null,status:null,reason:null}};
check(()=>assert.deepEqual(h.decodeFailureSerial(reportFrame(failure),binding),failure));
check(()=>assert.deepEqual(h.decodeFailureSerial(logs+reportFrame(failure),binding),failure));
const childText=Buffer.from('SIFRUNO_STARTUP_REPORT_BEGIN_'+binding.nonce+'\nSIFRUNO_NATIVE_LOG_END_'+binding.nonce+'_review\nPRIVATE');
const arbitrary=framePacket(packet('core',childText));check(()=>assert.equal(h.decodePrivateTestLogs(arbitrary,binding)[0].stdout_bytes,childText.length));check(()=>assert(!arbitrary.includes('PRIVATE')&&!arbitrary.includes('SIFRUNO_STARTUP_')));
// Strict compact ASCII packet admission must preserve decoded bytes exactly.
const canonical=Buffer.from(JSON.stringify(core)),highBit=Buffer.from(canonical);highBit[0]|=0x80;
for(const index of [0,1,canonical.length-1]){const altered=Buffer.from(canonical);altered[index]|=0x80;refuse(()=>h.decodePrivateTestLogs(framePacket(core,altered),binding));}
refuse(()=>h.decodeFailureSerial(reportFrame(failure)+logs,binding));
refuse(()=>h.parseSerial(framePacket(core)+reportFrame(guest)+framePacket(review),binding));
const oversized=packet('core',Buffer.alloc(32769,'x'),Buffer.alloc(32769,'y'));refuse(()=>h.decodePrivateTestLogs(framePacket(oversized),binding));
const maximum=packet('core',Buffer.alloc(65536,'x'));check(()=>assert.equal(h.decodePrivateTestLogs(framePacket(maximum),binding)[0].stdout_bytes,65536));
let accepted=false;try{h.decodePrivateTestLogs(framePacket(core,highBit),binding);accepted=true;}catch{}
check(()=>assert.notDeepEqual(highBit,canonical));
if(accepted)findings.push({id:'packet_ascii_high_bit_alias',line:213,claim:'Outer Base64 can decode to a non-ASCII high-bit JSON byte which ASCII conversion masks; altered decoded bytes are admitted as the same compact packet.',synthetic_reproduced:true});
let postAccepted=false;try{h.parseSerial(reportFrame(guest)+logs,binding);postAccepted=true;}catch{}
if(postAccepted)findings.push({id:'private_packets_after_report_exit',line:213,claim:'Private packets after the startup report/exit are admitted; the decoder does not enforce the producer order.',synthetic_reproduced:true});
console.log(JSON.stringify({passed:true,checks,synthetic:true,native_observation:false,findings}));
