// Read-only independent audit of a separately executed service-accounts receipt.
// No subprocess, HTTP, guest, account utility or credential access.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL,fileURLToPath} from 'node:url';

const [workerArg,reportArg,expectedSHA,outputArg]=process.argv.slice(2);
const worker=fs.realpathSync(workerArg),primary=path.resolve(worker,'../..');
assert.equal(path.basename(worker),'service-accounts-guest-sol');
const candidate=path.join(primary,'.worktrees/service-accounts-integration');
const reportFile=fs.realpathSync(reportArg);
assert(reportFile.startsWith(worker+path.sep));
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const reportRaw=fs.readFileSync(reportFile);assert.equal(hash(reportRaw),expectedSHA);
const r=JSON.parse(reportRaw);
assert.equal(r.schema_version,1);assert.equal(r.scope,'NSS_ADAPTED_stock_mail_service_account_lifecycle');
assert.equal(r.passed,true);assert.equal(r.native_observation,true);assert.equal(r.failure,null);
assert.equal(r.source_base,'392700489d49f13810923586a94eef6b48ec9cf6');
assert.equal(r.candidate_build_commit,'4ada64ff2a902fbce9949fff93600b6116c692c7');
assert.equal(r.candidate_build_authority,'root_supplied_frozen_binary_and_source_manifest');
assert.equal(r.image_sha256,'6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b');
assert.equal(r.image_signature_verified,true);
assert.equal(r.external_nic,false);assert.equal(r.host_shares,false);assert.equal(r.shared_dependency_inputs_read_only,true);
assert.equal(r.inputs_unchanged,true);
assert.deepEqual(r.role_mapping,{'payload/panelctl':'baseline-hostbroker','payload/hostbroker':'candidate-hostbroker','payload/qualifier.py':'new-NSS-only-service-account-fixture','payload/core.test':'reviewed-root-core-tests','payload/authority.test':'independent-review-tests'});
assert.deepEqual(r.limits,{qemu_seconds:600,qemu_output_bytes:2097152,broker_seconds:60,broker_output_bytes:16384,peer_request_seconds:50,peer_socket_seconds:45,check_host_output_bytes:8192,test_output_bytes:65536,test_seconds:20});
assert.equal(r.qemu.exit_code,0);assert.equal(r.qemu.signal,null);assert.equal(r.qemu.timed_out,false);assert.equal(r.qemu.output_limit,false);assert.equal(r.qemu.owned_child_exited,true);
assert(Number.isSafeInteger(r.qemu.output_bytes)&&r.qemu.output_bytes>0&&r.qemu.output_bytes<=2097152);
assert.deepEqual(r.cleanup,{owned_qemu_exited:true,no_live_process_mutation:true,no_host_listener_created:true,disposable_overlay_retained:true});
const roots={primary,baseline:worker,candidate,go:path.join(primary,'.tools/go'),modules:path.join(primary,'.cache/go-mod'),python:'C:/Users/Administrator/AppData/Local/Programs/Python/Python312'};
const norm=value=>path.resolve(value).toLowerCase();
function admitted(base,label) {
 assert(typeof label==='string'&&label&&!path.isAbsolute(label)&&!label.includes('\\')&&!label.split('/').some(part=>['','.','..'].includes(part)));
 const file=path.join(base,label);let current=base;
 for(const part of label.split('/')) {current=path.join(current,part);assert(!fs.lstatSync(current).isSymbolicLink()&&norm(fs.realpathSync(current))===norm(current));}
 const metadata=fs.lstatSync(file);assert(metadata.isFile()&&metadata.nlink===1);return file;
}
async function streamingSHA(file){const digest=createHash('sha256');for await(const chunk of fs.createReadStream(file))digest.update(chunk);return digest.digest('hex');}
assert(Array.isArray(r.source_catalog)&&r.source_catalog.length===1948);
assert.equal(hash(JSON.stringify(r.source_catalog)),r.source_catalog_sha256);
const labels=new Set();let joins=0;
for(const item of r.source_catalog) {
 assert.deepEqual(Object.keys(item).sort(),['bytes','namespace','path','sha256']);
 assert(Object.hasOwn(roots,item.namespace));assert(Number.isSafeInteger(item.bytes)&&item.bytes>=0&&item.bytes<=700*1024*1024);
 assert.match(item.sha256,/^[0-9a-f]{64}$/);const key=(item.namespace+'/'+item.path).toLowerCase();assert(!labels.has(key));labels.add(key);
 const file=admitted(roots[item.namespace],item.path);assert.equal(fs.statSync(file).size,item.bytes);assert.equal(await streamingSHA(file),item.sha256);joins++;
}
const candidateSources=r.source_catalog.filter(x=>x.namespace==='candidate'&&(x.path==='go.mod'||x.path==='go.sum'||/^(cmd|internal)\/.*\.go$/.test(x.path))).sort((a,b)=>`${a.namespace}/${a.path}`.localeCompare(`${b.namespace}/${b.path}`,'en'));
assert.equal(hash(JSON.stringify(candidateSources)),r.candidate_source_catalog_sha256);
function inventory(base){const files=['go.mod','go.sum'];const walk=folder=>{for(const entry of fs.readdirSync(folder,{withFileTypes:true})){const file=path.join(folder,entry.name);assert(!fs.lstatSync(file).isSymbolicLink());if(entry.isDirectory())walk(file);else if(file.endsWith('.go'))files.push(path.relative(base,file).replaceAll('\\','/'));}};walk(path.join(base,'cmd'));walk(path.join(base,'internal'));return files.sort();}
assert.deepEqual(candidateSources.map(x=>x.path).sort(),inventory(candidate));
assert.deepEqual(r.source_catalog.filter(x=>x.namespace==='baseline'&&(x.path==='go.mod'||x.path==='go.sum'||/^(cmd|internal)\/.*\.go$/.test(x.path))).map(x=>x.path).sort(),inventory(worker));
const manifestPin=r.source_catalog.find(x=>x.namespace==='candidate'&&x.path==='.cache/service-accounts/go-source-inputs.json');
assert(manifestPin&&manifestPin.sha256===r.candidate_build_manifest_sha256);
const runDir=path.join(worker,'.cache/alma9-qualification',r.run_id);
const hostFile=admitted(worker,path.relative(worker,path.join(runDir,'host-harness-source.mjs')).replaceAll('\\','/'));
const hostPin=r.source_catalog.find(x=>x.namespace==='baseline'&&x.path==='scripts/verify-service-accounts.mjs');
assert(hostPin&&hash(fs.readFileSync(hostFile))===hostPin.sha256);
const parser=await import(pathToFileURL(hostFile));
const serialFile=admitted(worker,path.relative(worker,path.join(runDir,'serial-private.log')).replaceAll('\\','/'));
const serialRaw=fs.readFileSync(serialFile);assert(serialRaw.length<=2097152);
assert.equal(serialRaw.length,r.qemu.output_bytes);
const guest=parser.parseSerial(serialRaw.toString('utf8'),{nonce:r.guest.nonce,hashes:r.binary_sha256,reviewNames:r.independent_expected_test_names,coreNames:['TestServiceAccountDefaultsPolicy','TestServiceAccountUseraddExactArgv']});
assert.deepEqual(guest,r.guest);
const planFile=admitted(worker,path.relative(worker,path.join(runDir,'payload-plan.json')).replaceAll('\\','/'));
const planRaw=fs.readFileSync(planFile);assert.equal(hash(planRaw),r.payload_plan_sha256);const plan=JSON.parse(planRaw);
assert.equal(plan.schema_version,1);assert(Array.isArray(plan.entries)&&plan.entries.length===8);
assert.deepEqual(plan.entries.map(x=>x.destination),['payload/panelctl','payload/hostbroker','payload/qualifier.py','payload/core.test','payload/authority.test','user-data','meta-data','network-config']);
for(const entry of plan.entries){const file=admitted(worker,entry.source);const bytes=fs.readFileSync(file);assert.equal(bytes.length,entry.bytes);assert.equal(hash(bytes),entry.sha256);joins++;}
const isoFile=admitted(worker,path.relative(worker,path.join(runDir,'payload.iso')).replaceAll('\\','/'));assert.equal(await streamingSHA(isoFile),r.iso_sha256);
const actualHashes={baseline:plan.entries[0].sha256,candidate:plan.entries[1].sha256,fixture:plan.entries[2].sha256,core_test:plan.entries[3].sha256,review_test:plan.entries[4].sha256};assert.deepEqual(actualHashes,r.binary_sha256);
assert.equal(fs.readFileSync(admitted(worker,plan.entries[0].source)).subarray(0,4).toString('hex'),'7f454c46');
assert.equal(fs.readFileSync(admitted(worker,plan.entries[1].source)).subarray(0,4).toString('hex'),'7f454c46');
const headers=r.source_catalog.filter(x=>x.namespace==='primary'&&x.path.startsWith('.tools/go/pkg/include/'));
assert.deepEqual(headers.map(x=>path.basename(x.path)).sort(),['asm_amd64.h','asm_ppc64x.h','asm_riscv64.h','funcdata.h','textflag.h']);
assert.equal(r.entire_go_distribution_verified,false);
assert.equal(r.assembler_headers,'all_five_installed_pkg_include_files_pinned_before_baseline_build_and_native_run');
const rootManifest=JSON.parse(fs.readFileSync(admitted(candidate,'.cache/service-accounts/go-source-inputs.json'),'utf8'));
assert.equal(rootManifest.length,253);assert.equal(hash(fs.readFileSync(admitted(candidate,'.cache/service-accounts/go-source-inputs.json'))),'0936998e5efc0a868153aaa5f135b93722c089b94dbf14de477ed71a861e57cd');
for(const item of rootManifest){const key='candidate/'+item.path.toLowerCase();assert(labels.has(key));const p=r.source_catalog.find(x=>x.namespace==='candidate'&&x.path===item.path);assert.equal(item.bytes,p.bytes);assert.equal(item.sha256,p.sha256);}
const authorityRaw=fs.readFileSync(admitted(candidate,'.cache/service-accounts/independent-authority.json'));
assert.equal(hash(authorityRaw),'758eb3da1c30b41aaea91cd94c73df75615ec4a2baf16c9d16bed69ebf97a0ed');
assert.equal(hash(authorityRaw),r.independent_builder_receipt_sha256);
const originalAuthority=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'acceptance.json');
assert.deepEqual(authorityRaw,fs.readFileSync(originalAuthority));
const authority=JSON.parse(authorityRaw);assert.equal(authority.candidate_commit,'23e9a97f17b9735fdffa7ed4012f78e4e8e44a57');
parser.validateReviewAuthority(authority,{bytes:plan.entries[4].bytes,sha256:plan.entries[4].sha256},r.independent_expected_test_names);
assert.equal(r.binary_sha256.review_test,'2927afc269ff2c78cd4cf71b6b0f61b385bc7f3d07477b0b0f1a6f07b75f6d61');
const originalELF=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../artifacts/service-accounts-review/build/independent.test');assert.equal(fs.statSync(originalELF).size,plan.entries[4].bytes);assert.equal(await streamingSHA(originalELF),plan.entries[4].sha256);
const baselineManifestPin=r.source_catalog.find(x=>x.namespace==='baseline'&&x.path.endsWith('/manifest.json'));
assert.equal(baselineManifestPin.sha256,'6e93d27c1d575b6b7fafd37e78a6781b937fcdab7e0a76b213ca70438067230c');
const baselineManifest=JSON.parse(fs.readFileSync(admitted(worker,baselineManifestPin.path),'utf8'));
assert.equal(baselineManifest.source_catalog.length,1459);assert.equal(baselineManifest.source_catalog_sha256,hash(JSON.stringify(baselineManifest.source_catalog)));
assert.deepEqual(baselineManifest.exits,{source_guard:0,list:0,build:0});assert.equal(baselineManifest.inputs_unchanged,true);assert.equal(baselineManifest.source_base,r.source_base);
const tools=r.source_catalog.filter(x=>x.namespace==='primary'||x.namespace==='python');
assert.equal(hash(JSON.stringify(tools)),baselineManifest.tools_catalog_sha256);
for(const row of baselineManifest.source_catalog){const actual=r.source_catalog.find(x=>x.namespace===row.namespace&&x.path===row.path);assert.deepEqual(actual,row);}
const harness=r.source_catalog.filter(x=>x.namespace==='baseline'&&(x.path==='scripts/verify-service-accounts.mjs'||x.path.startsWith('lab/service-accounts-guest/')));
assert.equal(hash(JSON.stringify(harness)),r.harness_catalog_sha256);
assert.equal(hostPin.sha256,'a5dfeadf43ca6517d324cbb56d19a22e5b627e326577236b54ece7c65401b614');
for(const index of [0,1,3,4])assert.equal(fs.readFileSync(admitted(worker,plan.entries[index].source)).subarray(0,4).toString('hex'),'7f454c46');
const reviewed=JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)),'harness-review.json')));
const canonicalPins=[];
for(const row of [...authority.candidate_source_pins,...reviewed.current_source_pins]) {
 const base=row.path.startsWith('internal/')?candidate:worker;
 const raw=fs.readFileSync(admitted(base,row.path));const canonical=Buffer.from(raw.toString('utf8').replaceAll('\r\n','\n'));
 assert.equal(hash(canonical),row.canonical_git_sha256);
 const blob=createHash('sha1').update(Buffer.from('blob '+canonical.length+'\0')).update(canonical).digest('hex');assert.equal(blob,row.git_blob);
 if(base===worker)assert.equal(hash(raw),row.sha256);
 const integrated=fs.readFileSync(admitted(candidate,row.path));assert.equal(hash(Buffer.from(integrated.toString('utf8').replaceAll('\r\n','\n'))),row.canonical_git_sha256);
 canonicalPins.push({path:row.path,historical_raw_sha256:row.sha256,current_candidate_bytes:integrated.length,current_candidate_sha256:hash(integrated),canonical_git_sha256:row.canonical_git_sha256,git_blob:blob});
}
assert.equal(r.candidate_source_catalog_sha256,'b24f8e5d6ba0c21b00563e85b748b10d3f99aeeb9cbb7ef64e4cec708f582501');assert.equal(candidateSources.length,152);
assert.deepEqual(r.binary_sha256,{baseline:'502f8bb8fca324c3f9b6813361e6b9f7506ffa5054437bc54316b49b03026b87',candidate:'de6b21a60fb6a6e823f9721d9bf1ceac5328b25ac9da511ee979895d4f6276a2',fixture:'d629cc012a4fa5edd4187086a1fc7197dc395869d247cfb5b514c85051f59b54',core_test:'0d136ef36ff59f04f84bc44370a67bdc8bb98af1c9fd778639d41c49b91d1698',review_test:'2927afc269ff2c78cd4cf71b6b0f61b385bc7f3d07477b0b0f1a6f07b75f6d61'});
assert.equal(r.compiler_generated_test_main,'generated_by_pinned_Go_tools_from_pinned_test_sources_not_separately_catalogued');
assert.equal(r.scope_limits.includes('no_cloudlinux_or_cpanel_certification'),true);
const defaults=guest.policy_before.find(x=>x.id==='useradd_defaults');assert.deepEqual(defaults,guest.policy_adapted.find(x=>x.id==='useradd_defaults'));assert.deepEqual(defaults,guest.policy_after.find(x=>x.id==='useradd_defaults'));assert.equal(defaults.bytes,119);assert.equal(defaults.sha256,'b121fd1b90c1a2fb6081a137dd7b441c7e7fec61bc17ca60db401a952d7b8825');
const result={schema_version:1,kind:'independent_read_only_actual_NSS_ADAPTED_service_identity_audit',passed:true,native_observation:true,execution_performed_by_reviewer:false,report_sha256:expectedSHA,report_bytes:reportRaw.length,run_id:r.run_id,source_catalog_entries:r.source_catalog.length,source_catalog_sha256:r.source_catalog_sha256,current_file_joins:joins,executed_host_harness_sha256:hostPin.sha256,guest_fixture_sha256:r.binary_sha256.fixture,binary_sha256:r.binary_sha256,image_sha256:r.image_sha256,iso_sha256:r.iso_sha256,payload_plan_sha256:r.payload_plan_sha256,serial_private_sha256:hash(serialRaw),serial_bytes:serialRaw.length,exact_nonce_serial_guest_join:true,root_manifest_entries:253,root_manifest_sha256:r.candidate_build_manifest_sha256,baseline_catalog_entries:1459,baseline_manifest_sha256:baselineManifestPin.sha256,candidate_namespace_entries:152,candidate_namespace_sha256:r.candidate_source_catalog_sha256,assembler_headers_pinned:headers,original_builder_authority_sha256:hash(authorityRaw),canonical_source_pins:canonicalPins,stock_useradd_defaults:defaults,NSS_only_disposable_adaptation:true,existing_controller_uid:65534,lifecycle_operations:guest.lifecycle.map(x=>({operation:x.operation,http_status:x.http_status,revision:x.account.revision,state:x.account.state})),account_mutation_requests:5,accepted_account_mutations:3,refusal_state_unchanged:guest.refusal_evidence,actual_clock_days:guest.clock_days,actual_last_password_change:guest.lifecycle[0].native.last_password_change,aging:'max=-1; password_expiry/inactivity never; current-day last-change is retained',native_directory_identity_reopen_equal:true,own_mail_absent_and_existing_mail_equal:true,subids_unrelated_public_identities_listeners_equal:true,core_native_families:guest.core_tests,independent_native_families:guest.review_tests,owned_cleanup:r.cleanup,bounds:r.limits,scope_limits:['Read-only audit; guest execution belongs to worker. Raw boot read privately for exact nonce frame only; never emitted.','NSS_ADAPTED image only: original NSS refused, one explicit disposable overlay adaptation; stock mail defaults unchanged.','Five top-level native families pass without skip; fixture-measured stdout hashes/names are not a second execution actor.','All declared catalogued inputs checked, including five assembler headers; compiler-generated test main and entire Go distribution are not certified.','Historical source-review failures and unavailable original mixed-newline raw snapshots remain separately classified in harness-review.json; canonical Git blobs are distinct authority.','No full stock provisioning,cPanel/CloudLinux,allOS,reboot,remote ingress,atomic privileged path stability or hostile guest qualification.']};
const output=path.resolve(outputArg);const own=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
assert(norm(output).startsWith(norm(path.join(own,'artifacts/service-accounts-review/native'))+path.sep));
for(let current=path.dirname(output);;current=path.dirname(current)) {
 const info=fs.lstatSync(current);assert(info.isDirectory()&&!info.isSymbolicLink()&&norm(fs.realpathSync(current))===norm(current));
 if(norm(current)===norm(own))break;
 assert(norm(current).startsWith(norm(own)+path.sep));
}
fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({passed:true,audit:output,audit_sha256:hash(fs.readFileSync(output)),report_sha256:expectedSHA,current_file_joins:joins}));
