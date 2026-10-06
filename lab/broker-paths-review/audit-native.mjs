// Read-only independent audit of a separately executed broker-paths receipt.
// No subprocess, HTTP, guest, account utility or credential access.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL,fileURLToPath} from 'node:url';

const [workerArg,reportArg,expectedSHA,outputArg]=process.argv.slice(2);
const worker=fs.realpathSync(workerArg),primary=path.resolve(worker,'../..');
assert.equal(path.basename(worker),'broker-paths-guest-sol');
const candidate=path.join(primary,'.worktrees/broker-paths-integration');
const reportFile=fs.realpathSync(reportArg);
assert(reportFile.startsWith(worker+path.sep));
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const reportRaw=fs.readFileSync(reportFile);assert.equal(hash(reportRaw),expectedSHA);
const r=JSON.parse(reportRaw);
assert.equal(r.schema_version,1);assert.equal(r.scope,'ADAPTED_signed_alma_broker_path_observation');
assert.equal(r.passed,true);assert.equal(r.native_observation,true);assert.equal(r.failure,null);
assert.equal(r.source_base,'b4225d8877d798cdf93b49d3584cc0d8d4cc8375');
assert.equal(r.candidate_build_commit,'9832d998c49558155d61adc066079b487c2f4042');
assert.equal(r.candidate_build_authority,'root_supplied_frozen_binary_and_source_manifest');
assert.equal(r.image_sha256,'6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b');
assert.equal(r.image_signature_verified,true);
assert.equal(r.external_nic,false);assert.equal(r.host_shares,false);assert.equal(r.shared_dependency_inputs_read_only,true);
assert.equal(r.inputs_unchanged,true);
assert.deepEqual(r.role_mapping,{'payload/panelctl':'baseline-hostbroker','payload/hostbroker':'candidate-hostbroker','payload/qualifier.py':'new-ADAPTED-broker-paths-fixture','payload/core.test':'reviewed-root-core-tests','payload/authority.test':'independent-review-tests'});
assert.deepEqual(r.limits,{qemu_seconds:600,qemu_output_bytes:2097152,broker_seconds:20,broker_output_bytes:16384,check_host_output_bytes:8192,test_output_bytes:65536,test_seconds:20});
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
assert(Array.isArray(r.source_catalog)&&r.source_catalog.length===1945);
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
const manifestPin=r.source_catalog.find(x=>x.namespace==='candidate'&&x.path==='.cache/broker-paths/go-source-inputs.json');
assert(manifestPin&&manifestPin.sha256===r.candidate_build_manifest_sha256);
const runDir=path.join(worker,'.cache/alma9-qualification',r.run_id);
const hostFile=admitted(worker,path.relative(worker,path.join(runDir,'host-harness-source.mjs')).replaceAll('\\','/'));
const hostPin=r.source_catalog.find(x=>x.namespace==='baseline'&&x.path==='scripts/verify-broker-paths.mjs');
assert(hostPin&&hash(fs.readFileSync(hostFile))===hostPin.sha256);
const parser=await import(pathToFileURL(hostFile));
const serialFile=admitted(worker,path.relative(worker,path.join(runDir,'serial-private.log')).replaceAll('\\','/'));
const serialRaw=fs.readFileSync(serialFile);assert(serialRaw.length<=2097152);
assert.equal(serialRaw.length,r.qemu.output_bytes);
const guest=parser.parseSerial(serialRaw.toString('utf8'),{nonce:r.guest.nonce,hashes:r.binary_sha256,reviewNames:r.independent_expected_test_names});
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
const rootManifest=JSON.parse(fs.readFileSync(admitted(candidate,'.cache/broker-paths/go-source-inputs.json'),'utf8'));
assert.equal(rootManifest.length,252);assert.equal(hash(fs.readFileSync(admitted(candidate,'.cache/broker-paths/go-source-inputs.json'))),'ca6b35bd4db8ba06249dccf6ed2622772b73b437cdb3ef32ffc3f62b4db44803');
for(const item of rootManifest){const key='candidate/'+item.path.toLowerCase();assert(labels.has(key));const p=r.source_catalog.find(x=>x.namespace==='candidate'&&x.path===item.path);assert.equal(item.bytes,p.bytes);assert.equal(item.sha256,p.sha256);}
const authorityRaw=fs.readFileSync(admitted(candidate,'.cache/broker-paths/independent-authority.json'));
assert.equal(hash(authorityRaw),'18213216341e53bd9335a94c24bf5af73e8b487b61dce3741349aaad67fc0b72');
assert.equal(hash(authorityRaw),r.independent_builder_receipt_sha256);
const originalAuthority=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'setgid-review.json');
assert.deepEqual(authorityRaw,fs.readFileSync(originalAuthority));
const authority=JSON.parse(authorityRaw);assert.equal(authority.candidate_fix_commit,'73ce4c5b9f9a83bcdb754c4469364461aa284faf');
parser.validateReviewAuthority(authority,{bytes:plan.entries[4].bytes,sha256:plan.entries[4].sha256},r.independent_expected_test_names);
assert.equal(r.binary_sha256.review_test,'9d0b9af9f3cdb4fdb9b4095e4189ad5bcdc040836cdbfb0708e06c67b0c8631c');
const baselineManifestPin=r.source_catalog.find(x=>x.namespace==='baseline'&&x.path.endsWith('/manifest.json'));
assert.equal(baselineManifestPin.sha256,'04b8d76b14ff1c844c36cb8f089d634d3dcc7a13186f9b80cb9185b2ed8c36b7');
const baselineManifest=JSON.parse(fs.readFileSync(admitted(worker,baselineManifestPin.path),'utf8'));
assert.equal(baselineManifest.source_catalog.length,1457);assert.equal(baselineManifest.source_catalog_sha256,hash(JSON.stringify(baselineManifest.source_catalog)));
assert.deepEqual(baselineManifest.exits,{source_guard:0,list:0,build:0});assert.equal(baselineManifest.inputs_unchanged,true);assert.equal(baselineManifest.source_base,r.source_base);
const tools=r.source_catalog.filter(x=>x.namespace==='primary'||x.namespace==='python');
assert.equal(hash(JSON.stringify(tools)),baselineManifest.tools_catalog_sha256);
for(const row of baselineManifest.source_catalog){const actual=r.source_catalog.find(x=>x.namespace===row.namespace&&x.path===row.path);assert.deepEqual(actual,row);}
const harness=r.source_catalog.filter(x=>x.namespace==='baseline'&&(x.path==='scripts/verify-broker-paths.mjs'||x.path.startsWith('lab/broker-paths-guest/')));
assert.equal(hash(JSON.stringify(harness)),r.harness_catalog_sha256);
assert.equal(hostPin.sha256,'0692d783d2adb12fd2e1d4d20dcb1a2c026eaf84bcf686fd5eecb135d3b28c35');
for(const index of [0,1,3,4])assert.equal(fs.readFileSync(admitted(worker,plan.entries[index].source)).subarray(0,4).toString('hex'),'7f454c46');
const result={schema_version:1,kind:'independent_read_only_actual_ADAPTED_broker_path_guest_audit',passed:true,report_sha256:expectedSHA,report_bytes:reportRaw.length,run_id:r.run_id,source_catalog_entries:r.source_catalog.length,source_catalog_sha256:r.source_catalog_sha256,current_file_joins:joins,executed_host_harness_sha256:hostPin.sha256,guest_fixture_sha256:r.binary_sha256.fixture,binary_sha256:r.binary_sha256,image_sha256:r.image_sha256,iso_sha256:r.iso_sha256,payload_plan_sha256:r.payload_plan_sha256,serial_private_sha256:hash(serialRaw),exact_nonce_serial_guest_join:true,root_manifest_entries:252,baseline_catalog_entries:1457,assembler_headers_pinned:headers,original_supplemental_authority_sha256:hash(authorityRaw),original_then_two_adapted_policies_then_final_equal:true,twelve_conflict_comparisons_exact:true,candidate_conflict_trees_unchanged:true,two_happy_fresh_reopen_empty_nonroot_GET:true,core_native_families:r.guest.core_tests.test_names,independent_native_families:r.guest.review_tests.test_names,owned_cleanup:true,limits:['Read-only audit; guest execution belongs to worker. Raw boot read privately for exact nonce frame only; never emitted.','ADAPTED image only: original NSS/mail refused, two explicit disposable overlay adaptations then invariance.','12 top-level native test families pass without skip; test stdout hashes/names are measured by reviewed fixture, not a second independent execution actor.','All declared catalogued inputs checked; compiler-generated test main not separately pinned and entire Go distribution not certified.','No stock provisioning,cPanel/CloudLinux,allOS,reboot,remote ingress,atomic privileged path stability or hostile guest qualification.']};
const output=path.resolve(outputArg);const own=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
assert(norm(output).startsWith(norm(path.join(own,'artifacts/broker-paths-review/native'))+path.sep));
for(let current=path.dirname(output);;current=path.dirname(current)) {
 const info=fs.lstatSync(current);assert(info.isDirectory()&&!info.isSymbolicLink()&&norm(fs.realpathSync(current))===norm(current));
 if(norm(current)===norm(own))break;
 assert(norm(current).startsWith(norm(own)+path.sep));
}
fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({passed:true,audit:output,audit_sha256:hash(fs.readFileSync(output)),report_sha256:expectedSHA,current_file_joins:joins}));
