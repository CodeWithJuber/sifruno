// Read-only independent audit of a separately executed stock-policy receipt.
// No subprocess, HTTP, guest, account utility or credential access.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL,fileURLToPath} from 'node:url';

const [workerArg,reportArg,expectedSHA,outputArg]=process.argv.slice(2);
const worker=fs.realpathSync(workerArg),primary=path.resolve(worker,'../..');
assert.equal(path.basename(worker),'stock-preflight-cli-sol');
const candidate=path.join(primary,'.worktrees/stock-preflight-integration');
const reportFile=fs.realpathSync(reportArg);
assert(reportFile.startsWith(worker+path.sep));
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const reportRaw=fs.readFileSync(reportFile);assert.equal(hash(reportRaw),expectedSHA);
const r=JSON.parse(reportRaw);
assert.equal(r.schema_version,1);assert.equal(r.scope,'signed_alma_stock_policy_refusal_order_observation');
assert.equal(r.passed,true);assert.equal(r.native_observation,true);assert.equal(r.failure,null);
assert.equal(r.source_base,'cebd86fa9ec12a24e6e597e88d5185d76540c685');
assert.equal(r.candidate_build_commit,'6494e272c61b533231db0cc889e5a604a5a980e0');
assert.equal(r.candidate_build_authority,'root_supplied_frozen_binary_and_source_manifest');
assert.equal(r.image_sha256,'6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b');
assert.equal(r.image_signature_verified,true);
assert.equal(r.external_nic,false);assert.equal(r.host_shares,false);assert.equal(r.shared_dependency_inputs_read_only,true);
assert.equal(r.inputs_unchanged,true);
assert.deepEqual(r.role_mapping,{'payload/panelctl':'baseline-hostbroker','payload/hostbroker':'candidate-hostbroker','payload/qualifier.py':'new-stock-policy-fixture'});
assert.deepEqual(r.limits,{qemu_seconds:600,qemu_output_bytes:2097152,broker_seconds:20,broker_output_bytes:16384,check_host_output_bytes:8192});
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
assert(Array.isArray(r.source_catalog)&&r.source_catalog.length>100&&r.source_catalog.length<10000);
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
const manifestPin=r.source_catalog.find(x=>x.namespace==='candidate'&&x.path==='.cache/stock-preflight/go-source-inputs.json');
assert(manifestPin&&manifestPin.sha256===r.candidate_build_manifest_sha256);
const runDir=path.join(worker,'.cache/alma9-qualification',r.run_id);
const hostFile=admitted(worker,path.relative(worker,path.join(runDir,'host-harness-source.mjs')).replaceAll('\\','/'));
const hostPin=r.source_catalog.find(x=>x.namespace==='baseline'&&x.path==='scripts/verify-stock-policy.mjs');
assert(hostPin&&hash(fs.readFileSync(hostFile))===hostPin.sha256);
const parser=await import(pathToFileURL(hostFile));
const serialFile=admitted(worker,path.relative(worker,path.join(runDir,'serial-private.log')).replaceAll('\\','/'));
const serialRaw=fs.readFileSync(serialFile);assert(serialRaw.length<=2097152);
assert.equal(serialRaw.length,r.qemu.output_bytes);
const guest=parser.parseSerial(serialRaw.toString('utf8'),{nonce:r.guest.nonce,hashes:r.binary_sha256});
assert.deepEqual(guest,r.guest);
const planFile=admitted(worker,path.relative(worker,path.join(runDir,'payload-plan.json')).replaceAll('\\','/'));
const planRaw=fs.readFileSync(planFile);assert.equal(hash(planRaw),r.payload_plan_sha256);const plan=JSON.parse(planRaw);
assert.equal(plan.schema_version,1);assert(Array.isArray(plan.entries)&&plan.entries.length===6);
assert.deepEqual(plan.entries.map(x=>x.destination),['payload/panelctl','payload/hostbroker','payload/qualifier.py','user-data','meta-data','network-config']);
for(const entry of plan.entries){const file=admitted(worker,entry.source);const bytes=fs.readFileSync(file);assert.equal(bytes.length,entry.bytes);assert.equal(hash(bytes),entry.sha256);joins++;}
const isoFile=admitted(worker,path.relative(worker,path.join(runDir,'payload.iso')).replaceAll('\\','/'));assert.equal(await streamingSHA(isoFile),r.iso_sha256);
const actualHashes={baseline:plan.entries[0].sha256,candidate:plan.entries[1].sha256,fixture:plan.entries[2].sha256};assert.deepEqual(actualHashes,r.binary_sha256);
assert.equal(fs.readFileSync(admitted(worker,plan.entries[0].source)).subarray(0,4).toString('hex'),'7f454c46');
assert.equal(fs.readFileSync(admitted(worker,plan.entries[1].source)).subarray(0,4).toString('hex'),'7f454c46');
const result={schema_version:1,kind:'independent_read_only_actual_stock_policy_guest_audit',passed:true,report_sha256:expectedSHA,report_bytes:reportRaw.length,run_id:r.run_id,source_catalog_entries:r.source_catalog.length,source_catalog_sha256:r.source_catalog_sha256,current_file_joins:joins,executed_host_harness_sha256:hostPin.sha256,guest_fixture_sha256:r.binary_sha256.fixture,binary_sha256:r.binary_sha256,image_sha256:r.image_sha256,iso_sha256:r.iso_sha256,payload_plan_sha256:r.payload_plan_sha256,serial_private_sha256:hash(serialRaw),exact_nonce_serial_guest_join:true,policy_before_after_equal:true,listeners_before_after_equal:true,baseline_three_empty_directories_candidate_zero:true,owned_cleanup:true,limits:['Read-only audit; guest execution belongs to worker. Raw boot read privately for exact nonce frame only; never emitted.','Policy invariance starts after explicit cloud-init staging, not untouched whole-image proof.','248-file root manifest stays historical binary build scope; current linked source catalog is separately checked.','Refusal/admission ordering only, no stock account provisioning,cPanel/CloudLinux,allOS,reboot,remote ingress,atomic policy stability or hostile guest qualification.']};
const output=path.resolve(outputArg);const own=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
assert(norm(output).startsWith(norm(path.join(own,'.cache/stock-policy-review'))+path.sep));
fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({passed:true,audit:output,audit_sha256:hash(fs.readFileSync(output)),report_sha256:expectedSHA,current_file_joins:joins}));
