// Read-only audit of an existing root-owned run. Never launches native work.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {auditDriver} from './receipt.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
assert.equal(process.argv.length,5,'Usage: node audit_result.mjs <primary> <candidate> <run-directory>');
const [primary,candidate,work]=process.argv.slice(2).map(p=>path.resolve(p));
assert.equal(candidate,path.join(primary,'.worktrees/web-crash-integration'));
assert.equal(path.dirname(work),path.join(candidate,'.cache/hostwebruntime-crash-host'));
assert(/^crash-[0-9]+-[a-f0-9]{24}$/.test(path.basename(work)));
const {admit,unchanged}=await import(pathToFileURL(path.join(candidate,'lab/hostwebruntime-crash-host/run.mjs')));
const {parseCrashSerial,inputHash}=await import(pathToFileURL(path.join(candidate,'lab/hostwebruntime-crash-host/parser.mjs')));
const reportRaw=fs.readFileSync(path.join(work,'report.json')),r=JSON.parse(reportRaw);
assert.equal(JSON.stringify(r,null,2),reportRaw.toString('utf8'),'Exact duplicate-free host JSON required');
assert.equal(r.schema_version,2);assert.equal(r.run,path.basename(work));
for(const k of ['passed','native_controller_death_qualified','qemu_launched','source_pins_unchanged'])assert.equal(r[k],true);
for(const k of ['production_activated','original_compatibility_certified','timed_out','output_limited'])assert.equal(r[k],false);
assert.equal(r.evidence_kind,'disposable-alma9-controller-death-native-execution');
assert.deepEqual(r.qemu_exit,{code:0,signal:null});
assert(!r.interrupted&&!r.qemu_error&&!r.cleanup_error&&!r.capture_error&&!r.failure);
const state=admit(primary);unchanged(state);
assert.deepEqual(r.source_inputs,state.inventory);assert.deepEqual(r.runner_sources,state.self);
assert.equal(r.source_catalog_sha256,state.pins.catalog.sha256);
const serial=fs.readFileSync(path.join(work,'serial.log'));assert.equal(serial.length,r.serial_bytes);assert.equal(hash(serial),r.serial_sha256);
const guest=parseCrashSerial(serial.toString('utf8'),r.nonce,state.pins,r.admission,state.packages);assert.deepEqual(guest,r.guest);
assert.equal(hash(fs.readFileSync(path.join(work,'payload.iso'))),r.iso_sha256);
assert.equal(r.payload.length,29);assert.equal(r.iso_readback.length,29);
for(const entry of r.payload){const bytes=fs.readFileSync(path.join(work,...entry.name.split('/')));assert.equal(bytes.length,entry.bytes);assert.equal(hash(bytes),entry.sha256);}
const lines=serial.toString('utf8').replaceAll('\r\n','\n').split('\n');
const begin=lines.indexOf('SIFRUNO_RUNTIME_CRASH_DRIVER_BEGIN '+r.nonce),raw=lines[begin+1];
const driver=JSON.parse(raw);assert.equal(JSON.stringify(driver),raw);
auditDriver(driver,{nonce:r.nonce,driverSHA:state.pins.driver.sha256,catalogSHA:state.pins.catalog.sha256,inputSHA:inputHash(r.nonce)});
unchanged(state);
console.log(JSON.stringify({kind:'independent-actual-controller-crash-receipt-audit',passed:true,
  native_execution_performed_by_reviewer:false,run:r.run,report_sha256:hash(reportRaw),serial_sha256:hash(serial),
  iso_sha256:r.iso_sha256,catalog_sha256:r.source_catalog_sha256,driver_report_sha256:hash(raw),
  source_inputs:r.source_inputs.length,runner_sources:r.runner_sources.length,payloads:r.payload.length,
  controller_signal:driver.crash.signal,native_unit_tests:state.catalog.required_tests.length,
  history_events:driver.history.length,checkpoint_revisions:driver.checkpoints.map(c=>c.coordinator.revision),
  observed_namespaces:driver.observed_namespace_ids.length,http_probes:driver.probes.length,
  limits:['same-driver HTTP measurements','adapted fixture inventory guard','no stock-policy reboot cPanel all-OS production-API claim']}));
