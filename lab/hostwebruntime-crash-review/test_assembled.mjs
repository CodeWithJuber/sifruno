// Synthetic source-integration checks. This never invokes QEMU or guest main.
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {test} from 'node:test';
import {synthetic} from './test_receipt.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const root=process.env.SIFRUNO_CRASH_CANDIDATE_ROOT;assert(root&&path.isAbsolute(root),'Explicit candidate root required');
const {parseCrashSerial,inputHash,accounts,CHECKS,ROOT}=await import(pathToFileURL(path.join(root,'lab/hostwebruntime-crash-host/parser.mjs')));
export function fixture() {
  const s=synthetic(),nonce=s.pins.nonce,driver=s.r;
  driver.input_sha256=inputHash(nonce);
  const pins={driver:{sha256:driver.driver_sha256},catalog:{sha256:driver.source_catalog_sha256},required_tests:['TestParserSyntheticOnly'],required_reaping_tests:['TestNamespaceReopenedHandlesReapOriginalChild']};
  const admission={schema_version:2,kind:'trusted-disposable-alma9-controller-crash',nonce,prepared_image_sha256:hash('synthetic-image'),fixture_sha256:hash('synthetic-fixture'),library_sha256:'99705157a37d290f6c5a3ed87c8f042ed45169b1c98c57f0017c99cc627acd9e',helper_sha256:'73ef86f95b34d255b4ab5c6145caae718ad1578efba7f1c0d24f5712c57fc9ed',source_catalog_sha256:driver.source_catalog_sha256,package_report_sha256:hash('synthetic-package-report'),driver_sha256:driver.driver_sha256,test_sha256:hash('synthetic-test'),zero_external_nics:true};
  const packages={packages:Array.from({length:18},(_,i)=>({name:'synthetic-parser-package-'+i,nevra:'synthetic-parser-package-'+i+'-0:1-1.el9.x86_64',sha256:hash('synthetic-rpm-'+i)}))};
  const output='=== RUN   TestParserSyntheticOnly\n--- PASS: TestParserSyntheticOnly (0.00s)\nPASS\n';
  admission.reaping_test_sha256=hash('synthetic-reaping-test');
  const regressionOutput='=== RUN   TestNamespaceReopenedHandlesReapOriginalChild\n--- PASS: TestNamespaceReopenedHandlesReapOriginalChild (0.00s)\nPASS\n';
  const receipt={exit_code:0,reaped:true,timed_out:false,output_bound_exceeded:false,stdout_sha256:hash(''),stderr_sha256:hash('')};
  const environment={os_id:'almalinux',version_id:'9.8',architecture:'x86_64',kernel:'synthetic-no-native-run',interfaces:['lo'],selinux_enforce:1,parent_no_new_privs:'0',parent_cap_eff:'0'.repeat(16),parent_cap_bnd:'0'.repeat(16),os_release_sha256:hash('synthetic-os')};
  const aa=accounts();
  const report={schema_version:2,kind:'alma9-controller-crash-qualification',nonce,driver_run_id:driver.run_id,fixture_only:true,passed:true,failure_code:null,checks:CHECKS,cleanup:{driver_reaped:true,listeners_extinct:true,observed_worker_namespaces_extinct:true,mounts_removed:true},provenance:{...Object.fromEntries(Object.entries(admission).filter(([k])=>k.endsWith('sha256'))),prepared_image_hash_admitted_not_guest_measured:true,linked_source_catalog_admitted_not_guest_reconstructed:true,borrowed_fixture_library_sha256:admission.library_sha256,borrowed_helper_functions:['clean_env','run_cmd','write_exact','write_runtime_report','ensure_dir','mount_bind','unmount','prepare_guest_policies','make_certificates'],old_fixture_main_called:false},environment:{before:environment,after:structuredClone(environment)},policy_adaptations:{guest_only_files_policy_declared:true,original_sha256:hash('synthetic-nss'),original_was_symlink:true,effective_identity_policy:['passwd: files','group: files','shadow: files'],stock_alma_nss_qualified:false,guest_only_no_mail_spool_policy_declared:true,useradd_original_sha256:hash('synthetic-useradd'),effective_mail_spool:false,stock_useradd_policy_qualified:false,effective_sha256:{'/etc/nsswitch.conf':hash('synthetic-effective-nss'),'/etc/default/useradd':hash('synthetic-effective-useradd')}},packages:packages.packages.map(p=>({name:p.name,nevra:p.nevra,rpm_sha256:p.sha256,signature_key_id:'B86B3716',signature_verified:true,installed_exact:true})),system_inputs:['/usr/sbin/httpd','/usr/sbin/php-fpm',...['mod_mpm_event.so','mod_unixd.so','mod_ssl.so','mod_proxy.so','mod_proxy_http.so','mod_proxy_fcgi.so','mod_authz_core.so','mod_authz_host.so','mod_dir.so','mod_mime.so','mod_log_config.so'].map(m=>'/usr/lib64/httpd/modules/'+m)].map(p=>({path:p,mode:0o755,bytes:100,sha256:hash('synthetic-file-'+p)})),tls_public_inputs:[ROOT+'/tls/ca.pem',...aa.map(a=>ROOT+'/tls/'+a.id+'/cert.pem')].map(p=>({path:p,sha256:hash('synthetic-public-cert-'+p)})),accounts:aa.map(a=>({id:a.id,username:a.username,uid:a.uid,gid:a.gid,password_locked:true,mail_spool:false,shell:'/usr/sbin/nologin'})),sentinels:[[ROOT+'/managed/controller-private-sentinel',0,'SIFRUNO_CONTROLLER_PRIVATE\n'],...aa.map(a=>[a.home+'/private.txt',a.uid,'SIFRUNO_PRIVATE_SENTINEL\n'])].map(([p,uid,body])=>({path:p,uid,gid:uid,mode:'0o600',sha256:hash(body),root_read_verified:true})),binds:aa.flatMap(a=>[ROOT+'/backend-jails/'+a.id+a.home,ROOT+'/backend-jails/'+a.id+ROOT+'/runtime/'+a.id]).map((target,i)=>({target,mount_id:i+100,source_dev:100,source_ino:i+100,target_mode:'0o750',jail_ancestors_mode:'0o755'})),tests:{...receipt,stdout_sha256:hash(output),passed_names:pins.required_tests,contract_passed:true},driver:{...receipt,report_sha256:hash(JSON.stringify(driver)),passed:true}};
  report.reaping_test={...receipt,stdout_sha256:hash(regressionOutput),passed_names:pins.required_reaping_tests,contract_passed:true};
  return {nonce,driver,pins,admission,packages,report,output,regressionOutput};
}
function transcript(s) {
  s.report.driver.report_sha256=hash(JSON.stringify(s.driver));
  return `SIFRUNO_RUNTIME_CRASH_TEST_BEGIN ${s.nonce}\n${s.output}SIFRUNO_RUNTIME_CRASH_TEST_END ${s.nonce}\nSIFRUNO_RUNTIME_CRASH_REGRESSION_BEGIN ${s.nonce}\n${s.regressionOutput}SIFRUNO_RUNTIME_CRASH_REGRESSION_END ${s.nonce}\nSIFRUNO_RUNTIME_CRASH_DRIVER_BEGIN ${s.nonce}\n${JSON.stringify(s.driver)}\nSIFRUNO_RUNTIME_CRASH_DRIVER_END ${s.nonce}\nSIFRUNO_RUNTIME_CRASH_BEGIN ${s.nonce}\n${JSON.stringify(s.report)}\nSIFRUNO_RUNTIME_CRASH_END ${s.nonce}\nSIFRUNO_RUNTIME_CRASH_EXIT ${s.nonce} 0\n`;
}
const parse=(s,raw=transcript(s))=>parseCrashSerial(raw,s.nonce,s.pins,s.admission,s.packages);
test('assembled candidate synthetic complete new schema passes',()=>assert.equal(parse(fixture()).passed,true));
const mutations={
  'guest nonzero exit':s=>s.report.driver.exit_code=3,
  'test nonzero exit':s=>s.report.tests.exit_code=3,
  'test skip':s=>s.output=s.output.replace('--- PASS:','--- SKIP:'),
  'cleanup foreign mounts':s=>s.report.cleanup.mounts_removed=false,
  'cleanup namespace survivor':s=>s.report.cleanup.observed_worker_namespaces_extinct=false,
  'old serving success kind':s=>s.report.kind='alma9-runtime-serving-qualification',
  'old runtime proof field':s=>s.report.provenance.runtime_manifest_sha256='0'.repeat(64),
  'unadmitted package':s=>s.report.packages[0].rpm_sha256='0'.repeat(64),
  'stock policy inflated':s=>s.report.policy_adaptations.stock_alma_nss_qualified=true,
  'external NIC':s=>s.report.environment.after.interfaces=['lo','eth0'],
  'unknown guest key':s=>s.report.EXTRA=true,
  'unknown nested driver':s=>s.driver.crash.extra=1,
  'reaping regression nonzero exit':s=>s.report.reaping_test.exit_code=3,
  'reaping regression skip':s=>s.regressionOutput=s.regressionOutput.replace('--- PASS:','--- SKIP:'),
  'reaping regression stderr':s=>s.report.reaping_test.stderr_sha256=hash('synthetic-error'),
  'reaping regression wrong test':s=>s.report.reaping_test.passed_names=['TestOldProof'],
  'reaping regression missing receipt':s=>delete s.report.reaping_test,
  'reaping regression failed contract':s=>s.report.reaping_test.contract_passed=false,
};
for(const [name,mutate]of Object.entries(mutations))test('assembled reject '+name,()=>{const s=fixture();mutate(s);assert.throws(()=>parse(s));});
const framing={
  'nonzero terminal':raw=>raw.replace(/(CRASH_EXIT [a-f0-9]{24}) 0/,'$1 1'),
  'duplicate terminal':raw=>raw+raw.split('\n').at(-2)+'\n',
  'foreign marker':raw=>raw+'SIFRUNO_RUNTIME_CRASH_FOREIGN\n',
  'marker alias':raw=>raw.replace('CRASH_DRIVER_END','CRASH_DRIVER_END_alias'),
  'foreign nonce':raw=>raw.replace(/(CRASH_DRIVER_BEGIN )([a-f0-9]{24})/,'$1'+ '0'.repeat(24)),
  'nested duplicate JSON':raw=>raw.replace('"schema_version":2','"schema_version":2,"schema_version":2'),
  'field case alias':raw=>raw.replace('"signal":9','"Signal":9'),
  'contradictory panic':raw=>raw+'panic: synthetic contradiction\n',
  'duplicate regression marker':raw=>raw.replace(/SIFRUNO_RUNTIME_CRASH_REGRESSION_BEGIN ([a-f0-9]{24})/,'$&\n$&'),
  'regression marker alias':raw=>raw.replace('CRASH_REGRESSION_END','CRASH_REGRESSION_END_alias'),
};
for(const [name,mutate]of Object.entries(framing))test('assembled reject '+name,()=>{const s=fixture();assert.throws(()=>parse(s,mutate(transcript(s))));});
