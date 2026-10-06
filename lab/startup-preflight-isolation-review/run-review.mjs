// Isolated synthetic execution and immutable byte receipt. No native probe.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawnSync,execFileSync} from 'node:child_process';
const own=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const guest=path.resolve(own,'../startup-preflight-guest-sol');
const old=path.resolve(own,'../startup-preflight-review-sol');
const commit='4c81b2c96cd6eaf3987b6b7db1c994c61dae0b8f';
const lab='lab/startup-preflight-isolation-review', output=path.join(own,'.cache/startup-preflight-isolation-review');
fs.mkdirSync(output,{recursive:true});
const temporary=fs.mkdtempSync(path.join(output,'temp-'));
const hash=b=>createHash('sha256').update(b).digest('hex');
const git=(base,...args)=>execFileSync('C:/Program Files/Git/cmd/git.exe',args,{cwd:base});
function pin(base,name){const file=path.resolve(base,name),relative=path.relative(base,file);assert(relative&&!relative.startsWith('..')&&!path.isAbsolute(relative));for(let p=file;;p=path.dirname(p)){assert(!fs.lstatSync(p).isSymbolicLink());assert.equal(fs.realpathSync(p).toLowerCase(),p.toLowerCase());if(p.toLowerCase()===base.toLowerCase())break;}const info=fs.lstatSync(file);assert(info.isFile()&&info.nlink===1);const raw=fs.readFileSync(file);return {path:name,bytes:raw.length,sha256:hash(raw)};}
assert.equal(git(guest,'rev-parse','HEAD').toString().trim(),commit);
assert.equal(git(guest,'status','--porcelain').length,0);
const files=['scripts/verify-startup-preflight.mjs','lab/startup-preflight-guest/README.md','lab/startup-preflight-guest/contract.test.mjs','lab/startup-preflight-guest/fixture.py','lab/startup-preflight-guest/fixture_test.py'];
const sources=files.map(name=>{const raw=fs.readFileSync(path.join(guest,name)),canonical=git(guest,'show',commit+':'+name);assert.equal(raw.toString().replaceAll('\r\n','\n'),canonical.toString());return {...pin(guest,name),canonical_git_sha256:hash(canonical),git_blob:git(guest,'rev-parse',commit+':'+name).toString().trim()};});
const preserved=['challenge-harness.mjs','challenge-fixture.py','harness-freeze.mjs','harness-review.json'].map(name=>pin(old,'lab/startup-preflight-review/'+name));
const logs=[];
const commands=[['decoder',process.execPath,[lab+'/decoder-challenges.mjs']],['isolation','C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python.exe',['-I','-B',lab+'/isolation-challenges.py']],['fixture','C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python.exe',['-I','-B',path.join(guest,'lab/startup-preflight-guest/fixture_test.py')]],['contract',process.execPath,['--test',path.join(guest,'lab/startup-preflight-guest/contract.test.mjs')]]];
for(const [label,executable,args] of commands){const env={PATH:'C:/Windows/System32',SystemRoot:'C:/Windows',WINDIR:'C:/Windows',TEMP:temporary,TMP:temporary,TMPDIR:temporary,PYTHONDONTWRITEBYTECODE:'1'};const result=spawnSync(executable,args,{cwd:own,env,timeout:30000,maxBuffer:1024*1024});for(const [suffix,bytes] of [['out',result.stdout??Buffer.alloc(0)],['err',result.stderr??Buffer.alloc(0)]]){const file=path.join(output,label+'.'+suffix);fs.writeFileSync(file,bytes,{flag:'wx'});logs.push(pin(own,path.relative(own,file).replaceAll('\\','/')));}assert.equal(result.error,undefined);assert.equal(result.status,0,label+' failed');logs.push({command:[executable,...args],exit_code:result.status,signal:result.signal,owned_TEMP_TMP_TMPDIR:true});}
assert.equal(git(guest,'status','--porcelain').length,0);
for(const p of sources)assert.deepEqual(pin(guest,p.path),{path:p.path,bytes:p.bytes,sha256:p.sha256});
for(const p of preserved)assert.deepEqual(pin(old,p.path),p);
const receipt={schema_version:1,verdict:'CLEAR',evidence_kind:'restricted_independent_corrected_fixture_source_and_synthetic_review',native_observation:false,guest_commit:commit,original_guest_commit:'2ab283a505dd92c4ce13ea15f06d2b835f8ec140',guest_source_pins:sources,prior_provisional_artifacts_unchanged:preserved,commands_and_raw_logs:logs,review_source:['decoder-challenges.mjs','isolation-challenges.py','run-review.mjs'].map(n=>pin(own,lab+'/'+n)),findings:[],observed_source:['Native test children alone receive explicit verified TMPDIR; all other child envs contain only fixed PATH/LANG/LC_ALL','Dedicated root/core/review dirs use root ownership, exact 0700, no special/write permissions in ancestors, nofollow descriptors, inode/device equality and exclusive descriptor-relative mkdir','No fallback to shared/global temp; separate native test role roots; fixture writes remain separate from diagnostic command','Nine-check schema and fixed first-refusal sequence; nonempty fresh state remains not_checked; unknown NSS spelling redacted','Strict nonce-bound marker order and compact JSON; policy/mail/subid/listener metadata equality enforced','Child timeout/output/session/pipe cleanup remains bounded; directories retained in disposable guest rather than recursive host cleanup'],limits:['Source review and synthetic data/models only; Linux authority semantics and actual native test success unexecuted','No Go rerun, provider/network calls, guest boot, privileged/native probes or live system changes','No hostile root concurrent writer or atomic policy stability certification','Original provisional CLEAR remains withdrawn; this receipt binds the correction only'],recovery:'Reject source adoption or revert correction before any separately gated actual execution; retain all original failure and positive logs; no cleanup of another worker artifacts'};
fs.writeFileSync(path.join(own,lab,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({verdict:'CLEAR',receipt:pin(own,lab+'/receipt.json'),runs:commands.length}));
