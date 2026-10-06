import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync,existsSync} from 'node:fs';
import {decodePreviewSerial} from './report.mjs';
import {sample,serial} from './synthetic.mjs';
test('synthetic complete seven-case report accepted with exact payload binding',()=>{const g=sample();assert.deepEqual(decodePreviewSerial(serial(g),g.nonce,g.inputs),g);});
test('report changes refuse: identity, outcome, captures, pairing, source and runtime',()=>{
 for(const change of [g=>g.passed=false,g=>g.controller_uid=0,g=>g.cases.reverse(),g=>g.cases[0].status=200,g=>g.cases[3].raw_sha256='0'.repeat(64),g=>g.cases[4].body.files[1].path='../secret',g=>g.cases[5].body.accounts=0,g=>g.native_accounts[0].uid=0,g=>g.runtime_paths[0].after='created',g=>g.owned_children_exited=false,g=>g.extra='secret']){const g=sample();change(g);assert.throws(()=>decodePreviewSerial(serial(g),g.nonce,sample().inputs));}
 const g=sample();g.inputs.sifruno='c'.repeat(64);assert.throws(()=>decodePreviewSerial(serial(g),g.nonce,sample().inputs));
});
test('serial duplicate keys, nonce, reordered and repeated framing refuse',()=>{
 const g=sample(),text=serial(g).toString();
 for(const raw of [text.replace('"passed":true','"passed":true,"passed":true'),text+text,text.replace('_EXIT_'+g.nonce+'_0','_EXIT_'+g.nonce+'_1'),text.replace('BEGIN_'+g.nonce,'BEGIN_'+'f'.repeat(32))])assert.throws(()=>decodePreviewSerial(Buffer.from(raw),g.nonce,g.inputs));
});
test('default and check mode never reach native path',()=>{
 const before=existsSync(new URL('../../.cache/native-web-preview',import.meta.url));
 for(const args of [[],['--check']]){const p=spawnSync(process.execPath,['lab/native-web-preview-guest/run.mjs',...args],{encoding:'utf8'});assert.equal(p.status,0);assert.deepEqual(JSON.parse(p.stdout),{mode:'check_only',native_observation:false,requires_explicit_run:true});}
 assert.equal(existsSync(new URL('../../.cache/native-web-preview',import.meta.url)),before);
 const source=readFileSync(new URL('./run.mjs',import.meta.url),'utf8');assert(source.includes("'-nic','none'"));assert(!source.includes('hostfwd'));assert(source.includes("'EmbedFiles'"));
});

test('import ignores importer --run argument without build or guest side effects',()=>{
 const before=existsSync(new URL('../../.cache/native-web-preview',import.meta.url));
 const script="process.argv=['node','unrelated-importer.mjs','--run']; await import('./lab/native-web-preview-guest/run.mjs'); console.log('IMPORT_INERT');";
 const p=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});
 assert.equal(p.status,0);assert.equal(p.stdout.trim(),'IMPORT_INERT');assert.equal(p.stderr,'');
 assert.equal(existsSync(new URL('../../.cache/native-web-preview',import.meta.url)),before);
});
