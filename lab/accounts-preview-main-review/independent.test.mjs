import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {stripTypeScriptTypes} from 'node:module';
const source=await fs.readFile('web/src/lib/accounts-web-preview.ts','utf8');
const m=await import('data:text/javascript;base64,'+Buffer.from(stripTypeScriptTypes(source,{mode:'transform'})).toString('base64'));
const h='a'.repeat(64),base={profile:'restricted-chroot-v1',profile_sha256:h,snapshot_sha256:h,bundle_sha256:h,accounts:0,active_accounts:0,suspended_accounts:0,files:[{path:'apache/front.conf',mode:384,bytes:1,sha256:h}]};
test('independent malformed metadata boundaries',()=>{
 for(const raw of [JSON.stringify(base).replace('"bytes":1','"bytes":1,"byt\\u0065s":2'),JSON.stringify({...base,accounts:null}),JSON.stringify({...base,profile_sha256:h+'\n'}),JSON.stringify({...base,files:[{...base.files[0],path:'apache/front.conf\n'}]})])assert.throws(()=>m.parseAccountsWebPreview(raw));
});
test('late resolved transport after cancellation cannot publish success',async()=>{
 const previous=globalThis.fetch;let resolve;try{
 globalThis.fetch=()=>new Promise(r=>resolve=r);
 const gate=new m.PreviewRequestGate(),old=gate.begin();const result=m.fetchAccountsWebPreview(old.signal);gate.invalidate();
 resolve(new Response(JSON.stringify(base)));
 await assert.rejects(result,e=>e.code==='cancelled');assert.equal(old.current(),false);
 }finally{globalThis.fetch=previous;}
});
test('late unauthorized transport cannot change newer request state',async()=>{
 const previous=globalThis.fetch;let resolve;try{
 globalThis.fetch=()=>new Promise(r=>resolve=r);
 const gate=new m.PreviewRequestGate(),old=gate.begin();let state='new-session';
 const result=m.fetchAccountsWebPreview(old.signal).catch(e=>{if(old.current())state='signed-out';return e.status;}).finally(()=>{if(old.current())state='old-complete';});
 const current=gate.begin();resolve(new Response('{}',{status:401}));
 assert.equal(await result,401);assert.equal(state,'new-session');assert(current.current());
 }finally{globalThis.fetch=previous;}
});
test('malformed UTF8 is rejected before render',async()=>{
 const previous=globalThis.fetch;try{globalThis.fetch=async()=>new Response(new Uint8Array([0xc3,0x28]));await assert.rejects(m.fetchAccountsWebPreview(new AbortController().signal));}finally{globalThis.fetch=previous;}
});
