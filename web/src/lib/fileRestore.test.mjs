import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const restoreURL = moduleURL(readFileSync(new URL("./restorePreview.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sitesURL)));
const api = await import(moduleURL(readFileSync(new URL("./fileRestore.ts", import.meta.url), "utf8").replaceAll('"./sites-api"',JSON.stringify(sitesURL)).replaceAll('"./restorePreview"',JSON.stringify(restoreURL))));
const site={id:"a".repeat(32),name:"Test",domain:"test.test",preview_host:"test.localhost",state:"active",revision:9,created_at:"2026-10-09T10:00:00Z",updated_at:"2026-10-09T10:00:00Z"};
const backup={id:"b".repeat(32),site_id:site.id,sha256:"c".repeat(64),revision:4,files:3};
const info={path:"pixel.png",bytes:11,sha256:"d".repeat(64)};
const preview=()=>({site_id:site.id,current_revision:site.revision,backup_id:backup.id,backup_sha256:backup.sha256,backup_revision:backup.revision,file:{path:info.path,kind:"added",before:null,after:info},preserved_files:3});

test("one-file metadata is strict and binds exact context",()=>{
 assert(api.fileRestoreMatches(preview(),site,backup,info.path));
 for(const mutate of [p=>p.extra=true,p=>p.preserved_files=64,p=>p.file.kind="removed",p=>p.file.after=null,p=>p.file.path="other.png",p=>p.file.after={...info,path:"../pixel.png"},p=>p.file.before=info,p=>p.file.after={...info,bytes:2097153}]){const p=structuredClone(preview());mutate(p);assert.equal(api.validFileRestorePreview(p),false)}
 for(const mutate of [p=>p.current_revision++,p=>p.backup_sha256="e".repeat(64),p=>p.backup_id="f".repeat(32),p=>p.site_id="f".repeat(32)]){const p=preview();mutate(p);assert.equal(api.fileRestoreMatches(p,site,backup,info.path),false)}
});

test("actual Huma HTTP envelope admits only the known schema metadata",async()=>{
 const wire={...preview(),$schema:"http://127.0.0.1:18640/FileRestorePreview.json"};
 assert(api.validFileRestorePreview(wire));assert(api.fileRestoreMatches(wire,site,backup,info.path));
 for(const schema of [null,{},"javascript:alert(1)","http://127.0.0.1:18640/Other.json","http://user:password@127.0.0.1/FileRestorePreview.json","http://127.0.0.1/FileRestorePreview.json?extra=1","http://127.0.0.1/FileRestorePreview.json#other"]){assert.equal(api.validFileRestorePreview({...wire,$schema:schema}),false)}
 assert.equal(api.validFileRestorePreview({...wire,unknown:true}),false);
 assert.equal(api.validFileRestorePreview({...wire,file:{...wire.file,$schema:wire.$schema}}),false);
 const old=globalThis.fetch;
 try { globalThis.fetch=async()=>new Response(JSON.stringify(wire),{status:200});assert.deepEqual(await api.previewFileRestore(site,backup,info.path,"test-csrf"),wire); }
 finally {globalThis.fetch=old}
});

test("preview and confirmation send exactly one file and do not retry failures",async()=>{
 const old=globalThis.fetch;let requests=[];
 try{
 globalThis.fetch=async(url,options)=>{requests.push({url,body:JSON.parse(options.body)});return new Response(JSON.stringify(preview()),{status:200})};
 const p=await api.previewFileRestore(site,backup,info.path,"test-csrf");
 assert.equal(requests.length,1);assert(requests[0].url.endsWith("/restore-file-preview"));assert.deepEqual(requests[0].body,{backup_id:backup.id,expected_backup_sha256:backup.sha256,expected_revision:9,path:info.path});
 const input={site,backup,path:info.path,preview:p,confirmed:true,csrf:"test-csrf",isLive:()=>true};
 for(const overrides of [{confirmed:false},{path:"other.txt"},{isLive:()=>false},{site:{...site,revision:10}}]){await assert.rejects(api.confirmFileRestore({...input,...overrides}));assert.equal(requests.length,1)}
 globalThis.fetch=async(url,options)=>{requests.push({url,body:JSON.parse(options.body)});return new Response(JSON.stringify({error:"conflict"}),{status:409})};
 await assert.rejects(api.confirmFileRestore(input));assert.equal(requests.length,2);assert(requests[1].url.endsWith("/restore-file"));assert.deepEqual(requests[1].body,{...requests[0].body,confirmed:true});
 globalThis.fetch=async()=>{throw new Error("connection ended")};await assert.rejects(api.confirmFileRestore(input));
 }finally{globalThis.fetch=old}
});
