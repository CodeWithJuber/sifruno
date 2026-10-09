import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const url = source => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sites = url(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const restore = url(readFileSync(new URL("./restorePreview.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sites)));
const api = await import(url(readFileSync(new URL("./archiveRestore.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sites)).replaceAll('"./restorePreview"', JSON.stringify(restore))));
const site = { id:"a".repeat(32), name:"Target", domain:"target.example", preview_host:`site-${"a".repeat(32)}.localhost`,state:"active",revision:2,created_at:"2026-10-09T10:00:00Z",updated_at:"2026-10-09T10:00:00Z" };
const file={path:"index.html",bytes:1,sha256:"b".repeat(64)};
const preview=()=>({site_id:site.id,current_revision:2,archive_sha256:"c".repeat(64),backup_id:"d".repeat(32),backup_revision:99,files:[{path:"index.html",kind:"unchanged",before:file,after:file}],counts:{added:0,modified:0,removed:0,unchanged:1}});
const input=()=>({site,archive:new File(["ZIP fixture bytes"],"site.zip"),csrf:"fixture",isLive:()=>true});
const response=value=>new Response(JSON.stringify(value),{headers:{"Content-Type":"application/json"}});
async function mock(fetcher, action){const old=globalThis.fetch;globalThis.fetch=fetcher;try{await action()}finally{globalThis.fetch=old}}
test("uploaded source revision is independent; strict fields, aliases, counts and source metadata",()=>{
 assert(api.validArchiveRestorePreview(preview()));
 for(const mutate of [p=>p.backup_sha256=p.archive_sha256,p=>p.extra=true,p=>p.current_revision=0,p=>p.counts.added=1,p=>p.files[0].path="../bad.txt",p=>p.archive_sha256="bad",p=>p.backup_revision=Number.MAX_SAFE_INTEGER+1]){const p=structuredClone(preview());mutate(p);assert.equal(api.validArchiveRestorePreview(p),false)}
});
test("preview and explicit confirmation resend identical File bytes and bind revision/hash",async()=>{
 const i=input();let calls=0;
 await mock(async(path,options)=>{calls++;assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.headers["X-CSRF-Token"],i.csrf);assert.equal(await options.body.get("archive").text(),await i.archive.text());assert.equal(options.body.get("expected_revision"),"2");
 if(calls===1){assert(path.endsWith("/archive-restore-preview"));assert.deepEqual([...options.body.keys()],["archive","expected_revision"]);return response(preview())}
 assert(path.endsWith("/archive-restore"));assert.equal(options.body.get("expected_archive_sha256"),preview().archive_sha256);return response({...site,revision:3});},async()=>{const p=await api.previewArchiveRestore(i);await api.confirmArchiveRestore({...i,preview:p})});assert.equal(calls,2);
});
test("late context invalidation, cross-site responses, stale confirmation and malformed body never become success",async()=>{
 let live=true,calls=0;
 await mock(async()=>{calls++;live=false;return response(preview())},()=>assert.rejects(api.previewArchiveRestore({...input(),isLive:()=>live}),e=>e.code==="context_changed"));assert.equal(calls,1);
 await mock(async()=>response({...preview(),site_id:"e".repeat(32)}),()=>assert.rejects(api.previewArchiveRestore(input()),e=>e.code==="invalid_response"));
 await mock(async()=>new Response("{}",{status:409}),()=>assert.rejects(api.confirmArchiveRestore({...input(),preview:preview()}),e=>e.status===409));
 await mock(async()=>response({...site,revision:4}),()=>assert.rejects(api.confirmArchiveRestore({...input(),preview:preview()}),e=>e.code==="invalid_response"));
 await mock(async()=>{throw Error("must not fetch")},()=>assert.rejects(api.confirmArchiveRestore({...input(),preview:{...preview(),current_revision:1}}),e=>e.code==="invalid_preview"));
});
