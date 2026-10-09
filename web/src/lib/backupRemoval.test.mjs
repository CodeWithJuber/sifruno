import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./backupRemoval.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sitesURL))));
const site = () => ({ id:"a".repeat(32), name:"Native static fixture", domain:"fixture.test", preview_host:`site-${"a".repeat(32)}.localhost`, state:"active", revision:9, created_at:"2026-10-09T00:00:00Z",updated_at:"2026-10-09T00:00:00Z" });
const backup = () => ({ id:"b".repeat(32),site_id:site().id,sha256:"c".repeat(64),revision:8,files:1,bytes:100,created_at:site().created_at });
const response = (v,status=200) => new Response(JSON.stringify(v),{status,headers:{"Content-Type":"application/json"}});
async function mockFetch(mock,action) { const original=globalThis.fetch; globalThis.fetch=mock; try { await action(); } finally { globalThis.fetch=original; } }
test("exact native confirmation carries archive hash, revision and CSRF once",async()=>{
  let calls=0;
  await mockFetch(async(url,options)=>{calls++;assert.equal(url,`/api/v1/sites/${site().id}/remove-backup`);assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.headers["X-CSRF-Token"],"fixture-csrf");assert.deepEqual(JSON.parse(options.body),{backup_id:backup().id,expected_backup_sha256:backup().sha256,expected_revision:9,confirmed:true});return response({...site(),revision:10});},async()=>{assert.equal((await api.removeSiteBackup(site(),backup(),"fixture-csrf",()=>true)).revision,10);});assert.equal(calls,1);
});
test("invalid, expired and changed contexts do not send or admit removal",async()=>{
  for(const [s,b] of [[undefined,backup()],[site(),undefined],[{...site(),revision:Number.MAX_SAFE_INTEGER},backup()],[{...site(),state:"recovery_required"},backup()],[site(),{...backup(),site_id:"d".repeat(32)}],[site(),{...backup(),sha256:"bad"}]]) assert.equal(api.canRemoveBackup(s,b),false);
  await mockFetch(()=>assert.fail("must not send"),async()=>await assert.rejects(api.removeSiteBackup(site(),backup(),"fixture-csrf",()=>false),e=>e.code==="session_changed"));
  let live=true;await mockFetch(async()=>{live=false;return response({...site(),revision:10});},async()=>await assert.rejects(api.removeSiteBackup(site(),backup(),"fixture-csrf",()=>live),e=>e.code==="session_changed"));
});
test("stale or uncertain failure never retries; incorrect site results rejected",async()=>{
  for(const status of [401,403,404,409,422,503]) { let calls=0;await mockFetch(async()=>{calls++;return response({error:"request_failed"},status);},async()=>await assert.rejects(api.removeSiteBackup(site(),backup(),"fixture-csrf",()=>true),e=>e.status===status));assert.equal(calls,1); }
  for(const value of [{...site(),revision:9},{...site(),revision:11},{...site(),revision:10,domain:"changed.test"}]) await mockFetch(async()=>response(value),async()=>await assert.rejects(api.removeSiteBackup(site(),backup(),"fixture-csrf",()=>true),e=>e.code==="invalid_response"));
  assert.match(api.backupRemovalError({}),/not retried/);
});
