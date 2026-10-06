import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
const source = await readFile(new URL("../web/src/lib/accounts-web-preview.ts", import.meta.url), "utf8");
const code = stripTypeScriptTypes(source, { mode: "transform" });
const { validAccountsWebPreview: valid, parseAccountsWebPreview: parse, fetchAccountsWebPreview: request, PreviewRequestGate: Gate } = await import("data:text/javascript;base64," + Buffer.from(code).toString("base64"));
const hash = "a".repeat(64);
const empty = () => ({ profile: "restricted-chroot-v1", profile_sha256: hash, snapshot_sha256: hash, bundle_sha256: hash, accounts: 0, active_accounts: 0, suspended_accounts: 0, files: [{ path: "apache/front.conf", mode: 384, bytes: 100, sha256: hash }] });
test("exact metadata, empty inventory and 100-account bound", () => {
  assert(valid(empty())); const v = empty(); v.accounts = v.active_accounts = 100;
  for (let i = 0; i < 100; i++) { const id = i.toString(16).padStart(32, "0"); for (const prefix of ["apache/backends", "fpm"]) v.files.push({ path: prefix + "/" + id + ".conf", mode: 384, bytes: 100, sha256: hash }); }
  assert(valid(v)); v.files[1].path = "fpm/" + "f".repeat(32) + ".conf"; assert(!valid(v));
});
test("schema aliases, missing fields, unsafe counts, paths/modes/hashes and total caps refuse", () => {
  const changes = [
    v => { v.PROFILE = v.profile; }, v => { delete v.accounts; }, v => { v.files = null; },
    v => { v.accounts = 1; }, v => { v.active_accounts = -1; }, v => { v.accounts = 1.5; },
    v => { v.accounts = 101; }, v => { v.files[0].path = "../private"; },
    v => { v.files[0].mode = 420; }, v => { v.files[0].bytes = 0; }, v => { v.files[0].bytes = 262145; },
    v => { v.files[0].sha256 = "A".repeat(64); }, v => { v.files[0].extra = "raw config"; },
  ];
  for (const change of changes) { const v = empty(); change(v); assert(!valid(v)); }
  const v = empty(); v.accounts = v.active_accounts = 100;
  for (let i = 0; i < 100; i++) for (const p of ["apache/backends", "fpm"]) v.files.push({ path: p + "/" + i.toString(16).padStart(32, "0") + ".conf", mode: 384, bytes: 262144, sha256: hash });
  assert(!valid(v));
});
test("JSON duplicates including escaped aliases and trailing JSON refuse", () => {
  const good = JSON.stringify(empty()); assert.deepEqual(parse(good), empty());
  for (const raw of [good.replace('"accounts":0', '"accounts":0,"accounts":0'), good.replace('"profile":', '"prof\\u0069le":"x","profile":'), good + "{}"]) assert.throws(() => parse(raw));
});
test("fixed GET and caller signal; status errors never fabricate zero inventory", async () => {
  const original = globalThis.fetch;
  try {
    let calls = 0;
    globalThis.fetch = async (url, opts) => { calls++; assert.equal(url, "/api/v1/accounts/web-preview"); assert.equal(opts.method, "GET"); assert.equal(opts.credentials, "same-origin"); assert.equal(opts.cache, "no-store"); assert(!("body" in opts)); return new Response(JSON.stringify(empty())); };
    assert.deepEqual(await request(new AbortController().signal), empty()); assert.equal(calls, 1);
    for (const status of [401, 403, 409, 503]) { globalThis.fetch = async () => new Response("private detail", { status }); await assert.rejects(request(new AbortController().signal), e => e.status === status && !e.message.includes("private detail")); }
    globalThis.fetch = async () => new Response("x".repeat(256 * 1024 + 1)); await assert.rejects(request(new AbortController().signal));
  } finally { globalThis.fetch = original; }
});
test("timeout/caller cancellation and stale success/error/finally identities", async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = (_url, opts) => new Promise((_resolve, reject) => { if (opts.signal.aborted) reject(new Error("abort")); else opts.signal.addEventListener("abort", () => reject(new Error("abort")), { once: true }); });
    await assert.rejects(request(new AbortController().signal, 1), e => e.code === "cancelled");
    const c = new AbortController(); const pending = request(c.signal); c.abort(); await assert.rejects(pending, e => e.code === "cancelled");
    const gate = new Gate(); const old = gate.begin(); const current = gate.begin(); assert(old.signal.aborted); assert(!old.current()); assert(current.current());
    let visible = "current"; if (old.current()) visible = "old success"; if (old.current()) visible = "old error"; if (old.current()) visible = "old finally"; assert.equal(visible, "current"); gate.invalidate(); assert(!current.current());
  } finally { globalThis.fetch = original; }
});
