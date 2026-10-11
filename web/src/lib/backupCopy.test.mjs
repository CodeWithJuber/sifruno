import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const restoreURL = moduleURL(readFileSync(new URL("./restoreHandoff.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sitesURL)));
const api = await import(moduleURL(readFileSync(new URL("./backupCopy.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sitesURL)).replaceAll('"./restoreHandoff"', JSON.stringify(restoreURL))));
const raw = Uint8Array.of(0x50, 0x4b, 3, 4, 0, 255, 128);
const sha = Buffer.from(await crypto.subtle.digest("SHA-256", raw)).toString("hex");
const site = { id: "a".repeat(32), name: "Source", domain: "source.test", preview_host: `site-${"a".repeat(32)}.localhost`, state: "active", revision: 9, created_at: "2026-10-09T00:00:00Z", updated_at: "2026-10-09T00:00:00Z" };
const backup = { id: "b".repeat(32), site_id: site.id, sha256: sha, revision: 8, files: 2, bytes: raw.length, created_at: site.created_at };
const selection = api.backupCopySelection(site, backup);
async function fixture(run, { current = site, archives = [backup], bytes = raw, onRequest = () => {} } = {}) {
  const original = globalThis.fetch, calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push(url); onRequest(url);
    assert.equal(options.method, "GET", "preparation must never mutate");
    assert.equal(options.credentials, "same-origin");
    if (url === `/api/v1/sites/${site.id}`) return Response.json(current);
    if (url === `/api/v1/sites/${site.id}/backups`) return Response.json({ items: archives });
    assert.equal(url, `/api/v1/sites/${site.id}/backups/${backup.id}/download`);
    return new Response(bytes, { headers: { "Content-Type": "application/zip" } });
  };
  try { await run(calls); } finally { globalThis.fetch = original; }
}

test("preparation binds fresh source to the exact saved archive and verifies raw bytes without import", async () => {
  await fixture(async calls => {
    const prepared = await api.prepareBackupCopy(selection, [site], () => true);
    assert.deepEqual(prepared.site, site); assert.deepEqual(prepared.backup, backup);
    assert.equal(prepared.archive.type, "application/zip");
    assert.deepEqual(new Uint8Array(await prepared.archive.arrayBuffer()), raw);
    assert.equal(calls.length, 3);
  });
});

test("missing, changed, duplicate and foreign snapshots never select a replacement or download", async () => {
  for (const archives of [[], [{ ...backup, id: "d".repeat(32) }], [{ ...backup, sha256: "d".repeat(64) }], [backup, backup], [{ ...backup, site_id: "d".repeat(32) }]]) {
    await fixture(async calls => {
      await assert.rejects(api.prepareBackupCopy(selection, [site], () => true), { code: "archive_handoff_changed" });
      assert.equal(calls.length, 2);
    }, { archives });
  }
});

test("missing source, stale revision, foreign record and recovery-required source refuse preparation", async () => {
  await fixture(async calls => { await assert.rejects(api.prepareBackupCopy(selection, [], () => true), { code: "copy_source_missing" }); assert.equal(calls.length, 0); });
  for (const current of [{ ...site, revision: 10 }, { ...site, state: "recovery_required" }, { ...site, id: "d".repeat(32), preview_host: `site-${"d".repeat(32)}.localhost` }]) {
    await fixture(async calls => { await assert.rejects(api.prepareBackupCopy(selection, [site], () => true)); assert.equal(calls.length, 2); }, { current });
  }
  await fixture(async () => assert.rejects(api.prepareBackupCopy({ ...selection, expectedRevision: 8 }, [site], () => true), { code: "stale_handoff" }));
});

test("corrupt ZIP or a saved byte-count mismatch is never preloaded", async () => {
  await fixture(async () => assert.rejects(api.prepareBackupCopy(selection, [site], () => true), { code: "invalid_response" }), { bytes: Uint8Array.of(1, 2, 3) });
  await fixture(async () => assert.rejects(api.prepareBackupCopy(selection, [site], () => true), { code: "copy_archive_changed" }), { archives: [{ ...backup, bytes: raw.length + 1 }] });
});

test("lost context before inventory or while downloading never returns prepared bytes", async () => {
  await fixture(async calls => { await assert.rejects(api.prepareBackupCopy(selection, [site], () => false), { code: "copy_context_changed" }); assert.equal(calls.length, 0); });
  for (const phase of ["/backups", "/download"]) {
    let live = true;
    await fixture(async calls => {
      await assert.rejects(api.prepareBackupCopy(selection, [site], () => live), { code: "copy_context_changed" });
      assert.equal(calls.length, phase === "/download" ? 3 : 2);
    }, { onRequest: url => { if (url.endsWith(phase)) live = false; } });
  }
});
