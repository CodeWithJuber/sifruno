import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./restoreHandoff.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sitesURL))));
const site = () => ({ id: "a".repeat(32), name: "Exact target", domain: "fixture.test", preview_host: `site-${"a".repeat(32)}.localhost`, state: "active", revision: 9, created_at: "2026-10-09T00:00:00Z", updated_at: "2026-10-09T00:00:00Z" });
const backup = () => ({ id: "b".repeat(32), site_id: site().id, sha256: "c".repeat(64), revision: 8, files: 1, bytes: 100, created_at: site().created_at });
const request = () => ({ backupId: backup().id, backupSHA256: backup().sha256, expectedRevision: site().revision });

test("handoff carries exact saved site revision, archive ID and hash without writing", () => {
  const original = globalThis.fetch;
  globalThis.fetch = () => assert.fail("handoff resolution must not make requests");
  try {
    const selected = backup();
    assert.deepEqual(api.restoreHandoffFor(site(), selected), request());
    assert.equal(api.resolveRestoreHandoff(request(), site().id, site(), [{ ...backup(), id: "d".repeat(32) }, selected]), selected);
    assert.equal(api.resolveRestoreHandoff(request(), site().id, { ...site(), state: "suspended" }, [selected]), selected);
  } finally { globalThis.fetch = original; }
});
test("fresh inventory never substitutes a deleted, changed, duplicate or foreign archive", () => {
  for (const inventory of [[], [{ ...backup(), id: "d".repeat(32) }], [{ ...backup(), sha256: "d".repeat(64) }], [{ ...backup(), site_id: "d".repeat(32) }], [backup(), backup()], [{ ...backup(), revision: 10 }], [{ ...backup(), files: 0 }]]) {
    assert.throws(() => api.resolveRestoreHandoff(request(), site().id, site(), inventory), error => error.code === "archive_handoff_changed");
  }
});
test("stale saved revision, recovery and malformed handoff are refused", () => {
  assert.throws(() => api.resolveRestoreHandoff(request(), site().id, { ...site(), revision: 10 }, [backup()]), error => error.code === "stale_handoff");
  for (const requested of [{ ...request(), backupId: "bad" }, { ...request(), backupSHA256: "bad" }, { ...request(), expectedRevision: 0 }, { ...request(), expectedRevision: Number.MAX_SAFE_INTEGER + 1 }, { ...request(), confirmed: true }, { ...request(), backupSHA256: undefined }]) assert.throws(() => api.resolveRestoreHandoff(requested, site().id, site(), [backup()]), error => error.code === "invalid_handoff");
  for (const value of [{ ...site(), state: "recovery_required" }, { ...site(), id: "d".repeat(32) }]) assert.throws(() => api.resolveRestoreHandoff(request(), site().id, value, [backup()]), error => error.code === "invalid_handoff");
});
