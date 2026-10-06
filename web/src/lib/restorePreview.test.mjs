// Actual TypeScript validator/request source; synthetic DTOs/fetch only, no state or servers.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./restorePreview.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sitesURL))));
const siteId = "a".repeat(32), backupId = "b".repeat(32), archiveSha = "c".repeat(64);
const file = (path, bytes = 10, sha256 = "d".repeat(64)) => ({ path, bytes, sha256 });
const backup = () => ({ id: backupId, site_id: siteId, created_at: "2026-10-06T10:00:00Z", bytes: 100, files: 3, sha256: archiveSha, revision: 4 });
const preview = () => ({ site_id: siteId, current_revision: 9, backup_id: backupId, backup_sha256: archiveSha, backup_revision: 4,
  files: [
    { path: "added.txt", kind: "added", before: null, after: file("added.txt") },
    { path: "index.html", kind: "modified", before: file("index.html"), after: file("index.html", 10, "e".repeat(64)) },
    { path: "keep.css", kind: "unchanged", before: file("keep.css", 0), after: file("keep.css", 0) },
    { path: "removed.txt", kind: "removed", before: file("removed.txt"), after: null },
  ], counts: { added: 1, modified: 1, removed: 1, unchanged: 1 } });
const cloned = value => structuredClone(value);
async function mockFetch(mock, operation) { const original = globalThis.fetch; globalThis.fetch = mock; try { await operation(); } finally { globalThis.fetch = original; } }
const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

test("mixed preview and zero-change snapshot have correct kind counts and selected archive binding", () => {
  assert(api.validRestorePreview(preview())); assert(api.restorePreviewMatches(preview(), siteId, 9, backup()));
  const unchanged = preview(); unchanged.files = [unchanged.files[2]]; unchanged.counts = { added: 0, modified: 0, removed: 0, unchanged: 1 };
  assert(api.validRestorePreview(unchanged));
  assert(api.restorePreviewMatches(unchanged, siteId, 9, { ...backup(), files: 1 }));
  const sizeChanged = preview(); sizeChanged.files[1].after = file("index.html", 11);
  assert(api.validRestorePreview(sizeChanged), "bytes alone identify a modification");
});
test("every object rejects omitted and extra fields, including file metadata and counts", () => {
  for (const target of [value => value, value => value.counts, value => value.files[1], value => value.files[1].before, value => value.files[1].after]) {
    const expected = target(preview());
    for (const key of Object.keys(expected)) { const value = preview(); delete target(value)[key]; assert.equal(api.validRestorePreview(value), false, key); }
    const value = preview(); target(value).content = "private content must never be admitted"; assert.equal(api.validRestorePreview(value), false);
  }
  for (const value of [null, [], {}, { ...preview(), files: null }, { ...preview(), counts: [] }]) assert.equal(api.validRestorePreview(value), false);
});
test("native path rules reject traversal, host paths, aliases, reserved names and unsupported extensions", () => {
  for (const path of ["", "/index.html", "C:/index.html", "a\\index.html", "../index.html", "a/./index.html", "a//index.html", "a/%2e.html", "a/index.html?secret", "a/index.html#x", "a/index.html\0", ".env.txt", "con.txt", "COM0/a.txt", "password/index.html", "id_rsa_old.txt", "secrets.json", "source.php", "résumé.txt", "a".repeat(81) + ".txt", Array(9).fill("a").join("/") + ".txt", "a." + "/x.txt", Array(4).fill("a".repeat(60)).join("/") + ".txt"]) {
    assert.equal(api.validRestorePath(path), false, path);
  }
  for (const path of ["index.html", "assets/Logo.PNG", "a-1/a_2.min.js", "font.woff2"]) assert(api.validRestorePath(path));
  const duplicate = preview(); duplicate.files[2].path = duplicate.files[1].path; duplicate.files[2].before.path = duplicate.files[2].after.path = duplicate.files[2].path;
  assert.equal(api.validRestorePreview(duplicate), false);
  const alias = preview(); alias.files[1].path = "Keep.css"; alias.files[1].before.path = alias.files[1].after.path = "Keep.css"; alias.files.sort((a, b) => a.path < b.path ? -1 : 1);
  assert.equal(api.validRestorePreview(alias), false);
  const unsorted = preview(); unsorted.files.reverse(); assert.equal(api.validRestorePreview(unsorted), false);
});
test("kind semantics reject invented additions/removals, unchanged corruption and disconnected metadata paths", () => {
  for (const change of [v => { v.files[0].before = file("added.txt"); }, v => { v.files[0].after = null; }, v => { v.files[3].after = file("removed.txt"); }, v => { v.files[3].before = null; }, v => { v.files[1].after = cloned(v.files[1].before); }, v => { v.files[1].before = null; }, v => { v.files[2].after.sha256 = "f".repeat(64); }, v => { v.files[2].after.bytes = 1; }, v => { v.files[1].after.path = "other.txt"; }, v => { v.files[1].kind = "changed"; }, v => { v.files[1].kind = {}; }]) {
    const value = preview(); change(value); assert.equal(api.validRestorePreview(value), false);
  }
});
test("revisions, identifiers, SHA-256, bytes and count sums fail closed", () => {
  for (const field of ["current_revision", "backup_revision"]) for (const invalid of [0, -1, 1.5, "9", Number.MAX_SAFE_INTEGER + 1]) assert.equal(api.validRestorePreview({ ...preview(), [field]: invalid }), false);
  assert.equal(api.validRestorePreview({ ...preview(), backup_revision: 10 }), false);
  for (const field of ["site_id", "backup_id", "backup_sha256"]) for (const invalid of [null, {}, "A".repeat(field.endsWith("sha256") ? 64 : 32), "a", "a".repeat(65)]) assert.equal(api.validRestorePreview({ ...preview(), [field]: invalid }), false);
  for (const invalid of [-1, 2 ** 21 + 1, 0.1, "10", Number.MAX_SAFE_INTEGER + 1]) { const value = preview(); value.files[1].before.bytes = invalid; assert.equal(api.validRestorePreview(value), false); }
  const badHash = preview(); badHash.files[1].before.sha256 = "D".repeat(64); assert.equal(api.validRestorePreview(badHash), false);
  for (const kind of api.restoreKinds) for (const invalid of [0, 2, -1, 0.5, "1", 129]) { const value = preview(); value.counts[kind] = invalid; assert.equal(api.validRestorePreview(value), false); }
});
test("union admits 128 disjoint bounded paths but rejects 129, excessive side count or aggregate bytes", () => {
  const boundary = preview(); boundary.files = [];
  for (let index = 0; index < 64; index++) { const path = `backup-${String(index).padStart(3, "0")}.txt`; boundary.files.push({ path, kind: "added", before: null, after: file(path, 0) }); }
  for (let index = 0; index < 64; index++) { const path = `current-${String(index).padStart(3, "0")}.txt`; boundary.files.push({ path, kind: "removed", before: file(path, 0), after: null }); }
  boundary.counts = { added: 64, modified: 0, removed: 64, unchanged: 0 }; assert(api.validRestorePreview(boundary));
  const overflow = cloned(boundary); overflow.files.push({ path: "z.txt", kind: "added", before: null, after: file("z.txt") }); overflow.counts.added++; assert.equal(api.validRestorePreview(overflow), false);
  const catalog = count => ({ ...preview(), files: Array.from({ length: count }, (_, i) => { const path = `file-${String(i).padStart(3, "0")}.txt`; return { path, kind: "unchanged", before: file(path, 2 << 20), after: file(path, 2 << 20) }; }), counts: { added: 0, modified: 0, removed: 0, unchanged: count } });
  assert(api.validRestorePreview(catalog(16))); assert.equal(api.validRestorePreview(catalog(17)), false);
  const sideOverflow = catalog(65); for (const entry of sideOverflow.files) { entry.before.bytes = entry.after.bytes = 0; } assert.equal(api.validRestorePreview(sideOverflow), false);
});
test("selected site, current revision, immutable archive identity and file count cannot be rebound", () => {
  for (const [site, revision, selected] of [["f".repeat(32), 9, backup()], [siteId, 10, backup()], [siteId, 9, { ...backup(), id: "f".repeat(32) }], [siteId, 9, { ...backup(), sha256: "f".repeat(64) }], [siteId, 9, { ...backup(), revision: 5 }], [siteId, 9, { ...backup(), site_id: "f".repeat(32) }], [siteId, 9, { ...backup(), files: 4 }]]) assert.equal(api.restorePreviewMatches(preview(), site, revision, selected), false);
});
test("maximum safe revision remains readable but cannot initiate an unsafe restore advance", () => {
  const value = { ...preview(), current_revision: Number.MAX_SAFE_INTEGER };
  assert(api.validRestorePreview(value)); assert(api.restorePreviewMatches(value, siteId, Number.MAX_SAFE_INTEGER, backup()));
  assert.equal(api.canConfirmRestorePreview(value, siteId, Number.MAX_SAFE_INTEGER, backup()), false);
  value.current_revision--; assert(api.canConfirmRestorePreview(value, siteId, Number.MAX_SAFE_INTEGER - 1, backup()));
  value.current_revision += 2; assert.equal(api.canConfirmRestorePreview(value, siteId, Number.MAX_SAFE_INTEGER + 1, backup()), false);
  assert.equal(api.canConfirmRestorePreview(preview(), siteId, 8, backup()), false);
});
test("preview request sends only the exact selected IDs/revision with same-origin session and memory-only CSRF", async () => {
  await mockFetch(async (url, options) => {
    assert.equal(url, `/api/v1/sites/${siteId}/restore-preview`); assert.equal(options.method, "POST"); assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store");
    assert.equal(options.headers["X-CSRF-Token"], "fixture-csrf"); assert.deepEqual(JSON.parse(options.body), { backup_id: backupId, expected_revision: 9 });
    return response(preview());
  }, async () => assert.deepEqual(await api.getRestorePreview(siteId, 9, backup(), "fixture-csrf"), preview()));
});
test("mismatched successful responses and HTTP 409/503 never produce a confirmed preview or auto retry", async () => {
  for (const change of [v => { v.current_revision = 10; }, v => { v.backup_sha256 = "f".repeat(64); }, v => { v.counts.modified = 2; }]) {
    const value = preview(); change(value); await mockFetch(async () => response(value), async () => await assert.rejects(api.getRestorePreview(siteId, 9, backup(), "fixture-csrf"), { code: "invalid_response" }));
  }
  for (const status of [409, 503]) { let calls = 0; await mockFetch(async () => { calls++; return response({ error: "fixture_failure" }, status); }, async () => { await assert.rejects(api.getRestorePreview(siteId, 9, backup(), "fixture-csrf"), { status }); assert.equal(calls, 1); }); }
  let calls = 0; await mockFetch(async () => { calls++; return response(preview()); }, async () => {
    for (const [site, revision, selected, csrf] of [[siteId, 0, backup(), "x"], [siteId, 9, backup(), ""], [siteId, 9, { ...backup(), id: "../other" }, "x"], [siteId, 9, { ...backup(), site_id: "f".repeat(32) }, "x"]]) assert.throws(() => api.getRestorePreview(site, revision, selected, csrf));
    assert.equal(calls, 0);
  });
});
