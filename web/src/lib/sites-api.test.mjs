// Actual request helper with isolated fetch and binary fixtures; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const source = stripTypeScriptTypes(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"), { mode: "transform" });
const api = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
const id = "a".repeat(32);
const site = { id, name: "Recovered", domain: "recovered.test", preview_host: `site-${id}.localhost`, state: "active", revision: 1, created_at: "2026-10-07T10:00:00Z", updated_at: "2026-10-07T10:00:00Z" };
const bytes = Uint8Array.of(0x50, 0x4b, 0x03, 0x04, 0, 0xff, 0x80, 0x0a);
async function mockFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

for (const type of ["application/x-zip-compressed", "application/zip", ""]) {
  test(`native ZIP upload normalizes ${type || "missing MIME"} and preserves filename, bytes and authentication`, async () => {
    const archive = new File([bytes], "saved-sifruno.zip", { type });
    let calls = 0;
    await mockFetch(async (url, options) => {
      ++calls;
      assert.equal(url, "/api/v1/sites/import");
      assert.equal(options.method, "POST"); assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store");
      assert(options.signal instanceof AbortSignal);
      assert.equal(options.headers["X-CSRF-Token"], "fixture-csrf"); assert.equal(options.headers.Accept, "application/json");
      assert.equal(options.headers["Content-Type"], undefined, "fetch generates the multipart boundary");
      assert(options.body instanceof FormData);
      assert.deepEqual([...options.body.keys()], ["name", "domain", "archive"]);
      assert.equal(options.body.get("name"), "Recovered"); assert.equal(options.body.get("domain"), "recovered.test");
      const part = options.body.get("archive");
      assert.equal(part.type, "application/zip"); assert.equal(part.name, archive.name); assert.equal(part.size, bytes.length);
      assert.deepEqual(new Uint8Array(await part.arrayBuffer()), bytes);
      return new Response(JSON.stringify(site), { status: 201, headers: { "Content-Type": "application/json" } });
    }, async () => assert.deepEqual(await api.importSiteArchive({ name: "Recovered", domain: "recovered.test", archive, csrf: "fixture-csrf" }), site));
    assert.equal(calls, 1); assert.equal(archive.type, type);
    assert.deepEqual(new Uint8Array(await archive.arrayBuffer()), bytes);
  });
}

test("normalizing MIME preserves server archive rejection", async () => {
  const archive = new File(["not a ZIP archive"], "invalid.zip", { type: "application/x-zip-compressed" });
  await mockFetch(async (_url, options) => {
    const part = options.body.get("archive");
    assert.equal(part.type, "application/zip"); assert.equal(await part.text(), "not a ZIP archive");
    return new Response(JSON.stringify({ error: "invalid_archive" }), { status: 422, headers: { "Content-Type": "application/json" } });
  }, async () => assert.rejects(api.importSiteArchive({ name: "Recovered", domain: "recovered.test", archive, csrf: "fixture-csrf" }), { status: 422, code: "website_transfer_failed" }));
});

for (const type of ["image/png", "font/woff2", "application/pdf", "text/plain", ""]) {
  test(`file upload preserves binary bytes with ${type || "missing MIME"}`, async () => {
    const file = new File([bytes], "asset.png", { type });
    await mockFetch(async (url, options) => {
      assert.equal(url, `/api/v1/sites/${id}/upload`); assert.equal(options.method, "POST");
      assert.equal(options.credentials, "same-origin"); assert.equal(options.headers["X-CSRF-Token"], "fixture-csrf");
      assert.equal(options.headers["Content-Type"], "application/json");
      const body = JSON.parse(options.body);
      assert.deepEqual(Object.keys(body).sort(), ["content", "expected_revision", "path"]);
      assert.equal(body.path, "assets/asset.png"); assert.equal(body.expected_revision, 1);
      assert.deepEqual(new Uint8Array(Buffer.from(body.content, "base64")), bytes);
      return new Response(JSON.stringify({ ...site, revision: 2 }), { status: 200 });
    }, async () => assert.equal((await api.uploadSiteFile({ siteId: id, path: "assets/asset.png", file, expectedRevision: 1, csrf: "fixture-csrf", isLive: () => true })).revision, 2));
  });
}
test("upload refuses oversized local bytes and stale sessions before dispatch", async () => {
  await mockFetch(async () => assert.fail("must not dispatch"), async () => {
    const input = { siteId: id, path: "x.png", expectedRevision: 1, csrf: "fixture-csrf", isLive: () => true };
    await assert.rejects(api.uploadSiteFile({ ...input, file: new Blob([new Uint8Array(2 * 1024 * 1024 + 1)]) }), { status: 413 });
    await assert.rejects(api.uploadSiteFile({ ...input, file: new Blob([bytes]), isLive: () => false }), { status: 401 });
  });
});
for (const status of [401, 403, 409, 413, 422, 503]) {
  test(`upload surfaces HTTP ${status} without retry or success`, async () => {
    let calls = 0;
    await mockFetch(async () => { ++calls; return new Response("{}", { status }); }, async () => {
      await assert.rejects(api.uploadSiteFile({ siteId: id, path: "x.png", file: new Blob([bytes]), expectedRevision: 1, csrf: "fixture-csrf", isLive: () => true }), { status });
    });
    assert.equal(calls, 1);
  });
}
test("upload rejects a response for an unrelated revision", async () => {
  await mockFetch(async () => new Response(JSON.stringify(site), { status: 200 }), async () => {
    await assert.rejects(api.uploadSiteFile({ siteId: id, path: "x.png", file: new Blob([bytes]), expectedRevision: 1, csrf: "fixture-csrf", isLive: () => true }), { code: "invalid_response" });
  });
});


test("binary replacement sends exact bytes and saved hash through authenticated PUT", async () => {
  const expectedSHA256 = "d".repeat(64), file = new File([bytes], "replacement.png", { type: "image/png" });
  await mockFetch(async (url, options) => {
    assert.equal(url, `/api/v1/sites/${id}/upload`); assert.equal(options.method, "PUT");
    assert.equal(options.credentials, "same-origin"); assert.equal(options.headers["X-CSRF-Token"], "fixture-csrf");
    const body = JSON.parse(options.body);
    assert.deepEqual(Object.keys(body).sort(), ["content", "expected_revision", "expected_sha256", "path"]);
    assert.equal(body.path, "assets/old.png"); assert.equal(body.expected_revision, 1); assert.equal(body.expected_sha256, expectedSHA256);
    assert.deepEqual(new Uint8Array(Buffer.from(body.content, "base64")), bytes);
    return new Response(JSON.stringify({ ...site, revision: 2 }), { status: 200 });
  }, async () => assert.equal((await api.replaceSiteFile({ siteId: id, path: "assets/old.png", file, expectedRevision: 1, expectedSHA256, csrf: "fixture-csrf", isLive: () => true })).revision, 2));
});
test("replacement refuses missing hashes and session change before dispatch", async () => {
  const input = { siteId: id, path: "x.png", file: new Blob([bytes]), expectedRevision: 1, csrf: "fixture-csrf", isLive: () => true };
  await mockFetch(async () => assert.fail("must not dispatch"), async () => {
    for (const expectedSHA256 of ["", "bad"]) await assert.rejects(api.replaceSiteFile({ ...input, expectedSHA256 }), { status: 422 });
    await assert.rejects(api.replaceSiteFile({ ...input, expectedSHA256: "d".repeat(64), isLive: () => false }), { status: 401 });
    await assert.rejects(api.replaceSiteFile({ ...input, expectedSHA256: "d".repeat(64), file: new Blob([new Uint8Array(2 * 1024 * 1024 + 1)]) }), { status: 413 });
  });
});
test("replacement conflict keeps its refusal without retry or create fallback", async () => {
  let calls = 0;
  await mockFetch(async (_url, options) => { ++calls; assert.equal(options.method, "PUT"); return new Response("{}", { status: 409 }); }, async () => {
    await assert.rejects(api.replaceSiteFile({ siteId: id, path: "missing.png", file: new Blob([bytes]), expectedRevision: 1, expectedSHA256: "d".repeat(64), csrf: "fixture-csrf", isLive: () => true }), { status: 409 });
  }); assert.equal(calls, 1);
});
