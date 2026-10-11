// Actual request helper with isolated fetch and binary fixtures; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const source = stripTypeScriptTypes(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"), { mode: "transform" });
const api = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
const fileManagerSource = readFileSync(new URL("../FileManager.tsx", import.meta.url), "utf8");
const previewValidatorSource = fileManagerSource.match(/const utf8Bytes = [^\n]+/)[0] + "\n" + fileManagerSource.slice(fileManagerSource.indexOf("const textExtensions"), fileManagerSource.indexOf("function validUtf16")) + "\nexport { validPath };";
const previewValidator = await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(previewValidatorSource, { mode: "transform" })).toString("base64")}`);
const id = "a".repeat(32);
const site = { id, name: "Recovered", domain: "recovered.test", preview_host: `site-${id}.localhost`, state: "active", revision: 1, created_at: "2026-10-07T10:00:00Z", updated_at: "2026-10-07T10:00:00Z" };
const bytes = Uint8Array.of(0x50, 0x4b, 0x03, 0x04, 0, 0xff, 0x80, 0x0a);
function withPreviewPort(content, operation) {
  const original = globalThis.document;
  globalThis.document = { querySelector(selector) { assert.equal(selector, 'meta[name="sifruno-sites-port"]'); return content === undefined ? null : { content }; } };
  try { operation(); } finally { if (original === undefined) delete globalThis.document; else globalThis.document = original; }
}
test("saved file preview uses the exact injected local HTTP port and validated saved path", () => {
  for (const [content, port] of [["8127", 8127], [" 8127 ", 8127], ["1", 1], ["65535", 65535], [undefined, 8082]]) {
    withPreviewPort(content, () => {
      for (const path of ["index.html", "assets/Saved-image.png", "docs/readme.txt", "downloads/manual.pdf"]) {
        assert.equal(api.savedFilePreviewURL(site, path, previewValidator.validPath), `http://site-${id}.localhost:${port}/${path}`);
      }
    });
  }
});
test("saved file preview inherits disabled port policy and rejects invalid site or preview host", () => {
  for (const content of ["", "0", "65536", "-1", "8127/path", "http://foreign.invalid", "8082.5", "invalid"]) {
    withPreviewPort(content, () => assert.equal(api.savedFilePreviewURL(site, "index.html", previewValidator.validPath), undefined));
  }
  withPreviewPort("8127", () => {
    for (const changed of [undefined, { ...site, id: "invalid" }, { ...site, preview_host: "foreign.invalid" }, { ...site, preview_host: `site-${id}.localhost@foreign.invalid` }, { ...site, state: "unknown" }, { ...site, revision: -1 }]) {
      assert.equal(api.savedFilePreviewURL(changed, "index.html", previewValidator.validPath), undefined);
    }
  });
});
test("saved file preview refuses unsafe paths with no external or root URL fallback", () => {
  withPreviewPort("8127", () => {
    for (const path of ["", "/", "../index.html", "nested/../index.html", "//foreign.invalid/index.html", "https://foreign.invalid/index.html", "javascript:alert(1)", "assets/%2e%2e/index.html", "assets/a.html?host=foreign.invalid", "assets/a.html#fragment", "assets\\a.html", "assets//a.html", "credentials.txt", "script.php", "a/./index.html"]) {
      assert.equal(api.savedFilePreviewURL(site, path, previewValidator.validPath), undefined);
    }
  });
});
const renameInput = { siteId: id, path: "assets/old.png", destination: "images/new.png", expectedSHA256: "d".repeat(64), expectedRevision: 1, csrf: "fixture-csrf", isLive: () => true };
async function mockFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

test("rename dispatches one authenticated checked mutation without file bytes", async () => {
  let calls = 0;
  await mockFetch(async (url, options) => {
    ++calls;
    assert.equal(url, `/api/v1/sites/${id}/rename`); assert.equal(options.method, "POST");
    assert.equal(options.credentials, "same-origin"); assert.equal(options.headers["X-CSRF-Token"], "fixture-csrf");
    assert.deepEqual(JSON.parse(options.body), { path: renameInput.path, destination: renameInput.destination, expected_sha256: renameInput.expectedSHA256, expected_revision: 1 });
    return new Response(JSON.stringify({ ...site, revision: 2 }), { status: 200 });
  }, async () => assert.equal((await api.renameSiteFile(renameInput)).revision, 2));
  assert.equal(calls, 1);
});
test("rename rejects no-op, invalid source metadata and expired context before dispatch", async () => {
  await mockFetch(async () => assert.fail("must not dispatch"), async () => {
    for (const change of [{ destination: renameInput.path.toUpperCase() }, { expectedRevision: 0 }, { expectedSHA256: "" }, { siteId: "other" }, { destination: "../outside.html" }]) {
      await assert.rejects(api.renameSiteFile({ ...renameInput, ...change }), { status: 422 });
    }
    await assert.rejects(api.renameSiteFile({ ...renameInput, isLive: () => false }), { status: 401 });
  });
});
for (const status of [401, 403, 404, 409, 422, 503]) {
  test(`rename surfaces HTTP ${status} once, keeping source and destination`, async () => {
    let calls = 0;
    await mockFetch(async () => { ++calls; return new Response("{}", { status }); }, async () => {
      await assert.rejects(api.renameSiteFile(renameInput), { status });
    });
    assert.equal(calls, 1); assert.equal(renameInput.destination, "images/new.png"); assert.equal(renameInput.path, "assets/old.png");
  });
}
test("rename rejects unrelated site/revision and context lost during response", async () => {
  for (const changed of [{ revision: 1 }, { revision: 3 }, { id: "b".repeat(32), preview_host: `site-${"b".repeat(32)}.localhost` }]) {
    await mockFetch(async () => new Response(JSON.stringify({ ...site, revision: 2, ...changed })), async () => assert.rejects(api.renameSiteFile(renameInput), { code: "invalid_response" }));
  }
  let live = true;
  await mockFetch(async () => { live = false; return new Response(JSON.stringify({ ...site, revision: 2 })); }, async () => assert.rejects(api.renameSiteFile({ ...renameInput, isLive: () => live }), { status: 401 }));
});

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

const fileSHA = async (data) => Buffer.from(await crypto.subtle.digest("SHA-256", data)).toString("hex");
async function downloadInput(data = bytes) {
  return { siteId: id, file: { path: "assets/saved.png", bytes: data.length, sha256: await fileSHA(data) }, expectedRevision: 2, isLive: () => true };
}
function fileResponse(data, input, overrides = {}) {
  return new Response(data, { headers: { "Content-Type": "application/octet-stream", "Content-Disposition": 'attachment; filename="saved.png"', "Content-Length": String(input.file.bytes), ...overrides } });
}
for (const [name, data] of [["binary", bytes], ["UTF-8", new TextEncoder().encode("مرحبا saved\n")], ["empty", new Uint8Array()], ["maximum-size", new Uint8Array(2 * 1024 * 1024)]]) {
  test(`saved ${name} file download binds record, preserves bytes and verifies SHA`, async () => {
    const input = await downloadInput(data);
    await mockFetch(async (url, options) => {
      const target = new URL(url, "http://127.0.0.1");
      assert.equal(target.pathname, `/api/v1/sites/${id}/files/download`);
      assert.deepEqual(Object.fromEntries(target.searchParams), { path: input.file.path, expected_revision: "2", expected_sha256: input.file.sha256 });
      assert.equal(options.method, "GET"); assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store");
      assert.equal(options.headers.Accept, "application/octet-stream"); assert(options.signal instanceof AbortSignal);
      assert.equal(options.body, undefined); assert.equal(options.headers["X-CSRF-Token"], undefined);
      return fileResponse(data, input);
    }, async () => {
      const result = await api.downloadSiteFile(input);
      assert.equal(result.type, "application/octet-stream"); assert.equal(result.size, data.length);
      assert.deepEqual(new Uint8Array(await result.arrayBuffer()), data);
    });
  });
}
for (const [name, headers] of [
  ["wrong MIME", { "Content-Type": "text/html" }],
  ["inline attachment", { "Content-Disposition": 'inline; filename="saved.png"' }],
  ["wrong filename", { "Content-Disposition": 'attachment; filename="other.png"' }],
  ["invalid length", { "Content-Length": "invalid" }],
  ["oversized header", { "Content-Length": String(2 * 1024 * 1024 + 1) }],
  ["wrong saved size", { "Content-Length": "0" }],
]) {
  test(`saved file download rejects ${name} before consuming bytes`, async () => {
    const input = await downloadInput(); let cancelled = false;
    const stream = new ReadableStream({ cancel() { cancelled = true; } });
    await mockFetch(async () => fileResponse(stream, input, headers), async () => assert.rejects(api.downloadSiteFile(input), { code: "invalid_response" }));
    assert.equal(cancelled, true);
  });
}
test("saved file download rejects missing length, missing stream and hash mismatch", async () => {
  const input = await downloadInput();
  await mockFetch(async () => { const response = fileResponse(bytes, input); response.headers.delete("Content-Length"); return response; }, async () => assert.rejects(api.downloadSiteFile(input), { code: "invalid_response" }));
  await mockFetch(async () => fileResponse(null, input), async () => assert.rejects(api.downloadSiteFile(input), { code: "invalid_response" }));
  const wrong = Uint8Array.from(bytes); wrong[0] ^= 1;
  await mockFetch(async () => fileResponse(wrong, input), async () => assert.rejects(api.downloadSiteFile(input), { code: "invalid_response" }));
});
test("saved file download bounds actual stream and rejects truncation", async () => {
  const input = await downloadInput();
  for (const data of [bytes.subarray(1), new Uint8Array(2 * 1024 * 1024 + 1)]) {
    await mockFetch(async () => fileResponse(data, input), async () => assert.rejects(api.downloadSiteFile(input), { code: "invalid_response" }));
  }
});
test("saved file download reassembles streamed chunks before verifying hash", async () => {
  const input = await downloadInput();
  const stream = new ReadableStream({ start(controller) { controller.enqueue(bytes.subarray(0, 3)); controller.enqueue(bytes.subarray(3)); controller.close(); } });
  await mockFetch(async () => fileResponse(stream, input), async () => assert.deepEqual(new Uint8Array(await (await api.downloadSiteFile(input)).arrayBuffer()), bytes));
});
test("saved file download refuses invalid records and expired context before dispatch", async () => {
  const input = await downloadInput();
  await mockFetch(async () => assert.fail("must not dispatch"), async () => {
    for (const change of [{ expectedRevision: 0 }, { file: { ...input.file, bytes: 2 * 1024 * 1024 + 1 } }, { file: { ...input.file, sha256: "" } }, { file: { ...input.file, path: "../saved.png" } }]) await assert.rejects(api.downloadSiteFile({ ...input, ...change }), { status: 422 });
    await assert.rejects(api.downloadSiteFile({ ...input, isLive: () => false }), { code: "session_changed" });
  });
});
test("saved file download suppresses a response after its context changes", async () => {
  const input = await downloadInput(); let live = true;
  await mockFetch(async () => { live = false; return fileResponse(bytes, input); }, async () => assert.rejects(api.downloadSiteFile({ ...input, isLive: () => live })));
});
for (const status of [401, 403, 404, 409, 422, 503]) {
  test(`saved file download preserves HTTP ${status} refusal without retry`, async () => {
    const input = await downloadInput(); let calls = 0;
    await mockFetch(async () => { ++calls; return new Response("{}", { status }); }, async () => assert.rejects(api.downloadSiteFile(input), { status, code: "website_transfer_failed" }));
    assert.equal(calls, 1);
  });
}
