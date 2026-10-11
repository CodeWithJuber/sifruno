import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./multiUpload.ts", import.meta.url), "utf8").replaceAll('"./sites-api"', JSON.stringify(sitesURL))));
// Exercise the exact validator used by the integrated File Manager.
const fileManager = readFileSync(new URL("../FileManager.tsx", import.meta.url), "utf8");
const validator = fileManager.match(/const utf8Bytes = [^\n]+/)[0] + "\n" + fileManager.slice(fileManager.indexOf("const textExtensions"), fileManager.indexOf("function validUtf16")) + "\nexport { validPath };";
const { validPath } = await import(moduleURL(validator));
const site = { id: "a".repeat(32), name: "Static fixture", domain: "fixture.test", preview_host: `site-${"a".repeat(32)}.localhost`, state: "active", revision: 7, created_at: "2026-10-09T00:00:00Z", updated_at: "2026-10-09T00:00:00Z" };
const catalog = [{ path: "index.html", bytes: 12, sha256: "b".repeat(64) }];
const entry = (name, size = 1, destination = name) => ({ file: new File([new Uint8Array(size)], name), path: destination });
const input = (entries, overrides = {}) => ({ site, entries, catalog, validPath, csrf: "fixture-csrf", isLive: () => true, shouldStop: () => false, onProgress: () => {}, ...overrides });
const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
async function mockFetch(mock, action) { const original = globalThis.fetch; globalThis.fetch = mock; try { await action(); } finally { globalThis.fetch = original; } }

test("whole selection rejects unsafe names, collisions and native limits before any POST", async () => {
  const bad = [
    [entry("good.css"), entry("private.php")], [entry("../secret.txt")], [entry("credentials.txt")], [entry("bad name.txt")],
    [entry("image.png", 2 * 1024 * 1024 + 1)], [entry("index.html")], [entry("INDEX.html")],
    [entry("new.txt"), entry("NEW.txt")], [entry("parent.png"), entry("leaf.txt", 1, "parent.png/leaf.txt")],
    [entry("a.css", 1, "assets/a.css"), entry("b.css", 1, "ASSETS/b.css")],
  ];
  await mockFetch(() => assert.fail("preflight must send zero POSTs"), async () => {
    for (const entries of bad) {
      assert(api.reviewMultiUpload(entries, catalog, validPath).problem);
      const result = await api.uploadMultipleFiles(input(entries));
      assert.equal(result.failure.status, 422); assert(result.outcomes.every((outcome) => outcome.status === "not_attempted"));
    }
    const full = Array.from({ length: 64 }, (_, index) => ({ path: `saved${index}.txt`, bytes: 0, sha256: "b".repeat(64) }));
    assert.equal((await api.uploadMultipleFiles(input([entry("new.txt")], { catalog: full }))).failure.status, 422);
    const large = Array.from({ length: 16 }, (_, index) => ({ path: `saved${index}.txt`, bytes: 2 * 1024 * 1024, sha256: "b".repeat(64) }));
    assert.equal((await api.uploadMultipleFiles(input([entry("new.txt")], { catalog: large }))).failure.status, 422);
    const aliasCatalog = [{ path: "Assets/saved.css", bytes: 1, sha256: "b".repeat(64) }];
    assert.equal((await api.uploadMultipleFiles(input([entry("new.css", 1, "assets/new.css")], { catalog: aliasCatalog }))).failure.status, 422);
  });
});

test("oversized selection is refused without examining files or growing review rows", () => {
  const entries = Array.from({ length: 10000 }, () => ({ get file() { assert.fail("must refuse count before examining files"); }, path: "new.txt" }));
  const review = api.reviewMultiUpload(entries, catalog, validPath);
  assert.match(review.problem, /64-file/); assert.equal(review.entries.length, 0);
});

test("exact byte/count limits, empty files and valid shared folders are reviewable", () => {
  const maxFile = entry("limit.png", 2 * 1024 * 1024);
  assert.equal(api.reviewMultiUpload([maxFile, entry("empty.txt", 0)], catalog, validPath).problem, undefined);
  const entries = Array.from({ length: 63 }, (_, index) => entry(`file${index}.txt`, 0));
  assert.equal(api.reviewMultiUpload(entries, catalog, validPath).problem, undefined);
  const fullBytes = Array.from({ length: 15 }, (_, index) => ({ path: `saved${index}.png`, bytes: 2 * 1024 * 1024, sha256: "b".repeat(64) }));
  assert.equal(api.reviewMultiUpload([maxFile], fullBytes, validPath).problem, undefined);
  assert.equal(api.reviewMultiUpload([entry("a.css", 1, "assets/a.css"), entry("b.css", 1, "assets/b.css")], catalog, validPath).problem, undefined);
});

test("serial uploads preserve binary bytes and use each confirmed next revision", async () => {
  const binary = Uint8Array.of(0x89, 80, 78, 71, 0, 255, 128, 10);
  const entries = [{ file: new File([binary], "image.png"), path: "assets/image.png" }, { file: new File(["body {}"], "site.css"), path: "assets/site.css" }];
  let calls = 0, inFlight = false;
  await mockFetch(async (url, options) => {
    assert.equal(inFlight, false); inFlight = true;
    assert.equal(url, `/api/v1/sites/${site.id}/upload`); assert.equal(options.method, "POST"); assert.equal(options.credentials, "same-origin"); assert.equal(options.headers["X-CSRF-Token"], "fixture-csrf");
    const body = JSON.parse(options.body); assert.deepEqual(Object.keys(body).sort(), ["content", "expected_revision", "path"]);
    assert.equal(body.expected_revision, 7 + calls); assert.equal(body.path, entries[calls].path);
    assert.deepEqual(Buffer.from(body.content, "base64"), Buffer.from(await entries[calls].file.arrayBuffer()));
    await Promise.resolve(); inFlight = false; calls++;
    return response({ ...site, revision: 7 + calls });
  }, async () => {
    const result = await api.uploadMultipleFiles(input(entries));
    assert.equal(result.failure, undefined); assert.deepEqual(result.outcomes.map((outcome) => outcome.status), ["saved", "saved"]); assert.equal(result.lastSite.revision, 9);
  });
  assert.equal(calls, 2);
});

for (const status of [401, 409, 422, 503]) {
  test(`HTTP ${status} stops after one saved file without fallback or retry`, async () => {
    let calls = 0;
    await mockFetch(async () => { calls++; return calls === 1 ? response({ ...site, revision: 8 }) : response({}, status); }, async () => {
      const result = await api.uploadMultipleFiles(input([entry("a.css"), entry("b.css"), entry("c.css")]));
      assert.equal(result.failure.status, status); assert.deepEqual(result.outcomes.map((outcome) => outcome.status), ["saved", "failed_or_unconfirmed", "not_attempted"]); assert.equal(result.lastSite.revision, 8);
    });
    assert.equal(calls, 2);
  });
}

test("uncertain response or unrelated metadata stops without claiming the pending file saved", async () => {
  for (const mock of [async () => { throw new Error("offline"); }, async () => response({ ...site, revision: 7 }), async () => response({ ...site, revision: 8, domain: "other.test" })]) {
    let calls = 0;
    await mockFetch(async (...args) => { calls++; return mock(...args); }, async () => {
      const result = await api.uploadMultipleFiles(input([entry("a.css"), entry("b.css")]));
      assert(result.failure); assert.deepEqual(result.outcomes.map((outcome) => outcome.status), ["failed_or_unconfirmed", "not_attempted"]);
    });
    assert.equal(calls, 1);
  }
});

test("stop keeps confirmed files and prevents remaining dispatches", async () => {
  let stop = false, calls = 0;
  await mockFetch(async () => { calls++; return response({ ...site, revision: 8 }); }, async () => {
    const result = await api.uploadMultipleFiles(input([entry("a.css"), entry("b.css")], { shouldStop: () => stop, onProgress: (outcomes) => { if (outcomes[0].status === "saved") stop = true; } }));
    assert.deepEqual(result.outcomes.map((outcome) => outcome.status), ["saved", "not_attempted"]);
  });
  assert.equal(calls, 1);
});

test("expired context makes zero writes, or leaves pending response unconfirmed with no late progress", async () => {
  await mockFetch(() => assert.fail("inactive context must not dispatch"), async () => {
    const result = await api.uploadMultipleFiles(input([entry("a.css")], { isLive: () => false }));
    assert.equal(result.outcomes[0].status, "not_attempted");
  });
  let live = true, calls = 0, lateProgress = 0;
  await mockFetch(async () => { calls++; live = false; return response({ ...site, revision: 8 }); }, async () => {
    const result = await api.uploadMultipleFiles(input([entry("a.css"), entry("b.css")], { isLive: () => live, onProgress: () => { if (!live) lateProgress++; } }));
    assert.deepEqual(result.outcomes.map((outcome) => outcome.status), ["failed_or_unconfirmed", "not_attempted"]); assert.equal(result.failure.code, "context_changed");
  });
  assert.equal(calls, 1); assert.equal(lateProgress, 0);
});
