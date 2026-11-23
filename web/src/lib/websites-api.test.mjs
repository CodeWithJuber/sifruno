// Websites list client checks with synthetic fetch responses; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const source = readFileSync(new URL("./websites-api.ts", import.meta.url), "utf8");
const api = await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`);

const accountId = "0123456789abcdef0123456789abcdef";
const site = (change = {}) => ({
  account_id: accountId, username: "example", domain: "example.com", state: "active",
  https: { on: true, not_after: "2027-02-21T12:30:00Z" }, php_version: "8.3", wordpress_version: "7.1.5",
  url: "https://example.com/", admin_url: "https://example.com/wp-admin/", created_at: "2026-11-23T10:00:00Z", ...change,
});
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

async function withFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

test("parsing accepts the contract, with Huma's $schema key and an old job's empty PHP version", () => {
  const list = api.parseWebsiteList({ $schema: "http://127.0.0.1/schemas/WebsiteListBody.json", sites: [site(), site({ account_id: "f".repeat(32), state: "suspended", https: { on: false, not_after: "" }, php_version: "", url: "http://old.example/", admin_url: "http://old.example/wp-admin/" })] });
  assert.equal(list.length, 2);
  assert.deepEqual(list[0], site());
  assert.equal(list[1].php_version, "");
  assert.deepEqual(list[1].https, { on: false, not_after: "" });
  assert.deepEqual(api.parseWebsiteList({ sites: [] }), []);
  // Unknown keys are dropped, not passed on.
  assert.equal("extra" in api.parseWebsite(site({ extra: "x" })), false);
});

test("parsing refuses anything outside the contract", () => {
  for (const bad of [
    site({ account_id: "A".repeat(32) }), site({ account_id: "abc" }), site({ username: "" }), site({ username: "Root" }),
    site({ domain: "" }), site({ domain: "a.example\n" }), site({ state: "" }), site({ state: 3 }),
    site({ https: { on: "yes", not_after: "" } }), site({ https: { on: true, not_after: "soon" } }), site({ https: null }),
    site({ url: "javascript:alert(1)" }), site({ admin_url: "ftp://example.com/" }), site({ url: "not a url" }),
    site({ php_version: 8.3 }), site({ wordpress_version: undefined }), site({ created_at: "yesterday" }),
  ]) assert.equal(api.parseWebsite(bad), undefined, JSON.stringify(bad));
  for (const bad of [null, [], { sites: {} }, { items: [] }, { sites: [site(), { ...site(), url: "data:text/html,x" }] }]) {
    assert.equal(api.parseWebsiteList(bad), undefined, JSON.stringify(bad));
  }
});

test("status names the state in words: Live, Suspended, or needing attention", () => {
  assert.deepEqual(api.siteStatus("active"), { label: "Live", tone: "live" });
  assert.deepEqual(api.siteStatus("suspended"), { label: "Suspended", tone: "suspended" });
  assert.deepEqual(api.siteStatus("recovery_required"), { label: "Needs review", tone: "attention" });
  assert.deepEqual(api.siteStatus("something_new"), { label: "Unknown status", tone: "attention" });
});

test("https is on until the certificate's date, expired after it, and off without one", () => {
  const now = new Date("2026-11-24T00:00:00Z");
  const on = api.httpsState({ on: true, not_after: "2027-02-21T12:30:00Z" }, now);
  assert.equal(on.kind, "on"); assert.equal(on.until.toISOString(), "2027-02-21T12:30:00.000Z");
  const expired = api.httpsState({ on: true, not_after: "2026-11-01T00:00:00Z" }, now);
  assert.equal(expired.kind, "expired"); assert.equal(expired.since.toISOString(), "2026-11-01T00:00:00.000Z");
  assert.deepEqual(api.httpsState({ on: false, not_after: "" }, now), { kind: "off" });
  assert.deepEqual(api.httpsState({ on: true, not_after: "" }, now), { kind: "on" });
  assert.equal(api.dayLabel("2027-02-21T12:30:00Z", "en-GB"), "21 Feb 2027");
  assert.equal(api.dayLabel("not a date", "en-GB"), "Date unavailable");
});

test("listWebsites reads GET /api/v1/websites/sites with the session cookie and no body", async () => {
  let seen;
  await withFetch(async (url, init) => { seen = { url, init }; return json({ sites: [site()] }); }, async () => {
    const sites = await api.listWebsites();
    assert.equal(sites.length, 1); assert.equal(sites[0].domain, "example.com");
  });
  assert.equal(seen.url, "/api/v1/websites/sites");
  assert.equal(seen.init.method, "GET"); assert.equal(seen.init.credentials, "same-origin"); assert.equal(seen.init.cache, "no-store");
  assert.equal(seen.init.body, undefined);
});

test("errors say what happened, why and what next, with the request under technical details", async () => {
  const notSetUp = "WordPress websites are not set up on this server. The panel needs the account service and the database service for them.";
  await withFetch(async () => json({ title: "Service Unavailable", status: 503, detail: notSetUp }, 503), async () => {
    await assert.rejects(api.listWebsites(), (error) => {
      assert.ok(error instanceof api.WebsitesApiError);
      assert.equal(error.status, 503);
      assert.equal(error.message, "Your websites could not be loaded.");
      assert.equal(error.why, notSetUp);
      assert.match(error.next, /Try again in a minute/);
      assert.equal(error.technical, "GET /api/v1/websites/sites returned HTTP 503 (Service Unavailable)");
      return true;
    });
  });
  await withFetch(async () => json({ title: "Unauthorized", status: 401, detail: "Operator session required" }, 401), async () => {
    await assert.rejects(api.listWebsites(), (error) => error.status === 401 && error.why === "Your sign-in has ended." && /Sign in again/.test(error.next));
  });
  await withFetch(async () => { throw new TypeError("fetch failed"); }, async () => {
    await assert.rejects(api.listWebsites(), (error) => error.status === 0 && error.why === "The panel could not reach its server." && error.technical === "GET /api/v1/websites/sites: network error");
  });
  await withFetch(async () => json({ sites: [site({ url: "javascript:alert(1)" })] }), async () => {
    await assert.rejects(api.listWebsites(), (error) => error.status === 0 && /not in the form the panel expects/.test(error.why) && /websites contract/.test(error.technical));
  });
  // A control character in the server's detail is not shown as is.
  await withFetch(async () => json({ title: "Service Unavailable", detail: "line one\nline two" }, 503), async () => {
    await assert.rejects(api.listWebsites(), (error) => error.why === "line one line two");
  });
});

test("getWebsite asks for one account and checks the answer is that account", async () => {
  const urls = [];
  await withFetch(async (url) => { urls.push(url); return json({ $schema: "x", ...site() }); }, async () => {
    assert.equal((await api.getWebsite(accountId)).account_id, accountId);
    await assert.rejects(api.getWebsite("f".repeat(32)), (error) => /not in the form/.test(error.why));
  });
  assert.deepEqual(urls, [`/api/v1/websites/sites/${accountId}`, `/api/v1/websites/sites/${"f".repeat(32)}`]);
  // An id that cannot be an account is refused without a request.
  await withFetch(async () => { throw new Error("must not be called"); }, async () => {
    for (const bad of ["", "../jobs", "A".repeat(32), "a".repeat(31)]) {
      await assert.rejects(api.getWebsite(bad), (error) => error.status === 404 && /nothing was sent/.test(error.technical));
    }
  });
  await withFetch(async () => json({ title: "Not Found", status: 404, detail: "That website was not found. It may have been removed, or it was not made with New website." }, 404), async () => {
    await assert.rejects(api.getWebsite(accountId), (error) => error.status === 404 && error.message === "This website could not be loaded." && /may have been removed/.test(error.why) && /Go back to Websites/.test(error.next));
  });
});

test("a cancelled read says so", async () => {
  const controller = new AbortController();
  await withFetch((_, init) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))), async () => {
    const pending = api.listWebsites({ signal: controller.signal });
    controller.abort();
    await assert.rejects(pending, (error) => error.why === "The request was cancelled." && /cancelled$/.test(error.technical));
  });
});
