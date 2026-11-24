// Websites client checks with synthetic sessions and fetch responses; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./websites-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL))));

const accountId = "0123456789abcdef0123456789abcdef";
const site = (change = {}) => ({
  account_id: accountId, username: "example", domain: "example.com", state: "active",
  https: { on: true, not_after: "2027-02-21T12:30:00Z" }, php_version: "8.3", wordpress_version: "7.1.5",
  url: "https://example.com/", admin_url: "https://example.com/wp-admin/", created_at: "2026-11-23T10:00:00Z", revision: 7, ...change,
});
// One site as its page reads it, and a signed-in session for its changes.
const detail = (change = {}) => site({ php_versions: ["8.2", "8.3"], ...change });
const session = { authenticated: true, csrf_token: "synthetic-csrf-token", expires_at: "2026-11-23T10:15:00Z" };
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
    site({ revision: 0 }), site({ revision: "7" }), site({ revision: 1.5 }), site({ revision: undefined }), site({ revision: 2 ** 60 }),
  ]) assert.equal(api.parseWebsite(bad), undefined, JSON.stringify(bad));
  // One site also names the PHP versions installed on the server.
  assert.deepEqual(api.parseWebsiteDetail(detail()), detail());
  assert.deepEqual(api.parseWebsiteDetail(detail({ php_versions: [] })).php_versions, []);
  for (const bad of [site(), detail({ php_versions: "8.3" }), detail({ php_versions: ["8.3", 8.4] }), detail({ php_versions: ["latest"] }), detail({ php_versions: Array(11).fill("8.3") }), detail({ revision: 0 })]) {
    assert.equal(api.parseWebsiteDetail(bad), undefined, JSON.stringify(bad));
  }
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
  await withFetch(async (url) => { urls.push(url); return json({ $schema: "x", ...detail() }); }, async () => {
    const one = await api.getWebsite(accountId);
    assert.equal(one.account_id, accountId); assert.deepEqual(one.php_versions, ["8.2", "8.3"]); assert.equal(one.revision, 7);
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

test("the PHP action offers only other installed versions, and only for a live site", () => {
  assert.deepEqual(api.phpChange(detail({ php_versions: ["8.1", "8.2", "8.3"] })), { kind: "ready", versions: ["8.1", "8.2"] });
  assert.deepEqual(api.phpChange(detail({ php_version: "", php_versions: ["8.3"] })), { kind: "ready", versions: ["8.3"] });
  assert.match(api.phpChange(detail({ php_versions: ["8.3"] })).why, /PHP 8\.3 is the only version installed/);
  assert.match(api.phpChange(detail({ php_versions: [] })).why, /found no PHP versions/);
  assert.match(api.phpChange(detail({ state: "suspended" })).why, /Resume the website/);
  assert.match(api.phpChange(detail({ state: "recovery_required" })).why, /has been checked/);
});

const removedAll = ["the database example_wp", "the hosting account example with its files and its site on the web server"];

test("a change reads the session token, then posts its own field and the page's revision with CSRF", async () => {
  const calls = [];
  await withFetch(async (url, init) => {
    calls.push({ url, init });
    if (url === "/api/v1/session") return json(session);
    if (url.endsWith("/delete")) return json({ $schema: "x", domain: "example.com", removed: removedAll, kept: [] });
    const body = JSON.parse(init.body);
    return json(detail({ revision: 8, ...(body.php_version ? { php_version: body.php_version } : { state: body.state }) }));
  }, async () => {
    const php = await api.changePhpVersion(detail(), "8.2");
    assert.equal(php.php_version, "8.2"); assert.equal(php.revision, 8);
    assert.equal((await api.setWebsiteState(detail(), "suspended")).state, "suspended");
    assert.equal((await api.setWebsiteState(detail({ state: "suspended" }), "active")).state, "active");
    const done = await api.deleteWebsite(detail(), "example.com");
    assert.deepEqual(done, { domain: "example.com", removed: removedAll, kept: [] });
    assert.equal(api.deletedSummary(done), `Removed: ${removedAll.join(", ")}.`);
    assert.equal(api.deletedSummary({ domain: "example.com", removed: ["the hosting account example"], kept: ["the database example_wp"] }),
      "Removed: the hosting account example. Left on the server, because it is not registered to this website: the database example_wp.");
  });
  const posts = calls.filter((call) => call.init.method === "POST");
  assert.equal(calls.filter((call) => call.url === "/api/v1/session").length, 4);
  assert.deepEqual(posts.map((call) => [call.url, JSON.parse(call.init.body)]), [
    [`/api/v1/websites/sites/${accountId}/php`, { php_version: "8.2", expected_revision: 7 }],
    [`/api/v1/websites/sites/${accountId}/state`, { state: "suspended", expected_revision: 7 }],
    [`/api/v1/websites/sites/${accountId}/state`, { state: "active", expected_revision: 7 }],
    [`/api/v1/websites/sites/${accountId}/delete`, { confirm_domain: "example.com", expected_revision: 7 }],
  ]);
  for (const post of posts) {
    assert.equal(post.init.headers["X-CSRF-Token"], session.csrf_token);
    assert.equal(post.init.headers["Content-Type"], "application/json");
    assert.equal(post.init.credentials, "same-origin");
  }
});

test("a refused change says what happened, why and what next, with the revision under technical details", async () => {
  const refuse = (status, title, body) => async (url) => url === "/api/v1/session" ? json(session) : json({ title, status, ...body }, status);
  const rejected = "The web server's configuration test failed with PHP 8.4, so the site kept PHP 8.3. PHP 8.4 may not be installed on this server.";
  await withFetch(refuse(422, "Unprocessable Entity", { detail: rejected, errors: [{ message: "account service: web configuration rejected" }] }), async () => {
    await assert.rejects(api.changePhpVersion(detail(), "8.4"), (error) => {
      assert.ok(error instanceof api.WebsitesApiError);
      assert.equal(error.status, 422);
      assert.equal(error.message, "The PHP version was not changed.");
      assert.equal(error.why, rejected);
      assert.match(error.next, /Choose another PHP version/);
      assert.equal(error.technical, `POST /api/v1/websites/sites/${accountId}/php returned HTTP 422 (Unprocessable Entity); account service: web configuration rejected; expected revision 7`);
      return true;
    });
  });
  const stale = "This website changed after the page loaded it, so nothing changed. Reload the page, check the website, then try again.";
  await withFetch(refuse(409, "Conflict", { detail: stale }), async () => {
    await assert.rejects(api.setWebsiteState(detail(), "suspended"), (error) => error.status === 409 && error.message === "The website was not suspended." && error.why === stale && /Reload the page to see the website as it is now/.test(error.next));
    await assert.rejects(api.setWebsiteState(detail({ state: "suspended" }), "active"), (error) => error.message === "The website was not resumed.");
  });
  // A stopped delete names what went and what is left, in the server's words.
  const left = "The database server did not remove the database example_wp. Removed before that: the database user example_wp. Still on the server: the database example_wp, the hosting account example with its files and its site on the web server.";
  await withFetch(refuse(503, "Service Unavailable", { detail: left, errors: [{ message: "ERROR 1010: database directory not empty" }] }), async () => {
    await assert.rejects(api.deleteWebsite(detail(), "example.com"), (error) => error.status === 503 && error.message === "The website was not deleted." && error.why === left && /Reload the page/.test(error.next) && /ERROR 1010/.test(error.technical));
  });
  await withFetch(refuse(422, "Unprocessable Entity", { detail: "The domain you typed is not this website's domain, example.com. Nothing was removed." }), async () => {
    await assert.rejects(api.deleteWebsite(detail(), "example.org"), (error) => error.status === 422 && /Type the website's domain exactly/.test(error.next));
  });
});

test("a change whose answer is lost is not reported as not made", async () => {
  // The session is read; the POST then fails on the network.
  await withFetch(async (url) => { if (url === "/api/v1/session") return json(session); throw new TypeError("fetch failed"); }, async () => {
    await assert.rejects(api.changePhpVersion(detail(), "8.2"), (error) => error.status === 0 && error.message === "The panel could not confirm the change." && /may still finish/.test(error.why)
      && /Reload the page to see the website as it is now/.test(error.next) && /network error; expected revision 7$/.test(error.technical));
  });
  // An answer for another site, or one outside the contract.
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json(detail({ account_id: "f".repeat(32) })), async () => {
    await assert.rejects(api.setWebsiteState(detail(), "suspended"), (error) => error.message === "The panel could not confirm the change." && /cannot tell whether the change was made/.test(error.why));
  });
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ domain: "other.example", removed: [], kept: [] }), async () => {
    await assert.rejects(api.deleteWebsite(detail(), "example.com"), (error) => error.message === "The panel could not confirm the change.");
  });
});

test("a change is not sent without a session", async () => {
  const urls = [];
  await withFetch(async (url) => { urls.push(url); return json({ authenticated: false }); }, async () => {
    await assert.rejects(api.deleteWebsite(detail(), "example.com"), (error) => error.status === 401 && error.message === "The website was not deleted." && error.why === "Your sign-in has ended." && /Sign in again/.test(error.next));
  });
  await withFetch(async (url) => { urls.push(url); return json({ title: "Unauthorized", status: 401, detail: "Operator session required" }, 401); }, async () => {
    await assert.rejects(api.changePhpVersion(detail(), "8.2"), (error) => error.status === 401 && error.message === "The PHP version was not changed.");
  });
  // The session could not be read at all: nothing was sent, so nothing changed.
  await withFetch(async (url) => { urls.push(url); throw new TypeError("fetch failed"); }, async () => {
    await assert.rejects(api.setWebsiteState(detail(), "suspended"), (error) => error.message === "The website was not suspended." && error.why === "The panel could not reach its server.");
  });
  assert.deepEqual(urls, ["/api/v1/session", "/api/v1/session", "/api/v1/session"]);
});
