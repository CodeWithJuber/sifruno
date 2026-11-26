// Domains page client checks with synthetic sessions and fetch responses; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./site-domains-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL))));

const accountId = "0123456789abcdef0123456789abcdef";
const detail = (change = {}) => ({
  $schema: "http://127.0.0.1/schemas/WebsiteDetail.json",
  account_id: accountId, username: "example", domain: "example.com", kind: "wordpress", state: "active",
  https: { on: true, not_after: "2027-02-21T12:30:00Z" }, php_version: "8.3", wordpress_version: "7.1.5",
  url: "https://example.com/", admin_url: "https://example.com/wp-admin/", created_at: "2026-11-23T10:00:00Z", revision: 7, site_folder_changed: false, always_https: true,
  php_versions: ["8.3"], aliases: [{ name: "www.example.com", https: "on" }, { name: "nodns.example.com", https: "waiting_for_dns" }],
  redirect_count: 1, redirects: [{ from: "/old-page", to: "https://example.com/new-page", status: 301 }], ...change,
});
const session = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-23T10:15:00Z" };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

async function withFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

test("parsing keeps the domains contract and refuses anything else", () => {
  const site = api.parseSiteDomains(detail());
  assert.deepEqual(site.aliases, [{ name: "www.example.com", https: "on" }, { name: "nodns.example.com", https: "waiting_for_dns" }]);
  assert.deepEqual(site.redirects, [{ from: "/old-page", to: "https://example.com/new-page", status: 301 }]);
  assert.equal(site.redirect_count, 1);
  // The server could not read the redirects: the count says there are more.
  assert.equal(api.parseSiteDomains(detail({ redirect_count: 3, redirects: [] })).redirect_count, 3);
  for (const bad of [
    { aliases: null },
    { aliases: [{ name: "Bad Domain", https: "on" }] },
    { aliases: [{ name: "www.example.com", https: "maybe" }] },
    { redirects: [{ from: "/a", to: "javascript:alert(1)", status: 301 }] },
    { redirects: [{ from: "/a", to: "https://example.com/", status: 307 }] },
    { redirects: [{ from: "www.example.com", to: "https://example.com/path", status: 301 }] },
    { redirect_count: 0 },
    { revision: 0 },
    { account_id: "nope" },
    { always_https: undefined },
    { always_https: "false" },
    { always_https: 0 },
    { always_https: null },
  ]) assert.equal(api.parseSiteDomains(detail(bad)), undefined, JSON.stringify(bad));
  assert.equal(site.always_https, true);
  assert.equal(api.parseSiteDomains(detail({ always_https: false })).always_https, false);
});

test("a domain is checked as the server checks it", () => {
  const site = api.parseSiteDomains(detail());
  assert.equal(api.checkDomain(" Shop.Example.com ", site), undefined);
  assert.equal(api.normalizeDomain(" Shop.Example.com "), "shop.example.com");
  for (const [value, part] of [
    ["", "Enter the domain"],
    ["localhost", "two or more parts"],
    ["192.0.2.1", "two or more parts"],
    ["*.example.com", "two or more parts"],
    ["a b.example.com", "two or more parts"],
    ["www.www.example.com", "two or more parts"],
    ["-x.example.com", "two or more parts"],
    ["example.com", "already this website's main domain"],
    ["www.example.com", "already a domain of this website"],
  ]) assert.match(api.checkDomain(value, site) ?? "", new RegExp(part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), value);
  const full = { ...site, aliases: Array.from({ length: 15 }, (_, i) => ({ name: `a${i}.example.com`, https: "pending" })) };
  assert.match(api.checkDomain("b.example.com", full), /at most 15/);
});

test("the form hints' example domain never says www.www.", () => {
  assert.equal(api.exampleOtherDomain("example.com"), "www.example.com");
  assert.equal(api.exampleOtherDomain("shop.example.com"), "www.shop.example.com");
  // A site whose domain starts with www. gets the domain without it.
  assert.equal(api.exampleOtherDomain("www.example.com"), "example.com");
  assert.equal(api.exampleOtherDomain("www.shop.example.co.uk"), "shop.example.co.uk");
  // Nothing sensible is left without the www.: a plain example instead.
  assert.equal(api.exampleOtherDomain("www.example"), "example.net");
});

test("a redirect's source and target are checked, with no way into the server's config", () => {
  const site = api.parseSiteDomains(detail());
  assert.equal(api.redirectKind("/x"), "path");
  assert.equal(api.redirectKind("www.example.com"), "domain");
  assert.equal(api.checkRedirectFrom("/new/page_1.html", site), undefined);
  assert.equal(api.checkRedirectFrom("www.example.com", site), undefined);
  assert.match(api.checkRedirectFrom("/old-page", site), /already a redirect/);
  assert.match(api.checkRedirectFrom("/a.*", site), /must start with \//);
  assert.match(api.checkRedirectFrom("/.well-known/acme-challenge/x", site), /must start with \//);
  assert.match(api.checkRedirectFrom("other.example", site), /not a path or a domain of this website/);
  assert.equal(api.checkRedirectTo("https://example.org/new?x=1&y=2", "/a", site), undefined);
  assert.equal(api.checkRedirectTo("http://example.org:8080/", "/a", site), undefined);
  for (const to of [
    "https://example.com/\nRewriteRule .* - [F]", "https://example.com/ [R=302,L]", "https://example.com/$1",
    "https://example.com/%{HTTP_COOKIE}", "https://example.com/#x", "https://example.com/\"x", "javascript:alert(1)",
    "/relative", "//example.com/", "HTTPS://example.com/", "https://user@example.com/", "https://192.0.2.1/",
    "https://example.com:70000/", `https://example.com/${"a".repeat(260)}`,
  ]) assert.match(api.checkRedirectTo(to, "/a", site) ?? "", /must start with http/, to);
  assert.match(api.checkRedirectTo("https://www.example.com/a/", "/a", site), /loop/);
  assert.equal(api.checkRedirectTo("https://other.example/a", "/a", site), undefined);
  // A whole domain goes to another domain's address, its path kept.
  assert.equal(api.checkRedirectTo("https://example.com/", "www.example.com", site), undefined);
  assert.match(api.checkRedirectTo("https://example.com/start", "www.example.com", site), /give only the address/);
  assert.deepEqual(api.redirectBody(" WWW.example.com ", "https://example.com/", 302), { from: "www.example.com", to: "https://example.com", status: 302 });
  assert.deepEqual(api.redirectBody("/a/", "https://example.org/b/", 301), { from: "/a/", to: "https://example.org/b/", status: 301 });
});

test("each alias's HTTPS is said in words", () => {
  assert.equal(api.aliasHttps("on").label, "https");
  assert.match(api.aliasHttps("waiting_for_dns").detail, /DNS does not point at this server/);
  assert.match(api.aliasHttps("pending").detail, /asking for one/);
  assert.match(api.aliasHttps("off").detail, /not set up/);
  assert.equal(api.statusLabel(301), "301, moved for good");
});

test("a change sends the revision with the session's CSRF token and reads the answer", async () => {
  const site = api.parseSiteDomains(detail());
  const calls = [];
  await withFetch(async (url, init) => {
    calls.push({ url, method: init.method ?? "GET", body: init.body, csrf: init.headers["X-CSRF-Token"] });
    if (url === "/api/v1/session") return json(session);
    return json(detail({ revision: 8, aliases: [...detail().aliases, { name: "shop.example.com", https: "pending" }] }));
  }, async () => {
    const next = await api.addDomain(site, " Shop.Example.com ");
    assert.equal(next.revision, 8);
    assert.equal(next.aliases.at(-1).name, "shop.example.com");
  });
  assert.equal(calls[1].url, `/api/v1/websites/sites/${accountId}/domain-add`);
  assert.equal(calls[1].method, "POST");
  assert.equal(calls[1].csrf, "c".repeat(43));
  assert.deepEqual(JSON.parse(calls[1].body), { domain: "shop.example.com", expected_revision: 7 });

  calls.length = 0;
  await withFetch(async (url, init) => {
    calls.push({ url, body: init.body });
    return url === "/api/v1/session" ? json(session) : json(detail({ revision: 8 }));
  }, async () => {
    await api.addRedirect(site, "www.example.com", "https://example.com/", 301);
    await api.removeRedirect(site, "/old-page");
    await api.removeDomain(site, "nodns.example.com");
  });
  assert.deepEqual(calls.filter((c) => c.url !== "/api/v1/session").map((c) => [c.url.split("/").at(-1), JSON.parse(c.body)]), [
    ["redirect-add", { from: "www.example.com", to: "https://example.com", status: 301, expected_revision: 7 }],
    ["redirect-remove", { from: "/old-page", expected_revision: 7 }],
    ["domain-remove", { domain: "nodns.example.com", expected_revision: 7 }],
  ]);
});

test("a refusal says what happened, why and what next, with the request under Technical details", async () => {
  const site = api.parseSiteDomains(detail());
  await withFetch(async (url) => url === "/api/v1/session" ? json(session)
    : json({ title: "Conflict", status: 409, detail: "www.other.example already belongs to another website on this server, other.example.", errors: [{ message: "account service: domain belongs to another account" }] }, 409), async () => {
    await assert.rejects(api.addDomain(site, "www.other.example"), (error) => {
      assert.equal(error.message, "The domain was not added.");
      assert.match(error.why, /already belongs to another website/);
      assert.match(error.next, /Reload the page/);
      assert.match(error.technical, /returned HTTP 409 \(Conflict\); account service: domain belongs to another account; expected revision 7/);
      return true;
    });
  });
  // An answer in another form leaves the outcome unknown.
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ odd: true }), async () => {
    await assert.rejects(api.removeDomain(site, "www.example.com"), (error) => error.message === "The panel could not confirm the change.");
  });
  // A signed-out session sends nothing.
  let posted = false;
  await withFetch(async (url) => { if (url !== "/api/v1/session") posted = true; return json({ authenticated: false }); }, async () => {
    await assert.rejects(api.addRedirect(site, "/a", "https://example.org/", 302), (error) => error.status === 401);
  });
  assert.equal(posted, false);
  await assert.rejects(api.getSiteDomains("../x"), (error) => error.status === 404);
});

test("Always use HTTPS says when the switch can change, why not, and what to do next", () => {
  const now = new Date("2026-11-26T12:00:00Z");
  const site = api.parseSiteDomains(detail());
  assert.deepEqual(api.alwaysHttps(site, now), { kind: "ready" });
  // A certificate with no date reads as in force, as the site list says.
  assert.equal(api.alwaysHttps({ ...site, https: { on: true, not_after: "" } }, now).kind, "ready");

  const none = api.alwaysHttps({ ...site, https: { on: false, not_after: "" } }, now);
  assert.equal(none.kind, "no-certificate");
  assert.match(none.why, /no certificate yet/);
  assert.match(none.next, /^Get a certificate on this tab first: point example\.com at this server/);
  // The panel leaves alone a site made before certificates were set up.
  assert.match(none.next, /if no certificate comes within a day, ask whoever runs this server\.$/);

  const expired = api.alwaysHttps({ ...site, https: { on: true, not_after: "2026-11-26T11:59:59Z" } }, now);
  assert.equal(expired.kind, "expired");
  assert.match(expired.why, /certificate has expired/);
  assert.match(expired.next, /example\.com still points at this server/);

  const noManager = api.alwaysHttps({ ...site, https: { on: false, not_after: "" }, aliases: [{ name: "www.example.com", https: "off" }] }, now);
  assert.equal(noManager.kind, "no-certificates-here");
  assert.match(noManager.next, /set up certificates/);

  const suspended = api.alwaysHttps({ ...site, state: "suspended" }, now);
  assert.equal(suspended.kind, "not-live");
  assert.match(suspended.next, /Resume the website/);
  assert.equal(api.alwaysHttps({ ...site, state: "recovery_required" }, now).kind, "not-live");

  assert.match(api.alwaysHttpsOutcome(site, now), /is on\. Visitors on http:\/\/ now go to https:\/\//);
  assert.match(api.alwaysHttpsOutcome({ ...site, https: { on: false, not_after: "" } }, now), /starts once a valid certificate is in force/);
  assert.match(api.alwaysHttpsOutcome({ ...site, always_https: false }, now), /is off/);
});

test("the switch sends exactly always_https and the revision, with the session's CSRF token", async () => {
  const site = api.parseSiteDomains(detail());
  const calls = [];
  await withFetch(async (url, init) => {
    calls.push({ url, method: init.method ?? "GET", body: init.body, csrf: init.headers["X-CSRF-Token"] });
    if (url === "/api/v1/session") return json(session);
    return json(detail({ revision: 8, always_https: false }));
  }, async () => {
    const next = await api.setAlwaysHttps(site, false);
    assert.equal(next.always_https, false);
    assert.equal(next.revision, 8);
  });
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url}`), ["GET /api/v1/session", `POST /api/v1/websites/sites/${accountId}/always-https`]);
  assert.equal(calls[1].csrf, "c".repeat(43));
  assert.deepEqual(JSON.parse(calls[1].body), { always_https: false, expected_revision: 7 });

  calls.length = 0;
  await withFetch(async (url, init) => {
    calls.push({ url, body: init.body });
    return url === "/api/v1/session" ? json(session) : json(detail({ revision: 8 }));
  }, async () => {
    assert.equal((await api.setAlwaysHttps(site, true)).always_https, true);
  });
  assert.deepEqual(JSON.parse(calls[1].body), { always_https: true, expected_revision: 7 });

  // An answer without the switch leaves the outcome unknown.
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json(detail({ always_https: undefined })), async () => {
    await assert.rejects(api.setAlwaysHttps(site, true), (error) => error.message === "The panel could not confirm the change." && /Reload the page/.test(error.next));
  });
});

test("a refused switch says what happened, why and what next; a 409 says the website changed meanwhile", async () => {
  const site = api.parseSiteDomains(detail());
  const stale = "This website changed after the page loaded it, so nothing changed. Reload the page, check the website, then try again.";
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ title: "Conflict", status: 409, detail: stale }, 409), async () => {
    await assert.rejects(api.setAlwaysHttps(site, false), (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.message, "Always use HTTPS did not change.");
      assert.match(error.why, /changed after the page read it, or another change to it was still running, so nothing changed/);
      assert.match(error.next, /The page has read the website again/);
      // The server's own words and the revision are technical details.
      assert.match(error.technical, /always-https returned HTTP 409 \(Conflict\); the server said: This website changed after the page loaded it.*; expected revision 7$/);
      return true;
    });
  });
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ title: "Unprocessable Entity", status: 422, detail: "always_https must be true or false." }, 422), async () => {
    await assert.rejects(api.setAlwaysHttps(site, true), (error) => {
      assert.equal(error.why, "always_https must be true or false.");
      assert.match(error.next, /try again/);
      assert.doesNotMatch(error.technical, /the server said/);
      return true;
    });
  });
  // Another change's 409 keeps the server's words.
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ title: "Conflict", status: 409, detail: stale }, 409), async () => {
    await assert.rejects(api.removeDomain(site, "www.example.com"), (error) => error.why === stale && /Reload the page/.test(error.next));
  });
  // A signed-out session sends nothing.
  let posted = false;
  await withFetch(async (url) => { if (url !== "/api/v1/session") posted = true; return json({ authenticated: false }); }, async () => {
    await assert.rejects(api.setAlwaysHttps(site, false), (error) => error.status === 401);
  });
  assert.equal(posted, false);
});
