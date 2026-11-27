// The customer's panel against the server's customer table. customer-routes.json
// is that table (internal/api/customer_routes.go), kept equal to it by
// TestCustomerRoutesFileMatchesTable. These checks fail when the customer's
// menu or a website tab needs a route the table refuses customers, or when the
// panel hides a control behind a route the server does not have.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const read = (name) => readFileSync(new URL(name, import.meta.url), "utf8");
const table = JSON.parse(read("./customer-routes.json"));
const customerMay = (route) => ["customerOpen", "ownWebsite", "ownWebsites"].includes(table[route]);

// pages.ts takes its icons from lucide-react, which a data: module cannot
// load; the checks need the pages, not their icons.
const pagesSource = read("../shell/pages.ts").replace(/^import \{([^}]+)\} from "lucide-react";$/m, (_, names) => `const {${names}} = new Proxy({}, { get: () => () => null });`);
const shell = await import(moduleURL(pagesSource));
const sitesURL = moduleURL(read("./sites-api.ts"));
const websitesURL = moduleURL(read("./websites-api.ts").replace('"./sites-api"', JSON.stringify(sitesURL)));
const toolsURL = moduleURL(read("./site-tools-api.ts").replace('"./sites-api"', JSON.stringify(sitesURL)).replaceAll('"./websites-api"', JSON.stringify(websitesURL)));
const backupsURL = moduleURL(read("./site-backups-api.ts").replace('"./sites-api"', JSON.stringify(sitesURL)));
const site = await import(moduleURL(read("./site-page.ts")
  .replaceAll('"./websites-api"', JSON.stringify(websitesURL)).replaceAll('"./site-tools-api"', JSON.stringify(toolsURL)).replaceAll('"./site-backups-api"', JSON.stringify(backupsURL))));
const auth = await import(moduleURL(read("./auth-api.ts")));

function assertCustomerMay(where, needs) {
  assert.ok(Array.isArray(needs) && needs.length > 0, `${where} names no routes it needs`);
  for (const route of needs) {
    assert.ok(route in table, `${where} needs ${route}, which the server does not have`);
    assert.ok(customerMay(route), `${where} needs ${route}, which the customer table refuses (${table[route]})`);
  }
}

test("the copy of the table is whole", () => {
  assert.ok(Object.keys(table).length >= 100, "customer-routes.json lists too few routes");
  for (const access of Object.values(table)) assert.ok(["adminOnly", "customerOpen", "ownWebsite", "ownWebsites"].includes(access), access);
  assert.equal(table["GET /api/v1/websites/sites"], "ownWebsites");
  assert.equal(table["POST /api/v1/websites/sites/{account_id}/state"], "adminOnly");
});

test("the customer's menu needs only routes customers may use", () => {
  const menu = shell.visiblePages(false, "customer");
  assert.deepEqual(menu.filter((p) => !p.parent).map((p) => p.label), ["Home", "Websites", "Account"]);
  for (const page of menu) assertCustomerMay(`menu entry ${page.label} (${page.path})`, page.needs);
});

test("every website tab needs only routes customers may use", () => {
  for (const tab of site.siteTabs) assertCustomerMay(`website tab ${tab.label}`, tab.needs);
  // The website pages a customer may open are those tabs.
  const tabPaths = site.siteTabs.map((t) => site.tabRoute(t.id));
  for (const page of shell.pages.filter((p) => shell.customerPage(p) && p.path.startsWith("/websites/sites/"))) {
    assert.ok(tabPaths.includes(page.path), `${page.path} is a customer page but no website tab`);
  }
  // Links from one tab to another (the health checklist's) stay inside them.
  for (const line of site.healthChecklist({ account_id: "a".repeat(32), state: "suspended", domain: "example.com", https: { on: false }, php_version: "", aliases: [], created_at: "2026-01-01T00:00:00Z" }, { failed: true }, { failed: true })) {
    if (line.fix) assert.ok(site.siteTabs.some((t) => t.id === line.fix), line.fix);
  }
});

test("a customer's Settings tab is shown only where it holds something", () => {
  const ids = (...args) => site.tabsFor(...args).map((t) => t.id);
  assert.ok(ids("simple", "active", undefined, false).includes("settings"), "Simple view's Settings holds the cron jobs and logs");
  assert.ok(!ids("advanced", "active", undefined, false).includes("settings"));
  assert.ok(ids("advanced", "active", "settings", false).includes("settings"), "opened by its address, it stays");
  assert.deepEqual(ids("simple", "partly_deleted", undefined, false), ["overview"]);
  assert.deepEqual(ids("advanced", "partly_deleted"), ["overview", "settings"]);
  assert.ok(ids("advanced", "active").includes("settings"));
});

test("every control the panel hides names a route the server has", () => {
  const root = new URL("../", import.meta.url);
  const gated = new Set();
  for (const file of readdirSync(root, { recursive: true }).filter((f) => f.endsWith(".tsx"))) {
    for (const m of readFileSync(new URL(file, root), "utf8").matchAll(/\bcan\("([^"]+)"\)/g)) {
      assert.ok(m[1] in table, `${file} hides a control behind ${m[1]}, which the server does not have`);
      gated.add(m[1]);
    }
  }
  // New website, static sites, the site's actions, backups and storage.
  assert.ok(gated.size >= 10, `only ${gated.size} gated routes found`);
});

test("the Always use HTTPS switch shows only for a login that may use its route", () => {
  const route = "POST /api/v1/websites/sites/{account_id}/always-https";
  // A site's owner may turn it on and off for its own websites.
  assert.equal(table[route], "ownWebsite");
  assert.match(read("../SiteDomains.tsx"), /const canHttps = viewer\.can\("POST \/api\/v1\/websites\/sites\/\{account_id\}\/always-https"\);[\s\S]*\{canHttps && <AlwaysHttpsSection /);
  const base = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-24T10:15:00Z", role: "customer", username: "alice" };
  assert.equal(auth.allows({ ...base, routes: [route] }, route), true);
  assert.equal(auth.allows({ ...base, routes: ["GET /api/v1/websites/sites/{account_id}"] }, route), false);
});

test("a restricted session may use only the routes it lists", () => {
  const base = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-24T10:15:00Z" };
  const admin = { ...base, role: "admin", username: "admin" };
  const customer = { ...base, role: "customer", username: "alice", routes: ["GET /api/v1/websites/sites", "POST /api/v1/websites/sites/{account_id}/domain-add"] };
  const route = "POST /api/v1/websites/sites/{account_id}/php";
  assert.equal(auth.allows(admin, route), true);
  assert.equal(auth.allows(null, route), true, "the public preview has no session and no limits");
  assert.equal(auth.allows(customer, route), false);
  assert.equal(auth.allows(customer, "POST /api/v1/websites/sites/{account_id}/domain-add"), true);
  assert.equal(auth.allows({ ...customer, routes: undefined }, "GET /api/v1/websites/sites"), false, "no list: nothing is offered");
  assert.equal(auth.allows({ ...admin, view_as: "alice", routes: [] }, route), false, "an admin viewing as a customer is restricted");
});

test("Account's own-login changes use routes open to customers, with the session's CSRF token", async () => {
  const routes = ["POST /api/v1/session/password", "POST /api/v1/session/authenticator/begin", "POST /api/v1/session/authenticator/finish"];
  for (const route of routes) assert.equal(table[route], "customerOpen", route);
  const original = globalThis.fetch;
  const sent = [];
  globalThis.fetch = async (url, init) => {
    sent.push({ route: `${init.method} ${url}`, csrf: init.headers["X-CSRF-Token"], fields: Object.keys(JSON.parse(init.body)).sort() });
    const answer = url.endsWith("/password") ? { other_sessions_ended: 2 } : url.endsWith("/begin") ? { secret: "A".repeat(32), otpauth_uri: "otpauth://totp/Sifruno:alice?secret=x", expires_at: "2026-11-24T10:10:00Z" } : { changed: true };
    return new Response(JSON.stringify(answer), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  try {
    assert.equal((await auth.changeOwnPassword("t".repeat(43), "old words here", "123456", "new words here!")).other_sessions_ended, 2);
    assert.equal((await auth.beginAuthenticatorChange("t".repeat(43), "old words here", "123456")).secret, "A".repeat(32));
    assert.equal((await auth.finishAuthenticatorChange("t".repeat(43), "654321")).changed, true);
  } finally { globalThis.fetch = original; }
  assert.deepEqual(sent.map((s) => s.route), routes);
  assert.ok(sent.every((s) => s.csrf === "t".repeat(43)));
  assert.deepEqual(sent.map((s) => s.fields.join(",")), ["current_password,new_password,totp_code", "current_password,totp_code", "totp_code"]);
});

test("the session's routes are checked when it is read", async () => {
  const original = globalThis.fetch;
  const answer = (value) => async () => new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
  const session = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-24T10:15:00Z", role: "customer", username: "alice", routes: ["GET /api/v1/session"] };
  try {
    globalThis.fetch = answer(session);
    assert.deepEqual((await auth.currentSession()).routes, ["GET /api/v1/session"]);
    globalThis.fetch = answer({ ...session, routes: "GET /api/v1/session" });
    await assert.rejects(auth.currentSession(), (error) => error.code === "invalid_response");
    globalThis.fetch = answer({ ...session, routes: [42] });
    await assert.rejects(auth.currentSession(), (error) => error.code === "invalid_response");
  } finally { globalThis.fetch = original; }
});
