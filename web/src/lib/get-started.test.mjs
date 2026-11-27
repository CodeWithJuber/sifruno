// Home's Get started list: each step's state, status and button from what
// the API reports. Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const source = readFileSync(new URL("./get-started.ts", import.meta.url), "utf8");
const gs = await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`);

const id = (n) => n.toString(16).padStart(32, "0");
const site = (change = {}) => ({
  account_id: id(1), username: "example", domain: "example.com", kind: "wordpress", state: "active",
  https: { on: true, not_after: "2027-02-01T00:00:00Z" }, always_https: true, php_version: "8.3", wordpress_version: "6.9",
  url: "https://example.com/", admin_url: "https://example.com/wp-admin/", created_at: "2026-11-27T00:00:00Z", revision: 3,
  site_folder_changed: false, aliases: [], redirect_count: 0, ...change,
});
const storage = (change = {}) => ({
  ready: true, public_key: "ssh-ed25519 AAAA sifruno-backup", configured: true, target: null, password_saved: true,
  nightly_at: "02:30", timezone: "UTC", last_drill: null, last_prune: null, ...change,
});
const drill = (passed, change = {}) => ({ account_id: id(1), domain: "example.com", passed, checked_at: "2026-11-27T00:22:00Z", files: 10, message: "", ...change });
const migration = (gate) => ({ source: id(9), source_host: "old.example.net", source_user: "root", tier: "", php_source: "", wordpress: true, databases: [], database_users: [],
  tables: [], notes: [], verify: null, gate, accepted: null, address: "", dns: [], key_removed: false, activity: [] });
const job = (change = {}) => ({ id: id(7), kind: "migration", domain: "shop.example", username: "shop", php_version: "", state: "running", steps: [],
  error: null, result: null, actor: "", created_at: "2026-11-27T00:00:00Z", updated_at: "2026-11-27T00:00:00Z", migration: migration("closed"), ...change });
const login = (change = {}) => ({ username: "bakery", websites: [id(1)], disabled: false, setup: "done", setup_expires_at: null, created_at: "2026-11-27T00:00:00Z", ...change });
const day = (iso) => iso.slice(0, 10);

const ok = (data) => ({ data });
const origin = "https://panel.example.com:8443";

test("the panel's address: trusted, no name, wrong place, name without a certificate", () => {
  const done = gs.panelAddressStep(ok({ available: true, address: origin }), origin);
  assert.equal(done.state, "done");
  assert.match(done.status, /panel\.example\.com:8443 with a certificate browsers trust/);
  assert.equal(done.action, undefined);

  const none = gs.panelAddressStep(ok({ available: false, detail: "no name" }), "http://127.0.0.1:8080");
  assert.equal(none.state, "todo");
  assert.equal(none.action.kind, "how");
  assert.ok(none.action.lines.some((line) => line.includes("--panel-host panel.example.com --acme-email")));

  const elsewhere = gs.panelAddressStep(ok({ available: false, address: origin }), "http://127.0.0.1:8080");
  assert.equal(elsewhere.state, "todo");
  assert.deepEqual(elsewhere.action, { kind: "address", label: "Open panel.example.com:8443", href: `${origin}/` });

  const untrusted = gs.panelAddressStep(ok({ available: false, address: origin }), "https://PANEL.example.com:8443");
  assert.equal(untrusted.state, "waiting");
  assert.match(untrusted.status, /certificate is not in place yet/);
  assert.equal(untrusted.action.kind, "how");
  assert.ok(untrusted.action.lines.some((line) => line.includes("journalctl -u sifruno")));
});

test("a step the panel could not read says so and offers nothing", () => {
  const loading = gs.firstWebsiteStep({ loading: true });
  assert.deepEqual([loading.state, loading.status, loading.action], ["unknown", "Checking…", undefined]);
  const failed = gs.customerLoginStep({ error: "Your sign-in has ended." });
  assert.equal(failed.state, "unknown");
  assert.match(failed.status, /could not check this: Your sign-in has ended\./);
});

test("the first website", () => {
  const empty = gs.firstWebsiteStep(ok([]));
  assert.equal(empty.state, "todo");
  assert.deepEqual(empty.action, { kind: "page", label: "Create a website", to: "/websites/new" });
  const two = gs.firstWebsiteStep(ok([site(), site({ account_id: id(2), domain: "two.example" })]));
  assert.equal(two.state, "done");
  assert.equal(two.status, "2 websites on this server.");
});

test("moving a website is optional and follows the latest move", () => {
  const none = gs.moveWebsiteStep(ok([{ ...job(), kind: "wordpress", migration: null }]));
  assert.equal(none.optional, true);
  assert.equal(none.state, "todo");
  assert.deepEqual(none.action, { kind: "page", label: "Move a website", to: "/websites/move" });

  const running = gs.moveWebsiteStep(ok([job()]));
  assert.equal(running.state, "todo");
  assert.match(running.status, /shop\.example is being moved/);
  assert.equal(running.action.to, `/websites/move/${id(7)}`);

  const failed = gs.moveWebsiteStep(ok([job({ state: "failed" })]));
  assert.match(failed.status, /stopped/);

  const ready = gs.moveWebsiteStep(ok([job({ id: id(8), migration: migration("open") }), job({ state: "succeeded", migration: migration("ready") })]));
  assert.equal(ready.state, "done");
  assert.equal(ready.action.to, `/websites/move/${id(7)}`);
});

test("backups: storage, password, restore test", () => {
  const sites = ok([site()]);
  const none = gs.backupsStep(ok(storage({ configured: false })), sites, day);
  assert.equal(none.state, "todo");
  assert.deepEqual(none.action, { kind: "page", label: "Set up backup storage", to: "/server/backups" });

  const unsaved = gs.backupsStep(ok(storage({ password_saved: false })), sites, day);
  assert.equal(unsaved.action.label, "Save the backup password");

  const untested = gs.backupsStep(ok(storage()), sites, day);
  assert.equal(untested.state, "todo");
  assert.deepEqual(untested.action, { kind: "page", label: "Test a restore", to: `/websites/sites/${id(1)}/backups` });
  assert.match(untested.status, /every night at 02:30/);

  const noSites = gs.backupsStep(ok(storage()), ok([]), day);
  assert.equal(noSites.state, "waiting");

  const failed = gs.backupsStep(ok(storage({ last_drill: drill(false) })), sites, day);
  assert.equal(failed.state, "todo");
  assert.equal(failed.action.to, `/websites/sites/${id(1)}/backups`);
  const failedGone = gs.backupsStep(ok(storage({ last_drill: drill(false, { account_id: id(5) }) })), sites, day);
  assert.equal(failedGone.action.to, "/server/backups");

  const passed = gs.backupsStep(ok(storage({ last_drill: drill(true) })), sites, day);
  assert.equal(passed.state, "done");
  assert.match(passed.status, /restore test passed on 2026-11-27/);
});

test("customer logins: none, waiting, expired, set up", () => {
  const none = gs.customerLoginStep(ok({ items: [], capacity: 500 }));
  assert.deepEqual([none.state, none.action.label, none.action.to], ["todo", "Give a customer a login", "/customers"]);
  const waiting = gs.customerLoginStep(ok({ items: [login({ setup: "pending" })], capacity: 500 }));
  assert.equal(waiting.state, "waiting");
  assert.match(waiting.status, /Waiting for bakery/);
  const expired = gs.customerLoginStep(ok({ items: [login({ setup: "expired" })], capacity: 500 }));
  assert.equal(expired.action.label, "Make a new setup link");
  const off = gs.customerLoginStep(ok({ items: [login({ disabled: true })], capacity: 500 }));
  assert.equal(off.state, "todo");
  const done = gs.customerLoginStep(ok({ items: [login(), login({ username: "florist" })], capacity: 500 }));
  assert.equal(done.state, "done");
  assert.equal(done.status, "2 customer logins are set up.");
});

test("Always use HTTPS: after a certificate, every certified site on", () => {
  const none = gs.alwaysHttpsStep(ok([]));
  assert.equal(none.state, "waiting");
  const noCert = gs.alwaysHttpsStep(ok([site({ https: { on: false, not_after: "" } })]));
  assert.equal(noCert.state, "waiting");
  assert.equal(noCert.action.to, `/websites/sites/${id(1)}/domains`);
  const off = gs.alwaysHttpsStep(ok([site(), site({ account_id: id(2), domain: "plain.example", always_https: false })]));
  assert.deepEqual([off.state, off.action.label, off.action.to], ["todo", "Turn it on", `/websites/sites/${id(2)}/domains`]);
  assert.match(off.status, /plain\.example still answers on plain http/);
  const old = gs.alwaysHttpsStep(ok([site({ always_https: undefined })]));
  assert.equal(old.state, "unknown");
  const done = gs.alwaysHttpsStep(ok([site(), site({ account_id: id(2), https: { on: false, not_after: "" } }), site({ account_id: id(3), state: "suspended", always_https: false })]));
  assert.equal(done.state, "done");
  assert.equal(done.status, "1 website sends visitors to https://. 1 website follows once its certificate comes.");
});

test("progress counts the required steps, and the next step is the first one the owner can act on", () => {
  const fresh = gs.getStartedSteps({
    address: ok({ available: false }), websites: ok([]), jobs: ok([]), backups: ok(storage({ configured: false })),
    customers: ok({ items: [], capacity: 500 }), origin: "http://127.0.0.1:8080", day,
  });
  assert.deepEqual(fresh.map((s) => s.id), ["panel-address", "first-website", "move-website", "backups", "customer-login", "always-https"]);
  assert.deepEqual(gs.getStartedProgress(fresh), { done: 0, total: 5, complete: false });
  // The panel's name needs the server, so its "how" is not the next button.
  assert.equal(gs.nextStep(fresh), "first-website");

  const ready = gs.getStartedSteps({
    address: ok({ available: true, address: origin }), websites: ok([site()]), jobs: ok([]), backups: ok(storage({ last_drill: drill(true) })),
    customers: ok({ items: [login()], capacity: 500 }), origin, day,
  });
  // Complete without the optional move; then the move is the next step.
  assert.deepEqual(gs.getStartedProgress(ready), { done: 5, total: 5, complete: true });
  assert.equal(gs.nextStep(ready), "move-website");
});

test("the note beside a setup link and Open phpMyAdmin follows the panel's certificate", () => {
  const trusted = { available: true, address: origin };
  assert.equal(gs.panelTrustNote(trusted, origin, "setup-link"), undefined);
  assert.equal(gs.panelTrustNote(trusted, origin, "phpmyadmin"), undefined);

  // At the name without a trusted certificate: both warn, and say what the
  // browser shows and where the next step is.
  const untrusted = { available: false, address: origin, detail: "Passkeys need a certificate browsers trust." };
  const link = gs.panelTrustNote(untrusted, origin, "setup-link");
  assert.equal(link.state, "untrusted");
  assert.match(link.what, /panel\.example\.com:8443/);
  assert.match(link.what, /Your connection is not private/);
  assert.match(link.next, /Give the panel its own address/);
  const pma = gs.panelTrustNote(untrusted, origin, "phpmyadmin");
  assert.equal(pma.state, "untrusted");
  assert.match(pma.what, /phpMyAdmin/);
  assert.match(pma.next, /Get started/);
  // A customer cannot act on Get started: it is told who can.
  assert.match(gs.panelTrustNote(untrusted, origin, "phpmyadmin", false).next, /hosting provider/);

  // No name: the link cannot be opened safely; phpMyAdmin is not served.
  const none = { available: false, detail: "no name" };
  assert.equal(gs.panelTrustNote(none, "http://127.0.0.1:8080", "setup-link").state, "no-name");
  assert.equal(gs.panelTrustNote(none, "http://127.0.0.1:8080", "phpmyadmin"), undefined);

  // Opened elsewhere (through an SSH tunnel): it cannot tell, and says so.
  const elsewhere = gs.panelTrustNote(untrusted, "http://127.0.0.1:8080", "setup-link");
  assert.equal(elsewhere.state, "unknown");
  assert.equal(elsewhere.href, `${origin}/`);
  assert.equal(gs.panelTrustNote(untrusted, "http://127.0.0.1:8080", "phpmyadmin").state, "unknown");
});
