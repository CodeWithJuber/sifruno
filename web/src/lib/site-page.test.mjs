// One website's page: its tabs in Simple and Advanced view, the stored view,
// the Overview's health checklist and recent activity. Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const read = (name) => readFileSync(new URL(name, import.meta.url), "utf8");
const sitesURL = moduleURL(read("./sites-api.ts"));
const websitesURL = moduleURL(read("./websites-api.ts").replace('"./sites-api"', JSON.stringify(sitesURL)));
const toolsURL = moduleURL(read("./site-tools-api.ts").replace('"./sites-api"', JSON.stringify(sitesURL)).replaceAll('"./websites-api"', JSON.stringify(websitesURL)));
const backupsURL = moduleURL(read("./site-backups-api.ts").replace('"./sites-api"', JSON.stringify(sitesURL)));
const page = await import(moduleURL(read("./site-page.ts")
  .replaceAll('"./websites-api"', JSON.stringify(websitesURL)).replaceAll('"./site-tools-api"', JSON.stringify(toolsURL)).replaceAll('"./site-backups-api"', JSON.stringify(backupsURL))));

const accountId = "0123456789abcdef0123456789abcdef";
const now = new Date("2026-11-24T10:00:00Z");
const site = (change = {}) => ({
  account_id: accountId, username: "example", domain: "example.com", kind: "wordpress", state: "active",
  https: { on: true, not_after: "2027-02-21T12:30:00Z" }, php_version: "8.3", php_versions: ["8.2", "8.3"],
  wordpress_version: "7.1.5", url: "https://example.com/", admin_url: "https://example.com/wp-admin/",
  created_at: "2026-11-20T10:00:00Z", revision: 4, site_folder_changed: false, aliases: [], redirect_count: 0, ...change,
});
const usage = (used, limit) => ({ disk_used_bytes: used, disk_limit_bytes: limit, traffic_month: "2026-11", traffic_bytes: 2048, traffic_complete: true });
const gib = 1024 ** 3;
const backups = (change = {}) => ({
  configured: true, ready: true, domain: "example.com", revision: 4, nightly_at: "02:30", timezone: "UTC",
  running: null, last_backup: null, last_restore: null, last_drill: null, snapshots: [], snapshots_error: "", ...change,
});
const job = (kind, status, finished, change = {}) => ({ kind, status, started_at: finished, finished_at: finished, actor: "scheduler", message: status === "failed" ? "The storage server did not answer." : "Done.", ...change });
const line = (lines, id) => lines.find((l) => l.id === id);
const ok = { failed: false };

test("Simple view shows the six tabs; Advanced adds Cron jobs and Logs before Settings", () => {
  assert.deepEqual(page.tabsFor("simple", "active").map((t) => t.id), ["overview", "domains", "files", "databases", "backups", "settings"]);
  assert.deepEqual(page.tabsFor("advanced", "active").map((t) => t.id), ["overview", "domains", "files", "databases", "backups", "cron", "logs", "settings"]);
  assert.equal(page.tabsFor("advanced", "active").some((t) => /mail/i.test(t.label)), false, "no Email tab: this server has no mail");
});

test("an Advanced tab opened by its address in Simple view stays while it is current", () => {
  assert.deepEqual(page.tabsFor("simple", "active", "logs").map((t) => t.id), ["overview", "domains", "files", "databases", "backups", "logs", "settings"]);
  assert.deepEqual(page.tabsFor("simple", "active", "cron").map((t) => t.id), ["overview", "domains", "files", "databases", "backups", "cron", "settings"]);
});

test("a partly deleted site has only Overview and Settings", () => {
  for (const mode of ["simple", "advanced"]) assert.deepEqual(page.tabsFor(mode, "partly_deleted", "files").map((t) => t.id), ["overview", "settings"]);
});

test("Settings holds cron jobs and logs in Simple view only; repairs and technical facts are Advanced", () => {
  assert.deepEqual(page.viewShows("simple"), { cronInSettings: true, logsInSettings: true, repair: false, technical: false });
  assert.deepEqual(page.viewShows("advanced"), { cronInSettings: false, logsInSettings: false, repair: true, technical: true });
});

test("addresses map to tabs and back", () => {
  assert.equal(page.tabFromPath(`/websites/sites/${accountId}`), "overview");
  assert.equal(page.tabFromPath(`/websites/sites/${accountId}/`), "overview");
  for (const tab of page.siteTabs.filter((t) => t.segment)) {
    assert.equal(page.tabFromPath(`/websites/sites/${accountId}/${tab.segment}`), tab.id);
    assert.equal(page.tabRoute(tab.id), `/websites/sites/$accountId/${tab.segment}`);
  }
  assert.equal(page.tabRoute("overview"), "/websites/sites/$accountId");
  assert.equal(page.tabFromPath(`/websites/sites/${accountId}/mail`), undefined);
  assert.equal(page.tabFromPath("/websites"), undefined);
  assert.equal(page.tabFromPath(`/websites/sites/${accountId}/files/more`), undefined);
});

test("the view is read and saved safely, and starts Simple when storage fails", () => {
  const store = new Map();
  const storage = () => ({ getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) });
  assert.equal(page.readViewMode(storage), "simple");
  assert.equal(page.saveViewMode("advanced", storage), true);
  assert.equal(store.get(page.viewModeKey), "advanced");
  assert.equal(page.readViewMode(storage), "advanced");
  store.set(page.viewModeKey, "expert");
  assert.equal(page.readViewMode(storage), "simple", "an unknown value is Simple");
  const refused = () => { throw new DOMException("blocked", "SecurityError"); };
  assert.equal(page.readViewMode(refused), "simple");
  assert.equal(page.saveViewMode("advanced", refused), false);
  const throwing = () => ({ getItem: () => { throw new Error("quota"); }, setItem: () => { throw new Error("quota"); } });
  assert.equal(page.readViewMode(throwing), "simple");
  assert.equal(page.saveViewMode("simple", throwing), false);
});

test("a healthy site passes every line, in a fixed order", () => {
  const lines = page.healthChecklist(site(), { data: usage(2 * gib, 10 * gib), failed: false },
    { data: backups({ last_backup: job("backup", "succeeded", "2026-11-24T02:31:00Z") }), failed: false }, now);
  assert.deepEqual(lines.map((l) => l.id), ["serving", "https", "php", "backups", "disk"]);
  assert.deepEqual(lines.map((l) => l.state), ["ok", "ok", "ok", "ok", "ok"]);
  assert.equal(lines.some((l) => l.fix), false, "a passing line offers no fix");
  assert.match(line(lines, "serving").detail, /set to serve/, "worded from the state, not a fetch");
  assert.match(line(lines, "https").detail, /^Valid until /);
  assert.equal(line(lines, "php").detail, "PHP 8.3, installed on this server.");
  assert.equal(line(lines, "disk").detail, "2 GB of 10 GB (20%).");
});

test("reads still running say Checking, and failed reads say unknown", () => {
  let lines = page.healthChecklist(site(), ok, ok, now);
  assert.equal(line(lines, "disk").state, "checking");
  assert.equal(line(lines, "backups").state, "checking");
  lines = page.healthChecklist(site(), { failed: true }, { failed: true }, now);
  assert.equal(line(lines, "disk").state, "unknown");
  assert.equal(line(lines, "backups").state, "unknown");
  assert.equal(line(lines, "disk").fix, undefined);
});

test("the serving line follows the account state and the site folder", () => {
  const serving = (change) => line(page.healthChecklist(site(change), ok, ok, now), "serving");
  assert.deepEqual([serving({ state: "suspended" }).state, serving({ state: "suspended" }).fix], ["attention", "settings"]);
  assert.equal(serving({ state: "recovery_required" }).state, "problem");
  assert.equal(serving({ site_folder_changed: true }).state, "problem");
  assert.equal(serving({ state: "something_new" }).state, "unknown");
  const partly = page.healthChecklist(site({ state: "partly_deleted" }), ok, ok, now);
  assert.deepEqual(partly.map((l) => [l.id, l.state, l.fix]), [["serving", "problem", "settings"]]);
});

test("HTTPS: missing and expired are problems, near its end needs attention", () => {
  const https = (value) => line(page.healthChecklist(site({ https: value }), ok, ok, now), "https");
  assert.deepEqual([https({ on: false, not_after: "" }).state, https({ on: false, not_after: "" }).fix], ["problem", "domains"]);
  assert.equal(https({ on: true, not_after: "2026-11-20T00:00:00Z" }).state, "problem");
  assert.match(https({ on: true, not_after: "2026-11-20T00:00:00Z" }).detail, /expired/);
  const soon = https({ on: true, not_after: "2026-12-01T10:00:00Z" });
  assert.equal(soon.state, "attention");
  assert.match(soon.detail, /7 days from now/);
  assert.equal(https({ on: true, not_after: "2026-12-09T10:00:00Z" }).state, "ok", "15 days left is fine");
  assert.equal(https({ on: true, not_after: "" }).state, "ok");
});

test("PHP: a version not installed on the server is a problem; unreported is unknown", () => {
  const php = (change) => line(page.healthChecklist(site(change), ok, ok, now), "php");
  assert.deepEqual([php({ php_version: "8.1" }).state, php({ php_version: "8.1" }).fix], ["problem", "settings"]);
  assert.match(php({ php_version: "8.1" }).detail, /\(8\.2, 8\.3\)/);
  assert.equal(php({ php_version: "" }).state, "unknown");
  assert.equal(php({ php_versions: [] }).state, "unknown");
});

test("disk: no quota is fine, 90% needs attention, full is a problem with a way to Files", () => {
  const disk = (u) => line(page.healthChecklist(site(), { data: u, failed: false }, ok, now), "disk");
  assert.deepEqual([disk(usage(5 * gib, 0)).state, disk(usage(5 * gib, 0)).detail], ["ok", "5 GB used. No quota is set."]);
  assert.deepEqual([disk(usage(9.2 * gib, 10 * gib)).state, disk(usage(9.2 * gib, 10 * gib)).fix], ["attention", "files"]);
  assert.deepEqual([disk(usage(10 * gib, 10 * gib)).state, disk(usage(10 * gib, 10 * gib)).fix], ["problem", "files"]);
});

test("backups: not set up, not ready, failed, missing and old each say so", () => {
  const backup = (data) => line(page.healthChecklist(site(), ok, { data, failed: false }, now), "backups");
  assert.deepEqual([backup(backups({ configured: false })).state, backup(backups({ configured: false })).fix], ["problem", "backups"]);
  assert.equal(backup(backups({ ready: false })).state, "problem");
  assert.match(backup(backups()).detail, /^No backup yet\. Backups run every night at 02:30\.$/);
  assert.equal(backup(backups()).state, "attention");
  const old = backup(backups({ snapshots: [{ id: "d".repeat(64), time: "2026-11-20T02:31:00Z", bytes: 1, files: 1, databases: [] }] }));
  assert.equal(old.state, "attention");
  assert.match(old.detail, /4 days old/);
  const failed = backup(backups({ snapshots: [{ id: "d".repeat(64), time: "2026-11-23T02:31:00Z", bytes: 1, files: 1, databases: [] }], last_backup: job("backup", "failed", "2026-11-24T02:31:00Z") }));
  assert.equal(failed.state, "problem");
  assert.match(failed.detail, /^The last backup failed/);
  const recovered = backup(backups({ last_backup: job("backup", "succeeded", "2026-11-24T02:31:00Z") }));
  assert.equal(recovered.state, "ok");
  assert.equal(page.lastBackupAt(backups({ snapshots: [{ id: "d".repeat(64), time: "2026-11-24T05:00:00Z", bytes: 1, files: 1, databases: [] }], last_backup: job("backup", "succeeded", "2026-11-24T02:31:00Z") })), Date.parse("2026-11-24T05:00:00Z"));
});

test("recent activity lists what the API records for this site, newest first", () => {
  assert.deepEqual(page.recentActivity(site()).map((i) => i.id), ["created"]);
  const items = page.recentActivity(site(), backups({
    last_backup: job("backup", "failed", "2026-11-24T02:31:00Z"),
    last_restore: job("restore", "succeeded", "2026-11-22T09:00:00Z", { what: "database", actor: "admin" }),
    last_drill: { account_id: accountId, domain: "example.com", passed: true, checked_at: "2026-11-23T03:00:00Z", files: 12, message: "The backup restored and matched." },
  }));
  assert.deepEqual(items.map((i) => i.id), ["backup", "drill", "restore", "created"]);
  assert.deepEqual(items.map((i) => i.ok), [false, true, true, true]);
  assert.equal(items[0].title, "Backup failed");
  assert.equal(items[0].detail, "Started by the nightly schedule. The storage server did not answer.");
  assert.equal(items[2].title, "Restored the database from a backup");
  assert.equal(items[2].detail, "Started by admin.");
  const other = page.recentActivity(site(), backups({ last_drill: { account_id: "f".repeat(32), domain: "other.example", passed: false, checked_at: "2026-11-23T03:00:00Z", files: 0, message: "x" } }));
  assert.deepEqual(other.map((i) => i.id), ["created"], "another site's drill is not this site's activity");
});
