// Scheduled jobs, logs and usage client checks with synthetic answers; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const websitesURL = moduleURL(readFileSync(new URL("./websites-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL)));
const api = await import(moduleURL(readFileSync(new URL("./site-tools-api.ts", import.meta.url), "utf8")
  .replace('"./sites-api"', JSON.stringify(sitesURL)).replace('"./websites-api"', JSON.stringify(websitesURL)).replace('"./websites-api"', JSON.stringify(websitesURL))));
const websites = await import(websitesURL);

const accountId = "0123456789abcdef0123456789abcdef";
const session = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-23T10:15:00Z" };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const cron = (change = {}) => ({
  jobs: [{ schedule: "*/5 * * * *", command: "php ~/public_html/wp-cron.php > /dev/null 2>&1", next_run: "2026-11-24T10:10:00+04:00" }],
  max_jobs: 50, server_time: "2026-11-24T10:07:30+04:00", revision: 7, state: "active", ...change,
});

async function withFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

test("schedules follow the account service's grammar", () => {
  for (const s of ["* * * * *", "*/5 * * * *", "0 3 * * 1-5", "0,30 9-17 * * 1,3,5", "59 23 31 12 7", "1-59/2 * * * *", "  0   3 * * *  "]) {
    assert.equal(api.scheduleProblem(s), undefined, s);
  }
  for (const s of ["", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "5/10 * * * *", "5-1 * * * *", "1,,2 * * * *", "@daily", "* * * jan *", "0~30 * * * *", "100 * * * *"]) {
    assert.ok(api.scheduleProblem(s), s);
  }
  assert.match(api.scheduleProblem("60 * * * *"), /minute field "60"/);
  assert.equal(api.normalizeSchedule(" 0\t3  * * * "), "0 3 * * *");
  for (const preset of api.cronPresets) assert.equal(api.scheduleProblem(preset.schedule), undefined, preset.id);
  assert.equal(api.scheduleLabel("0 3 * * *"), "Every day at 03:00");
  assert.equal(api.scheduleLabel("1 2 3 4 5"), undefined);
});

test("commands are one line without %", () => {
  assert.equal(api.commandProblem("php artisan schedule:run >> ~/cron.log 2>&1"), undefined);
  assert.equal(api.commandProblem("x".repeat(1024)), undefined);
  for (const c of ["", " true", "true ", "-n true", "* true", "echo a\n* * * * * id", "echo a\rb", "date +%s", "a\tb", "a\u2028b", "é".repeat(513)]) {
    assert.ok(api.commandProblem(c), JSON.stringify(c));
  }
});

test("values read in plain words", () => {
  assert.equal(api.bytesLabel(0), "0 bytes");
  assert.equal(api.bytesLabel(1536), "1.5 KB");
  assert.equal(api.bytesLabel(200 * 1024 * 1024), "200 MB");
  assert.equal(api.bytesLabel(1.25 * 1024 ** 3), "1.3 GB");
  assert.equal(api.serverZone("2026-11-24T10:07:30+04:00"), "UTC+04:00");
  assert.equal(api.serverZone("2026-11-24T10:07:30Z"), "UTC");
  // The run time is shown on the server's clock, whatever the reader's zone.
  assert.equal(api.serverClock("2026-11-24T10:10:00+04:00", "en-GB"), "24 Nov 2026, 10:10");
  assert.match(api.serverClock(""), /^Never/);
  assert.deepEqual(api.diskUse({ disk_used_bytes: 50 * 1024 * 1024, disk_limit_bytes: 200 * 1024 * 1024, traffic_month: "2026-11", traffic_bytes: 0, traffic_complete: true }), { used: "50 MB", limit: "200 MB", percent: 25, full: false });
  assert.deepEqual(api.diskUse({ disk_used_bytes: 10, disk_limit_bytes: 0, traffic_month: "2026-11", traffic_bytes: 0, traffic_complete: true }), { used: "10 bytes", full: false });
  assert.equal(api.monthLabel("2026-11", "en-GB"), "November 2026");
});

test("answers are checked against the contract", () => {
  assert.deepEqual(api.parseWebsiteCron({ $schema: "x", ...cron() }), cron());
  assert.equal(api.parseWebsiteCron(cron({ jobs: [{ schedule: "@reboot", command: "x", next_run: "" }] })), undefined);
  assert.equal(api.parseWebsiteCron(cron({ max_jobs: 10 })), undefined);
  assert.equal(api.parseWebsiteCron(cron({ revision: 0 })), undefined);
  assert.equal(api.parseWebsiteCron(cron({ jobs: Array.from({ length: 51 }, () => cron().jobs[0]) })), undefined);
  const log = { kind: "access", lines: ['1.2.3.4 - - [24/Nov/2026:10:00:00 +0400] "GET /<script> HTTP/1.1" 200 5'], truncated: true, size_bytes: 4096, missing: false };
  assert.deepEqual(api.parseWebsiteLog(log, "access"), log);
  assert.equal(api.parseWebsiteLog(log, "error"), undefined);
  assert.equal(api.parseWebsiteLog({ ...log, lines: [1] }, "access"), undefined);
  const usage = { disk_used_bytes: 1, disk_limit_bytes: 0, traffic_month: "2026-11", traffic_bytes: 5, traffic_complete: false };
  assert.deepEqual(websites.parseWebsiteUsage(usage), usage);
  assert.equal(websites.parseWebsiteUsage({ ...usage, traffic_month: "2026-13" }), undefined);
  assert.equal(websites.parseWebsiteUsage({ ...usage, disk_used_bytes: -1 }), undefined);
  // The list takes usage when it is there, and refuses a malformed one.
  const site = { account_id: accountId, username: "example", domain: "example.com", kind: "php", state: "active", https: { on: false, not_after: "" }, php_version: "8.3", wordpress_version: "", url: "http://example.com/", admin_url: "", created_at: "2026-11-23T10:00:00Z", revision: 7, site_folder_changed: false };
  assert.deepEqual(websites.parseWebsite({ ...site, usage }).usage, usage);
  assert.equal(websites.parseWebsite({ ...site, usage: { ...usage, traffic_bytes: "5" } }), undefined);
});

test("saving sends the whole list with the revision and the session's CSRF token", async () => {
  const calls = [];
  await withFetch(async (url, init) => {
    calls.push({ url, init });
    if (url === "/api/v1/session") return json(session);
    return json(cron({ revision: 8, jobs: [] }));
  }, async () => {
    const saved = await api.saveCron(accountId, 7, [{ schedule: "0 3 * * *", command: "~/nightly.sh" }]);
    assert.equal(saved.revision, 8);
  });
  assert.equal(calls.length, 2);
  const post = calls[1];
  assert.equal(post.url, `/api/v1/websites/sites/${accountId}/cron`);
  assert.equal(post.init.method, "POST");
  assert.equal(post.init.headers["X-CSRF-Token"], session.csrf_token);
  assert.deepEqual(JSON.parse(post.init.body), { jobs: [{ schedule: "0 3 * * *", command: "~/nightly.sh" }], expected_revision: 7 });
});

test("a refusal says what happened, why and what next, with the server's detail", async () => {
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ title: "Unprocessable Entity", status: 422, detail: "Job 1: The command contains %, which cron turns into a new line." }, 422), async () => {
    await assert.rejects(api.saveCron(accountId, 7, [{ schedule: "* * * * *", command: "x" }]), (error) => {
      assert.equal(error.name, "SiteToolsApiError");
      assert.equal(error.message, "The scheduled jobs were not saved.");
      assert.match(error.why, /^Job 1: The command contains %/);
      assert.match(error.technical, /HTTP 422/);
      return true;
    });
  });
  await withFetch(async () => json({ title: "Unauthorized", status: 401 }, 401), async () => {
    await assert.rejects(api.saveCron(accountId, 7, []), (error) => error.status === 401 && /nothing was sent/.test(error.technical));
  });
  await assert.rejects(api.getCron("not-an-id"), (error) => error.status === 404 && /nothing was sent/.test(error.technical));
});

test("reads go to the site's own routes and check the answer", async () => {
  const seen = [];
  await withFetch(async (url) => {
    seen.push(url);
    if (url.endsWith("/cron")) return json(cron());
    if (url.endsWith("/logs/error")) return json({ kind: "error", lines: [], truncated: false, size_bytes: 0, missing: true });
    if (url.endsWith("/usage")) return json({ disk_used_bytes: 1024, disk_limit_bytes: 2048, traffic_month: "2026-11", traffic_bytes: 99, traffic_complete: true });
    return json({}, 404);
  }, async () => {
    assert.equal((await api.getCron(accountId)).jobs.length, 1);
    assert.equal((await api.getLog(accountId, "error")).missing, true);
    assert.equal((await api.getUsage(accountId)).traffic_bytes, 99);
  });
  assert.deepEqual(seen, [`/api/v1/websites/sites/${accountId}/cron`, `/api/v1/websites/sites/${accountId}/logs/error`, `/api/v1/websites/sites/${accountId}/usage`]);
  await withFetch(async () => json({ kind: "access", lines: "not a list" }), async () => {
    await assert.rejects(api.getLog(accountId, "access"), (error) => /did not match the contract/.test(error.technical));
  });
});
