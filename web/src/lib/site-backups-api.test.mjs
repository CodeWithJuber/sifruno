// Website backups client checks with synthetic sessions and fetch responses; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./site-backups-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL))));

const accountId = "0123456789abcdef0123456789abcdef";
const snapshotId = "d".repeat(64);
const hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const session = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-24T10:15:00Z" };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const problem = (status, detail, errors) => json({ title: "Problem", status, detail, ...(errors ? { errors } : {}) }, status);

const storage = (extra = {}) => ({
  $schema: "http://127.0.0.1/schemas/BackupStorage.json", ready: true, public_key: "ssh-ed25519 AAAA sifruno-backup", configured: true,
  target: { host: "backup.example.test", port: 22, user: "sifbackup", path: "/srv/backups/web1", host_keys: [hostKey] }, password_saved: false,
  nightly_at: "02:30", timezone: "Asia/Dubai",
  last_drill: { account_id: accountId, domain: "example.test", passed: true, checked_at: "2026-11-23T23:10:00Z", snapshot: snapshotId, snapshot_time: "2026-11-23T22:31:00Z", files: 1830, subset: "1/8", message: "The latest backup restored completely." },
  last_prune: null, ...extra,
});
const snapshot = (id = snapshotId, extra = {}) => ({ id, time: "2026-11-23T22:31:04.123456789Z", bytes: 52428800, files: 1830, databases: ["example_wp"], ...extra });
const site = (extra = {}) => ({
  configured: true, ready: true, domain: "example.test", revision: 7, nightly_at: "02:30", timezone: "Asia/Dubai",
  running: null, last_backup: { kind: "backup", status: "succeeded", started_at: "2026-11-23T22:30:00Z", finished_at: "2026-11-23T22:31:10Z", actor: "scheduler", snapshot: snapshotId, message: "The site and its databases were backed up." },
  last_restore: null, last_drill: null, snapshots: [snapshot()], snapshots_error: "", ...extra,
});

async function withFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

function server(answer) {
  const calls = [];
  const mock = async (url, init) => {
    if (url === "/api/v1/session") return json(session);
    calls.push({ url, method: init.method, headers: init.headers, body: init.body === undefined ? undefined : JSON.parse(init.body) });
    return answer(url, init);
  };
  return { calls, mock };
}

test("target fields follow the broker's rules", () => {
  for (const ok of ["backup.example.test", "10.0.0.5", "::1", "fd00::5", "a"]) assert.equal(api.checkHost(ok), undefined, ok);
  for (const bad of ["", "Backup.example.test", "-oProxyCommand=x", "backup example", "0.0.0.0", "a_b.example", "x".repeat(254)]) assert.equal(typeof api.checkHost(bad), "string", bad);
  for (const ok of ["22", "1", "65535", "2222"]) assert.equal(api.checkPort(ok), undefined, ok);
  for (const bad of ["", "0", "65536", "22a", "-1", "1.5", " 22"]) assert.equal(typeof api.checkPort(bad), "string", bad);
  for (const ok of ["sifbackup", "_b", "a.b-c_9"]) assert.equal(api.checkUser(ok), undefined, ok);
  for (const bad of ["", "-l", "Sif", "sif backup", "a".repeat(33)]) assert.equal(typeof api.checkUser(bad), "string", bad);
  for (const ok of ["/srv/backups", "/srv/backups/web-1.x_y"]) assert.equal(api.checkPath(ok), undefined, ok);
  for (const bad of ["", "srv", "/srv/", "/srv//x", "/srv/my backups", "/srv/\"x\"", "/srv/../etc", "/srv/./x"]) assert.equal(typeof api.checkPath(bad), "string", bad);
  for (const ok of [hostKey, `backup.example.test ${hostKey}`, `# backup.example.test:22 SSH-2.0\n[backup.example.test]:2222 ${hostKey}\n`]) assert.equal(api.checkKnownHosts(ok), undefined, ok);
  for (const bad of ["", "# only a comment", "not a key", "ssh-dss AAAA", "ssh-ed25519"]) assert.equal(typeof api.checkKnownHosts(bad), "string", bad);
});

test("a target form sends exactly the five keys, the port as a number", () => {
  const form = { host: " backup.example.test ", port: "22", user: "sifbackup", path: "/srv/backups/web1", known_hosts: `${hostKey}\r\n` };
  assert.deepEqual(api.targetBody(form), { body: { host: "backup.example.test", port: 22, user: "sifbackup", path: "/srv/backups/web1", known_hosts: `${hostKey}\n` } });
  const bad = api.targetBody({ ...form, path: "relative" });
  assert.equal(bad.field, "path");
  assert.deepEqual(api.formFromTarget(null), { host: "", port: "22", user: "", path: "", known_hosts: "" });
  assert.equal(api.formFromTarget(storage().target).known_hosts, hostKey);
});

test("a restore needs the domain typed exactly and sends the page's revision", () => {
  const s = { domain: "example.test", revision: 7 };
  assert.deepEqual(api.restoreBody(s, snapshot(), "both", "example.test"), { body: { snapshot: snapshotId, what: "both", confirm_domain: "example.test", expected_revision: 7 } });
  for (const typed of ["", "Example.test", "example.test ", "example"]) assert.ok("problem" in api.restoreBody(s, snapshot(), "files", typed), JSON.stringify(typed));
  assert.match(api.restoreBody(s, snapshot(), "files", "").problem, /Type example.test to confirm/);
  assert.match(api.restoreBody(s, snapshot(snapshotId, { databases: [] }), "database", "example.test").problem, /no database/);
  assert.ok("problem" in api.restoreBody(s, snapshot(), "everything", "example.test"));
  assert.match(api.restoreEffect("files"), /Files added since the backup stay/);
  assert.match(api.restoreEffect("database"), /lost/);
  assert.match(api.restoreEffect("both"), /stay.*lost/s);
});

test("numbers, times and lines read plainly", () => {
  assert.equal(api.formatBytes(0), "0 bytes");
  assert.equal(api.formatBytes(1), "1 byte");
  assert.equal(api.formatBytes(1536), "1.5 KB");
  assert.equal(api.formatBytes(52428800), "50 MB");
  assert.equal(api.formatBytes(-1), "Unknown size");
  assert.equal(api.formatWhen("2026-11-23T22:31:04Z", "Asia/Dubai"), "24 Nov 2026, 02:31 (Asia/Dubai)");
  assert.match(api.formatWhen("2026-11-23T22:31:04Z", "Local"), /\(this browser's time\)$/);
  assert.equal(api.formatWhen("not a date", "UTC"), "Unknown time");
  assert.equal(api.scheduleLine("02:30", "Asia/Dubai"), "Every night at 02:30, Asia/Dubai. Kept: 7 daily and 4 weekly.");
  assert.equal(api.drillLine(storage().last_drill, "Asia/Dubai"), "Passed, 24 Nov 2026, 03:10 (Asia/Dubai), example.test.");
  assert.match(api.drillLine(null, "UTC"), /No restore drill has run yet/);
  assert.match(api.runningLine({ kind: "backup", started_at: "2026-11-23T22:30:00Z", actor: "scheduler" }, "UTC"), /^A backup is running\. Started by the nightly schedule/);
  assert.equal(api.resultTechnical({ step: "copy", detail: "cp: cannot create", snapshot: snapshotId }), `step: copy\ncp: cannot create\nbackup id: ${snapshotId}`);
});

test("polling runs only while a job runs, and the password closes only once saved", () => {
  assert.equal(api.shouldPoll(site()), false);
  assert.equal(api.shouldPoll(site({ running: { kind: "restore", started_at: "2026-11-24T08:00:00Z", actor: "admin" } })), true);
  assert.equal(api.shouldPoll(undefined), false);
  assert.equal(api.passwordFrom({ ...storage(), initialized: true, password: "p".repeat(43) }), "p".repeat(43));
  assert.equal(api.passwordFrom({ ...storage(), initialized: false }), undefined);
  assert.equal(api.canClosePassword(false), false);
  assert.equal(api.canClosePassword(true), true);
});

test("answers are read strictly", () => {
  assert.deepEqual(api.parseBackupStorage(storage()).target.host_keys, [hostKey]);
  assert.equal(api.parseBackupStorage(storage({ target: null, configured: false })).target, null);
  assert.equal(api.parseBackupStorage(storage({ ready: "yes" })), undefined);
  assert.equal(api.parseBackupStorage(storage({ last_drill: { passed: true } })), undefined);
  assert.equal(api.parseBackupStorage(storage()).password_saved, false);
  assert.equal(api.parseBackupStorage(storage({ password_saved: undefined })), undefined);
  assert.equal(api.parseShownPassword({ password: "p".repeat(43) }), "p".repeat(43));
  for (const bad of [{}, { password: "" }, { password: "p".repeat(44) }, { password: `${"p".repeat(42)}<` }, null]) assert.equal(api.parseShownPassword(bad), undefined, JSON.stringify(bad));
  const parsed = api.parseSiteBackups(site());
  assert.equal(parsed.snapshots[0].bytes, 52428800);
  assert.equal(parsed.last_backup.status, "succeeded");
  assert.equal(api.parseSiteBackups(site({ snapshots: [snapshot("short")] })), undefined);
  assert.equal(api.parseSiteBackups(site({ running: { kind: "delete", started_at: "2026-11-24T08:00:00Z", actor: "x" } })), undefined);
  assert.equal(api.parseSiteBackups(site({ snapshots: [snapshot(snapshotId, { databases: ["a;drop"] })] })), undefined);
  assert.equal(api.parseSiteBackups(site({ snapshots: [snapshot(snapshotId, { databases: null })] })).snapshots[0].databases.length, 0);
  assert.equal(api.parseBackupStorageSaved({ ...storage(), initialized: true }).password, undefined);
});

test("saving the target sends the CSRF token and the exact body, and returns the password once", async () => {
  const { calls, mock } = server(() => json({ ...storage(), initialized: true, password: "p".repeat(43) }));
  await withFetch(mock, async () => {
    const saved = await api.saveBackupStorage({ host: "backup.example.test", port: "2222", user: "sifbackup", path: "/srv/backups/web1", known_hosts: hostKey });
    assert.equal(saved.password, "p".repeat(43));
    assert.equal(saved.initialized, true);
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/v1/websites/backup-storage");
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].headers["X-CSRF-Token"], session.csrf_token);
  assert.deepEqual(calls[0].body, { host: "backup.example.test", port: 2222, user: "sifbackup", path: "/srv/backups/web1", known_hosts: hostKey });
});

test("the password is shown again and confirmed saved with the CSRF token and an empty body", async () => {
  const { calls, mock } = server((url) => url.endsWith("/password") ? json({ password: "p".repeat(43) }) : json(storage({ password_saved: true })));
  await withFetch(mock, async () => {
    assert.equal(await api.showBackupPassword(), "p".repeat(43));
    assert.equal((await api.confirmBackupPasswordSaved()).password_saved, true);
  });
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.headers["X-CSRF-Token"], JSON.stringify(c.body)]), [
    ["POST", "/api/v1/websites/backup-storage/password", session.csrf_token, "{}"],
    ["POST", "/api/v1/websites/backup-storage/password-saved", session.csrf_token, "{}"],
  ]);
  const gone = server(() => problem(409, "The backup password was already marked as saved, so the panel no longer shows it. Use the copy you saved. Nothing changed."));
  await withFetch(gone.mock, async () => {
    await assert.rejects(api.showBackupPassword(), (error) => {
      assert.equal(error.message, "The backup password could not be shown.");
      assert.match(error.why, /already marked as saved/);
      assert.match(error.next, /Use the copy you saved/);
      assert.doesNotMatch(`${error.why} ${error.technical}`, /p{43}/);
      return true;
    });
  });
});

test("a bad target is not sent, and a refused one says why with technical details", async () => {
  const { calls, mock } = server(() => problem(422, "The panel could not reach the backup storage server, so nothing was backed up.", [{ message: "step: connect" }, { message: "Host key verification failed." }]));
  await withFetch(mock, async () => {
    await assert.rejects(api.saveBackupStorage({ host: "-x", port: "22", user: "u", path: "/srv", known_hosts: hostKey }), (error) => error.status === 422 && /not sent/.test(error.technical));
    assert.equal(calls.length, 0);
    await assert.rejects(api.saveBackupStorage({ host: "backup.example.test", port: "22", user: "u", path: "/srv", known_hosts: hostKey }), (error) => {
      assert.equal(error.message, "The backup storage was not saved.");
      assert.match(error.why, /could not reach/);
      assert.match(error.technical, /step: connect; Host key verification failed/);
      return true;
    });
  });
});

test("the site's jobs post to their own addresses", async () => {
  const running = { kind: "backup", started_at: "2026-11-24T08:00:00Z", actor: "admin" };
  const { calls, mock } = server(() => json({ running }, 202));
  await withFetch(mock, async () => {
    assert.deepEqual(await api.startBackup(accountId), running);
    await api.startDrill(accountId);
    await api.startRestore(accountId, { domain: "example.test", revision: 7 }, snapshot(), "database", "example.test");
  });
  assert.deepEqual(calls.map((c) => [c.url, c.body]), [
    [`/api/v1/websites/sites/${accountId}/backups`, {}],
    [`/api/v1/websites/sites/${accountId}/backups/drill`, {}],
    [`/api/v1/websites/sites/${accountId}/backups/restore`, { snapshot: snapshotId, what: "database", confirm_domain: "example.test", expected_revision: 7 }],
  ]);
  await withFetch(mock, async () => {
    await assert.rejects(api.startRestore(accountId, { domain: "example.test", revision: 7 }, snapshot(), "files", "wrong"), (error) => /not sent/.test(error.technical));
    await assert.rejects(api.startBackup("not-an-id"), (error) => error.status === 404);
  });
  assert.equal(calls.length, 3);
});

test("a busy site answers 409 with the server's words", async () => {
  const { mock } = server(() => problem(409, "This site already has a backup, restore or drill running. Wait for it to finish, then try again."));
  await withFetch(mock, async () => {
    await assert.rejects(api.startBackup(accountId), (error) => error.status === 409 && /already has a backup/.test(error.why) && error.message === "The backup did not start.");
  });
});

test("reading the site's backups and the storage page", async () => {
  const { calls, mock } = server((url) => url.endsWith("/backups") ? json(site()) : json(storage()));
  await withFetch(mock, async () => {
    const s = await api.getSiteBackups(accountId);
    assert.equal(s.domain, "example.test");
    const st = await api.getBackupStorage();
    assert.equal(st.timezone, "Asia/Dubai");
  });
  assert.deepEqual(calls.map((c) => c.method), ["GET", "GET"]);
  const broken = server(() => json({ configured: true }));
  await withFetch(broken.mock, async () => {
    await assert.rejects(api.getSiteBackups(accountId), (error) => error.status === 0 && /contract/.test(error.technical));
  });
});
