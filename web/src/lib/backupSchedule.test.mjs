// Actual DTO/helper source with synthetic fetch responses; no server or state access.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./backupSchedule.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL))));
const siteId = "a".repeat(32);
const schedule = () => ({ site_id: siteId, revision: 1, interval: "daily", enabled: true, created_at: "2026-10-06T10:00:00Z", updated_at: "2026-10-06T10:00:00Z", next_run_at: "2026-10-07T10:00:00Z", last_run_at: null, last_status: "never", last_backup_id: "", last_error: "", pending: false });
const envelope = (value = schedule()) => ({ schedule: value, intervals: ["hourly", "daily", "weekly"], max_archives: 8, runner_enabled: true });
const input = () => ({ expected_revision: 2, expected_schedule_revision: 1, interval: "weekly", enabled: false });
const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
async function mockFetch(mock, operation) { const original = globalThis.fetch; globalThis.fetch = mock; try { await operation(); } finally { globalThis.fetch = original; } }

test("exact envelope admits absent and configured schedules and fixed capability limits", () => {
  assert(api.validBackupScheduleEnvelope(envelope()));
  assert(api.validBackupScheduleEnvelope(envelope(null)));
  for (const change of [v => { v.schedule = undefined; }, v => { delete v.runner_enabled; }, v => { v.extra = true; }, v => { v.max_archives = 9; }, v => { v.runner_enabled = "false"; }, v => { v.intervals.reverse(); }, v => { v.intervals.push("daily"); }, v => { v.intervals = ["hourly", "daily", "monthly"]; }]) {
    const value = envelope(); change(value); assert.equal(api.validBackupScheduleEnvelope(value), false);
  }
});
test("schedule fails closed on unknown fields, unsafe revisions, identity, flags and enums", () => {
  for (const change of [v => { v.extra = true; }, v => { delete v.pending; }, v => { v.site_id = "A".repeat(32); }, v => { v.revision = 0; }, v => { v.revision = Number.MAX_SAFE_INTEGER + 1; }, v => { v.revision = 1.5; }, v => { v.enabled = 1; }, v => { v.pending = "true"; }, v => { v.interval = "monthly"; }, v => { v.last_status = {}; }, v => { v.last_error = "raw server path"; }]) {
    const value = schedule(); change(value); assert.equal(api.validBackupSchedule(value), false);
  }
});
test("timestamps require canonical whole-second UTC and genuine calendar dates", () => {
  for (const field of ["created_at", "updated_at", "next_run_at", "last_run_at"]) for (const invalid of ["2026-02-30T10:00:00Z", "2026-02-29T10:00:00Z", "2026-10-06T24:00:00Z", "2026-10-06T10:00:00.000Z", "2026-10-06T10:00:00+00:00", "yesterday"]) {
    assert.equal(api.validBackupSchedule({ ...schedule(), [field]: invalid }), false);
  }
  assert(api.validBackupSchedule({ ...schedule(), created_at: "2024-02-29T10:00:00Z" }));
  assert.equal(api.validBackupSchedule({ ...schedule(), updated_at: "2026-10-05T10:00:00Z" }), false);
  assert.equal(api.validBackupSchedule({ ...schedule(), next_run_at: "2026-10-05T10:00:00Z" }), false);
});
test("historical status relationships persist while paused or pending", () => {
  const completed = { ...schedule(), last_status: "completed", last_run_at: "2026-10-06T10:00:00Z", last_backup_id: "b".repeat(32) };
  const failed = { ...schedule(), last_status: "failed", last_run_at: "2026-10-06T10:00:00Z", last_error: "archive_capacity" };
  const interrupted = { ...failed, last_status: "interrupted", last_error: "interrupted" };
  for (const value of [completed, failed, { ...failed, last_error: "backup_failed" }, interrupted]) {
    assert(api.validBackupSchedule(value)); assert(api.validBackupSchedule({ ...value, enabled: false, pending: true, next_run_at: value.created_at }));
    assert.equal(api.validBackupSchedule({ ...value, last_run_at: null }), false);
    assert.equal(api.validBackupSchedule({ ...value, last_run_at: "2026-10-06T10:00:01Z" }), false);
  }
  for (const value of [{ ...schedule(), last_backup_id: "b".repeat(32) }, { ...schedule(), last_run_at: schedule().created_at }, { ...completed, last_error: "backup_failed" }, { ...failed, last_backup_id: "b".repeat(32) }, { ...interrupted, last_error: "backup_failed" }]) assert.equal(api.validBackupSchedule(value), false);
});
test("PUT admits exactly both expected revisions, interval and enabled", () => {
  assert(api.validBackupScheduleInput(input())); assert(api.validBackupScheduleInput({ ...input(), expected_schedule_revision: 0 }));
  for (const value of [{ ...input(), csrf: "not a body field" }, { ...input(), expected_revision: 0 }, { ...input(), expected_schedule_revision: -1 }, { ...input(), expected_schedule_revision: 0.5 }, { ...input(), interval: "monthly" }, { ...input(), enabled: "true" }]) assert.equal(api.validBackupScheduleInput(value), false);
});
test("GET uses existing private fetch controls and rejects foreign site responses", async () => {
  await mockFetch(async (url, options) => {
    assert.equal(url, `/api/v1/sites/${siteId}/backup-schedule`); assert.equal(options.method, "GET"); assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store"); assert(options.signal instanceof AbortSignal); assert.equal(options.body, undefined); assert.equal(options.headers["X-CSRF-Token"], undefined);
    return response(envelope());
  }, async () => assert.equal((await api.getBackupSchedule(siteId)).schedule.site_id, siteId));
  await mockFetch(async () => response(envelope({ ...schedule(), site_id: "b".repeat(32) })), async () => await assert.rejects(api.getBackupSchedule(siteId), e => e.code === "invalid_response"));
});
test("PUT keeps CSRF in a header, sends exact revision body and requires a confirmed advance", async () => {
  const saved = { ...schedule(), revision: 2, interval: "weekly", enabled: false };
  await mockFetch(async (url, options) => {
    assert.equal(url, `/api/v1/sites/${siteId}/backup-schedule`); assert.equal(options.method, "PUT"); assert.equal(options.headers["X-CSRF-Token"], "synthetic-csrf"); assert.equal(options.credentials, "same-origin"); assert.deepEqual(JSON.parse(options.body), input()); assert.equal(url.includes("synthetic-csrf"), false);
    return response(envelope(saved));
  }, async () => assert.equal((await api.putBackupSchedule(siteId, input(), "synthetic-csrf")).schedule.revision, 2));
  for (const invalid of [null, { ...saved, revision: 1 }, { ...saved, site_id: "b".repeat(32) }, { ...saved, enabled: true }, { ...saved, interval: "hourly" }]) await mockFetch(async () => response(envelope(invalid)), async () => await assert.rejects(api.putBackupSchedule(siteId, input(), "synthetic-csrf"), e => e.code === "invalid_response"));
});
test("invalid outbound inputs are rejected before fetch", () => {
  assert.throws(() => api.getBackupSchedule("bad")); assert.throws(() => api.putBackupSchedule(siteId, input(), "")); assert.throws(() => api.putBackupSchedule(siteId, { ...input(), extra: true }, "synthetic-csrf"));
});
test("conflict, expiry, unavailable and malformed responses never become success", async () => {
  for (const status of [400, 401, 403, 409, 422, 503]) await mockFetch(async () => response({ error: "request_failed" }, status), async () => await assert.rejects(api.putBackupSchedule(siteId, input(), "synthetic-csrf"), e => e.status === status));
  await mockFetch(async () => new Response('{"schedule":'), async () => await assert.rejects(api.getBackupSchedule(siteId), e => e.code === "invalid_response"));
  assert.match(api.backupScheduleError({}), /could not be confirmed/);
});
