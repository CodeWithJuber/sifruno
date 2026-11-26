// Contract checks use synthetic sessions and fetch responses; no server/state access.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./access-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL))));
const item = (current = true, letter = "a") => ({ id: letter.repeat(32), created_at: "2026-10-05T10:00:00Z", expires_at: "2026-10-05T22:00:00Z", current, kept_signed_in: false });
const kept = () => ({ ...item(false, "c"), expires_at: "2026-10-12T10:00:00Z", kept_signed_in: true });
const inventory = () => ({ items: [item(), item(false, "b"), kept()], capacity: 128, idle_seconds: 1800, kept_idle_seconds: 86400 });

test("strict bounded inventory requires unique public handles and one current session", () => {
  assert(api.validAccessInventory(inventory()));
  for (const change of [
    (v) => { v.items = []; }, (v) => { v.items[0].current = false; },
    (v) => { v.items[1].current = true; }, (v) => { v.items[1].id = v.items[0].id; },
    (v) => { v.items[1].id = "cookie-token"; }, (v) => { v.items[1].id = "B".repeat(32); },
    (v) => { v.capacity = 129; }, (v) => { v.idle_seconds = 900; }, (v) => { v.kept_idle_seconds = 1800; }, (v) => { delete v.kept_idle_seconds; v.lifetime_seconds = 900; },
    (v) => { v.extra = true; }, (v) => { v.items[0].device = "invented"; },
    (v) => { v.items = Array.from({ length: 129 }, (_, i) => ({ ...item(i === 0), id: i.toString(16).padStart(32, "0") })); },
  ]) { const value = inventory(); change(value); assert.equal(api.validAccessInventory(value), false); }
});
test("session timestamps and flag fail closed", () => {
  for (const change of [
    (v) => { v.created_at = "yesterday"; }, (v) => { v.expires_at = v.created_at; },
    (v) => { v.expires_at = "2026-10-04T10:15:00Z"; }, (v) => { v.current = "true"; },
    (v) => { delete v.id; }, (v) => { v.expires_at = "2026-99-99T10:15:00Z"; },
  ]) { const value = item(); change(value); assert.equal(api.validAccessSession(value), false); }
});
test("exact 12-hour or kept 7-day limit and canonical UTC calendar timestamps required", () => {
  assert(api.validAccessSession({ ...item(), created_at: "2024-02-29T23:50:00Z", expires_at: "2024-03-01T11:50:00Z" }));
  assert(api.validAccessSession(kept()));
  assert.equal(api.validAccessSession({ ...kept(), kept_signed_in: false }), false);
  assert.equal(api.validAccessSession({ ...item(), kept_signed_in: true }), false);
  assert.equal(api.validAccessSession({ ...item(), kept_signed_in: "no" }), false);
  for (const change of [
    (v) => { v.expires_at = "2026-10-05T21:59:59Z"; }, (v) => { v.expires_at = "2026-10-05T22:00:01Z"; },
    (v) => { v.created_at = "2026-02-30T10:00:00Z"; v.expires_at = "2026-02-30T22:00:00Z"; },
    (v) => { v.created_at = "2026-02-29T10:00:00Z"; v.expires_at = "2026-02-29T22:00:00Z"; },
    (v) => { v.created_at = "2026-10-05T24:00:00Z"; v.expires_at = "2026-10-06T12:00:00Z"; },
    (v) => { v.created_at = "2026-10-05T10:00:00+00:00"; }, (v) => { v.expires_at = "2026-10-05T22:00:00.000Z"; },
  ]) { const value = item(); change(value); assert.equal(api.validAccessSession(value), false); }
});
test("revocation result bounds and exact fields", () => {
  for (const revoked_count of [0, 1, 127]) assert(api.validRevocation({ revoked_count }));
  for (const revoked_count of [-1, 128, 0.5, "1", null]) assert.equal(api.validRevocation({ revoked_count }), false);
  assert.equal(api.validRevocation({ revoked_count: 1, extra: true }), false);
});

test("same-origin inventory and POST csrf/body contracts use fixed endpoints", async () => {
  const calls = [], original = globalThis.fetch;
  globalThis.fetch = async (url, options) => { calls.push({ url, options }); return Response.json(url.endsWith("/sessions") ? inventory() : { revoked_count: 1 }); };
  try {
    await api.getAccessInventory(); await api.revokeAccessSession("b".repeat(32), "fixture-csrf"); await api.revokeOtherAccessSessions("fixture-csrf");
    assert.deepEqual(calls.map((call) => call.url), ["/api/v1/session/sessions", `/api/v1/session/sessions/${"b".repeat(32)}/revoke`, "/api/v1/session/revoke-others"]);
    for (const { url, options } of calls) { assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store"); assert(!url.includes("fixture-csrf")); }
    for (const { options } of calls.slice(1)) { assert.equal(options.method, "POST"); assert.equal(options.body, "{}"); assert.equal(options.headers["X-CSRF-Token"], "fixture-csrf"); }
    assert.equal(calls[0].options.method, "GET"); assert.equal(calls[0].options.headers["X-CSRF-Token"], undefined);
  } finally { globalThis.fetch = original; }
});
test("bad management handle never reaches fetch, single revoke must confirm exactly one", async () => {
  const original = globalThis.fetch; let calls = 0;
  globalThis.fetch = async () => { ++calls; return Response.json({ revoked_count: 0 }); };
  try {
    assert.throws(() => api.revokeAccessSession("../cookie", "fixture-csrf")); assert.equal(calls, 0);
    await assert.rejects(api.revokeAccessSession("b".repeat(32), "fixture-csrf")); assert.equal(calls, 1);
  } finally { globalThis.fetch = original; }
});
test("session check accepts signed-out401; login/logout use existingDTO and bodies", async () => {
  const original = globalThis.fetch, calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return url.endsWith("/login") ? Response.json({ authenticated: true, csrf_token: "fixture-csrf", expires_at: item().expires_at }) : Response.json({ authenticated: false }, { status: url.endsWith("/logout") ? 200 : 401 });
  };
  try {
    assert.deepEqual(await api.getAccessSession(), { authenticated: false });
    assert.equal((await api.loginAccessSession("fixture-key")).authenticated, true);
    assert.deepEqual(await api.logoutAccessSession("fixture-csrf"), { authenticated: false });
    assert.equal(calls[1].options.body, '{"access_key":"fixture-key"}'); assert.equal(calls[2].options.body, "{}");
    assert(calls.every(({ url }) => !url.includes("fixture-key") && !url.includes("fixture-csrf")));
  } finally { globalThis.fetch = original; }
});
test("Access failures describe revoked, stale and current-session responses", async () => {
  const original = globalThis.fetch;
  try {
    for (const [status, expected] of [[401, /expired or was revoked/], [403, /origin was rejected/], [404, /already revoked/], [409, /Sign out locally/]]) {
      globalThis.fetch = async () => Response.json({ error: "fixture_failure" }, { status });
      await assert.rejects(api.getAccessInventory(), (failure) => { assert.match(api.accessError(failure), expected); return true; });
    }
  } finally { globalThis.fetch = original; }
});
