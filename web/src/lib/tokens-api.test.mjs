// API tokens page client checks with synthetic sessions and fetch responses; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./tokens-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL))));

const id = "0123456789abcdef0123456789abcdef";
// A synthetic token in the right shape; not a credential for any server.
const secret = `sfr_AbCdEf${"x".repeat(37)}`;
const token = (overrides = {}) => ({ id, name: "WHMCS", prefix: "sfr_AbCdEf", created_at: "2026-11-24T10:00:00Z", expires_at: "2027-02-22T10:00:00Z", last_used_at: null, expired: false, ...overrides });
const session = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-24T10:15:00Z" };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

async function withFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

// Answers the session read, then hands every other request to answer.
function server(answer) {
  const calls = [];
  const mock = async (url, init) => {
    if (url === "/api/v1/session") return json(session);
    calls.push({ url, method: init.method, headers: init.headers, credentials: init.credentials, body: init.body === undefined ? undefined : JSON.parse(init.body) });
    return answer(url, init);
  };
  return { calls, mock };
}

test("the name check mirrors the server", () => {
  for (const ok of ["WHMCS", "Billing (prod)", "a", "x".repeat(64), "Ünïcode name", "名前"]) assert.equal(api.checkTokenName(ok), undefined, ok);
  for (const bad of ["", "   ", " WHMCS", "WHMCS ", "x".repeat(65), "line\nbreak", "tab\there", "right‮left", "zero​width"]) {
    assert.equal(typeof api.checkTokenName(bad), "string", JSON.stringify(bad));
  }
  assert.match(api.checkTokenName(""), /such as WHMCS/);
  assert.match(api.checkTokenName(" x"), /spaces at the start and end/);
  for (const days of [1, 7, 90, 365]) assert.equal(api.checkExpiryDays(days), undefined);
  for (const days of [0, 366, -1, 1.5, Number.NaN]) assert.match(api.checkExpiryDays(days), /1 to 365 days/);
  assert.deepEqual([...api.expiryChoices], [7, 30, 90, 180, 365]);
  assert.equal(api.defaultExpiryDays, 90);
  assert.equal(api.expiresOn(90, new Date("2026-11-24T10:00:00Z")).toISOString(), "2027-02-22T10:00:00.000Z");
});

test("answers are read strictly and a listed token never carries a secret", () => {
  assert.deepEqual(api.parseToken(token()), token());
  assert.deepEqual(api.parseToken(token({ last_used_at: "2026-11-25T08:00:00Z", expired: true })), token({ last_used_at: "2026-11-25T08:00:00Z", expired: true }));
  for (const change of [
    (v) => { v.token = secret; }, (v) => { v.hash = "abc"; }, (v) => { delete v.expired; },
    (v) => { v.id = "../x"; }, (v) => { v.prefix = "sfr_short"; }, (v) => { v.prefix = "abc_AbCdEf"; },
    (v) => { v.created_at = "yesterday"; }, (v) => { v.expires_at = v.created_at; }, (v) => { v.last_used_at = ""; },
    (v) => { v.expired = "false"; }, (v) => { v.name = " padded"; },
  ]) { const value = token(); change(value); assert.equal(api.parseToken(value), undefined); }

  assert.equal(api.parseCreatedToken({ ...token(), token: secret }).token, secret);
  assert.equal(api.parseCreatedToken({ ...token(), token: secret.replace("AbCdEf", "ZZZZZZ") }), undefined, "the token must start with its prefix");
  assert.equal(api.parseCreatedToken({ ...token(), token: "sfr_short" }), undefined);
  assert.equal(api.parseCreatedToken(token()), undefined);

  const list = { items: [token(), token({ id: "f".repeat(32), name: "Backups" })], capacity: 32 };
  assert.equal(api.parseTokenList(list).items.length, 2);
  assert.equal(api.parseTokenList({ items: [], capacity: 32 }).items.length, 0);
  assert.equal(api.parseTokenList({ ...list, extra: 1 }), undefined);
  assert.equal(api.parseTokenList({ items: [token(), token()], capacity: 32 }), undefined, "IDs are unique");
  assert.equal(api.parseTokenList({ items: [token()], capacity: 0 }), undefined);
  assert.equal(api.parseTokenList({ items: [{ ...token(), token: secret }], capacity: 32 }), undefined);
});

test("create sends exactly the name and expiry with the session's CSRF token", async () => {
  const { calls, mock } = server(() => json({ ...token({ name: "Billing" }), token: secret }));
  await withFetch(mock, async () => {
    const created = await api.createApiToken("Billing", 30);
    assert.equal(created.token, secret);
    assert.equal(created.name, "Billing");
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/v1/session/tokens");
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].credentials, "same-origin");
  assert.deepEqual(calls[0].body, { name: "Billing", expires_in_days: 30 });
  assert.equal(calls[0].headers["X-CSRF-Token"], session.csrf_token);
  assert.equal(calls[0].headers.Authorization, undefined);
});

test("a value that fails the panel's checks is never sent", async () => {
  const { calls, mock } = server(() => json({}));
  await withFetch(mock, async () => {
    await assert.rejects(api.createApiToken(" padded", 90), (error) => error.status === 422 && /spaces/.test(error.why));
    await assert.rejects(api.createApiToken("WHMCS", 400), (error) => error.status === 422 && /1 to 365/.test(error.why));
    await assert.rejects(api.revokeApiToken("../../session/logout"), (error) => error.status === 404);
  });
  assert.equal(calls.length, 0);
});

test("list and revoke use fixed addresses; revoke must answer for the same token", async () => {
  const { calls, mock } = server((url) => url.endsWith("/revoke") ? json(token()) : json({ items: [token()], capacity: 32 }));
  await withFetch(mock, async () => {
    assert.equal((await api.listApiTokens()).items[0].name, "WHMCS");
    assert.equal((await api.revokeApiToken(id)).id, id);
  });
  assert.deepEqual(calls.map((call) => `${call.method} ${call.url}`), ["GET /api/v1/session/tokens", `POST /api/v1/session/tokens/${id}/revoke`]);
  assert.deepEqual(calls[1].body, {});
  assert.equal(calls[0].headers["X-CSRF-Token"], undefined);

  const other = server(() => json(token({ id: "e".repeat(32) })));
  await withFetch(other.mock, async () => {
    await assert.rejects(api.revokeApiToken(id), (error) => error.status === 0 && /Refresh the list/.test(error.next));
  });
});

test("errors say what happened, why and what to do next, and never echo a token", async () => {
  const cases = [
    [401, { error: "unauthorized" }, /sign-in has ended/i, /Sign in again/],
    [403, { error: "csrf_invalid" }, /origin did not match/, /Reload the page/],
    [404, { error: "token_not_found" }, /revoked already/, /Refresh the list/],
    [409, { error: "token_name_taken", detail: "Another token already has this name. Choose a different name." }, /already has this name/, /different name/],
    [409, { error: "token_limit" }, /at most 32/, /Revoke a token/],
    [422, { error: "invalid_token_name", detail: "Use a name of at most 64 characters." }, /at most 64/, /Fix the marked value/],
    [429, { error: "rate_limited" }, /Too many/, /Wait a minute/],
    [503, { error: "operator_unavailable" }, /could not save/, /check the panel's disk/],
  ];
  for (const [status, body, why, next] of cases) {
    const { mock } = server(() => json({ ...body, title: "Problem", status, authenticated: false }, status));
    await withFetch(mock, async () => {
      await assert.rejects(api.createApiToken("Billing", 90), (error) => {
        assert(error instanceof api.TokensApiError);
        assert.equal(error.message, "The token was not created.");
        assert.match(error.why, why); assert.match(error.next, next);
        assert.match(error.technical, new RegExp(`POST /api/v1/session/tokens returned HTTP ${status}`));
        assert(!`${error.message}${error.why}${error.next}${error.technical}`.includes("sfr_"));
        return true;
      });
    });
  }
  await withFetch(async () => json({ authenticated: false }, 401), async () => {
    await assert.rejects(api.listApiTokens(), (error) => error.status === 401 && /see the tokens/.test(error.next));
  });
  await withFetch(async () => { throw new TypeError("offline"); }, async () => {
    await assert.rejects(api.listApiTokens(), (error) => error.status === 0 && /could not reach its server/.test(error.why));
  });
  await withFetch(async () => json({ items: [{ ...token(), token: secret }], capacity: 32 }), async () => {
    await assert.rejects(api.listApiTokens(), (error) => /not in the form the panel expects/.test(error.why));
  });
});
