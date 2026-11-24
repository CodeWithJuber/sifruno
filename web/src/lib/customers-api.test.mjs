// Customers page client checks with synthetic answers; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const api = await import(moduleURL(readFileSync(new URL("./customers-api.ts", import.meta.url), "utf8")));

const siteA = "a".repeat(32);
const siteB = "b".repeat(32);
// A synthetic link secret in the right shape; not a credential for any server.
const secret = "S".repeat(43);
const login = (overrides = {}) => ({ username: "alice", websites: [siteA], disabled: false, setup: "pending", setup_expires_at: "2026-11-25T10:00:00Z", created_at: "2026-11-24T10:00:00Z", ...overrides });
const session = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-24T10:15:00Z", role: "admin" };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

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

test("the checks mirror the server", () => {
  for (const ok of ["alice", "bob.smith", "c-d_e", "x".repeat(32)]) assert.equal(api.checkUsername(ok), undefined, ok);
  for (const bad of ["", "al", "Alice", "1alice", "x".repeat(33), "ali ce", "alice/"]) assert.equal(typeof api.checkUsername(bad), "string", bad);
  assert.match(api.checkWebsites([]), /at least one/);
  assert.match(api.checkWebsites(Array.from({ length: 65 }, () => siteA)), /at most 64/);
  assert.match(api.checkWebsites(["site-1"]), /from the list/);
  assert.equal(api.checkWebsites([siteA, siteB]), undefined);
});

test("a setup link's secret is read from the address's fragment only", () => {
  assert.equal(api.linkSecret(`#${secret}`), secret);
  assert.equal(api.linkSecret(secret), secret);
  for (const bad of ["", "#", `#${secret}x`, "#short", `#${"S".repeat(42)}=`]) assert.equal(api.linkSecret(bad), undefined, bad);
  assert.equal(api.setupLinkURL(`/setup#${secret}`, "http://127.0.0.1:8080"), `http://127.0.0.1:8080/setup#${secret}`);
  assert.equal(api.setupLinkURL(`https://panel.example.com:2083/setup#${secret}`, "http://127.0.0.1:8080"), `https://panel.example.com:2083/setup#${secret}`);
});

test("answers are read strictly", () => {
  assert.deepEqual(api.parseCustomer(login()), login());
  assert.deepEqual(api.parseCustomer(login({ setup: "done", setup_expires_at: null })), login({ setup: "done", setup_expires_at: null }));
  for (const bad of [login({ username: "Alice" }), login({ websites: ["x"] }), login({ websites: [siteA, siteA] }), login({ setup: "maybe" }), login({ setup: "done" }), login({ setup_expires_at: null }), { ...login(), extra: 1 }, null, []]) {
    assert.equal(api.parseCustomer(bad), undefined, JSON.stringify(bad));
  }
  assert.ok(api.parseSetupLink({ ...login(), setup_link: `/setup#${secret}` }));
  assert.ok(api.parseSetupLink({ ...login(), setup_link: `https://panel.example.com/setup#${secret}` }));
  assert.equal(api.parseSetupLink({ ...login(), setup_link: `/elsewhere#${secret}` }), undefined);
  assert.equal(api.parseSetupLink({ ...login(), setup_link: "/setup#short" }), undefined);
  assert.equal(api.parseCustomerList({ items: [login(), login()], capacity: 500 }), undefined);
  assert.equal(api.parseCustomerList({ items: [login()], capacity: 500 }).items.length, 1);
});

test("the state label names what the admin should do", () => {
  assert.deepEqual(api.loginState(login({ disabled: true })), { label: "Turned off", tone: "off" });
  assert.deepEqual(api.loginState(login({ setup: "done", setup_expires_at: null })), { label: "Ready", tone: "ready" });
  assert.deepEqual(api.loginState(login()), { label: "Waiting for setup", tone: "waiting" });
  assert.deepEqual(api.loginState(login({ setup: "expired" })), { label: "Setup link expired", tone: "attention" });
});

test("changes send the session's CSRF token and only their own fields", async () => {
  const { calls, mock } = server((url) => url.endsWith("/setup-link") || url === "/api/v1/session/customers" ? json({ ...login(), setup_link: `/setup#${secret}` }) : json(login()));
  await withFetch(mock, async () => {
    await api.createCustomer("alice", [siteA]);
    await api.setCustomerWebsites("alice", [siteA, siteB]);
    await api.setCustomerDisabled("alice", true);
    await api.newSetupLink("alice");
    await api.removeCustomer("alice");
  });
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [
    ["POST", "/api/v1/session/customers", { username: "alice", websites: [siteA] }],
    ["POST", "/api/v1/session/customers/alice/websites", { websites: [siteA, siteB] }],
    ["POST", "/api/v1/session/customers/alice/state", { disabled: true }],
    ["POST", "/api/v1/session/customers/alice/setup-link", {}],
    ["POST", "/api/v1/session/customers/alice/delete", {}],
  ]);
  for (const call of calls) assert.equal(call.headers["X-CSRF-Token"], session.csrf_token);
});

test("a refused change says what, why and what next, without the link", async () => {
  const { mock } = server(() => json({ error: "username_taken", detail: "Someone already signs in with this username. Choose another one." }, 409));
  await withFetch(mock, async () => {
    await assert.rejects(api.createCustomer("alice", [siteA]), (error) => {
      assert.equal(error.message, "The login was not made.");
      assert.match(error.why, /already signs in/);
      assert.match(error.next, /try again/);
      assert.match(error.technical, /HTTP 409 \(username_taken\)/);
      return true;
    });
  });
  // Bad values are not sent at all.
  const quiet = server(() => { throw new Error("must not be called"); });
  await withFetch(quiet.mock, async () => {
    await assert.rejects(api.createCustomer("Alice", [siteA]), (error) => error.status === 422 && /lowercase/.test(error.why));
    await assert.rejects(api.setCustomerWebsites("alice", []), (error) => error.status === 422);
  });
  assert.equal(quiet.calls.length, 0);
  // An answer that does not match is not trusted.
  const odd = server(() => json({ ...login(), setup_link: "https://evil.example/" }));
  await withFetch(odd.mock, async () => {
    await assert.rejects(api.newSetupLink("alice"), (error) => /not in the form/.test(error.why));
  });
});
