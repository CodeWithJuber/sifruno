// Passkey answers from the server are checked strictly, and the browser
// helpers turn base64url and WebAuthn objects back and forth. Synthetic
// values only; no server or browser state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const auth = await import(moduleURL(readFileSync(new URL("./auth-api.ts", import.meta.url), "utf8")));
const passkey = await import(moduleURL(readFileSync(new URL("./passkey.ts", import.meta.url), "utf8")));

const item = (id = "a") => ({ id: id.repeat(32), credential_id: "AQIDBA", name: "Laptop", created_at: "2026-11-25T10:00:00Z", synced: true, blocked: false });
const list = () => ({ items: [item(), { ...item("b"), last_used_at: "2026-11-25T11:00:00Z" }], capacity: 10, available: true, address: "https://panel.example.com:8443", rp_id: "panel.example.com", user_id: "A".repeat(43) });

test("a passkey list is accepted only as the server sends it", () => {
  assert(auth.validPasskeyList(list()));
  assert(auth.validPasskeyList({ items: [], capacity: 10, available: false, detail: "Passkeys need the panel's name." }));
  for (const change of [
    (v) => { v.capacity = 11; }, (v) => { v.items[1].id = v.items[0].id; }, (v) => { v.items[0].id = "A".repeat(32); },
    (v) => { v.items[0].credential_id = "a+b/"; }, (v) => { v.items[0].credential_id = "AQIDB"; }, (v) => { v.items[0].name = ""; },
    (v) => { v.items[0].name = " padded"; }, (v) => { v.items[0].name = "x".repeat(65); }, (v) => { v.items[0].created_at = "yesterday"; },
    (v) => { v.items[0].synced = "yes"; }, (v) => { v.items[0].private_key = "x"; }, (v) => { v.extra = true; },
    (v) => { v.user_id = "not base64url!"; }, (v) => { v.address = "http://panel.example.com"; }, (v) => { v.available = "true"; },
    (v) => { v.items = Array.from({ length: 11 }, (_, i) => item(i.toString(16))); },
  ]) { const value = list(); change(value); assert.equal(auth.validPasskeyList(value), false); }
});

test("ceremonies and creation options need a challenge, a relying party and a token", () => {
  const ceremony = { ceremony: "C".repeat(43), options: { challenge: "Y2hhbGxlbmdlLWJ5dGVzLTMyLWxvbmctZW5vdWdo", rpId: "panel.example.com", userVerification: "required" }, expires_at: "2026-11-25T10:05:00Z" };
  assert(auth.validPasskeyCeremony(ceremony));
  for (const change of [(v) => { v.ceremony = "short"; }, (v) => { delete v.options.rpId; }, (v) => { v.options.challenge = "!"; }, (v) => { v.expires_at = "soon"; }]) {
    const value = structuredClone(ceremony); change(value); assert.equal(auth.validPasskeyCeremony(value), false);
  }
  const creation = { options: { challenge: "Y2hhbGxlbmdl", rp: { id: "panel.example.com", name: "Sifruno panel" }, user: { id: "A".repeat(43), name: "admin", displayName: "admin" } }, expires_at: "2026-11-25T10:05:00Z" };
  assert(auth.validPasskeyCreation(creation));
  for (const change of [(v) => { delete v.options.rp; }, (v) => { v.options.user.id = "x".repeat(90); }, (v) => { delete v.expires_at; }]) {
    const value = structuredClone(creation); change(value); assert.equal(auth.validPasskeyCreation(value), false);
  }
  assert(auth.validPasskeyStatus({ available: false, detail: "Passkeys need the panel's name.", address: "https://panel.example.com:8443" }));
  assert.equal(auth.validPasskeyStatus({ available: false, address: "javascript:alert(1)" }), false);
});

test("removing refuses an ID that is not a passkey handle before any request", async () => {
  await assert.rejects(auth.removePasskey("C".repeat(43), "../tokens"), (e) => e instanceof auth.AuthError && e.code === "invalid_request");
});

test("base64url round-trips bytes without padding", () => {
  for (const bytes of [[], [0], [251, 255], [1, 2, 3, 4, 5], Array.from({ length: 64 }, (_, i) => i * 4)]) {
    const encoded = passkey.toBase64url(new Uint8Array(bytes));
    assert.match(encoded, /^[A-Za-z0-9_-]*$/);
    assert.deepEqual([...new Uint8Array(passkey.fromBase64url(encoded))], bytes);
  }
  assert.throws(() => passkey.fromBase64url("a+b"));
  assert.throws(() => passkey.fromBase64url("abcde"));
});

test("without the browser's JSON helpers, options and answers are converted by hand", () => {
  const request = passkey.requestOptions({ challenge: "AQID", rpId: "panel.example.com", allowCredentials: [{ type: "public-key", id: "BAUG" }] });
  assert.deepEqual([...new Uint8Array(request.challenge)], [1, 2, 3]);
  assert.deepEqual([...new Uint8Array(request.allowCredentials[0].id)], [4, 5, 6]);
  const creation = passkey.creationOptions({ challenge: "AQID", rp: { id: "panel.example.com" }, user: { id: "BwgJ", name: "admin" }, excludeCredentials: [{ type: "public-key", id: "CgsM" }] });
  assert.deepEqual([...new Uint8Array(creation.user.id)], [7, 8, 9]);
  assert.deepEqual([...new Uint8Array(creation.excludeCredentials[0].id)], [10, 11, 12]);
  const buf = (...b) => new Uint8Array(b).buffer;
  const json = passkey.credentialJSON({ id: "AQ", rawId: buf(1), type: "public-key", authenticatorAttachment: "platform", getClientExtensionResults: () => ({}),
    response: { clientDataJSON: buf(2), authenticatorData: buf(3), signature: buf(4), userHandle: buf(5) } });
  assert.deepEqual(json, { id: "AQ", rawId: "AQ", type: "public-key", authenticatorAttachment: "platform", clientExtensionResults: {}, response: { clientDataJSON: "Ag", authenticatorData: "Aw", signature: "BA", userHandle: "BQ" } });
  const made = passkey.credentialJSON({ id: "AQ", rawId: buf(1), type: "public-key", response: { clientDataJSON: buf(2), attestationObject: buf(6), getTransports: () => ["internal"] } });
  assert.deepEqual(made.response, { clientDataJSON: "Ag", attestationObject: "Bg", transports: ["internal"] });
});

test("the browser's errors become plain sentences, and a cancelled sign-in says nothing", () => {
  const error = (name) => Object.assign(new Error("x"), { name });
  assert.equal(passkey.passkeyBrowserProblem(error("NotAllowedError"), false), "");
  assert.match(passkey.passkeyBrowserProblem(error("NotAllowedError"), true), /Nothing was added/);
  assert.match(passkey.passkeyBrowserProblem(error("InvalidStateError"), true), /already holds a passkey/);
  assert.match(passkey.passkeyBrowserProblem(error("SecurityError"), false), /at its name over HTTPS/);
});
