// A website move's record: its shape checks and the words the page builds from it; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const record = await import(moduleURL(readFileSync(new URL("./migration-record.ts", import.meta.url), "utf8")));

const migration = (change = {}) => ({
  source: "c".repeat(32), source_host: "old.example.test", source_user: "shopone", tier: "native", php_source: "ea-php82", wordpress: true,
  databases: ["shopone_wp"], database_users: ["shopone_wpu"], tables: [], notes: [], verify: null, gate: "ready", accepted: null,
  address: "203.0.113.7", dns: [{ name: "shop.example.test", type: "A", value: "203.0.113.7" }], key_removed: true,
  activity: [{ at: "2026-11-26T10:00:00Z", actor: "admin", what: "Started moving the account shopone." }], ...change,
});

test("the certificate step's outcome is read, and the cutover says when https comes", () => {
  const copied = record.parseMigration(migration({ certificate: { copied: true, not_after: "2027-03-01T12:00:00Z", issuer: "Old CA" } }));
  assert.deepEqual(copied.certificate, { copied: true, not_after: "2027-03-01T12:00:00Z", issuer: "Old CA", why: "" });
  assert.equal(record.certificateNote(copied, "en-GB"),
    "The website already answers https on this server, with the certificate copied from the old server, valid until 1 Mar 2027. Once these records point here, the panel replaces it with a Let's Encrypt certificate before it runs out.");

  const refused = record.parseMigration(migration({ certificate: { copied: false, why: "The old server's certificate was not copied. It expired on 2026-10-01." } }));
  assert.equal(record.certificateNote(refused, "en-GB"),
    "The old server's certificate was not copied. It expired on 2026-10-01. Once these records point here, the panel gets the website's certificate by itself, usually within the hour, when certificates are set up on this server. Until then the website uses http.");

  // A move from before the step has no outcome: the general words.
  const older = record.parseMigration(migration());
  assert.equal(older.certificate, null);
  assert.equal(record.certificateNote(older, "en-GB"),
    "Once these records point here, the panel gets the website's certificate by itself, usually within the hour, when certificates are set up on this server. Until then the website uses http.");

  for (const bad of [
    { copied: "yes" },
    { copied: true, not_after: "soon" },
    { copied: true },
    { copied: false, why: 7 },
    { copied: true, not_after: "2027-03-01T12:00:00Z", issuer: "x".repeat(2000) },
  ]) assert.equal(record.parseMigration(migration({ certificate: bad })), undefined, JSON.stringify(bad));
});
