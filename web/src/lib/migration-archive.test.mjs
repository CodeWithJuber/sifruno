// A cPanel backup file for Move a website here: the answer's shape and the chosen file's checks; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const archive = await import(moduleURL(readFileSync(new URL("./migration-archive.ts", import.meta.url), "utf8")));

const answer = (change = {}) => ({
  source: {
    id: "d".repeat(32), via: "archive", expires_at: "2026-11-28T10:00:00Z", host: "", port: 0, key_line: "", install_command: "", host_keys: [], pinned_fingerprint: "",
    archive: { user: "shopone", domain: "shop.example.com", databases: ["shopone_wp"], bytes: 4096, home_bytes: 2048, home: "/home/shopone",
      not_carried: [{ part: "mail", text: "Email accounts and their mail stay with the old host." }, { part: "file", text: "A link to a place outside the website's home was not copied.", where: "public_html/x" }] },
    ...change,
  },
});

test("the server's answer for an uploaded backup file is read", () => {
  const s = archive.parseArchiveSource(answer());
  assert.equal(s.archive.user, "shopone");
  assert.deepEqual(s.archive.databases, ["shopone_wp"]);
  assert.deepEqual(s.archive.not_carried[0], { part: "mail", text: "Email accounts and their mail stay with the old host.", where: "" });
  assert.equal(s.archive.not_carried[1].where, "public_html/x");
});

test("an answer that is not a backup file's source is refused", () => {
  assert.equal(archive.parseArchiveSource(answer({ via: "whm" })), undefined);
  assert.equal(archive.parseArchiveSource(answer({ id: "not an id" })), undefined);
  assert.equal(archive.parseArchiveSource(answer({ archive: { user: "Shop One", domain: "x", databases: [], bytes: 1, home_bytes: 1, not_carried: [] } })), undefined);
  assert.equal(archive.parseArchiveSource(answer({ archive: { user: "shopone", domain: "shop.example.com", databases: [], bytes: -1, home_bytes: 1, not_carried: [] } })), undefined);
  assert.equal(archive.parseArchiveSource(answer({ archive: { user: "shopone", domain: "shop.example.com", databases: [], bytes: 1, home_bytes: 1, not_carried: [{ part: "x" }] } })), undefined);
  assert.equal(archive.parseArchiveSource({}), undefined);
});

test("a chosen file is checked before it is sent", () => {
  assert.equal(archive.checkArchiveFile({ name: "cpmove-shopone.tar.gz", size: 10 }), undefined);
  assert.equal(archive.checkArchiveFile({ name: "backup-11.26.2026_10-00-00_shopone.tar.gz", size: 10 }), undefined);
  assert.equal(archive.checkArchiveFile({ name: "shopone.TGZ", size: 10 }), undefined);
  assert.match(archive.checkArchiveFile(undefined), /Choose the backup file/);
  assert.match(archive.checkArchiveFile({ name: "site.zip", size: 10 }), /\.tar\.gz file cPanel's backup made/);
  assert.match(archive.checkArchiveFile({ name: "cpmove-shopone.tar.gz", size: 0 }), /empty/);
  assert.match(archive.checkArchiveFile({ name: "cpmove-shopone.tar.gz", size: archive.maxArchiveBytes + 1 }), /32 GiB/);
});

test("sizes read as a person reads them", () => {
  assert.equal(archive.sizeText(10), "1 KB");
  assert.equal(archive.sizeText(5 * 1024 * 1024), "5.0 MB");
  assert.equal(archive.sizeText(3 * 1024 ** 3), "3.0 GB");
});
