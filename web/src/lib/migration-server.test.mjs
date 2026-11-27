// Another Linux server for Move a website here: the answer's shape and the checks on what the person types; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const server = await import(moduleURL(readFileSync(new URL("./migration-server.ts", import.meta.url), "utf8")));

const site = (change = {}) => ({
  domain: "blog.example.com", aliases: [], www: true, server: "nginx", where: "/etc/nginx/conf.d/blog.conf line 1", doc_root: "/var/www/blog", owner: "nginx", account: "blog",
  php_source: "php8.2-fpm", php: "8.2", wordpress: true, database: "wordpress", certificate: false, movable: true, refused: [],
  not_carried: [{ part: "mail", text: "Email, DNS and FTP accounts stay on the old server." }, { part: "rule", text: "add_header: Extra response headers are not carried.", where: "/etc/nginx/conf.d/blog.conf line 9" }],
  ...change,
});

test("the server's websites are read", () => {
  const sites = server.parseSites({ sites: [site(), site({ domain: "app.example.com", movable: false, account: "", owner: "", doc_root: "", refused: [{ part: "rule", text: "proxy_pass: not converted.", where: "/etc/nginx/conf.d/app.conf line 4" }] })] });
  assert.equal(sites.length, 2);
  assert.equal(sites[0].database, "wordpress");
  assert.deepEqual(sites[0].not_carried[0], { part: "mail", text: "Email, DNS and FTP accounts stay on the old server.", where: "" });
  assert.equal(sites[1].refused[0].where, "/etc/nginx/conf.d/app.conf line 4");
  assert.equal(server.serverName(sites[0]), "nginx");
  assert.equal(server.serverName(site({ server: "apache" })), "Apache");
});

test("an answer that is not the server's websites is refused", () => {
  assert.equal(server.parseSites({}), undefined);
  assert.equal(server.parseSites({ sites: [site({ server: "iis" })] }), undefined);
  assert.equal(server.parseSites({ sites: [site({ movable: "yes" })] }), undefined);
  assert.equal(server.parseSites({ sites: [site({ refused: [{ part: "rule" }] })] }), undefined);
  assert.equal(server.parseSites({ sites: [site({ owner: "x".repeat(33) })] }), undefined);
});

test("the account name, password and key are checked before they are sent", () => {
  assert.equal(server.checkAccountName("blog"), undefined);
  assert.match(server.checkAccountName(""), /Enter/);
  assert.match(server.checkAccountName("Blog"), /lowercase/);
  assert.match(server.checkAccountName("1blog"), /starting with a letter/);
  assert.match(server.checkAccountName("ab"), /3 to 32/);
  assert.equal(server.checkRootPassword("correct horse"), undefined);
  assert.match(server.checkRootPassword("a\nb"), /line breaks/);
  assert.match(server.checkRootPassword(""), /Enter/);
  const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
  assert.equal(server.checkPrivateKey(key), undefined);
  assert.equal(server.checkPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"), undefined);
  assert.match(server.checkPrivateKey("ssh-ed25519 AAAAC3Nza root@x"), /public key/);
  assert.match(server.checkPrivateKey(""), /Paste/);
});
