// Files client checks with synthetic answers and fetch responses; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./files-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL))));

const accountId = "0123456789abcdef0123456789abcdef";
const when = "2026-11-24T10:00:00.5Z";
const file = (change = {}) => ({ name: "index.php", type: "file", size: 12, mode: "0644", modified: when, version: "0123456789abcdef", ...change });
const folder = (change = {}) => ({ name: "wp-content", type: "folder", size: 0, mode: "0755", modified: when, ...change });
const session = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-24T10:15:00Z" };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

async function withFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

test("names and paths follow the server's rules", () => {
  for (const good of ["index.php", ".htaccess", "a b", "café.txt", "...", "x".repeat(255)]) assert.equal(api.checkName(good), undefined, good);
  for (const bad of ["", ".", "..", "a/b", "a\nb", "a\u0000b", "a\u007fb", "a\u0085b", "x".repeat(256), "é".repeat(128), "\ud800x"]) assert.ok(api.checkName(bad), JSON.stringify(bad));
  assert.equal(api.validPath(""), true);
  assert.equal(api.validPath("public_html/wp-content/uploads"), true);
  for (const bad of ["/etc", "../x", "a//b", "a/", "a/./b", "a/../b", "a\u0000", Array(65).fill("a").join("/"), "a/".repeat(400) + "b"]) assert.equal(api.validPath(bad), false, bad);
  assert.equal(api.joinPath("", "public_html"), "public_html");
  assert.equal(api.joinPath("public_html", "index.php"), "public_html/index.php");
  assert.equal(api.parentPath("public_html/wp-content"), "public_html");
  assert.equal(api.parentPath("public_html"), "");
  assert.equal(api.baseName("public_html/index.php"), "index.php");
  assert.deepEqual(api.pathTrail("public_html/wp-content"), [{ name: "Home folder", path: "" }, { name: "public_html", path: "public_html" }, { name: "wp-content", path: "public_html/wp-content" }]);
  assert.equal(api.wellFormed("a😀b"), true);
  assert.equal(api.wellFormed("a\ud83db"), false);
  assert.equal(api.wellFormed("\ude00"), false);
});

test("sizes, modes and dates read plainly", () => {
  assert.equal(api.sizeLabel(0, "en"), "0 bytes");
  assert.equal(api.sizeLabel(1, "en"), "1 byte");
  assert.equal(api.sizeLabel(1536, "en"), "1.5 KB");
  assert.equal(api.sizeLabel(64 << 20, "en"), "64 MB");
  assert.equal(api.modeLabel("0644"), "rw-r--r--");
  assert.equal(api.modeLabel("0750"), "rwxr-x---");
  const p = api.permissionsOf("0640");
  assert.deepEqual(p.owner, { read: true, write: true, execute: false });
  assert.deepEqual(p.others, { read: false, write: false, execute: false });
  assert.equal(api.modeOf({ ...p, others: { read: true, write: false, execute: false } }), "0644");
  // setuid is shown, never set: permissions drop it.
  assert.equal(api.specialBits("4755"), true);
  assert.equal(api.modeOf(api.permissionsOf("4755")), "0755");
  assert.match(api.modifiedLabel(when, "en"), /2026/);
  assert.equal(api.modifiedLabel("not a date", "en"), "Unknown");
  const sorted = api.sortEntries([file({ name: "b.txt" }), folder({ name: "z" }), file({ name: "a10.txt" }), file({ name: "a9.txt" })], "en").map((e) => e.name);
  assert.deepEqual(sorted, ["z", "a9.txt", "a10.txt", "b.txt"]);
});

test("actions follow the entry and the site's state", () => {
  const all = api.actionsFor(file(), "public_html/index.php", true);
  assert.deepEqual(all, { open: false, edit: true, download: true, rename: true, permissions: true, remove: true });
  assert.equal(api.actionsFor(file({ size: api.maxTextBytes + 1 }), "a", true).edit, false);
  const link = api.actionsFor({ name: "shadow", type: "link", size: 0, mode: "0777", modified: when }, "shadow", true);
  assert.deepEqual(link, { open: false, edit: false, download: false, rename: true, permissions: false, remove: true });
  const readOnly = api.actionsFor(folder(), "public_html/wp-content", false);
  assert.deepEqual(readOnly, { open: true, edit: false, download: false, rename: false, permissions: false, remove: false });
  const own = api.actionsFor(folder({ name: "public_html" }), "public_html", true);
  assert.equal(own.remove || own.rename || own.permissions, false);
  // A folder the server reports locked (OpenLiteSpeed's .lsns) opens, and
  // nothing else.
  const lsns = api.actionsFor(folder({ name: ".lsns", locked: "OpenLiteSpeed's working folder." }), ".lsns", true);
  assert.deepEqual(lsns, { open: true, edit: false, download: false, rename: false, permissions: false, remove: false });
});

test("permissions read in words beside the mode", () => {
  assert.equal(api.modeWords("0644", "file"), "Owner can read and write; others can read");
  assert.equal(api.modeWords("0755", "folder"), "Owner can read, write and open; others can read and open");
  assert.equal(api.modeWords("0750", "folder"), "Owner can read, write and open; group can read and open; others have no access");
  assert.equal(api.modeWords("0600", "file"), "Owner can read and write; others have no access");
  assert.equal(api.modeWords("0700", "file"), "Owner can read, write and run; others have no access");
  assert.equal(api.modeWords("0444", "file"), "Owner can read; others can read");
  assert.equal(api.modeWords("0000", "file"), "No one has access");
  assert.equal(api.modeWords("0070", "folder"), "Owner has no access; group can read, write and open; others have no access");
  assert.equal(api.modeWords("0777", "link"), "Set by what the link points to");
});

test("answers outside the contract are refused", () => {
  assert.deepEqual(api.parseEntry(file()), file());
  assert.equal("extra" in api.parseEntry(file({ extra: 1 })), false);
  for (const bad of [file({ name: "../x" }), file({ name: "a/b" }), file({ type: "device" }), file({ size: -1 }), file({ size: 1.5 }), file({ mode: "644" }), file({ modified: "soon" }), file({ version: undefined }), file({ version: "XYZ" }), folder({ size: 4096 }), folder({ version: "0123456789abcdef" })]) {
    assert.equal(api.parseEntry(bad), undefined, JSON.stringify(bad));
  }
  // A lock's reason is one short line, kept as the server words it.
  assert.equal(api.parseEntry(folder({ name: ".lsns", locked: "OpenLiteSpeed's working folder." })).locked, "OpenLiteSpeed's working folder.");
  for (const locked of ["", 7, "x".repeat(301), "two\nlines"]) assert.equal(api.parseEntry(folder({ locked })), undefined, JSON.stringify(locked));
  assert.equal(api.parseFolder({ path: ".lsns", entries: [], skipped: 0, truncated: false, locked: "OpenLiteSpeed's working folder." }, ".lsns").locked, "OpenLiteSpeed's working folder.");
  const list = { $schema: "x", path: "public_html", entries: [file(), folder()], skipped: 1, truncated: false };
  assert.equal(api.parseFolder(list, "public_html").entries.length, 2);
  assert.equal("locked" in api.parseFolder(list, "public_html"), false);
  assert.equal(api.parseFolder(list, ""), undefined, "an answer about another folder");
  assert.equal(api.parseFolder({ ...list, entries: [file(), file()] }, "public_html"), undefined, "a name twice");
  assert.equal(api.parseFolder({ ...list, skipped: -1 }, "public_html"), undefined);
  const content = "<?php echo 'é';";
  const text = { path: "public_html/index.php", file: file({ size: new TextEncoder().encode(content).length }), content };
  assert.equal(api.parseFileText(text, "public_html/index.php").content, content);
  assert.equal(api.parseFileText({ ...text, file: file({ size: 3 }) }, "public_html/index.php"), undefined, "content and size disagree");
  assert.equal(api.parseFileText(text, "public_html/other.php"), undefined, "another file's content");
});

test("editor text is checked before it is sent", () => {
  assert.equal(api.checkText("<?php\necho 1;\n"), undefined);
  assert.ok(api.checkText("a\u0000b"));
  assert.ok(api.checkText("\ud800"));
  assert.ok(api.checkText("a".repeat(api.maxTextBytes + 1)));
});

test("a folder is listed with its path in the query, and refusals send nothing", async () => {
  const calls = [];
  await withFetch(async (url, init) => {
    calls.push([url, init.method]);
    return json({ path: "public_html/wp content", entries: [folder()], skipped: 0, truncated: false });
  }, async () => {
    const got = await api.listFolder(accountId, "public_html/wp content");
    assert.equal(got.entries[0].name, "wp-content");
    await assert.rejects(api.listFolder(accountId, "../etc"), (e) => e instanceof api.FilesApiError && e.status === 0 && /nothing was sent/.test(e.technical));
    await assert.rejects(api.listFolder("nope", ""), api.FilesApiError);
  });
  assert.deepEqual(calls, [[`/api/v1/websites/sites/${accountId}/files?path=public_html%2Fwp%20content`, "GET"]]);
});

test("a save sends the version it opened, with the session's CSRF token", async () => {
  const sent = [];
  await withFetch(async (url, init) => {
    sent.push({ url, init });
    if (url === "/api/v1/session") return json(session);
    return json(file({ version: "fedcba9876543210" }));
  }, async () => {
    const saved = await api.saveText(accountId, "public_html/index.php", "<?php echo 2;", "0123456789abcdef");
    assert.equal(saved.version, "fedcba9876543210");
  });
  const post = sent[1];
  assert.equal(post.url, `/api/v1/websites/sites/${accountId}/files/save`);
  assert.equal(post.init.method, "POST");
  assert.equal(post.init.headers["X-CSRF-Token"], session.csrf_token);
  assert.deepEqual(JSON.parse(post.init.body), { path: "public_html/index.php", content: "<?php echo 2;", expected_version: "0123456789abcdef" });
});

test("the server's explanation is passed on with its word under technical details", async () => {
  await withFetch(async (url) => {
    if (url === "/api/v1/session") return json(session);
    return json({ title: "Conflict", status: 409, detail: "The file changed after you opened it, so your version was not saved.", errors: [{ message: "account service: file operation failed: changed" }] }, 409);
  }, async () => {
    await assert.rejects(api.saveText(accountId, "a.txt", "x", "0123456789abcdef"), (e) => {
      assert.equal(e.message, "The file was not saved.");
      assert.match(e.why, /changed after you opened it/);
      assert.equal(e.next, "");
      assert.match(e.technical, /HTTP 409 \(Conflict\); account service: file operation failed: changed/);
      return true;
    });
  });
  // A token refusal carries {error, message}.
  await withFetch(async () => json({ error: "token_not_allowed", message: "An API token cannot use this part of the panel API." }, 403), async () => {
    await assert.rejects(api.listFolder(accountId, ""), (e) => /API token/.test(e.why));
  });
  // An answer the panel cannot read leaves a change's outcome open.
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ name: "../x" }), async () => {
    await assert.rejects(api.makeFolder(accountId, "new"), (e) => e.message === "The panel could not confirm the change.");
  });
});

test("permissions and downloads", async () => {
  await assert.rejects(api.setPermissions(accountId, "a", "4755"), api.FilesApiError);
  assert.equal(api.downloadURL(accountId, "public_html/my file.zip"), `/api/v1/websites/sites/${accountId}/files/download?path=public_html%2Fmy%20file.zip`);
});
