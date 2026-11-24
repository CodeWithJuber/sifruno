// Databases page client checks with synthetic sessions and fetch responses; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const api = await import(moduleURL(readFileSync(new URL("./databases-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL))));

const accountId = "0123456789abcdef0123456789abcdef";
const base = `/api/v1/websites/sites/${accountId}/databases`;
const typedSecret = "correct horse battery 9";
const list = () => ({ databases: [{ name: "example_shop", users: ["example_app"] }, { name: "example_wp", users: ["example_wp"] }], users: [{ name: "example_app" }, { name: "example_wp" }] });
const session = { authenticated: true, csrf_token: "c".repeat(43), expires_at: "2026-11-24T10:15:00Z" };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const problem = (status, detail, errors) => json({ title: "Problem", status, detail, ...(errors ? { errors } : {}) }, status);

async function withFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

// Answers the session read, then hands every other request to answer.
function server(answer) {
  const calls = [];
  const mock = async (url, init) => {
    if (url === "/api/v1/session") return json(session);
    calls.push({ url, method: init.method, headers: init.headers, body: init.body === undefined ? undefined : JSON.parse(init.body) });
    return answer(url, init);
  };
  return { calls, mock };
}

test("a name is the hosting account's name, an underscore and the suffix, within dbhost's limits", () => {
  assert.equal(api.fullName("example", "shop"), "example_shop");
  for (const ok of ["a", "shop", "shop_2", "0", "_", "a".repeat(16)]) {
    assert.equal(api.checkSuffix("database", "example", ok), undefined, ok);
    assert.equal(api.checkSuffix("user", "example", ok), undefined, ok);
  }
  for (const bad of ["", "Shop", "my-shop", "my shop", "shöp", "a.b", "a".repeat(17), "../x", "x`", "x'"]) {
    assert.equal(typeof api.checkSuffix("database", "example", bad), "string", bad);
    assert.equal(typeof api.checkSuffix("user", "example", bad), "string", bad);
  }
  // 64 characters for a database, 47 for a user: a long account name leaves a user less room.
  const long = `a${"b".repeat(31)}`;
  assert.equal(api.suffixLimit("database", long), 16);
  assert.equal(api.suffixLimit("user", long), 14);
  assert.equal(api.suffixLimit("user", "example"), 16);
  assert.equal(api.checkSuffix("user", long, "s".repeat(14)), undefined);
  assert.match(api.checkSuffix("user", long, "s".repeat(15)), /at most 14 characters/);
  assert.equal(api.checkSuffix("database", long, "s".repeat(16)), undefined);
  assert.match(api.checkSuffix("database", "example", "Shop"), /lowercase/);
  assert.match(api.checkSuffix("user", "example", ""), /name for the user/);
});

test("the password check mirrors the server: 12 to 128 bytes, no control characters, no outer space", () => {
  for (const ok of [typedSecret, "x".repeat(12), "x".repeat(128), "inner  spaces are fine", `p ${"ü".repeat(63)}`, "it's a \"quoted\" pass\\word"]) {
    assert.equal(api.checkPassword(ok), undefined, ok);
  }
  for (const bad of ["", "elevenchars", "x".repeat(129), ` ${typedSecret}`, `${typedSecret} `, "correct horse\nbattery", "correct horse\tbattery", "correct horse\u007fbattery", "correct horse\u0085battery", "ü".repeat(65)]) {
    assert.equal(typeof api.checkPassword(bad), "string", JSON.stringify(bad));
  }
  assert.match(api.checkPassword("short"), /at least 12/);
  assert.match(api.checkPassword(`${typedSecret} `), /space at the start or end/);
});

test("a delete needs the name typed again exactly, and the WordPress database is recognised", () => {
  assert.equal(api.checkConfirmName("example_shop", "example_shop"), undefined);
  for (const typed of ["", "example", "EXAMPLE_SHOP", "example_shop ", " example_shop", "example_wp"]) {
    assert.equal(typeof api.checkConfirmName("example_shop", typed), "string", JSON.stringify(typed));
  }
  assert.match(api.checkConfirmName("example_shop", ""), /Type example_shop to confirm/);
  assert.equal(api.usedByWordPress("example", "example_wp"), true);
  assert.equal(api.usedByWordPress("example", "example_shop"), false);
  assert.equal(api.usedByWordPress("example", "other_wp"), false);
  assert.deepEqual(api.databasesFor(list().databases, "example_app"), ["example_shop"]);
  assert.deepEqual(api.databasesFor(list().databases, "example_none"), []);
  assert.equal(api.checkDatabaseChoice(list().databases, "example_shop"), undefined);
  assert.equal(typeof api.checkDatabaseChoice(list().databases, ""), "string");
  assert.equal(typeof api.checkDatabaseChoice(list().databases, "other_wp"), "string");
  assert.equal(api.databaseHost, "127.0.0.1");
});

test("parsing accepts the contract, with Huma's $schema key, and drops unknown keys", () => {
  const parsed = api.parseSiteDatabases({ $schema: "http://127.0.0.1/schemas/SiteDatabasesBody.json", ...list(), extra: "x" });
  assert.deepEqual(parsed, list());
  assert.deepEqual(api.parseSiteDatabases({ databases: [], users: [] }), { databases: [], users: [] });
  assert.deepEqual(api.parseSiteDatabases({ databases: [{ name: "example_new", users: [], password: typedSecret }], users: [] }), { databases: [{ name: "example_new", users: [] }], users: [] });
  assert.equal(api.parseNamed({ $schema: "x", name: "example_shop" }), "example_shop");
});

test("parsing refuses anything outside the contract", () => {
  for (const bad of [
    null, [], {}, { databases: [] }, { users: [] }, { databases: {}, users: [] }, { databases: [], users: null },
    { databases: [{ name: "example_shop" }], users: [] }, { databases: [{ name: "", users: [] }], users: [] },
    { databases: [{ name: "bad name", users: [] }], users: [] }, { databases: [{ name: "x".repeat(65), users: [] }], users: [] },
    { databases: [{ name: "example_shop", users: [7] }], users: [] }, { databases: [{ name: "example_shop", users: ["a b"] }], users: [] },
    { databases: [{ name: "example_shop", users: "example_app" }], users: [] }, { databases: [], users: ["example_app"] },
    { databases: [], users: [{ name: "x".repeat(48) }] }, { databases: [], users: [{ name: "<b>" }] }, { databases: [null], users: [] },
  ]) assert.equal(api.parseSiteDatabases(bad), undefined, JSON.stringify(bad));
  for (const bad of [null, {}, { name: 3 }, { name: "" }, { name: "a b" }, { name: "x".repeat(65) }]) assert.equal(api.parseNamed(bad), undefined, JSON.stringify(bad));
  assert.equal(api.parseNamed({ name: "x".repeat(48) }, api.databaseUserLimit), undefined);
});

test("the list is one GET, without a token, and a bad address sends nothing", async () => {
  const { calls, mock } = server(() => json({ $schema: "x", ...list() }));
  await withFetch(mock, async () => {
    assert.deepEqual(await api.listSiteDatabases(accountId), list());
    assert.equal(calls.length, 1);
    assert.deepEqual([calls[0].url, calls[0].method, calls[0].body], [base, "GET", undefined]);
    assert.equal("X-CSRF-Token" in calls[0].headers, false);
    for (const bad of ["", "abc", accountId.toUpperCase(), `${accountId}/../x`]) {
      await assert.rejects(api.listSiteDatabases(bad), (error) => error instanceof api.DatabasesApiError && error.status === 404 && /nothing was sent/.test(error.technical));
    }
    assert.equal(calls.length, 1);
  });
  await withFetch(server(() => json({ databases: "none" })).mock, async () => {
    await assert.rejects(api.listSiteDatabases(accountId), (error) => error.message === "The databases could not be loaded." && /did not match the databases contract/.test(error.technical));
  });
});

test("each change reads the session token, then posts exactly the contract's keys", async () => {
  const named = { [base]: "example_shop", [`${base}/users`]: "example_app", [`${base}/users/example_app/password`]: "example_app", [`${base}/example_shop/delete`]: "example_shop", [`${base}/users/example_app/delete`]: "example_app" };
  const { calls, mock } = server((url) => json({ $schema: "x", name: named[url] }, url === base || url.endsWith("/users") ? 201 : 200));
  await withFetch(mock, async () => {
    assert.equal(await api.createSiteDatabase(accountId, "example", "shop"), "example_shop");
    assert.equal(await api.createDatabaseUser(accountId, "example", { name_suffix: "app", password: typedSecret, database: "example_shop", extra: "dropped" }), "example_app");
    assert.equal(await api.setDatabaseUserPassword(accountId, "example_app", typedSecret), "example_app");
    assert.equal(await api.deleteSiteDatabase(accountId, "example_shop", "example_shop"), "example_shop");
    assert.equal(await api.deleteDatabaseUser(accountId, "example_app", "example_app"), "example_app");
  });
  assert.deepEqual(calls.map((call) => [call.method, call.url, call.body]), [
    ["POST", base, { name_suffix: "shop" }],
    ["POST", `${base}/users`, { name_suffix: "app", password: typedSecret, database: "example_shop" }],
    ["POST", `${base}/users/example_app/password`, { password: typedSecret }],
    ["POST", `${base}/example_shop/delete`, { confirm_name: "example_shop" }],
    ["POST", `${base}/users/example_app/delete`, { confirm_name: "example_app" }],
  ]);
  for (const call of calls) {
    assert.equal(call.headers["X-CSRF-Token"], session.csrf_token);
    assert.equal(call.headers["Content-Type"], "application/json");
  }
});

test("a value the server would refuse is not sent, and the reason names no password", async () => {
  const { calls, mock } = server(() => json({ name: "example_shop" }, 201));
  let requests = 0;
  const counting = (...args) => { requests += 1; return mock(...args); };
  await withFetch(counting, async () => {
    const refused = (error) => error instanceof api.DatabasesApiError && error.status === 422 && /^not sent: /.test(error.technical) && !JSON.stringify([error.message, error.why, error.next, error.technical]).includes("short pw");
    await assert.rejects(api.createSiteDatabase(accountId, "example", "My-Shop"), refused);
    await assert.rejects(api.createDatabaseUser(accountId, "example", { name_suffix: "App", password: typedSecret, database: "example_shop" }), refused);
    await assert.rejects(api.createDatabaseUser(accountId, "example", { name_suffix: "app", password: "short pw", database: "example_shop" }), refused);
    await assert.rejects(api.createDatabaseUser(accountId, "example", { name_suffix: "app", password: typedSecret, database: "" }), refused);
    await assert.rejects(api.setDatabaseUserPassword(accountId, "example_app", "short pw"), refused);
    await assert.rejects(api.deleteSiteDatabase(accountId, "example_shop", "example_sho"), refused);
    await assert.rejects(api.deleteDatabaseUser(accountId, "example_app", ""), refused);
    const missing = (error) => error instanceof api.DatabasesApiError && error.status === 404 && /nothing was sent/.test(error.technical);
    await assert.rejects(api.createSiteDatabase("abc", "example", "shop"), missing);
    await assert.rejects(api.createSiteDatabase(accountId, "Example", "shop"), missing);
    await assert.rejects(api.setDatabaseUserPassword(accountId, "example_app/../x", typedSecret), missing);
    await assert.rejects(api.deleteSiteDatabase(accountId, "example shop", "example shop"), missing);
    await assert.rejects(api.deleteDatabaseUser(accountId, "", ""), missing);
  });
  assert.equal(requests, 0);
  assert.equal(calls.length, 0);
});

test("a failed change says what happened, why and what to do, with the server's technical text and never the password", async () => {
  const cases = [
    [problem(409, "A database user named example_app already exists on this server. Choose another name."), 409, /already exists/, /another name/, /HTTP 409/],
    [problem(422, "password must be 12 to 128 characters, with no control characters and no space at the start or end."), 422, /12 to 128/, /Fix the value/, /HTTP 422/],
    [problem(404, "That database was not found on this website. It may have been deleted."), 404, /not found on this website/, /Refresh the list/, /HTTP 404/],
    [problem(502, "The database server refused the request. Open Technical details to see why.", [{ message: "ERROR 1064 (42000) at line 1: You have an error near [statement removed]" }]), 502, /refused the request/, /Refresh the list/, /HTTP 502 \(Problem\): ERROR 1064 .* near \[statement removed\]/],
    [problem(503, "The database server is not answering. Check that it is running, then try again.", [{ message: "database server unavailable" }]), 503, /not answering/, /database server/, /database server unavailable/],
    [problem(403, "Valid session CSRF token required"), 403, /CSRF token/, /Reload the page/, /HTTP 403/],
    [new Response("<html>bad gateway</html>", { status: 500 }), 500, /HTTP 500/, /service log/, /HTTP 500/],
  ];
  for (const [response, status, why, next, technical] of cases) {
    await withFetch(server(() => response.clone()).mock, async () => {
      await assert.rejects(api.createDatabaseUser(accountId, "example", { name_suffix: "app", password: typedSecret, database: "example_shop" }), (error) => {
        assert.ok(error instanceof api.DatabasesApiError);
        assert.equal(error.message, "The database user was not created.");
        assert.equal(error.status, status);
        assert.match(error.why, why); assert.match(error.next, next); assert.match(error.technical, technical);
        assert.equal(JSON.stringify([error.message, error.why, error.next, error.technical]).includes(typedSecret), false);
        return true;
      });
    });
  }
  // Each operation names its own failure.
  const { mock } = server(() => problem(503, ""));
  await withFetch(mock, async () => {
    await assert.rejects(api.createSiteDatabase(accountId, "example", "shop"), { message: "The database was not created." });
    await assert.rejects(api.setDatabaseUserPassword(accountId, "example_app", typedSecret), { message: "The password was not changed." });
    await assert.rejects(api.deleteSiteDatabase(accountId, "example_shop", "example_shop"), { message: "The database was not deleted." });
    await assert.rejects(api.deleteDatabaseUser(accountId, "example_app", "example_app"), { message: "The database user was not deleted." });
    await assert.rejects(api.listSiteDatabases(accountId), { message: "The databases could not be loaded." });
  });
});

test("an answer that names something else is not taken as success", async () => {
  await withFetch(server(() => json({ name: "other_shop" }, 201)).mock, async () => {
    await assert.rejects(api.createSiteDatabase(accountId, "example", "shop"), (error) => error.status === 0 && /Refresh the list/.test(error.next) && /did not match the databases contract/.test(error.technical));
    await assert.rejects(api.deleteSiteDatabase(accountId, "example_shop", "example_shop"), (error) => error.status === 0);
  });
  await withFetch(server(() => json({}, 200)).mock, async () => {
    await assert.rejects(api.setDatabaseUserPassword(accountId, "example_app", typedSecret), (error) => error.status === 0);
  });
});

test("an ended session, a lost connection and a cancelled request are told apart", async () => {
  const ended = (error) => error.status === 401 && error.why === "Your sign-in has ended." && /Sign in again/.test(error.next);
  let posts = 0;
  await withFetch(async (url) => { if (url !== "/api/v1/session") posts += 1; return json({ authenticated: false }, 401); }, async () => {
    await assert.rejects(api.createSiteDatabase(accountId, "example", "shop"), ended);
    await assert.rejects(api.listSiteDatabases(accountId), ended);
  });
  await withFetch(async (url) => { if (url !== "/api/v1/session") posts += 1; return json({ authenticated: false }); }, async () => {
    await assert.rejects(api.deleteDatabaseUser(accountId, "example_app", "example_app"), ended);
  });
  assert.equal(posts, 1); // only the list's GET; no change was sent without a session
  await withFetch(async () => { throw new TypeError("fetch failed"); }, async () => {
    await assert.rejects(api.listSiteDatabases(accountId), (error) => error.status === 0 && /could not reach its server/.test(error.why) && /network error/.test(error.technical));
  });
  const controller = new AbortController();
  controller.abort();
  await withFetch(async (_url, init) => { init.signal.throwIfAborted(); return json(list()); }, async () => {
    await assert.rejects(api.listSiteDatabases(accountId, { signal: controller.signal }), (error) => error.status === 0 && error.why === "The request was cancelled.");
  });
});

test("Open phpMyAdmin posts an empty object with the session token and takes only a sign-in link on the panel", async () => {
  const link = `/api/v1/phpmyadmin/sifruno-signon.php?code=${"C".repeat(43)}`;
  const answer = { $schema: "x", url: link, link_expires_at: "2026-11-24T10:01:00Z", login_expires_at: "2026-11-24T11:00:00Z" };
  const { calls, mock } = server(() => json(answer, 201));
  await withFetch(mock, async () => {
    const opened = await api.openPhpMyAdmin(accountId);
    assert.equal(opened.url, link);
    assert.equal(opened.linkExpiresAt.toISOString(), "2026-11-24T10:01:00.000Z");
    assert.equal(opened.loginExpiresAt.toISOString(), "2026-11-24T11:00:00.000Z");
  });
  assert.deepEqual(calls.map((call) => [call.method, call.url, call.body]), [["POST", `${base}/phpmyadmin`, {}]]);
  assert.equal(calls[0].headers["X-CSRF-Token"], session.csrf_token);

  // A link anywhere else, or without its code, is never opened.
  for (const url of [`https://evil.example${link}`, "//evil.example/x", "/api/v1/phpmyadmin/index.php", `${link}&next=//evil.example`, "javascript:alert(1)", `/api/v1/phpmyadmin/sifruno-signon.php?code=${"C".repeat(42)}`]) {
    assert.equal(api.parsePhpMyAdminLink({ ...answer, url }), undefined, url);
  }
  assert.equal(api.parsePhpMyAdminLink({ ...answer, login_expires_at: "soon" }), undefined);
  await withFetch(server(() => json({ ...answer, url: "https://evil.example/" }, 201)).mock, async () => {
    await assert.rejects(api.openPhpMyAdmin(accountId), (error) => error.status === 0 && error.message === "phpMyAdmin did not open." && /Reload the page/.test(error.next));
  });
  let requests = 0;
  await withFetch(async () => { requests += 1; return json(session); }, async () => {
    await assert.rejects(api.openPhpMyAdmin("not-an-id"), (error) => error.status === 404 && /nothing was sent/.test(error.technical));
  });
  assert.equal(requests, 0);
});

test("a phpMyAdmin that does not open says what happened, why and what to do", async () => {
  const cases = [
    [problem(409, "This website has no database yet, so phpMyAdmin would have nothing to show. Create a database first."), /no database yet/, /Create a database below/],
    [problem(503, "phpMyAdmin is not set up on this server. Run Sifruno's installer (install.sh) again to add it."), /not set up/, /install\.sh/],
    [problem(429, "Too many phpMyAdmin sign-ins are open on this server."), /Too many/, /Wait a minute/],
    [problem(502, "The database server refused to make phpMyAdmin's temporary user. Open Technical details to see why.", [{ message: "ERROR 1045 (28000): Access denied" }]), /temporary user/, /database server's log/],
    [problem(403, "An API token cannot use this part of the panel API."), /API token/, /Reload the page/],
  ];
  for (const [response, why, next] of cases) {
    await withFetch(server(() => response.clone()).mock, async () => {
      await assert.rejects(api.openPhpMyAdmin(accountId), (error) => {
        assert.ok(error instanceof api.DatabasesApiError);
        assert.equal(error.message, "phpMyAdmin did not open.");
        assert.match(error.why, why); assert.match(error.next, next);
        return true;
      });
    });
  }
});
