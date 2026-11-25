// Wizard client checks with synthetic sessions and fetch responses; no server or state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const moduleURL = (source) => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`;
const sitesURL = moduleURL(readFileSync(new URL("./sites-api.ts", import.meta.url), "utf8"));
const recordURL = moduleURL(readFileSync(new URL("./migration-record.ts", import.meta.url), "utf8"));
const wordpressURL = moduleURL(readFileSync(new URL("./wordpress-api.ts", import.meta.url), "utf8").replace('"./sites-api"', JSON.stringify(sitesURL)).replace('"./migration-record"', JSON.stringify(recordURL)));
const api = await import(wordpressURL);
const migrations = await import(moduleURL(readFileSync(new URL("./migration-api.ts", import.meta.url), "utf8").replace('"./wordpress-api"', JSON.stringify(wordpressURL))));

const jobId = "0123456789abcdef0123456789abcdef";
const password = "correct horse battery";
const input = () => ({ domain: "example.com", title: "My site", admin_user: "siteadmin", admin_email: "me@example.com", admin_password: password, php_version: "8.3" });
const steps = (states = ["running", "pending", "pending", "pending", "pending"]) => [
  { name: "account", title: "Create the hosting account" }, { name: "web", title: "Put the site live with PHP" },
  { name: "ssl", title: "Turn on https" }, { name: "database", title: "Create the database" }, { name: "wordpress", title: "Install WordPress" },
].map((step, i) => ({ ...step, state: states[i], message: "", started_at: states[i] === "pending" ? "" : "2026-11-23T10:00:00Z", finished_at: "" }));
const job = (change = {}) => ({
  id: jobId, kind: "wordpress", domain: "example.com", username: "example", state: "running", steps: steps(),
  error: null, result: null, actor: "admin", created_at: "2026-11-23T10:00:00Z", updated_at: "2026-11-23T10:00:05Z", ...change,
});
const succeeded = () => job({ state: "succeeded", steps: steps(["done", "done", "skipped", "done", "done"]), result: { url: "http://example.com/", admin_url: "http://example.com/wp-admin/", wordpress_version: "7.1.5", account_id: "a".repeat(32) } });
const failed = () => job({ state: "failed", steps: steps(["undone", "undone", "skipped", "undone", "failed"]), error: { step: "wordpress", what: "WordPress could not be installed.", why: "The download failed.", next: "Try again later.", technical: "wp core download: exit 1" } });
const session = { authenticated: true, csrf_token: "fixture-csrf", expires_at: "2026-11-23T10:15:00Z" };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

async function withFetch(mock, operation) {
  const original = globalThis.fetch; globalThis.fetch = mock;
  try { await operation(); } finally { globalThis.fetch = original; }
}

test("domain check mirrors hostaccounts.validDomain", () => {
  for (const ok of ["example.com", "a.b", "my-site.example.co.uk", "xn--bcher-kva.example", "01.2.3.4", "1.2.3.4.5", `${"a".repeat(63)}.com`, `${"a.".repeat(125)}abc`]) {
    assert.equal(api.checkDomain(ok), undefined, ok);
  }
  for (const bad of ["", "example", "Example.com", "1.2.3.4", "255.255.255.255", "::1", "2001:db8::1", "example.com:8080", "http://example.com", "example.com/", "-example.com", "example-.com", "exa_mple.com", "example..com", ".example.com", "example.com.", "exa mple.com", "bücher.example", `${"a".repeat(64)}.com`, `${"a.".repeat(126)}ab`]) {
    assert.equal(typeof api.checkDomain(bad), "string", bad);
  }
  assert.match(api.checkDomain("1.2.3.4"), /IP address/);
  assert.match(api.checkDomain("http://example.com"), /without http/);
});

test("title is 1-200 UTF-8 bytes of printable text after trimming the ends", () => {
  for (const ok of ["My site", "x", "Café & Bäckerei — Dubai", "موقعي", "a".repeat(200), "é".repeat(100), "😀".repeat(50), " leading and trailing ", `  ${"a".repeat(200)}  `]) {
    assert.equal(api.checkTitle(ok), undefined, ok);
  }
  // Bytes, not characters: these are at most 200 characters but over 200 bytes.
  for (const bad of ["é".repeat(101), "😀".repeat(51), "موقع".repeat(26)]) assert.match(api.checkTitle(bad), /of 200 bytes/, bad);
  assert.match(api.checkTitle("é".repeat(101)), /202 of 200 bytes/);
  for (const bad of ["", "   ", "a\nb", "tab\there", "zero\u200bwidth", "no\u00a0break", "a".repeat(201), "bell\u0007"]) {
    assert.equal(typeof api.checkTitle(bad), "string", JSON.stringify(bad));
  }
  assert.match(api.checkTitle("   "), /not only spaces/);
});

test("admin username follows ^[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,59}$", () => {
  for (const ok of ["siteadmin", "a", "Admin.User", "me@example.com", "_x-y", "@", "a".repeat(60)]) assert.equal(api.checkAdminUser(ok), undefined, ok);
  for (const bad of ["", "-admin", "has space", "ümlaut", "a".repeat(61), "semi;colon", "admin\n"]) assert.equal(typeof api.checkAdminUser(bad), "string", bad);
});

test("admin email is a plain address of at most 100 characters", () => {
  for (const ok of ["me@example.com", "first.last+tag@sub.example.co", "a@b", `${"a".repeat(88)}@example.com`]) assert.equal(api.checkAdminEmail(ok), undefined, ok);
  for (const bad of ["", "me", "me@", "@example.com", "Me <me@example.com>", "me@example.com ", "me@exa mple.com", "me@@example.com", `${"a".repeat(89)}@example.com`]) {
    assert.equal(typeof api.checkAdminEmail(bad), "string", bad);
  }
});

test("admin password is 12-128 UTF-8 bytes with no space at either end and no control characters", () => {
  for (const ok of ["a".repeat(12), "a".repeat(128), "correct horse battery", "Пароль-надёжный", "ñ".repeat(64), "ñ".repeat(6), "😀".repeat(3), "x y z 1 2 3 !@#", "zero​width-pw", "inner nbsp-pw"]) {
    assert.equal(api.checkAdminPassword(ok), undefined, JSON.stringify(ok));
  }
  for (const bad of ["", "a".repeat(11), "a".repeat(129), "ñ".repeat(5), "ñ".repeat(65), "😀".repeat(33), " leading-space-pw", "trailing-space-pw ", "trailing-nbsp-pw ", "tab\tinside-pw", "new\nline-password", "del\u007fcharacter-pw"]) {
    assert.equal(typeof api.checkAdminPassword(bad), "string", JSON.stringify(bad));
  }
  // A problem message never repeats the password itself.
  for (const bad of [" leading-space-pw", "short-pw"]) assert.equal(api.checkAdminPassword(bad).includes(bad.trim()), false);
});

test("PHP version is one of 8.1-8.4 and defaults to 8.3", () => {
  assert.equal(api.defaultPhpVersion, "8.3");
  assert.deepEqual([...api.phpVersions], ["8.1", "8.2", "8.3", "8.4"]);
  for (const ok of api.phpVersions) assert.equal(api.checkPhpVersion(ok), undefined);
  for (const bad of ["", "8.0", "8.5", "8", "8.3 ", "7.4"]) assert.equal(typeof api.checkPhpVersion(bad), "string", bad);
  assert.deepEqual(api.checkWordPressInput(input()), {});
  assert.deepEqual(Object.keys(api.checkWordPressInput({ ...input(), domain: "", php_version: "9" })), ["domain", "php_version"]);
});

test("job parsing accepts the contract's running, succeeded and failed shapes", () => {
  const running = api.parseJob(job());
  assert.equal(running.state, "running"); assert.equal(running.steps.length, 5); assert.equal(running.error, null); assert.equal(running.result, null);
  assert.equal(api.parseJob(succeeded()).result.wordpress_version, "7.1.5");
  assert.equal(api.parseJob(failed()).error.what, "WordPress could not be installed.");
  assert.deepEqual(api.jobProgress(api.parseJob(job({ steps: steps(["done", "done", "running", "pending", "pending"]) }))), { done: 2, total: 5 });
  // A skipped "ssl" step counts as finished: the job carries on without it.
  assert.deepEqual(api.jobProgress(api.parseJob(succeeded())), { done: 5, total: 5 });
  // The short step form in the contract (name and title only besides state) is filled in.
  const short = api.parseJob(job({ steps: [{ name: "account", title: "Create the hosting account", state: "pending" }] }));
  assert.deepEqual(short.steps[0], { name: "account", title: "Create the hosting account", state: "pending", message: "", started_at: "", finished_at: "" });
  // The username is empty until the account step picks one.
  assert.equal(api.parseJob(job({ username: "" })).username, "");
  assert.equal(api.parseJobResponse({ job: job() }).id, jobId);
  assert.equal(api.parseJobList({ jobs: [job(), succeeded()] }).length, 2);
});

test("job parsing matches the finished backend: $schema keys, the fixed actor, restart and undo failures", () => {
  // Huma adds "$schema" next to "job" and "jobs"; unknown keys are ignored.
  const schema = "http://127.0.0.1/schemas/JobBody.json";
  assert.equal(api.parseJobResponse({ $schema: schema, job: job({ actor: "local-operator" }) }).actor, "local-operator");
  assert.equal(api.parseJobList({ $schema: schema, jobs: [job(), failed()] }).length, 2);
  // A job that was running when the panel restarted comes back as failed.
  const restarted = api.parseJob(job({ state: "failed", steps: steps(["done", "failed", "pending", "pending", "pending"]), error: { step: "web", what: "The panel restarted while this website was being created.", why: "The setup was interrupted.", next: "Try again.", technical: "" } }));
  assert.equal(restarted.state, "failed"); assert.match(restarted.error.what, /panel restarted/);
  // Undo problems are passed through as written.
  const leftovers = api.parseJob(job({ state: "failed", steps: steps(["done", "undone", "skipped", "undone", "failed"]), error: { step: "wordpress", what: "WordPress could not be installed.", why: "The download failed.", next: "These could not be removed: the hosting account example. Remove it in Customers, then try again.", technical: "undo account: userdel exited 1\nwordpress: download timed out" } }));
  assert.match(leftovers.error.next, /could not be removed/); assert.match(leftovers.error.technical, /^undo account: /);
});

test("the ssl step: skipped keeps its reason, and the last screen tells https from http", () => {
  const notPointing = "The domain does not point at this server yet, so the site uses http. The panel tries again every few hours.";
  const httpSite = succeeded();
  httpSite.steps[2] = { ...httpSite.steps[2], state: "skipped", message: notPointing, finished_at: "2026-11-23T10:01:00Z" };
  const parsed = api.parseJob(httpSite);
  assert.deepEqual(parsed.steps.map((s) => `${s.name}=${s.state}`), ["account=done", "web=done", "ssl=skipped", "database=done", "wordpress=done"]);
  assert.equal(api.usesHttps(parsed.result), false);
  assert.equal(api.httpReason(parsed), notPointing);
  // Not set up on this server: the same, with that reason.
  const plain = succeeded(); plain.steps[2].message = "Certificates are not set up on this server.";
  assert.equal(api.httpReason(api.parseJob(plain)), "Certificates are not set up on this server.");

  const httpsSite = job({ state: "succeeded", steps: steps(["done", "done", "done", "done", "done"]), result: { url: "https://example.com/", admin_url: "https://example.com/wp-admin/", wordpress_version: "7.1.5", account_id: "a".repeat(32) } });
  const secure = api.parseJob(httpsSite);
  assert.equal(api.usesHttps(secure.result), true);
  assert.equal(api.httpReason(secure), "");
  // Both links must be https to call the site https.
  assert.equal(api.usesHttps({ ...secure.result, admin_url: "http://example.com/wp-admin/" }), false);

  // A job from before the ssl step: four steps, no reason, still http.
  const old = job({ state: "succeeded", steps: steps(["done", "done", "done", "done", "done"]).filter((s) => s.name !== "ssl"), result: succeeded().result });
  const oldParsed = api.parseJob(old);
  assert.equal(oldParsed.steps.length, 4); assert.equal(api.httpReason(oldParsed), ""); assert.equal(api.usesHttps(oldParsed.result), false);
});

test("job parsing fails closed on values outside the contract", () => {
  for (const change of [
    { id: "ABCDEF" + "0".repeat(26) }, { id: "short" }, { kind: "static" }, { state: "done" }, { domain: "" },
    { username: "Root" }, { username: "ab" }, { steps: [] }, { steps: "account" }, { steps: steps(["running", "waiting", "pending", "pending", "pending"]) },
    { steps: [{ name: "", title: "x", state: "pending" }] }, { created_at: "yesterday" }, { error: "boom" },
    { state: "succeeded", result: null }, { state: "succeeded", steps: steps(["done", "done", "done", "done", "done"]), result: { url: "javascript:alert(1)", admin_url: "http://example.com/wp-admin/", wordpress_version: "7.1.5" } },
    { result: { url: "http://example.com/", admin_url: "data:text/html,hi", wordpress_version: "7.1.5" } },
    { result: { url: "http://example.com/", admin_url: "http://example.com/wp-admin/" } },
  ]) assert.equal(api.parseJob(job(change)), undefined, JSON.stringify(change));
  assert.equal(api.parseJob(null), undefined);
  assert.equal(api.parseJobResponse(job()), undefined);
  assert.equal(api.parseJobList({ jobs: Array.from({ length: 21 }, job) }), undefined);
  assert.equal(api.parseJobList({ jobs: [job(), { ...job(), kind: "x" }] }), undefined);
});

test("create reads the session token, then posts exactly the six fields with CSRF", async () => {
  const calls = [];
  await withFetch(async (url, options) => {
    calls.push({ url, options });
    if (url === "/api/v1/session") return json(session);
    return json({ $schema: "http://127.0.0.1/schemas/JobBody.json", job: job() }, 202);
  }, async () => {
    const created = await api.createWordPressSite({ ...input(), extra: "dropped" });
    assert.equal(created.id, jobId);
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.method, "GET");
  const post = calls[1];
  assert.equal(post.url, "/api/v1/websites/wordpress"); assert.equal(post.options.method, "POST");
  assert.equal(post.options.credentials, "same-origin"); assert.equal(post.options.cache, "no-store");
  assert.equal(post.options.headers["X-CSRF-Token"], "fixture-csrf"); assert.equal(post.options.headers["Content-Type"], "application/json");
  assert.deepEqual(Object.keys(JSON.parse(post.options.body)), ["domain", "title", "admin_user", "admin_email", "admin_password", "php_version"]);
  assert.deepEqual(JSON.parse(post.options.body), input());
});

test("create sends the title trimmed, as the server stores it", async () => {
  let sent;
  await withFetch(async (url, options) => {
    if (url === "/api/v1/session") return json(session);
    sent = JSON.parse(options.body); return json({ job: job() }, 202);
  }, async () => { await api.createWordPressSite({ ...input(), title: "  My site  " }); });
  assert.equal(sent.title, "My site");
});

test("create refuses invalid input before anything is sent", async () => {
  await withFetch(async () => assert.fail("must not dispatch"), async () => {
    for (const change of [{ domain: "Example.com" }, { admin_password: "short" }, { php_version: "8.0" }, { title: "" }]) {
      await assert.rejects(api.createWordPressSite({ ...input(), ...change }), (error) => error instanceof api.WordPressApiError && error.status === 422);
    }
  });
});

test("create stops when the session has ended", async () => {
  let posts = 0;
  await withFetch(async (url) => {
    if (url === "/api/v1/session") return json({ authenticated: false }, 401);
    ++posts; return json({ job: job() }, 202);
  }, async () => {
    await assert.rejects(api.createWordPressSite(input()), { status: 401 });
  });
  assert.equal(posts, 0);
});

for (const [status, detail] of [
  [400, "The request body is not valid JSON."], [409, "A website for example.com is already being set up."],
  [409, "Two website setups are already running. Wait for one to finish."], [413, "The request body is larger than 4 KiB."],
  [415, "Send the request as application/json."], [422, "unexpected property \"extra\""],
  [503, "The MariaDB service is not running."], [503, "Website creation is not set up on this server"],
]) {
  test(`create surfaces HTTP ${status} problem detail without the password`, async () => {
    await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ title: "Problem", status, detail }, status), async () => {
      await assert.rejects(api.createWordPressSite(input()), (error) => {
        assert(error instanceof api.WordPressApiError);
        assert.equal(error.status, status); assert.equal(error.detail, detail);
        assert.equal(error.message, "The website was not created.");
        assert(error.next.length > 0); assert.match(error.technical, new RegExp(`HTTP ${status}`));
        for (const part of [error.message, error.detail, error.next, error.technical]) assert.equal(part.includes(password), false);
        return true;
      });
    });
  });
}

test("create rejects a 202 that does not describe a job for this domain", async () => {
  for (const body of [{ job: job({ domain: "other.com" }) }, { job: { id: jobId } }, {}]) {
    await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json(body, 202), async () => {
      await assert.rejects(api.createWordPressSite(input()), { status: 0 });
    });
  }
});

test("create gives up after 20 seconds and says the site may exist", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let posted;
  await withFetch(async (url, options) => {
    if (url === "/api/v1/session") return json(session);
    return new Promise((_, reject) => { posted = true; options.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))); });
  }, async () => {
    const pending = api.createWordPressSite(input());
    while (!posted) await new Promise((resolve) => setImmediate(resolve));
    t.mock.timers.tick(api.createTimeoutMs - 1);
    await new Promise((resolve) => setImmediate(resolve));
    t.mock.timers.tick(1);
    await assert.rejects(pending, (error) => {
      assert.equal(error.status, 0);
      assert.match(error.detail, /20 seconds/);
      assert.match(error.next, /first try worked/);
      return true;
    });
  });
});

test("reading a job validates the id first and the answer after", async () => {
  await withFetch(async () => assert.fail("must not dispatch"), async () => {
    for (const bad of ["", "../session", "ABCDEF0123456789ABCDEF0123456789", jobId + "0"]) {
      await assert.rejects(api.getWebsiteJob(bad), { status: 404 });
    }
  });
  const seen = [];
  await withFetch(async (url, options) => { seen.push([url, options.method, options.headers["X-CSRF-Token"]]); return json({ job: job() }); }, async () => {
    assert.equal((await api.getWebsiteJob(jobId)).id, jobId);
  });
  assert.deepEqual(seen, [[`/api/v1/websites/jobs/${jobId}`, "GET", undefined]]);
  await withFetch(async () => json({ job: job({ id: "f".repeat(32) }) }), async () => {
    await assert.rejects(api.getWebsiteJob(jobId), { status: 0 });
  });
  await withFetch(async () => json({ title: "Not Found", status: 404, detail: "no such job" }, 404), async () => {
    await assert.rejects(api.getWebsiteJob(jobId), (error) => error.status === 404 && error.detail === "no such job" && error.message === "The setup progress could not be loaded.");
  });
  await withFetch(async () => { throw new TypeError("offline"); }, async () => {
    await assert.rejects(api.getWebsiteJob(jobId), (error) => error.status === 0 && /reach its server/.test(error.detail));
  });
});

test("listing jobs returns newest-first records as given", async () => {
  await withFetch(async (url) => { assert.equal(url, "/api/v1/websites/jobs"); return json({ jobs: [succeeded(), failed()] }); }, async () => {
    const jobs = await api.listWebsiteJobs();
    assert.deepEqual(jobs.map((j) => j.state), ["succeeded", "failed"]);
  });
  await withFetch(async () => json({ items: [] }), async () => {
    await assert.rejects(api.listWebsiteJobs(), { status: 0 });
  });
});

// A PHP site: its own steps, a result with no WordPress, and the database's
// name when it asked for one.
const dbSecret = ["chosen", "db", "pass", "0123"].join(" ");
const shortSecret = "short";
const phpInput = (change = {}) => ({ domain: "example.com", php_version: "8.2", database: "create", database_password: dbSecret, ...change });
const phpSteps = (states = ["done", "done", "skipped", "done", "done"]) => [
  { name: "account", title: "Create the hosting account" }, { name: "web", title: "Put the site live with PHP" },
  { name: "ssl", title: "Turn on https" }, { name: "database", title: "Create the database" }, { name: "placeholder", title: "Add a placeholder page" },
].map((step, i) => ({ ...step, state: states[i], message: "", started_at: "2026-11-23T10:00:00Z", finished_at: "" }));
const phpJob = (change = {}) => job({ kind: "php", php_version: "8.2", state: "succeeded", steps: phpSteps(), result: { url: "https://example.com/", admin_url: "", wordpress_version: "", account_id: "a".repeat(32), database: "example_wp" }, ...change });

test("PHP site jobs parse with no WordPress and their database's name", () => {
  const parsed = api.parseJob(phpJob());
  assert.equal(parsed.kind, "php"); assert.equal(parsed.php_version, "8.2");
  assert.deepEqual(parsed.result, { url: "https://example.com/", admin_url: "", wordpress_version: "", account_id: "a".repeat(32), database: "example_wp" });
  assert.equal(api.usesHttps(parsed.result), true);
  // Without a database the server leaves the key out.
  assert.equal(api.parseJob(phpJob({ result: { url: "http://example.com/", admin_url: "", wordpress_version: "", account_id: "a".repeat(32) } })).result.database, "");
  assert.equal(api.usesHttps(api.parseJob(phpJob({ result: { url: "http://example.com/", admin_url: "", wordpress_version: "", account_id: "a".repeat(32) } })).result), false);
  // A WordPress job reads as before, its database empty.
  assert.equal(api.parseJob(succeeded()).result.database, "");
  for (const change of [
    { result: { url: "https://example.com/", admin_url: "https://example.com/wp-admin/", wordpress_version: "", account_id: "a".repeat(32) } },
    { result: { url: "https://example.com/", admin_url: "", wordpress_version: "7.1.5", account_id: "a".repeat(32) } },
    { result: { url: "https://example.com/", admin_url: "", wordpress_version: "", account_id: "a".repeat(32), database: "Example DB" } },
    { php_version: "latest" },
  ]) assert.equal(api.parseJob(phpJob(change)), undefined, JSON.stringify(change));
  // A WordPress job still needs its admin link.
  assert.equal(api.parseJob(job({ state: "succeeded", steps: steps(["done", "done", "skipped", "done", "done"]), result: { url: "http://example.com/", admin_url: "", wordpress_version: "7.1.5", account_id: "a".repeat(32) } })), undefined);
});

test("PHP site checks: the database password only when a database is asked for", () => {
  assert.deepEqual(api.checkPhpSiteInput(phpInput()), {});
  assert.deepEqual(api.checkPhpSiteInput(phpInput({ database: "none", database_password: "" })), {});
  assert.deepEqual(Object.keys(api.checkPhpSiteInput(phpInput({ database_password: "short" }))), ["database_password"]);
  assert.deepEqual(Object.keys(api.checkPhpSiteInput(phpInput({ database_password: " leading space 12" }))), ["database_password"]);
  assert.deepEqual(Object.keys(api.checkPhpSiteInput(phpInput({ database: "yes" }))), ["database"]);
  assert.deepEqual(Object.keys(api.checkPhpSiteInput(phpInput({ domain: "Example.com", php_version: "7.4" }))), ["domain", "php_version"]);
  // The database user's password follows the admin password's rule.
  for (const value of ["", "short", "a\nb-0123456789", "x".repeat(129)]) assert.equal(api.checkDatabasePassword(value), api.checkAdminPassword(value));
});

test("create a PHP site posts exactly its four fields, the password only with a database", async () => {
  const posts = [];
  await withFetch(async (url, options) => {
    if (url === "/api/v1/session") return json(session);
    posts.push({ url, options }); return json({ job: phpJob({ state: "running", result: null, steps: phpSteps(["running", "pending", "pending", "pending", "pending"]) }) }, 202);
  }, async () => {
    const created = await api.createPhpSite({ ...phpInput(), title: "dropped", admin_password: dbSecret });
    assert.equal(created.kind, "php");
    await api.createPhpSite(phpInput({ database: "none", database_password: "typed then unchosen" }));
  });
  assert.equal(posts.length, 2);
  assert.equal(posts[0].url, "/api/v1/websites/php"); assert.equal(posts[0].options.method, "POST");
  assert.equal(posts[0].options.headers["X-CSRF-Token"], "fixture-csrf");
  assert.deepEqual(JSON.parse(posts[0].options.body), phpInput());
  assert.deepEqual(Object.keys(JSON.parse(posts[0].options.body)), ["domain", "php_version", "database", "database_password"]);
  assert.deepEqual(JSON.parse(posts[1].options.body), { domain: "example.com", php_version: "8.2", database: "none", database_password: "" });
  // Invalid input is refused before anything is sent.
  await withFetch(async () => assert.fail("must not dispatch"), async () => {
    for (const change of [{ domain: "Example.com" }, { database_password: shortSecret }, { php_version: "8.0" }]) {
      await assert.rejects(api.createPhpSite(phpInput(change)), (error) => error instanceof api.WordPressApiError && error.status === 422 && !error.technical.includes("short"));
    }
  });
  // A 202 that is not a PHP site job for this domain is not trusted.
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ job: job() }, 202), async () => {
    await assert.rejects(api.createPhpSite(phpInput()), { status: 0 });
  });
});

test("server text is kept to one short line", async () => {
  await withFetch(async () => json({ status: 503, detail: `line one\nline two\u0000${"x".repeat(900)}` }, 503), async () => {
    await assert.rejects(api.getWebsiteJob(jobId), (error) => !/[\n\u0000]/.test(error.detail) && error.detail.length <= 500);
  });
});

// ---- Move a website here ------------------------------------------------------

const sourceId = "c".repeat(32);
const migrationSteps = (states) => ["source", "account", "web", "files", "database", "cron", "verify", "key"].map((name, i) => ({ name, title: name, state: states[i] ?? "pending", message: "", started_at: "", finished_at: "" }));
const migrationRecord = (change = {}) => ({
  source: sourceId, source_host: "old.example.test", source_user: "shopone", tier: "native", php_source: "ea-php81", wordpress: true,
  databases: ["shopone_wp"], database_users: ["shopone_wpu"], tables: [], notes: [], probes: [{ path: "/private/", kind: "deny" }],
  verify: { running: false, ran: true, cutover_allowed: true, verdict: "CUTOVER ALLOWED", pages_compared: 5, pages_pass: 5, pages_warn: 0, pages_fail: 0, probes_pass: 1, probes_fail: 0, lines: [], finished_at: "2026-11-24T10:00:00Z" },
  gate: "open", address: "203.0.113.7", key_removed: true, activity: [{ at: "2026-11-24T10:00:00Z", actor: "local-operator", what: "Started." }], ...change,
});
const migrationJob = (change = {}) => job({
  kind: "migration", domain: "shop.example.test", username: "shopone", state: "succeeded", steps: migrationSteps(Array(8).fill("done")),
  result: { url: "http://shop.example.test/", admin_url: "http://shop.example.test/wp-admin/", wordpress_version: "", account_id: "a".repeat(32), database: "shopone_wp" },
  migration: migrationRecord(), ...change,
});

test("a move's job is read with its migration record, and a running one without a domain yet", () => {
  const parsed = api.parseJob(migrationJob());
  assert.equal(parsed.kind, "migration");
  assert.equal(parsed.migration.gate, "open");
  assert.equal(parsed.migration.verify.pages_compared, 5);
  const running = api.parseJob(migrationJob({ domain: "", state: "running", result: null, steps: migrationSteps(["running"]) }));
  assert.equal(running.domain, "");
  // A wizard job still needs its domain and has no migration record.
  assert.equal(api.parseJob(job({ domain: "" })), undefined);
  assert.equal(api.parseJob({ ...succeeded(), migration: migrationRecord() }), undefined);
  // A move without its record, or with a gate the panel does not know, is refused.
  assert.equal(api.parseJob(migrationJob({ migration: null })), undefined);
  assert.equal(api.parseJob(migrationJob({ migration: migrationRecord({ gate: "half-open" }) })), undefined);
});

test("the move's inputs are checked before anything is sent", () => {
  for (const host of ["", "root@old.example.test", "old.example.test:22", "OLD.example.test", "localhost", "127.0.0.1", "x/y"]) assert.ok(migrations.checkSourceHost(host), host);
  assert.equal(migrations.checkSourceHost("203.0.113.5"), undefined);
  for (const port of ["", "0", "65536", "22a"]) assert.ok(migrations.checkSourcePort(port), port);
  assert.equal(migrations.checkSourcePort("2222"), undefined);
  assert.ok(migrations.checkAcceptReason("   "));
  assert.ok(migrations.checkAcceptReason("a\nb"));
  assert.equal(migrations.checkAcceptReason("Known plugin difference"), undefined);
});

test("opening a source posts only host and port and trusts only a source with its key line", async () => {
  const source = { id: sourceId, host: "old.example.test", port: 22, key_line: `restrict ssh-ed25519 AAAA sifruno-migration-${sourceId}`, install_command: "echo ... >> /root/.ssh/authorized_keys", host_keys: [{ type: "ssh-ed25519", fingerprint: "SHA256:abc" }], pinned_fingerprint: "", expires_at: "2026-11-25T10:00:00Z" };
  const posts = [];
  await withFetch(async (url, options) => {
    if (url === "/api/v1/session") return json(session);
    posts.push({ url, options }); return json({ source });
  }, async () => {
    const opened = await migrations.openSource("old.example.test", 22);
    assert.equal(opened.host_keys[0].fingerprint, "SHA256:abc");
  });
  assert.equal(posts[0].url, "/api/v1/websites/migrations/sources");
  assert.deepEqual(JSON.parse(posts[0].options.body), { host: "old.example.test", port: 22 });
  assert.equal(posts[0].options.headers["X-CSRF-Token"], "fixture-csrf");
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ source: { ...source, key_line: "ssh-ed25519 AAAA someone-else" } }), async () => {
    await assert.rejects(migrations.openSource("old.example.test", 22), { status: 0 });
  });
  // A refusal keeps the server's reason and says what to do next.
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ status: 422, detail: "Sifruno could not reach the old server over SSH." }, 422), async () => {
    await assert.rejects(migrations.openSource("old.example.test", 22), (error) => error.status === 422 && error.message === "Sifruno could not connect to the old server." && error.detail.includes("SSH"));
  });
});

test("stale key lines are read only with the line they name, and cleared with the session", async () => {
  const key = { id: sourceId, host: "old.example.test", port: 22, line: `sifruno-migration-${sourceId}`, detail: "Remove the line.", since: "2026-11-24T10:00:00Z" };
  assert.deepEqual(migrations.parseStaleKeys({ keys: [key] }), [key]);
  assert.equal(migrations.parseStaleKeys({ keys: [{ ...key, line: "sifruno-migration-" + "d".repeat(32) }] }), undefined);
  const posts = [];
  await withFetch(async (url, options) => {
    if (url === "/api/v1/session") return json(session);
    posts.push({ url, method: options.method, csrf: options.headers["X-CSRF-Token"] });
    return json({ cleared: sourceId });
  }, async () => { await migrations.clearStaleKey(sourceId); });
  assert.deepEqual(posts, [{ url: `/api/v1/websites/migrations/stale-keys/${sourceId}/cleared`, method: "POST", csrf: "fixture-csrf" }]);
});

test("accepting red lines sends the trimmed reason and expects the move back", async () => {
  const posts = [];
  await withFetch(async (url, options) => {
    if (url === "/api/v1/session") return json(session);
    posts.push({ url, body: JSON.parse(options.body) });
    return json({ job: migrationJob({ migration: migrationRecord({ gate: "accepted", accepted: { actor: "local-operator", at: "2026-11-24T10:05:00Z", reason: "checked" } }) }) });
  }, async () => {
    const accepted = await migrations.acceptMigration(jobId, "  checked  ");
    assert.equal(accepted.migration.gate, "accepted");
    assert.equal(accepted.migration.accepted.reason, "checked");
  });
  assert.deepEqual(posts, [{ url: `/api/v1/websites/migrations/${jobId}/accept`, body: { reason: "checked" } }]);
  // A wizard job in the answer is not a move.
  await withFetch(async (url) => url === "/api/v1/session" ? json(session) : json({ job: succeeded() }), async () => {
    await assert.rejects(migrations.readyMigration(jobId), { status: 0 });
  });
});
