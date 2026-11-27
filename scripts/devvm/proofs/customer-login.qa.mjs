// Browser checks for customer logins, run by `proof.sh customer-login`
// against a panel in the dev VM that runs as sifpanel with the real broker.
// It reads the panel state's operator key for first-run setup and never
// prints it; the admin's and the customer's passwords, their authenticator
// keys and the customer's setup link exist only in this process.
//   node customer-login.qa.mjs <origin> <key-file> <out-dir> <sites> [chrome-executable] [https-origin]
// sites is "make:<domain>" to have the wizard make two PHP sites,
// a.<domain> and b.<domain>, or "existing" to use the first two websites the
// panel lists. With https-origin the customer works over the HTTPS listener,
// as from its own computer; its host name is mapped to 127.0.0.1.
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";

const [origin, keyFile, outDir, sitesMode, chrome, httpsOrigin] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const key = readFileSync(keyFile, "utf8").trim();
const run = Date.now().toString(36).slice(-5);
const customer = `qacust${run}`;
const adminPassword = `qa admin ${randomBytes(12).toString("hex")}`;
const customerPassword = `qa customer ${randomBytes(12).toString("hex")}`;
const customerNewWords = `qa customer new ${randomBytes(12).toString("hex")}`;
const customerOrigin = httpsOrigin || origin;
const checks = [];
const errors = [];
const check = (name, ok, detail = "") => { checks.push({ name, ok: Boolean(ok) }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${!ok && detail ? ` (${detail})` : ""}`); };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const path = (page) => new URL(page.url()).pathname;
const noOverflow = (page) => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1);

// RFC 6238 with the panel's parameters, to act as the authenticator apps.
function base32(s) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32(secret)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0");
}
const stepNow = () => Math.floor(Date.now() / 30000);
const nextStep = async (used) => { while (stepNow() <= used) await sleep(1000); return stepNow(); };

// A JSON request from the page, with the session's CSRF token for a change.
const call = (page, method, url, body) => page.evaluate(async ({ method, url, body }) => {
  const headers = { Accept: "application/json" };
  if (method !== "GET") {
    const session = await (await fetch("/api/v1/session")).json();
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = session.csrf_token;
  }
  const response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: response.status, text: await response.text() };
}, { method, url, body });

// The controls only an admin may use, counted on the pages that carry them:
// Websites, one website's Settings (Simple view) and its Backups.
async function controlsOn(page, base, accountId) {
  const counts = {};
  const count = async (...ids) => { for (const id of ids) counts[id] = await page.getByTestId(id).count(); };
  await page.goto(base + "/websites");
  await page.getByTestId("websites-count").filter({ hasText: "website" }).waitFor();
  await count("new-website-link", "static-sites-link");
  await page.goto(base + `/websites/sites/${accountId}/settings`);
  await page.getByTestId("site-settings").waitFor();
  await count("site-action-php", "use-current-folder", "change-state", "delete-website");
  await page.goto(base + `/websites/sites/${accountId}/backups`);
  // The backups, or the problem that says why they could not be read.
  await page.locator('[data-testid="site-backups"][data-account-id], [data-testid="backups-problem"]').first().waitFor({ timeout: 60_000 });
  await count("back-up-now", "drill-now", "restore-snapshot", "go-backup-storage");
  return counts;
}

const remoteHost = httpsOrigin ? new URL(httpsOrigin).hostname : "";
const browser = await chromium.launch({ headless: true, ...(chrome ? { executablePath: chrome } : {}), ...(remoteHost ? { args: [`--host-resolver-rules=MAP ${remoteHost} 127.0.0.1`] } : {}) });
async function context(viewport = { width: 1440, height: 900 }) {
  const ctx = await browser.newContext({ viewport, ignoreHTTPSErrors: Boolean(httpsOrigin) });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  // Refusals are what this proof checks; the browser logs each one.
  page.on("console", (m) => { if (m.type() === "error" && !/\b(401|403|404|409|422|429)\b/.test(m.text())) errors.push(`console: ${m.text()}`); });
  return { ctx, page };
}

try {
  console.log("## Admin: first-run setup and sign-in");
  const { page: admin } = await context();
  await admin.goto(origin + "/customers");
  await admin.getByTestId("setup-key").waitFor();
  await admin.getByLabel("Access key", { exact: true }).fill(key);
  await admin.getByRole("button", { name: "Continue", exact: true }).click();
  await admin.getByTestId("setup-account").waitFor();
  await admin.getByLabel("Username", { exact: true }).fill("admin");
  await admin.getByLabel("Password", { exact: true }).fill(adminPassword);
  await admin.getByLabel("Password again", { exact: true }).fill(adminPassword);
  await admin.getByRole("button", { name: "Continue", exact: true }).click();
  await admin.getByTestId("setup-code").waitFor();
  const adminSecret = (await admin.getByTestId("setup-secret").innerText()).replace(/\s+/g, "");
  await admin.getByLabel("6-digit code from the app", { exact: true }).fill(totp(adminSecret, stepNow()));
  await admin.getByRole("button", { name: "Create admin account", exact: true }).click();
  // Argon2id is slow under the VM's software emulation.
  await admin.getByTestId("signed-in-as").waitFor({ timeout: 180_000 });
  check("the admin is signed in", true);

  console.log("## Two websites");
  let domains;
  if (sitesMode.startsWith("make:")) {
    const base = sitesMode.slice(5);
    domains = [`a.${base}`, `b.${base}`];
    for (const domain of domains) {
      const started = await call(admin, "POST", "/api/v1/websites/php", { domain, php_version: "8.3", database: "none" });
      const job = started.status === 202 ? JSON.parse(started.text).job : undefined;
      check(`the wizard starts a PHP site for ${domain}`, job, `HTTP ${started.status} ${started.text.slice(0, 300)}`);
      let state = job?.state;
      const since = Date.now();
      while (job && state !== "succeeded" && state !== "failed" && Date.now() - since < 15 * 60 * 1000) {
        await sleep(5000);
        state = JSON.parse((await call(admin, "GET", `/api/v1/websites/jobs/${job.id}`)).text).job.state;
      }
      check(`the site ${domain} is made`, state === "succeeded", state);
    }
  }
  const listed = JSON.parse((await call(admin, "GET", "/api/v1/websites/sites")).text).sites;
  if (!domains) domains = listed.slice(0, 2).map((s) => s.domain);
  const [siteA, siteB] = domains.map((d) => listed.find((s) => s.domain === d));
  check("the admin's list has both websites", siteA && siteB, JSON.stringify(listed.map((s) => s.domain)));
  console.log(`  websites: ${siteA?.domain} (the customer's) and ${siteB?.domain} (not the customer's)`);

  console.log("## Admin: a login for the first website");
  // The admin signed in on /customers, which read the website list before
  // the sites existed; opening Websites first, as an admin would, makes
  // Customers read it again.
  await admin.getByTestId("nav-websites").click();
  await admin.getByTestId("websites-count").filter({ hasText: "website" }).waitFor();
  await admin.getByTestId("nav-customers").click();
  await admin.getByTestId("create-login").waitFor();
  check("Customers opens the customer logins page at /customers", path(admin) === "/customers");
  check("the old hosting-accounts screen is in the menu, under Advanced", (await admin.getByTestId("nav-accounts").count()) === 1);
  await admin.getByTestId("login-username").fill(customer);
  // The picker lists the websites once they load; if they cannot be loaded
  // the page shows why instead, which the transcript must carry.
  const pick = admin.locator(`[data-testid=pick-website][data-domain="${siteA.domain}"]`);
  const sitesProblem = admin.getByTestId("customer-sites-problem");
  await pick.or(sitesProblem).first().waitFor({ timeout: 30000 }).catch(() => {});
  if (await sitesProblem.count()) {
    await admin.screenshot({ path: join(outDir, "1440-admin-websites-problem.png"), fullPage: true });
    console.log(`  the page could not list the websites: ${(await sitesProblem.innerText()).replace(/\s+/g, " ")}`);
  } else if (!(await pick.count())) {
    await admin.screenshot({ path: join(outDir, "1440-admin-no-website-to-pick.png"), fullPage: true });
    console.log(`  the form offered no ${siteA.domain} to pick; it shows: ${(await admin.getByTestId("create-login").innerText()).replace(/\s+/g, " ")}`);
  }
  await pick.check();
  await admin.getByTestId("create-login-submit").click();
  await admin.getByTestId("setup-link-panel").waitFor();
  const link = await admin.getByTestId("setup-link-value").inputValue();
  const linkPath = `/setup#${link.split("#")[1] ?? ""}`;
  check("the admin gets a one-time setup link with its secret after #", /\/setup#[A-Za-z0-9_-]{43}$/.test(link));
  await admin.screenshot({ path: join(outDir, "1440-admin-setup-link.png"), mask: [admin.getByTestId("setup-link-value")] });
  await admin.getByTestId("hide-setup-link").click();
  const row = admin.locator(`[data-testid=login-row][data-username="${customer}"]`);
  check("the new login waits for setup", (await row.getByTestId("login-state").innerText()).includes("Waiting for setup"));
  await admin.screenshot({ path: join(outDir, "1440-admin-customers.png") });

  console.log(`## Customer: setup from the link${httpsOrigin ? " over HTTPS" : ""}`);
  const { page: cust } = await context();
  await cust.goto(customerOrigin + linkPath);
  await cust.getByTestId("customer-setup-secret").waitFor();
  check("the setup page takes the secret out of the address bar", !cust.url().includes("#"));
  check("the password field asks for a new password", (await cust.locator("#customer-password").getAttribute("autocomplete")) === "new-password");
  const customerSecret = (await cust.getByTestId("customer-setup-secret").innerText()).replace(/\s+/g, "");
  await cust.screenshot({ path: join(outDir, "1440-customer-setup.png"), mask: [cust.getByTestId("customer-setup-secret")] });
  await cust.locator("#customer-password").fill(customerPassword);
  await cust.locator("#customer-code").fill(totp(customerSecret, stepNow() + 5));
  await cust.getByTestId("customer-setup-submit").click();
  await cust.getByText("That code did not match").waitFor({ timeout: 120_000 });
  check("a wrong code does not finish the setup", true);
  let used = stepNow();
  await cust.locator("#customer-code").fill(totp(customerSecret, used));
  await cust.getByTestId("customer-setup-submit").click();
  await cust.waitForURL((url) => url.pathname === "/websites", { timeout: 180_000 });
  await cust.getByTestId("websites-count").filter({ hasText: "website" }).waitFor();
  check("setup signs the customer in and opens Websites", path(cust) === "/websites");
  const again = await call(cust, "POST", "/api/v1/session/customer-setup/begin", { token: linkPath.split("#")[1] });
  check("the setup link works only once", again.status === 404, `HTTP ${again.status}`);

  console.log("## Customer: what it sees");
  const menu = await cust.locator('[data-slot="sidebar-menu-button"]').evaluateAll((items) => items.map((i) => i.textContent.trim()));
  check("the customer's menu is Home, Websites and Account", menu.join(",") === "Home,Websites,Account", menu.join(","));
  check("the customer sees one website", (await cust.getByTestId("websites-count").innerText()).trim() === "1 website");
  check(`the customer's list shows ${siteA.domain} and not ${siteB.domain}`, (await cust.getByText(siteA.domain).count()) > 0 && (await cust.getByText(siteB.domain).count()) === 0);
  await cust.screenshot({ path: join(outDir, "1440-customer-websites.png") });
  await cust.goto(customerOrigin + `/websites/sites/${siteA.account_id}`);
  await cust.getByText(siteA.domain).first().waitFor();
  check("the customer opens its own website's page", true);

  console.log("## Customer: only what it can use");
  const own = JSON.parse((await call(cust, "GET", "/api/v1/session")).text);
  check("the customer's session lists the routes it may use", Array.isArray(own.routes) && own.routes.includes("GET /api/v1/websites/sites") && !own.routes.includes("POST /api/v1/websites/sites/{account_id}/state"), JSON.stringify(own.routes ?? null).slice(0, 200));
  const offered = await controlsOn(cust, customerOrigin, siteA.account_id);
  for (const [name, n] of Object.entries(offered)) check(`the customer is not offered ${name}`, n === 0, String(n));
  await cust.screenshot({ path: join(outDir, "1440-customer-backups.png"), fullPage: true });

  console.log("## Customer: another website is refused");
  await cust.goto(customerOrigin + `/websites/sites/${siteB.account_id}`);
  await sleep(3000);
  check(`the address of ${siteB.domain} does not show it`, (await cust.getByText(siteB.domain).count()) === 0);
  await cust.screenshot({ path: join(outDir, "1440-customer-other-site.png") });
  const other = await call(cust, "GET", `/api/v1/websites/sites/${siteB.account_id}`);
  const missing = await call(cust, "GET", `/api/v1/websites/sites/${"d".repeat(32)}`);
  check("the API refuses the other website like one that does not exist", other.status === 404 && other.text === missing.text, `HTTP ${other.status}`);
  const change = await call(cust, "POST", `/api/v1/websites/sites/${siteB.account_id}/domain-add`, { domain: `grab.${siteB.domain}`, expected_revision: siteB.revision });
  check("a change to the other website is refused", change.status === 404, `HTTP ${change.status}`);
  for (const [method, url] of [["GET", "/api/v1/server"], ["GET", "/api/v1/accounts"], ["GET", "/api/v1/session/customers"], ["GET", "/api/v1/websites/jobs"], ["POST", `/api/v1/websites/sites/${siteA.account_id}/state`]]) {
    const answer = await call(cust, method, url, method === "POST" ? { state: "suspended", expected_revision: siteA.revision } : undefined);
    check(`the customer cannot use ${method} ${url}`, answer.status === 403, `HTTP ${answer.status}`);
  }
  await cust.goto(customerOrigin + "/customers");
  await cust.getByTestId("admin-page-notice").waitFor();
  check("an admin page shows a notice to the customer, not its data", true);

  console.log("## Customer: sign out and sign in again");
  await cust.goto(customerOrigin + "/account");
  await cust.getByTestId("account-username").waitFor();
  await cust.getByRole("button", { name: "Sign out", exact: true }).first().click();
  await cust.getByTestId("admin-sign-in").waitFor();
  used = await nextStep(used);
  await cust.getByLabel("Username", { exact: true }).fill(customer);
  await cust.getByLabel("Password", { exact: true }).fill(customerPassword);
  await cust.getByLabel("6-digit code", { exact: true }).fill(totp(customerSecret, used));
  await cust.getByRole("button", { name: "Sign in", exact: true }).click();
  await cust.getByTestId("signed-in-as").waitFor({ timeout: 180_000 });
  check("the customer signs in with its password and a fresh code", (await cust.getByTestId("signed-in-as").innerText()).includes(customer));
  const phone = await context({ width: 390, height: 844 });
  await phone.ctx.addCookies(await cust.context().cookies());
  await phone.page.goto(customerOrigin + "/websites", { waitUntil: "domcontentloaded", timeout: 60_000 });
  await phone.page.getByTestId("websites-count").filter({ hasText: "website" }).waitFor();
  check("the customer's Websites has no horizontal overflow at 390", await noOverflow(phone.page));
  await phone.page.screenshot({ path: join(outDir, "390-customer-websites.png") });

  console.log("## Customer: changes its password on Account");
  await cust.goto(customerOrigin + "/account");
  await cust.getByTestId("account-password-form").waitFor();
  check("Account offers the password and authenticator changes", (await cust.getByTestId("account-authenticator").count()) === 1);
  used = await nextStep(used);
  await cust.getByTestId("current-password").fill(customerPassword);
  await cust.getByTestId("new-password").fill(customerNewWords);
  await cust.getByTestId("password-code").fill(totp(customerSecret, used + 10));
  await cust.getByTestId("change-password-submit").click();
  await cust.getByTestId("password-problem").waitFor({ timeout: 180_000 });
  const refused = await cust.getByTestId("password-problem").innerText();
  check("a wrong current code is refused, saying what, why and what next", refused.includes("Your password was not changed") && refused.includes("wrong") && refused.includes("Next step"), refused);
  await cust.screenshot({ path: join(outDir, "1440-customer-password-refused.png") });
  await cust.getByTestId("password-code").fill(totp(customerSecret, used));
  await cust.getByTestId("change-password-submit").click();
  await cust.getByTestId("password-changed").filter({ hasText: "changed" }).waitFor({ timeout: 180_000 });
  check("the password change works and this session stays", (await call(cust, "GET", "/api/v1/session")).status === 200);
  const fresh = await context();
  await fresh.page.goto(customerOrigin + "/websites");
  await fresh.page.getByTestId("admin-sign-in").waitFor();
  used = await nextStep(used);
  const oldTry = await fresh.page.evaluate(async (body) => (await fetch("/api/v1/session/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).status,
    { username: customer, password: customerPassword, totp_code: totp(customerSecret, used) });
  check("the old password stops working", oldTry === 401, `HTTP ${oldTry}`);
  await fresh.page.getByLabel("Username", { exact: true }).fill(customer);
  await fresh.page.getByLabel("Password", { exact: true }).fill(customerNewWords);
  await fresh.page.getByLabel("6-digit code", { exact: true }).fill(totp(customerSecret, used));
  await fresh.page.getByRole("button", { name: "Sign in", exact: true }).click();
  await fresh.page.getByTestId("signed-in-as").waitFor({ timeout: 180_000 });
  check("the new password signs in", (await fresh.page.getByTestId("signed-in-as").innerText()).includes(customer));

  console.log("## Admin: view as the customer");
  await admin.goto(origin + "/customers");
  await row.getByTestId("view-as").click();
  await admin.getByTestId("view-as-banner").waitFor();
  const banner = await admin.getByTestId("view-as-banner").innerText();
  check("viewing as the customer shows a banner naming whose account it is", banner.includes(customer) && banner.includes("recorded as yours"), banner);
  await admin.getByTestId("websites-count").filter({ hasText: "website" }).waitFor();
  check("while viewing, the admin sees only the customer's website", (await admin.getByTestId("websites-count").innerText()).trim() === "1 website");
  check("while viewing, New website is not offered", (await admin.getByTestId("new-website-link").count()) === 0);
  const adminMenu = await admin.locator('[data-slot="sidebar-menu-button"]').evaluateAll((items) => items.map((i) => i.textContent.trim()));
  check("while viewing, the menu is the customer's", adminMenu.join(",") === "Home,Websites,Account", adminMenu.join(","));
  const viewing = await call(admin, "GET", `/api/v1/websites/sites/${siteB.account_id}`);
  check("while viewing, the other website is refused", viewing.status === 404, `HTTP ${viewing.status}`);
  await admin.screenshot({ path: join(outDir, "1440-admin-view-as.png") });
  const phoneAdmin = await context({ width: 390, height: 844 });
  await phoneAdmin.ctx.addCookies(await admin.context().cookies());
  await phoneAdmin.page.goto(origin + "/websites", { waitUntil: "domcontentloaded", timeout: 60_000 });
  await phoneAdmin.page.getByTestId("view-as-banner").waitFor();
  check("the banner fits at 390 with no horizontal overflow", await noOverflow(phoneAdmin.page));
  await phoneAdmin.page.screenshot({ path: join(outDir, "390-admin-view-as.png") });
  await admin.getByTestId("end-view-as").click();
  await admin.getByTestId("customers").waitFor();
  check("Back to admin view ends viewing and returns to Customers", (await admin.getByTestId("view-as-banner").count()) === 0 && path(admin) === "/customers");
  const both = JSON.parse((await call(admin, "GET", "/api/v1/websites/sites")).text).sites.length;
  check("the admin sees every website again", both >= 2, String(both));

  console.log("## Admin: the controls the customer is not offered");
  const adminOffered = await controlsOn(admin, origin, siteA.account_id);
  for (const name of ["new-website-link", "static-sites-link", "site-action-php", "change-state", "delete-website"]) check(`the admin is offered ${name}`, adminOffered[name] > 0, String(adminOffered[name]));
  check("the admin is offered Back up now, or Set up backup storage before any", adminOffered["back-up-now"] + adminOffered["go-backup-storage"] > 0, JSON.stringify(adminOffered));
  await admin.screenshot({ path: join(outDir, "1440-admin-backups.png"), fullPage: true });
  await admin.goto(origin + "/account");
  await admin.getByTestId("account-password-form").waitFor();
  check("the admin's menu has Account, with the same password change", (await admin.getByTestId("nav-account").count()) === 1 && (await admin.getByTestId("account-websites-list").count()) === 0);
  await admin.goto(origin + "/customers");
  await admin.getByTestId("customers").waitFor();

  console.log("## Admin: turn the login off");
  await row.getByTestId("toggle-login").click();
  await admin.getByTestId("customers-notice").waitFor();
  const ended = await call(cust, "GET", "/api/v1/session");
  check("turning the login off signs the customer out at once", ended.status === 401, `HTTP ${ended.status}`);

  check("no unexpected browser errors", errors.length === 0, errors.slice(0, 3).join(" | "));
} catch (error) {
  check("the browser run finished", false, error instanceof Error ? error.message.split("\n")[0] : String(error));
} finally {
  await browser.close();
}
const failed = checks.filter((c) => !c.ok).length;
console.log(`${checks.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
