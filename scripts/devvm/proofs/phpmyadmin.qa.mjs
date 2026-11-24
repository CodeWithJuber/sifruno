// Browser checks for phpMyAdmin's one-click sign-in, run by `proof.sh
// phpmyadmin` against a panel in the dev VM that runs as sifpanel with the
// real broker, MariaDB and phpMyAdmin behind OpenLiteSpeed. The panel has
// three addresses, each reached through an SSH forward: loopback (first-run
// setup with the access key), HTTPS for panel.proof.test (the admin), and
// phpMyAdmin's own HTTPS origin on another port. It makes two PHP sites with
// a database each, opens phpMyAdmin from the first one's Databases tab, and
// asks the VM (phpmyadmin.guest.sh) to check the temporary user and, later,
// that it expired. The access key is read from the seeded state and never
// printed; the admin's password, its authenticator key and the sites'
// database passwords exist only here.
//   node phpmyadmin.qa.mjs <loopback-origin> <panel-origin> <phpmyadmin-origin>
//     <state-dir> <out-dir> <domain> <vm.sh> <guest-dir> [chrome-executable]
import { createHmac, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";

const [loopback, panelOrigin, pmaOrigin, stateDir, outDir, domain, vmsh, guestDir, chrome] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const guest = "/opt/sifruno-proof/phpmyadmin.guest.sh";
const admissionCookie = "__Host-sifruno_phpmyadmin";
const key = readFileSync(join(stateDir, "operator/access.key"), "utf8").trim();
const panelPassword = `qa ${randomBytes(12).toString("hex")}`;
const checks = [];
const errors = [];
const check = (name, ok, detail = "") => { checks.push({ name, ok: Boolean(ok) }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${!ok && detail ? ` (${detail})` : ""}`); };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// RFC 6238 with the panel's parameters, to act as the admin's authenticator app.
function base32(s) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
const step = () => Math.floor(Date.now() / 30000);
function totp(secret) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step()));
  const h = createHmac("sha1", base32(secret)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0");
}

// The VM's own checks; their PASS and FAIL lines go to the transcript.
function guestStep(args) {
  try {
    execFileSync(vmsh, ["ssh", `${guest} ${args}`], { stdio: "inherit" });
    return true;
  } catch {
    return false;
  }
}

const host = new URL(panelOrigin).hostname;
const browser = await chromium.launch({ headless: true, args: [`--host-resolver-rules=MAP ${host} 127.0.0.1`], ...(chrome ? { executablePath: chrome } : {}) });
try {
  // The certificate is the panel's self-signed one.
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => { if (m.type() === "error" && !/\b(401|409|422)\b/.test(m.text())) errors.push(`console: ${m.text()}`); });
  const signonURLs = [];
  ctx.on("request", (r) => { if (r.url().includes("/sifruno-signon.php?code=")) signonURLs.push(r.url()); });

  console.log("## Browser: phpMyAdmin's origin without a code or an admission");
  const stranger = await browser.newContext({ ignoreHTTPSErrors: true });
  const anon = await stranger.newPage();
  const anonAnswer = await anon.goto(`${pmaOrigin}/index.php`);
  check("phpMyAdmin's origin answers 401 with a page that says to open phpMyAdmin from the panel", anonAnswer?.status() === 401 && (await anon.locator("h1").innerText()) === "phpMyAdmin needs a new sign-in.");
  await anon.screenshot({ path: join(outDir, "1440-phpmyadmin-no-admission.png") });
  await stranger.close();

  console.log("## Browser: first-run setup on the server's loopback address, then the admin over HTTPS");
  await page.goto(loopback + "/websites");
  await page.getByTestId("setup-key").waitFor();
  await page.getByLabel("Access key", { exact: true }).fill(key);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByTestId("setup-account").waitFor();
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page.getByLabel("Password", { exact: true }).fill(panelPassword);
  await page.getByLabel("Password again", { exact: true }).fill(panelPassword);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByTestId("setup-code").waitFor();
  const secret = (await page.getByTestId("setup-secret").innerText()).replace(/\s+/g, "");
  await page.getByLabel("6-digit code from the app", { exact: true }).fill(totp(secret));
  let lastStep = step();
  await page.getByRole("button", { name: "Create admin account", exact: true }).click();
  await page.getByTestId("signed-in-as").waitFor({ timeout: 180_000 });
  check("the admin account is made on the server", true);
  // Each sign-in needs a code from a later 30-second step than the last one.
  const signIn = async () => {
    while (step() <= lastStep) await sleep(1000);
    lastStep = step();
    await page.goto(panelOrigin + "/");
    return page.evaluate(async ({ password, code }) => (await fetch("/api/v1/session/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "admin", password, totp_code: code }) })).status,
      { password: panelPassword, code: totp(secret) });
  };
  check("the admin signs in over HTTPS", (await signIn()) === 200);

  console.log("## Two PHP sites, each with its own database");
  const sites = [];
  for (const name of [`a-${domain}`, `b-${domain}`]) {
    const dbPassword = randomBytes(15).toString("base64url");
    const made = await page.evaluate(async ({ name, dbPassword }) => {
      const session = await (await fetch("/api/v1/session")).json();
      const r = await fetch("/api/v1/websites/php", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrf_token },
        body: JSON.stringify({ domain: name, php_version: "8.3", database: "create", database_password: dbPassword }) });
      return { status: r.status, body: await r.json() };
    }, { name, dbPassword });
    const jobId = made.body?.job?.id;
    check(`the wizard starts ${name}`, made.status === 202, `${made.status} ${JSON.stringify(made.body).slice(0, 200)}`);
    let job;
    const started = Date.now();
    while (jobId && Date.now() - started < 15 * 60 * 1000) {
      job = (await page.evaluate(async (id) => (await fetch(`/api/v1/websites/jobs/${id}`)).json(), jobId)).job;
      if (job?.state === "succeeded" || job?.state === "failed") break;
      await sleep(5000);
    }
    console.log(`  ${name}: ${job?.state ?? "no job"} after ${Math.round((Date.now() - started) / 1000)} s, account ${job?.username ?? "?"}`);
    check(`${name} is made, with the database ${job?.username}_wp`, job?.state === "succeeded" && job?.result?.database?.startsWith(`${job.username}_wp`), job?.error ? JSON.stringify(job.error).slice(0, 300) : "");
    sites.push({ domain: name, user: job?.username, id: job?.result?.account_id });
  }
  const [a, b] = sites;
  // A fresh 15-minute panel session for the click.
  check("the admin signs in again", (await signIn()) === 200);

  console.log("## The panel's origin no longer serves phpMyAdmin");
  const onPanel = await page.evaluate(async () => (await fetch("/api/v1/phpmyadmin/")).status);
  check("the panel answers 404 for /api/v1/phpmyadmin/ to a signed-in admin", onPanel === 404, String(onPanel));

  console.log(`## Browser: Open phpMyAdmin on ${a.domain}'s Databases tab`);
  await page.goto(`${panelOrigin}/websites/sites/${a.id}/databases`);
  const button = page.getByTestId("open-phpmyadmin");
  await button.waitFor({ timeout: 30000 });
  check("the Databases tab has an Open phpMyAdmin button", (await button.innerText()).includes("Open phpMyAdmin") && !(await button.isDisabled()));
  check("it says phpMyAdmin opens on its own address, for this website's databases only", (await page.getByTestId("open-phpmyadmin-hint").innerText()).includes("phpMyAdmin's own address, signed in to this website's databases only"));
  await page.screenshot({ path: join(outDir, "1440-databases-tab.png"), fullPage: true });
  const [tab] = await Promise.all([ctx.waitForEvent("page"), button.click()]);
  const tabErrors = [];
  tab.on("console", (m) => { if (m.type() === "error") tabErrors.push(m.text()); });
  tab.on("pageerror", (e) => tabErrors.push(e.message));
  await tab.waitForURL((u) => u.origin === pmaOrigin && u.pathname === "/index.php", { timeout: 60000 });
  await tab.locator("#pma_navigation_tree").waitFor({ timeout: 60000 });
  await tab.waitForLoadState("networkidle").catch(() => {});
  check("one click lands in phpMyAdmin on its own origin, signed in (its database tree, no login form)", (await tab.locator("#input_username").count()) === 0);
  check("the new tab has no opener", await tab.evaluate(() => window.opener === null));
  check("the sign-in link was on phpMyAdmin's origin, opened once, with a code", signonURLs.length === 1 && signonURLs[0].startsWith(`${pmaOrigin}/sifruno-signon.php?code=`) && /\?code=[A-Za-z0-9_-]{43}$/.test(signonURLs[0]), signonURLs.join(" "));
  const tree = (await tab.locator("#pma_navigation_tree").innerText()).replace(/\s+/g, " ");
  console.log(`  phpMyAdmin's database tree: ${tree.slice(0, 300)}`);
  check(`it lists ${a.user}_wp`, tree.includes(`${a.user}_wp`));
  check(`it does not list ${b.user}_wp, the other website's`, !tree.includes(`${b.user}_wp`));
  const csp = await tab.evaluate(async () => (await fetch(location.href)).headers.get("content-security-policy"));
  check("phpMyAdmin's pages may connect and post only to their own origin", csp?.includes("connect-src 'self'") && csp.includes("form-action 'self'") && csp.includes("frame-ancestors 'none'"), csp ?? "none");
  check("no script or style was blocked on phpMyAdmin's page", !tabErrors.some((t) => /Content Security Policy/i.test(t)), tabErrors.slice(0, 2).join(" | "));
  const pmaCookies = await ctx.cookies(pmaOrigin);
  const admission = pmaCookies.find((c) => c.name === admissionCookie);
  check("the admission cookie is __Host-, HttpOnly, Secure, SameSite=Strict, Path=/, ending within the hour",
    admission && admission.httpOnly && admission.secure && admission.sameSite === "Strict" && admission.path === "/" && admission.expires > Date.now() / 1000 && admission.expires <= Date.now() / 1000 + 3600,
    JSON.stringify(admission ?? {}));
  check("the panel's session cookie stays on /api/v1", (await ctx.cookies(panelOrigin)).filter((c) => c.name === "sifruno_operator").every((c) => c.path === "/api/v1"));
  await tab.screenshot({ path: join(outDir, "1440-phpmyadmin-signed-in.png") });

  console.log("## phpMyAdmin's origin cannot use the panel's API");
  const fromTab = await tab.evaluate(async (url) => {
    try { const r = await fetch(url, { credentials: "include" }); return `answered ${r.status}`; } catch (e) { return `blocked: ${e.name}`; }
  }, `${panelOrigin}/api/v1/session`);
  check("a fetch from a phpMyAdmin page to the panel's API gets nothing", fromTab.startsWith("blocked"), fromTab);
  const withOrigin = await ctx.request.get(`${panelOrigin}/api/v1/session`, { headers: { Origin: pmaOrigin, "Sec-Fetch-Site": "same-site" } });
  const without = await ctx.request.get(`${panelOrigin}/api/v1/session`);
  check("the panel refuses its API to a request from phpMyAdmin's origin, cookie and all (403)", withOrigin.status() === 403 && without.status() === 200, `${withOrigin.status()} / ${without.status()}`);
  const post = await ctx.request.post(`${panelOrigin}/api/v1/websites/sites/${a.id}/databases/phpmyadmin`, { headers: { Origin: pmaOrigin, "Content-Type": "application/json" }, data: "{}" });
  check("and refuses a change from there too", post.status() === 403, String(post.status()));
  check("there are no CORS headers on the panel's answer", !withOrigin.headers()["access-control-allow-origin"]);
  const apiThere = await ctx.request.get(`${pmaOrigin}/api/v1/session`);
  check("phpMyAdmin's origin answers 404 for the panel's API path", apiThere.status() === 404, String(apiThere.status()));

  console.log("## Browser: the same link again, and the admission cookie alone");
  const again = await ctx.newPage();
  const reused = await again.goto(signonURLs[0] ?? `${pmaOrigin}/sifruno-signon.php?code=${"A".repeat(43)}`);
  check("a used code is refused (403, and says to open phpMyAdmin again)", reused?.status() === 403 && (await again.locator("h1").innerText()) === "This phpMyAdmin link no longer works.");
  await again.screenshot({ path: join(outDir, "1440-phpmyadmin-code-reused.png") });
  const alone = await again.goto(`${pmaOrigin}/index.php`);
  await again.locator("#pma_navigation_tree").waitFor({ timeout: 30000 }).catch(() => {});
  check("the admission cookie alone, with no code, lets the browser back in", alone?.status() === 200 && (await again.locator("#pma_navigation_tree").count()) === 1);

  console.log("## VM: the temporary user and its password");
  check("the VM's checks of the temporary user pass", guestStep(`check ${guestDir} ${a.user} ${b.user}`));

  console.log("## VM: the temporary user expires (proof build: 2 minutes)");
  check("the VM sees the sweeper drop it", guestStep("expire"));
  const after = await again.goto(`${pmaOrigin}/index.php`);
  check("then the admission cookie no longer lets the browser in (401)", after?.status() === 401 && (await again.locator("h1").innerText()) === "phpMyAdmin needs a new sign-in.");
  await again.screenshot({ path: join(outDir, "1440-phpmyadmin-expired.png") });
  await tab.reload();
  check("the open phpMyAdmin tab asks for a new sign-in too", (await tab.locator("h1").first().innerText().catch(() => "")).trim() === "phpMyAdmin needs a new sign-in.");

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await page.getByTestId("open-phpmyadmin").waitFor({ timeout: 30000 });
  check("the Databases tab fits a phone screen", await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await page.screenshot({ path: join(outDir, "390-databases-tab.png"), fullPage: true });
  check("no browser errors on the panel's pages", errors.length === 0, errors.slice(0, 3).join(" | "));
} catch (e) {
  check("the browser run finished", false, String(e).slice(0, 300));
} finally {
  await browser.close();
}
const failed = checks.filter((c) => !c.ok).length;
console.log(`RESULT (browser): ${checks.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
