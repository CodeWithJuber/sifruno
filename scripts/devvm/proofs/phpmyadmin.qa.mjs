// Browser checks for phpMyAdmin's one-click sign-in, run by `proof.sh
// phpmyadmin` against a panel in the dev VM that runs as sifpanel with the
// real broker, MariaDB and phpMyAdmin behind OpenLiteSpeed. It makes two PHP
// sites with a database each, opens phpMyAdmin from the first one's
// Databases tab, and asks the VM (phpmyadmin.guest.sh) to check the
// temporary user and, later, that it expired. The panel's access key is read
// from the seeded state and never printed; the admin's password, its
// authenticator key and the sites' database passwords exist only here.
//   node phpmyadmin.qa.mjs <origin> <state-dir> <out-dir> <domain> <vm.sh>
//     <guest-dir> [chrome-executable]
import { createHmac, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";

const [origin, stateDir, outDir, domain, vmsh, guestDir, chrome] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const guest = "/opt/sifruno-proof/phpmyadmin.guest.sh";
const key = readFileSync(join(stateDir, "operator/access.key"), "utf8").trim();
const panelPassword = `qa ${randomBytes(12).toString("hex")}`;
const checks = [];
const errors = [];
const check = (name, ok, detail = "") => { checks.push({ name, ok: Boolean(ok) }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${!ok && detail ? ` (${detail})` : ""}`); };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const base = "/api/v1/phpmyadmin/";

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

const browser = await chromium.launch({ headless: true, ...(chrome ? { executablePath: chrome } : {}) });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => { if (m.type() === "error" && !/\b(401|409|422)\b/.test(m.text())) errors.push(`console: ${m.text()}`); });
  const signonURLs = [];
  ctx.on("request", (r) => { if (r.url().includes("sifruno-signon.php?code=")) signonURLs.push(r.url()); });

  console.log("## Browser: without a panel sign-in, phpMyAdmin does not open");
  const stranger = await browser.newContext();
  const anon = await stranger.newPage();
  const anonAnswer = await anon.goto(origin + base);
  check("the panel answers 401 with a page that says to sign in", anonAnswer?.status() === 401 && (await anon.locator("h1").innerText()) === "You are not signed in to the panel.");
  await anon.screenshot({ path: join(outDir, "1440-phpmyadmin-not-signed-in.png") });
  await stranger.close();

  console.log("## Browser: first-run setup and sign-in");
  await page.goto(origin + "/websites");
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
  const setupStep = step();
  await page.getByRole("button", { name: "Create admin account", exact: true }).click();
  await page.getByTestId("signed-in-as").waitFor({ timeout: 180_000 });
  check("the admin signs in to the panel", true);

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
    check(`the wizard starts ${name}`, made.status === 202 || made.status === 201 || made.status === 200, `${made.status} ${JSON.stringify(made.body).slice(0, 200)}`);
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

  // The panel's sign-in lasts 15 minutes and the sites took a while: sign
  // in again, with a code from a later 30-second step than the last one.
  while (step() <= setupStep) await sleep(1000);
  const relogin = await page.evaluate(async ({ password, code }) => {
    const r = await fetch("/api/v1/session/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "admin", password, totp_code: code }) });
    return r.status;
  }, { password: panelPassword, code: totp(secret) });
  check("the admin signs in again for a fresh 15-minute session", relogin === 200, String(relogin));

  console.log(`## Browser: Open phpMyAdmin on ${a.domain}'s Databases tab`);
  await page.goto(`${origin}/websites/sites/${a.id}/databases`);
  const button = page.getByTestId("open-phpmyadmin");
  await button.waitFor({ timeout: 30000 });
  check("the Databases tab has an Open phpMyAdmin button", (await button.innerText()).includes("Open phpMyAdmin") && !(await button.isDisabled()));
  check("it says phpMyAdmin opens signed in to this website's databases only", (await page.getByTestId("open-phpmyadmin-hint").innerText()).includes("this website's databases only"));
  await page.screenshot({ path: join(outDir, "1440-databases-tab.png"), fullPage: true });
  const [tab] = await Promise.all([ctx.waitForEvent("page"), button.click()]);
  const tabErrors = [];
  tab.on("console", (m) => { if (m.type() === "error") tabErrors.push(m.text()); });
  tab.on("pageerror", (e) => tabErrors.push(e.message));
  await tab.waitForURL((u) => u.pathname === `${base}index.php`, { timeout: 60000 });
  await tab.locator("#pma_navigation_tree").waitFor({ timeout: 60000 });
  await tab.waitForLoadState("networkidle").catch(() => {});
  check("one click lands in phpMyAdmin, signed in (its database tree, no login form)", (await tab.locator("#input_username").count()) === 0);
  check("the new tab has no opener", await tab.evaluate(() => window.opener === null));
  check("the sign-in link was opened once, with a code", signonURLs.length === 1 && /\?code=[A-Za-z0-9_-]{43}$/.test(signonURLs[0]), String(signonURLs.length));
  check("the address bar shows no code once signed in", !tab.url().includes("code="));
  const tree = (await tab.locator("#pma_navigation_tree").innerText()).replace(/\s+/g, " ");
  console.log(`  phpMyAdmin's database tree: ${tree.slice(0, 300)}`);
  check(`it lists ${a.user}_wp`, tree.includes(`${a.user}_wp`));
  check(`it does not list ${b.user}_wp, the other website's`, !tree.includes(`${b.user}_wp`));
  const csp = await tab.evaluate(async () => (await fetch(location.href)).headers.get("content-security-policy"));
  check("phpMyAdmin's pages get phpMyAdmin's policy from the panel", csp?.includes("'unsafe-eval'") && csp.includes("frame-ancestors 'none'"), csp ?? "none");
  const panelCSP = await page.evaluate(async () => (await fetch("/api/v1/session")).headers.get("content-security-policy"));
  check("the panel's own routes keep their strict policy", panelCSP?.includes("script-src 'self';") && !panelCSP.includes("unsafe"), panelCSP ?? "none");
  const cookies = await ctx.cookies(origin);
  const stray = cookies.filter((c) => c.name !== "sifruno_operator" && !c.path.startsWith(base));
  check("phpMyAdmin's cookies stay under /api/v1/phpmyadmin/ and the panel keeps one session cookie", stray.length === 0 && cookies.filter((c) => c.name === "sifruno_operator").length === 1, cookies.map((c) => `${c.name}@${c.path}`).join(" "));
  check("no script or style was blocked on phpMyAdmin's page", !tabErrors.some((t) => /Content Security Policy/i.test(t)), tabErrors.slice(0, 2).join(" | "));
  await tab.setViewportSize({ width: 1440, height: 900 });
  await tab.screenshot({ path: join(outDir, "1440-phpmyadmin-signed-in.png") });

  console.log("## Browser: the same link again");
  const again = await ctx.newPage();
  const reused = await again.goto(signonURLs[0] ?? `${origin}${base}sifruno-signon.php?code=${"A".repeat(43)}`);
  check("a used code is refused (403, and says to open phpMyAdmin again)", reused?.status() === 403 && (await again.locator("h1").innerText()) === "This phpMyAdmin link no longer works.");
  await again.screenshot({ path: join(outDir, "1440-phpmyadmin-code-reused.png") });
  await again.close();

  console.log("## VM: the temporary user and its password");
  check("the VM's checks of the temporary user pass", guestStep(`check ${guestDir} ${a.user} ${b.user}`));

  console.log("## VM: the temporary user expires (proof build: 2 minutes)");
  check("the VM sees the sweeper drop it", guestStep("expire"));
  await tab.reload();
  await tab.waitForLoadState("load");
  const ended = (await tab.locator("h1").first().innerText().catch(() => "")).trim();
  console.log(`  phpMyAdmin after the expiry: ${tab.url()} "${ended}"`);
  check("phpMyAdmin then sends the browser to the sign-in script, which asks for a new sign-in", new URL(tab.url()).pathname === `${base}sifruno-signon.php` && ended === "phpMyAdmin needs a new sign-in.");
  await tab.screenshot({ path: join(outDir, "1440-phpmyadmin-expired.png") });

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
