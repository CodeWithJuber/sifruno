// Browser checks for the New website wizard, run by `proof.sh
// wordpress-wizard` against a panel in the dev VM that runs as sifpanel with
// the real broker and MariaDB. It reads the panel state's operator key for
// first-run setup and never prints it; the admin's panel password, its
// authenticator key and the WordPress admin password exist only in this
// process, which also checks that the job record never holds the last one.
//   node wordpress-wizard.qa.mjs <origin> <state-dir> <out-dir> <domain>
//     <vm.sh> <guest-jobs-file> [chrome-executable]
import { createHmac, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";

const [origin, stateDir, outDir, domain, vmsh, guestJobs, chrome] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const key = readFileSync(join(stateDir, "operator/access.key"), "utf8").trim();
const panelPassword = `qa ${randomBytes(12).toString("hex")}`;
const wpPassword = randomBytes(15).toString("base64url");
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
function totp(secret) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac("sha1", base32(secret)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0");
}

const browser = await chromium.launch({ headless: true, ...(chrome ? { executablePath: chrome } : {}) });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => { if (m.type() === "error" && !/\b(401|409|422)\b/.test(m.text())) errors.push(`console: ${m.text()}`); });

  console.log("## Browser: sign in and open the wizard");
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
  await page.getByRole("button", { name: "Create admin account", exact: true }).click();
  // Creating the admin hashes the password with Argon2id, which takes far
  // longer under the VM's software emulation than on real hardware.
  await page.getByTestId("signed-in-as").waitFor({ timeout: 180_000 });
  check("the admin signs in to the panel", true);

  await page.getByTestId("new-website-link").click();
  await page.getByTestId("new-website-form").waitFor();
  check("Websites has a New website button that opens the wizard at /websites/new", new URL(page.url()).pathname === "/websites/new");
  check("the website type is WordPress", (await page.getByTestId("website-type").innerText()).trim() === "WordPress");
  const pw = page.locator("#nw-admin-password");
  check("the admin password field asks for a new password", (await pw.getAttribute("autocomplete")) === "new-password");
  check("the admin email and username fields autofill correctly",
    (await page.locator("#nw-admin-email").getAttribute("autocomplete")) === "email" && (await page.locator("#nw-admin-user").getAttribute("autocomplete")) === "username");

  // Feedback only after the person leaves a field.
  const domainField = page.locator("#nw-domain");
  await domainField.fill("not a domain");
  check("no error while typing", (await domainField.getAttribute("aria-invalid")) !== "true");
  await domainField.blur();
  await page.waitForTimeout(300);
  check("a bad domain is marked after leaving the field", (await domainField.getAttribute("aria-invalid")) === "true");

  await domainField.fill(domain);
  await page.locator("#nw-title").fill("Sifruno wizard proof");
  await page.locator("#nw-admin-user").fill("wizardadmin");
  await page.locator("#nw-admin-email").fill(`admin@${domain}`);
  await pw.fill(wpPassword);
  await page.screenshot({ path: join(outDir, "1440-light-new-website.png"), mask: [pw] });

  console.log("## Browser: create the site and follow the job");
  await page.getByTestId("create-website").click();
  await page.waitForURL(/\/websites\/jobs\/[0-9a-f]{32}$/, { timeout: 60000 });
  const jobId = new URL(page.url()).pathname.split("/").pop();
  check("Create starts a job and opens its page", /^[0-9a-f]{32}$/.test(jobId));
  check("the form's password is not in the URL", !page.url().includes(wpPassword));
  await page.getByTestId("job-steps").waitFor();
  await page.screenshot({ path: join(outDir, "1440-light-job-running.png") });

  const started = Date.now();
  let state = "running";
  // The step list shows while the job runs; the last screen replaces it.
  // Remember every list of step states seen, to check the HTTPS step's.
  const seenStates = [];
  while (Date.now() - started < 20 * 60 * 1000) {
    if (await page.getByTestId("job-succeeded").count()) { state = "succeeded"; break; }
    if (await page.getByTestId("job-failed").count()) { state = "failed"; break; }
    const states = await page.getByTestId("job-steps").locator("li").evaluateAll((items) => items.map((li) => li.getAttribute("data-state"))).catch(() => []);
    if (states.length) seenStates.push(states.join(" "));
    await sleep(5000);
  }
  console.log(`  the job ended ${state} after ${Math.round((Date.now() - started) / 1000)} s`);
  if (state === "failed") console.log(`  shown: ${(await page.getByTestId("job-failed").innerText()).replace(/\s+/g, " ").slice(0, 600)}`);
  check("the job succeeds and the page shows the last screen", state === "succeeded");
  await page.screenshot({ path: join(outDir, "1440-light-job-done.png") });

  if (state === "succeeded") {
    check("the last screen names the domain", (await page.getByRole("heading", { level: 2 }).innerText()).includes(`${domain} is ready`));
    const user = (await page.getByTestId("job-username").innerText()).trim();
    const version = (await page.getByTestId("job-wordpress-version").innerText()).trim();
    console.log(`  hosting account ${user}, WordPress ${version}`);
    check("it shows the hosting account and the WordPress version", /^[a-z][a-z0-9_]{2,31}$/.test(user) && /^\d+\.\d+/.test(version));
    // The HTTPS step is found by its name in the job and on the page by its
    // place and state, so the check does not depend on the step's title.
    const job = (await page.evaluate(async (id) => (await fetch(`/api/v1/websites/jobs/${id}`)).json(), jobId)).job;
    const names = job.steps.map((s) => s.name);
    const ssl = job.steps.find((s) => s.name === "ssl");
    console.log(`  steps: ${job.steps.map((s) => `${s.name} ${s.state}`).join(", ")}`);
    check("the steps include HTTPS, after the site goes live and before the database",
      names.includes("ssl") && names.indexOf("ssl") === names.indexOf("web") + 1 && names.indexOf("database") === names.indexOf("ssl") + 1, names.join(" "));
    check("the HTTPS step is done, with a certificate from the test CA", ssl?.state === "done", ssl ? `${ssl.state}: ${ssl.message}` : "no ssl step");
    // The HTTPS step is the third: while WordPress installed, the list showed it done.
    const sslIndex = job.steps.findIndex((s) => s.name === "ssl");
    check("while the job ran, the step list showed the HTTPS step's state",
      seenStates.some((line) => line.split(" ")[sslIndex] === ssl?.state), seenStates.at(-1) ?? "never seen");
    const protocol = (await page.getByTestId("site-protocol").innerText()).trim();
    check(`the last screen says the site uses ${ssl?.state === "done" ? "https" : "http"}`, protocol.includes(ssl?.state === "done" ? "uses https" : "uses http"), protocol);
    const scheme = ssl?.state === "done" ? "https" : "http";
    check(`Open site points at the new site over ${scheme}`, (await page.getByTestId("open-site").getAttribute("href")) === `${scheme}://${domain}/`);
    check(`Open WordPress admin points at wp-admin over ${scheme}`, (await page.getByTestId("open-admin").getAttribute("href")) === `${scheme}://${domain}/wp-admin/`);
    await page.getByTestId("set-up-dns").click();
    check("Set up DNS explains the record to add", (await page.getByTestId("dns-help").innerText()).includes(domain));
    await page.reload();
    await page.getByTestId("job-succeeded").waitFor({ timeout: 30000 });
    check("the job page still shows the result after a reload", true);
    await page.setViewportSize({ width: 390, height: 844 });
    check("the result fits a phone screen", await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({ path: join(outDir, "390-light-job-done.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 900 });

    console.log("## Browser: the new site in Websites");
    await page.getByTestId("go-to-websites").click();
    await page.getByTestId("websites-table").waitFor({ timeout: 30000 });
    check("Go to Websites on the last screen opens /websites", new URL(page.url()).pathname === "/websites");
    const row = page.locator(`[data-testid="website-row"][data-domain="${domain}"]`);
    check("Websites lists the new domain", (await row.count()) === 1);
    check("its status badge says Live", (await row.getByTestId("website-status").innerText()).trim() === "Live");
    const httpsBadge = row.getByTestId("website-https");
    check("it has an https badge with the certificate's expiry", (await httpsBadge.getAttribute("data-https")) === "on" && (await row.getByTestId("website-https-until").innerText()).startsWith("until "),
      `${await httpsBadge.getAttribute("data-https")}: ${(await row.innerText()).replace(/\s+/g, " ")}`);
    check("the list shows the site's WordPress version", (await row.getByTestId("website-wordpress").innerText()).trim() === version);
    check("Open site in the list is https", (await row.getByTestId("open-site").getAttribute("href")) === `https://${domain}/`);
    await page.screenshot({ path: join(outDir, "1440-light-websites.png"), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    check("the list fits a phone screen", await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({ path: join(outDir, "390-light-websites.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 900 });

    await row.getByTestId("website-details-link").click();
    await page.getByTestId("website-overview").waitFor({ timeout: 30000 });
    check("Details opens /websites/sites/<account id>", new URL(page.url()).pathname === `/websites/sites/${job.result.account_id}`, new URL(page.url()).pathname);
    check("the site page shows the WordPress version", (await page.getByTestId("website-wordpress").innerText()).trim() === version);
    check("the site page shows the hosting account", (await page.getByTestId("website-username").innerText()).trim() === user);
    check("the site page's Open site is https", (await page.getByTestId("open-site").getAttribute("href")) === `https://${domain}/`);
    await page.screenshot({ path: join(outDir, "1440-light-website-overview.png"), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    check("the site page fits a phone screen", await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({ path: join(outDir, "390-light-website-overview.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 900 });
  }

  console.log("## Browser: the same domain again is refused");
  await page.goto(origin + "/websites/new");
  await page.getByTestId("new-website-form").waitFor();
  await page.locator("#nw-domain").fill(domain);
  await page.locator("#nw-title").fill("Twice");
  await page.locator("#nw-admin-user").fill("wizardadmin");
  await page.locator("#nw-admin-email").fill(`admin@${domain}`);
  await page.locator("#nw-admin-password").fill(wpPassword);
  await page.getByTestId("create-website").click();
  await page.getByTestId("new-website-problem").waitFor({ timeout: 30000 });
  const problem = (await page.getByTestId("new-website-problem").innerText()).replace(/\s+/g, " ");
  console.log(`  shown: ${problem.slice(0, 200).trimEnd()}`);
  check("a second site for the same domain is refused with a reason", problem.length > 10 && new URL(page.url()).pathname === "/websites/new");

  console.log("## The password is held nowhere");
  const listed = await page.evaluate(async () => (await fetch("/api/v1/websites/jobs")).text());
  check("the jobs API never returns the WordPress admin password", listed.includes(jobId) && !listed.includes(wpPassword));
  const sites = await page.evaluate(async () => (await fetch("/api/v1/websites/sites")).text());
  check("the websites API never returns it either", sites.includes(domain) && !sites.includes(wpPassword));
  const stored = await page.evaluate(() => JSON.stringify({ ...sessionStorage }) + JSON.stringify({ ...localStorage }));
  check("the browser's storage holds no password", !stored.includes(wpPassword) && !stored.includes(panelPassword));
  const local = join(outDir, "jobs.json");
  execFileSync(vmsh, ["get", guestJobs, local]);
  const file = readFileSync(local, "utf8");
  check("the job file on the server never holds the WordPress admin password", file.includes(jobId) && !file.includes(wpPassword));
  check("no browser errors", errors.length === 0, errors.slice(0, 3).join(" | "));
} catch (e) {
  check("the browser run finished", false, String(e).slice(0, 300));
} finally {
  await browser.close();
}
const failed = checks.filter((c) => !c.ok).length;
console.log(`RESULT (browser): ${checks.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
