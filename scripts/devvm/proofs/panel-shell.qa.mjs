// Browser checks for the Phase 1 panel shell and admin sign-in, run by
// `proof.sh panel-shell` against a panel with throwaway state. It reads that
// state's operator key for first-run setup and never prints it; the admin's
// password and authenticator key exist only in this process.
//   node panel-shell.qa.mjs <origin> <state-dir> <out-dir> [chrome-executable]
//     [https-origin certificate-sha256]
// With the last two, it also signs in over the HTTPS listener: the host name
// in https-origin is mapped to 127.0.0.1 and the served certificate must
// have the fingerprint the panel printed.
import { createHmac, randomBytes } from "node:crypto";
import { connect } from "node:tls";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";

const [origin, stateDir, outDir, chrome, httpsOrigin, expectedFingerprint] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
let key = readFileSync(join(stateDir, "operator/access.key"), "utf8").trim();
const run = Date.now().toString(36);
const siteName = `Shell QA ${run}`;
const checks = [];
const errors = [];
const check = (name, ok, detail = "") => { checks.push({ name, ok: Boolean(ok), detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${!ok && detail ? ` (${detail})` : ""}`); };
const noOverflow = (page) => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1);
const path = (page) => new URL(page.url()).pathname;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const password = `qa ${randomBytes(12).toString("hex")}`;

// RFC 6238 with the panel's parameters, to act as the admin's authenticator app.
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

const remoteHost = httpsOrigin ? new URL(httpsOrigin).hostname : "";
const browser = await chromium.launch({ headless: true, ...(chrome ? { executablePath: chrome } : {}), ...(remoteHost ? { args: [`--host-resolver-rules=MAP ${remoteHost} 127.0.0.1`] } : {}) });
async function context(viewport, preview = false, options = {}) {
  const ctx = await browser.newContext({ viewport, ...options });
  if (preview) {
    await ctx.route((url) => url.origin === origin && !url.pathname.startsWith("/api/") && !url.pathname.includes("."), async (route) => {
      const response = await route.fetch();
      const body = (await response.text()).replace("<head>", '<head><meta name="sifruno-public-preview" content="true">');
      await route.fulfill({ response, body });
    });
  }
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  // Refused sign-ins (401, 422, 429) are expected here; the browser logs each one.
  page.on("console", (m) => { if (m.type() === "error" && !/\b(401|403|421|422|429)\b|Unauthorized/.test(m.text())) errors.push(`console: ${m.text()}`); });
  return { ctx, page };
}

try {
  // Desktop, light.
  const { ctx, page } = await context({ width: 1440, height: 900 });
  await page.goto(origin + "/");
  await page.getByRole("heading", { name: "Server monitoring" }).waitFor();
  const topLevel = await page.locator('[data-slot="sidebar-menu-button"]').count();
  check("sidebar has 8 top-level items", topLevel === 8, `found ${topLevel}`);
  check("no Compatibility or Platforms in menu", (await page.getByTestId("nav-evidence").count()) + (await page.getByTestId("nav-platform").count()) === 0);
  check("home has no horizontal overflow at 1440", await noOverflow(page));
  await page.screenshot({ path: join(outDir, "1440-light-home.png") });

  await page.getByTestId("nav-websites").click();
  check("Websites menu item opens /websites", path(page) === "/websites", path(page));
  // First-run setup: access key, then username and password, then 2FA.
  await page.getByTestId("setup-key").waitFor();
  check("a fresh panel asks for first-run setup on a private page", true);
  await page.getByLabel("Access key", { exact: true }).fill(key);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByTestId("setup-account").waitFor();
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByLabel("Password again", { exact: true }).fill(password + "x");
  check("mismatched passwords are caught before sending", await page.getByText("The two passwords are different.").isVisible() && await page.getByRole("button", { name: "Continue", exact: true }).isDisabled());
  await page.getByLabel("Password again", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByTestId("setup-code").waitFor();
  const secret = (await page.getByTestId("setup-secret").innerText()).replace(/\s+/g, "");
  check("setup shows a 32-character authenticator key", /^[A-Z2-7]{32}$/.test(secret));
  const link = await page.getByRole("link", { name: "Open in authenticator app" }).getAttribute("href");
  check("setup offers an authenticator-app link for this admin", link.startsWith("otpauth://totp/Sifruno:admin?") && link.includes(`secret=${secret}`));
  await page.screenshot({ path: join(outDir, "1440-light-setup-code.png"), mask: [page.getByTestId("setup-secret")] });
  await page.getByLabel("6-digit code from the app", { exact: true }).fill(totp(secret, stepNow() + 5));
  await page.getByRole("button", { name: "Create admin account", exact: true }).click();
  await page.getByText("That code did not match").waitFor();
  check("a wrong code does not create the admin", true);
  const used = stepNow();
  await page.getByLabel("6-digit code from the app", { exact: true }).fill(totp(secret, used));
  await page.getByRole("button", { name: "Create admin account", exact: true }).click();
  await page.getByTestId("signed-in-as").waitFor();
  check("setup signs the new admin in", (await page.getByTestId("signed-in-as").innerText()).includes("Signed in as admin"));
  const status = await page.evaluate(async () => (await fetch("/api/v1/session/setup")).json());
  check("the server no longer asks for setup", status.admin_required === false);

  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByTestId("admin-sign-in").waitFor();
  check("sign out returns a private page to the sign-in form", true);
  const signIn = async (username, pass, code) => {
    await page.getByLabel("Username", { exact: true }).fill(username);
    await page.getByLabel("Password", { exact: true }).fill(pass);
    await page.getByLabel("6-digit code", { exact: true }).fill(code);
    const answer = page.waitForResponse((r) => r.url().endsWith("/api/v1/session/login") && r.request().method() === "POST");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    return (await answer).status();
  };
  let answered = await signIn("admin", password, totp(secret, stepNow() + 5));
  await page.getByText("The username, password or code is wrong").waitFor();
  check("a wrong code is refused with a plain message", answered === 401, `HTTP ${answered}`);
  await page.screenshot({ path: join(outDir, "1440-light-sign-in.png") });
  answered = await signIn("admin", password, totp(secret, used));
  check("the code used for setup cannot sign in again", answered === 401, `HTTP ${answered}`);
  while (stepNow() <= used) await sleep(1000);
  let lastStep = stepNow();
  answered = await signIn("admin", password, totp(secret, lastStep));
  await page.getByTestId("signed-in-as").waitFor();
  check("the admin signs in with password and a fresh code", answered === 200 && path(page) === "/websites", `HTTP ${answered}`);

  // Create a static site so the Files handoff has something to carry. Static
  // sites live at /websites/static since Websites lists the WordPress sites.
  await page.goto(origin + "/websites/static");
  await page.getByRole("button", { name: "Create website", exact: true }).first().click();
  await page.getByTestId("website-create-form").getByLabel("Website name", { exact: true }).fill(siteName);
  await page.getByTestId("website-create-form").getByLabel("Domain", { exact: true }).fill(`shell-qa-${run}.test`);
  await page.getByTestId("website-create-form").getByRole("button", { name: "Create website", exact: true }).click();
  await page.getByRole("button", { name: `Open website ${siteName}`, exact: true }).waitFor();
  await page.getByRole("button", { name: `Open website ${siteName}`, exact: true }).click();
  await page.getByTestId("website-details").waitFor();
  const siteId = await page.getByTestId("website-details").getAttribute("data-site-id");
  await page.screenshot({ path: join(outDir, "1440-light-websites.png") });

  // A static site's files open in the old static file screen; Files in the
  // menu is each website's real home folder now.
  await page.getByRole("button", { name: "Open File Manager", exact: true }).click();
  await page.getByTestId("file-manager-inventory").waitFor();
  check("Open File Manager goes to /websites/static/files", path(page) === "/websites/static/files", path(page));
  check("Files opens the same website", (await page.getByTestId("file-manager-inventory").getAttribute("data-site-id")) === siteId);
  check("breadcrumb shows Websites › Static site files (old)", (await page.locator('[data-slot="breadcrumb"]').innerText()).replace(/\s+/g, " ").includes("Websites"));

  await page.goBack();
  await page.getByTestId("website-details").waitFor();
  check("back button returns to /websites/static with the site still open", path(page) === "/websites/static" && (await page.getByTestId("website-details").getAttribute("data-site-id")) === siteId, path(page));

  await page.getByTestId("nav-files").click();
  await page.getByTestId("files-sites").waitFor();
  const current = await page.locator('nav[aria-label="Panel sections"] [aria-current="page"]').count();
  check("Files in the menu opens the website picker, the one current menu link", path(page) === "/websites/files" && current === 1, `${path(page)}, ${current} current`);

  await page.goto(origin + "/websites/backups");
  await page.getByRole("heading", { name: "Backups", level: 1 }).waitFor();
  check("deep link /websites/backups loads after reload", path(page) === "/websites/backups");
  await page.getByRole("button", { name: "Sign out locally", exact: true }).waitFor({ timeout: 15000 }).then(() => check("session survives reload", true), () => check("session survives reload", false));

  // Command palette.
  await page.keyboard.press("Control+K");
  await page.getByRole("combobox", { name: "Search pages and actions" }).fill("network");
  await page.screenshot({ path: join(outDir, "1440-light-command-palette.png") });
  await page.keyboard.press("Enter");
  await page.waitForURL("**/server/network");
  check("Ctrl+K, type, Enter opens Server › Network", path(page) === "/server/network");
  check("Network tab is marked current", (await page.getByTestId("nav-network").getAttribute("aria-current")) === "page");
  check("Server stays highlighted in the sidebar", (await page.getByTestId("nav-services").getAttribute("data-active")) !== null);

  await page.keyboard.press("Control+B");
  await page.waitForTimeout(400);
  check("Ctrl+B does not hide the sidebar", await page.getByTestId("nav-websites").isVisible());
  check("no sidebar_state cookie", !(await ctx.cookies()).some((c) => c.name === "sidebar_state"));
  await page.goto(origin + "/no-such-page");
  await page.getByText("This page does not exist").waitFor();
  check("unknown URL shows the not-found message", true);

  await page.goto(origin + "/activity");
  await page.getByRole("heading", { name: "Activity", level: 1 }).waitFor();
  await page.goto(origin + "/settings");
  await page.getByRole("heading", { name: "AI spending" }).waitFor();
  check("Activity and Settings pages load", true);

  await page.goto(origin + "/websites/static");
  await page.getByRole("button", { name: "Switch to dark theme" }).click();
  check("dark theme applies", await page.evaluate(() => document.documentElement.classList.contains("dark")));
  await page.getByRole("button", { name: `Open website ${siteName}`, exact: true }).click();
  await page.getByTestId("website-details").waitFor();
  await page.screenshot({ path: join(outDir, "1440-dark-websites.png") });
  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await ctx.close();

  // Phone width.
  const phone = await context({ width: 390, height: 844 });
  await phone.page.goto(origin + "/websites/files");
  await phone.page.getByRole("heading", { name: "Files", level: 1 }).waitFor();
  check("no horizontal overflow at 390", await noOverflow(phone.page));
  await phone.page.getByRole("button", { name: "Open navigation", exact: true }).click();
  await phone.page.getByTestId("nav-backups").waitFor();
  await phone.page.screenshot({ path: join(outDir, "390-light-menu.png") });
  await phone.page.getByTestId("nav-files").click();
  await phone.page.waitForTimeout(500);
  check("tapping the current page closes the phone menu", !(await phone.page.getByTestId("nav-files").isVisible()));
  await phone.page.getByRole("button", { name: "Open navigation", exact: true }).click();
  await phone.page.getByTestId("nav-backups").waitFor();
  await phone.page.getByTestId("nav-backups").click();
  await phone.page.waitForURL("**/websites/backups");
  await phone.page.waitForTimeout(500);
  check("phone menu navigates and closes", path(phone.page) === "/websites/backups" && !(await phone.page.getByTestId("nav-backups").isVisible()));
  await phone.page.goto(origin + "/");
  await phone.page.getByRole("heading", { name: "Server monitoring" }).waitFor();
  check("home has no horizontal overflow at 390", await noOverflow(phone.page));
  await phone.page.screenshot({ path: join(outDir, "390-light-home.png"), fullPage: false });
  await phone.ctx.close();

  // Public preview: private pages are neither listed nor reachable.
  const pub = await context({ width: 1440, height: 900 }, true);
  const privateCalls = [];
  pub.page.on("request", (r) => { const p = new URL(r.url()).pathname; if (/^\/api\/v1\/(session|sites|accounts|trail|budget|operator)/.test(p)) privateCalls.push(p); });
  await pub.page.goto(origin + "/");
  await pub.page.getByRole("heading", { name: "Server monitoring" }).waitFor();
  check("preview hides private menu items", (await pub.page.getByTestId("nav-websites").count()) === 0 && (await pub.page.getByTestId("nav-accounts").count()) === 0);
  check("preview shows the panel tour", (await pub.page.getByTestId("nav-panel-preview").count()) === 1);
  await pub.page.goto(origin + "/websites/files");
  await pub.page.waitForURL(origin + "/");
  check("preview redirects private URLs to Home", path(pub.page) === "/");
  check("preview makes no private API calls", privateCalls.length === 0, privateCalls.join(","));
  await pub.ctx.close();

  if (httpsOrigin) {
    // The panel beyond loopback, as another machine sees it.
    const { port } = new URL(httpsOrigin);
    const served = await new Promise((resolve, reject) => {
      const socket = connect({ host: "127.0.0.1", port: Number(port), servername: remoteHost, rejectUnauthorized: false }, () => { const fp = socket.getPeerCertificate().fingerprint256; socket.end(); resolve(fp); });
      socket.on("error", reject);
    });
    check("the HTTPS listener serves the certificate whose fingerprint the panel printed", served === expectedFingerprint, `${served} vs ${expectedFingerprint}`);
    const net = await context({ width: 1440, height: 900 }, false, { ignoreHTTPSErrors: true });
    await net.page.goto(httpsOrigin + "/");
    await net.page.getByTestId("admin-sign-in").waitFor();
    check("over HTTPS even Home asks for sign-in first", (await net.page.getByRole("heading", { name: "Server monitoring" }).count()) === 0);
    check("over HTTPS there is no access-key option", (await net.page.getByText("Sign in with the server's access key instead").count()) === 0);
    const probe = await net.page.evaluate(async () => {
      const reading = await fetch("/api/v1/server");
      const key = await fetch("/api/v1/session/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ access_key: "A".repeat(43) }) });
      const setup = await fetch("/api/v1/session/setup/totp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "admin" }) });
      return [reading.status, key.status, setup.status];
    });
    check("over HTTPS readings need a session and the key and setup are refused", probe[0] === 401 && probe[1] === 403 && probe[2] === 403, probe.join(","));
    const foreign = await net.ctx.request.get(`https://127.0.0.1:${port}/`, { failOnStatusCode: false });
    check("an unknown host name gets 421", foreign.status() === 421, `HTTP ${foreign.status()}`);
    while (stepNow() <= lastStep) await sleep(1000);
    lastStep = stepNow();
    await net.page.getByLabel("Username", { exact: true }).fill("admin");
    await net.page.getByLabel("Password", { exact: true }).fill(password);
    await net.page.getByLabel("6-digit code", { exact: true }).fill(totp(secret, lastStep));
    await net.page.getByRole("button", { name: "Sign in", exact: true }).click();
    await net.page.getByRole("heading", { name: "Server monitoring" }).waitFor();
    check("an admin signs in over HTTPS and sees the server readings", (await net.page.getByTestId("signed-in-as").innerText()).includes("admin"));
    const cookie = (await net.ctx.cookies()).find((c) => c.name === "sifruno_operator");
    check("the session cookie over HTTPS is Secure, HttpOnly and SameSite=Strict", cookie?.secure === true && cookie?.httpOnly === true && cookie?.sameSite === "Strict");
    await net.page.getByTestId("nav-websites").click();
    await net.page.getByRole("button", { name: `Open website ${siteName}`, exact: true }).waitFor();
    check("websites made on the server are there over HTTPS", true);
    await net.page.screenshot({ path: join(outDir, "1440-light-https-websites.png") });
    await net.ctx.close();
  }

  // Last, because it locks the admin's name for a minute: the per-name limit
  // also guards a real account.
  const late = await context({ width: 1440, height: 900 });
  await late.page.goto(origin + "/websites");
  await late.page.getByTestId("admin-sign-in").waitFor();
  const lockout = [];
  for (let i = 0; i < 6; i++) {
    await late.page.getByLabel("Username", { exact: true }).fill("admin");
    await late.page.getByLabel("Password", { exact: true }).fill("not the password");
    await late.page.getByLabel("6-digit code", { exact: true }).fill("123456");
    const answer = late.page.waitForResponse((r) => r.url().endsWith("/api/v1/session/login") && r.request().method() === "POST");
    await late.page.getByRole("button", { name: "Sign in", exact: true }).click();
    lockout.push((await answer).status());
  }
  // Earlier sign-ins in this run used some of the name's five tries, so check
  // the shape: plain refusals, then 429 from the first limited try onward.
  const first429 = lockout.indexOf(429);
  check("the admin's own name is rate limited after repeated failures", first429 >= 1 && lockout.slice(0, first429).every((c) => c === 401) && lockout.slice(first429).every((c) => c === 429), lockout.join(","));
  await late.ctx.close();
} catch (error) {
  check("run completed", false, String(error && error.message || error).slice(0, 400));
} finally {
  key = "";
  await browser.close();
}
check("no page errors", errors.length === 0, errors.slice(0, 5).join(" | "));
const passed = checks.filter((c) => c.ok).length;
writeFileSync(join(outDir, "report.json"), JSON.stringify({ origin, passed, failed: checks.length - passed, checks }, null, 2) + "\n");
console.log(`${passed} passed, ${checks.length - passed} failed`);
process.exitCode = checks.every((c) => c.ok) ? 0 : 1;
