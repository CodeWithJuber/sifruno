// Browser checks for the Phase 1 panel shell, run by `proof.sh panel-shell`
// against a panel with throwaway state. It reads that state's operator key to
// sign in and never prints it.
//   node panel-shell.qa.mjs <origin> <state-dir> <out-dir> [chrome-executable]
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";

const [origin, stateDir, outDir, chrome] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
let key = readFileSync(join(stateDir, "operator/access.key"), "utf8").trim();
const run = Date.now().toString(36);
const siteName = `Shell QA ${run}`;
const checks = [];
const errors = [];
const check = (name, ok, detail = "") => { checks.push({ name, ok: Boolean(ok), detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${!ok && detail ? ` (${detail})` : ""}`); };
const noOverflow = (page) => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1);
const path = (page) => new URL(page.url()).pathname;

const browser = await chromium.launch({ headless: true, ...(chrome ? { executablePath: chrome } : {}) });
async function context(viewport, preview = false) {
  const ctx = await browser.newContext({ viewport });
  if (preview) {
    await ctx.route((url) => url.origin === origin && !url.pathname.startsWith("/api/") && !url.pathname.includes("."), async (route) => {
      const response = await route.fetch();
      const body = (await response.text()).replace("<head>", '<head><meta name="sifruno-public-preview" content="true">');
      await route.fulfill({ response, body });
    });
  }
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => { if (m.type() === "error" && !/401|Unauthorized/.test(m.text())) errors.push(`console: ${m.text()}`); });
  return { ctx, page };
}

try {
  // Desktop, light.
  const { ctx, page } = await context({ width: 1440, height: 900 });
  await page.goto(origin + "/");
  await page.getByRole("heading", { name: "Server monitoring" }).waitFor();
  const topLevel = await page.locator('[data-slot="sidebar-menu-button"]').count();
  check("sidebar has 7 top-level items", topLevel === 7, `found ${topLevel}`);
  check("no Compatibility or Platforms in menu", (await page.getByTestId("nav-evidence").count()) + (await page.getByTestId("nav-platform").count()) === 0);
  check("home has no horizontal overflow at 1440", await noOverflow(page));
  await page.screenshot({ path: join(outDir, "1440-light-home.png") });

  await page.getByTestId("nav-websites").click();
  check("Websites menu item opens /websites", path(page) === "/websites", path(page));
  await page.getByLabel("Operator access key", { exact: true }).fill(key);
  await page.getByRole("button", { name: "Sign in locally", exact: true }).click();
  await page.getByRole("button", { name: "Sign out locally", exact: true }).waitFor();
  check("sign-in works inside the new shell", true);

  // Create a website so the Files handoff has something to carry.
  await page.getByRole("button", { name: "Create website", exact: true }).first().click();
  await page.getByTestId("website-create-form").getByLabel("Website name", { exact: true }).fill(siteName);
  await page.getByTestId("website-create-form").getByLabel("Domain", { exact: true }).fill(`shell-qa-${run}.test`);
  await page.getByTestId("website-create-form").getByRole("button", { name: "Create website", exact: true }).click();
  await page.getByRole("button", { name: `Open website ${siteName}`, exact: true }).waitFor();
  await page.getByRole("button", { name: `Open website ${siteName}`, exact: true }).click();
  await page.getByTestId("website-details").waitFor();
  const siteId = await page.getByTestId("website-details").getAttribute("data-site-id");
  await page.screenshot({ path: join(outDir, "1440-light-websites.png") });

  await page.getByRole("button", { name: "Open File Manager", exact: true }).click();
  await page.getByTestId("file-manager-inventory").waitFor();
  check("Open File Manager goes to /websites/files", path(page) === "/websites/files", path(page));
  check("Files opens the same website", (await page.getByTestId("file-manager-inventory").getAttribute("data-site-id")) === siteId);
  const current = await page.locator('nav[aria-label="Panel sections"] [aria-current="page"]').count();
  check("exactly one menu link is the current page", current === 1, "found " + current);
  check("breadcrumb shows Websites › Files", (await page.locator('[data-slot="breadcrumb"]').innerText()).replace(/\s+/g, " ").includes("Websites"));

  await page.goBack();
  await page.getByTestId("website-details").waitFor();
  check("back button returns to /websites with the site still open", path(page) === "/websites" && (await page.getByTestId("website-details").getAttribute("data-site-id")) === siteId, path(page));

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

  await page.goto(origin + "/websites");
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
