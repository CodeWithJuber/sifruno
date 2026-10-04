import { chromium } from "playwright";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile, lstat, realpath, readdir } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, isAbsolute, sep } from "node:path";
import { fileURLToPath } from "node:url";

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const worktreeRoot = sourceRoot;
const primaryRoot = basename(dirname(sourceRoot)) === ".worktrees" ? dirname(dirname(sourceRoot)) : sourceRoot;
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { checkCode: code }); };
let root = worktreeRoot;
let fixtureRoot;
let output;
let phase = "repo_context";
let browser;
let credential;
const origin = "http://127.0.0.1:8084";
const sitesOrigin = "http://127.0.0.1:8086";
const runId = new Date().toISOString().replace(/[-:.Z]/g, "") + "-" + randomUUID().slice(0, 8);
const report = {
  schema_version: 1,
  evidence_kind: "observed_isolated_native_transfer_browser_qa",
  checked_at: new Date().toISOString(),
  fixture_only: true,
  public_meta_test: "synthetic response transform in isolated fixture; not a public production route",
  main_state_mutated: false,
  paid_provider_calls: 0,
  compatibility_certified: false,
  browser: "isolated Playwright Chromium",
  workflow: {},
  viewports: [],
  public_preview: {},
  source_sha256: {},
};

async function directory(path) {
  const rel = relative(worktreeRoot, path);
  const parts = rel.split(sep);
  check(!isAbsolute(rel) && parts.every(part => part && part !== ".."), "output_escape");
  let current = await realpath(worktreeRoot);
  for (const part of parts) {
    current = join(current, part);
    try { await mkdir(current); } catch (error) { if (error.code !== "EEXIST") throw error; }
    const stat = await lstat(current);
    check(stat.isDirectory() && !stat.isSymbolicLink() && await realpath(current) === current, "output_not_regular");
  }
}

async function boundedFile(path, maximum, ancestor = root) {
  const rel = relative(ancestor, path);
  check(rel && !isAbsolute(rel) && !rel.split(sep).includes(".."), "input_escape");
  let current = await realpath(ancestor);
  for (const part of rel.split(sep)) {
    current = join(current, part);
    const stat = await lstat(current);
    check(!stat.isSymbolicLink() && await realpath(current) === current, "input_link");
  }
  const stat = await lstat(current);
  check(stat.isFile() && stat.nlink === 1 && stat.size > 0 && stat.size <= maximum, "input_not_bounded_regular");
  const bytes = await readFile(current);
  check(bytes.length === stat.size && bytes.length <= maximum, "input_changed");
  return bytes;
}

function launchEnvironment() {
  const allowed = new Set(["PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA"]);
  const env = {};
  for (const name of Object.keys(process.env)) if (allowed.has(name.toUpperCase()) && process.env[name]) env[name] = process.env[name];
  return env;
}

async function fixtureContext(theme, viewport, { publicView = false, injectPublicMeta = false } = {}) {
  const context = await browser.newContext({ viewport, acceptDownloads: true, reducedMotion: "reduce" });
  await context.addInitScript(value => localStorage.setItem("sifruno-theme", value), theme);
  const privateRequests = [];
  const outOfScope = [];
  await context.route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const local = url.origin === origin;
    const preview = url.protocol === "http:" && url.port === "8086" && /^site-[a-f0-9]{32}\.localhost$/.test(url.hostname);
    if (!local && !preview) { outOfScope.push(url.href); await route.abort("blockedbyclient"); return; }
    if (publicView && /^\/api\/v1\/(session|sites)(\/|$)/.test(url.pathname)) { privateRequests.push(url.pathname); await route.abort("blockedbyclient"); return; }
    if (!publicView && /^\/api\/v1\/(session|sites)(\/|$)/.test(url.pathname)) privateRequests.push(url.pathname);
    if (publicView && injectPublicMeta && url.origin === origin && url.pathname === "/" && request.resourceType() === "document") {
      const response = await route.fetch();
      const html = (await response.text()).replace("</head>", '<meta name="sifruno-public-preview" content="test-only"></head>');
      await route.fulfill({ response, body: html });
      return;
    }
    const method = request.method();
    const allowedMutation = (method === "POST" && ["/api/v1/session/login", "/api/v1/sites", "/api/v1/sites/import"].includes(url.pathname)) ||
      (method === "PUT" && /^\/api\/v1\/sites\/[a-f0-9]{32}\/file$/.test(url.pathname)) ||
      (method === "POST" && /^\/api\/v1\/sites\/[a-f0-9]{32}\/backups$/.test(url.pathname));
    if (!publicView && !["GET", "HEAD"].includes(method) && !allowedMutation) { outOfScope.push(`${method} ${url.pathname}`); await route.abort("blockedbyclient"); return; }
    await route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.setDefaultNavigationTimeout(15000);
  return { context, page, privateRequests, outOfScope };
}

async function login(page) {
  await page.getByRole("button", { name: "Websites", exact: true }).click();
  await page.getByLabel("Operator access key", { exact: true }).waitFor();
  check(await page.getByLabel("Operator access key", { exact: true }).getAttribute("type") === "password", "key_input_not_password");
  await page.getByLabel("Operator access key", { exact: true }).fill(credential);
  await page.getByRole("button", { name: "Sign in locally", exact: true }).click();
  await page.getByRole("button", { name: "Sign out locally", exact: true }).waitFor();
  check(await page.evaluate(key => !document.body.innerText.includes(key) && !Object.values(localStorage).some(value => value.includes(key)), credential), "credential_persisted_or_displayed");
}

async function themedDialog(theme) {
  phase = `dialog_${theme}`;
  const { context, page, privateRequests, outOfScope } = await fixtureContext(theme, { width: 1440, height: 960 });
  try {
    const response = await page.goto(origin, { waitUntil: "networkidle" });
    check(response?.ok(), "fixture_ui_unavailable");
    await login(page);
    await page.getByRole("button", { name: "Import native ZIP", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Import native Sifruno ZIP", exact: true });
    await dialog.waitFor();
    const appearance = await dialog.evaluate(element => ({
      dark: document.documentElement.classList.contains("dark"),
      background: getComputedStyle(element).backgroundColor,
      foreground: getComputedStyle(element).color,
    }));
    check(appearance.dark === (theme === "dark"), `theme_class_${theme}`);
    check(appearance.background === (theme === "dark" ? "rgb(22, 33, 43)" : "rgb(255, 255, 255)"), `dialog_background_${theme}`);
    check(appearance.foreground === (theme === "dark" ? "rgb(228, 237, 243)" : "rgb(23, 46, 60)"), `dialog_foreground_${theme}`);
    const viewports = [];
    for (const width of [390, 768, 1440]) {
      phase = `dialog_${theme}_${width}`;
      await page.setViewportSize({ width, height: width === 390 ? 844 : 960 });
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      const extent = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
      check(extent.document <= extent.viewport + 1 && extent.body <= extent.viewport + 1, `dialog_overflow_${theme}_${width}`);
      const result = { width, theme, ...extent, ...appearance };
      if (width === 390 && theme === "light" || width === 1440 && theme === "dark") {
        const filename = `import-dialog-${width}-${theme}.png`;
        await dialog.screenshot({ path: join(output, filename), timeout: 15000 });
        result.screenshot = filename;
      }
      viewports.push(result);
    }
    check(privateRequests.includes("/api/v1/session"), `dialog_session_not_checked_${theme}`);
    check(outOfScope.length === 0, `dialog_out_of_scope_${theme}`);
    return viewports;
  } finally { await context.close(); }
}

async function main() {
  phase = "repo_context";
  root = primaryRoot;
  fixtureRoot = join(root, ".cache/native-transfer-fixture");
  output = join(worktreeRoot, "artifacts/native-transfer", runId);
  await directory(output);

  phase = "fixture_metadata";
  const metadata = JSON.parse((await boundedFile(join(fixtureRoot, "current.json"), 8192)).toString("utf8"));
  check(metadata.origin === origin && metadata.sites_origin === sitesOrigin && metadata.main_state_mutated === false && metadata.paid_provider_calls === 0 && Number.isInteger(metadata.pid) && /^[A-Za-z0-9_-]{1,96}$/.test(metadata.id), "fixture_metadata_invalid");
  const expectedState = join(fixtureRoot, metadata.id, "private-state");
  const stateRoot = resolve(root, metadata.state);
  check(stateRoot === expectedState, "fixture_state_not_exact");
  const key = await boundedFile(join(stateRoot, "operator", "access.key"), 44, fixtureRoot);
  check(key.length === 44 && /^[A-Za-z0-9_-]{43}\n$/.test(key.toString("ascii")), "fixture_key_format");
  credential = key.toString("ascii").trim();
  const binaryPath = resolve(root, metadata.binary);
  const binaryHash = hash(await boundedFile(binaryPath, 32 << 20));
  check(binaryHash === metadata.binary_sha256, "fixture_binary_hash_mismatch");
  report.fixture_id = metadata.id;
  report.fixture_pid = metadata.pid;
  report.binary_sha256 = binaryHash;
  report.site_origin = metadata.sites_origin;

  phase = "source_hashes";
  for (const path of ["web/dist/index.html", "web/src/Websites.tsx", "web/src/lib/sites-api.ts", "web/src/websites.css", "scripts/verify-native-transfers-ui.mjs"]) {
    report.source_sha256[path] = hash(await boundedFile(join(worktreeRoot, path), 4 << 20, worktreeRoot));
  }
  const bundleDir = join(worktreeRoot, "web/dist/assets");
  const transferBundle = (await readdir(bundleDir)).find(name => /^Websites-[A-Za-z0-9_-]+\.js$/.test(name));
  check(Boolean(transferBundle), "website_bundle_missing");
  report.source_sha256[`web/dist/assets/${transferBundle}`] = hash(await boundedFile(join(bundleDir, transferBundle), 4 << 20, worktreeRoot));

  phase = "browser_launch";
  try { browser = await chromium.launch({ headless: true, env: launchEnvironment() }); }
  catch { throw Object.assign(new Error("browser_launch_failed"), { checkCode: "browser_launch_failed" }); }

  phase = "workflow";
  const workflow = await fixtureContext("light", { width: 1440, height: 960 });
  let archive;
  try {
    const { context, page } = workflow;
    const response = await page.goto(origin, { waitUntil: "networkidle" });
    check(response?.ok(), "fixture_ui_unavailable");
    await login(page);
    const nonce = randomUUID().slice(0, 8);
    const sourceName = `Luna transfer source ${nonce}`;
    const sourceDomain = `luna-source-${nonce}.test`;
    const importedName = `Luna transfer imported ${nonce}`;
    const importedDomain = `luna-import-${nonce}.test`;
    const sourceContent = `<!doctype html><html><head><title>Luna ZIP ${nonce}</title></head><body><main>native ZIP payload ${nonce}</main></body></html>`;

    phase = "source_create";
    await page.locator("#website-name").fill(sourceName);
    await page.locator("#website-domain").fill(sourceDomain);
    await page.getByRole("button", { name: "Create website", exact: true }).click();
    await page.getByText(`Created ${sourceName}.`, { exact: true }).waitFor();
    const sourceSiteId = await page.getByTestId("website-details").getAttribute("data-site-id");
    check(/^[a-f0-9]{32}$/.test(sourceSiteId ?? ""), "source_site_id_invalid");
    await page.getByRole("button", { name: "Edit index.html", exact: true }).click();
    await page.locator("#site-file-content").fill(sourceContent);
    await page.getByRole("button", { name: "Save file", exact: true }).click();
    await page.getByText("Saved index.html.", { exact: true }).waitFor();
    const previewHref = await page.getByRole("link", { name: "Local HTTP preview", exact: true }).getAttribute("href");
    check(previewHref === `http://site-${sourceSiteId}.localhost:8086/`, "preview_port_metadata_mismatch");

    phase = "backup_create";
    await page.getByRole("button", { name: "Create ZIP backup", exact: true }).click();
    const backup = page.locator(".website-backup-list article").first();
    await backup.waitFor({ state: "visible" });
    await backup.locator("details summary").click();
    const expectedSha = (await backup.locator("details code").textContent())?.trim();
    check(/^[a-f0-9]{64}$/.test(expectedSha ?? ""), "backup_sha_missing");

    phase = "backup_download";
    const downloadPromise = page.waitForEvent("download");
    await backup.getByRole("button", { name: /Download ZIP backup/ }).click();
    const download = await downloadPromise;
    const stream = await download.createReadStream();
    const parts = [];
    for await (const part of stream) parts.push(part);
    archive = Buffer.concat(parts);
    const archiveSha = hash(archive);
    check(archive.length > 0 && archive.length <= 34 * 1024 * 1024 && archiveSha === expectedSha, "download_hash_or_size_mismatch");

    phase = "native_import";
    await page.getByRole("button", { name: "Import native ZIP", exact: true }).click();
    const importDialog = page.getByRole("dialog", { name: "Import native Sifruno ZIP", exact: true });
    await importDialog.waitFor();
    await page.locator("#import-website-name").fill("é".repeat(41));
    await page.locator("#import-website-domain").fill(importedDomain);
    await page.locator("#import-website-archive").setInputFiles({ name: "sifruno-site.zip", mimeType: "application/zip", buffer: archive });
    check(await importDialog.getByRole("button", { name: "Import website", exact: true }).isDisabled(), "82_byte_name_admitted");
    await page.locator("#import-website-name").fill("é".repeat(40));
    check(await importDialog.getByRole("button", { name: "Import website", exact: true }).isEnabled(), "80_byte_name_rejected");
    await page.locator("#import-website-domain").fill("é".repeat(127));
    check(await importDialog.getByRole("button", { name: "Import website", exact: true }).isDisabled(), "254_byte_domain_admitted");
    await page.locator("#import-website-domain").fill(importedDomain);
    await page.locator("#import-website-name").fill(importedName);
    await importDialog.getByRole("button", { name: "Import website", exact: true }).click();
    await page.waitForFunction(name => document.querySelector(".website-details .card-heading h2")?.textContent === name, importedName);
    const importedSiteId = await page.getByTestId("website-details").getAttribute("data-site-id");
    check(/^[a-f0-9]{32}$/.test(importedSiteId ?? "") && await page.locator("#site-file-content").inputValue() === sourceContent, "imported_site_contract_mismatch");
    const preview = await page.goto(`http://site-${importedSiteId}.localhost:8086/`, { waitUntil: "networkidle" });
    check(preview?.ok() && (await page.locator("body").innerText()).includes(`native ZIP payload ${nonce}`), "import_vhost_content_missing");

    phase = "corrupt_import_draft_guard";
    await page.goto(origin, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: "Websites", exact: true }).click();
    const draft = `<main>preserve dirty draft ${nonce}</main>`;
    await page.locator("#site-file-content").fill(draft);
    const siteCount = await page.locator(".website-list-item").count();
    await page.getByRole("button", { name: "Import native ZIP", exact: true }).click();
    const corruptDialog = page.getByRole("dialog", { name: "Import native Sifruno ZIP", exact: true });
    await page.locator("#import-website-name").fill(`Corrupt target ${nonce}`);
    await page.locator("#import-website-domain").fill(`corrupt-${nonce}.test`);
    await page.locator("#import-website-archive").setInputFiles({ name: "corrupt.zip", mimeType: "application/zip", buffer: Buffer.from("not a ZIP") });
    const importButton = corruptDialog.getByRole("button", { name: "Import website", exact: true });
    check(await importButton.isDisabled(), "dirty_draft_import_not_blocked");
    await corruptDialog.getByRole("checkbox", { name: "Discard the unsaved editor draft after the import succeeds.", exact: true }).check();
    await importButton.click();
    await corruptDialog.locator("p[role=alert]").filter({ hasText: "not a valid native Sifruno site archive" }).waitFor();
    check(await page.locator("#site-file-content").inputValue() === draft, "corrupt_import_lost_draft");
    check(await page.locator(".website-list-item").count() === siteCount, "corrupt_import_created_site");
    check(workflow.outOfScope.length === 0, "workflow_out_of_scope_request");
    report.workflow = { source_site_created: true, seeded_index_edited: true, backup_created: true, download_sha256: archiveSha, download_bytes: archive.length, native_import_created_site: true, imported_vhost_8086_served_content: true, invalid_name_and_domain_byte_limits_enforced: true, dirty_draft_requires_explicit_discard: true, corrupt_archive_rejected_without_discarding_draft: true, corrupt_archive_created_no_site: true };
    report.source_site_id = sourceSiteId;
    report.imported_site_id = importedSiteId;
  } finally { await workflow.context.close(); }

  phase = "themed_dialogs";
  for (const theme of ["light", "dark"]) report.viewports.push(...await themedDialog(theme));

  phase = "public_meta_privacy";
  const publicView = await fixtureContext("light", { width: 1440, height: 960 }, { publicView: true, injectPublicMeta: true });
  try {
    const response = await publicView.page.goto(origin, { waitUntil: "networkidle" });
    check(response?.ok(), "public_meta_fixture_unavailable");
    await publicView.page.waitForTimeout(300);
    check(await publicView.page.getByTestId("websites-view").count() === 0, "public_meta_mounted_websites");
    check(await publicView.page.getByTestId("nav-websites").count() === 0, "public_meta_exposed_websites_nav");
    check(publicView.privateRequests.length === 0, "public_meta_private_requests");
    check(publicView.outOfScope.length === 0, "public_meta_out_of_scope_request");
    report.public_preview = { injection: "test-only Playwright response transform on isolated fixture HTML", websites_unmounted: true, websites_nav_absent: true, private_session_or_sites_fetches: 0 };
  } finally { await publicView.context.close(); }

  phase = "source_hashes_final";
  report.source_sha256["web/src/Websites.tsx"] = hash(await boundedFile(join(worktreeRoot, "web/src/Websites.tsx"), 4 << 20, worktreeRoot));
  report.source_sha256["web/src/lib/sites-api.ts"] = hash(await boundedFile(join(worktreeRoot, "web/src/lib/sites-api.ts"), 4 << 20, worktreeRoot));
  report.source_sha256["web/src/websites.css"] = hash(await boundedFile(join(worktreeRoot, "web/src/websites.css"), 4 << 20, worktreeRoot));
  report.passed = true;
  report.outcome = "completed against isolated fixture only";
  phase = "report_write";
  await writeFile(join(output, "report.json"), JSON.stringify(report, null, 2) + "\n", { encoding: "utf8", flag: "wx" });
  await browser.close();
  browser = undefined;
  console.log(JSON.stringify({ result: "passed", report: relative(worktreeRoot, join(output, "report.json")).split(sep).join("/"), workflow: report.workflow, viewports: report.viewports, public_preview: report.public_preview, binary_sha256: report.binary_sha256, source_sha256: report.source_sha256 }));
}

main().catch(error => {
  const code = error && /^[a-z0-9_]+$/.test(error.checkCode ?? "") ? error.checkCode : "unexpected_error";
  console.error(JSON.stringify({ result: "failed", phase, code }));
  if (browser) void browser.close().catch(() => undefined);
  process.exitCode = 1;
});
