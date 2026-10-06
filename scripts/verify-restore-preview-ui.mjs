// Actual isolated UI/API observations; no live state, shared-input writes or publication.
// Run from this assigned worktree: node scripts/verify-restore-preview-ui.mjs --source-root <restore-preview-integration>
// Reuses verify-access-ui.mjs lifecycle, bounded catalogs and sanitized receipt patterns.
import { createRequire } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer as httpServer } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { once } from 'node:events';
import { mkdir, readFile, writeFile, lstat, realpath, readdir } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve, isAbsolute, sep, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const primary = resolve(root, '../..');
const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { checkCode: code }); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const runId = new Date().toISOString().replace(/[-:.Z]/g, '') + '-' + randomUUID().slice(0, 8);
const fixture = join(root, '.cache/restore-preview-ui', runId);
const output = join(root, 'artifacts/restore-preview-ui', runId);
const servers = [], contexts = [], secrets = new Set(), releases = new Set();
let sourceRoot, binary, ui, chromium, browser, publicServer, publicOrigin, diagnosticPage, phase = 'admission';
const savedTemp = Object.fromEntries(['TEMP', 'TMP', 'TMPDIR'].map(name => [name, process.env[name]]));
const report = { schema_version: 1, run_id: runId, checked_at: new Date().toISOString(),
  evidence_kind: 'observed_isolated_native_restore_preview_browser_qa', passed: false,
  platform: process.platform, fixture_only: true, main_state_mutated: false, shared_inputs_mutated: false,
  live_activation: false, paid_provider_calls: 0, compatibility_certified: false,
  source_role: 'reviewed restore-preview-integration read-only inputs', workflow: {}, private_viewports: [], public_viewports: [], cleanup: {}, screenshots: {},
  timing_limit: 'Synthetic 503 and malformed 200 are intercepted preview responses. Delayed real preview cancellation/Escape/navigation inspect late UI clearing; programmatic navigation bypasses the modal for that controlled lifecycle case. A separately labeled synthetic short session expiry inspects UI clearing; it does not qualify server expiry.',
  public_limit: 'Local HTML public-mode/read-only metrics fixture; no production proxy, tunnel, physical phone or remote authorization qualification.',
  revision_limit: 'Maximum-safe revision advance is covered by source DTO contract tests only; no private fixture metadata was edited to invent a maximum revision.',
  readonly_limit: 'Preview state invariance compares actual API site, file catalog, backup inventory, schedule and scoped journal observations; no direct fixture metadata reads except its newly created operator key.' };

function contained(ancestor, path) { const rel = relative(ancestor, path); return Boolean(rel && !isAbsolute(rel) && !rel.split(sep).includes('..')); }
async function directory(path) {
  check(contained(root, path), 'output_escape'); let current = await realpath(root);
  for (const part of relative(root, path).split(sep)) {
    current = join(current, part); try { await mkdir(current); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const stat = await lstat(current); check(stat.isDirectory() && !stat.isSymbolicLink() && await realpath(current) === current, 'output_not_regular');
  }
}
async function bounded(path, maximum, ancestor) {
  check(contained(ancestor, path), 'input_escape'); let current = await realpath(ancestor);
  for (const part of relative(ancestor, path).split(sep)) { current = join(current, part); check(!(await lstat(current)).isSymbolicLink() && await realpath(current) === current, 'input_link'); }
  const stat = await lstat(current); check(stat.isFile() && stat.nlink === 1 && stat.size > 0 && stat.size <= maximum, 'input_not_bounded_regular');
  const bytes = await readFile(current); check(bytes.length === stat.size, 'input_changed'); return bytes;
}
async function catalog(ancestor, folders, include, maximumFiles, maximumTotal) {
  const entries = []; let total = 0;
  async function visit(path) {
    const stat = await lstat(path); check(!stat.isSymbolicLink(), 'catalog_link');
    if (stat.isDirectory()) { for (const name of (await readdir(path)).sort()) await visit(join(path, name)); return; }
    const label = relative(ancestor, path).split(sep).join('/'); if (!include(label)) return;
    const bytes = await bounded(path, 8 << 20, ancestor); total += bytes.length;
    check(entries.length < maximumFiles && total <= maximumTotal, 'catalog_bound'); entries.push({ path: label, bytes: bytes.length, sha256: hash(bytes) });
  }
  for (const folder of folders) await visit(join(ancestor, folder)); entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0); return entries;
}
const sourceCatalog = () => catalog(sourceRoot, ['cmd', 'internal', 'config', 'web/src', 'go.mod', 'go.sum', 'package.json', 'package-lock.json', 'web/package.json', 'web/package-lock.json', 'web/tsconfig.json', 'web/vite.config.ts', 'web/scripts/sync-brand.mjs'], path => /\.(go|json|sum|mod|ts|tsx|css|mjs)$/.test(path), 2048, 32 << 20);
const uiCatalog = () => catalog(ui, ['.'], () => true, 512, 80 << 20);
async function freePort() {
  const server = tcpServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const port = server.address().port;
  await new Promise((done, fail) => server.close(error => error ? fail(error) : done())); return port;
}
function environment() {
  const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'LANG', 'LC_ALL']);
  return { ...Object.fromEntries(Object.entries(process.env).filter(([name, value]) => allowed.has(name.toUpperCase()) && value)), TEMP: join(fixture, 'temp'), TMP: join(fixture, 'temp'), TMPDIR: join(fixture, 'temp') };
}
const timeout = (promise, milliseconds, code) => { let timer; return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error(code), { checkCode: code })), milliseconds); })]).finally(() => clearTimeout(timer)); };
async function responseJSON(response, status, code) {
  check(response.status() === status, code); const bytes = await response.body(); check(bytes.length <= 1 << 20, 'api_response_bound');
  const value = JSON.parse(bytes.toString('utf8')); if (value.csrf_token) secrets.add(value.csrf_token); return value;
}
async function api(context, server, path, { method = 'GET', data, csrf, status = 200 } = {}) {
  check(/^\/api\/v1\/(trail|session(?:\/(?:login|logout))?|sites(?:\/[a-f0-9]{32}(?:\/(?:backup-schedule|backups|file|files|restore-preview|restore))?)?)(?:\?path=(?:index\.html|target\.css|stay\.txt|currentonly\.txt))?$/.test(path), 'api_path_not_admitted');
  const response = await context.request.fetch(server.origin + path, { method, data, maxRedirects: 0, timeout: 10000,
    headers: { Origin: server.origin, Accept: 'application/json', ...(data !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } });
  const value = await responseJSON(response, status, 'api_status_mismatch'); for (const cookie of await context.cookies()) secrets.add(cookie.value); return value;
}
async function startServer(ownedBinary) {
  const state = join(fixture, 'state');
  const origin = 'http://127.0.0.1:' + await freePort();
  const child = spawn(ownedBinary, ['--listen', new URL(origin).host, '--sites-listen=', '--state', state, '--ui', ui], { cwd: root, env: environment(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const server = { origin, child, key: undefined, logBytes: 0, logLimitExceeded: false, spawnError: false }; servers.push(server);
  child.on('error', () => { server.spawnError = true; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => { server.logBytes += bytes.length; if (server.logBytes > 2 << 20) { server.logLimitExceeded = true; child.kill(); } });
  let ready = false;
  for (let i = 0; i < 100; i++) {
    check(!server.spawnError && child.exitCode === null && child.signalCode === null && !server.logLimitExceeded, 'owned_server_exited');
    try { ready = (await fetch(origin + '/api/v1/status', { redirect: 'error', signal: AbortSignal.timeout(500) })).ok; } catch { /* bounded startup */ }
    if (ready) break; await new Promise(done => setTimeout(done, 100));
  }
  check(ready, 'owned_server_not_ready'); server.key = (await bounded(join(state, 'operator/access.key'), 256, fixture)).toString('utf8').trim();
  check(/^[A-Za-z0-9_-]{43}$/.test(server.key), 'fixture_key_shape'); secrets.add(server.key); return server;
}
async function contextFor(server, width = 1440, theme = 'light', cookies, publicMode = false) {
  const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, colorScheme: theme, locale: 'en-GB' });
  context.setDefaultTimeout(12000); await context.addInitScript(value => localStorage.setItem('sifruno-theme', value), theme); if (cookies) await context.addCookies(cookies);
  const stats = { page_errors: 0, external_requests: 0, session_requests: 0, site_requests: 0, schedule_requests: 0, schedule_puts: 0, preview_posts: 0, restore_posts: 0, mutation_requests: 0, asset_failures: 0, out_of_scope_mutations: 0 };
  await context.route('**/*', route => {
    const request = route.request(), url = new URL(request.url()); if (!['http:', 'https:'].includes(url.protocol)) return route.continue();
    if (![server.origin, publicOrigin].includes(url.origin)) { stats.external_requests++; return route.abort(); }
    const allowedWrite = !publicMode && (/^\/api\/v1\/session\/(login|logout)$/.test(url.pathname) || url.pathname === '/api/v1/sites' || /^\/api\/v1\/sites\/[a-f0-9]{32}\/(file|backups|backup-schedule|restore-preview|restore)$/.test(url.pathname));
    if (!['GET', 'HEAD'].includes(request.method()) && !allowedWrite) { stats.out_of_scope_mutations++; return route.abort(); } return route.continue();
  });
  context.on('request', request => { const url = new URL(request.url()); if (url.pathname.startsWith('/api/v1/session')) stats.session_requests++; if (url.pathname.startsWith('/api/v1/sites')) stats.site_requests++; if (url.pathname.endsWith('/backup-schedule')) { stats.schedule_requests++; if (request.method() === 'PUT') stats.schedule_puts++; } if (request.method() === 'POST' && url.pathname.endsWith('/restore-preview')) stats.preview_posts++; if (request.method() === 'POST' && url.pathname.endsWith('/restore')) stats.restore_posts++; if (!['GET', 'HEAD'].includes(request.method())) stats.mutation_requests++; });
  context.on('response', response => { if (response.status() >= 400 && /\/(assets|brand)\//.test(new URL(response.url()).pathname)) stats.asset_failures++; });
  const page = await context.newPage(); page.on('pageerror', () => stats.page_errors++); contexts.push(context); return { context, page, stats };
}
async function nav(page, id) { const item = page.getByTestId('nav-' + id); if (!await item.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click(); await item.click(); }
async function settled(page) {
  await page.getByTestId('backups-page').waitFor({ state: 'visible' });
  await page.waitForFunction(() => {
    const backups = document.querySelector('[data-testid="backups-page"]');
    return backups?.querySelector('[data-testid="backups-inventory"]')?.getAttribute('data-fresh') === 'true' && backups?.querySelector('[data-testid="backup-schedule"]')?.getAttribute('data-fresh') === 'true' && !backups?.querySelector('.website-busy');
  });
  check(await page.getByTestId('backup-schedule').isVisible(), 'schedule_not_visible');
}
async function refresh(page) { await page.getByRole('button', { name: 'Refresh backup records', exact: true }).click(); await settled(page); }
async function login(page, server) { await page.getByLabel('Operator access key', { exact: true }).fill(server.key); await page.getByRole('button', { name: 'Sign in locally', exact: true }).click(); await page.getByRole('button', { name: 'Sign out locally', exact: true }).waitFor(); }
async function privacy(page) {
  check(!await page.getByLabel('Operator access key', { exact: true }).isVisible(), 'auth_ui_screenshot_forbidden');
  const text = await page.locator('body').innerText(); check([...secrets].every(value => !text.includes(value)), 'secret_in_visible_ui');
  const storage = await page.evaluate(() => [...Object.values(localStorage), ...Object.values(sessionStorage)]); check(storage.every(value => [...secrets].every(secret => !value.includes(secret))), 'credential_in_storage');
  check(await page.locator('input[type="password"]').evaluateAll(items => items.every(item => item.value === '')), 'password_retained');
}
async function screenshot(page, name) {
  await privacy(page); await page.evaluate(() => document.fonts.ready); await page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1), 'horizontal_overflow');
  check(await page.evaluate(() => { const images = [...document.querySelectorAll('img[alt="Sifruno"]')]; return images.length > 0 && images.every(image => image.complete && image.naturalWidth > 0); }), 'brand_not_loaded');
  await page.screenshot({ path: join(output, name), fullPage: !name.startsWith('dialog-'), timeout: 15000 }); report.screenshots[name] = hash(await bounded(join(output, name), 8 << 20, output));
}
function healthy(stats) { check(stats.page_errors === 0 && stats.external_requests === 0 && stats.asset_failures === 0 && stats.out_of_scope_mutations === 0, 'browser_resource_or_scope_error'); }
const restoreButton = (page, backup) => page.getByRole('button', { name: 'Restore backup ' + backup.id, exact: true });
const confirmationLabel = 'I reviewed the verified preview and understand that the current saved files will be replaced.';
async function openPreview(page, backup, path, revision, status = 200, verified = true) {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === 'POST');
  await restoreButton(page, backup).click(); await page.getByTestId('backup-restore-confirm').waitFor({ state: 'visible' });
  const response = await pending; check(JSON.stringify(JSON.parse(response.request().postData())) === JSON.stringify({ backup_id: backup.id, expected_revision: revision }), 'ui_preview_binding_body');
  const value = await responseJSON(response, status, 'preview_response_status');
  if (status === 200 && verified) await page.getByTestId('restore-preview-verified').waitFor(); else await page.getByTestId('restore-preview-error').waitFor();
  await page.waitForFunction(() => !document.querySelector('[data-testid="backups-page"]')?.querySelector('.website-busy')); return value;
}
async function cancelPreview(page, backup, escape = false) {
  if (escape) await page.keyboard.press('Escape'); else await page.getByRole('button', { name: 'Cancel restore', exact: true }).click();
  await page.getByTestId('backup-restore-confirm').waitFor({ state: 'detached' }); await settled(page);
  check(await restoreButton(page, backup).evaluate(button => button === document.activeElement), 'restore_focus_not_returned');
}
async function refreshPreviewFailure(page) {
  await page.getByTestId('backup-restore-confirm').getByRole('button', { name: 'Refresh backup records', exact: true }).click();
  await page.getByTestId('backup-restore-confirm').waitFor({ state: 'detached' }); await settled(page);
}
async function observeState(context, server, base) {
  const [site, files, backups, schedule, trail] = await Promise.all([base, base + '/files', base + '/backups', base + '/backup-schedule', '/api/v1/trail'].map(path => api(context, server, path)));
  check(Array.isArray(files.items) && Array.isArray(backups.items) && Array.isArray(trail.items), 'observed_state_contract');
  return { site, files, backups, schedule, trail };
}
const observationHash = value => hash(Buffer.from(JSON.stringify(value)));
async function writeNativeFile(context, server, base, csrf, path, content) {
  const site = await api(context, server, base), files = await api(context, server, base + '/files');
  const existing = files.items.find(file => file.path === path);
  return api(context, server, base + '/file', { method: 'PUT', csrf, data: { path, content, expected_sha256: existing?.sha256 ?? '', expected_revision: site.revision } });
}
async function nativeBackup(context, server, base, csrf) {
  const site = await api(context, server, base);
  return api(context, server, base + '/backups', { method: 'POST', csrf, data: { expected_revision: site.revision } });
}
async function assertFourKinds(page, value) {
  const expected = { added: 1, modified: 1, removed: 1, unchanged: 1 };
  check(JSON.stringify(value.counts) === JSON.stringify(expected), 'actual_four_kind_counts');
  check(value.files.map(file => file.path + ':' + file.kind).join(',') === 'currentonly.txt:removed,index.html:modified,stay.txt:unchanged,target.css:added', 'actual_four_kind_direction');
  for (const [kind, count] of Object.entries(expected)) check(await page.getByTestId('restore-count-' + kind).innerText() === String(count), 'ui_four_kind_counts');
  check(await page.getByTestId('restore-preview-verified').locator('li').count() === 4 && await page.getByTestId('restore-confirm').isDisabled() && !await page.getByLabel(confirmationLabel, { exact: true }).isChecked(), 'review_not_required_or_file_union_missing');
}
async function createSite(context, server, csrf, name, domain) { const site = await api(context, server, '/api/v1/sites', { method: 'POST', data: { name, domain }, csrf }); check(/^[a-f0-9]{32}$/.test(site.id) && Number.isSafeInteger(site.revision), 'created_site_contract'); return site; }
async function delayedRoute(page, pattern, method, code) {
  let received, release, finished; const arrived = new Promise(done => { received = done; }), gate = new Promise(done => { release = done; }), delivered = new Promise(done => { finished = done; }); let failed = false;
  releases.add(release);
  const handler = async route => {
    if (route.request().method() !== method) return route.continue();
    try { const response = await route.fetch({ timeout: 10000, maxRedirects: 0 }); check(response.status() === 200, code); received(); await gate; await route.fulfill({ response }); }
    catch { failed = true; received(); } finally { finished(); }
  };
  await page.route(pattern, handler);
  return { arrived: () => timeout(arrived, 10000, 'delayed_route_not_arrived'), finish: async () => { release(); await timeout(delivered, 10000, 'delayed_route_not_finished'); releases.delete(release); await page.unroute(pattern, handler); check(!failed, 'delayed_response_delivery_failed'); } };
}
async function startPublic(server) {
  const allowed = new Set(['/api/v1/status', '/api/v1/platform', '/api/v1/server', '/api/v1/services']);
  publicServer = httpServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://127.0.0.1'); if (!['GET', 'HEAD'].includes(request.method)) { response.writeHead(405); return response.end(); }
      if (url.pathname.startsWith('/api/')) {
        if (!allowed.has(url.pathname)) { response.writeHead(404); return response.end(); }
        const upstream = await fetch(server.origin + url.pathname + url.search, { redirect: 'error', signal: AbortSignal.timeout(10000) }); const bytes = Buffer.from(await upstream.arrayBuffer()); check(bytes.length <= 2 << 20, 'public_metrics_bound');
        response.writeHead(upstream.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); return response.end(bytes);
      }
      const path = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).slice(1), file = resolve(ui, path); let bytes = await bounded(file, 8 << 20, ui);
      if (path === 'index.html') bytes = Buffer.from(bytes.toString('utf8').replace('<head>', '<head><meta name="sifruno-public-preview" content="true">'));
      const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json' };
      response.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' }); response.end(bytes);
    } catch { response.writeHead(404); response.end(); }
  });
  publicServer.listen(0, '127.0.0.1'); await once(publicServer, 'listening'); publicOrigin = 'http://127.0.0.1:' + publicServer.address().port;
}

async function execute() {
  check(basename(root) === 'restore-preview-ui-sol' && basename(dirname(root)) === '.worktrees' && await realpath(root) === root, 'owner_root_not_admitted');
  const args = process.argv.slice(2); check(args.length === 2 && args[0] === '--source-root' && isAbsolute(args[1]), 'explicit_source_root_required'); sourceRoot = resolve(args[1]);
  check(sourceRoot === join(primary, '.worktrees/restore-preview-integration') && await realpath(sourceRoot) === sourceRoot, 'source_root_not_admitted');
  binary = join(sourceRoot, '.cache/restore-preview/sifruno.exe'); ui = join(sourceRoot, 'web/dist');
  await directory(fixture); await directory(output); await directory(join(fixture, 'temp'));
  report.harness_sha256 = hash(await bounded(fileURLToPath(import.meta.url), 1 << 20, root));
  report.source_catalog = await sourceCatalog(); report.source_catalog_sha256 = hash(Buffer.from(JSON.stringify(report.source_catalog)));
  report.ui_assets = await uiCatalog(); report.ui_catalog_sha256 = hash(Buffer.from(JSON.stringify(report.ui_assets)));
  const binaryBytes = await bounded(binary, 80 << 20, sourceRoot); report.binary_sha256 = hash(binaryBytes);
  const ownedBinary = join(fixture, 'sifruno.exe'); await writeFile(ownedBinary, binaryBytes, { flag: 'wx' }); check(hash(await bounded(ownedBinary, 80 << 20, fixture)) === report.binary_sha256, 'owned_binary_copy_mismatch');
  const require = createRequire(join(primary, 'package.json')); ({ chromium } = require('playwright'));
  const pkg = await bounded(join(primary, 'node_modules/playwright/package.json'), 32768, primary); report.playwright = { version: JSON.parse(pkg).version, package_sha256: hash(pkg) }; report.node_version = process.version;
  const executable = chromium.executablePath(); report.browser_tool_sha256 = hash(await bounded(executable, 256 << 20, dirname(executable)));
  for (const name of ['TEMP', 'TMP', 'TMPDIR']) process.env[name] = join(fixture, 'temp');
  phase = 'fresh_owned_process'; const server = await startServer(ownedBinary);
  browser = await chromium.launch({ headless: true, executablePath: executable, env: environment(), timeout: 15000 }); report.browser_version = browser.version(); await startPublic(server);
  const { context, page, stats } = await contextFor(server); diagnosticPage = page; await page.goto(server.origin); await nav(page, 'backups');
  await page.getByLabel('Operator access key', { exact: true }).waitFor(); check(stats.site_requests === 0 && stats.preview_posts === 0 && stats.restore_posts === 0, 'signed_out_private_request');
  phase = 'actual_ui_login_product_seed'; await login(page, server); const session = await api(context, server, '/api/v1/session'), csrf = session.csrf_token;
  let site = await createSite(context, server, csrf, 'Restore QA alpha', 'restore-alpha.test'); const second = await createSite(context, server, csrf, 'Restore QA bravo', 'restore-bravo.test');
  const base = '/api/v1/sites/' + site.id, path = base + '/restore-preview';
  const originalIndex = await api(context, server, base + '/file?path=index.html');
  const backupA = await nativeBackup(context, server, base, csrf);
  await writeNativeFile(context, server, base, csrf, 'target.css', 'body { color: teal; }'); await writeNativeFile(context, server, base, csrf, 'stay.txt', 'Unchanged owned fixture');
  const backupB = await nativeBackup(context, server, base, csrf); site = await api(context, server, base);
  await api(context, server, base + '/restore', { method: 'POST', csrf, data: { backup_id: backupA.id, expected_revision: site.revision } });
  await writeNativeFile(context, server, base, csrf, 'index.html', '<!doctype html><title>Current owned fixture</title>');
  await writeNativeFile(context, server, base, csrf, 'currentonly.txt', 'Removed by the selected restore'); await writeNativeFile(context, server, base, csrf, 'stay.txt', 'Unchanged owned fixture');
  site = await api(context, server, base); await refresh(page); await page.getByTestId('backups-site-picker').selectOption(site.id); await settled(page);
  // Keep an actual unsaved Websites editor draft through preview/restore; do not send it.
  await nav(page, 'websites'); await page.getByLabel('File content', { exact: true }).waitFor(); const editorDraft = '<!doctype html><title>Unsaved owned draft</title>'; await page.getByLabel('File content', { exact: true }).fill(editorDraft);
  await nav(page, 'backups'); await settled(page); report.workflow.actual_ui_login_four_kind_product_seed = true;
  phase = 'actual_readonly_preview_cancel_escape'; const beforePreview = await observeState(context, server, base), beforeRestorePosts = stats.restore_posts;
  const actualPreview = await openPreview(page, backupB, path, site.revision); await assertFourKinds(page, actualPreview);
  check(actualPreview.site_id === site.id && actualPreview.current_revision === site.revision && actualPreview.backup_id === backupB.id && actualPreview.backup_sha256 === backupB.sha256 && actualPreview.backup_revision === backupB.revision, 'actual_preview_identity');
  check(await page.getByRole('button', { name: 'Cancel restore', exact: true }).evaluate(button => button === document.activeElement), 'restore_cancel_initial_focus');
  check(observationHash(await observeState(context, server, base)) === observationHash(beforePreview) && stats.restore_posts === beforeRestorePosts, 'preview_mutated_observed_state');
  report.preview_readonly_observation_sha256 = observationHash(beforePreview); await cancelPreview(page, backupB);
  await openPreview(page, backupB, path, site.revision); await cancelPreview(page, backupB, true);
  check(observationHash(await observeState(context, server, base)) === observationHash(beforePreview) && stats.restore_posts === beforeRestorePosts, 'cancel_escape_mutated_observed_state');
  report.workflow.actual_preview_four_kinds_readonly_cancel_escape_focus = true;
  phase = 'viewport_matrix'; const cookies = await context.cookies();
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) {
    const view = await contextFor(server, width, theme, cookies); await view.page.goto(server.origin); await nav(view.page, 'backups'); await settled(view.page); await view.page.getByTestId('backups-site-picker').selectOption(site.id); await settled(view.page);
    check(await view.page.evaluate(() => document.documentElement.classList.contains('dark')) === (theme === 'dark'), 'private_theme_mismatch');
    await screenshot(view.page, `private-${width}-${theme}.png`); const value = await openPreview(view.page, backupB, path, site.revision); await assertFourKinds(view.page, value);
    check(await view.page.getByTestId('backup-restore-confirm').evaluate(dialog => { const box = dialog.getBoundingClientRect(); return box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight; }), 'dialog_outside_viewport');
    check(await view.page.getByRole('button', { name: 'Cancel restore', exact: true }).evaluate(button => button === document.activeElement), 'viewport_cancel_initial_focus');
    await screenshot(view.page, `dialog-${width}-${theme}.png`); await cancelPreview(view.page, backupB, true); healthy(view.stats);
    report.private_viewports.push({ width, theme, passed: true, overflow: false, verified_preview_visible: true, four_kind_counts: true, dialog_bounds: true, cancel_focus: true, escape_focus: true, visible_credentials: false, browser_storage_credentials: false, ...view.stats }); await view.context.close();
    const pub = await contextFor(server, width, theme, undefined, true); await pub.page.goto(publicOrigin + '/#backups'); await pub.page.getByRole('heading', { name: 'Server overview', exact: true }).waitFor();
    await screenshot(pub.page, `public-${width}-${theme}.png`); healthy(pub.stats);
    check(await pub.page.getByTestId('nav-backups').count() === 0 && await pub.page.getByTestId('backup-restore-confirm').count() === 0 && await pub.page.evaluate(() => document.documentElement.classList.contains('dark')) === (theme === 'dark') && pub.stats.site_requests === 0 && pub.stats.session_requests === 0 && pub.stats.mutation_requests === 0, 'public_private_request_or_theme');
    report.public_viewports.push({ width, theme, passed: true, overflow: false, restore_hidden: true, ...pub.stats }); await pub.context.close();
  }
  phase = 'actual_stale_preview_confirm'; await openPreview(page, backupB, path, site.revision);
  site = await writeNativeFile(context, server, base, csrf, 'index.html', '<!doctype html><title>Actual concurrent change</title>'); const concurrent = await observeState(context, server, base);
  await page.getByLabel(confirmationLabel, { exact: true }).check(); const staleResponse = page.waitForResponse(value => new URL(value.url()).pathname === base + '/restore' && value.request().method() === 'POST'); await page.getByTestId('restore-confirm').click(); await responseJSON(await staleResponse, 409, 'stale_confirm_not_conflict');
  await page.getByTestId('backup-restore-confirm').getByRole('alert').waitFor(); check(await page.getByTestId('restore-preview-verified').count() === 0 && await page.getByTestId('restore-confirm').isDisabled() && !await page.getByLabel(confirmationLabel, { exact: true }).isChecked(), 'stale_confirmation_not_invalidated');
  check(observationHash(await observeState(context, server, base)) === observationHash(concurrent), 'stale_confirm_overwrote_state'); await refreshPreviewFailure(page); report.workflow.actual_stale_preview_confirm_409_no_overwrite = true;
  phase = 'actual_preview_revision_conflict'; site = await writeNativeFile(context, server, base, csrf, 'index.html', '<!doctype html><title>Second concurrent change</title>');
  await openPreview(page, backupB, path, site.revision - 1, 409); check(await page.getByTestId('restore-confirm').isDisabled(), 'conflict_preview_allowed_restore'); await refreshPreviewFailure(page); report.workflow.actual_preview_revision_conflict_refresh = true;
  phase = 'synthetic_preview_unavailable_and_malformed';
  const beforeSynthetic = observationHash(await observeState(context, server, base)), noRestore = stats.restore_posts;
  for (const mode of ['synthetic503', 'malformed200']) {
    const handler = async route => { if (mode === 'synthetic503') return route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"synthetic_preview_unavailable"}' }); const response = await route.fetch({ timeout: 10000, maxRedirects: 0 }); check(response.status() === 200, 'malformed_donor_status'); const value = await response.json(); value.counts.modified++; return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(value) }); };
    await page.route('**' + path, handler); await openPreview(page, backupB, path, site.revision, mode === 'synthetic503' ? 503 : 200, false);
    check(await page.getByTestId('restore-confirm').isDisabled() && await page.getByTestId('restore-preview-verified').count() === 0 && !await page.getByLabel(confirmationLabel, { exact: true }).isChecked(), 'synthetic_preview_confirmation_admitted');
    await page.unroute('**' + path, handler); await refreshPreviewFailure(page);
  }
  check(stats.restore_posts === noRestore && observationHash(await observeState(context, server, base)) === beforeSynthetic, 'synthetic_preview_sent_restore_or_mutated_state'); report.workflow.synthetic_503_and_malformed_200_dto_blocked_explicit_refresh = true;
  phase = 'delayed_real_preview_lifecycle';
  for (const action of ['cancel', 'escape', 'navigation']) {
    const delayed = await delayedRoute(page, '**' + path, 'POST', 'delayed_actual_preview_status'), beforePosts = stats.preview_posts, restores = stats.restore_posts;
    await restoreButton(page, backupB).click(); await delayed.arrived(); await page.getByTestId('restore-preview-loading').waitFor();
    check(await page.getByTestId('restore-confirm').isDisabled() && await page.getByRole('button', { name: 'Create ZIP backup', exact: true }).isDisabled() && await page.getByTestId('backups-site-picker').isDisabled() && await page.getByTestId('backup-schedule-review').isDisabled(), 'preview_shared_lock_missing');
    await restoreButton(page, backupB).evaluate(button => { button.click(); button.click(); }); await page.getByTestId('restore-confirm').evaluate(button => button.click());
    check(stats.preview_posts === beforePosts + 1 && stats.restore_posts === restores, 'preview_or_restore_duplicate');
    if (action === 'navigation') await page.getByTestId('nav-overview').evaluate(item => item.click()); else if (action === 'escape') await page.keyboard.press('Escape'); else await page.getByRole('button', { name: 'Cancel restore', exact: true }).click();
    await page.getByTestId('backup-restore-confirm').waitFor({ state: 'detached' }); await delayed.finish();
    if (action === 'navigation') await nav(page, 'backups'); await settled(page);
    check(await page.getByTestId('restore-preview-verified').count() === 0 && await page.getByTestId('backup-restore-confirm').count() === 0 && stats.restore_posts === restores, 'late_preview_repopulated_private_review');
    if (action !== 'navigation') check(await restoreButton(page, backupB).evaluate(button => button === document.activeElement), 'delayed_cancel_focus_not_returned');
  }
  report.workflow.delayed_real_preview_cancel_escape_navigation_shared_lock_duplicate_guard = true;
  phase = 'actual_confirm_restore_preview'; await openPreview(page, backupB, path, site.revision);
  phase = 'actual_confirm_restore_checkbox'; await page.getByLabel(confirmationLabel, { exact: true }).check();
  phase = 'actual_confirm_restore_post';
  const restoreResponse = page.waitForResponse(value => new URL(value.url()).pathname === base + '/restore' && value.request().method() === 'POST'); await page.getByTestId('restore-confirm').click();
  const restored = await responseJSON(await restoreResponse, 200, 'actual_restore_status');
  phase = 'actual_confirm_restore_dialog_clear'; await page.getByTestId('backup-restore-confirm').waitFor({ state: 'detached' });
  phase = 'actual_confirm_restore_inventory_refresh'; await settled(page);
  check(restored.id === site.id && restored.revision === site.revision + 1 && await page.getByTestId('backups-inventory').getAttribute('data-revision') === String(restored.revision), 'actual_restore_revision_inventory_not_refreshed');
  phase = 'actual_confirm_restore_api_observations'; const afterRestore = await observeState(context, server, base); check(afterRestore.files.items.map(file => file.path).join(',') === 'index.html,stay.txt,target.css' && (await api(context, server, base + '/file?path=index.html')).content === originalIndex.content && afterRestore.trail.items.length > concurrent.trail.items.length, 'actual_restore_content_or_journal');
  await api(context, server, path, { method: 'POST', csrf, data: { backup_id: backupB.id, expected_revision: site.revision }, status: 409 }); site = restored;
  report.workflow.actual_confirm_restore_content_revision_inventory_journal_and_old_preview_stale = true;
  phase = 'actual_zero_change_preview'; const zeroBefore = observationHash(await observeState(context, server, base)), zeroRestorePosts = stats.restore_posts; const zero = await openPreview(page, backupB, path, site.revision);
  check(zero.counts.added === 0 && zero.counts.modified === 0 && zero.counts.removed === 0 && zero.counts.unchanged === 3 && await page.getByTestId('restore-preview-no-changes').isVisible(), 'actual_zero_change_display');
  check(observationHash(await observeState(context, server, base)) === zeroBefore && stats.restore_posts === zeroRestorePosts, 'zero_preview_mutated_state');
  phase = 'actual_zero_change_cancel'; await cancelPreview(page, backupB);
  phase = 'actual_editor_draft_preservation';
  await nav(page, 'websites'); await page.getByLabel('File content', { exact: true }).waitFor(); check(await page.getByLabel('File content', { exact: true }).inputValue() === editorDraft, 'websites_editor_draft_lost'); await nav(page, 'backups'); await settled(page);
  report.workflow.actual_confirm_restore_content_revision_inventory_journal_and_old_preview_stale = true; report.workflow.actual_zero_change_readonly_and_editor_draft_kept = true;
  phase = 'selected_site_private_clear'; await page.getByTestId('backups-site-picker').selectOption(second.id); await settled(page); check(await page.getByTestId('backup-restore-confirm').count() === 0 && await page.getByTestId('restore-preview-verified').count() === 0 && await page.getByTestId('backup-row').count() === 0, 'cross_site_preview_leak'); await page.getByTestId('backups-site-picker').selectOption(site.id); await settled(page); report.workflow.selected_site_private_clear = true;
  phase = 'synthetic_short_ui_session_expiry_delayed_real_preview';
  const expiring = await contextFor(server, 1440, 'light', cookies);
  const expireFixture = async route => { const response = await route.fetch({ timeout: 10000, maxRedirects: 0 }); const value = await response.json(); check(value.authenticated === true, 'expiry_donor_session'); value.expires_at = new Date(Date.now() + 5000).toISOString(); return route.fulfill({ response, body: JSON.stringify(value) }); };
  await expiring.page.route('**/api/v1/session', expireFixture); await expiring.page.goto(server.origin); await nav(expiring.page, 'backups'); await settled(expiring.page); await expiring.page.getByTestId('backups-site-picker').selectOption(site.id); await settled(expiring.page);
  const expiringPreview = await delayedRoute(expiring.page, '**' + path, 'POST', 'expiry_actual_preview_status'); await restoreButton(expiring.page, backupB).click(); await expiringPreview.arrived();
  await expiring.page.getByLabel('Operator access key', { exact: true }).waitFor(); await expiringPreview.finish();
  check(await expiring.page.getByTestId('restore-preview-verified').count() === 0 && await expiring.page.getByTestId('backup-restore-confirm').count() === 0 && await expiring.page.getByTestId('backups-inventory').count() === 0 && expiring.stats.restore_posts === 0, 'synthetic_ui_expiry_retained_private_state');
  healthy(expiring.stats); await expiring.context.close(); report.workflow.synthetic_short_ui_session_expiry_delayed_actual_preview_clear = true;
  phase = 'actual_logout_private_clear'; const logout = page.waitForResponse(value => new URL(value.url()).pathname === '/api/v1/session/logout' && value.request().method() === 'POST'); await page.getByRole('button', { name: 'Sign out locally', exact: true }).click(); await responseJSON(await logout, 200, 'actual_logout_status'); await page.getByLabel('Operator access key', { exact: true }).waitFor();
  check(await page.getByTestId('backup-restore-confirm').count() === 0 && await page.getByTestId('backups-inventory').count() === 0, 'logout_private_state_not_cleared'); await api(context, server, path, { method: 'POST', csrf, data: { backup_id: backupB.id, expected_revision: site.revision }, status: 401 }); healthy(stats);
  report.workflow.actual_logout_private_clear_and_unauthenticated_preview_denied = true; report.workflow.actual_isolated_tcp = true; report.passed = true;
}

try { await timeout(execute(), 480000, 'overall_execution_bound'); }
catch (error) {
  const operation = ['locator.waitFor', 'locator.click', 'locator.check', 'page.waitForFunction', 'locator.selectOption', 'page.waitForResponse', 'page.goto', 'locator.inputValue'].find(name => String(error.message).startsWith(name));
  report.failure = { phase, code: error.checkCode || 'bounded_browser_operation_failed', ...(operation ? { operation } : {}) }; process.exitCode = 1;
  if (diagnosticPage) report.failure_ui = await diagnosticPage.evaluate(() => {
    const dialog = document.querySelector('[data-testid="backup-restore-confirm"]'), inventory = document.querySelector('[data-testid="backups-inventory"]'), confirm = document.querySelector('[data-testid="restore-confirm"]');
    const revision = inventory?.getAttribute('data-revision');
    return { diagnostic_only: true, dialog_open: Boolean(dialog?.open), preview_present: Boolean(document.querySelector('[data-testid="restore-preview-verified"]')), preview_error_present: Boolean(document.querySelector('[data-testid="restore-preview-error"]')), inventory_fresh: inventory?.getAttribute('data-fresh') === 'true', inventory_revision: /^\d{1,16}$/.test(revision ?? '') ? revision : null, busy_present: Boolean(document.querySelector('.website-busy')), confirm_disabled: confirm ? confirm.disabled : null, signed_out: Boolean(document.querySelector('#backup-access-key')), editor_present: Boolean(document.querySelector('#site-file-content')) };
  }).catch(() => ({ diagnostic_only: true, unavailable: true }));
}
finally {
  for (const release of releases) release(); releases.clear();
  try { if (browser) await timeout(browser.close(), 10000, 'browser_cleanup_bound'); report.cleanup.browser_closed = true; } catch { report.cleanup.browser_closed = false; }
  try { if (publicServer) { publicServer.closeAllConnections(); await timeout(new Promise(done => publicServer.close(done)), 3000, 'public_cleanup_bound'); } report.cleanup.public_fixture_closed = true; } catch { report.cleanup.public_fixture_closed = false; }
  report.cleanup.owned_children_stopped = true; report.cleanup.owned_listeners_closed = true;
  for (const server of servers) {
    try { if (server.child.exitCode === null && server.child.signalCode === null) { const exited = once(server.child, 'exit'); server.child.kill(); await timeout(exited, 10000, 'child_cleanup_bound'); } report.cleanup.owned_children_stopped &&= server.child.exitCode !== null || server.child.signalCode !== null; } catch { report.cleanup.owned_children_stopped = false; }
    try { await fetch(server.origin + '/api/v1/status', { signal: AbortSignal.timeout(500) }); report.cleanup.owned_listeners_closed = false; } catch { /* closed owned listener */ }
    server.key = undefined;
    if (server.logLimitExceeded || server.spawnError) { report.failure ||= { phase: 'owned_process', code: 'owned_process_log_or_spawn_failure' }; process.exitCode = 1; }
  }
  try {
    if (report.source_catalog_sha256) check(hash(Buffer.from(JSON.stringify(await sourceCatalog()))) === report.source_catalog_sha256, 'source_changed_after_execution');
    if (report.binary_sha256) check(hash(await bounded(binary, 80 << 20, sourceRoot)) === report.binary_sha256, 'binary_changed_after_execution');
    if (report.ui_catalog_sha256) check(hash(Buffer.from(JSON.stringify(await uiCatalog()))) === report.ui_catalog_sha256, 'ui_changed_after_execution');
    if (report.harness_sha256) check(hash(await bounded(fileURLToPath(import.meta.url), 1 << 20, root)) === report.harness_sha256, 'harness_changed_after_execution');
    report.source_binary_ui_harness_unchanged = Boolean(report.harness_sha256 && report.binary_sha256 && report.source_catalog_sha256 && report.ui_catalog_sha256);
  } catch (error) { report.failure ||= { phase: 'post_run_inputs', code: error.checkCode || 'input_recheck_failed' }; process.exitCode = 1; }
  for (const [name, value] of Object.entries(savedTemp)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  if (!Object.values(report.cleanup).every(Boolean)) { report.failure ||= { phase: 'cleanup', code: 'owned_cleanup_failed' }; process.exitCode = 1; }
  if (process.exitCode) report.passed = false;
  await directory(output); const bytes = Buffer.from(JSON.stringify(report, null, 2) + '\n'); check(bytes.length <= 2 << 20 && [...secrets].every(value => !bytes.includes(Buffer.from(value))), 'report_secret_or_bound');
  secrets.clear(); await writeFile(join(output, 'report.json'), bytes, { flag: 'wx' });
  console.log(JSON.stringify({ passed: report.passed, report: relative(root, join(output, 'report.json')).split(sep).join('/'), sha256: hash(bytes), private_viewports: report.private_viewports.length, public_viewports: report.public_viewports.length, failure: report.failure, cleanup: report.cleanup }));
}
