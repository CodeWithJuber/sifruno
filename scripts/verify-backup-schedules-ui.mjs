// Actual isolated UI/API observations; no live state, shared-input writes or publication.
// Run from this assigned worktree: node scripts/verify-backup-schedules-ui.mjs --source-root <backup-schedules-integration>
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
const fixture = join(root, '.cache/backup-schedule-ui', runId);
const output = join(root, 'artifacts/backup-schedules-ui', runId);
const servers = [], contexts = [], secrets = new Set(), releases = new Set();
let sourceRoot, binary, ui, chromium, browser, publicServer, publicOrigin, phase = 'admission';
const savedTemp = Object.fromEntries(['TEMP', 'TMP', 'TMPDIR'].map(name => [name, process.env[name]]));
const report = { schema_version: 1, run_id: runId, checked_at: new Date().toISOString(),
  evidence_kind: 'observed_isolated_native_backup_schedules_browser_qa', passed: false,
  platform: process.platform, fixture_only: true, main_state_mutated: false, shared_inputs_mutated: false,
  live_activation: false, paid_provider_calls: 0, compatibility_certified: false, native_scheduled_job_execution_qualified: false,
  source_role: 'reviewed backup-schedules-integration read-only inputs', workflow: {}, private_viewports: [], public_viewports: [], cleanup: {}, screenshots: {},
  timing_limit: 'Synthetic 503 is an intercepted PUT response. Delayed real PUT/navigation and real GET/logout inspect late UI clearing; programmatic navigation bypasses the modal for that controlled lifecycle case.',
  public_limit: 'Local HTML public-mode/read-only metrics fixture; no production proxy, tunnel, physical phone or remote authorization qualification.',
  runner_limit: 'Flag-on and flag-off fresh processes, configuration and native manual ZIP creation observed. Future due-time execution is qualified separately by core/CLI receipts.' };

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
  check(/^\/api\/v1\/(session(?:\/(?:login|logout))?|sites(?:\/[a-f0-9]{32}(?:\/(?:backup-schedule|backups|file))?)?)(?:\?path=index\.html)?$/.test(path), 'api_path_not_admitted');
  const response = await context.request.fetch(server.origin + path, { method, data, maxRedirects: 0, timeout: 10000,
    headers: { Origin: server.origin, Accept: 'application/json', ...(data !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } });
  const value = await responseJSON(response, status, 'api_status_mismatch'); for (const cookie of await context.cookies()) secrets.add(cookie.value); return value;
}
async function startServer(enabled, ownedBinary) {
  const state = join(fixture, enabled ? 'runner-on-state' : 'runner-off-state');
  const origin = 'http://127.0.0.1:' + await freePort();
  const child = spawn(ownedBinary, ['--listen', new URL(origin).host, '--sites-listen=', '--state', state, '--ui', ui, ...(enabled ? ['--backup-scheduler'] : [])], { cwd: root, env: environment(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const server = { enabled, origin, child, key: undefined, logBytes: 0, logLimitExceeded: false, spawnError: false }; servers.push(server);
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
  const stats = { page_errors: 0, external_requests: 0, session_requests: 0, site_requests: 0, schedule_requests: 0, schedule_puts: 0, mutation_requests: 0, asset_failures: 0, out_of_scope_mutations: 0 };
  await context.route('**/*', route => {
    const request = route.request(), url = new URL(request.url()); if (!['http:', 'https:'].includes(url.protocol)) return route.continue();
    if (![server.origin, publicOrigin].includes(url.origin)) { stats.external_requests++; return route.abort(); }
    const allowedWrite = !publicMode && (/^\/api\/v1\/session\/(login|logout)$/.test(url.pathname) || url.pathname === '/api/v1/sites' || /^\/api\/v1\/sites\/[a-f0-9]{32}\/(file|backups|backup-schedule)$/.test(url.pathname));
    if (!['GET', 'HEAD'].includes(request.method()) && !allowedWrite) { stats.out_of_scope_mutations++; return route.abort(); } return route.continue();
  });
  context.on('request', request => { const url = new URL(request.url()); if (url.pathname.startsWith('/api/v1/session')) stats.session_requests++; if (url.pathname.startsWith('/api/v1/sites')) stats.site_requests++; if (url.pathname.endsWith('/backup-schedule')) { stats.schedule_requests++; if (request.method() === 'PUT') stats.schedule_puts++; } if (!['GET', 'HEAD'].includes(request.method())) stats.mutation_requests++; });
  context.on('response', response => { if (response.status() >= 400 && /\/(assets|brand)\//.test(new URL(response.url()).pathname)) stats.asset_failures++; });
  const page = await context.newPage(); page.on('pageerror', () => stats.page_errors++); contexts.push(context); return { context, page, stats };
}
async function nav(page, id) { const item = page.getByTestId('nav-' + id); if (!await item.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click(); await item.click(); }
async function settled(page) {
  await page.getByTestId('backups-page').waitFor({ state: 'visible' });
  await page.waitForFunction(() => document.querySelector('[data-testid="backups-inventory"]')?.getAttribute('data-fresh') === 'true' && document.querySelector('[data-testid="backup-schedule"]')?.getAttribute('data-fresh') === 'true' && !document.querySelector('.website-busy'));
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
async function review(page) { await page.getByTestId('backup-schedule-review').click(); await page.getByTestId('backup-schedule-confirm').waitFor({ state: 'visible' }); }
async function save(page, path, status = 200, expected) {
  await review(page); const response = page.waitForResponse(value => new URL(value.url()).pathname === path && value.request().method() === 'PUT');
  await page.getByTestId('backup-schedule-save').click(); const observed = await response;
  if (expected) check(JSON.stringify(JSON.parse(observed.request().postData())) === JSON.stringify(expected), 'ui_expected_revisions_or_draft_mismatch');
  const value = await responseJSON(observed, status, 'ui_schedule_status'); await page.getByTestId('backup-schedule-confirm').waitFor({ state: 'hidden' });
  if (status === 200) await settled(page); else await page.getByTestId('backup-schedule').getByRole('alert').waitFor(); return value;
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
  check(basename(root) === 'backup-schedules-ui-sol' && basename(dirname(root)) === '.worktrees' && await realpath(root) === root, 'owner_root_not_admitted');
  const args = process.argv.slice(2); check(args.length === 2 && args[0] === '--source-root' && isAbsolute(args[1]), 'explicit_source_root_required'); sourceRoot = resolve(args[1]);
  check(sourceRoot === join(primary, '.worktrees/backup-schedules-integration') && await realpath(sourceRoot) === sourceRoot, 'source_root_not_admitted');
  binary = join(sourceRoot, '.cache/backup-schedules/sifruno.exe'); ui = join(sourceRoot, 'web/dist');
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
  phase = 'fresh_owned_processes'; const on = await startServer(true, ownedBinary), off = await startServer(false, ownedBinary);
  browser = await chromium.launch({ headless: true, executablePath: executable, env: environment(), timeout: 15000 }); report.browser_version = browser.version(); await startPublic(on);
  const workflow = await contextFor(on), { context, page, stats } = workflow; await page.goto(on.origin); await nav(page, 'backups');
  await page.getByLabel('Operator access key', { exact: true }).waitFor(); check(stats.schedule_requests === 0, 'signed_out_schedule_request');
  phase = 'actual_ui_login_and_site_setup'; await login(page, on); const session = await api(context, on, '/api/v1/session'), csrf = session.csrf_token;
  let site = await createSite(context, on, csrf, 'Schedule QA alpha', 'schedule-alpha.test'); const second = await createSite(context, on, csrf, 'Schedule QA bravo', 'schedule-bravo.test');
  await refresh(page); await page.getByTestId('backups-site-picker').selectOption(site.id); await settled(page);
  const base = '/api/v1/sites/' + site.id, path = base + '/backup-schedule'; check((await api(context, on, path)).schedule === null, 'initial_schedule_not_absent');
  check(await page.getByTestId('backup-schedule').getByText('Not configured', { exact: true }).isVisible(), 'absent_schedule_ui'); report.workflow.actual_ui_login_absent_schedule = true;
  phase = 'confirmation_cancel_escape'; await page.getByLabel('Enable scheduled backups', { exact: true }).check(); const reviewButton = page.getByTestId('backup-schedule-review'), beforeCancel = stats.schedule_puts;
  await review(page); check(await page.getByRole('button', { name: 'Cancel schedule change', exact: true }).evaluate(button => button === document.activeElement), 'dialog_cancel_not_focused');
  await page.getByRole('button', { name: 'Cancel schedule change', exact: true }).click(); check(await reviewButton.evaluate(button => button === document.activeElement), 'cancel_focus_not_restored');
  await review(page); await page.keyboard.press('Escape'); await page.getByTestId('backup-schedule-confirm').waitFor({ state: 'hidden' }); check(await reviewButton.evaluate(button => button === document.activeElement), 'escape_focus_not_restored');
  check(stats.schedule_puts === beforeCancel && (await api(context, on, path)).schedule === null, 'cancel_or_escape_mutated_schedule'); report.workflow.confirmation_cancel_escape_focus = true;
  phase = 'actual_daily_pause_resume'; let saved = (await save(page, path)).schedule; check(saved.interval === 'daily' && saved.enabled && saved.revision === 1, 'daily_configuration_not_confirmed');
  check((await api(context, on, base)).revision === site.revision, 'configuration_changed_site_revision');
  await page.getByLabel('Enable scheduled backups', { exact: true }).uncheck(); saved = (await save(page, path)).schedule; check(!saved.enabled && saved.revision === 2, 'pause_not_confirmed');
  await page.getByLabel('Enable scheduled backups', { exact: true }).check(); saved = (await save(page, path)).schedule; check(saved.enabled && saved.revision === 3, 'resume_not_confirmed'); report.workflow.actual_daily_pause_resume = true;
  phase = 'actual_dual_revision_conflict'; await page.getByLabel('Interval', { exact: true }).selectOption('weekly'); const file = await api(context, on, base + '/file?path=index.html');
  site = await api(context, on, base + '/file', { method: 'PUT', csrf, data: { path: 'index.html', content: '<!doctype html><title>Owned schedule QA</title><main>Revision conflict fixture</main>', expected_sha256: file.sha256, expected_revision: site.revision } });
  saved = (await api(context, on, path, { method: 'PUT', csrf, data: { expected_revision: site.revision, expected_schedule_revision: saved.revision, interval: 'hourly', enabled: true } })).schedule;
  await save(page, path, 409); check(await page.getByLabel('Interval', { exact: true }).inputValue() === 'weekly' && await page.getByLabel('Enable scheduled backups', { exact: true }).isChecked(), 'conflict_draft_lost');
  check((await api(context, on, path)).schedule.interval === 'hourly', 'conflict_mutated_schedule'); await refresh(page);
  check(await page.getByLabel('Interval', { exact: true }).inputValue() === 'weekly', 'refresh_replaced_conflict_draft');
  saved = (await save(page, path, 200, { expected_revision: site.revision, expected_schedule_revision: saved.revision, interval: 'weekly', enabled: true })).schedule; check(saved.revision === 5, 'review_retry_revision'); report.workflow.actual_dual_revision_conflict_draft_refresh_review = true;
  phase = 'synthetic_503_draft_retention'; await page.getByLabel('Interval', { exact: true }).selectOption('daily'); await page.getByLabel('Enable scheduled backups', { exact: true }).uncheck();
  const refuse = route => route.request().method() === 'PUT' ? route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"synthetic_unavailable"}' }) : route.continue(); await page.route('**' + path, refuse); await save(page, path, 503);
  check(await page.getByLabel('Interval', { exact: true }).inputValue() === 'daily' && !await page.getByLabel('Enable scheduled backups', { exact: true }).isChecked() && await reviewButton.isDisabled(), 'synthetic_503_draft_or_freshness_lost');
  check((await api(context, on, path)).schedule.revision === saved.revision, 'synthetic_503_changed_server'); await page.unroute('**' + path, refuse); await refresh(page);
  saved = (await save(page, path, 200, { expected_revision: site.revision, expected_schedule_revision: saved.revision, interval: 'daily', enabled: false })).schedule; report.workflow.synthetic_503_draft_retention_explicit_retry = true;
  phase = 'actual_manual_backup_with_schedule'; const beforeManual = await api(context, on, path); const manualResponse = page.waitForResponse(response => new URL(response.url()).pathname === base + '/backups' && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Create ZIP backup', exact: true }).click(); const archive = await responseJSON(await manualResponse, 200, 'manual_backup_status'); await settled(page);
  check(/^[a-f0-9]{32}$/.test(archive.id) && archive.files > 0 && archive.bytes > 0 && /^[a-f0-9]{64}$/.test(archive.sha256), 'manual_native_archive_contract');
  check((await api(context, on, base + '/backups')).items.some(item => item.id === archive.id) && JSON.stringify((await api(context, on, path)).schedule) === JSON.stringify(beforeManual.schedule), 'manual_backup_schedule_history_changed');
  report.workflow.actual_manual_native_backup_schedule_history_preserved = true;
  phase = 'cross_site_private_draft_boundary'; await page.getByLabel('Interval', { exact: true }).selectOption('hourly'); await page.getByTestId('backups-site-picker').selectOption(second.id); await settled(page);
  check((await api(context, on, '/api/v1/sites/' + second.id + '/backup-schedule')).schedule === null && await page.getByLabel('Interval', { exact: true }).inputValue() === 'daily' && !await page.getByLabel('Enable scheduled backups', { exact: true }).isChecked(), 'cross_site_draft_leaked');
  await page.getByTestId('backups-site-picker').selectOption(site.id); await settled(page); report.workflow.cross_site_draft_boundary = true;
  phase = 'delayed_real_put_navigation'; await page.getByLabel('Interval', { exact: true }).selectOption('weekly'); await page.getByLabel('Enable scheduled backups', { exact: true }).check(); const delayedPut = await delayedRoute(page, '**' + path, 'PUT', 'delayed_actual_put_status');
  await review(page); const beforeDelayed = stats.schedule_puts; await page.getByTestId('backup-schedule-save').click(); await delayedPut.arrived();
  check(await page.getByTestId('backup-schedule-save').isDisabled() && await page.getByRole('button', { name: 'Create ZIP backup', exact: true }).isDisabled() && await page.getByTestId('backups-site-picker').isDisabled(), 'pending_mutation_not_locked');
  await page.getByTestId('backup-schedule-save').evaluate(button => { button.click(); button.click(); }); check(stats.schedule_puts === beforeDelayed + 1, 'duplicate_schedule_put');
  await page.getByTestId('nav-overview').evaluate(item => item.click()); await page.getByTestId('backup-schedule').waitFor({ state: 'detached' }); await delayedPut.finish();
  check((await api(context, on, path)).schedule.interval === 'weekly', 'delayed_actual_put_not_observed'); await nav(page, 'backups'); await settled(page);
  check(!await page.getByText('Backup schedule saved and enabled.', { exact: true }).isVisible(), 'late_navigation_completion_rendered'); report.workflow.delayed_real_put_navigation_late_state_guard_duplicate_block = true;
  phase = 'viewport_matrix'; const cookies = await context.cookies();
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) {
    const view = await contextFor(on, width, theme, cookies); await view.page.goto(on.origin); await nav(view.page, 'backups'); await settled(view.page); await view.page.getByTestId('backups-site-picker').selectOption(site.id); await settled(view.page);
    check(await view.page.evaluate(() => document.documentElement.classList.contains('dark')) === (theme === 'dark'), 'private_theme_mismatch');
    await screenshot(view.page, `private-${width}-${theme}.png`); await view.page.getByLabel('Enable scheduled backups', { exact: true }).uncheck(); await review(view.page);
    check(await view.page.getByTestId('backup-schedule-confirm').evaluate(dialog => { const box = dialog.getBoundingClientRect(); return box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight; }), 'dialog_outside_viewport');
    await screenshot(view.page, `dialog-${width}-${theme}.png`); await view.page.keyboard.press('Escape'); healthy(view.stats);
    report.private_viewports.push({ width, theme, passed: true, overflow: false, schedule_visible: true, dialog_bounds: true, visible_credentials: false, browser_storage_credentials: false, ...view.stats }); await view.context.close();
    const pub = await contextFor(on, width, theme, undefined, true); await pub.page.goto(publicOrigin + '/#backups'); await pub.page.getByRole('heading', { name: 'Server overview', exact: true }).waitFor();
    check(await pub.page.getByTestId('nav-backups').count() === 0 && await pub.page.getByTestId('backup-schedule').count() === 0 && pub.stats.site_requests === 0 && pub.stats.session_requests === 0 && pub.stats.mutation_requests === 0, 'public_private_request_or_view');
    await screenshot(pub.page, `public-${width}-${theme}.png`); healthy(pub.stats);
    check(await pub.page.evaluate(() => document.documentElement.classList.contains('dark')) === (theme === 'dark') && pub.stats.site_requests === 0 && pub.stats.session_requests === 0 && pub.stats.mutation_requests === 0, 'public_theme_or_private_request');
    report.public_viewports.push({ width, theme, passed: true, overflow: false, schedule_hidden: true, ...pub.stats }); await pub.context.close();
  }
  phase = 'actual_runner_off_capability'; const disabled = await contextFor(off); await disabled.page.goto(off.origin); await nav(disabled.page, 'backups'); await login(disabled.page, off); const offSession = await api(disabled.context, off, '/api/v1/session');
  const offSite = await createSite(disabled.context, off, offSession.csrf_token, 'Runner off QA', 'schedule-off.test'); await refresh(disabled.page);
  check((await api(disabled.context, off, '/api/v1/sites/' + offSite.id + '/backup-schedule')).runner_enabled === false && await disabled.page.getByLabel('Enable scheduled backups', { exact: true }).isDisabled(), 'runner_off_enabled_ui');
  await save(disabled.page, '/api/v1/sites/' + offSite.id + '/backup-schedule'); check((await api(disabled.context, off, '/api/v1/sites/' + offSite.id + '/backup-schedule')).schedule.enabled === false, 'runner_off_paused_save_failed'); healthy(disabled.stats); report.workflow.actual_runner_off_enable_disabled_paused_save = true;
  phase = 'delayed_real_get_logout'; const delayedGet = await delayedRoute(page, '**' + path, 'GET', 'delayed_actual_get_status'); await page.getByRole('button', { name: 'Refresh backup records', exact: true }).click(); await delayedGet.arrived();
  const logoutResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/session/logout' && response.request().method() === 'POST'); await page.getByRole('button', { name: 'Sign out locally', exact: true }).click(); await responseJSON(await logoutResponse, 200, 'logout_status');
  await page.getByLabel('Operator access key', { exact: true }).waitFor(); await delayedGet.finish(); check(await page.getByTestId('backup-schedule').count() === 0 && await page.getByTestId('backups-inventory').count() === 0, 'logout_late_get_retained_private_ui');
  await api(context, on, path, { status: 401 }); healthy(stats); report.workflow.actual_logout_delayed_get_private_clear = true;
  report.workflow.actual_isolated_tcp = true; report.passed = true;
}

try { await timeout(execute(), 480000, 'overall_execution_bound'); }
catch (error) { report.failure = { phase, code: error.checkCode || 'bounded_browser_operation_failed' }; process.exitCode = 1; }
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
