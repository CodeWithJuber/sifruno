// Actual browser session writes use one fresh, owned loopback server only.
// Keys, cookies, CSRF, request bodies and browser diagnostics never enter reports.
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
const primary = basename(dirname(root)) === '.worktrees' ? resolve(root, '../..') : root;
const { chromium } = createRequire(join(primary, 'package.json'))('playwright');
const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { checkCode: code }); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const runId = new Date().toISOString().replace(/[-:.Z]/g, '') + '-' + randomUUID().slice(0, 8);
const output = join(root, 'artifacts/operator-sessions', runId);
const fixture = join(root, '.cache/operator-session-ui', runId);
const state = join(fixture, 'state');
const binary = join(root, '.cache/session-batch/sifruno.exe');
const ui = join(root, 'web/dist');
const secrets = new Set();
const contexts = [];
let phase = 'prepare', child, browser, publicServer, origin, publicOrigin, credential, delayedRelease;
const report = { schema_version: 1, run_id: runId, checked_at: new Date().toISOString(),
  evidence_kind: 'observed_isolated_operator_sessions_browser_qa', passed: false,
  platform: process.platform, fixture_only: true, main_state_mutated: false, paid_provider_calls: 0,
  live_activation: false, remote_auth_qualified: false, compatibility_certified: false,
  workflow: {}, private_viewports: [], public_mode_viewports: [], sources: {}, cleanup: {},
  public_mode_limit: 'Local HTML declaration/read-only metrics fixture; production proxy exclusion is separately tested by Go. No tunnel, publication or physical phone test.',
  timing_limit: 'One delayed real mutation response/unmount and one synthetic 503; browser clock expiry is distinct from server expiry tests.' };

function contained(ancestor, path) { const rel = relative(ancestor, path); return rel && !isAbsolute(rel) && !rel.split(sep).includes('..'); }
async function directory(path) {
  check(contained(root, path), 'directory_escape');
  let current = await realpath(root);
  for (const part of relative(root, path).split(sep)) {
    current = join(current, part);
    try { await mkdir(current); } catch (e) { if (e.code !== 'EEXIST') throw e; }
    const stat = await lstat(current);
    check(stat.isDirectory() && !stat.isSymbolicLink() && await realpath(current) === current, 'directory_not_regular');
  }
}
async function bounded(path, maximum, ancestor = root) {
  check(contained(ancestor, path), 'input_escape');
  let current = await realpath(ancestor);
  for (const part of relative(ancestor, path).split(sep)) {
    current = join(current, part);
    check(!(await lstat(current)).isSymbolicLink() && await realpath(current) === current, 'input_link');
  }
  const stat = await lstat(current);
  check(stat.isFile() && stat.nlink === 1 && stat.size > 0 && stat.size <= maximum, 'input_not_bounded_regular');
  const bytes = await readFile(current);
  check(bytes.length === stat.size, 'input_changed'); return bytes;
}
async function freePort() {
  const server = tcpServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise((resolve, reject) => server.close(e => e ? reject(e) : resolve())); return port;
}
async function uiCatalog() {
  const entries = []; let total = 0;
  async function visit(path) {
    const stat = await lstat(path); check(!stat.isSymbolicLink(), 'ui_catalog_link');
    if (stat.isDirectory()) { for (const name of (await readdir(path)).sort()) await visit(join(path, name)); return; }
    const bytes = await bounded(path, 8 << 20, ui); total += bytes.length;
    check(entries.length < 512 && total <= 80 << 20, 'ui_catalog_bound');
    entries.push({ path: relative(ui, path).split(sep).join('/'), bytes: bytes.length, sha256: hash(bytes) });
  }
  await visit(ui); return entries;
}
async function api(context, path, { method = 'GET', data, csrf, status = 200 } = {}) {
  const response = await context.request.fetch(origin + path, { method, data, maxRedirects: 0, timeout: 10000,
    headers: { Origin: origin, Accept: 'application/json', ...(data !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } });
  check(response.status() === status, 'api_status_mismatch');
  const bytes = await response.body(); check(bytes.length <= 1 << 20, 'api_response_bound');
  const value = JSON.parse(bytes.toString('utf8'));
  if (value.csrf_token) secrets.add(value.csrf_token);
  for (const c of await context.cookies()) secrets.add(c.value);
  return value;
}
async function contextFor(width = 1440, theme = 'light', cookies) {
  const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, colorScheme: theme, locale: 'en-GB' });
  await context.addInitScript(value => localStorage.setItem('sifruno-theme', value), theme);
  if (cookies) await context.addCookies(cookies);
  const stats = { page_errors: 0, external_requests: 0, session_requests: 0, mutation_requests: 0, asset_failures: 0 };
  context.on('request', request => {
    const url = new URL(request.url());
    if (!['http:', 'https:'].includes(url.protocol)) return;
    if (![origin, publicOrigin].includes(url.origin)) stats.external_requests++;
    if (url.pathname.startsWith('/api/v1/session')) stats.session_requests++;
    if (request.method() !== 'GET' && request.method() !== 'HEAD') stats.mutation_requests++;
  });
  context.on('response', response => { if (response.status() >= 400 && /\/(assets|brand)\//.test(new URL(response.url()).pathname)) stats.asset_failures++; });
  const page = await context.newPage(); page.on('pageerror', () => stats.page_errors++);
  contexts.push(context); return { context, page, stats };
}
async function nav(page, id) {
  const target = page.getByTestId('nav-' + id);
  if (!await target.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
  await target.click();
}
async function rowCount(page, count) { await page.waitForFunction(n => document.querySelectorAll('[data-testid="access-other-row"]').length === n, count); }
async function settled(page) { await page.getByTestId('access-page').waitFor(); await page.waitForFunction(() => document.querySelector('[data-testid="access-page"]')?.getAttribute('aria-busy') === 'false'); }
async function refresh(page) { await page.getByTestId('access-refresh').click(); await settled(page); }
async function login(page) {
  await page.getByLabel('Operator access key', { exact: true }).fill(credential);
  await page.getByRole('button', { name: 'Sign in locally', exact: true }).click();
  await page.getByTestId('access-current-row').waitFor(); await settled(page);
}
async function extraSession() {
  const v = await contextFor(); const s = await api(v.context, '/api/v1/session/login', { method: 'POST', data: { access_key: credential } });
  const inv = await api(v.context, '/api/v1/session/sessions');
  return { ...v, csrf: s.csrf_token, id: inv.items.find(x => x.current).id };
}
async function privacy(page, inventory) {
  const text = await page.locator('body').innerText();
  check([...secrets].every(value => !text.includes(value)), 'secret_in_visible_ui');
  check(!inventory || inventory.items.every(x => !text.includes(x.id)), 'management_handle_in_visible_ui');
  const storage = await page.evaluate(() => [...Object.values(localStorage), ...Object.values(sessionStorage)]);
  check(storage.every(value => [...secrets].every(secret => !value.includes(secret))), 'credential_in_browser_storage');
}
async function screenshot(page, name) {
  await page.evaluate(() => document.fonts.ready);
  await page.evaluate(() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))));
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1), 'horizontal_overflow');
  check(await page.evaluate(() => [...document.querySelectorAll('img[alt="Sifruno"]')].every(x => x.complete && x.naturalWidth > 0)), 'brand_not_loaded');
  await page.screenshot({ path: join(output, name), fullPage: !name.includes('dialog'), timeout: 15000 });
  report.sources[name] = hash(await bounded(join(output, name), 8 << 20, output));
}
async function mutation(page, click, path) {
  const response = page.waitForResponse(r => new URL(r.url()).pathname === path && r.request().method() === 'POST');
  await click(); const r = await response; check(r.status() === 200, 'ui_mutation_status'); return r.json();
}
async function startPublicModeFixture() {
  const allowed = new Set(['/api/v1/status', '/api/v1/platform', '/api/v1/server', '/api/v1/services']);
  publicServer = httpServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
      if (url.pathname.startsWith('/api/')) {
        if (!allowed.has(url.pathname)) { res.writeHead(404); return res.end(); }
        const upstream = await fetch(origin + url.pathname + url.search, { redirect: 'error', signal: AbortSignal.timeout(10000) });
        const bytes = Buffer.from(await upstream.arrayBuffer()); check(bytes.length <= 2 << 20, 'public_metrics_bound');
        res.writeHead(upstream.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); return res.end(bytes);
      }
      const path = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).slice(1);
      const file = resolve(ui, path); let bytes = await bounded(file, 8 << 20, ui);
      if (path === 'index.html') bytes = Buffer.from(bytes.toString('utf8').replace('<head>', '<head><meta name="sifruno-public-preview" content="true">'));
      const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json' };
      res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' }); res.end(bytes);
    } catch { res.writeHead(404); res.end(); }
  });
  publicServer.listen(0, '127.0.0.1'); await once(publicServer, 'listening'); publicOrigin = 'http://127.0.0.1:' + publicServer.address().port;
}

try {
  await directory(output); await directory(fixture);
  for (const path of ['scripts/verify-access-ui.mjs', 'internal/operator/operator.go', 'internal/operator/sessions.go', 'internal/api/api.go', 'internal/api/session_controls.go', 'internal/api/session_spec.go', 'web/src/App.tsx', 'web/src/Access.tsx', 'web/src/access.css', 'web/src/lib/access-api.ts', 'web/dist/index.html']) report.sources[path] = hash(await bounded(join(root, path), 2 << 20));
  report.binary_sha256 = hash(await bounded(binary, 80 << 20));
  report.ui_assets = await uiCatalog(); report.ui_catalog_sha256 = hash(Buffer.from(JSON.stringify(report.ui_assets)));
  origin = 'http://127.0.0.1:' + await freePort(); report.origin = origin;
  child = spawn(binary, ['--listen', new URL(origin).host, '--sites-listen=', '--state', state, '--ui', ui], { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let logBytes = 0; for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => { logBytes += bytes.length; if (logBytes > 65536) child.kill(); });
  let ready = false;
  for (let i = 0; i < 100; i++) {
    check(child.exitCode === null, 'owned_server_exited');
    try { ready = (await fetch(origin + '/api/v1/status', { signal: AbortSignal.timeout(500) })).ok; } catch { /* bounded startup */ }
    if (ready) break; await new Promise(r => setTimeout(r, 100));
  }
  check(ready, 'owned_server_not_ready');
  credential = (await bounded(join(state, 'operator/access.key'), 256, fixture)).toString('utf8').trim(); secrets.add(credential);
  check(/^[A-Za-z0-9_-]{43}$/.test(credential), 'fixture_key_shape');
  browser = await chromium.launch({ headless: true }); await startPublicModeFixture();
  const a = await contextFor(); const page = a.page; await page.goto(origin); await nav(page, 'access');
  await page.getByLabel('Operator access key', { exact: true }).waitFor();
  phase = 'real_login'; await login(page); const s = await api(a.context, '/api/v1/session'); report.workflow.login = true;
  const b = await extraSession(), c = await extraSession(); await refresh(page); await rowCount(page, 2);
  const inv = await api(a.context, '/api/v1/session/sessions'); const idx = inv.items.filter(x => !x.current).findIndex(x => x.id === b.id);
  const target = page.getByTestId('access-other-row').nth(idx).getByRole('button');
  phase = 'dialog_cancel_and_escape'; const before = a.stats.mutation_requests; await target.click();
  await page.getByRole('dialog').waitFor(); await page.getByRole('button', { name: 'Cancel revocation', exact: true }).click();
  await page.getByRole('dialog').waitFor({ state: 'hidden' }); check(await target.evaluate(x => x === document.activeElement), 'cancel_focus_not_restored');
  await target.click(); await page.keyboard.press('Escape'); await page.getByRole('dialog').waitFor({ state: 'hidden' });
  check(await target.evaluate(x => x === document.activeElement), 'escape_focus_not_restored');
  check(a.stats.mutation_requests === before && (await api(a.context, '/api/v1/session/sessions')).items.length === 3, 'cancel_mutated_sessions'); report.workflow.cancel_escape_focus = true;
  phase = 'real_single_revocation'; await target.click();
  const one = await mutation(page, () => page.getByTestId('access-confirm-revoke').click(), '/api/v1/session/sessions/' + b.id + '/revoke');
  check(one.revoked_count === 1, 'single_revocation_count'); await rowCount(page, 1); await settled(page); await api(b.context, '/api/v1/session', { status: 401 }); report.workflow.selected_revoke_cookie_replay_401 = true;
  phase = 'real_bulk_revocation'; const d = await extraSession(); await refresh(page); await rowCount(page, 2);
  await page.getByTestId('access-revoke-others').click();
  const all = await mutation(page, () => page.getByTestId('access-confirm-revoke').click(), '/api/v1/session/revoke-others');
  check(all.revoked_count === 2, 'bulk_revocation_count'); await rowCount(page, 0); await settled(page);
  for (const other of [c, d]) await api(other.context, '/api/v1/session', { status: 401 });
  check((await api(a.context, '/api/v1/session')).authenticated === true, 'bulk_removed_current'); report.workflow.bulk_revoke_count_2_current_retained = true;
  phase = 'real_logout_replay'; const oldCookies = await a.context.cookies();
  await mutation(page, () => page.getByTestId('access-signout').click(), '/api/v1/session/logout'); await page.getByLabel('Operator access key', { exact: true }).waitFor();
  const replay = await contextFor(1440, 'light', oldCookies); await api(replay.context, '/api/v1/session', { status: 401 }); report.workflow.logout_cookie_replay_401 = true;
  phase = 'external_revocation_ui'; await login(page); const e = await extraSession();
  const own = (await api(a.context, '/api/v1/session/sessions')).items.find(x => x.current).id;
  await api(e.context, '/api/v1/session/sessions/' + own + '/revoke', { method: 'POST', data: {}, csrf: e.csrf });
  await refresh(page); await page.getByLabel('Operator access key', { exact: true }).waitFor(); check(await page.getByTestId('access-other-row').count() === 0, 'revoked_ui_retained_inventory'); report.workflow.external_revoke_refresh_clears_private_ui = true;
  await login(page); await rowCount(page, 1);
  phase = 'delayed_real_mutation_unmount';
  let received; const arrived = new Promise(r => { received = r; }); let release; const released = new Promise(r => { release = r; }); delayedRelease = release;
  let delivered, deliveryFailed = false; const finishedDelivery = new Promise(r => { delivered = r; });
  const delay = async route => {
    try { const response = await route.fetch(); check(response.status() === 200, 'delayed_actual_mutation_status'); received(); await released; await route.fulfill({ response }); }
    catch { deliveryFailed = true; received(); }
    finally { delivered(); }
  };
  await page.route('**/api/v1/session/revoke-others', delay); await page.getByTestId('access-revoke-others').click(); await page.getByTestId('access-confirm-revoke').click();
  await Promise.race([arrived, new Promise((_, reject) => setTimeout(() => reject(Object.assign(new Error('delivery_timeout'), { checkCode: 'delivery_timeout' })), 10000))]);
  // Deliberately dispatch shell navigation to unmount the pending component;
  // a native modal otherwise keeps ordinary pointer navigation unavailable.
  await page.getByTestId('nav-overview').evaluate(x => x.click());
  await page.getByTestId('access-page').waitFor({ state: 'detached' });
  release(); await finishedDelivery; check(!deliveryFailed, 'delayed_response_delivery_failed');
  delayedRelease = undefined; await page.unroute('**/api/v1/session/revoke-others', delay); await nav(page, 'access'); await settled(page); await rowCount(page, 0);
  check((await api(a.context, '/api/v1/session/sessions')).items.length === 1, 'delayed_mutation_state_not_observed');
  check(!await page.getByText('1 other session revoked. Your current session remains signed in.', { exact: true }).isVisible(), 'unmounted_completion_rendered'); report.workflow.real_mutation_delayed_response_unmount = true;
  phase = 'synthetic_refresh_failure'; const f = await extraSession(); await refresh(page); await rowCount(page, 1);
  const refuse = route => route.fulfill({ status: 503, contentType: 'application/problem+json', body: '{"error":"operator_unavailable"}' });
  await page.route('**/api/v1/session/sessions', refuse); await refresh(page); await page.getByRole('alert').waitFor();
  check(await page.getByTestId('access-revoke-others').isDisabled() && await page.getByTestId('access-other-row').getByRole('button').isDisabled(), 'failed_refresh_allowed_revocation');
  check((await api(a.context, '/api/v1/session/sessions')).items.length === 2, 'synthetic_failure_changed_server');
  await page.unroute('**/api/v1/session/sessions', refuse); await refresh(page); await rowCount(page, 1); report.workflow.synthetic_503_stale_actions_disabled_recovery = true;
  const currentCookies = await a.context.cookies();
  phase = 'client_clock_expiry'; const expiring = await contextFor(1440, 'light', currentCookies); await expiring.page.clock.install({ time: new Date() });
  await expiring.page.goto(origin); await nav(expiring.page, 'access'); await settled(expiring.page); await expiring.page.clock.fastForward('16:00');
  await expiring.page.getByLabel('Operator access key', { exact: true }).waitFor(); check(await expiring.page.getByTestId('access-current-row').count() === 0, 'client_expiry_retained_private_ui');
  check((await api(a.context, '/api/v1/session')).authenticated === true, 'client_clock_claimed_server_expiry'); report.workflow.client_clock_expiry_only = true; await expiring.context.close();
  phase = 'viewport_matrix';
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) {
    const v = await contextFor(width, theme, currentCookies); await v.page.goto(origin); await nav(v.page, 'access'); await settled(v.page); await rowCount(v.page, 1);
    await privacy(v.page, await api(v.context, '/api/v1/session/sessions')); await screenshot(v.page, `private-${width}-${theme}.png`);
    await v.page.getByTestId('access-revoke-others').click(); await v.page.getByRole('dialog').waitFor();
    check(await v.page.getByRole('dialog').evaluate(x => { const r = x.getBoundingClientRect(); return r.left >= 0 && r.right <= innerWidth && r.top >= 0 && r.bottom <= innerHeight; }), 'dialog_outside_viewport');
    await screenshot(v.page, `dialog-${width}-${theme}.png`); await v.page.keyboard.press('Escape');
    check(v.stats.page_errors === 0 && v.stats.external_requests === 0 && v.stats.asset_failures === 0, 'private_browser_resource_error');
    report.private_viewports.push({ width, theme, passed: true, overflow: false, dialog_bounds: true, visible_credentials: false, browser_storage_credentials: false, ...v.stats }); await v.context.close();
    const pub = await contextFor(width, theme); await pub.page.goto(publicOrigin + '/#access'); await pub.page.getByRole('heading', { name: 'Server overview', exact: true }).waitFor();
    check(await pub.page.getByTestId('nav-access').count() === 0 && await pub.page.getByTestId('access-page').count() === 0, 'public_mode_access_visible');
    await screenshot(pub.page, `public-${width}-${theme}.png`);
    check(pub.stats.session_requests === 0 && pub.stats.mutation_requests === 0 && pub.stats.page_errors === 0 && pub.stats.external_requests === 0 && pub.stats.asset_failures === 0, 'public_mode_private_or_external_request');
    report.public_mode_viewports.push({ width, theme, passed: true, overflow: false, access_hidden: true, ...pub.stats }); await pub.context.close();
  }
  await privacy(page, await api(a.context, '/api/v1/session/sessions'));
  check(a.stats.page_errors === 0 && a.stats.external_requests === 0 && a.stats.asset_failures === 0, 'workflow_browser_resource_error');
  for (const [path, expected] of Object.entries(report.sources)) {
    if (path.endsWith('.png')) continue;
    check(hash(await bounded(join(root, path), 2 << 20)) === expected, 'source_changed_during_execution');
  }
  check(hash(await bounded(binary, 80 << 20)) === report.binary_sha256, 'binary_changed_during_execution');
  check(hash(Buffer.from(JSON.stringify(await uiCatalog()))) === report.ui_catalog_sha256, 'ui_assets_changed_during_execution');
  report.source_binary_ui_unchanged_after_execution = true;
  report.workflow.resource_errors = 0; report.workflow.actual_isolated_tcp = true; report.passed = true;
} catch (error) {
  report.failure = { phase, code: error.checkCode || 'bounded_browser_operation_failed' }; process.exitCode = 1;
} finally {
  if (delayedRelease) delayedRelease();
  credential = undefined; secrets.clear();
  try { if (browser) await browser.close(); report.cleanup.browser_closed = true; } catch { report.cleanup.browser_closed = false; }
  try { if (publicServer) { publicServer.closeAllConnections(); await new Promise(r => publicServer.close(r)); } report.cleanup.public_fixture_closed = true; } catch { report.cleanup.public_fixture_closed = false; }
  try { if (child && child.exitCode === null && child.signalCode === null) { const exited = once(child, 'exit'); child.kill(); await Promise.race([exited, new Promise((_, reject) => setTimeout(() => reject(new Error()), 10000))]); } report.cleanup.owned_child_stopped = !child || child.exitCode !== null || child.signalCode !== null; } catch { report.cleanup.owned_child_stopped = false; }
  if (origin) { try { await fetch(origin + '/api/v1/status', { signal: AbortSignal.timeout(500) }); report.cleanup.owned_listener_closed = false; } catch { report.cleanup.owned_listener_closed = true; } }
  if (!Object.values(report.cleanup).every(Boolean)) { report.passed = false; process.exitCode = 1; }
  if (process.exitCode) report.passed = false;
  await directory(output); const bytes = Buffer.from(JSON.stringify(report, null, 2) + '\n'); await writeFile(join(output, 'report.json'), bytes);
  console.log(JSON.stringify({ passed: report.passed, report: relative(root, join(output, 'report.json')).split(sep).join('/'), sha256: hash(bytes), private_viewports: report.private_viewports.length, public_mode_viewports: report.public_mode_viewports.length, failure: report.failure, cleanup: report.cleanup }));
}
