// Real browser writes use a fresh owned native fixture. Main auth/state are never read.
// The existing start-transfer-fixture binary is hash checked, copied, and given fresh state.
// node scripts/verify-backups-ui.mjs [--ui-root PATH] [--public-origin APPROVED_URL]
import { createRequire } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdir, readFile, writeFile, lstat, realpath, rm, readdir } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const primary = basename(dirname(root)) === '.worktrees' ? resolve(root, '../..') : root;
const { chromium } = createRequire(join(primary, 'package.json'))('playwright');
const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { checkCode: code }); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const args = process.argv.slice(2);
check(args.length % 2 === 0 && args.every((arg, index) => index % 2 ? Boolean(arg) : ['--ui-root', '--public-origin'].includes(arg)), 'invalid_arguments');
const option = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const uiRoot = resolve(option('--ui-root', join(primary, '.worktrees/native-transfer-ui')));
const approvedPublic = 'https://preview-tunnel.example.com';
const remotePublic = option('--public-origin', null);
check(remotePublic === null || remotePublic === approvedPublic || /^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(remotePublic), 'public_origin_not_admitted');
const origin = 'http://127.0.0.1:18404', sitesOrigin = 'http://127.0.0.1:18406', publicOrigin = 'http://127.0.0.1:18405';
const runId = new Date().toISOString().replace(/[-:.Z]/g, '') + '-' + randomUUID().slice(0, 8);
const fixtureBase = join(root, '.cache/backups-ui-fixture'), fixture = join(fixtureBase, runId), state = join(fixture, 'private-state');
const output = join(root, 'artifacts/backups-ui', runId);
let phase = 'prepare', child, browser, credential, publicServer;
const report = { schema_version: 1, checked_at: new Date().toISOString(), evidence_kind: 'observed_isolated_native_backups_browser_qa', fixture_only: true, main_state_mutated: false, paid_provider_calls: 0, compatibility_certified: false, phone_verified: false, origin, public_origin: publicOrigin, workflow: {}, viewports: [], public_viewports: [], remote_public_viewports: [], sources: {}, cleanup: {} };

function contained(ancestor, path) { const rel = relative(ancestor, path); return rel && !isAbsolute(rel) && !rel.split(sep).includes('..'); }
async function directory(path) {
  check(contained(root, path), 'output_escape');
  let current = await realpath(root);
  for (const part of relative(root, path).split(sep)) {
    current = join(current, part);
    try { await mkdir(current); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    check((await lstat(current)).isDirectory() && !(await lstat(current)).isSymbolicLink() && await realpath(current) === current, 'directory_not_regular');
  }
}
async function bounded(path, limit, ancestor) {
  check(contained(ancestor, path), 'input_escape');
  let current = await realpath(ancestor);
  for (const part of relative(ancestor, path).split(sep)) {
    current = join(current, part); const stat = await lstat(current);
    check(!stat.isSymbolicLink() && await realpath(current) === current, 'input_link');
  }
  const stat = await lstat(current);
  check(stat.isFile() && stat.nlink === 1 && stat.size > 0 && stat.size <= limit, 'input_not_bounded_regular');
  const bytes = await readFile(current); check(bytes.length === stat.size, 'input_changed'); return bytes;
}
function environment() {
  const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA']);
  return Object.fromEntries(Object.entries(process.env).filter(([name, value]) => allowed.has(name.toUpperCase()) && value));
}
async function waitFor(read, code) {
  const end = Date.now() + 15000;
  while (!await read() && Date.now() < end) await new Promise(done => setTimeout(done, 30));
  check(Boolean(await read()), code);
}
async function startFixture() {
  const uiRel = relative(primary, uiRoot); check(!isAbsolute(uiRel) && !uiRel.split(sep).includes('..') && await realpath(uiRoot) === uiRoot, 'ui_root_not_admitted');
  check((await lstat(join(uiRoot, 'web/src/Backups.tsx'))).isFile(), 'backups_source_not_ready');
  const metadataBase = join(primary, '.cache/native-transfer-fixture');
  const metadata = JSON.parse((await bounded(join(metadataBase, 'current.json'), 8192, metadataBase)).toString('utf8'));
  check(metadata.origin === 'http://127.0.0.1:8084' && metadata.main_state_mutated === false && metadata.application_credentials_inherited === false && /^[A-Za-z0-9_-]{1,96}$/.test(metadata.id), 'existing_fixture_metadata_invalid');
  const binaryPath = resolve(primary, metadata.binary);
  check(binaryPath === join(metadataBase, metadata.id, 'sifruno.exe'), 'existing_fixture_binary_not_exact');
  const binary = await bounded(binaryPath, 32 << 20, metadataBase);
  check(hash(binary) === metadata.binary_sha256, 'fixture_binary_hash_mismatch');
  report.binary_sha256 = hash(binary); report.binary_provenance = 'hash-checked existing start-transfer-fixture executable; API behavior observed independently';
  await directory(fixture); const ownedBinary = join(fixture, 'sifruno.exe'); await writeFile(ownedBinary, binary, { flag: 'wx' });
  for (const source of ['web/src/Backups.tsx', 'web/src/backups.css', 'web/src/App.tsx', 'web/src/Websites.tsx', 'web/src/lib/sites-api.ts', 'web/dist/index.html']) report.sources[source] = hash(await bounded(join(uiRoot, source), 4 << 20, uiRoot));
  report.sources['scripts/verify-backups-ui.mjs'] = hash(await bounded(join(root, 'scripts/verify-backups-ui.mjs'), 1 << 20, root));
  const bundleNames = await readdir(join(uiRoot, 'web/dist/assets'));
  for (const name of bundleNames.filter(name => /^Backups-.*\.(js|css)$/.test(name))) report.sources['web/dist/assets/' + name] = hash(await bounded(join(uiRoot, 'web/dist/assets', name), 4 << 20, uiRoot));
  check(bundleNames.some(name => /^Backups-.*\.js$/.test(name)), 'backups_bundle_missing');
  for (const port of [18404, 18405, 18406]) {
    let occupied = false;
    try { await fetch('http://127.0.0.1:' + port, { signal: AbortSignal.timeout(500), redirect: 'error' }); occupied = true; } catch { }
    check(!occupied, 'owned_fixture_port_occupied');
  }
  child = spawn(ownedBinary, ['--listen', '127.0.0.1:18404', '--sites-listen', '127.0.0.1:18406', '--state', state, '--ui', join(uiRoot, 'web/dist')], { cwd: root, env: environment(), stdio: 'ignore', windowsHide: true });
  let childFailed = false; child.on('error', () => { childFailed = true; });
  await waitFor(async () => {
    check(!childFailed && child.exitCode === null, 'owned_fixture_exited');
    try { return (await fetch(origin + '/api/v1/session', { signal: AbortSignal.timeout(500), redirect: 'error' })).status === 401; } catch { return false; }
  }, 'owned_fixture_startup_failed');
  credential = (await bounded(join(state, 'operator/access.key'), 44, fixture)).toString('ascii').trim();
  check(/^[A-Za-z0-9_-]{43}$/.test(credential), 'owned_fixture_key_invalid');
  report.fixture_id = runId; report.fixture_pid = child.pid;
  // An actual isolated HTTP public proxy serves the same build and only public GETs.
  publicServer = createServer(async (request, response) => {
    const url = new URL(request.url, publicOrigin);
    const allowed = request.method === 'GET' && (url.pathname === '/' || /^\/(assets|brand)\/[A-Za-z0-9_./-]+$/.test(url.pathname) || ['/api/v1/server', '/api/v1/status', '/api/v1/platform', '/api/v1/services'].includes(url.pathname));
    if (!allowed) { response.writeHead(404); return response.end(); }
    try {
      const upstream = await fetch(origin + url.pathname + url.search, { signal: AbortSignal.timeout(10000), redirect: 'error' });
      let bytes = Buffer.from(await upstream.arrayBuffer()); check(bytes.length <= 8 << 20, 'public_proxy_response_bound');
      if (url.pathname === '/') bytes = Buffer.from(bytes.toString('utf8').replace('</head>', '<meta name="sifruno-public-preview" content="isolated-read-only"></head>'));
      response.writeHead(upstream.status, { 'Content-Type': upstream.headers.get('content-type') || 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Sifruno-View': 'public-read-only' }); response.end(bytes);
    } catch { response.writeHead(503); response.end(); }
  });
  await new Promise((done, reject) => { publicServer.once('error', reject); publicServer.listen(18405, '127.0.0.1', done); });
}
async function api(context, path, { method = 'GET', data, csrf, expected = 200 } = {}) {
  check(path.startsWith('/api/v1/') && !path.includes('..'), 'fixture_api_path_not_admitted');
  const response = await context.request.fetch(origin + path, { method, data, headers: { Origin: origin, Accept: 'application/json', ...(data !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }, timeout: 10000, maxRedirects: 0 });
  check(response.status() === expected, 'fixture_api_status_' + response.status());
  const bytes = await response.body(); check(bytes.length <= 1 << 20, 'fixture_api_response_bound'); return JSON.parse(bytes.toString('utf8'));
}
async function contextFor(base, width, theme, publicView = false) {
  const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, colorScheme: theme, locale: 'en-US', reducedMotion: 'reduce', acceptDownloads: true });
  await context.addInitScript(value => localStorage.setItem('sifruno-theme', value), theme);
  const health = { page_errors: 0, console_errors: 0, failed_requests: 0, external_requests: 0, out_of_scope_mutations: 0, private_requests: 0, unexpected_http_errors: 0, expected_http_errors: [] };
  const expectedHttp = new Set([401]);
  const seen = { backup_mutations: 0, restore_mutations: 0, downloads: 0 };
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== base) { health.external_requests++; return route.abort(); }
    if (publicView && /^\/api\/v1\/(session|sites|accounts|trail|budget)(\/|$)/.test(url.pathname)) { health.private_requests++; return route.abort(); }
    const allowedWrite = !publicView && (/^\/api\/v1\/session\/(login|logout)$/.test(url.pathname) || url.pathname === '/api/v1/sites' || /^\/api\/v1\/sites\/[a-f0-9]{32}\/(file|backups|restore)$/.test(url.pathname));
    if (!['GET', 'HEAD'].includes(request.method()) && !allowedWrite) { health.out_of_scope_mutations++; return route.abort(); }
    if (request.method() === 'POST' && url.pathname.endsWith('/backups')) seen.backup_mutations++;
    if (request.method() === 'POST' && url.pathname.endsWith('/restore')) seen.restore_mutations++;
    if (url.pathname.endsWith('/download')) seen.downloads++;
    return route.continue();
  });
  const page = await context.newPage(); page.setDefaultTimeout(15000); page.setDefaultNavigationTimeout(20000);
  page.on('pageerror', () => health.page_errors++);
  page.on('requestfailed', request => { if (request.failure()?.errorText !== 'net::ERR_ABORTED') health.failed_requests++; });
  page.on('console', message => {
    if (message.type() !== 'error') return;
    const code = message.text().match(/^Failed to load resource: the server responded with a status of (\d{3})/);
    if (!code || !expectedHttp.has(Number(code[1]))) health.console_errors++;
  });
  page.on('response', response => {
    if (response.status() < 400) return;
    if (expectedHttp.has(response.status())) health.expected_http_errors.push({ path: new URL(response.url()).pathname, status: response.status() });
    else health.unexpected_http_errors++;
  });
  return { context, page, health, expectedHttp, seen };
}
async function nav(page, id) {
  const target = page.getByTestId('nav-' + id);
  if (!await target.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
  await target.click();
}
async function overflow(page) { check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1), 'horizontal_overflow'); }
async function screenshot(page, name, fullPage = true) {
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
  await page.evaluate(() => document.fonts.ready); await overflow(page);
  await page.screenshot({ path: join(output, name), fullPage, timeout: 15000 });
}
function healthy(health) {
  check(Object.entries(health).filter(([name]) => name !== 'expected_http_errors').every(([, count]) => count === 0), 'browser_health_failure');
  check(health.expected_http_errors.every(item => item.status === 401 ? item.path === '/api/v1/session' : [409, 503].includes(item.status) && /^\/api\/v1\/sites\/[a-f0-9]{32}\/(restore|backups\/[a-f0-9]{32}\/download)$/.test(item.path)), 'unexpected_error_endpoint');
}
async function login(page, view = 'backups') {
  await nav(page, view);
  const key = page.getByLabel('Operator access key', { exact: true }); await key.waitFor();
  check(await key.getAttribute('type') === 'password', 'operator_key_not_password');
  await key.fill(credential); await page.getByRole('button', { name: 'Sign in locally', exact: true }).click();
  await page.getByRole('button', { name: 'Sign out locally', exact: true }).waitFor();
  check(await page.evaluate(value => !document.body.innerText.includes(value) && !Object.values(localStorage).some(entry => entry.includes(value)), credential), 'fixture_credential_displayed_or_persisted');
}
async function selectSite(page, id) {
  await page.getByTestId('backups-site-picker').selectOption(id);
  await waitFor(async () => await page.getByTestId('backups-inventory').getAttribute('data-site-id') === id, 'backup_site_selection_failed');
}
async function currentRow(page, id) { const row = page.locator(`[data-testid="backup-row"][data-backup-id="${id}"]`); await row.waitFor(); return row; }
async function restoreDialog(page, id) {
  await page.getByRole('button', { name: 'Restore backup ' + id, exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Restore ZIP backup?', exact: true }); await dialog.waitFor();
  check(await dialog.getByRole('button', { name: 'Confirm restore', exact: true }).isDisabled(), 'restore_missing_explicit_confirmation');
  return dialog;
}

async function workflow() {
  const v = await contextFor(origin, 1440, 'light'), { page, context } = v;
  try {
    phase = 'actual_site_create_and_content'; await page.goto(origin, { waitUntil: 'networkidle' }); await login(page, 'websites');
    const name = 'Backup QA ' + runId.slice(-8), domain = 'backup-qa-' + runId.slice(-8) + '.test';
    await page.locator('#website-name').fill(name); await page.locator('#website-domain').fill(domain);
    await page.getByRole('button', { name: 'Create website', exact: true }).click(); await page.getByText('Created ' + name + '.', { exact: true }).waitFor();
    const siteId = await page.getByTestId('website-details').getAttribute('data-site-id'); check(/^[a-f0-9]{32}$/.test(siteId), 'actual_site_id_missing');
    const base = '/api/v1/sites/' + siteId;
    const content = '<!doctype html><title>Owned native backup QA</title><main>Baseline ' + runId + '</main>';
    await page.getByLabel('File content', { exact: true }).fill(content); await page.getByRole('button', { name: 'Save file', exact: true }).click(); await page.getByText('Saved index.html.', { exact: true }).waitFor();
    check((await api(context, base + '/file?path=index.html')).content === content, 'browser_content_not_persisted');
    const dirtyDraft = content + '<p>Unsaved editor draft remains local</p>';
    await page.getByLabel('File content', { exact: true }).fill(dirtyDraft);
    const session = await api(context, '/api/v1/session'); check(session.authenticated && session.csrf_token?.length === 43, 'owned_fixture_session_invalid');
    phase = 'actual_global_backup_create'; await nav(page, 'backups'); await page.getByTestId('backups-page').waitFor(); await selectSite(page, siteId);
    check(await page.getByTestId('backup-row').count() === 0, 'fresh_fixture_has_backups');
    const beforeBackup = v.seen.backup_mutations; await page.getByRole('button', { name: 'Create ZIP backup', exact: true }).click();
    await waitFor(() => v.seen.backup_mutations > beforeBackup, 'backup_button_no_real_post');
    await waitFor(async () => await page.getByTestId('backup-row').count() === 1, 'created_backup_not_in_ui');
    const backup = (await api(context, base + '/backups')).items[0]; check(backup.site_id === siteId && backup.files === 1 && /^[a-f0-9]{64}$/.test(backup.sha256), 'actual_backup_contract_invalid');
    let site = await api(context, base);
    check(Number(await page.getByTestId('backups-inventory').getAttribute('data-revision')) === site.revision, 'backup_ui_revision_stale');
    const row = await currentRow(page, backup.id); await row.locator('details summary').click(); check((await row.innerText()).includes(backup.sha256), 'backup_hash_not_inspectable');
    phase = 'actual_backup_download_hash';
    const downloadPromise = page.waitForEvent('download'); await row.getByRole('button', { name: 'Download ZIP backup ' + backup.id, exact: true }).click();
    const download = await downloadPromise, stream = await download.createReadStream(); const parts = []; let size = 0;
    for await (const part of stream) { size += part.length; check(size <= 34 << 20, 'download_exceeds_bound'); parts.push(part); }
    const archive = Buffer.concat(parts);
    check(hash(archive) === backup.sha256 && size === backup.bytes && archive.subarray(0, 2).toString('ascii') === 'PK', 'download_does_not_match_actual_backup');
    const archivePath = join(state, 'sites/data', siteId, 'backups', backup.id + '.zip');
    const storedArchive = await bounded(archivePath, 34 << 20, fixture); check(hash(storedArchive) === backup.sha256, 'native_archive_not_actual_download');
    phase = 'actual_confirmed_restore';
    const baselineFile = await api(context, base + '/file?path=index.html');
    await api(context, base + '/file', { method: 'PUT', csrf: session.csrf_token, data: { path: 'index.html', content: content + '<p>Changed after backup</p>', expected_sha256: baselineFile.sha256, expected_revision: baselineFile.revision } });
    await page.getByRole('button', { name: 'Refresh backup records', exact: true }).click();
    site = await api(context, base);
    await waitFor(async () => Number(await page.getByTestId('backups-inventory').getAttribute('data-revision')) === site.revision, 'refresh_did_not_load_actual_revision');
    const beforeRestore = v.seen.restore_mutations;
    const confirm = await restoreDialog(page, backup.id); await screenshot(page, '1440-light-restore-confirmation.png', false);
    check(v.seen.restore_mutations === beforeRestore, 'restore_before_confirmation');
    await confirm.getByRole('checkbox', { name: 'I understand that the current site files will be replaced.', exact: true }).check();
    await confirm.getByRole('button', { name: 'Confirm restore', exact: true }).click(); await confirm.waitFor({ state: 'hidden' });
    check(v.seen.restore_mutations === beforeRestore + 1 && (await api(context, base + '/file?path=index.html')).content === content, 'confirmed_restore_not_actual_backup_content');
    phase = 'actual_restore_revision_conflict'; v.expectedHttp.add(409);
    const conflict = await restoreDialog(page, backup.id);
    const currentFile = await api(context, base + '/file?path=index.html'); const concurrentContent = content + '<p>Concurrent fixture update</p>';
    await api(context, base + '/file', { method: 'PUT', csrf: session.csrf_token, data: { path: 'index.html', content: concurrentContent, expected_sha256: currentFile.sha256, expected_revision: currentFile.revision } });
    const conflictResponse = page.waitForResponse(response => response.url() === origin + base + '/restore' && response.status() === 409);
    await conflict.getByRole('checkbox', { name: 'I understand that the current site files will be replaced.', exact: true }).check(); await conflict.getByRole('button', { name: 'Confirm restore', exact: true }).click(); await conflictResponse;
    check((await api(context, base + '/file?path=index.html')).content === concurrentContent, 'conflict_overwrote_concurrent_content');
    await screenshot(page, '1440-light-real-restore-conflict.png', false);
    await page.getByRole('button', { name: 'Cancel restore', exact: true }).click();
    check(await page.getByRole('button', { name: 'Create ZIP backup', exact: true }).isDisabled() && await page.getByRole('button', { name: 'Restore backup ' + backup.id, exact: true }).isDisabled(), 'conflict_does_not_block_writes_until_refresh');
    await page.getByRole('button', { name: 'Refresh backup records', exact: true }).click();
    await waitFor(async () => await page.getByRole('button', { name: 'Restore backup ' + backup.id, exact: true }).isEnabled(), 'conflict_refresh_does_not_readmit_explicit_restore');
    const renewed = await restoreDialog(page, backup.id); await renewed.getByRole('button', { name: 'Cancel restore', exact: true }).click();
    phase = 'actual_archive_corruption_rejection'; v.expectedHttp.add(503);
    const corruption = Buffer.from(storedArchive); corruption[0] ^= 0xff;
    await bounded(archivePath, 34 << 20, fixture); await writeFile(archivePath, corruption);
    const beforeCorrupt = await api(context, base + '/file?path=index.html');
    try {
      const downloadFailure = page.waitForResponse(response => response.url().endsWith('/download') && response.status() === 503);
      await page.getByRole('button', { name: 'Download ZIP backup ' + backup.id, exact: true }).click(); await downloadFailure;
      await waitFor(async () => await page.getByRole('alert').count() > 0, 'corrupt_download_has_no_error');
      check(await page.getByRole('button', { name: 'Restore backup ' + backup.id, exact: true }).isDisabled(), 'corrupt_download_does_not_require_refresh');
      await writeFile(archivePath, storedArchive);
      await page.getByRole('button', { name: 'Refresh backup records', exact: true }).click();
      await waitFor(async () => await page.getByTestId('backups-inventory').getAttribute('data-fresh') === 'true', 'recovered_archive_refresh_failed');
      const badRestore = await restoreDialog(page, backup.id);
      await writeFile(archivePath, corruption);
      const restoreFailure = page.waitForResponse(response => response.url() === origin + base + '/restore' && response.status() === 503);
      await badRestore.getByRole('checkbox', { name: 'I understand that the current site files will be replaced.', exact: true }).check(); await badRestore.getByRole('button', { name: 'Confirm restore', exact: true }).click(); await restoreFailure;
      await badRestore.getByRole('alert').waitFor();
      const after = await api(context, base + '/file?path=index.html');
      check(after.content === beforeCorrupt.content && after.sha256 === beforeCorrupt.sha256 && after.revision === beforeCorrupt.revision, 'corrupt_restore_changed_live_fixture_content');
      await screenshot(page, '1440-light-corrupt-archive-rejected.png', false);
      await badRestore.getByRole('button', { name: 'Cancel restore', exact: true }).click();
    } finally { await bounded(archivePath, 34 << 20, fixture); await writeFile(archivePath, storedArchive); }
    await page.getByRole('button', { name: 'Refresh backup records', exact: true }).click(); await currentRow(page, backup.id);
    await nav(page, 'websites');
    await page.getByLabel('File content', { exact: true }).waitFor();
    check(await page.getByLabel('File content', { exact: true }).inputValue() === dirtyDraft, 'global_backups_discarded_editor_draft');
    await nav(page, 'backups'); await currentRow(page, backup.id);
    healthy(v.health);
    report.workflow = { real_browser_site_create: true, real_browser_content_saved: true, global_backup_created: true, actual_download_sha256: hash(archive), actual_download_bytes: size, confirmed_restore_content_verified: true, actual_revision_conflict: true, conflict_blocks_writes_until_refresh: true, refresh_requires_new_confirmation: true, corrupt_download_rejected_status: 503, corrupt_restore_rejected_status: 503, corrupt_restore_preserved_content_hash_revision: true, fixture_archive_recovered: true, unsaved_websites_editor_draft_preserved: true, health: v.health };
    report.site_id = siteId; report.backup_id = backup.id;
    phase = 'actual_logout'; await page.getByRole('button', { name: 'Sign out locally', exact: true }).click(); await page.getByLabel('Operator access key', { exact: true }).waitFor();
    check(await page.getByTestId('backup-row').count() === 0 && !(await context.cookies()).some(cookie => cookie.name === 'sifruno_operator'), 'logout_retained_private_records_or_cookie');
    await api(context, '/api/v1/sites', { expected: 401 }); report.workflow.logout = true;
  } finally { await context.close(); }
}

async function viewport(width, theme) {
  phase = 'private_viewport_' + width + '_' + theme; const v = await contextFor(origin, width, theme);
  try {
    await v.page.goto(origin, { waitUntil: 'networkidle' }); await nav(v.page, 'backups'); await v.page.getByLabel('Operator access key', { exact: true }).waitFor();
    await screenshot(v.page, width + '-' + theme + '-backups-login.png'); await login(v.page); await selectSite(v.page, report.site_id);
    const row = await currentRow(v.page, report.backup_id); await row.locator('details summary').click(); check((await row.innerText()).includes(report.workflow.actual_download_sha256), 'viewport_inventory_does_not_match_real_backup');
    check(await v.page.locator('html').evaluate(element => element.classList.contains('dark')) === (theme === 'dark'), 'theme_not_applied');
    await screenshot(v.page, width + '-' + theme + '-backups.png');
    const dialog = await restoreDialog(v.page, report.backup_id); await screenshot(v.page, width + '-' + theme + '-backups-confirmation.png', false); await dialog.getByRole('button', { name: 'Cancel restore', exact: true }).click();
    check(v.seen.restore_mutations === 0 && v.seen.backup_mutations === 0, 'viewport_cancel_mutated_fixture');
    await v.page.getByRole('button', { name: 'Sign out locally', exact: true }).click(); await v.page.getByLabel('Operator access key', { exact: true }).waitFor();
    check(await v.page.getByTestId('backup-row').count() === 0, 'viewport_logout_retained_backup_rows'); healthy(v.health);
    report.viewports.push({ width, theme, real_backup_inventory: true, explicit_restore_confirmation: true, cancellation_mutations: 0, logout_cleared_rows: true, document_overflow: false, health: v.health });
  } finally { await v.context.close(); }
}
async function publicViewport(base, width, theme, remote = false) {
  phase = (remote ? 'remote_public_' : 'isolated_public_') + width + '_' + theme; const v = await contextFor(base, width, theme, true);
  try {
    await v.page.goto(base, { waitUntil: 'networkidle' }); await v.page.getByTestId('server-overview').waitFor();
    check(await v.page.locator('meta[name="sifruno-public-preview"]').count() === 1, 'public_marker_missing');
    for (const id of ['backups', 'websites', 'accounts', 'trail', 'budget']) check(await v.page.getByTestId('nav-' + id).count() === 0, 'private_public_navigation_visible');
    check(await v.page.getByTestId('backups-page').count() === 0 && await v.page.getByLabel('Operator access key', { exact: true }).count() === 0, 'public_private_component_mounted');
    await screenshot(v.page, (remote ? 'remote-public-' : 'isolated-public-') + width + '-' + theme + '.png'); healthy(v.health);
    const result = { width, theme, backups_unmounted: true, private_navigation_hidden: true, private_api_requests: 0, document_overflow: false, health: v.health };
    (remote ? report.remote_public_viewports : report.public_viewports).push(result);
  } finally { await v.context.close(); }
}

try {
  await directory(output); phase = 'owned_fixture_start'; await startFixture();
  browser = await chromium.launch({ headless: true, env: environment() });
  await workflow();
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await viewport(width, theme);
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await publicViewport(publicOrigin, width, theme);
  if (remotePublic) for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await publicViewport(remotePublic, width, theme, true);
  phase = 'source_consistency';
  for (const [source, before] of Object.entries(report.sources)) check(hash(await bounded(join(source.startsWith('scripts/') ? root : uiRoot, source), 4 << 20, source.startsWith('scripts/') ? root : uiRoot)) === before, 'source_changed_during_qa');
  report.passed = true;
} catch (error) { report.passed = false; report.failure = { phase, code: error.checkCode || 'bounded_browser_step_failed' }; process.exitCode = 1; }
finally {
  credential = undefined; await browser?.close().catch(() => {});
  if (publicServer?.listening) await new Promise(done => { publicServer.close(done); publicServer.closeAllConnections(); });
  if (child && child.exitCode === null && child.signalCode === null) { const exited = new Promise(done => child.once('exit', done)); child.kill(); await Promise.race([exited, new Promise(done => setTimeout(done, 5000))]); }
  report.cleanup.owned_process_stopped = !child || child.exitCode !== null || child.signalCode !== null;
  try {
    const exists = await lstat(fixture).catch(() => null);
    if (exists) { check(report.cleanup.owned_process_stopped && contained(fixtureBase, fixture) && basename(fixture) === runId && await realpath(fixture) === fixture, 'cleanup_target_or_process_not_safe'); await rm(fixture, { recursive: true, force: false }); }
    report.cleanup.owned_fixture_deleted = true;
  } catch { report.cleanup.owned_fixture_deleted = false; report.passed = false; process.exitCode = 1; }
  try { await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n'); } catch { process.exitCode = 1; }
  console.log(JSON.stringify({ passed: report.passed, failure: report.failure, cleanup: report.cleanup, evidence: relative(root, join(output, 'report.json')).replaceAll('\\', '/') }));
}
