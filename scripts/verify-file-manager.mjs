// Real browser writes use a fresh owned native fixture. Main auth/state are never read.
// The existing start-transfer-fixture binary is hash checked, copied, and given fresh state.
// node scripts/verify-file-manager.mjs [--ui-root PATH] [--public-origin APPROVED_URL]
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
const fixtureBase = join(root, '.cache/file-manager-ui-fixture'), fixture = join(fixtureBase, runId), state = join(fixture, 'private-state');
const output = join(root, 'artifacts/file-manager', runId);
let phase = 'prepare', child, browser, credential, publicServer;
const report = { schema_version: 1, checked_at: new Date().toISOString(), evidence_kind: 'observed_isolated_native_file_manager_browser_qa', fixture_only: true, main_state_mutated: false, paid_provider_calls: 0, compatibility_certified: false, phone_verified: false, origin, public_origin: publicOrigin, workflow: {}, viewports: [], public_viewports: [], remote_public_viewports: [], sources: {}, cleanup: {} };

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
  check((await lstat(join(uiRoot, 'web/src/FileManager.tsx'))).isFile(), 'file_manager_source_not_ready');
  const metadataBase = join(primary, '.cache/native-transfer-fixture');
  const metadata = JSON.parse((await bounded(join(metadataBase, 'current.json'), 8192, metadataBase)).toString('utf8'));
  check(metadata.origin === 'http://127.0.0.1:8084' && metadata.main_state_mutated === false && metadata.application_credentials_inherited === false && /^[A-Za-z0-9_-]{1,96}$/.test(metadata.id), 'existing_fixture_metadata_invalid');
  const binaryPath = resolve(primary, metadata.binary);
  check(binaryPath === join(metadataBase, metadata.id, 'sifruno.exe'), 'existing_fixture_binary_not_exact');
  const binary = await bounded(binaryPath, 32 << 20, metadataBase);
  check(hash(binary) === metadata.binary_sha256, 'fixture_binary_hash_mismatch');
  report.binary_sha256 = hash(binary); report.binary_provenance = 'hash-checked existing start-transfer-fixture executable; API behavior observed independently';
  await directory(fixture); const ownedBinary = join(fixture, 'sifruno.exe'); await writeFile(ownedBinary, binary, { flag: 'wx' });
  for (const source of ['web/src/FileManager.tsx', 'web/src/file-manager.css', 'web/src/App.tsx', 'web/src/Websites.tsx', 'web/src/lib/sites-api.ts', 'web/dist/index.html']) report.sources[source] = hash(await bounded(join(uiRoot, source), 4 << 20, uiRoot));
  report.sources['scripts/verify-file-manager.mjs'] = hash(await bounded(join(root, 'scripts/verify-file-manager.mjs'), 1 << 20, root));
  const bundleNames = await readdir(join(uiRoot, 'web/dist/assets'));
  for (const name of bundleNames.filter(name => /^FileManager-.*\.(js|css)$/.test(name))) report.sources['web/dist/assets/' + name] = hash(await bounded(join(uiRoot, 'web/dist/assets', name), 4 << 20, uiRoot));
  check(bundleNames.some(name => /^FileManager-.*\.js$/.test(name)), 'file_manager_bundle_missing');
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
  const health = { page_errors: 0, console_errors: 0, failed_requests: 0, external_requests: 0, out_of_scope_mutations: 0, private_requests: 0, private_module_requests: 0, unexpected_http_errors: 0, expected_http_errors: [] };
  const expectedHttp = new Set([401]);
  const seen = { file_writes: [], file_reads: [] };
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== base) { health.external_requests++; return route.abort(); }
    if (publicView && /\/(FileManager|Backups|Accounts|Websites)-[A-Za-z0-9_-]+\.js$/.test(url.pathname)) health.private_module_requests++;
    if (publicView && /^\/api\/v1\/(session|sites|accounts|trail|budget)(\/|$)/.test(url.pathname)) { health.private_requests++; return route.abort(); }
    const allowedWrite = !publicView && ((request.method() === 'POST' && /^\/api\/v1\/session\/(login|logout)$/.test(url.pathname)) || (request.method() === 'POST' && url.pathname === '/api/v1/sites') || (request.method() === 'PUT' && /^\/api\/v1\/sites\/[a-f0-9]{32}\/file$/.test(url.pathname)));
    if (!['GET', 'HEAD'].includes(request.method()) && !allowedWrite) { health.out_of_scope_mutations++; return route.abort(); }
    if (request.method() === 'PUT' && url.pathname.endsWith('/file')) {
      const body = request.postDataJSON();
      seen.file_writes.push({ path: body.path, expected_revision: body.expected_revision, expected_sha256: body.expected_sha256, bytes: Buffer.byteLength(body.content, 'utf8'), sha256: hash(Buffer.from(body.content, 'utf8')) });
    }
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
  page.on('response', async response => {
    const url = new URL(response.url());
    if (url.pathname.endsWith('/file') && response.request().method() === 'GET' && response.status() === 200) {
      try { const body = await response.json(); seen.file_reads.push({ path: body.path, sha256: body.sha256, revision: body.revision, bytes: Buffer.byteLength(body.content, 'utf8') }); } catch { health.page_errors++; }
    }
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
  check(health.expected_http_errors.every(item => item.status === 401 ? item.path === '/api/v1/session' : item.status === 409 && /^\/api\/v1\/sites\/[a-f0-9]{32}\/file$/.test(item.path)), 'unexpected_error_endpoint');
}
async function login(page, view = 'files') {
  await nav(page, view);
  const key = page.getByLabel('Operator access key', { exact: true }); await key.waitFor();
  check(await key.getAttribute('type') === 'password', 'operator_key_not_password');
  await key.fill(credential); await page.getByRole('button', { name: 'Sign in locally', exact: true }).click();
  await page.getByRole('button', { name: 'Sign out locally', exact: true }).waitFor();
  check(await page.evaluate(value => !document.body.innerText.includes(value) && !Object.values(localStorage).some(entry => entry.includes(value)), credential), 'fixture_credential_displayed_or_persisted');
}

async function manager(page) { await nav(page, 'files'); await page.getByTestId('file-manager-page').waitFor(); }
async function selected(page, id) {
  await page.getByTestId('file-manager-site-picker').selectOption(id);
  await waitFor(async () => await page.getByTestId('file-manager-inventory').getAttribute('data-site-id') === id && await page.getByTestId('file-manager-inventory').getAttribute('data-fresh') === 'true', 'file_manager_site_selection_failed');
}
const managerPage = page => page.getByTestId('file-manager-page');
const editor = page => managerPage(page).getByLabel('File content', { exact: true });
const save = page => managerPage(page).getByRole('button', { name: 'Save file', exact: true });
async function rootFolder(page) { const rootButton = managerPage(page).getByRole('button', { name: 'Root folder', exact: true }); if (await rootButton.count() && await rootButton.isVisible()) await rootButton.click(); }
async function openFile(page, path) {
  await rootFolder(page);
  const folders = path.split('/').slice(0, -1); let current = '';
  for (const part of folders) { current = current ? current + '/' + part : part; await managerPage(page).getByRole('button', { name: 'Open folder ' + current, exact: true }).click(); }
  await managerPage(page).getByRole('button', { name: 'View file ' + path, exact: true }).click();
  await editor(page).waitFor();
}
async function fileMatches(page, file, v) {
  await waitFor(async () => await editor(page).inputValue() === file.content && v.seen.file_reads.some(item => item.path === file.path && item.sha256 === file.sha256 && item.revision === file.revision), 'file_editor_does_not_match_actual_read');
  check(hash(Buffer.from(await editor(page).inputValue(), 'utf8')) === file.sha256, 'editor_hash_differs_from_server_file');
  const readBase = managerPage(page).getByTestId('file-manager-editor');
  check(await readBase.getAttribute('data-file-path') === file.path && await readBase.getAttribute('data-read-sha256') === file.sha256 && Number(await readBase.getAttribute('data-read-revision')) === file.revision, 'editor_read_base_differs_from_actual_response');
}
async function saveActual(page, v, path, content) {
  await editor(page).fill(content); const before = v.seen.file_writes.length;
    const response = page.waitForResponse(response => response.url() === origin + '/api/v1/sites/' + report.site_id + '/file' && response.request().method() === 'PUT' && response.status() === 200);
    response.catch(() => {});
  await save(page).click(); await response;
  await waitFor(async () => await save(page).isDisabled(), 'save_success_did_not_clear_dirty_state');
  check(v.seen.file_writes.length === before + 1 && v.seen.file_writes.at(-1).path === path && v.seen.file_writes.at(-1).sha256 === hash(Buffer.from(content, 'utf8')), 'save_button_did_not_submit_actual_file');
  const actual = await api(v.context, '/api/v1/sites/' + report.site_id + '/file?path=' + encodeURIComponent(path));
  const catalog = (await api(v.context, '/api/v1/sites/' + report.site_id + '/files')).items.find(item => item.path === path);
  check(actual.content === content && actual.sha256 === hash(Buffer.from(content, 'utf8')) && catalog.bytes === Buffer.byteLength(content, 'utf8') && catalog.sha256 === actual.sha256, 'browser_write_content_bytes_hash_not_persisted');
  return actual;
}
async function workflow() {
  const v = await contextFor(origin, 1440, 'light'), { context, page } = v;
  try {
    phase = 'real_fixture_website_create'; await page.goto(origin, { waitUntil: 'networkidle' }); await login(page, 'websites');
    const name = 'Files QA ' + runId.slice(-8), domain = 'files-qa-' + runId.slice(-8) + '.test';
    await page.locator('#website-name').fill(name); await page.locator('#website-domain').fill(domain);
    await page.getByRole('button', { name: 'Create website', exact: true }).click(); await page.getByText('Created ' + name + '.', { exact: true }).waitFor();
    const id = await page.getByTestId('website-details').getAttribute('data-site-id'); check(/^[a-f0-9]{32}$/.test(id), 'fixture_site_id_missing'); report.site_id = id;
    const base = '/api/v1/sites/' + id, session = await api(context, '/api/v1/session'); check(session.authenticated && session.csrf_token?.length === 43, 'fixture_session_invalid');
    const secondary = await api(context, '/api/v1/sites', { method: 'POST', csrf: session.csrf_token, data: { name: 'Secondary files fixture ' + runId.slice(-8), domain: 'secondary-files-' + runId.slice(-8) + '.test' } });
    phase = 'real_inventory_and_read'; await manager(page); await selected(page, id);
    await rootFolder(page);
    const initialCatalog = (await api(context, base + '/files')).items;
    const paths = await managerPage(page).getByTestId('file-row').evaluateAll(elements => elements.map(element => element.getAttribute('data-file-path')));
    check(JSON.stringify(paths.sort()) === JSON.stringify(initialCatalog.filter(item => !item.path.includes('/')).map(item => item.path).sort()), 'root_inventory_not_actual_file_catalog');
    await openFile(page, 'index.html'); await fileMatches(page, await api(context, base + '/file?path=index.html'), v);
    phase = 'real_existing_file_save'; const content = '<!doctype html><title>Owned File Manager fixture</title><main>Saved ' + runId + ' é</main>';
    await saveActual(page, v, 'index.html', content);
    phase = 'real_new_nested_utf8_file'; await managerPage(page).getByRole('button', { name: 'New text file', exact: true }).click();
    await managerPage(page).getByLabel('Relative file path', { exact: true }).fill('assets/readme.txt');
    const nestedContent = 'Actual UTF-8 file: café, مرحبا, नमस्ते. ' + runId;
    await saveActual(page, v, 'assets/readme.txt', nestedContent);
    await openFile(page, 'assets/readme.txt'); await fileMatches(page, await api(context, base + '/file?path=assets%2Freadme.txt'), v);
    const nestedRow = managerPage(page).locator('[data-testid="file-row"][data-file-path="assets/readme.txt"]'); check(await nestedRow.isVisible(), 'derived_folder_does_not_show_actual_nested_file');
    phase = 'real_search'; await rootFolder(page);
    const search = managerPage(page).getByRole('searchbox', { name: 'Search files', exact: true });
    await search.fill('no-file-matches-' + runId); check(await managerPage(page).getByTestId('file-row').count() === 0, 'file_search_does_not_filter');
    await search.fill('index.html'); check(await managerPage(page).locator('[data-testid="file-row"][data-file-path="index.html"]').isVisible(), 'file_search_cannot_find_actual_file'); await search.fill('');
    await openFile(page, 'index.html');
    phase = 'dirty_draft_navigation_and_refresh'; const draft = content + '<p>Preserved draft</p>'; await editor(page).fill(draft);
    const beforeNavigation = v.seen.file_writes.length;
    const sitePicker = page.getByTestId('file-manager-site-picker'), signOut = managerPage(page).getByRole('button', { name: 'Sign out locally', exact: true });
    if (!await sitePicker.isDisabled()) await sitePicker.selectOption(secondary.id);
    if (!await signOut.isDisabled()) await signOut.click();
    check(await sitePicker.inputValue() === id && await editor(page).inputValue() === draft && (await api(context, '/api/v1/session')).authenticated, 'dirty_site_switch_or_logout_lost_draft');
    await rootFolder(page); await managerPage(page).getByRole('button', { name: 'Open folder assets', exact: true }).click();
    const otherFile = managerPage(page).getByRole('button', { name: 'View file assets/readme.txt', exact: true });
    const readsBeforeDirtyOpen = v.seen.file_reads.length;
    if (!await otherFile.isDisabled()) await otherFile.click();
    check(await editor(page).inputValue() === draft && await managerPage(page).getByTestId('file-manager-editor').getAttribute('data-file-path') === 'index.html' && v.seen.file_reads.length === readsBeforeDirtyOpen, 'dirty_open_other_file_not_guarded');
    await nav(page, 'overview'); await manager(page); check(await editor(page).inputValue() === draft, 'overview_navigation_discarded_file_manager_draft');
    await nav(page, 'backups'); await manager(page); check(await editor(page).inputValue() === draft, 'backup_navigation_discarded_file_manager_draft');
    phase = 'dirty_draft_main_refresh';
    await waitFor(async () => await managerPage(page).getByTestId('file-manager-inventory').getAttribute('data-fresh') === 'true', 'navigation_inventory_never_settled');
    const sessionRead = page.waitForResponse(response => response.url() === origin + '/api/v1/session' && response.status() === 200);
    sessionRead.catch(() => {});
    await page.getByRole('button', { name: 'Refresh server data', exact: true }).click(); await sessionRead;
    check(await editor(page).inputValue() === draft && v.seen.file_writes.length === beforeNavigation, 'refresh_or_navigation_saved_or_discarded_draft');
    phase = 'real_revision_and_hash_conflict'; v.expectedHttp.add(409);
    const prior = await api(context, base + '/file?path=index.html'), concurrent = content + '<p>Actual concurrent revision</p>';
    await api(context, base + '/file', { method: 'PUT', csrf: session.csrf_token, data: { path: 'index.html', content: concurrent, expected_sha256: prior.sha256, expected_revision: prior.revision } });
    const failedSave = page.waitForResponse(response => response.url() === origin + base + '/file' && response.request().method() === 'PUT' && response.status() === 409);
    failedSave.catch(() => {});
    await save(page).click(); await failedSave;
    const conflict = page.getByTestId('file-manager-conflict'); await conflict.waitFor();
    check(await editor(page).inputValue() === draft && await save(page).isDisabled(), 'conflict_discarded_draft_or_allows_blind_save');
    const latest = await api(context, base + '/file?path=index.html'); check(latest.content === concurrent, 'conflicting_save_overwrote_server_file');
    const beforeRead = v.seen.file_reads.length, beforeResolution = v.seen.file_writes.length;
    await conflict.getByRole('button', { name: 'Read latest server version', exact: true }).click();
    await waitFor(() => v.seen.file_reads.length > beforeRead && v.seen.file_reads.some(item => item.path === 'index.html' && item.sha256 === latest.sha256 && item.revision === latest.revision), 'conflict_resolution_did_not_reread_actual_latest');
    await conflict.locator('details summary').click();
    check((await conflict.innerText()).includes(concurrent), 'conflict_compare_does_not_show_actual_latest_content');
    await screenshot(page, '1440-light-real-file-conflict.png');
    await conflict.getByRole('button', { name: 'Keep draft and use latest revision', exact: true }).click();
    check(await editor(page).inputValue() === draft && v.seen.file_writes.length === beforeResolution, 'conflict_adoption_saved_or_discarded_draft');
    await saveActual(page, v, 'index.html', draft);
    phase = 'invalid_path_and_utf8_byte_limits'; await managerPage(page).getByRole('button', { name: 'New text file', exact: true }).click();
    const pathInput = managerPage(page).getByLabel('Relative file path', { exact: true }); await editor(page).fill('bounded fixture text');
    const beforeInvalid = v.seen.file_writes.length;
    const invalidPaths = ['../escape.txt', '/absolute.txt', 'a\\escape.txt', '.env', 'source.php', 'credentials.txt', 'CON.txt', 'index.html/child.txt', 'a/b/c/d/e/f/g/h/i.txt', 'a'.repeat(80) + '.txt'];
    for (const invalid of invalidPaths) { await pathInput.fill(invalid); check(await save(page).isDisabled(), 'invalid_relative_path_admitted'); }
    await pathInput.fill('assets/boundary.txt');
    await editor(page).fill('é'.repeat(1048576)); check(await save(page).isEnabled(), 'exact_2mib_utf8_text_not_admitted');
    await editor(page).fill('é'.repeat(1048577)); check(await save(page).isDisabled(), 'over_2mib_utf8_text_admitted');
    await editor(page).fill('bounded fixture text');
    const exactPath = 'a'.repeat(70) + '/' + 'b'.repeat(70) + '/' + 'c'.repeat(54) + '.txt';
    check(Buffer.byteLength(exactPath) === 200, 'qa_path_boundary_fixture_invalid');
    await pathInput.fill(exactPath); check(await save(page).isEnabled(), 'exact_200_byte_path_not_admitted');
    await pathInput.fill(exactPath.slice(0, -4) + 'x.txt'); check(await save(page).isDisabled(), 'over_200_byte_path_admitted');
    check(v.seen.file_writes.length === beforeInvalid, 'invalid_or_boundary_draft_sent_write');
    const validBeforeInvalid = await api(context, base + '/file?path=index.html');
    await api(context, base + '/file', { method: 'PUT', csrf: session.csrf_token, expected: 422, data: { path: '../escape.txt', content: 'invalid fixture path', expected_sha256: '', expected_revision: validBeforeInvalid.revision } });
    await api(context, base + '/file', { method: 'PUT', csrf: session.csrf_token, expected: 422, data: { path: 'oversized.txt', content: 'x'.repeat(2097153), expected_sha256: '', expected_revision: validBeforeInvalid.revision } });
    const validAfterInvalid = await api(context, base + '/file?path=index.html'); check(validAfterInvalid.revision === validBeforeInvalid.revision && validAfterInvalid.sha256 === validBeforeInvalid.sha256, 'invalid_backend_write_changed_existing_content');
    await managerPage(page).getByRole('button', { name: 'Discard draft', exact: true }).click();
    phase = 'logout'; await managerPage(page).getByRole('button', { name: 'Sign out locally', exact: true }).click(); await managerPage(page).getByLabel('Operator access key', { exact: true }).waitFor();
    check(await managerPage(page).getByTestId('file-row').count() === 0 && await managerPage(page).getByTestId('file-manager-editor').count() === 0 && !(await context.cookies()).some(cookie => cookie.name === 'sifruno_operator'), 'logout_retained_private_files_or_cookie'); await api(context, '/api/v1/sites', { expected: 401 });
    healthy(v.health);
    report.workflow = { browser_site_created: true, inventory_and_read_match_actual_api: true, existing_file_saved: true, new_nested_utf8_file_saved: true, new_file_bytes: Buffer.byteLength(nestedContent, 'utf8'), new_file_sha256: hash(Buffer.from(nestedContent, 'utf8')), derived_folder_and_search: true, dirty_navigation_and_refresh_preserved_draft: true, navigation_writes: 0, actual_revision_hash_conflict: true, conflict_reread_actual_latest: true, resolution_no_implicit_write: true, explicit_resolved_save: true, invalid_path_cases: invalidPaths.length, utf8_bytes_boundary: { admitted: 2097152, denied: 2097154 }, path_bytes_boundary: { admitted: 200, denied: 201 }, invalid_draft_writes: 0, actual_backend_invalid_path_and_size_422: true, invalid_backend_writes_preserved_revision_hash: true, logout_private_data_and_cookie_cleared: true, file_writes: v.seen.file_writes, health: v.health };
  } catch (error) {
    if (phase.startsWith('dirty_') || phase.startsWith('real_revision_')) {
      try {
        report.failure_observation = { editor_retained: await editor(page).count() > 0, inventory_fresh: await managerPage(page).getByTestId('file-manager-inventory').getAttribute('data-fresh'), refresh_disabled: await page.getByRole('button', { name: 'Refresh server data', exact: true }).isDisabled(), file_read_count: v.seen.file_reads.length, file_write_count: v.seen.file_writes.length, health: v.health };
        await screenshot(page, 'failed-' + phase + '.png');
      } catch { }
    }
    throw error;
  } finally { await context.close(); }
}
async function viewport(width, theme) {
  phase = 'private_viewport_' + width + '_' + theme; const v = await contextFor(origin, width, theme);
  try {
    await v.page.goto(origin, { waitUntil: 'networkidle' }); await manager(v.page); await managerPage(v.page).getByLabel('Operator access key', { exact: true }).waitFor(); await screenshot(v.page, width + '-' + theme + '-files-login.png');
    await login(v.page); await selected(v.page, report.site_id); await openFile(v.page, 'index.html');
    await fileMatches(v.page, await api(v.context, '/api/v1/sites/' + report.site_id + '/file?path=index.html'), v);
    check(await v.page.locator('html').evaluate(element => element.classList.contains('dark')) === (theme === 'dark'), 'theme_not_applied');
    await screenshot(v.page, width + '-' + theme + '-files.png');
    await openFile(v.page, 'assets/readme.txt'); await fileMatches(v.page, await api(v.context, '/api/v1/sites/' + report.site_id + '/file?path=assets%2Freadme.txt'), v); await screenshot(v.page, width + '-' + theme + '-files-nested.png');
    check(v.seen.file_writes.length === 0, 'viewport_read_only_flow_mutated_fixture');
    await managerPage(v.page).getByRole('button', { name: 'Sign out locally', exact: true }).click(); await managerPage(v.page).getByLabel('Operator access key', { exact: true }).waitFor(); check(await managerPage(v.page).getByTestId('file-row').count() === 0, 'viewport_logout_retained_file_rows'); healthy(v.health);
    report.viewports.push({ width, theme, actual_root_and_nested_file_reads: true, read_only_flow_writes: 0, logout_cleared_private_rows: true, document_overflow: false, health: v.health });
  } finally { await v.context.close(); }
}
async function publicViewport(base, width, theme, remote = false) {
  phase = (remote ? 'remote_public_' : 'isolated_public_') + width + '_' + theme; const v = await contextFor(base, width, theme, true);
  try {
    await v.page.goto(base, { waitUntil: 'networkidle' }); await v.page.getByTestId('server-overview').waitFor(); check(await v.page.locator('meta[name="sifruno-public-preview"]').count() === 1, 'public_marker_missing');
    for (const id of ['files', 'backups', 'websites', 'accounts', 'trail', 'budget']) check(await v.page.getByTestId('nav-' + id).count() === 0, 'private_public_navigation_visible');
    check(await v.page.getByTestId('file-manager-page').count() === 0 && await v.page.getByLabel('Operator access key', { exact: true }).count() === 0, 'public_file_manager_or_auth_mounted');
    await screenshot(v.page, (remote ? 'remote-public-' : 'isolated-public-') + width + '-' + theme + '.png'); healthy(v.health);
    const result = { width, theme, file_manager_unmounted: true, private_navigation_hidden: true, private_api_requests: 0, document_overflow: false, health: v.health }; (remote ? report.remote_public_viewports : report.public_viewports).push(result);
  } finally { await v.context.close(); }
}

try {
  await directory(output); phase = 'owned_fixture_start'; await startFixture(); browser = await chromium.launch({ headless: true, env: environment() }); await workflow();
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await viewport(width, theme);
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await publicViewport(publicOrigin, width, theme);
  if (remotePublic) for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await publicViewport(remotePublic, width, theme, true);
  phase = 'source_consistency'; for (const [source, before] of Object.entries(report.sources)) check(hash(await bounded(join(source.startsWith('scripts/') ? root : uiRoot, source), 4 << 20, source.startsWith('scripts/') ? root : uiRoot)) === before, 'source_changed_during_qa'); report.passed = true;
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
