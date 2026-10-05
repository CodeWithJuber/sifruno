// Public design tour acceptance. Static sample interactions do not qualify hosting execution.
// Staged: node scripts/verify-panel-preview.mjs --dist-root .cache/panel-preview-build/RUN/dist
// Live: node scripts/verify-panel-preview.mjs --public-origin https://preview-tunnel.example.com
// Both arguments run both surfaces against the supplied build. No auth, backend writes or service restart.
import { createRequire } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, readFile, writeFile, lstat, realpath, readdir } from 'node:fs/promises';
import { dirname, join, resolve, relative, sep, isAbsolute, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { chromium } = createRequire(join(root, 'package.json'))('playwright');
const approvedPublic = 'https://preview-tunnel.example.com';
const publicApis = ['/api/v1/server', '/api/v1/status', '/api/v1/platform', '/api/v1/services'];
const args = process.argv.slice(2);
function check(ok, code) { if (!ok) throw Object.assign(new Error(code), { checkCode: code }); }
check(args.length > 0 && args.length % 2 === 0 && args.every((arg, i) => i % 2 ? Boolean(arg) : ['--dist-root', '--public-origin'].includes(arg)), 'invalid_arguments');
check(new Set(args.filter((_, i) => i % 2 === 0)).size === args.length / 2, 'duplicate_arguments');
const option = name => { const i = args.indexOf(name); return i < 0 ? null : args[i + 1]; };
const remote = option('--public-origin');
check(remote === null || remote === approvedPublic, 'public_origin_not_approved');
const stage = option('--dist-root');
const dist = resolve(stage || join(root, 'web/dist'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const runId = new Date().toISOString().replace(/[-:.Z]/g, '') + '-' + randomUUID().slice(0, 8);
const output = join(root, 'artifacts/panel-preview', runId);
const pins = new Map(), responseJobs = [];
const report = { schema_version: 1, checked_at: new Date().toISOString(), passed: false, evidence_kind: 'public_sample_gallery_browser_acceptance', browser: 'isolated Playwright Chromium', browser_plugin: 'Browser plugin not available; repository Playwright acceptance workflow', dist_root: relative(root, dist), public_origin: remote, staged_origin: null, main_state_mutated: false, fixture_backend_created: false, hosting_execution_qualified: false, compatibility_certified: false, phone_verified: false, sources: {}, viewports: [], cleanup: {} };
let browser, server, phase = 'prepare';
const fixtureHealth = { rejected_requests: 0, upstream_failures: 0 };

function inside(parent, path) { const rel = relative(parent, path); return !isAbsolute(rel) && !rel.split(sep).includes('..'); }
async function regularPath(path, directory = false) {
  check(inside(root, path), 'path_outside_workspace');
  let current = root;
  for (const part of relative(root, path).split(sep).filter(Boolean)) {
    current = join(current, part); const info = await lstat(current);
    check(!info.isSymbolicLink() && (await realpath(current)).toLowerCase() === current.toLowerCase(), 'symlink_or_reparse_path');
  }
  const info = await lstat(path);
  check(directory ? info.isDirectory() : info.isFile() && info.nlink === 1, 'not_regular_owned_input');
}
async function prepare() {
  check(stage ? inside(join(root, '.cache/panel-preview-build'), dist) && extname(dist) === '' && dist.endsWith(sep + 'dist') : Boolean(remote), 'dist_root_not_admitted');
  await regularPath(dist, true);
  async function pinDirectory(directory) {
    for (const item of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, item.name); await regularPath(path, item.isDirectory());
      if (item.isDirectory()) await pinDirectory(path);
      else { const bytes = await readFile(path); check(bytes.length <= 16 << 20 && pins.size < 512, 'build_input_bound'); pins.set(relative(dist, path).split(sep).join('/'), digest(bytes)); }
    }
  }
  await pinDirectory(dist);
  check(pins.has('index.html') && [...pins.keys()].some(name => /^assets\/PanelPreview-[\w-]+\.js$/.test(name)), 'panel_preview_build_missing');
  report.sources.dist = Object.fromEntries(pins);
  for (const name of ['scripts/verify-panel-preview.mjs', 'web/src/App.tsx', 'web/src/PanelPreview.tsx', 'web/src/panel-preview.css']) {
    await regularPath(join(root, name)); report.sources[name] = digest(await readFile(join(root, name)));
  }
  let current = root;
  for (const part of relative(root, output).split(sep)) {
    current = join(current, part); try { await mkdir(current); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    await regularPath(current, true);
  }
}
async function boundedBody(response, limit) {
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try { while (true) { const item = await reader.read(); if (item.done) break; size += item.value.length; check(size <= limit, 'upstream_body_bound'); chunks.push(item.value); } return Buffer.concat(chunks); }
  finally { await reader.cancel(); }
}
function admittedApi(url) {
  if (!publicApis.includes(url.pathname)) return false;
  if (!url.search) return true;
  return url.pathname === '/api/v1/server' && [...url.searchParams].length === 1 && /^\d{1,3}$/.test(url.searchParams.get('range_seconds') || '') && Number(url.searchParams.get('range_seconds')) <= 600;
}
async function startFixture() {
  server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://127.0.0.1');
      const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      const api = admittedApi(url);
      if (request.method !== 'GET' || (!api && (url.search || !pins.has(name)))) { fixtureHealth.rejected_requests++; response.writeHead(403); return response.end(); }
      let bytes, type, status = 200;
      if (api) {
        // Fixed read-only upstream. No inbound cookies, authorization, Host or other headers forwarded.
        const upstream = await fetch('http://127.0.0.1:8080' + url.pathname + url.search, { signal: AbortSignal.timeout(10000), redirect: 'error', headers: { Accept: 'application/json' } });
        status = upstream.status; type = 'application/json'; bytes = await boundedBody(upstream, 1 << 20);
      } else {
        const path = join(dist, ...name.split('/')); await regularPath(path); bytes = await readFile(path);
        check(digest(bytes) === pins.get(name), 'staged_asset_changed');
        type = ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.webmanifest': 'application/manifest+json' })[extname(name)] || 'application/octet-stream';
        if (name === 'index.html') { const html = bytes.toString('utf8'); check(html.includes('</head>') && !html.includes('name="sifruno-public-preview"'), 'stage_public_marker_not_injectable'); bytes = Buffer.from(html.replace('</head>', '<meta name="sifruno-public-preview" content="isolated-read-only"></head>')); }
      }
      response.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Sifruno-View': 'public-read-only' }); response.end(bytes);
    } catch { fixtureHealth.upstream_failures++; if (!response.headersSent) response.writeHead(502); response.end(); }
  });
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  report.staged_origin = 'http://127.0.0.1:' + server.address().port;
}
async function settle(page) { await page.evaluate(async () => { await document.fonts.ready; await new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))); }); }
async function overflow(page) { check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1), 'horizontal_document_overflow'); }
async function screenshot(page, name) { await page.evaluate(() => scrollTo(0, 0)); await settle(page); await overflow(page); await page.screenshot({ path: join(output, name + '.png'), fullPage: true, timeout: 15000 }); }
async function press(control, key = 'Enter') { await control.focus(); check(await control.evaluate(element => document.activeElement === element), 'keyboard_control_not_focused'); await control.press(key); }
async function facts(locator) { return locator.locator('div').evaluateAll(elements => Object.fromEntries(elements.filter(element => element.querySelector('dt') && element.querySelector('dd')).map(element => [element.querySelector('dt').textContent.trim(), element.querySelector('dd').textContent.trim()]))); }
// Keep label assertions scoped to the displayed sample gallery, separately from live monitoring.
async function galleryInvariant(page) {
  const gallery = page.getByTestId('panel-preview');
  check(await gallery.isVisible() && await gallery.getByText('Sample workspace / read-only preview', { exact: true }).isVisible(), 'sample_readonly_label_missing');
  check(await gallery.getByText('This public tour uses sample content. Private workflows require local operator sign-in.', { exact: true }).isVisible(), 'sample_boundary_missing');
  check(await page.locator('.panel-footer').getByText('Sample workspace · read-only', { exact: true }).isVisible(), 'sample_footer_missing');
  check(await gallery.locator('textarea,input:not([data-testid="preview-file-search"]),[contenteditable="true"],a[download]').count() === 0, 'gallery_edit_or_download_control_present');
  const forbidden = await gallery.locator('button,a').evaluateAll(elements => elements.some(element => /\b(save|create|restore|download|sign[ -]?in|log[ -]?in|delete|upload)\b/i.test((element.getAttribute('aria-label') || '') + ' ' + element.textContent)));
  check(!forbidden, 'gallery_write_or_login_action_present');
  check(await page.locator('main').count() === 1 && await page.locator('h1:visible').count() === 1, 'landmark_heading_invalid');
  const unnamed = await page.locator('button,input').evaluateAll(elements => elements.filter(element => element.getClientRects().length).some(element => !(element.getAttribute('aria-label') || element.getAttribute('aria-labelledby') || element.labels?.length || element.textContent.trim())));
  check(!unnamed, 'unnamed_visible_control'); await overflow(page);
}
async function selectedFile(page, path) {
  const content = page.getByTestId('preview-file-content'); await content.locator('code').waitFor();
  check(await content.getAttribute('data-path') === path, 'sample_file_selection_mismatch');
  const bytes = Buffer.from(await content.textContent(), 'utf8'), metadata = await facts(page.locator('.pp-file-facts'));
  check(metadata.Size === (bytes.length < 1024 ? bytes.length + ' B' : (bytes.length / 1024).toFixed(1) + ' KiB') && metadata.Encoding === 'UTF-8' && metadata['SHA-256 of this sample text'] === digest(bytes), 'sample_text_size_or_hash_mismatch');
  return { path, bytes: bytes.length, sha256: digest(bytes) };
}
async function files(page) {
  const rows = page.getByTestId('preview-file-row'), search = page.getByTestId('preview-file-search');
  check(await rows.count() === 1 && await page.getByTestId('preview-folder').count() === 3, 'sample_root_inventory_mismatch');
  const result = [await selectedFile(page, 'index.html')];
  check((await page.getByTestId('preview-file-content').textContent()).includes('<h1>A place for your next idea.</h1>'), 'sample_index_text_missing');
  await press(page.locator('[data-testid="preview-folder"][data-path="assets"]'), 'Enter');
  check(await rows.count() === 2 && await page.getByTestId('preview-folder').count() === 0, 'sample_folder_did_not_open');
  for (const path of ['assets/app.js', 'assets/styles.css']) {
    await press(page.locator('[data-testid="preview-file-row"][data-path="' + path + '"]'), 'Space');
    result.push(await selectedFile(page, path)); await galleryInvariant(page);
  }
  await press(page.getByRole('navigation', { name: 'Sample folder path' }).getByRole('button', { name: 'public_html', exact: true }));
  check(await rows.count() === 1 && await page.getByTestId('preview-folder').count() === 3, 'sample_breadcrumb_did_not_reset');
  for (const path of ['notes/readme.txt', 'docs/help.html']) {
    await search.fill(path.toUpperCase()); check(await rows.count() === 1, 'global_sample_path_search_failed');
    await press(rows.first()); result.push(await selectedFile(page, path)); await galleryInvariant(page);
  }
  await search.fill('no-sample-file-' + runId); check(await rows.count() === 0 && await page.getByRole('status').filter({ hasText: 'No sample files match this search.' }).isVisible(), 'sample_empty_search_missing');
  await search.fill(''); check(await rows.count() === 1, 'sample_search_did_not_clear');
  await screenshot(page, phase + '-files'); return { files: result, folder_navigation: true, global_case_insensitive_search: true, empty_and_reset: true, read_only: true };
}
async function module(page, id, key = 'Enter') {
  const button = page.getByTestId('preview-module-' + id); await press(button, key);
  check(await button.getAttribute('aria-pressed') === 'true', 'sample_module_not_selected'); await galleryInvariant(page);
}
async function backups(page) {
  await page.getByTestId('preview-module-files').focus(); await page.keyboard.press('Tab');
  check(await page.getByTestId('preview-module-backups').evaluate(element => document.activeElement === element), 'module_controls_not_keyboard_reachable');
  await module(page, 'backups', 'Space'); const rows = page.getByTestId('preview-backup-row'); check(await rows.count() === 2, 'sample_backup_count_mismatch');
  const result = [];
  for (const [i, revision, count, sha, date, size] of [[0, 4, 5, 'a4', '2026-10-01T10:30:00Z', '1.4 KiB'], [1, 3, 4, 'b3', '2026-09-30T16:45:00Z', '1.2 KiB']]) {
    await press(rows.nth(i)); const details = page.getByTestId('preview-backup-details'), values = await facts(details);
    check(await rows.nth(i).getAttribute('aria-pressed') === 'true' && values.Archive === `studio-revision-${revision}.zip` && values.Files === count + ' static files' && values.Revision === String(revision) && values['Illustrative SHA-256'] === sha.repeat(32), 'illustrative_backup_metadata_mismatch');
    check(await details.locator('time').getAttribute('datetime') === date && (await rows.nth(i).innerText()).includes(size), 'illustrative_backup_time_or_size_mismatch');
    result.push({ archive: values.Archive, revision, static_files: count, illustrative_hash: true }); await galleryInvariant(page);
  }
  check(await page.getByText('This tour displays sample records only.', { exact: false }).isVisible(), 'illustrative_backup_boundary_missing');
  await screenshot(page, phase + '-backups'); return result;
}
async function websites(page) {
  await module(page, 'websites'); const rows = page.getByTestId('preview-site-row'); check(await rows.count() === 2, 'sample_site_count_mismatch');
  const result = [];
  for (const [i, name, domain, state, revision] of [[0, 'Studio website', 'studio.example.test', 'Active', 4], [1, 'Documentation', 'docs.example.test', 'Suspended', 2]]) {
    await press(rows.nth(i), 'Space'); const values = await facts(page.getByTestId('preview-site-details'));
    check((await rows.nth(i).innerText()).includes(name) && await rows.nth(i).getAttribute('aria-pressed') === 'true' && values['Sample domain'] === domain && values['Website state'] === state && values.Revision === String(revision) && values['Content type'] === 'Static files' && values.Workspace === 'App-owned site', 'sample_site_metadata_mismatch');
    result.push({ name, sample_domain: domain, state, revision }); await galleryInvariant(page);
  }
  await screenshot(page, phase + '-websites'); return result;
}
async function navigate(page, id) { const target = page.getByTestId('nav-' + id); if (!await target.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click(); await press(target); }
async function viewport(base, width, theme, surface) {
  phase = surface + '-' + width + '-' + theme;
  const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, colorScheme: theme, locale: 'en-US', reducedMotion: 'reduce', serviceWorkers: 'block', acceptDownloads: false });
  await context.addInitScript(value => localStorage.setItem('sifruno-theme', value), theme);
  const health = { private_requests: 0, private_module_requests: 0, mutation_requests: 0, external_requests: 0, unknown_requests: 0, page_errors: 0, console_errors: 0, failed_requests: 0, http_errors: 0, downloads: 0, asset_mismatches: 0 };
  const apis = {}, assets = new Set(); let realSample = false;
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== base) { health.external_requests++; return route.abort(); }
    if (!['GET', 'HEAD'].includes(request.method())) { health.mutation_requests++; return route.abort(); }
    if (/\/(FileManager|Backups|Websites|Accounts|Tools)-[\w-]+\.js$/.test(url.pathname)) { health.private_module_requests++; return route.abort(); }
    if (url.pathname.startsWith('/api/') && !admittedApi(url)) { health.private_requests++; return route.abort(); }
    if (!url.pathname.startsWith('/api/') && url.pathname !== '/' && !pins.has(url.pathname.slice(1))) { health.unknown_requests++; return route.abort(); }
    return route.continue();
  });
  const page = await context.newPage(); page.setDefaultTimeout(12000); page.setDefaultNavigationTimeout(20000);
  page.on('pageerror', () => health.page_errors++); page.on('console', message => { if (message.type() === 'error') health.console_errors++; });
  page.on('requestfailed', request => { if (request.failure()?.errorText !== 'net::ERR_ABORTED') health.failed_requests++; }); page.on('download', () => health.downloads++);
  page.on('response', response => {
    const job = (async () => {
      const url = new URL(response.url()); if (response.status() >= 400) health.http_errors++;
      if (url.pathname.startsWith('/api/')) {
        apis[url.pathname] = (apis[url.pathname] || 0) + 1;
        if (url.pathname === '/api/v1/server' && response.status() === 200) { const sample = await response.json(); realSample = sample.collector?.name === 'gopsutil/v4' && Number.isFinite(Date.parse(sample.sampled_at)); }
      } else if (url.pathname !== '/' && response.status() === 200) {
        const name = url.pathname.slice(1); assets.add(name); if (digest(await response.body()) !== pins.get(name)) health.asset_mismatches++;
      }
    })().catch(() => health.page_errors++); responseJobs.push(job);
  });
  try {
    const response = await page.goto(base + '/', { waitUntil: 'networkidle' });
    check(response.status() === 200 && await page.title() === 'Sifruno · Server panel', 'page_identity_mismatch');
    check(response.headers()['x-sifruno-view'] === 'public-read-only' && await page.locator('meta[name="sifruno-public-preview"]').count() === 1, 'public_scope_metadata_missing');
    await page.getByTestId('server-overview').waitFor();
    check(await page.evaluate(() => document.documentElement.classList.contains('dark')) === (theme === 'dark'), 'rendered_theme_mismatch');
    check(await page.getByTestId('panel-preview').count() === 0, 'preview_replaces_default_overview');
    for (const id of ['files', 'backups', 'websites', 'accounts', 'trail', 'budget']) check(await page.getByTestId('nav-' + id).count() === 0, 'private_nav_present');
    check(await page.getByLabel('Operator access key', { exact: true }).count() === 0, 'operator_auth_mounted');
    check(await page.getByTestId('open-panel-preview').isVisible(), 'overview_explore_panel_not_visible');
    await screenshot(page, phase + '-overview');
    const storageBefore = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }));
    await press(page.getByTestId('open-panel-preview')); await page.getByTestId('panel-preview').waitFor();
    check(await page.getByRole('heading', { name: 'Panel preview', level: 1, exact: true }).isVisible(), 'preview_heading_missing'); await galleryInvariant(page);
    const fileResult = await files(page), backupResult = await backups(page), websiteResult = await websites(page);
    check(JSON.stringify(await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }))) === JSON.stringify(storageBefore), 'gallery_persisted_state');
    check(await context.cookies().then(cookies => cookies.length === 0), 'public_session_cookie_created');
    await navigate(page, 'overview'); await page.getByTestId('server-overview').waitFor();
    await navigate(page, 'panel-preview'); await page.getByTestId('panel-preview').waitFor(); await galleryInvariant(page);
    check(await page.getByTestId('preview-module-files').getAttribute('aria-pressed') === 'true', 'gallery_navigation_does_not_reset_to_files');
    await Promise.all(responseJobs); check(realSample, 'actual_host_monitoring_sample_missing');
    check([...assets].some(name => /^assets\/PanelPreview-[\w-]+\.js$/.test(name)), 'gallery_lazy_asset_not_observed');
    check(Object.values(health).every(value => value === 0), 'browser_boundary_or_runtime_failure');
    report.viewports.push({ surface, width, theme, rendered_theme_verified: true, default_overview_retained: true, obvious_overview_entry: true, nav_entry: true, labels_present_each_module: true, keyboard_tab_enter_and_space: true, file_gallery: fileResult, illustrative_backups: backupResult, sample_websites: websiteResult, public_api_reads: apis, gallery_storage_unchanged: true, cookie_count: 0, overflow: false, asset_hashes_equal: true, health });
  } catch (error) { report.failure_observation = { surface, width, theme, health, public_api_reads: apis }; try { await screenshot(page, phase + '-failure'); } catch { /* Original failure retained. */ } throw error; }
  finally { await context.close(); }
}
try {
  await prepare(); if (stage) await startFixture();
  const env = {}; for (const name of ['PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA']) if (process.env[name] !== undefined) env[name] = process.env[name];
  browser = await chromium.launch({ headless: true, env });
  for (const [base, surface] of [[report.staged_origin, 'staged'], [remote, 'live']].filter(([base]) => base)) for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await viewport(base, width, theme, surface);
  phase = 'final_pins'; await Promise.all(responseJobs);
  for (const [name, hash] of pins) check(digest(await readFile(join(dist, ...name.split('/')))) === hash, 'build_changed_during_verification');
  for (const [name, hash] of Object.entries(report.sources).filter(([name]) => name !== 'dist')) check(digest(await readFile(join(root, name))) === hash, 'source_changed_during_verification');
  check(Object.values(fixtureHealth).every(value => value === 0), 'fixture_request_failure'); report.passed = true;
} catch (error) { report.failure = { phase, code: error.checkCode || 'bounded_browser_or_fixture_step_failed' }; process.exitCode = 1; }
finally {
  if (browser) { try { await browser.close(); report.cleanup.browser_closed = true; } catch { report.cleanup.browser_closed = false; process.exitCode = 1; report.passed = false; } }
  if (server?.listening) { await new Promise(done => { server.close(done); server.closeAllConnections(); }); report.cleanup.owned_fixture_closed = !server.listening; } else report.cleanup.owned_fixture_closed = true;
  report.cleanup.no_live_processes_stopped = true; report.fixture_health = fixtureHealth;
  try { await regularPath(output, true); await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' }); console.log(JSON.stringify({ passed: report.passed, report: join(output, 'report.json'), report_sha256: digest(await readFile(join(output, 'report.json'))), failure: report.failure, cases: report.viewports.length, cleanup: report.cleanup })); }
  catch { process.exitCode = 1; console.log(JSON.stringify({ passed: false, failure: report.failure || { phase: 'report', code: 'report_directory_unavailable' } })); }
}
