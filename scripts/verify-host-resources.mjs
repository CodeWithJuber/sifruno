// Read-only browser acceptance for Storage/Network. No auth, state or service access.
// node scripts/verify-host-resources.mjs --origin http://127.0.0.1:PORT [--public-origin URL] [--ui-root PATH]
import { createRequire } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile, realpath, lstat } from 'node:fs/promises';
import { dirname, join, resolve, relative, sep, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const primary = dirname(root).endsWith('.worktrees') ? resolve(root, '../..') : root;
const { chromium } = createRequire(join(primary, 'package.json'))('playwright');
const approvedPublic = 'https://preview-tunnel.example.com';
const args = process.argv.slice(2);
function check(ok, code) { if (!ok) throw Object.assign(new Error(code), { checkCode: code }); }
function option(name, fallback) {
  const index = args.indexOf(name);
  return index < 0 ? fallback : args[index + 1];
}
check(args.every((arg, index) => index % 2 ? Boolean(arg) : ['--origin', '--public-origin', '--ui-root'].includes(arg)) && args.length % 2 === 0, 'invalid_arguments');
const uiRoot = resolve(option('--ui-root', root));
check(!isAbsolute(relative(primary, uiRoot)) && !relative(primary, uiRoot).split(sep).includes('..'), 'ui_root_escapes_primary_workspace');
function loopback(value) {
  const url = new URL(value);
  check(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'origin_not_plain_loopback');
  return url.origin;
}
const origin = loopback(option('--origin', 'http://127.0.0.1:8080'));
const publicValue = option('--public-origin', undefined);
const publicOrigin = publicValue ? publicValue === approvedPublic ? approvedPublic : loopback(publicValue) : null;
const runId = new Date().toISOString().replace(/[-:.Z]/g, '') + '-' + randomUUID().slice(0, 8);
const output = join(root, 'artifacts/host-resources', runId);
const digest = value => createHash('sha256').update(value).digest('hex');
const report = {
  schema_version: 1, checked_at: new Date().toISOString(), origin, public_origin: publicOrigin,
  evidence_kind: 'observed_read_only_host_resources_browser_qa', browser: 'Playwright Chromium',
  server_mutations: 0, phone_verified: false, compatibility_certified: false,
  sources: {}, live_viewports: [], synthetic_contract_checks: [], public_viewports: [],
};
const assetChecks = new Map();
let browser, phase = 'prepare';

async function prepareOutput() {
  let current = await realpath(root);
  const path = relative(root, output);
  check(!isAbsolute(path) && !path.split(sep).includes('..'), 'output_escapes_workspace');
  for (const part of path.split(sep)) {
    current = join(current, part);
    try { await mkdir(current); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const stat = await lstat(current);
    check(stat.isDirectory() && !stat.isSymbolicLink() && await realpath(current) === current, 'output_not_regular_directory');
  }
}
async function getServer(base) {
  const response = await fetch(base + '/api/v1/server', { signal: AbortSignal.timeout(10000), redirect: 'error', headers: { Accept: 'application/json' } });
  check(response.status === 200, 'server_http_not_200');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      check(size <= 1048576, 'server_response_not_bounded');
      chunks.push(chunk.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally { await reader.cancel(); }
}
const numeric = value => value === null || typeof value === 'number' && Number.isFinite(value) && value >= 0;
function serverContract(server) {
  check(Number.isFinite(Date.parse(server.sampled_at)) && server.collector?.name === 'gopsutil/v4', 'real_collector_identity_or_timestamp_missing');
  check(Array.isArray(server.storage?.disks) && Array.isArray(server.history) && server.history.length <= server.collector.history_limit, 'real_inventory_or_history_invalid');
  for (const component of ['storage', 'network']) check(typeof server[component]?.available === 'boolean' && typeof server[component].reason === 'string', 'availability_contract_invalid');
  for (const key of ['total_bytes', 'used_bytes', 'free_bytes', 'used_percent']) check(numeric(server.storage[key]), 'storage_measurement_invalid');
  for (const key of ['bytes_received', 'bytes_sent', 'rx_bytes_per_second', 'tx_bytes_per_second']) check(numeric(server.network[key]), 'network_measurement_invalid');
  for (const disk of server.storage.disks) {
    check(/^Volume \d+$/.test(disk.label) && typeof disk.id === 'string' && !/[\\/:]/.test(disk.id), 'disk_identity_not_sanitized');
    check(typeof disk.available === 'boolean' && typeof disk.reason === 'string', 'disk_availability_invalid');
    for (const key of ['total_bytes', 'used_bytes', 'free_bytes', 'used_percent']) check(numeric(disk[key]), 'disk_measurement_invalid');
  }
  check(new Set(server.storage.disks.map(disk => disk.id)).size === server.storage.disks.length, 'disk_ids_not_unique');
  let prior = -Infinity;
  for (const sample of server.history) {
    const at = Date.parse(sample.sampled_at);
    check(Number.isFinite(at) && at > prior && at <= Date.parse(server.sampled_at), 'history_not_ordered_real_samples');
    prior = at;
  }
}
async function waitFor(read, code) {
  const deadline = Date.now() + 12000;
  while (!await read() && Date.now() < deadline) await new Promise(done => setTimeout(done, 30));
  check(Boolean(await read()), code);
}
async function isolated(base, width, theme, fixture) {
  const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, colorScheme: theme, locale: 'en-US', reducedMotion: 'reduce' });
  await context.addInitScript(value => localStorage.setItem('sifruno-theme', value), theme);
  const health = { page_errors: 0, console_errors: 0, failed_requests: 0, http_errors: 0, external_requests: 0, mutation_requests: 0, private_requests: 0 };
  const observed = { samples: new Map(), ranges: [], requests: 0, assets: new Map() };
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== base) { health.external_requests++; return route.abort(); }
    if (!['GET', 'HEAD'].includes(request.method())) { health.mutation_requests++; return route.abort(); }
    if (url.pathname.startsWith('/api/') && !['/api/v1/server', '/api/v1/status', '/api/v1/platform', '/api/v1/services'].includes(url.pathname)) { health.private_requests++; return route.abort(); }
    if (url.pathname === '/api/v1/server' && fixture) return route.fulfill({ status: fixture.status, contentType: 'application/json', body: JSON.stringify(fixture.body) });
    return route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(12000); page.setDefaultNavigationTimeout(20000);
  page.on('pageerror', () => health.page_errors++);
  page.on('console', message => { if (message.type() === 'error') health.console_errors++; });
  page.on('requestfailed', request => { if (request.failure()?.errorText !== 'net::ERR_ABORTED') health.failed_requests++; });
  page.on('response', async response => {
    const url = new URL(response.url());
    if (response.status() >= 400) health.http_errors++;
    if (/^\/assets\/[A-Za-z0-9_.-]+\.(js|css)$/.test(url.pathname) && response.status() === 200) {
      try {
        const source = 'web/dist' + url.pathname;
        if (!assetChecks.has(source)) { const expected = digest(await readFile(join(uiRoot, source))); assetChecks.set(source, expected); report.sources[source] = expected; }
        observed.assets.set(source, digest(await response.body()));
      } catch { health.page_errors++; }
    }
    if (url.pathname === '/api/v1/server') {
      observed.requests++; observed.ranges.push(url.searchParams.get('range_seconds'));
      if (response.status() === 200) try { const body = await response.json(); observed.samples.set(body.sampled_at, body); } catch { health.page_errors++; }
    }
  });
  return { context, page, health, observed };
}
async function navigate(page, section) {
  const target = page.getByTestId('nav-' + section);
  if (!await target.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
  await target.click();
  await page.getByTestId(section + '-page').waitFor();
  check(await page.getByRole('heading', { level: 1, name: section === 'storage' ? 'Storage' : 'Network', exact: true }).isVisible(), 'section_heading_mismatch');
}
async function overflow(page) {
  const sizes = await page.evaluate(() => ({ width: innerWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
  check(sizes.document <= sizes.width + 1 && sizes.body <= sizes.width + 1, 'horizontal_document_overflow');
}
async function basics(page) {
  check(await page.locator('main').count() === 1 && await page.locator('h1:visible').count() === 1, 'landmark_or_heading_count');
  const failures = await page.evaluate(() => [...document.querySelectorAll('button,input,select,textarea')].filter(element => element.getClientRects().length).filter(element => !(element.getAttribute('aria-label') || element.getAttribute('aria-labelledby') || element.labels?.length || element.textContent.trim())).length);
  check(failures === 0, 'unnamed_visible_controls');
}
async function renderedSample(page, section, observed) {
  const container = page.getByTestId(section + '-page');
  let sample;
  await waitFor(async () => { const at = await container.getAttribute('data-sampled-at'); sample = observed.samples.get(at); return Boolean(sample); }, 'rendered_timestamp_not_observed_response');
  check(await container.locator(`time[datetime="${sample.sampled_at}"]`).count() > 0, 'visible_sample_timestamp_missing');
  serverContract(sample);
  return sample;
}
const formatBytes = value => {
  if (value === null) return 'Unavailable';
  if (value === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const power = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** power).toLocaleString('en-US', { maximumFractionDigits: power ? 1 : 0 })} ${units[power]}`;
};
const formatRate = value => value === null ? 'Unavailable' : value > 0 && value < 1 ? `${value.toLocaleString('en-US', { maximumSignificantDigits: 3 })} B/s` : formatBytes(value) + '/s';
async function metric(page, id, expected, rate = false, count = false) {
  const value = page.getByTestId(id);
  check(await value.isVisible(), id + '_not_visible');
  check(await value.getAttribute('data-metric-value') === String(expected), id + '_differs_from_observed_sample');
  const text = await value.innerText();
  if (expected === null) check(/unavailable|warming|collecting|—|n\/a/i.test(text) && !/\d/.test(text), id + '_unknown_uses_numeric_default');
  else check(text.trim() === (count ? String(expected) : rate ? formatRate(expected) : formatBytes(expected)), id + '_visible_value_differs_from_observed_sample');
}
function healthy(health) { check(Object.values(health).every(count => count === 0), 'runtime_request_or_console_failure'); }

// Page-specific interaction checks are below; synthetic responses never certify a live host.
async function storage(page, observed) {
  const sample = await renderedSample(page, 'storage', observed);
  await metric(page, 'storage-total', sample.storage.available ? sample.storage.total_bytes : null);
  await metric(page, 'storage-used', sample.storage.available ? sample.storage.used_bytes : null);
  await metric(page, 'storage-free', sample.storage.available ? sample.storage.free_bytes : null);
  await metric(page, 'storage-volumes', sample.storage.disks.length, false, true);
  const rows = page.getByTestId('volume-row');
  const rowIds = () => rows.evaluateAll(elements => elements.map(element => element.getAttribute('data-volume-id')));
  const expectedOrder = (disks, order) => [...disks].sort((a, b) => {
    if (order === 'label') return (a.label || a.id).localeCompare(b.label || b.id, 'en-US');
    const key = order === 'free' ? 'free_bytes' : 'used_percent';
    const av = a.available ? a[key] : null, bv = b.available ? b[key] : null;
    if (av === null) return bv === null ? a.id.localeCompare(b.id, 'en-US') : 1;
    if (bv === null) return -1;
    return (order === 'free' ? av - bv : bv - av) || a.id.localeCompare(b.id, 'en-US');
  }).map(disk => disk.id);
  for (const order of ['label', 'used', 'free']) {
    await page.getByTestId('volume-sort').selectOption(order);
    const current = await renderedSample(page, 'storage', observed);
    check(JSON.stringify(await rowIds()) === JSON.stringify(expectedOrder(current.storage.disks, order)), 'volume_sort_order_incorrect');
  }
  await page.getByTestId('volume-sort').selectOption('label');
  const search = page.getByRole('searchbox', { name: 'Search volumes', exact: true });
  await search.fill('sifruno-qa-no-volume-matches');
  check(await rows.count() === 0 && await page.getByRole('heading', { name: 'No matching volumes', exact: true }).isVisible(), 'volume_search_does_not_filter');
  await page.getByRole('button', { name: 'Clear volume search', exact: true }).click();
  check(await search.inputValue() === '' && await rows.count() === sample.storage.disks.length, 'volume_search_does_not_reset');
  let detailsVerified = false;
  if (sample.storage.disks.length) {
    const disk = sample.storage.disks[0];
    await search.fill(disk.id);
    check(JSON.stringify(await rowIds()) === JSON.stringify([disk.id]), 'volume_search_does_not_match_real_id');
    const details = page.getByRole('button', { name: `Details for ${disk.label || disk.id}`, exact: true });
    await details.click();
    check(await details.getAttribute('aria-expanded') === 'true' && await page.getByTestId('volume-details').isVisible(), 'volume_details_does_not_expand');
    const pairs = await page.getByTestId('volume-details').locator('dl > div').evaluateAll(elements => Object.fromEntries(elements.map(element => [element.querySelector('dt').textContent, element.querySelector('dd').textContent])));
    check(pairs['Volume ID'] === disk.id && pairs['Collector label'] === disk.label && pairs['Total capacity'] === formatBytes(disk.available ? disk.total_bytes : null) && pairs['Used space'] === formatBytes(disk.available ? disk.used_bytes : null) && pairs['Free space'] === formatBytes(disk.available ? disk.free_bytes : null), 'volume_details_differs_from_real_inventory');
    check(pairs['Mount path'] === 'Not reported by collector' && pairs.Filesystem === 'Not reported by collector', 'unreported_disk_details_invented');
    await overflow(page);
    await details.click();
    check(await details.getAttribute('aria-expanded') === 'false' && await page.getByTestId('volume-details').count() === 0, 'volume_details_does_not_close');
    await search.fill(''); detailsVerified = true;
  }
  return { sampled_at: sample.sampled_at, volume_count: sample.storage.disks.length, available: sample.storage.available, search: true, sort_modes: ['label', 'used', 'free'], multi_volume_sort_observed: sample.storage.disks.length > 1, details: detailsVerified ? 'observed' : 'no_live_volumes_to_inspect' };
}
async function network(page, observed) {
  const sample = await renderedSample(page, 'network', observed);
  for (const [id, key] of Object.entries({ 'network-rx-rate': 'rx_bytes_per_second', 'network-tx-rate': 'tx_bytes_per_second', 'network-received': 'bytes_received', 'network-sent': 'bytes_sent' })) await metric(page, id, sample.network.available ? sample.network[key] : null, key.endsWith('per_second'));
  const chartCheck = async current => {
    for (const direction of ['rx', 'tx']) {
      const key = `network_${direction}_bytes_per_second`;
      const series = page.getByTestId(`network-${direction}-chart`);
      const values = current.history.filter(entry => entry[key] !== null);
      check(await series.locator('circle').count() === values.length, 'chart_point_count_differs_from_samples');
      const titles = await series.locator('circle title').allTextContents();
      check(titles.every((title, index) => title.endsWith(`${direction === 'rx' ? 'Received' : 'Sent'} ${formatRate(values[index][key])}`)), 'chart_point_values_not_real_samples');
      const path = await series.locator('path').getAttribute('d');
      check(!/NaN|Infinity|undefined/.test(path) && (values.length ? path.includes('M') : path.trim() === ''), 'chart_unknown_rates_use_numeric_path');
    }
    check((await page.locator('#network-chart-description').textContent()).startsWith(`${current.history.length} recorded samples.`), 'chart_sample_count_not_real');
    if (!current.history.some(entry => entry.network_rx_bytes_per_second !== null || entry.network_tx_bytes_per_second !== null)) check(await page.getByText('Waiting for measured rates', { exact: true }).isVisible(), 'chart_missing_unknown_rate_label');
  };
  await chartCheck(sample);
  for (const seconds of [300, 600, 60]) {
    const before = observed.requests;
    const range = page.getByRole('radiogroup', { name: 'Network chart time range', exact: true }).locator(`[data-value="${seconds}"]`);
    await range.click();
    await waitFor(() => observed.requests > before && observed.ranges.at(-1) === String(seconds), 'network_range_did_not_fetch_requested_window');
    check(await range.getAttribute('aria-checked') === 'true', 'network_range_not_selected');
    await chartCheck(await renderedSample(page, 'network', observed));
  }
  const previousRequests = observed.requests;
  await page.getByRole('button', { name: 'Refresh server data', exact: true }).click();
  await waitFor(() => observed.requests > previousRequests, 'refresh_did_not_request_host_sample');
  await renderedSample(page, 'network', observed);
  check(await page.getByText('Host aggregate', { exact: true }).isVisible() && await page.getByText(/They are not a billing-period transfer total/).isVisible(), 'network_scope_or_counter_limits_unlabelled');
  return { sampled_at: sample.sampled_at, history_count: sample.history.length, available: sample.network.available, charts_match_samples: true, chart_ranges: [300, 600, 60], refresh: true };
}
async function viewport(base, width, theme, isPublic = false) {
  phase = `${isPublic ? 'public' : 'live'}_${width}_${theme}`;
  const { context, page, health, observed } = await isolated(base, width, theme);
  const result = { width, theme, sections: {}, screenshots: [] };
  try {
    const response = await page.goto(base + '/', { waitUntil: 'networkidle' });
    check(response?.status() === 200 && /Sifruno/.test(await page.title()), 'html_identity_invalid');
    check(await page.locator('html').evaluate(element => element.classList.contains('dark')) === (theme === 'dark'), 'selected_theme_not_applied');
    if (isPublic) {
      check(await page.locator('meta[name="sifruno-public-preview"]').count() === 1, 'public_preview_marker_missing');
      for (const privateView of ['websites', 'accounts', 'trail', 'budget']) check(await page.getByTestId('nav-' + privateView).count() === 0, 'private_navigation_visible');
    }
    for (const section of ['storage', 'network']) {
      await navigate(page, section);
      result.sections[section] = await (section === 'storage' ? storage : network)(page, observed);
      await basics(page); await overflow(page); await page.evaluate(() => document.fonts.ready);
      const name = `${isPublic ? 'public' : 'live'}-${width}-${theme}-${section}.png`;
      await page.screenshot({ path: join(output, name), fullPage: true }); result.screenshots.push(name);
    }
    await waitFor(() => observed.assets.size >= 3 && [...observed.assets.keys()].some(source => source.includes('HostResources-')), 'served_host_resources_assets_not_observed');
    for (const [source, served] of observed.assets) check(assetChecks.get(source) === served, 'served_asset_differs_from_reviewed_ui_dist');
    healthy(health); result.health = health; result.document_overflow = false; result.passed = true; result.served_assets_match_reviewed_build = true;
    (isPublic ? report.public_viewports : report.live_viewports).push(result);
  } finally { await context.close(); }
}
async function synthetic(server) {
  const unavailable = structuredClone(server);
  unavailable.collector.status = 'unavailable'; unavailable.collector.reasons = ['Synthetic browser-only unavailable contract']; unavailable.history = [];
  for (const component of ['cpu', 'memory', 'storage', 'network', 'uptime']) {
    unavailable[component].available = false; unavailable[component].reason = 'Synthetic browser-only unavailable contract';
    for (const key of Object.keys(unavailable[component])) if (!['available', 'reason', 'disks'].includes(key)) unavailable[component][key] = null;
  }
  unavailable.storage.disks = [];
  const warming = structuredClone(server); warming.collector.status = 'partial'; warming.network.available = true; warming.network.reason = 'Waiting for a second counter sample'; warming.network.rx_bytes_per_second = null; warming.network.tx_bytes_per_second = null; warming.history = [];
  for (const fixture of [{ name: 'unavailable', status: 200, body: unavailable }, { name: 'warming-up', status: 200, body: warming }, { name: 'http-error', status: 503, body: { error: 'synthetic_browser_only' } }]) {
    phase = 'synthetic_' + fixture.name;
    const { context, page, health, observed } = await isolated(origin, 390, 'light', fixture);
    try {
      await page.goto(origin + '/', { waitUntil: 'networkidle' });
      for (const section of ['storage', 'network']) {
        const nav = page.getByTestId('nav-' + section);
        if (!await nav.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
        await nav.click();
        if (fixture.status === 200) {
          await page.getByTestId(section + '-page').waitFor();
          await (section === 'storage' ? storage : network)(page, observed);
        } else {
          await page.getByRole('alert').first().waitFor();
          check(await page.getByTestId(section + '-page').count() === 0, 'http_failure_renders_metrics');
        }
        await overflow(page);
      }
      check(health.page_errors === 0 && health.mutation_requests === 0 && health.external_requests === 0 && health.private_requests === 0, 'synthetic_runtime_or_boundary_failure');
      const name = 'synthetic-' + fixture.name + '.png';
      await page.screenshot({ path: join(output, name), fullPage: true });
      report.synthetic_contract_checks.push({ name: fixture.name, evidence_kind: 'synthetic_browser_response', server_mutated: false, passed: true, screenshot: name });
    } finally { await context.close(); }
  }
}
try {
  await prepareOutput();
  check(await realpath(uiRoot) === uiRoot, 'ui_root_not_regular');
  check((await lstat(join(uiRoot, 'web/src/HostResources.tsx'))).isFile(), 'new_host_resources_source_missing');
  for (const source of ['scripts/verify-host-resources.mjs', 'web/src/App.tsx', 'web/src/HostResources.tsx', 'web/src/host-resources.css', 'web/src/lib/api.ts', 'web/dist/index.html']) {
    const sourceRoot = source.startsWith('scripts/') ? root : uiRoot;
    try { report.sources[source] = digest(await readFile(join(sourceRoot, source))); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const server = await getServer(origin); serverContract(server);
  report.initial_sample = { sampled_at: server.sampled_at, collector: server.collector.name, storage_available: server.storage.available, network_available: server.network.available, volume_count: server.storage.disks.length, history_count: server.history.length };
  const env = {};
  for (const key of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'LOCALAPPDATA', 'USERPROFILE']) if (process.env[key] !== undefined) env[key] = process.env[key];
  browser = await chromium.launch({ headless: true, env });
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await viewport(origin, width, theme);
  await synthetic(server);
  if (publicOrigin) for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) await viewport(publicOrigin, width, theme, true);
  phase = 'source_consistency';
  for (const [source, before] of Object.entries(report.sources)) check(digest(await readFile(join(source.startsWith('scripts/') ? root : uiRoot, source))) === before, 'source_changed_during_qa');
  report.public_preview_checked = Boolean(publicOrigin); report.passed = true;
} catch (error) {
  report.passed = false; report.failure = { phase, code: error.checkCode || 'bounded_browser_step_failed' }; process.exitCode = 1;
} finally {
  await browser?.close();
  try { await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n'); } catch { process.exitCode = 1; }
  console.log(JSON.stringify({ passed: report.passed, failure: report.failure, evidence: relative(root, join(output, 'report.json')).replaceAll('\\', '/'), public_preview_checked: report.public_preview_checked || false }));
}
