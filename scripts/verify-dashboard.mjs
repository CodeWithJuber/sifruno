// Read-only browser acceptance for the running source dashboard, not an archived package.
import { chromium } from 'playwright';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile, lstat, realpath } from 'node:fs/promises';
import { dirname, join, relative, resolve, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const origin = 'http://127.0.0.1:8080';
const hash = value => createHash('sha256').update(value).digest('hex');
const runId = new Date().toISOString().replace(/[-:.Z]/g, '') + '-' + randomUUID().slice(0, 8);
const reportRoot = join(root, 'artifacts/dashboard');
const output = join(reportRoot, runId);
const report = {
  schema_version: 1,
  evidence_kind: 'observed_running_source_browser_qa',
  checked_at: new Date().toISOString(),
  origin,
  browser: 'Playwright Chromium',
  browser_fallback_reason: 'In-app browser acquisition failed: Browser is not available: iab. The Browser plugin skill is absent.',
  archived_package_verified: false,
  compatibility_certified: false,
  paid_provider_calls: 0,
  server_store_mutations: 0,
  viewports: [],
  synthetic_contract_checks: [],
  sources: {},
};
let browser;
let phase = 'prepare';

function check(condition, code) {
  if (!condition) throw Object.assign(new Error(code), { checkCode: code });
}
async function regularDirectory(path) {
  const canonicalRoot = await realpath(root);
  const parts = relative(root, path).split(sep);
  check(parts.length > 0 && !parts.some(part => !part || part === '..') && !isAbsolute(relative(root, path)), 'report_path_escapes_workspace');
  let current = canonicalRoot;
  for (const part of parts) {
    current = join(current, part);
    try { await mkdir(current); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const info = await lstat(current);
    check(info.isDirectory() && !info.isSymbolicLink() && await realpath(current) === current, 'report_directory_not_regular');
  }
}
async function json(path) {
  const response = await fetch(origin + path, { signal: AbortSignal.timeout(10000), headers: { Accept: 'application/json' } });
  check(response.status === 200, 'live_api_http_' + response.status);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = '';
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      check(bytes <= 1048576, 'live_api_response_too_large');
      text += decoder.decode(chunk.value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } finally { await reader.cancel(); }
}
function inspectNoSensitiveFields(value) {
  const visit = (node, depth = 0) => {
    check(depth < 24, 'api_nested_too_deep');
    if (node && typeof node === 'object') for (const [key, entry] of Object.entries(node)) {
      check(!/^(argv|cmdline|command_line|environment|environ|env|password|token|secret|api_key|hostname|username|mountpoint|device|address|addresses)$/i.test(key), 'api_sensitive_field_present');
      visit(entry, depth + 1);
    }
  };
  visit(value);
}
function finiteNullable(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  return value === null || (typeof value === 'number' && Number.isFinite(value) && value >= minimum && value <= maximum);
}
function verifyServerContract(server) {
  inspectNoSensitiveFields(server);
  check(server.os === (process.platform === 'win32' ? 'windows' : process.platform) && Number.isFinite(Date.parse(server.sampled_at)), 'server_identity_or_timestamp_invalid');
  check(server.collector?.name === 'gopsutil/v4' && server.collector.interval_seconds === 5 && server.collector.history_limit === 120 && ['available', 'partial', 'unavailable'].includes(server.collector.status), 'collector_contract_invalid');
  for (const name of ['cpu', 'memory', 'storage', 'uptime', 'network']) {
    check(server[name] && typeof server[name].available === 'boolean' && typeof server[name].reason === 'string', 'component_availability_invalid');
  }
  for (const [component, fields] of Object.entries({ cpu: ['usage_percent'], memory: ['used_percent'], storage: ['used_percent'] })) {
    for (const field of fields) check(finiteNullable(server[component][field], 0, 100), 'metric_percent_invalid');
  }
  for (const [component, fields] of Object.entries({ cpu: ['logical_cores', 'physical_cores'], memory: ['total_bytes', 'used_bytes', 'available_bytes'], storage: ['total_bytes', 'used_bytes', 'free_bytes'], uptime: ['seconds'], network: ['bytes_received', 'bytes_sent', 'rx_bytes_per_second', 'tx_bytes_per_second'] })) {
    for (const field of fields) check(finiteNullable(server[component][field]), 'metric_counter_invalid');
    if (!server[component].available && component !== 'cpu') {
      check(fields.every(field => server[component][field] === null), 'unavailable_metric_uses_numeric_default');
    }
  }
  check(server.cpu.available || server.cpu.usage_percent === null, 'unavailable_cpu_uses_numeric_default');
  check(server.memory.available && server.memory.total_bytes > 0 && server.memory.used_bytes <= server.memory.total_bytes && server.memory.available_bytes <= server.memory.total_bytes, 'real_memory_observation_unavailable');
  check(Math.abs(server.memory.total_bytes - os.totalmem()) <= 4096, 'memory_total_differs_from_native_host');
  check(server.cpu.logical_cores === os.cpus().length, 'cpu_count_differs_from_native_host');
  check(server.uptime.available && Math.abs(server.uptime.seconds - os.uptime()) < 30, 'uptime_differs_from_native_host');
  check(server.storage.available && server.storage.total_bytes > 0 && Array.isArray(server.storage.disks) && server.storage.disks.length > 0, 'real_storage_observation_unavailable');
  for (const disk of server.storage.disks) {
    check(/^Volume \d+$/.test(disk.label) && typeof disk.id === 'string' && !/[\\/:]/.test(disk.id), 'storage_exposes_mount_or_device_path');
  }
  check(Array.isArray(server.history) && server.history.length > 0 && server.history.length <= 120, 'history_not_bounded_observed_samples');
  let prior = -Infinity;
  for (const sample of server.history) {
    const at = Date.parse(sample.sampled_at);
    check(Number.isFinite(at) && at > prior && at <= Date.parse(server.sampled_at), 'history_timestamp_invalid');
    prior = at;
    for (const key of ['cpu_usage_percent', 'memory_used_percent', 'storage_used_percent']) check(finiteNullable(sample[key], 0, 100), 'history_percentage_invalid');
    for (const key of ['network_rx_bytes_per_second', 'network_tx_bytes_per_second']) check(finiteNullable(sample[key]), 'history_rate_invalid');
  }
}
async function isolatedPage(viewport, theme, serverReplacement) {
  const context = await browser.newContext({ viewport, colorScheme: theme, reducedMotion: 'reduce' });
  await context.addInitScript(value => localStorage.setItem('sifruno-theme', value), theme);
  const health = { page_errors: 0, console_errors: 0, failed_requests: 0, http_errors: [], blocked_external: 0, mutation_requests: 0 };
  const observed = { server: null, services: null, server_requests: [] };
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== origin) { health.blocked_external++; return route.abort('blockedbyclient'); }
    if (!['GET', 'HEAD'].includes(request.method())) { health.mutation_requests++; return route.abort('blockedbyclient'); }
    if (url.pathname === '/api/v1/server' && serverReplacement) {
      return route.fulfill({ status: serverReplacement.status, contentType: 'application/json', body: JSON.stringify(serverReplacement.body) });
    }
    return route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(12000);
  page.setDefaultNavigationTimeout(15000);
  page.on('pageerror', () => health.page_errors++);
  page.on('console', message => { if (message.type() === 'error') health.console_errors++; });
  page.on('requestfailed', request => { if (request.failure()?.errorText !== 'net::ERR_ABORTED') health.failed_requests++; });
  page.on('response', async response => {
    const path = new URL(response.url()).pathname;
    if (response.status() >= 400 && !serverReplacement) health.http_errors.push({ path, status: response.status() });
    if (path === '/api/v1/server' && response.status() === 200) {
      try {
        observed.server = await response.json();
        observed.server_requests.push(new URL(response.url()).searchParams.get('range_seconds'));
      } catch { health.page_errors++; }
    }
    if (path === '/api/v1/services' && response.status() === 200) {
      try { observed.services = await response.json(); } catch { health.page_errors++; }
    }
  });
  return { context, page, health, observed };
}
async function noOverflow(page, code) {
  const measured = await page.evaluate(() => ({ width: innerWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
  check(measured.document <= measured.width + 1 && measured.body <= measured.width + 1, code + '_document_overflow');
}
async function accessibilityBasics(page) {
  check(await page.locator('main').count() === 1, 'main_landmark_count');
  check(await page.locator('h1:visible').count() === 1, 'visible_h1_count');
  const problems = await page.evaluate(() => {
    const visible = element => element.getClientRects().length > 0;
    const named = element => Boolean(element.getAttribute('aria-label') || element.getAttribute('aria-labelledby') || element.labels?.length || element.textContent.trim());
    return {
      unnamed_controls: [...document.querySelectorAll('button,input,select,textarea')].filter(visible).filter(element => !named(element)).length,
      missing_image_alt: [...document.images].filter(visible).filter(element => !element.hasAttribute('alt')).length,
      missing_images: [...document.images].filter(visible).filter(element => !element.complete || element.naturalWidth === 0).length,
    };
  });
  check(Object.values(problems).every(value => value === 0), 'basic_accessible_names_or_images');
}
async function navigation(page, label) {
  const labels = { Overview: ['overview', 'Server overview'], Services: ['services', 'Services'], Compatibility: ['evidence', 'Compatibility evidence'], 'Change trail': ['trail', 'Change trail'], 'AI budget': ['budget', 'AI spending controls'], Platforms: ['platform', 'Platform profiles'] };
  const [id, heading] = labels[label];
  const item = page.getByTestId('nav-' + id);
  if (!await item.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
  await item.click();
  check(await page.getByRole('heading', { level: 1, name: heading, exact: true }).isVisible(), 'navigation_not_selected');
}
async function healthy(health, code) {
  check(health.page_errors === 0 && health.console_errors === 0 && health.failed_requests === 0 && health.http_errors.length === 0 && health.blocked_external === 0 && health.mutation_requests === 0, code + '_browser_health');
}
async function waitObserved(read, code) {
  const deadline = Date.now() + 12000;
  while (!read() && Date.now() < deadline) await new Promise(yes => setTimeout(yes, 25));
  check(Boolean(read()), code);
}
async function metricMatches(page, id, expected, unit) {
  const value = page.getByTestId(id);
  const text = (await value.innerText()).trim();
  if (expected === null) {
    check(!/\d/.test(text) && /unavailable|warming|collecting|—|n\/a/i.test(text), id + '_null_was_rendered_as_number');
    check(await value.getAttribute('data-metric-value') === 'null', id + '_null_measurement_lost');
    return;
  }
  check(Number(await value.getAttribute('data-metric-value')) === expected, id + '_raw_measurement_differs_from_sample');
  if (unit === 'percent') {
    const displayed = id === 'cpu-usage' ? text : await value.evaluate(element => element.closest('.metric-card').textContent);
    const match = displayed.replaceAll(',', '').match(/(\d+(?:\.\d+)?)\s*%/);
    check(match && Math.abs(Number(match[1]) - expected) <= 0.11, id + '_differs_from_observed_sample');
  }
}
async function syntheticContracts(server) {
  const unavailable = structuredClone(server);
  unavailable.collector.status = 'unavailable';
  unavailable.collector.reasons = ['Browser-only unavailable contract fixture'];
  unavailable.history = [];
  for (const component of ['cpu', 'memory', 'storage', 'uptime', 'network']) {
    unavailable[component].available = false;
    unavailable[component].reason = 'Browser-only unavailable contract fixture';
    for (const field of Object.keys(unavailable[component])) {
      if (!['available', 'reason', 'disks'].includes(field)) unavailable[component][field] = null;
    }
  }
  unavailable.storage.disks = [];
  for (const fixture of [
    { name: 'null-metrics', status: 200, body: unavailable },
    { name: 'http-error', status: 503, body: { error: 'browser_only_qa_fixture' } },
    { name: 'invalid-contract', status: 200, body: { ...server, memory: { ...server.memory, total_bytes: 'invalid' } } },
  ]) {
    phase = 'synthetic browser-only ' + fixture.name;
    const { context, page, health } = await isolatedPage({ width: 390, height: 844 }, 'light', fixture);
    try {
      await page.goto(origin, { waitUntil: 'networkidle' });
      if (fixture.name === 'null-metrics') {
        await page.getByTestId('server-overview').waitFor();
        for (const id of ['cpu-usage', 'memory-usage', 'storage-usage', 'server-uptime']) await metricMatches(page, id, null);
        check(await page.getByText('Waiting for the first measurements', { exact: true }).count() >= 1 && (await page.getByTestId('cpu-chart').locator('path').getAttribute('d')).trim() === '', 'null_cpu_chart_missing_empty_state');
      } else {
        await page.getByRole('alert').first().waitFor();
        check(await page.getByTestId('memory-usage').count() === 0, 'invalid_data_retains_live_metric');
      }
      await noOverflow(page, 'synthetic_' + fixture.name);
      check(health.page_errors === 0 && health.mutation_requests === 0 && health.blocked_external === 0, 'synthetic_contract_runtime_error');
      await page.screenshot({ path: join(output, 'synthetic-' + fixture.name + '.png'), fullPage: true });
      report.synthetic_contract_checks.push({ evidence_kind: 'synthetic_browser_response', name: fixture.name, passed: true, metric_zero_fallback: false, server_mutated: false, screenshot: 'synthetic-' + fixture.name + '.png' });
    } finally { await context.close(); }
  }
}
async function publicPrivacy() {
  phase = 'public preview privacy';
  const publicOrigin = 'http://127.0.0.1:8081';
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, colorScheme: 'light' });
  const requested = [];
  try {
    await context.route('**/*', route => {
      const request = route.request();
      const url = new URL(request.url());
      check(url.origin === publicOrigin && ['GET', 'HEAD'].includes(request.method()), 'public_page_external_or_mutating_request');
      requested.push(url.pathname);
      return route.continue();
    });
    const page = await context.newPage();
    await page.goto(publicOrigin, { waitUntil: 'networkidle', timeout: 15000 });
    await page.getByTestId('server-overview').waitFor({ timeout: 12000 });
    check(await page.locator('meta[name="sifruno-public-preview"]').count() === 1, 'public_preview_meta_missing');
    check(await page.getByTestId('nav-trail').count() === 0 && await page.getByTestId('nav-budget').count() === 0, 'public_preview_shows_private_tools');
    check(!requested.some(path => path === '/api/v1/trail' || path === '/api/v1/budget'), 'public_preview_fetches_private_tools');
    const privateStatuses = {};
    for (const path of ['/api/v1/trail', '/api/v1/budget']) {
      const response = await fetch(publicOrigin + path, { signal: AbortSignal.timeout(10000) });
      check([403, 404].includes(response.status), 'public_proxy_exposes_private_api');
      privateStatuses[path] = response.status;
      await response.body?.cancel();
    }
    await noOverflow(page, 'public_preview');
    await page.screenshot({ path: join(output, 'public-preview-390-light.png'), fullPage: true });
    report.public_preview = { origin: publicOrigin, private_tools_hidden: true, private_api_not_requested_by_page: true, private_api_statuses: privateStatuses, wan_reachability_verified: false, screenshot: 'public-preview-390-light.png' };
  } finally { await context.close(); }
}
async function liveViewport(viewport, theme) {
  const { context, page, health, observed } = await isolatedPage(viewport, theme);
  const label = `${viewport.width}-${theme}`;
  try {
    phase = 'live ' + label;
    const response = await page.goto(origin, { waitUntil: 'networkidle' });
    check(response?.status() === 200, 'page_not_http_200');
    check(page.url() === origin + '/' && /Sifruno/i.test(await page.title()), 'page_identity');
    check(response.headers()['content-security-policy']?.includes("script-src 'self'"), 'csp_header_missing');
    await page.getByTestId('server-overview').waitFor();
    await waitObserved(() => observed.server, 'server_response_not_observed');
    const renderedAt = await page.getByTestId('server-overview').getAttribute('data-sampled-at');
    check(renderedAt === observed.server.sampled_at, 'rendered_sample_timestamp_does_not_match_response');
    check(await page.locator('html').evaluate(element => element.classList.contains('dark')) === (theme === 'dark'), 'theme_does_not_match_selection');
    check(await page.locator('vite-error-overlay, nextjs-portal').count() === 0, 'framework_error_overlay');
    await page.evaluate(() => document.fonts.ready);
    await accessibilityBasics(page);
    await noOverflow(page, label + '_overview');
    await metricMatches(page, 'cpu-usage', observed.server.cpu.usage_percent, 'percent');
    await metricMatches(page, 'memory-usage', observed.server.memory.used_percent, 'percent');
    await metricMatches(page, 'storage-usage', observed.server.storage.used_percent, 'percent');
    await metricMatches(page, 'server-uptime', observed.server.uptime.seconds, 'seconds');
    const uptimeText = (await page.getByTestId('server-uptime').innerText()).trim();
    check(/\d+[dhms]/.test(uptimeText), 'uptime_not_rendered_in_units');
    check(await page.getByTestId('cpu-chart').isVisible() && await page.getByTestId('memory-chart').isVisible(), 'real_charts_not_rendered');
    check(await page.getByRole('button', { name: /create account|add domain|backup now|restart service|stop service|deploy site/i }).count() === 0, 'unimplemented_hosting_action_present');
    await page.screenshot({ path: join(output, label + '-overview.png'), fullPage: true });
    for (const seconds of [300, 600, 60]) {
      const period = page.getByRole('radiogroup', { name: 'Chart time range', exact: true }).locator(`[data-value="${seconds}"]`);
      await period.click();
      await waitObserved(() => observed.server_requests.some(range => range === String(seconds)), 'chart_range_request_missing');
      check(await period.getAttribute('aria-checked') === 'true', 'chart_range_not_selected');
    }
    await navigation(page, 'Services');
    await page.getByTestId('service-inventory').waitFor();
    await waitObserved(() => observed.services, 'services_response_not_observed');
    await accessibilityBasics(page);
    const search = page.getByRole('searchbox', { name: 'Search services', exact: true });
    await search.fill('sifruno-no-service-matches-qa');
    check(await page.getByText('No matching services', { exact: true }).isVisible(), 'service_search_did_not_filter');
    await search.fill('');
    if (observed.services.items.length) {
      const first = observed.services.items[0];
      await search.fill(first.name);
      check(await page.getByText(first.display_name || first.name, { exact: true }).count() >= 1, 'service_search_cannot_find_live_service');
      await search.fill('');
    }
    const stateFilter = page.getByRole('radiogroup', { name: 'Service state', exact: true });
    for (const state of ['running', 'stopped']) {
      await stateFilter.locator(`[data-value="${state}"]`).click();
      const states = await page.locator('.service-table tbody tr .service-state').allTextContents();
      check(states.every(value => value.trim().toLowerCase() === state), 'service_state_filter_did_not_filter');
      check(states.length > 0 || !observed.services.items.some(service => service.status === state), 'service_filter_hides_real_matching_services');
    }
    await stateFilter.locator('[data-value="all"]').click();
    const details = page.getByRole('button', { name: /^Details for / }).first();
    if (await details.count()) {
      await details.click();
      check(await details.getAttribute('aria-expanded') === 'true' && await page.locator('.service-detail').isVisible(), 'read_only_service_details_not_expanded');
      await page.getByRole('button', { name: 'Close service details', exact: true }).click();
      check(await page.locator('.service-detail').count() === 0, 'read_only_service_details_not_closed');
    }
    const next = page.getByRole('button', { name: 'Next services', exact: true });
    if (await next.count() && await next.isEnabled()) {
      const before = await page.locator('.service-table tbody').innerText();
      await next.click();
      check(await page.locator('.service-table tbody').innerText() !== before, 'service_pagination_did_not_change_rows');
      await page.getByRole('button', { name: 'Previous services', exact: true }).click();
    }
    await noOverflow(page, label + '_services');
    await page.screenshot({ path: join(output, label + '-services.png'), fullPage: true });
    for (const name of ['Compatibility', 'Change trail', 'AI budget', 'Platforms', 'Overview']) {
      await navigation(page, name);
      await noOverflow(page, label + '_' + name.replaceAll(' ', '_'));
    }
    const oldRequests = observed.server_requests.length;
    await page.getByRole('button', { name: 'Refresh server data', exact: true }).click();
    await waitObserved(() => observed.server_requests.length > oldRequests, 'refresh_did_not_fetch_live_server');
    await page.getByTestId('server-overview').waitFor();
    const toggle = page.getByRole('button', { name: `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`, exact: true });
    if (!await toggle.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
    await toggle.focus();
    await toggle.press('Enter');
    check(await page.locator('html').evaluate(element => element.classList.contains('dark')) !== (theme === 'dark'), 'keyboard_theme_toggle_did_not_work');
    await healthy(health, label);
    report.viewports.push({ ...viewport, theme, meaningful_overview: true, metrics_match_observed_response: true, service_search: true, service_state_filter: true, service_details: true, service_pagination: true, chart_ranges: [60, 300, 600], refresh: true, section_navigation: true, keyboard_theme_toggle: true, basic_accessible_names: true, document_overflow: false, browser_errors: 0, screenshots: [label + '-overview.png', label + '-services.png'] });
  } finally { await context.close(); }
}

async function main() {
  await regularDirectory(output);
  for (const source of ['web/src/App.tsx', 'web/src/Dashboard.tsx', 'web/src/Tools.tsx', 'web/src/lib/api.ts', 'web/src/index.css', 'web/dist/index.html', 'internal/api/api.go', 'internal/serverinfo/types.go', 'internal/serverinfo/collector.go', 'internal/serverinfo/native.go', 'internal/serverinfo/sanitize.go', 'internal/serverinfo/services_windows.go']) {
    try { report.sources[source] = hash(await readFile(join(root, source))); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  phase = 'live contracts';
  const server = await json('/api/v1/server');
  const services = await json('/api/v1/services');
  verifyServerContract(server); inspectNoSensitiveFields(services);
  check(services.available === true && Array.isArray(services.items) && services.items.length <= 256 && ['windows-scm', 'systemd'].includes(services.manager) && typeof services.truncated === 'boolean', 'real_services_contract_unavailable');
  for (const service of services.items) {
    check(Object.keys(service).every(key => ['id', 'name', 'display_name', 'status', 'start_type'].includes(key)), 'service_exposes_unapproved_fields');
    check(Object.values(service).every(value => typeof value === 'string' && value.length <= 512), 'service_field_unbounded_or_invalid');
    check(!/_[a-f0-9]{4,}$/i.test(service.name) && !/_[a-f0-9]{4,}$/i.test(service.display_name), 'service_instance_identifier_exposed');
  }
  check(services.items.every(service => typeof service.id === 'string' && /^[a-f0-9]{32}$/.test(service.id)) && new Set(services.items.map(service => service.id)).size === services.items.length, 'service_identity_not_opaque_and_unique');
  report.collector = { name: server.collector.name, version: server.collector.version, status: server.collector.status };
  report.services = { available: services.available, manager: services.manager, count: services.items.length, truncated: services.truncated };
  report.native_observation = { os: process.platform, logical_cores: os.cpus().length, memory_total_bytes: os.totalmem(), uptime_seconds: Math.round(os.uptime()) };
  const browserEnv = {};
  for (const name of ['SystemRoot', 'WINDIR', 'PATH', 'Path', 'TEMP', 'TMP', 'LOCALAPPDATA', 'USERPROFILE', 'HOME']) {
    if (typeof process.env[name] === 'string') browserEnv[name] = process.env[name];
  }
  browser = await chromium.launch({ headless: true, env: browserEnv });
  for (const viewport of [{ width: 390, height: 844 }, { width: 768, height: 1024 }, { width: 1440, height: 1000 }]) {
    for (const theme of ['light', 'dark']) await liveViewport(viewport, theme);
  }
  await syntheticContracts(server);
  await publicPrivacy();
  phase = 'source consistency';
  for (const [source, digest] of Object.entries(report.sources)) {
    check(hash(await readFile(join(root, source))) === digest, 'source_changed_during_qa');
  }
}

try {
  await main();
  report.passed = true;
  await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  await writeFile(join(reportRoot, 'latest.json'), JSON.stringify({ run_id: runId, report: relative(root, join(output, 'report.json')).replaceAll('\\', '/'), sha256: hash(await readFile(join(output, 'report.json'))), passed: true }, null, 2) + '\n');
  console.log('Dashboard QA passed. Evidence: artifacts/dashboard/' + runId + '/report.json');
} catch (error) {
  report.passed = false;
  report.failure = { phase, code: error.checkCode ?? error.name ?? 'qa_failure' };
  try { await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n'); } catch { }
  console.error('Dashboard QA failed during ' + phase + ': ' + report.failure.code + '. Raw diagnostic data is suppressed.');
  process.exitCode = 1;
} finally {
  await browser?.close();
}
