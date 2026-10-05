import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile, realpath, lstat } from 'node:fs/promises';
import { dirname, extname, join, relative, resolve, sep, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'web', 'dist');
const runId = new Date().toISOString().replace(/[-:.Z]/g, '') + '-' + randomUUID().slice(0, 8);
const output = join(root, 'artifacts', 'accounts-ui', runId);
const syntheticKey = 'synthetic-only-operator-key';
const syntheticCsrf = 'synthetic-only-csrf-token';
const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { checkCode: code }); };
const iso = () => new Date().toISOString();
let phase = 'setup', server, browser;
const contexts = [];
const report = {
  schema_version: 1,
  evidence_kind: 'isolated_synthetic_route_fixture_browser_qa',
  checked_at: iso(),
  fixture_only: true,
  main_state_mutated: false,
  linux_actions_verified: false,
  public_preview: {},
  workflows: {},
  viewports: [],
};

function envPath(name) {
  return Object.entries(process.env).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
}

async function makeOutputDirectory() {
  const rel = relative(root, output);
  check(rel && !isAbsolute(rel) && rel.split(sep).every((part) => part && part !== '..'), 'output_path');
  const expected = await realpath(root);
  await mkdir(join(root, 'artifacts'), { recursive: true });
  const parent = await realpath(join(root, 'artifacts'));
  check(parent.startsWith(expected + sep), 'artifact_parent');
  await mkdir(join(root, 'artifacts', 'accounts-ui'), { recursive: true });
  const base = await realpath(join(root, 'artifacts', 'accounts-ui'));
  check(base.startsWith(expected + sep), 'artifact_base');
  await mkdir(output);
  const stat = await lstat(output);
  check(stat.isDirectory() && !stat.isSymbolicLink() && await realpath(output) === output, 'artifact_output');
}

function mockAccount(overrides = {}) {
  return {
    id: 'a'.repeat(32), username: 'alice', domain: 'example.test',
    home: '/home/alice', public_html: '/home/alice/public_html',
    state: 'active', uid: 1001, gid: 1001, revision: 3,
    created_at: '2026-10-01T10:00:00Z', updated_at: '2026-10-02T11:00:00Z',
    ...overrides,
  };
}

function platformFixture() {
  return { os: 'windows', arch: 'amd64', os_name: 'Windows fixture', mode: 'control-plane', control_plane_supported: true, hosting_runtime: 'unverified', compatibility_verified: false, profiles: [] };
}

function statusFixture() {
  return { product: 'Sifruno', stage: 'local', ready: false, reference: { family: 'fixture', documentation_version: '0', exact_build: 'synthetic', os: 'fixture', artifact_sha256: '0'.repeat(64), licensed_reference_verified: false }, inventory_complete: true, total: 0, passed: 0, untested: 0, blockers: [], entries: [], ai_monthly_cap_usd_micros: 0, pilot_accounts: 0 };
}

function serverFixture() {
  const measurement = (extra = {}) => ({ available: false, reason: 'synthetic fixture', ...extra });
  return {
    sampled_at: iso(), os: 'windows', arch: 'amd64',
    collector: { name: 'fixture', version: '1', interval_seconds: 5, history_limit: 60, status: 'unavailable', reasons: ['synthetic fixture'] },
    cpu: measurement({ usage_percent: 1, logical_cores: 2, physical_cores: 1, model: 'fixture' }),
    memory: measurement({ total_bytes: 1024, used_bytes: 512, available_bytes: 512, used_percent: 50 }),
    storage: measurement({ total_bytes: 1024, used_bytes: 128, free_bytes: 896, used_percent: 12.5, disks: [] }),
    uptime: measurement({ seconds: 60 }), network: measurement({ bytes_received: 1, bytes_sent: 1, rx_bytes_per_second: 0, tx_bytes_per_second: 0 }), history: [],
  };
}

function servicesFixture() {
  return { sampled_at: iso(), available: true, reason: '', manager: 'windows-scm', truncated: false, items: [] };
}

function createScenario(mode) {
  const recovery = mode === 'recovery';
  const unavailable = mode === 'unavailable';
  const state = {
    mode,
    signedIn: false,
    accounts: mode === 'empty' ? [] : [mockAccount(recovery ? { state: 'recovery_required', revision: 7 } : {})],
    capability: unavailable
      ? { available: false, reason: 'linux_broker_not_configured', backend: 'windows', restrictions: ['domain_metadata_only', 'password_locked_and_nologin_in_all_states', 'suspension_is_pam_account_expiry_only', 'existing_processes_mail_web_and_databases_unaffected', 'no_delete_or_original_backup_restore', 'no_cpanel_compatibility_certification'] }
      : recovery
        ? { available: false, reason: 'managed_account_recovery_required', backend: 'linux-local', restrictions: ['domain_metadata_only', 'password_locked_and_nologin_in_all_states', 'suspension_is_pam_account_expiry_only', 'existing_processes_mail_web_and_databases_unaffected', 'no_delete_or_original_backup_restore', 'no_cpanel_compatibility_certification'] }
        : { available: true, reason: '', backend: 'linux-local', restrictions: ['domain_metadata_only', 'password_locked_and_nologin_in_all_states', 'suspension_is_pam_account_expiry_only', 'existing_processes_mail_web_and_databases_unaffected', 'no_delete_or_original_backup_restore', 'no_cpanel_compatibility_certification'] },
    sessionReads: 0,
    capabilityReads: 0,
    accountReads: 0,
    createCalls: 0,
    stateCalls: 0,
    timeoutAborts: 0,
    listFailure: mode === 'list-failure',
    unexpected: [],
  };
  return state;
}

function json(route, status, value) {
  return route.fulfill({ status, contentType: 'application/json; charset=utf-8', body: JSON.stringify(value) });
}

function apiHandler(state, route) {
  const request = route.request();
  const url = new URL(request.url());
  const path = url.pathname;
  const method = request.method();
  if (path === '/api/v1/status' && method === 'GET') return json(route, 200, statusFixture());
  if (path === '/api/v1/platform' && method === 'GET') return json(route, 200, platformFixture());
  if (path.startsWith('/api/v1/server') && method === 'GET') return json(route, 200, serverFixture());
  if (path === '/api/v1/services' && method === 'GET') return json(route, 200, servicesFixture());
  if (path === '/api/v1/session' && method === 'GET') {
    state.sessionReads++;
    return state.signedIn
      ? json(route, 200, { authenticated: true, csrf_token: syntheticCsrf, expires_at: '2026-10-06T00:00:00Z' })
      : json(route, 401, { authenticated: false, error: 'unauthorized' });
  }
  if (path === '/api/v1/session/login' && method === 'POST') {
    let body;
    try { body = request.postDataJSON(); } catch { body = {}; }
    if (body?.access_key !== syntheticKey) return json(route, 401, { error: 'unauthorized' });
    state.signedIn = true;
    return json(route, 200, { authenticated: true, csrf_token: syntheticCsrf, expires_at: '2026-10-06T00:00:00Z' });
  }
  if (path === '/api/v1/session/logout' && method === 'POST') {
    state.signedIn = false;
    return json(route, 200, { authenticated: false });
  }
  if (path === '/api/v1/accounts/capability' && method === 'GET') {
    state.capabilityReads++;
    if (!state.signedIn) return json(route, 401, { error: 'unauthorized' });
    return json(route, 200, state.capability);
  }
  if (path === '/api/v1/accounts' && method === 'GET') {
    state.accountReads++;
    if (!state.signedIn) return json(route, 401, { error: 'unauthorized' });
    if (state.listFailure && state.accountReads > 1) return json(route, 503, { error: 'broker_unavailable' });
    if (state.mode === 'state-conflict' && state.accountReads > 1) state.accounts[0].revision = 4;
    return json(route, 200, { items: state.accounts });
  }
  if (path === '/api/v1/accounts' && method === 'POST') {
    state.createCalls++;
    if (!state.signedIn || request.headers()['x-csrf-token'] !== syntheticCsrf) return json(route, 403, { error: 'unauthorized' });
    let body;
    try { body = request.postDataJSON(); } catch { body = {}; }
    if (state.mode === 'create-conflict-timeout') {
      if (state.createCalls === 1) return json(route, 409, { error: 'conflict' });
      state.timeoutAborts++;
      return route.abort('timedout');
    }
    if (state.mode === 'empty') {
      const created = mockAccount({ id: 'b'.repeat(32), username: body.username, domain: body.domain, home: `/home/${body.username}`, public_html: `/home/${body.username}/public_html`, uid: 1002, gid: 1002, revision: 1 });
      state.accounts.push(created);
      return json(route, 201, created);
    }
    return json(route, 409, { error: 'conflict' });
  }
  const stateMatch = path.match(/^\/api\/v1\/accounts\/([^/]+)\/state$/);
  if (stateMatch && method === 'POST') {
    state.stateCalls++;
    if (!state.signedIn || request.headers()['x-csrf-token'] !== syntheticCsrf) return json(route, 403, { error: 'unauthorized' });
    if (state.stateCalls === 1) return json(route, 409, { error: 'conflict' });
    let body;
    try { body = request.postDataJSON(); } catch { body = {}; }
    check(body.expected_revision === 4 && body.reason === 'Fixture state review', 'state_retry_payload');
    const updated = { ...state.accounts[0], state: body.state, revision: 5, updated_at: iso() };
    state.accounts[0] = updated;
    return json(route, 200, updated);
  }
  state.unexpected.push(`${method} ${path}`);
  return json(route, 404, { error: 'fixture_route_missing' });
}

function startServer() {
  const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.webmanifest': 'application/manifest+json' };
  server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url || '/', 'http://127.0.0.1');
      let name = decodeURIComponent(url.pathname);
      if (name === '/') name = '/index.html';
      const file = resolve(dist, '.' + name);
      const rel = relative(dist, file);
      if (!rel || isAbsolute(rel) || rel.split(sep).includes('..')) { response.writeHead(404).end(); return; }
      let bytes = await readFile(file);
      if (name === '/index.html' && url.searchParams.get('publicPreview') === '1') {
        let html = bytes.toString('utf8');
        html = html.replace('</head>', '<meta name="sifruno-public-preview" content="fixture"></head>');
        bytes = Buffer.from(html, 'utf8');
      }
      response.writeHead(200, { 'content-type': mime[extname(name).toLowerCase()] || 'application/octet-stream', 'cache-control': 'no-store', 'content-length': bytes.length });
      response.end(bytes);
    } catch {
      response.writeHead(404).end();
    }
  });
  return new Promise((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolvePromise(`http://127.0.0.1:${address.port}`);
    });
  });
}

async function contextFor(origin, state, theme, viewport, publicPreview = false) {
  const context = await browser.newContext({ viewport, colorScheme: theme, reducedMotion: 'reduce' });
  contexts.push(context);
  await context.addInitScript((selectedTheme) => localStorage.setItem('sifruno-theme', selectedTheme), theme);
  const health = { externalBlocked: 0, failedRequests: 0, pageErrors: 0, consoleErrors: 0, consoleKinds: [], httpErrors: [], accountCalls: [], expectedTimeouts: 0 };
  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== origin) { health.externalBlocked++; return route.abort('blockedbyclient'); }
    const privateAccountApi = /^\/api\/v1\/(session|accounts)(\/|$)/.test(url.pathname);
    if (privateAccountApi) {
      health.accountCalls.push(`${request.method()} ${url.pathname}`);
      if (publicPreview) return route.abort('blockedbyclient');
    }
    if (url.pathname.startsWith('/api/v1/')) {
      if (url.pathname.startsWith('/api/v1/accounts') && request.method() !== 'GET' && request.method() !== 'POST') return route.abort('blockedbyclient');
      if (url.pathname.startsWith('/api/v1/session') && !['GET', 'POST'].includes(request.method())) return route.abort('blockedbyclient');
      return apiHandler(state, route);
    }
    if (url.pathname.startsWith('/api/') && !['GET', 'HEAD'].includes(request.method())) return route.abort('blockedbyclient');
    return route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(12000); page.setDefaultNavigationTimeout(12000);
  page.on('pageerror', () => health.pageErrors++);
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    const text = message.text();
    const status = text.match(/server responded with a status of (\d{3})/);
    if (status && ['401', '409'].includes(status[1])) return;
    if (status?.[1] === '503' && state.listFailure) return;
    health.consoleErrors++;
    health.consoleKinds.push(status ? `response-${status[1]}` : text.includes('net::ERR_') ? 'network-error' : 'script-error');
  });
  page.on('response', (response) => {
    const path = new URL(response.url()).pathname;
    const expected = (response.status() === 401 && path === '/api/v1/session') ||
      (response.status() === 409 && (path === '/api/v1/accounts' || /\/api\/v1\/accounts\/[^/]+\/state$/.test(path))) ||
      (response.status() === 503 && state.listFailure && path === '/api/v1/accounts' && response.request().method() === 'GET');
    if (response.status() >= 400 && !expected) health.httpErrors.push({ path, status: response.status() });
  });
  page.on('requestfailed', (request) => {
    if (state.timeoutAborts > 0 && request.url().includes('/api/v1/accounts') && !['net::ERR_ABORTED'].includes(request.failure()?.errorText)) health.expectedTimeouts++;
    else if (request.failure()?.errorText !== 'net::ERR_ABORTED') health.failedRequests++;
  });
  return { context, page, health };
}

async function nav(page, id) {
  const target = page.getByTestId(`nav-${id}`);
  if (!await target.isVisible()) await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
  await target.click();
}

async function signIn(page) {
  await nav(page, 'accounts');
  const key = page.getByLabel('Operator access key', { exact: true });
  await key.waitFor();
  await key.fill(syntheticKey);
  await page.getByRole('button', { name: 'Sign in locally', exact: true }).click();
  await page.getByRole('button', { name: 'Sign out locally', exact: true }).waitFor();
  check(await page.evaluate((sentinel) => !document.body.innerText.includes(sentinel) && !Object.values(localStorage).some((value) => value.includes(sentinel)), syntheticKey), 'synthetic_key_persisted');
}

async function noOverflow(page) {
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1), 'horizontal_overflow');
}

async function screenshot(page, name) {
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.evaluate(() => new Promise((resolvePromise) => requestAnimationFrame(() => requestAnimationFrame(resolvePromise))));
  await noOverflow(page);
  await page.screenshot({ path: join(output, name), fullPage: true, timeout: 12000 });
}

function healthy(health, { allowTimeout = false } = {}) {
  check(health.externalBlocked === 0, 'external_blocked');
  check(health.failedRequests === 0, 'failed_request');
  check(health.pageErrors === 0, 'page_error');
  if (health.httpErrors.length) {
    const { path, status } = health.httpErrors[0];
    const category = path.startsWith('/assets/') ? 'asset' : path.startsWith('/brand/') ? 'brand' : path.startsWith('/api/') ? 'api' : 'route';
    const routeCode = path.replace(/[^a-z0-9]/gi, '_').slice(0, 48);
    check(false, `http_${status}_${category}_${routeCode}`);
  }
  const expectedTimeoutConsoleErrors = allowTimeout ? health.consoleKinds.filter((kind) => kind === 'network-error').length : 0;
  check(health.consoleErrors === expectedTimeoutConsoleErrors, health.consoleKinds[0] ? `console_${health.consoleKinds[0]}` : 'console_error');
  check(allowTimeout || health.expectedTimeouts === 0, 'unexpected_timeout');
}

async function viewports(origin) {
  for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) {
    phase = `viewport-${width}-${theme}`;
    const state = createScenario('populated');
    const run = await contextFor(origin, state, theme, { width, height: width === 390 ? 844 : 1000 });
    await run.page.goto(origin);
    await signIn(run.page);
    await run.page.getByTestId('account-details').waitFor();
    const productCopy = await run.page.locator('.accounts-view').innerText();
    check(!/domain_metadata_only|password_locked_and_nologin_in_all_states|suspension_is_pam_account_expiry_only|existing_processes_mail_web_and_databases_unaffected|no_delete_or_original_backup_restore|no_cpanel_compatibility_certification/.test(productCopy), 'capability_codes_rendered');
    check(await run.page.getByText('UID', { exact: true }).count() > 0, 'uid_visible');
    check(await run.page.getByText('GID', { exact: true }).count() > 0, 'gid_visible');
    const visual = await run.page.evaluate(() => ({
      dark: document.documentElement.classList.contains('dark'),
      background: getComputedStyle(document.querySelector('.account-capability')).backgroundColor,
      foreground: getComputedStyle(document.querySelector('.account-capability')).color,
    }));
    check(visual.dark === (theme === 'dark'), 'theme_not_applied');
    await screenshot(run.page, `${width}-${theme}-accounts.png`);
    healthy(run.health);
    report.viewports.push({ width, theme, screenshot: `${width}-${theme}-accounts.png`, overflow: false, theme_rendered: visual });
    await run.context.close();
  }
}

async function workflowChecks(origin) {
  phase = 'empty-create';
  const emptyState = createScenario('empty');
  const empty = await contextFor(origin, emptyState, 'light', { width: 1440, height: 1000 });
  await empty.page.goto(origin); await signIn(empty.page);
  await empty.page.getByText('No Linux accounts have been created yet.', { exact: true }).waitFor();
  await empty.page.getByLabel('Username', { exact: true }).fill('mariam2');
  await empty.page.getByLabel('Domain', { exact: true }).fill('example.test');
  await empty.page.getByLabel('Reason', { exact: true }).fill('Initial account request');
  const createButton = empty.page.getByRole('button', { name: 'Create Linux account', exact: true });
  check(await createButton.isEnabled(), 'valid_create_disabled');
  await empty.page.getByLabel('Domain', { exact: true }).fill('BadDomain');
  check(await createButton.isDisabled(), 'invalid_domain_admitted');
  await empty.page.getByLabel('Domain', { exact: true }).fill('example.test');
  await createButton.click();
  await empty.page.getByTestId('account-details').getByRole('heading', { name: 'mariam2' }).waitFor();
  check(emptyState.createCalls === 1 && emptyState.accounts.length === 1, 'create_endpoint_not_used');
  check(emptyState.accountReads === 1 && emptyState.capabilityReads === 1, 'account_read_contract');
  healthy(empty.health);
  report.workflows.create = { created_via_post: true, invalid_domain_blocked: true, key_not_persisted: true, post_count: emptyState.createCalls };
  await empty.context.close();

  phase = 'state-conflict';
  const conflictState = createScenario('state-conflict');
  const conflict = await contextFor(origin, conflictState, 'dark', { width: 1440, height: 1000 });
  await conflict.page.goto(origin); await signIn(conflict.page);
  phase = 'state-dialog-open';
  await conflict.page.getByRole('button', { name: 'Suspend account', exact: true }).click();
  const dialog = conflict.page.getByRole('dialog', { name: 'Suspend this Linux account?', exact: true });
  await dialog.waitFor();
  phase = 'state-dialog-escape';
  await conflict.page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'hidden' });
  phase = 'state-dialog-reopen';
  await conflict.page.getByRole('button', { name: 'Suspend account', exact: true }).click();
  phase = 'state-dialog-submit-conflict';
  await conflict.page.getByLabel('Reason', { exact: true }).last().fill('Fixture state review');
  await conflict.page.getByRole('button', { name: 'Confirm suspension', exact: true }).click();
  phase = 'state-conflict-visible';
  await dialog.getByRole('alert').waitFor();
  check(await conflict.page.getByLabel('Reason', { exact: true }).last().inputValue() === 'Fixture state review', 'state_reason_lost_on_conflict');
  await screenshot(conflict.page, '1440-dark-state-conflict-dialog.png');
  phase = 'state-conflict-refresh-click';
  await dialog.getByRole('button', { name: 'Refresh accounts', exact: true }).click();
  phase = 'state-conflict-refresh-result';
  await conflict.page.getByText('current revision 4', { exact: false }).waitFor();
  check(await conflict.page.getByLabel('Reason', { exact: true }).last().inputValue() === 'Fixture state review', 'state_reason_lost_on_refresh');
  phase = 'state-conflict-reconfirm';
  await conflict.page.getByRole('button', { name: 'Confirm suspension', exact: true }).click();
  await conflict.page.getByText('alice is suspended.', { exact: true }).waitFor();
  check(conflictState.stateCalls === 2 && conflictState.accountReads === 2 && conflictState.accounts[0].state === 'suspended', 'state_revision_reconcile');
  healthy(conflict.health);
  report.workflows.state_conflict = { escape_closes_confirmation: true, reason_preserved: true, manual_refresh_updated_revision: true, manual_reconfirm_only: true, state_post_count: conflictState.stateCalls };
  await conflict.context.close();

  phase = 'timeout-no-retry';
  const timeoutState = createScenario('create-conflict-timeout');
  const timeout = await contextFor(origin, timeoutState, 'light', { width: 768, height: 1000 });
  await timeout.page.goto(origin); await signIn(timeout.page);
  await timeout.page.getByLabel('Username', { exact: true }).fill('sara2');
  await timeout.page.getByLabel('Domain', { exact: true }).fill('sara.example');
  await timeout.page.getByLabel('Reason', { exact: true }).fill('Reconcile uncertain result');
  await timeout.page.getByRole('button', { name: 'Create Linux account', exact: true }).click();
  await timeout.page.getByRole('alert').waitFor();
  check(await timeout.page.getByLabel('Username', { exact: true }).inputValue() === 'sara2' && await timeout.page.getByLabel('Reason', { exact: true }).inputValue() === 'Reconcile uncertain result', 'create_draft_lost_on_conflict');
  check(timeoutState.createCalls === 1, 'unexpected_create_retry_after_conflict');
  await timeout.page.getByRole('button', { name: 'Refresh accounts', exact: true }).click();
  await timeout.page.locator('.account-refresh-notice').waitFor({ state: 'hidden' });
  await timeout.page.locator('.account-busy').waitFor({ state: 'hidden' });
  check(await timeout.page.getByRole('button', { name: 'Create Linux account', exact: true }).isEnabled(), 'create_not_reenabled_after_manual_refresh');
  await timeout.page.getByRole('button', { name: 'Create Linux account', exact: true }).click();
  await timeout.page.getByText(/could not be confirmed/i).waitFor();
  await timeout.page.waitForTimeout(400);
  check(timeoutState.createCalls === 2 && timeoutState.timeoutAborts === 1, 'timeout_was_retried');
  check(await timeout.page.getByLabel('Username', { exact: true }).inputValue() === 'sara2' && await timeout.page.getByLabel('Reason', { exact: true }).inputValue() === 'Reconcile uncertain result', 'create_draft_lost_on_timeout');
  await timeout.page.getByRole('button', { name: 'Refresh accounts', exact: true }).click();
  await timeout.page.locator('.account-busy').waitFor({ state: 'hidden' });
  check(timeoutState.createCalls === 2, 'refresh_replayed_create');
  healthy(timeout.health, { allowTimeout: true });
  report.workflows.conflict_timeout = { draft_preserved: true, timeout_fixture: 'route-aborted-as-timeout', no_automatic_retry: true, no_refresh_replay: true, create_post_count: timeoutState.createCalls };
  await timeout.context.close();

  phase = 'recovery-only-list';
  const recoveryState = createScenario('recovery');
  const recovery = await contextFor(origin, recoveryState, 'light', { width: 1440, height: 1000 });
  await recovery.page.goto(origin); await signIn(recovery.page);
  await recovery.page.getByTestId('account-details').waitFor();
  check(await recovery.page.getByText('recovery required', { exact: true }).count() >= 1, 'recovery_identity_hidden');
  check(await recovery.page.getByRole('button', { name: 'Create Linux account', exact: true }).isDisabled(), 'recovery_create_not_blocked');
  check(await recovery.page.getByRole('button', { name: 'Suspend account', exact: true }).count() === 0, 'recovery_state_action_visible');
  check(recoveryState.accountReads === 1, 'recovery_list_not_loaded');
  await screenshot(recovery.page, '1440-light-recovery-only.png');
  healthy(recovery.health);
  report.workflows.recovery = { recovery_fixture: true, account_list_read: true, all_mutations_blocked: true, screenshot: '1440-light-recovery-only.png' };
  await recovery.context.close();

  phase = 'windows-unavailable';
  const unavailableState = createScenario('unavailable');
  const unavailable = await contextFor(origin, unavailableState, 'light', { width: 390, height: 844 });
  await unavailable.page.goto(origin); await signIn(unavailable.page);
  await unavailable.page.getByText(/currently has no configured broker/i).waitFor();
  check(!await unavailable.page.getByText('linux_broker_not_configured', { exact: false }).count() && !await unavailable.page.getByText('password_locked_and_nologin_in_all_states', { exact: false }).count(), 'capability_codes_rendered');
  check(await unavailable.page.getByRole('button', { name: 'Create Linux account', exact: true }).count() === 0, 'windows_create_panel_visible');
  check(unavailableState.accountReads === 0, 'windows_unavailable_accounts_list_requested');
  healthy(unavailable.health);
  report.workflows.unavailable = { reason_displayed: true, create_hidden: true, account_list_requests: unavailableState.accountReads };
  await unavailable.context.close();

  phase = 'list-refresh-fails-closed';
  const staleState = createScenario('list-failure');
  const stale = await contextFor(origin, staleState, 'light', { width: 768, height: 1000 });
  phase = 'list-failure-load';
  await stale.page.goto(origin); await signIn(stale.page);
  phase = 'list-failure-fill';
  await stale.page.getByLabel('Username', { exact: true }).fill('mariam2');
  await stale.page.getByLabel('Domain', { exact: true }).fill('mariam.example');
  await stale.page.getByLabel('Reason', { exact: true }).fill('Keep this draft after list failure');
  phase = 'list-failure-refresh';
  await stale.page.getByRole('button', { name: 'Refresh accounts', exact: true }).click();
  phase = 'list-failure-error-visible';
  await stale.page.getByText(/Linux account broker is unavailable/i).waitFor();
  phase = 'list-failure-details';
  check(await stale.page.getByTestId('account-details').getByRole('heading', { name: 'alice' }).count() === 1, 'list_failure_cleared_last_details');
  check(await stale.page.getByLabel('Username', { exact: true }).inputValue() === 'mariam2' && await stale.page.getByLabel('Reason', { exact: true }).inputValue() === 'Keep this draft after list failure', 'list_failure_draft_lost');
  phase = 'list-failure-controls';
  check(await stale.page.getByRole('button', { name: 'Create Linux account', exact: true }).isDisabled(), 'list_failure_create_not_blocked');
  check(await stale.page.getByRole('button', { name: 'Suspend account', exact: true }).isDisabled(), 'list_failure_state_not_blocked');
  phase = 'list-failure-request-submit';
  await stale.page.locator('form').filter({ has: stale.page.getByLabel('Username', { exact: true }) }).evaluate((form) => form.requestSubmit());
  check(staleState.createCalls === 0 && staleState.stateCalls === 0, 'list_failure_mutation_reachable');
  check(staleState.accountReads === 2, 'list_failure_refresh_contract');
  healthy(stale.health);
  report.workflows.list_failure = { refresh_returned_503: true, last_details_preserved: true, create_draft_preserved: true, create_and_state_mutations_blocked: true, create_post_count: staleState.createCalls, state_post_count: staleState.stateCalls };
  await stale.context.close();
}

async function publicPreviewCheck(origin) {
  phase = 'public-preview-exclusion';
  const state = createScenario('populated');
  const run = await contextFor(origin, state, 'light', { width: 1440, height: 1000 }, true);
  await run.page.goto(`${origin}/?publicPreview=1`);
  await run.page.getByTestId('server-overview').waitFor();
  check(await run.page.getByTestId('nav-accounts').count() === 0, 'public_accounts_nav_visible');
  check(run.health.accountCalls.length === 0, 'public_private_api_requested');
  await screenshot(run.page, '1440-light-public-preview.png');
  healthy(run.health);
  report.public_preview = { accounts_nav_absent: true, session_capability_and_account_requests: 0, screenshot: '1440-light-public-preview.png' };
  await run.context.close();
}

async function main() {
  await makeOutputDirectory();
  const indexStat = await lstat(join(dist, 'index.html'));
  check(indexStat.isFile() && !indexStat.isSymbolicLink() && indexStat.size > 0 && indexStat.size < (1 << 20), 'built_index_missing');
  const origin = await startServer();
  const childEnv = {};
  for (const name of ['PATH', 'TEMP', 'TMP', 'SYSTEMROOT', 'WINDIR', 'LOCALAPPDATA', 'USERPROFILE', 'PROGRAMFILES', 'PROGRAMFILES(X86)']) {
    const value = envPath(name);
    if (value) childEnv[name] = value;
  }
  try {
    browser = await chromium.launch({ headless: true, env: childEnv });
    await viewports(origin);
    await workflowChecks(origin);
    await publicPreviewCheck(origin);
    report.passed = true;
    report.screenshot_directory = relative(root, output).split(sep).join('/');
    await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    process.stdout.write(`${JSON.stringify({ passed: true, screenshot_directory: report.screenshot_directory, viewports: report.viewports.length, workflows: Object.keys(report.workflows), public_preview: report.public_preview })}\n`);
  } finally {
    for (const context of contexts) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
    await new Promise((resolvePromise) => server?.close(() => resolvePromise()));
  }
}

main().catch((error) => {
  const code = error && typeof error.checkCode === 'string' && /^[a-z0-9_-]+$/.test(error.checkCode) ? error.checkCode : 'flow_unexpected';
  process.stderr.write(`Accounts browser check failed during ${phase} [${code}].\n`);
  process.exitCode = 1;
});
