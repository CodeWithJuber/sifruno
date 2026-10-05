import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { mkdir, writeFile, readFile, stat } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { brandServer } from './brand-server.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = join(root, 'artifacts/brand');
await mkdir(output, { recursive: true });
const server = brandServer();
await new Promise((yes, no) => { server.once('error', no); server.listen(0, '127.0.0.1', yes); });
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true });
const results = [];
try {
  for (const [label, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
    const context = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 1, permissions: ['clipboard-read', 'clipboard-write'] });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('response', r => { if (r.status() >= 400) errors.push(`${r.status()} ${new URL(r.url()).pathname}`); });
    await page.goto(origin, { waitUntil: 'networkidle' });
    await page.evaluate(() => document.fonts.ready);
    assert.equal(await page.title(), 'Sifruno — Brand identity');
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${label}: overflow`);
    assert(await page.evaluate(() => [...document.images].every(img => img.complete && img.naturalWidth > 0)), `${label}: missing image`);
    // Check every actual download and manifest icon, not just image loads.
    for (const url of await page.locator('a[download]').evaluateAll(links => links.map(link => link.href))) {
      const response = await context.request.get(url); assert.equal(response.status(), 200, `${label}: ${url}`);
    }
    const manifestResponse = await context.request.get(`${origin}/assets/brand/site.webmanifest`);
    for (const icon of (await manifestResponse.json()).icons) {
      assert.equal((await context.request.get(`${origin}/assets/brand/${icon.src}`)).status(), 200);
    }
    await page.screenshot({ path: join(output, `${label}-light.png`), fullPage: true });
    await page.getByRole('button', { name: 'Teal' }).click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), '#087F6F');
    await page.waitForFunction(() => document.getElementById('status').textContent === '');
    await page.getByRole('button', { name: 'Dark view' }).click();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    assert.equal(await page.getByRole('button', { name: 'Light view' }).getAttribute('aria-pressed'), 'true');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Shift+Tab');
    assert(await page.getByRole('button', { name: 'Light view' }).evaluate(el => getComputedStyle(el).outlineStyle !== 'none'), 'visible keyboard focus');
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: join(output, `${label}-dark.png`), fullPage: true });
    await page.getByRole('button', { name: 'Light view' }).press('Enter');
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
    assert.deepEqual(errors, [], `${label}: browser errors`);
    results.push({ viewport: label, width, assets: 'loaded', downloadLinks: 'pass', overflow: 'none', themeToggle: 'pass', colorCopy: 'pass', keyboardFocus: 'pass', browserErrors: 0 });
    await context.close();
  }
  const denied = await fetch(`${origin}/config/baseline.json`);
  assert.equal(denied.status, 404, 'preview must not expose project config');
  const method = await fetch(origin, { method: 'POST' }); assert.equal(method.status, 405);
  const extracted = JSON.parse((await readFile(join(root, '.cache/brand-package-review/current.json'), 'utf8')).replace(/^\uFEFF/, ''));
  const zip = await readFile(join(root, 'deliverables/sifruno-brand-kit.zip'));
  assert.equal(createHash('sha256').update(zip).digest('hex'), extracted.sha256, 'package changed: run scripts/package-brand.ps1');
  const fileContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const filePage = await fileContext.newPage();
  await filePage.goto(pathToFileURL(join(extracted.path, 'assets/brand/index.html')).href, { waitUntil: 'load' });
  await filePage.evaluate(() => document.fonts.ready);
  assert(await filePage.locator('#kit-download').isHidden(), 'archive self-download must be hidden');
  assert(await filePage.evaluate(() => [...document.images].every(img => img.complete && img.naturalWidth > 0)), 'archive images missing');
  assert(await filePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'archive overflow');
  for (const url of await filePage.locator('a[download]:visible').evaluateAll(links => links.map(link => link.href))) {
    assert((await stat(fileURLToPath(url))).isFile(), `archive download missing: ${url}`);
  }
  await filePage.getByRole('button', { name: 'Dark view' }).click();
  assert.equal(await filePage.locator('html').getAttribute('data-theme'), 'dark');
  await fileContext.close();
  await writeFile(join(output, 'browser-check.json'), JSON.stringify({ results, exposureCheck: 'pass', extractedArchive: 'pass', packageSha256: extracted.sha256 }, null, 2) + '\n');
  console.log(`PASS: desktop 1440px and mobile 390px, light/dark screenshots, real downloads, color copy, keyboard theme control, local assets, no overflow or browser errors; extracted ZIP preview and links.`);
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}
