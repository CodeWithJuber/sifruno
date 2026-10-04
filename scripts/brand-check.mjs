import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import sharp from 'sharp';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dir = join(root, 'assets/brand');
const manifest = JSON.parse(await readFile(join(dir, 'asset-manifest.json'), 'utf8'));
const dimensions = {
  'favicons/favicon-16.png': [16, 16], 'favicons/favicon-32.png': [32, 32],
  'favicons/favicon-48.png': [48, 48], 'favicons/apple-touch-icon.png': [180, 180],
  'icons/sifruno-app-icon-192.png': [192, 192], 'icons/sifruno-app-icon-512.png': [512, 512],
  'icons/sifruno-app-icon-1024.png': [1024, 1024], 'icons/sifruno-maskable-512.png': [512, 512],
  'social/sifruno-avatar.png': [1024, 1024], 'social/sifruno-cover.png': [1200, 630],
  'social/sifruno-v2-comparison.png': [1200, 800], 'social/sifruno-v3-typography.png': [1200, 800],
};
for (const file of manifest.files) {
  const data = await readFile(join(dir, file.path));
  assert.equal(data.length, file.bytes, `size: ${file.path}`);
  assert.equal(createHash('sha256').update(data).digest('hex'), file.sha256, `hash: ${file.path}`);
  if (dimensions[file.path]) {
    const meta = await sharp(data).metadata();
    assert.deepEqual([meta.width, meta.height], dimensions[file.path], `dimensions: ${file.path}`);
  }
  if (file.path.startsWith('logos/') && file.path.endsWith('.svg')) {
    const source = data.toString();
    assert(!/<text\b|<script\b|<image\b|<foreignObject\b|url\(/i.test(source), `self-contained logo: ${file.path}`);
    assert(source.includes('<title'), `accessible title: ${file.path}`);
    const png = await sharp(join(dir, file.path.replace(/\.svg$/, '.png'))).metadata().catch(() => null);
    if (png) {
      const vector = await sharp(data).metadata();
      assert.deepEqual([png.width, png.height], [vector.width * 3, vector.height * 3], `vector/PNG export scale: ${file.path}`);
    }
  }
}
const display = JSON.parse(await readFile(join(dir, 'lettering/sifruno-display.json'), 'utf8'));
assert.equal(display.glyphs.map(g => g.letter).join(''), 'Sifruno', 'custom lettering spelling');
const standaloneS = (await readFile(join(dir, 'marks/sifruno-mark-primary.svg'), 'utf8')).match(/ d="([^"]+)"/)[1];
assert.equal(display.glyphs[0].path, standaloneS, 'custom lettering must retain the original S');
assert.equal(manifest.identity?.status, 'approved');
for (const name of ['primary', 'on-dark', 'mono-ink', 'mono-white']) {
  const source = ['primary', 'on-dark'].includes(name) ? `sifruno-v3-sifr-uno-${name}` : `sifruno-v3-${name}`;
  assert.deepEqual(await readFile(join(dir, `logos/sifruno-logo-${name}.svg`)), await readFile(join(dir, `logos/${source}.svg`)), 'canonical logo must be the approved V3');
}
for (const split of ['sifr-uno', 'sif-runo']) {
  const vector = await readFile(join(dir, `logos/sifruno-v3-${split}-primary.svg`), 'utf8');
  const fills = [...vector.matchAll(/<path fill="([^"]+)"/g)].map(m => m[1]);
  assert.equal(fills.length, 7, 'one shape per logo letter');
  assert.deepEqual([...new Set(fills)].sort(), ['#087F6F', '#142F35']);
  assert.equal(fills.filter(fill => fill === '#087F6F').length, split === 'sifr-uno' ? 4 : 3);
}
const ico = await readFile(join(dir, 'favicons/favicon.ico'));
assert.equal(ico.readUInt16LE(0), 0); assert.equal(ico.readUInt16LE(2), 1); assert.equal(ico.readUInt16LE(4), 3);
for (let i = 0; i < 3; i++) {
  const p = 6 + i * 16;
  const size = ico[p]; const length = ico.readUInt32LE(p + 8); const offset = ico.readUInt32LE(p + 12);
  assert(offset + length <= ico.length);
  const frame = await sharp(ico.subarray(offset, offset + length)).metadata();
  assert.equal(frame.width, size); assert.equal(frame.height, size);
}
// The actual maskable artwork must fit inside the central 80%-diameter circle.
const mask = await sharp(join(dir, 'icons/sifruno-maskable-512.png')).removeAlpha().raw().toBuffer();
let brandPixels = 0;
for (let y = 0; y < 512; y++) for (let x = 0; x < 512; x++) {
  const n = (y * 512 + x) * 3;
  if (mask[n] > 90 && mask[n + 1] > 130 && mask[n + 2] > 110) {
    brandPixels++;
    assert(Math.hypot(x + .5 - 256, y + .5 - 256) <= 204.8, 'maskable mark exceeds safe zone');
  }
}
assert(brandPixels > 10000, 'maskable mark missing');
function luminance(hex) {
  const rgb = hex.match(/[a-f0-9]{2}/gi).map(n => parseInt(n, 16) / 255).map(n => n <= .04045 ? n / 12.92 : ((n + .055) / 1.055) ** 2.4);
  return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
}
const colors = JSON.parse(await readFile(join(root, 'assets/design-tokens.json'), 'utf8')).colors;
const contrast = [];
for (const [fg, bg] of [['ink', 'paper'], ['teal', 'white'], ['muted', 'paper'], ['mint', 'ink'], ['darkMuted', 'darkSurface']]) {
  const a = luminance(colors[fg]); const b = luminance(colors[bg]); const ratio = (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
  assert(ratio >= 4.5, `${fg}/${bg}: ${ratio}`); contrast.push({ foreground: fg, background: bg, ratio: +ratio.toFixed(2) });
}
await mkdir(join(root, 'artifacts/brand'), { recursive: true });
await writeFile(join(root, 'artifacts/brand/asset-check.json'), JSON.stringify({ assets: manifest.files.length, hashes: 'pass', dimensions: 'pass', icoFrames: 3, maskableSafeZone: 'pass', contrast }, null, 2) + '\n');
// A pixel-scale contact sheet supports visual review; icons are not enlarged by smoothing.
const panels = [];
let x = 24;
for (const size of [16, 32, 48]) {
  const input = await sharp(join(dir, `favicons/favicon-${size}.png`)).resize(size * 4, size * 4, { kernel: 'nearest' }).png().toBuffer();
  panels.push({ input, left: x, top: 24 }); x += size * 4 + 32;
}
await sharp({ create: { width: 520, height: 240, channels: 4, background: '#F7F8F4' } }).composite(panels).png().toFile(join(root, 'artifacts/brand/favicon-review.png'));
console.log(`PASS: ${manifest.files.length} asset hashes; PNG dimensions; 3 ICO frames; maskable safe zone; 5 text contrast pairs.`);
console.log(contrast.map(p => `${p.foreground}/${p.background}: ${p.ratio}:1`).join('\n'));
