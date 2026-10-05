import { readFile, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import opentype from 'opentype.js';
import sharp from 'sharp';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'assets', 'brand');
const tokens = JSON.parse(await readFile(join(root, 'assets/design-tokens.json'), 'utf8'));
const c = tokens.colors;
const files = [];
for (const dir of ['logos', 'marks', 'icons', 'favicons', 'social', 'fonts', 'licenses']) {
  await mkdir(join(out, dir), { recursive: true });
}
async function save(name, data) {
  await writeFile(join(out, name), data);
  files.push(name);
}
async function copy(source, name) {
  await copyFile(source, join(out, name));
  files.push(name);
}
const fontDir = join(root, 'node_modules/@fontsource/inter');
function parseFont(data) {
  return opentype.parse(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
}
const font = parseFont(await readFile(join(fontDir, 'files/inter-latin-600-normal.woff')));
const bold = parseFont(await readFile(join(fontDir, 'files/inter-latin-700-normal.woff')));
const regular = parseFont(await readFile(join(fontDir, 'files/inter-latin-400-normal.woff')));
// Brand copy is Latin ASCII. Read glyph outlines and pair kerning directly;
// opentype's text shaper does not support this Inter build's ccmp lookup.
function latinPath(face, text, x, y, size) {
  if (!/^[\x20-\x7e]+$/.test(text)) throw new Error('Use a full text shaper for non-ASCII lettering');
  const path = new opentype.Path();
  const scale = size / face.unitsPerEm;
  const glyphs = [...text].map(char => face.charToGlyph(char));
  glyphs.forEach((glyph, i) => {
    path.extend(glyph.getPath(x, y, size));
    x += glyph.advanceWidth * scale;
    if (i + 1 < glyphs.length) x += face.getKerningValue(glyph, glyphs[i + 1]) * scale;
  });
  return path;
}

// Original filled shape. Paired angled terminals are part of the silhouette.
export const markPath = 'M56 7H26a15 15 0 0 0 0 30h12a5 5 0 0 1 0 10H12L8 57h30a15 15 0 0 0 0-30H26a5 5 0 0 1 0-10h26Z';
const mark = (fill, transform = '') => `<path fill="${fill}"${transform ? ` transform="${transform}"` : ''} d="${markPath}"/>`;
const svg = (w, h, title, body) => `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-labelledby="title"><title id="title">${title}</title>${body}</svg>\n`;

const word = latinPath(font, 'sifruno', 0, 0, 78);
const bb = word.getBoundingBox();
const width = Math.ceil(bb.x2 - bb.x1);
const wordHeight = bb.y2 - bb.y1;
const logoWidth = width + 112;
const letters = (fill, x, y) => `<path fill="${fill}" transform="translate(${(x - bb.x1).toFixed(2)} ${(y - bb.y1).toFixed(2)})" d="${word.toPathData(2)}"/>`;
const variants = {
  primary: [c.teal, c.ink],
  'on-dark': [c.mint, c.white],
  'mono-ink': [c.ink, c.ink],
  'mono-white': [c.white, c.white],
};
for (const [name, [markFill, wordFill]] of Object.entries(variants)) {
  const body = mark(markFill, 'translate(12 12)') + letters(wordFill, 96, (88 - wordHeight) / 2);
  const logo = svg(logoWidth, 88, 'Sifruno', body);
  await save(`logos/sifruno-v1-logo-${name}.svg`, logo);
  await save(`logos/sifruno-v1-logo-${name}.png`, await sharp(Buffer.from(logo)).resize(logoWidth * 3, 264).png().toBuffer());
  await save(`logos/sifruno-v1-wordmark-${name}.svg`, svg(width + 24, 88, 'Sifruno', letters(wordFill, 12, (88 - wordHeight) / 2)));
  await save(`marks/sifruno-mark-${name}.svg`, svg(64, 64, 'Sifruno S mark', mark(markFill)));
}

// Version 2: the original S becomes the first letter, not a separate badge.
// Inter Bold gives the remaining outlined letters a closer weight to the mark.
const tail = latinPath(bold, 'ifruno', 0, 0, 78);
const tailBox = tail.getBoundingBox();
const tailHeight = tailBox.y2 - tailBox.y1;
const initialScale = tailHeight / 50;
const initialWidth = 48 * initialScale;
const v2Width = Math.ceil(12 + initialWidth + 4 + tailBox.x2 - tailBox.x1 + 12);
const initialTop = (88 - tailHeight) / 2;
function v2Body(cut, prefixFill, suffixFill) {
  const prefix = new opentype.Path(); const suffix = new opentype.Path();
  const glyphs = [...'ifruno'].map(char => bold.charToGlyph(char));
  let cursor = 0;
  glyphs.forEach((glyph, i) => {
    (i < cut - 1 ? prefix : suffix).extend(glyph.getPath(cursor, 0, 78));
    cursor += glyph.advanceWidth * 78 / bold.unitsPerEm;
    if (i + 1 < glyphs.length) cursor += bold.getKerningValue(glyph, glyphs[i + 1]) * 78 / bold.unitsPerEm;
  });
  const initial = mark(prefixFill, `translate(${(12 - 8 * initialScale).toFixed(3)} ${(initialTop - 7 * initialScale).toFixed(3)}) scale(${initialScale.toFixed(5)})`);
  const textTransform = `translate(${(12 + initialWidth + 4 - tailBox.x1).toFixed(2)} ${(initialTop - tailBox.y1).toFixed(2)})`;
  return `${initial}<g transform="${textTransform}"><path fill="${prefixFill}" d="${prefix.toPathData(2)}"/><path fill="${suffixFill}" d="${suffix.toPathData(2)}"/></g>`;
}
for (const [split, cut] of [['sifr-uno', 4], ['sif-runo', 3]]) {
  for (const name of ['primary', 'on-dark']) {
    const [first, second] = variants[name];
    const logo = svg(v2Width, 88, `Sifruno version 2 — ${split}`, v2Body(cut, first, second));
    await save(`logos/sifruno-v2-${split}-${name}.svg`, logo);
    await save(`logos/sifruno-v2-${split}-${name}.png`, await sharp(Buffer.from(logo)).resize(v2Width * 3, 264).png().toBuffer());
  }
}
for (const name of ['mono-ink', 'mono-white']) {
  const [first, second] = variants[name];
  const logo = svg(v2Width, 88, 'Sifruno version 2', v2Body(4, first, second));
  await save(`logos/sifruno-v2-${name}.svg`, logo);
  await save(`logos/sifruno-v2-${name}.png`, await sharp(Buffer.from(logo)).resize(v2Width * 3, 264).png().toBuffer());
}
const comparisonLabel = (text, x, y, fill) => `<path fill="${fill}" d="${latinPath(regular, text, x, y, 22).toPathData(2)}"/>`;
const compareBoard = svg(1200, 800, 'Sifruno version 1 and two-color version 2 comparison', `<path fill="${c.paper}" d="M0 0h1200v800H0z"/>${comparisonLabel('01 / SEPARATE MARK', 72, 72, c.muted)}<g transform="translate(56 100) scale(1.35)">${mark(c.teal, 'translate(12 12)')}${letters(c.ink, 96, (88 - wordHeight) / 2)}</g><path fill="${c.line}" d="M72 268h1056v1H72z"/>${comparisonLabel('02A / INTEGRATED S - SIFR + UNO', 72, 326, c.muted)}<g transform="translate(56 356) scale(1.65)">${v2Body(4, c.teal, c.ink)}</g><path fill="${c.ink}" d="M0 558h1200v242H0z"/>${comparisonLabel('02B / INTEGRATED S - SIF + RUNO', 72, 620, c.darkMuted)}<g transform="translate(56 650) scale(1.65)">${v2Body(3, c.mint, c.white)}</g>`);
await save('social/sifruno-v2-comparison.svg', compareBoard);
await save('social/sifruno-v2-comparison.png', await sharp(Buffer.from(compareBoard)).png().toBuffer());

// Version 3 uses original logo lettering throughout: consistent 10-unit stems,
// circular counters and the S mark's angled terminals in i, f and r.
const display = JSON.parse(await readFile(join(out, 'lettering/sifruno-display.json'), 'utf8'));
if (display.glyphs.map(g => g.letter).join('') !== 'Sifruno') throw new Error('Unexpected custom logotype spelling');
if (display.glyphs[0].path !== markPath) throw new Error('Custom initial S must match the brand mark');
files.push('lettering/sifruno-display.json');
const displayWidth = display.glyphs.reduce((sum, g) => sum + g.advance, 0) + 24;
function displayBody(cut, first, second) {
  let cursor = 12;
  const body = display.glyphs.map((g, i) => {
    const shape = `<path fill="${i < cut ? first : second}" fill-rule="${g.fillRule ?? 'nonzero'}"${g.transform ? ` transform="${g.transform}"` : ''} d="${g.path}"/>`;
    const placed = `<g transform="translate(${cursor} 8)">${shape}</g>`;
    cursor += g.advance; return placed;
  }).join('');
  return body;
}
for (const [split, cut] of [['sifr-uno', 4], ['sif-runo', 3]]) {
  for (const name of ['primary', 'on-dark']) {
    const [first, second] = variants[name];
    const logo = svg(displayWidth, 80, `Sifruno version 3 custom lettering — ${split}`, displayBody(cut, first, second));
    await save(`logos/sifruno-v3-${split}-${name}.svg`, logo);
    await save(`logos/sifruno-v3-${split}-${name}.png`, await sharp(Buffer.from(logo)).resize(displayWidth * 3, 240).png().toBuffer());
  }
}
for (const name of ['mono-ink', 'mono-white']) {
  const [first, second] = variants[name];
  const logo = svg(displayWidth, 80, 'Sifruno version 3 custom lettering', displayBody(4, first, second));
  await save(`logos/sifruno-v3-${name}.svg`, logo);
  await save(`logos/sifruno-v3-${name}.png`, await sharp(Buffer.from(logo)).resize(displayWidth * 3, 240).png().toBuffer());
}
// Stable default filenames always point to the user-approved identity.
if (tokens.identity?.status !== 'approved' || tokens.identity.direction !== 'v3-custom-lettering' || tokens.identity.colorSplit !== 'sifr-uno') {
  throw new Error('Canonical exports require the approved V3 Sifr/uno identity');
}
for (const name of Object.keys(variants)) {
  const source = ['primary', 'on-dark'].includes(name) ? `sifruno-v3-sifr-uno-${name}` : `sifruno-v3-${name}`;
  for (const ext of ['svg', 'png']) await copy(join(out, `logos/${source}.${ext}`), `logos/sifruno-logo-${name}.${ext}`);
  await copy(join(out, `logos/${source}.svg`), `logos/sifruno-wordmark-${name}.svg`);
}
const typeBoard = svg(1200, 800, 'Sifruno: custom logo lettering, two colors, one-color and small-size applications', `<path fill="${c.paper}" d="M0 0h1200v800H0z"/>${comparisonLabel('SIFRUNO / CUSTOM LOGO LETTERING', 72, 72, c.muted)}<g transform="translate(50 108) scale(2.7)">${displayBody(4, c.teal, c.ink)}</g>${comparisonLabel('Same S. Shared curves. Angled endings. One clear name.', 72, 418, c.muted)}<path fill="${c.ink}" d="M0 486h1200v314H0z"/>${comparisonLabel('ON DARK / TWO COLORS', 72, 542, c.darkMuted)}<g transform="translate(56 578) scale(1.4)">${displayBody(4, c.mint, c.white)}</g>${comparisonLabel('ONE COLOR', 700, 542, c.darkMuted)}<g transform="translate(688 602) scale(.86)">${displayBody(4, c.white, c.white)}</g>${comparisonLabel('WORKS AT 120PX', 700, 728, c.darkMuted)}<g transform="translate(695 746) scale(${(120 / displayWidth).toFixed(5)})">${displayBody(4, c.mint, c.white)}</g>`);
await save('social/sifruno-v3-typography.svg', typeBoard);
await save('social/sifruno-v3-typography.png', await sharp(Buffer.from(typeBoard)).png().toBuffer());

const icon = svg(96, 96, 'Sifruno app icon', `<path fill="${c.ink}" d="M0 0h96v96H0z"/>${mark(c.mint, 'translate(8 8) scale(1.25)')}`);
const maskable = svg(96, 96, 'Sifruno maskable app icon', `<path fill="${c.ink}" d="M0 0h96v96H0z"/>${mark(c.mint, 'translate(14 14) scale(1.0625)')}`);
const favicon = svg(64, 64, 'Sifruno favicon', `<rect width="64" height="64" rx="13" fill="${c.ink}"/>${mark(c.mint)}`);
await save('icons/sifruno-app-icon.svg', icon);
await save('icons/sifruno-app-icon-maskable.svg', maskable);
await save('favicons/favicon.svg', favicon);
const frames = [];
for (const size of [16, 32, 48]) {
  const data = await sharp(Buffer.from(favicon)).resize(size, size).png().toBuffer();
  await save(`favicons/favicon-${size}.png`, data);
  frames.push({ size, data });
}
// Windows ICO directory with PNG payloads: modern browsers and Windows support it.
const header = Buffer.alloc(6 + frames.length * 16);
header.writeUInt16LE(1, 2); header.writeUInt16LE(frames.length, 4);
let offset = header.length;
frames.forEach(({ size, data }, i) => {
  const p = 6 + i * 16;
  header[p] = size; header[p + 1] = size;
  header.writeUInt16LE(1, p + 4); header.writeUInt16LE(32, p + 6);
  header.writeUInt32LE(data.length, p + 8); header.writeUInt32LE(offset, p + 12);
  offset += data.length;
});
await save('favicons/favicon.ico', Buffer.concat([header, ...frames.map(f => f.data)]));
for (const size of [192, 512, 1024]) {
  await save(`icons/sifruno-app-icon-${size}.png`, await sharp(Buffer.from(icon)).resize(size, size).png().toBuffer());
}
await save('icons/sifruno-maskable-512.png', await sharp(Buffer.from(maskable)).resize(512, 512).png().toBuffer());
await save('favicons/apple-touch-icon.png', await sharp(Buffer.from(icon)).resize(180, 180).png().toBuffer());
await save('social/sifruno-avatar.png', await sharp(Buffer.from(icon)).resize(1024, 1024).png().toBuffer());

const slogan = latinPath(regular, 'Zero friction. Full control.', 80, 390, 48).toPathData(2);
const cover = svg(1200, 630, 'Sifruno — Zero friction. Full control.', `<path fill="${c.paper}" d="M0 0h1200v630H0z"/><g transform="translate(64 132) scale(1.6)">${mark(c.teal, 'translate(12 12)')}${letters(c.ink, 96, (88 - wordHeight) / 2)}</g><path fill="${c.ink}" d="${slogan}"/><path fill="${c.teal}" d="M80 496h1040v4H80z"/>`);
await save('social/sifruno-v1-cover.svg', cover);
await save('social/sifruno-v1-cover.png', await sharp(Buffer.from(cover)).png().toBuffer());
const approvedCover = svg(1200, 630, 'Sifruno — Zero friction. Full control.', `<path fill="${c.paper}" d="M0 0h1200v630H0z"/><g transform="translate(64 132) scale(1.8)">${displayBody(4, c.teal, c.ink)}</g><path fill="${c.ink}" d="${slogan}"/><path fill="${c.teal}" d="M80 496h1040v4H80z"/>`);
await save('social/sifruno-cover.svg', approvedCover);
await save('social/sifruno-cover.png', await sharp(Buffer.from(approvedCover)).png().toBuffer());

const uiIcons = ['layout-dashboard', 'globe', 'server', 'database', 'mail', 'archive', 'shield-check', 'puzzle', 'workflow', 'terminal', 'settings-2', 'users'];
for (const name of uiIcons) {
  await copy(join(root, `node_modules/lucide-static/icons/${name}.svg`), `icons/ui-${name}.svg`);
}
await copy(join(root, 'node_modules/lucide-static/LICENSE'), 'licenses/lucide-LICENSE.txt');
await copy(join(fontDir, 'LICENSE'), 'licenses/inter-OFL.txt');
for (const weight of [400, 500, 600]) {
  await copy(join(fontDir, `files/inter-latin-${weight}-normal.woff2`), `fonts/inter-latin-${weight}.woff2`);
}
await save('site.webmanifest', JSON.stringify({
  name: 'Sifruno', short_name: 'Sifruno', start_url: '.', display: 'standalone',
  background_color: c.paper, theme_color: c.ink,
  icons: [
    { src: 'icons/sifruno-app-icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
    { src: 'icons/sifruno-app-icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
    { src: 'icons/sifruno-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
  ],
}, null, 2) + '\n');
const colorVars = Object.entries(c).map(([key, val]) => `  --sifruno-${key.replace(/[A-Z]/g, s => '-' + s.toLowerCase())}: ${val};`).join('\n');
const css = `/* Generated by scripts/brand-build.mjs from design-tokens.json. */\n:root {\n${colorVars}\n  --sifruno-font: Inter, ${tokens.typography.fallback};\n  --sifruno-radius-control: ${tokens.radiusPx.control}px;\n  --sifruno-radius-surface: ${tokens.radiusPx.surface}px;\n}\n`;
await writeFile(join(root, 'assets/design-tokens.css'), css);
const manifest = {
  brand: 'Sifruno', version: tokens.version, generator: 'scripts/brand-build.mjs',
  identity: tokens.identity,
  originality: 'Original S mark and V3 custom logo lettering; Inter-derived V1/V2 wordmark outlines; Lucide interface icons.',
  files: await Promise.all(files.sort().map(async path => {
    const data = await readFile(join(out, path));
    return { path, bytes: data.length, sha256: createHash('sha256').update(data).digest('hex') };
  })),
};
await writeFile(join(out, 'asset-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Built ${files.length} Sifruno assets. SVG letters are outlined; font and icon licenses included.`);
