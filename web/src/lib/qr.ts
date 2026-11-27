// A QR code encoder for the authenticator app's otpauth:// link, so a phone
// can scan it instead of typing a 32-letter key. It follows ISO/IEC
// 18004:2015 for one case only: byte mode, error correction level M,
// versions 1 to 40. It runs in the browser and nothing else sees the text:
// no request, no log, no storage.

export interface QrCode {
  version: number;
  mask: number;
  // Modules per side, without the quiet zone: 4 × version + 17.
  size: number;
  // modules[y][x] is true for a dark module.
  modules: boolean[][];
}

// Level M's error correction for each version (index 0 is unused): the
// codewords each block carries, and the number of blocks (ISO/IEC 18004
// Table 9).
const eccPerBlock = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const blockCount = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];

// Level M is 00 in the format information.
const levelBits = 0b00;
const formatMask = 0x5412;
const formatGenerator = 0x537; // x^10 + x^8 + x^5 + x^4 + x^2 + x + 1
const versionGenerator = 0x1f25; // x^12 + x^11 + x^10 + x^9 + x^8 + x^5 + x^2 + 1

export const minVersion = 1;
export const maxVersion = 40;

export class QrTooLong extends Error {}

const sizeOf = (version: number) => 4 * version + 17;

// The modules left for data and error correction once the function patterns
// are drawn, from the symbol's area.
function dataModules(version: number): number {
  const size = sizeOf(version);
  let n = size * size - 3 * 64 - 2 * (size - 16) - 31; // finders with separators, timing, format, the dark module
  if (version >= 2) {
    const per = Math.floor(version / 7) + 2;
    n -= 25 * (per * per - 3) - 10 * (per - 2); // alignment patterns, less where they cross the timing lines
  }
  if (version >= 7) n -= 36; // the two version blocks
  return n;
}

export const totalCodewords = (version: number) => Math.floor(dataModules(version) / 8);
export const dataCodewords = (version: number) => totalCodewords(version) - eccPerBlock[version] * blockCount[version];

// The rows and columns of the alignment patterns' centres (Annex E): 6, then
// evenly spaced up to size − 7, with an even step.
export function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const last = sizeOf(version) - 7;
  const step = 2 * Math.floor((version * 8 + count * 3 + 5) / (count * 4 - 4));
  const out = [6];
  for (let i = count - 2; i >= 0; i--) out.push(last - i * step);
  return out;
}

// The remainder of value × x^(degree) divided by generator, for the BCH
// codes of the format and version information.
function bchRemainder(value: number, generator: number, degree: number): number {
  let rem = value << degree;
  for (let bit = 31 - Math.clz32(rem); bit >= degree; bit--) {
    if ((rem >>> bit) & 1) rem ^= generator << (bit - degree);
  }
  return rem;
}

// The 15 format bits for level M and a mask, masked with 101010000010010.
export const formatBits = (mask: number) => {
  const data = (levelBits << 3) | mask;
  return ((data << 10) | bchRemainder(data, formatGenerator, 10)) ^ formatMask;
};

// The 18 version bits, for versions 7 and up.
export const versionBits = (version: number) => (version << 12) | bchRemainder(version, versionGenerator, 12);

// ---- Reed-Solomon over GF(256) with the polynomial x^8 + x^4 + x^3 + x^2 + 1

const exp = new Uint8Array(512);
const log = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = x;
    log[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) exp[i] = exp[i - 255];
}
const times = (a: number, b: number) => (a === 0 || b === 0 ? 0 : exp[log[a] + log[b]]);

// The generator polynomial (x − α^0)(x − α^1)…(x − α^(degree−1)), highest
// power first, without its leading 1.
function generator(degree: number): Uint8Array {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array<number>(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= times(poly[j], exp[i]);
    }
    poly = next;
  }
  return Uint8Array.from(poly.slice(1));
}

// The error correction codewords of one block: the remainder of data × x^n
// divided by the generator.
export function errorCorrection(data: ArrayLike<number>, degree: number): Uint8Array {
  const gen = generator(degree);
  const rem = new Uint8Array(degree);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ rem[0];
    rem.copyWithin(0, 1);
    rem[degree - 1] = 0;
    for (let j = 0; j < degree; j++) rem[j] ^= times(gen[j], factor);
  }
  return rem;
}

// ---- The codewords

// The smallest version whose data codewords hold the bytes in byte mode.
export function chooseVersion(length: number): number {
  for (let v = minVersion; v <= maxVersion; v++) {
    const countBits = v < 10 ? 8 : 16;
    if (length < 2 ** countBits && 4 + countBits + 8 * length <= 8 * dataCodewords(v)) return v;
  }
  throw new QrTooLong(`${length} bytes do not fit in a version ${maxVersion} QR code at level M`);
}

// The data codewords: mode 0100, the count, the bytes, the terminator, then
// the pad bytes 11101100 and 00010001 in turn.
function dataStream(bytes: Uint8Array, version: number): Uint8Array {
  const capacity = dataCodewords(version);
  const bits: number[] = [];
  const put = (value: number, length: number) => { for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
  put(0b0100, 4);
  put(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, capacity * 8 - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  const out = new Uint8Array(capacity);
  for (let i = 0; i < bits.length; i++) out[i >>> 3] |= bits[i] << (7 - (i & 7));
  for (let i = bits.length / 8, pad = 0xec; i < capacity; i++, pad ^= 0xec ^ 0x11) out[i] = pad;
  return out;
}

// The final message: the data split into blocks (the short ones first), each
// with its error correction, then interleaved codeword by codeword.
function codewords(data: Uint8Array, version: number): Uint8Array {
  const blocks = blockCount[version], ecc = eccPerBlock[version];
  const total = totalCodewords(version);
  const longBlocks = total % blocks;
  const shortData = Math.floor(total / blocks) - ecc;
  const dataBlocks: Uint8Array[] = [], eccBlocks: Uint8Array[] = [];
  for (let b = 0, at = 0; b < blocks; b++) {
    const length = shortData + (b >= blocks - longBlocks ? 1 : 0);
    const block = data.subarray(at, at + length);
    at += length;
    dataBlocks.push(block);
    eccBlocks.push(errorCorrection(block, ecc));
  }
  const out: number[] = [];
  for (let i = 0; i <= shortData; i++) for (const block of dataBlocks) if (i < block.length) out.push(block[i]);
  for (let i = 0; i < ecc; i++) for (const block of eccBlocks) out.push(block[i]);
  return Uint8Array.from(out);
}

// ---- The symbol

class Grid {
  readonly dark: boolean[][];
  readonly reserved: boolean[][];
  constructor(readonly size: number) {
    this.dark = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
    this.reserved = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  }
  fix(x: number, y: number, dark: boolean) { this.dark[y][x] = dark; this.reserved[y][x] = true; }
}

function drawFunctionPatterns(grid: Grid, version: number) {
  const size = grid.size;
  // Timing patterns on row and column 6; the finders draw over their ends.
  for (let i = 0; i < size; i++) { grid.fix(6, i, i % 2 === 0); grid.fix(i, 6, i % 2 === 0); }
  // The three finders, each with its light separator.
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x < 0 || y < 0 || x >= size || y >= size) continue;
      const ring = Math.max(Math.abs(dx), Math.abs(dy));
      grid.fix(x, y, ring !== 2 && ring !== 4);
    }
  }
  // Alignment patterns, except where a finder is.
  const at = alignmentPositions(version);
  for (const cy of at) for (const cx of at) {
    if ((cx === 6 && cy === 6) || (cx === 6 && cy === size - 7) || (cx === size - 7 && cy === 6)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) grid.fix(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  // The format areas, filled for real once the mask is known, and the
  // module that is always dark.
  drawFormat(grid, 0);
  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      grid.fix(a, b, dark); // top right, read across
      grid.fix(b, a, dark); // bottom left, read down
    }
  }
}

function drawFormat(grid: Grid, mask: number) {
  const size = grid.size, bits = formatBits(mask);
  const bit = (i: number) => ((bits >>> i) & 1) === 1;
  // Around the top-left finder: bits 0–7 down column 8, skipping the timing
  // row; bits 8–14 along row 8 leftwards, skipping the timing column.
  for (let i = 0; i <= 5; i++) grid.fix(8, i, bit(i));
  grid.fix(8, 7, bit(6));
  grid.fix(8, 8, bit(7));
  grid.fix(7, 8, bit(8));
  for (let i = 9; i < 15; i++) grid.fix(14 - i, 8, bit(i));
  // The copy: bits 0–7 along row 8 from the right, bits 8–14 up column 8
  // from the bottom.
  for (let i = 0; i < 8; i++) grid.fix(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) grid.fix(8, size - 15 + i, bit(i));
  grid.fix(8, size - 8, true);
}

// Data and error correction bits in two-module columns from the bottom
// right, up and down in turn, skipping the timing column.
function placeCodewords(grid: Grid, message: Uint8Array) {
  const size = grid.size;
  let i = 0;
  for (let right = size - 1, upward = true; right >= 1; right -= 2, upward = !upward) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step++) {
      const y = upward ? size - 1 - step : step;
      for (const x of [right, right - 1]) {
        if (grid.reserved[y][x]) continue;
        // The remainder bits after the message stay light.
        grid.dark[y][x] = i < message.length * 8 && ((message[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
        i++;
      }
    }
  }
}

const masks: ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function applyMask(grid: Grid, mask: number) {
  const flip = masks[mask];
  for (let y = 0; y < grid.size; y++) for (let x = 0; x < grid.size; x++) {
    if (!grid.reserved[y][x] && flip(x, y)) grid.dark[y][x] = !grid.dark[y][x];
  }
}

// The penalty of a masked symbol (ISO/IEC 18004 7.8.3): N1 = 3 for a run of
// five same-coloured modules in a row or column, plus 1 for each module more;
// N2 = 3 for each 2 × 2 block of one colour; N3 = 40 for each 1:1:3:1:1
// finder-like pattern with four times its unit of light on one side, the
// light around the symbol counting; N4 = 10 for each 5 % the dark share is
// away from 50 %.
export function penalty(dark: readonly (readonly boolean[])[]): number {
  const size = dark.length;
  let score = 0;
  const line = (at: (i: number) => boolean) => {
    // Runs of alternating colour, light first. The light around the symbol
    // pads both ends, as long as the symbol is wide: no pattern is ever
    // wider than that.
    const pad = size;
    const runs: number[] = [];
    let colour = false, length = pad;
    for (let i = 0; i < size; i++) {
      const c = at(i);
      if (c === colour) { length++; continue; }
      runs.push(length);
      colour = c;
      length = 1;
    }
    runs.push(length + (colour ? 0 : pad));
    if (colour) runs.push(pad);
    for (let r = 0; r < runs.length; r++) {
      // The padding is not the symbol's own: it counts for N3 only.
      const own = runs[r] - (r === 0 ? pad : 0) - (r === runs.length - 1 ? pad : 0);
      if (own >= 5) score += 3 + own - 5;
    }
    // Dark runs sit at odd indexes. A finder-like pattern is dark runs of
    // n, 3n, n with light runs of n between, and 4n light on one side and
    // at least n light on the other.
    for (let r = 3; r + 2 < runs.length; r += 2) {
      const n = runs[r - 2];
      if (runs[r - 1] !== n || runs[r] !== 3 * n || runs[r + 1] !== n || runs[r + 2] !== n) continue;
      const before = runs[r - 3], after = r + 3 < runs.length ? runs[r + 3] : 0;
      if (before >= 4 * n && after >= n) score += 40;
      if (after >= 4 * n && before >= n) score += 40;
    }
  };
  for (let y = 0; y < size; y++) line((x) => dark[y][x]);
  for (let x = 0; x < size; x++) line((y) => dark[y][x]);
  for (let y = 0; y + 1 < size; y++) for (let x = 0; x + 1 < size; x++) {
    const c = dark[y][x];
    if (dark[y][x + 1] === c && dark[y + 1][x] === c && dark[y + 1][x + 1] === c) score += 3;
  }
  let darkCount = 0;
  for (const row of dark) for (const c of row) if (c) darkCount++;
  const total = size * size;
  // The smallest k with (45 − 5k) % ≤ dark share ≤ (55 + 5k) %.
  score += 10 * (Math.ceil(Math.abs(darkCount * 20 - total * 10) / total) - 1);
  return score;
}

// The QR code for text, UTF-8 encoded, in the smallest version that holds
// it, with the mask of the lowest penalty (the first on a tie). Throws
// QrTooLong past version 40.
export function encodeQr(text: string): QrCode {
  const bytes = new TextEncoder().encode(text);
  const version = chooseVersion(bytes.length);
  const grid = new Grid(sizeOf(version));
  drawFunctionPatterns(grid, version);
  placeCodewords(grid, codewords(dataStream(bytes, version), version));
  let best = 0, bestScore = Infinity;
  for (let mask = 0; mask < masks.length; mask++) {
    applyMask(grid, mask);
    drawFormat(grid, mask);
    const score = penalty(grid.dark);
    if (score < bestScore) { best = mask; bestScore = score; }
    applyMask(grid, mask);
  }
  applyMask(grid, best);
  drawFormat(grid, best);
  return { version, mask: best, size: grid.size, modules: grid.dark };
}

// An SVG path that draws the dark modules, each row's runs as one rectangle,
// offset by the quiet zone.
export function qrPath(code: QrCode, quiet = 4): string {
  const parts: string[] = [];
  code.modules.forEach((row, y) => {
    for (let x = 0; x < code.size; x++) {
      if (!row[x]) continue;
      let end = x;
      while (end + 1 < code.size && row[end + 1]) end++;
      parts.push(`M${x + quiet} ${y + quiet}h${end - x + 1}v1h-${end - x + 1}z`);
      x = end;
    }
  });
  return parts.join("");
}
