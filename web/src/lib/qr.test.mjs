// The QR encoder against the standard's own tables and examples (ISO/IEC
// 18004:2015), and fixed inputs whose version, mask and modules were
// checked against an independent encoder (Nayuki's qrcodegen 1.8.0, byte
// mode, level M, no boost) and read back with zbarimg. Synthetic text only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

const source = readFileSync(new URL("./qr.ts", import.meta.url), "utf8");
const qr = await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`);

test("format bits for level M and each mask, as Annex C lists them", () => {
  const table = ["101010000010010", "101000100100101", "101111001111100", "101101101001011", "100010111111001", "100000011001110", "100111110010111", "100101010100000"];
  table.forEach((bits, mask) => assert.equal(qr.formatBits(mask).toString(2).padStart(15, "0"), bits, `mask ${mask}`));
});

test("version bits for versions 7 to 40, as Annex D lists them", () => {
  const table = [0x07c94, 0x085bc, 0x09a99, 0x0a4d3, 0x0bbf6, 0x0c762, 0x0d847, 0x0e60d, 0x0f928, 0x10b78, 0x1145d, 0x12a17, 0x13532, 0x149a6, 0x15683, 0x168c9, 0x177ec,
    0x18ec4, 0x191e1, 0x1afab, 0x1b08e, 0x1cc1a, 0x1d33f, 0x1ed75, 0x1f250, 0x209d5, 0x216f0, 0x228ba, 0x2379f, 0x24b0b, 0x2542e, 0x26a64, 0x27541, 0x28c69];
  table.forEach((bits, i) => assert.equal(qr.versionBits(i + 7), bits, `version ${i + 7}`));
});

test("codewords and alignment patterns follow Tables 1, 9 and E.1", () => {
  // [version, all codewords, data codewords at level M]
  for (const [v, total, data] of [[1, 26, 16], [2, 44, 28], [3, 70, 44], [4, 100, 64], [5, 134, 86], [6, 172, 108], [7, 196, 124], [8, 242, 154], [9, 292, 182], [10, 346, 216], [20, 1085, 669], [27, 1828, 1128], [40, 3706, 2334]]) {
    assert.equal(qr.totalCodewords(v), total, `version ${v} codewords`);
    assert.equal(qr.dataCodewords(v), data, `version ${v} data codewords`);
  }
  assert.deepEqual(qr.alignmentPositions(1), []);
  assert.deepEqual(qr.alignmentPositions(2), [6, 18]);
  assert.deepEqual(qr.alignmentPositions(7), [6, 22, 38]);
  assert.deepEqual(qr.alignmentPositions(10), [6, 28, 50]);
  assert.deepEqual(qr.alignmentPositions(15), [6, 26, 48, 70]);
  assert.deepEqual(qr.alignmentPositions(32), [6, 34, 60, 86, 112, 138]);
  assert.deepEqual(qr.alignmentPositions(36), [6, 24, 50, 76, 102, 128, 154]);
  assert.deepEqual(qr.alignmentPositions(40), [6, 30, 58, 86, 114, 142, 170]);
});

test("error correction of Annex I's 1-M example", () => {
  const data = [0x10, 0x20, 0x0c, 0x56, 0x61, 0x80, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11];
  assert.deepEqual([...qr.errorCorrection(data, 10)], [0xa5, 0x24, 0xd4, 0xc1, 0xed, 0x36, 0xc7, 0x87, 0x2c, 0x55]);
});

test("the smallest version that holds the bytes, and nothing past version 40", () => {
  assert.equal(qr.chooseVersion(14), 1);
  assert.equal(qr.chooseVersion(15), 2);
  assert.equal(qr.chooseVersion(213), 10);
  assert.equal(qr.chooseVersion(214), 11);
  assert.equal(qr.chooseVersion(2331), 40);
  assert.throws(() => qr.chooseVersion(2332), qr.QrTooLong);
  assert.throws(() => qr.encodeQr("x".repeat(2332)), qr.QrTooLong);
});

test("fixed inputs: version, mask and every module", () => {
  const hello = qr.encodeQr("Hello, world!");
  assert.equal(hello.version, 1);
  assert.equal(hello.mask, 2);
  assert.deepEqual(hello.modules.map((row) => row.map((dark) => (dark ? "1" : "0")).join("")), [
    "111111100000101111111", "100000100101001000001", "101110101011101011101", "101110101000001011101", "101110101100101011101",
    "100000101111001000001", "111111101010101111111", "000000001010000000000", "101111100111001111100", "000110011000110011101",
    "000100101110111001110", "011001010011110101100", "110111101000101100001", "000000001000011111000", "111111100110111100110",
    "100000101010110101110", "101110101101111010011", "101110101010000111000", "101110101111101100100", "100000100010110011100",
    "111111101101001010010",
  ]);
  // An authenticator link of the shape the panel makes, with a stand-in key.
  const link = qr.encodeQr(`otpauth://totp/Sifruno:alice?secret=${"A".repeat(32)}&issuer=Sifruno`);
  assert.deepEqual([link.version, link.mask, link.size], [5, 2, 37]);
  const setup = qr.encodeQr("https://panel.example.com:8443/setup");
  assert.deepEqual([setup.version, setup.mask], [3, 2]);
});

test("the penalty counts runs, blocks, finder-like patterns and balance", () => {
  // A 21 × 21 symbol of one colour: 21 runs of 21 in each direction
  // (3 + 16 each), 400 blocks of 2 × 2, and all light or all dark (N4 90).
  const light = Array.from({ length: 21 }, () => new Array(21).fill(false));
  assert.equal(qr.penalty(light), 42 * 19 + 400 * 3 + 90);
  // One row 1011101 in the middle of light: a finder-like pattern with
  // light on both sides counts twice. 1110101 has the same dark columns,
  // runs and blocks, but no such pattern.
  const row = (bits) => {
    const grid = Array.from({ length: 21 }, () => new Array(21).fill(false));
    bits.forEach((dark, i) => { grid[10][7 + i] = dark === 1; });
    return grid;
  };
  assert.equal(qr.penalty(row([1, 0, 1, 1, 1, 0, 1])) - qr.penalty(row([1, 1, 1, 0, 1, 0, 1])), 80);
});

test("the SVG path draws exactly the dark modules, inside the quiet zone", () => {
  const code = qr.encodeQr("Hello, world!");
  const dark = code.modules.flat().filter(Boolean).length;
  const path = qr.qrPath(code);
  let area = 0, minX = Infinity, minY = Infinity, maxX = 0;
  for (const [, x, y, w] of path.matchAll(/M(\d+) (\d+)h(\d+)v1h-\3z/g)) {
    area += Number(w);
    minX = Math.min(minX, Number(x)); minY = Math.min(minY, Number(y)); maxX = Math.max(maxX, Number(x) + Number(w));
  }
  assert.equal(area, dark);
  assert.equal(path.replace(/M\d+ \d+h\d+v1h-\d+z/g, ""), "");
  assert.deepEqual([minX, minY, maxX], [4, 4, 4 + code.size]);
});
