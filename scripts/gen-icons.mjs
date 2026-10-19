// Generates the placeholder icon set the Tauri bundler needs.
// Run with: node scripts/gen-icons.mjs
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";

const OUT = new URL("../src-tauri/icons/", import.meta.url);
mkdirSync(OUT, { recursive: true });

function crc32(buf) {
  let c, crc = 0xffffffff;
  for (let n = 0; n < buf.length; n++) {
    c = (crc ^ buf[n]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = c ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function png(size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      const p = rowStart + 1 + x * 4;
      const edge = x < 4 || y < 4 || x >= size - 4 || y >= size - 4;
      raw[p] = edge ? 0x2f : 0x11;
      raw[p + 1] = edge ? 0x81 : 0x17;
      raw[p + 2] = edge ? 0xf6 : 0x22;
      raw[p + 3] = 255;
    }
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

for (const size of [32, 128, 256]) {
  const name = size === 256 ? "128x128@2x.png" : `${size}x${size}.png`;
  writeFileSync(new URL(name, OUT), png(size));
}

// Minimal ICO wrapping the 32x32 PNG (ICO supports embedded PNG since Vista).
const p32 = png(32);
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(1, 4);
const entry = Buffer.alloc(16);
entry[0] = 32;
entry[1] = 32;
entry.writeUInt16LE(1, 4);
entry.writeUInt16LE(32, 6);
entry.writeUInt32LE(p32.length, 8);
entry.writeUInt32LE(22, 12);
writeFileSync(new URL("icon.ico", OUT), Buffer.concat([header, entry, p32]));
console.log("icons written");
