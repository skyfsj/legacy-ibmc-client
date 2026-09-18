// Headless decoder test: runs src/renderer/decoder.js against the REAL captured
// frame and writes a PNG, so the browser decoder can be verified without Electron
// or a live session.
//
// Browser APIs (canvas / ImageData / createImageBitmap) are shimmed here; JPEG
// decoding uses jpeg-js instead of Chromium's decoder.
//
// Run: node test/decoder.test.mjs

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';


const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const EVIDENCE = path.join(ROOT, '..', '..', '..', 'docs', 'protocol', 'evidence');

// ---------- minimal canvas shim ----------
class ShimCtx {
  constructor(canvas) { this.canvas = canvas; }
  _target() { return this.canvas.pixels; }
  clearRect(x, y, w, h) {
    if (x === 0 && y === 0 && w === this.canvas.width && h === this.canvas.height) this._target().fill(0);
  }
  putImageData(img, x, y) {
    const src = img.data, dst = this._target(), W = this.canvas.width;
    for (let row = 0; row < img.height; row++) {
      const d0 = ((y + row) * W + x) * 4, s0 = row * img.width * 4;
      dst.set(src.subarray(s0, s0 + img.width * 4), d0);
    }
  }
  drawImage(src, x = 0, y = 0, w, h) {
    const dst = this._target(), W = this.canvas.width, H = this.canvas.height;
    const sw = src.width, sh = src.height;
    const sdata = src.pixels ? src.pixels : src.data;
    const dw = w ?? sw, dh = h ?? sh;
    for (let row = 0; row < dh; row++) {
      const dy = y + row;
      if (dy < 0 || dy >= H) continue;
      const sy = Math.min(sh - 1, Math.floor((row * sh) / dh));
      for (let col = 0; col < dw; col++) {
        const dx = x + col;
        if (dx < 0 || dx >= W) continue;
        const sx = Math.min(sw - 1, Math.floor((col * sw) / dw));
        const si = (sy * sw + sx) * 4, di = (dy * W + dx) * 4;
        dst[di] = sdata[si]; dst[di + 1] = sdata[si + 1]; dst[di + 2] = sdata[si + 2]; dst[di + 3] = 255;
      }
    }
  }
}
class ShimCanvas {
  constructor() { this.width = 0; this.height = 0; this.pixels = null; }
  getContext() {
    if (!this.pixels || this.pixels.length !== this.width * this.height * 4) {
      this.pixels = new Uint8ClampedArray(this.width * this.height * 4);
    }
    return new ShimCtx(this);
  }
}
globalThis.document = { createElement: (t) => { if (t !== 'canvas') throw new Error('unexpected ' + t); return new ShimCanvas(); } };
globalThis.ImageData = class ImageData {
  constructor(data, width, height) { this.data = data; this.width = width; this.height = height; }
};
globalThis.createImageBitmap = async (blob) => {
  const buf = Buffer.from(await blob.arrayBuffer());
  const raw = jpeg.decode(buf, { useTArray: true, maxMemoryUsageInMB: 256 });
  return { width: raw.width, height: raw.height, data: raw.data, close() {} };
};

// ---------- load the real ESM decoder via data: URLs ----------
function dataUrl(code) { return 'data:text/javascript;base64,' + Buffer.from(code).toString('base64'); }
const tablesCode = fs.readFileSync(path.join(ROOT, 'src/renderer/jpeg-tables.js'), 'utf8');
const tablesUrl = dataUrl(tablesCode);
let decoderCode = fs.readFileSync(path.join(ROOT, 'src/renderer/decoder.js'), 'utf8');
decoderCode = decoderCode.replace("from './jpeg-tables.js'", `from '${tablesUrl}'`);
const { FrameDecoder } = await import(dataUrl(decoderCode));

// ---------- run ----------
// frame-2.bin is the COMBINED buffer: [diffFlag] ++ concat(seq>=1 sub-packet data).
// The frame header (width/height/dqt) lives in the seq-0 sub-packet, i.e. in the
// raw stream, NOT in the combined buffer.
const framePath = path.join(EVIDENCE, 'frame-2.bin');
const streamPath = path.join(EVIDENCE, 'session-server-stream.bin');

if (!fs.existsSync(framePath)) {
  console.log('\n⚠️  跳过：未找到帧固件 ' + framePath);
  console.log('   这需要用你自己的抓包导出（见 NOTICE.md / docs/protocol/tools/）。\n');
  process.exit(0);
}
const stream = fs.readFileSync(framePath);

// pull the real frame's seq-0 sub-packet out of the raw stream to read its header
const raw = fs.readFileSync(streamPath);
let headerPacket = null;
for (let i = 0; i + 4 <= raw.length;) {
  if (!(raw[i] === 0xfe && raw[i + 1] === 0xf6 && raw[i + 2] === 0x00)) { i++; continue; }
  const dlen = raw[i + 3];
  if (i + 4 + dlen > raw.length) break;
  const p = Buffer.from(raw.subarray(i + 4, i + 4 + dlen));
  if (p[2] === 0x02 && p.readUInt16BE(4) === 0) {
    const d = Buffer.from(p.subarray(4));
    if (d.readUInt32BE(3) > 0) headerPacket = d;      // the real frame (packLenght > 0)
  }
  i += 4 + dlen;
}
if (!headerPacket) throw new Error('未在原始流中找到真实帧的帧头子包');

const flags = headerPacket[7];
const width = ((flags & 0x7f) << 8) | headerPacket[8];
const height = headerPacket.readUInt16BE(9);
const dqt = (headerPacket[16] & 0x0f) - 1;
console.log(`重组缓冲 ${stream.length}B`);
console.log(`帧头: ${width}x${height}, dqt 索引=${dqt}, packLenght=${headerPacket.readUInt32BE(3)}, 差分=${(flags >> 7) & 1}`);
console.log(`差分标志（重组缓冲[0]）= ${stream[0]}`);
if (stream.length !== headerPacket.readUInt32BE(3) + 1) {
  console.warn(`⚠️ 缓冲长度 ${stream.length} != packLenght+1 ${headerPacket.readUInt32BE(3) + 1}`);
}

const jpeg = (await import('jpeg-js')).default;   // only needed once we actually decode

const dec = new FrameDecoder();
const t0 = Date.now();
const stats = await dec.decode({ stream, blockX: Math.ceil(width / 64), blockY: Math.ceil(height / 64), dqt });
const ms = Date.now() - t0;
console.log('解码统计:', JSON.stringify(stats));

const target = new ShimCanvas();
target.width = width; target.height = height;
const tctx = target.getContext('2d');
dec.drawTo(tctx);

// ---------- write PNG ----------
function writePng(file, rgba, w, h) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 4 + 1)] = 0;
    Buffer.from(rgba.buffer, rgba.byteOffset + y * w * 4, w * 4).copy(raw, y * (w * 4 + 1) + 1);
  }
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td) >>> 0);
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
  fs.writeFileSync(file, png);
}
let CRC = null;
function crc32(buf) {
  if (!CRC) {
    CRC = new Int32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1); CRC[n] = c; }
  }
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff);
}

const outPng = path.join(ROOT, 'test', 'decoder-output.png');
writePng(outPng, target.pixels, width, height);
const rawOut = path.join(ROOT, 'test', 'decoder-output.rgba');
fs.writeFileSync(rawOut, Buffer.from(target.pixels.buffer));

console.log(`\n解码耗时 ${ms}ms → ${outPng}`);
console.log(`JPEG 块 ${stats.jpeg} 个（失败 ${stats.jpegErrors}），复制块 ${stats.copy}，RLE 块 ${stats.rle}`);
console.log(`块流消耗 ${stats.consumed}/${stats.expected} 字节 ${stats.consumed === stats.expected ? '✅ 完全吻合' : '❌ 不吻合'}`);
const expectedBlocks = Math.ceil(width / 64) * Math.ceil(height / 64);
console.log(`块数 ${stats.blocks}/${expectedBlocks} ${stats.blocks === expectedBlocks ? '✅' : '❌'}`);

const ok = stats.consumed === stats.expected && stats.jpegErrors === 0 && stats.blocks === expectedBlocks;
console.log(ok ? '\n✅ 解码器验证通过' : '\n❌ 解码器验证失败');
process.exit(ok ? 0 : 1);
