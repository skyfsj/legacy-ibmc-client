// Huawei iBMC KVM video block decoder.
//
// A reassembled frame is a sequence of 64x64 blocks. Each block starts with a
// 1-byte descriptor:  bits7..5 = zipType, bits4..2 = rleType.
//   zipType 0/1 -> RLE block, variant chosen by rleType:
//       0 = solid fill, 1 = two-colour bitstream,
//       2 = 3-colour palette, 3 = 4-colour palette,
//       4 = copy left, 5 = copy left with hue rotation,
//       6 = copy block above, 7 = copy above with hue rotation
//   zipType 2/3 -> JPEG block: u16be scan length, then raw entropy-coded scan data
//                  (JPEG headers are synthesised locally — see jpeg-tables.js)
//   zipType 4   -> no-op: block keeps its previous content (1 byte)
//   zipType 5   -> copy the block one ROW above  (n - blockX)
//   zipType 6   -> copy the block to the LEFT    (n - 1)
//
// Block state (pixels, rleType, palette) persists across frames, which is what
// makes the copy blocks an effective delta encoding.
//
// Structure verified against a live capture: 130/130 blocks for 800x600, and the
// stream consumes exactly the buffer. See ../../huawei-ibmc-kvm-protocol/03-video-channel.md

import { buildJpegBytes } from './jpeg-tables.js';

const BLOCK = 64;
const PIX = BLOCK * BLOCK;

/** BT.601 full-range YCbCr -> RGB, matching ColorConverter.ycbcr2rgb. */
function ycbcr2rgb(Y, Cb, Cr) {
  Y &= 0xff; Cb &= 0xff; Cr &= 0xff;
  let r = Y + 1.402 * (Cr - 128);
  let g = Y - 0.34414 * (Cb - 128) - 0.71414 * (Cr - 128);
  let b = Y + 1.772 * (Cb - 128);
  r = r < 0 ? 0 : r > 255 ? 255 : r;
  g = g < 0 ? 0 : g > 255 ? 255 : g;
  b = b < 0 ? 0 : b > 255 ? 255 : b;
  return [r | 0, g | 0, b | 0];
}

export class FrameDecoder {
  constructor() {
    this.blockX = 0;
    this.blockY = 0;
    this.blocks = [];
    this.stats = {};
  }

  _ensure(blockX, blockY) {
    if (this.blockX === blockX && this.blockY === blockY && this.blocks.length === blockX * blockY) return;
    this.blockX = blockX; this.blockY = blockY;
    this.blocks = new Array(blockX * blockY).fill(null);
  }

  _blank() {
    const canvas = document.createElement('canvas');
    canvas.width = BLOCK; canvas.height = BLOCK;
    return { canvas, ctx: canvas.getContext('2d', { willReadFrequently: true }), rleType: null, palette: null };
  }

  _block(n) { return this.blocks[n] || (this.blocks[n] = this._blank()); }

  /**
   * Decode one reassembled frame into the persistent block grid.
   * @param {{stream: Uint8Array, blockX: number, blockY: number, dqt: number}} args
   *   stream[0] is the differential flag; the block stream starts at index 1.
   */
  async decode({ stream, blockX, blockY, dqt }) {
    this._ensure(blockX, blockY);
    const buf = stream instanceof Uint8Array ? stream : new Uint8Array(stream);
    const nBlocks = blockX * blockY;
    const u16 = (i) => (buf[i] << 8) | buf[i + 1];
    const stats = this.stats = {
      expected: buf.length, consumed: 0, blocks: 0,
      jpeg: 0, rle: 0, copy: 0, noop: 0, invalid: 0, jpegErrors: 0,
    };

    // ---- pass A: sequential walk. syclen and the resulting rleType of each block
    // must be resolved in order, because copy/RLE-inherit variants depend on the
    // referenced block's type as of THIS frame.
    const types = new Array(nBlocks);
    const ops = [];
    let i = 1;
    for (let n = 0; n < nBlocks; n++) {
      if (i >= buf.length) { ops.push({ n, kind: 'truncated' }); stats.invalid++; break; }
      const desc = buf[i];
      const zipType = (desc & 0xe0) >> 5;
      const rleType = (desc & 0x1c) >> 2;
      const op = { n, zipType, rleType, at: i };
      let prevType = types[n - 1];            // for noop we must report the unchanged type

      if (zipType === 0 || zipType === 1) {
        op.kind = 'rle';
        if (rleType <= 3) {
          const palBytes = rleType === 0 ? 0 : rleType === 1 ? 6 : rleType === 2 ? 9 : 12;
          op.ownPalette = true;
          op.colorsAt = rleType === 0 ? i + 1 : i + 3;
          op.dataAt = i + 3 + palBytes;
          op.len = rleType === 0 ? 0 : u16(i + 1);
          op.syclen = rleType === 0 ? 4 : 3 + palBytes + op.len;
          types[n] = rleType;
        } else {
          // palette inherited; source is n-1 for 4/5, n-blockX for 6/7
          const refIdx = (rleType === 4 || rleType === 5) ? n - 1 : n - blockX;
          op.refIdx = refIdx;
          const srcType = (refIdx >= 0 && refIdx < n && types[refIdx] !== undefined)
            ? types[refIdx]
            : (this.blocks[refIdx] ? this.blocks[refIdx].rleType : null);
          if (refIdx < 0 || srcType === null || srcType === undefined) {
            op.kind = 'invalid'; op.syclen = 0; types[n] = null;
          } else if (srcType === 0 && (rleType === 4 || rleType === 6)) {
            op.kind = 'copy'; op.syclen = 1; types[n] = 0;   // source is solid -> pure copy
          } else {
            op.ownPalette = false; op.inheritType = srcType;
            op.rotate = (rleType === 5 || rleType === 7) && srcType === 1;
            op.dataAt = i + 3; op.len = u16(i + 1); op.syclen = 3 + op.len;
            types[n] = srcType;
          }
        }
      } else if (zipType === 2 || zipType === 3) {
        op.kind = 'jpeg'; op.len = u16(i + 1); op.dataAt = i + 3; op.syclen = 3 + op.len;
        op.scan = buf.subarray(op.dataAt, op.dataAt + op.len);
        types[n] = null;
      } else if (zipType === 4) {
        op.kind = 'noop'; op.syclen = 1; types[n] = prevType ?? null;
      } else {
        const refIdx = zipType === 5 ? n - blockX : n - 1;
        if (refIdx < 0) { op.kind = 'invalid'; op.syclen = 0; types[n] = null; }
        else {
          op.kind = 'copy'; op.refIdx = refIdx; op.syclen = 1;
          types[n] = (types[refIdx] !== undefined) ? types[refIdx] : (this.blocks[refIdx] ? this.blocks[refIdx].rleType : null);
        }
      }
      ops.push(op);
      stats.blocks++;
      i += op.syclen;
      if (op.syclen === 0 && op.kind === 'invalid') break;
    }
    stats.consumed = i;

    // ---- pass B: JPEG blocks in parallel (Chromium's decoder, including RST markers)
    await Promise.all(ops.filter((o) => o.kind === 'jpeg').map(async (op) => {
      try {
        const jpeg = buildJpegBytes(op.scan, dqt);
        const bmp = await createImageBitmap(new Blob([jpeg], { type: 'image/jpeg' }));
        const b = this._block(op.n);
        b.ctx.clearRect(0, 0, BLOCK, BLOCK);
        b.ctx.drawImage(bmp, 0, 0, BLOCK, BLOCK);
        b.rleType = null; b.palette = null;
        bmp.close?.();
        stats.jpeg++;
      } catch (e) {
        stats.jpegErrors++;
        if (stats.jpegErrors <= 3) console.warn(`JPEG 块 #${op.n} 解码失败:`, e.message);
      }
    }));

    // ---- pass C: RLE and copy blocks, in block order
    for (const op of ops) {
      if (op.kind === 'jpeg') continue;              // already decoded in pass B
      if (op.kind === 'rle') { this._decodeRle(op, buf); stats.rle++; }
      else if (op.kind === 'copy') {
        const src = this.blocks[op.refIdx];
        const b = this._block(op.n);
        b.ctx.clearRect(0, 0, BLOCK, BLOCK);
        if (src) { b.ctx.drawImage(src.canvas, 0, 0); b.rleType = src.rleType; b.palette = src.palette; }
        stats.copy++;
      } else if (op.kind === 'noop') stats.noop++;
      else stats.invalid++;
    }

    return stats;
  }

  _decodeRle(op, buf) {
    const b = this._block(op.n);
    const pixels = new Uint8ClampedArray(PIX * 4);
    let written = 0;

    // resolve palette
    let pal;
    if (op.ownPalette) {
      if (op.rleType === 0) pal = Uint8Array.from(buf.subarray(op.colorsAt, op.colorsAt + 3));
      else {
        const nCol = op.rleType === 1 ? 2 : op.rleType === 2 ? 3 : 4;
        pal = Uint8Array.from(buf.subarray(op.colorsAt, op.colorsAt + nCol * 3));
      }
    } else {
      const src = this.blocks[op.refIdx];
      pal = src && src.palette ? Uint8Array.from(src.palette) : new Uint8Array(op.inheritType === 1 ? 6 : op.inheritType === 2 ? 9 : 12);
      if (op.rotate && pal.length >= 6) {
        const rotated = [pal[3], pal[4], pal[5], pal[0], pal[1], pal[2]];
        pal.set(rotated, 0);
      }
    }

    const type = op.ownPalette ? op.rleType : op.inheritType;

    if (type === 0) {
      const [r, g, bl] = ycbcr2rgb(pal[0] ?? 0, pal[1] ?? 0, pal[2] ?? 0);
      for (let p = 0; p < PIX; p++) { const o = p * 4; pixels[o] = r; pixels[o + 1] = g; pixels[o + 2] = bl; pixels[o + 3] = 255; }
    } else if (type === 1) {
      const c1 = ycbcr2rgb(pal[0], pal[1], pal[2]);
      const c2 = ycbcr2rgb(pal[3], pal[4], pal[5]);
      let cur = c1, tmp = 0, lastnum = 0, m = op.dataAt, isLastCyc = false;
      const end = op.dataAt + op.len;
      let guard = 0;
      while ((m < end || isLastCyc) && written < PIX && guard++ < PIX * 2) {
        let mt = m;
        if (!isLastCyc && lastnum < 8 && mt < buf.length) {
          tmp = ((tmp & 0xffff) | ((buf[mt] & 0xff) << (8 - lastnum))) & 0xffff;
          lastnum += 8; mt++;
        }
        const run = ((tmp & 0xfc00) >> 10) + 1;
        tmp = (tmp << 6) & 0xffff; lastnum -= 6;
        let change = 0;
        if (run >= 64) { change = (tmp & 0x8000) >> 15; tmp = (tmp << 1) & 0xffff; lastnum -= 1; }
        for (let k = 0; k < run && written < PIX; k++, written++) {
          const o = written * 4; pixels[o] = cur[0]; pixels[o + 1] = cur[1]; pixels[o + 2] = cur[2]; pixels[o + 3] = 255;
        }
        if (change === 0) cur = (cur === c1) ? c2 : c1;
        if (isLastCyc || mt >= end) {
          if (isLastCyc) { mt++; isLastCyc = false; }
          if (tmp !== 0 || (lastnum !== 0 && written < PIX)) isLastCyc = true;
        }
        m = --mt;
      }
    } else {
      const cols = [];
      for (let c = 0; c < pal.length; c += 3) cols.push(ycbcr2rgb(pal[c], pal[c + 1], pal[c + 2]));
      for (let m = op.dataAt; m < op.dataAt + op.len && written < PIX; m++) {
        const v = buf[m];
        const run = ((v & 0xfc) >> 2) + 1;
        const col = cols[v & 3] || [0, 0, 0];
        for (let k = 0; k < run && written < PIX; k++, written++) {
          const o = written * 4; pixels[o] = col[0]; pixels[o + 1] = col[1]; pixels[o + 2] = col[2]; pixels[o + 3] = 255;
        }
      }
    }

    b.ctx.putImageData(new ImageData(pixels, BLOCK, BLOCK), 0, 0);
    b.rleType = type; b.palette = pal;
  }

  /** Composite the persistent block grid onto a canvas context. */
  drawTo(ctx) {
    for (let n = 0; n < this.blocks.length; n++) {
      const b = this.blocks[n];
      if (!b) continue;
      ctx.drawImage(b.canvas, (n % this.blockX) * BLOCK, ((n / this.blockX) | 0) * BLOCK);
    }
  }
}
