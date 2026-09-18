// Walk the reassembled block stream of a frame using the ImageDecoder rules,
// and verify it consumes exactly the available bytes and produces 4096 pixels per RLE block.
import fs from "node:fs";

const path = process.argv[2];
const b = fs.readFileSync(path);
const W = 800, H = 600;
const blockX = Math.ceil(W / 64), blockY = Math.ceil(H / 64);
const nBlocks = blockX * blockY;
console.log(`缓冲 ${b.length} 字节；${W}x${H} → 块网格 ${blockX}x${blockY} = ${nBlocks} 块`);
console.log(`blockCutWidth=${64 - (blockX * 64 - W)}  blockCutHeight=${64 - (blockY * 64 - H)}`);
console.log(`[0]=${b[0]} (差分标志), 块流从 index 1 开始\n`);

const u16 = (i) => (b[i] << 8) | b[i + 1];
const rleTypes = [];      // per block: rleType of that block (needed for 4..7 inheritance)
const blockInfo = [];
let i = 1, n = 0, ok = true;

function rleSyclen(i, rleType, hasPalette) {
  // returns {syclen, pix, colors, note}
  if (rleType === 0) {
    // solid fill: palette present only when hasPalette (i.e. not inherited)
    const cols = hasPalette ? b.subarray(i + 1, i + 4) : null;
    return { syclen: hasPalette ? 4 : 1, pix: 4096, colors: cols, note: "纯色填充", pal: hasPalette ? 1 : 0 };
  }
  const len = u16(i + 1);
  const palN = { 1: 2, 2: 3, 3: 4 }[rleType] ?? 0;
  const palBytes = hasPalette ? palN * 3 : 0;
  const dataAt = i + 3 + palBytes;
  // decode bitstream to count pixels
  let pix = 0;
  if (rleType === 1) {
    let tmp = 0, lastnum = 0, m = dataAt, isLast = false;
    while (m < dataAt + len) {
      let mt = m;
      if (!isLast && lastnum < 8) { tmp = (tmp & 0xffff) | ((b[mt] & 0xff) << (8 - lastnum)); lastnum += 8; mt++; }
      let sub = ((tmp & 0xfc00) >> 10) + 1;
      tmp = (tmp << 6) & 0xffff; lastnum -= 6;
      if (sub >= 64) { tmp = (tmp << 1) & 0xffff; lastnum -= 1; }
      pix += sub;
      if (isLast || mt >= dataAt + len) { if (isLast) { mt++; isLast = false; } if (tmp !== 0 || (lastnum !== 0 && pix < 4096)) isLast = true; }
      m = --mt;
    }
  } else {
    // types 2/3: 6-bit run + 2-bit index
    for (let m = dataAt; m < dataAt + len; m++) pix += ((b[m] & 0xfc) >> 2) + 1;
  }
  return { syclen: 3 + palBytes + len, pix, colors: null, note: `RLE 类型${rleType}`, pal: palN };
}

while (i < b.length && n < nBlocks) {
  const desc = b[i], zipType = (desc & 0xe0) >> 5, rZipType = (desc & 0x1c) >> 2;
  let syclen, note = "", pix = null, pal = 0, rleType = null;
  if (zipType === 0 || zipType === 1) {
    let type = rZipType, hasPal = true;
    if (rZipType >= 4 && rZipType <= 7) {
      const src = (rZipType === 4 || rZipType === 5) ? n - 1 : n - blockX;
      if (src < 0) { ok = false; note = `引用越界 src=${src}`; syclen = 1; }
      else {
        rleType = rleTypes[src];
        hasPal = (rleType !== 0) && (rZipType === 4 || rZipType === 6 || rZipType === 5 || rZipType === 7);
        // 4/6: 若源为纯色 → syclen=1；否则复用其调色板（不再读调色板）
        if (rleType === 0 && (rZipType === 4 || rZipType === 6)) { syclen = 1; note = `复制块${rZipType}（源为纯色）`; rleType = 0; }
        else { const r = rleSyclen(i, rleType, false); syclen = r.syclen; pix = r.pix; note = `复制块${rZipType}（继承类型${rleType}）`; }
      }
    } else {
      const r = rleSyclen(i, rZipType, true);
      syclen = r.syclen; pix = r.pix; pal = r.pal; note = r.note; rleType = rZipType;
    }
    rleTypes[n] = rleType;
  } else if (zipType === 2 || zipType === 3) {
    const len = u16(i + 1);
    syclen = 3 + len;
    note = `JPEG 块（裸扫描 ${len} 字节）`;
    rleTypes[n] = null;
  } else if (zipType === 4) { syclen = 1; note = "空操作"; rleTypes[n] = null; }
  else if (zipType === 5) { const src = n - blockX; rleTypes[n] = src >= 0 ? rleTypes[src] : null; syclen = 1; note = "复制上一行块"; }
  else { const src = n - 1; rleTypes[n] = src >= 0 ? rleTypes[src] : null; syclen = 1; note = "复制左邻块"; }
  if (i + syclen > b.length) { ok = false; note += ` !! 越界 (需要 ${syclen}, 只剩 ${b.length - i})`; }
  blockInfo.push({ n, i, zipType, rZipType, syclen, pix, pal, note });
  if (n < 25 || n >= nBlocks - 5 || (pix !== null && pix !== 4096)) {
    console.log(`块#${String(n).padStart(3)} @${String(i).padStart(5)} zip=${zipType} rle=${rZipType} syclen=${String(syclen).padStart(4)} 像素=${pix ?? "-"} 调色板=${pal}  ${note}`);
  }
  i += syclen; n++;
}

console.log(`\n=== 结果 ===`);
console.log(`走完 ${n}/${nBlocks} 块，块流结束于 offset ${i}，缓冲长度 ${b.length}`);
console.log(`是否恰好消耗完: ${i === b.length ? "✅ 完全吻合" : `❌ 差 ${b.length - i} 字节`}`);
const types = {};
for (const bl of blockInfo) { const k = `${bl.zipType}/${bl.rZipType}`; types[k] = (types[k] || 0) + 1; }
console.log("块类型分布 (zipType/rZipType: 数量):", JSON.stringify(types, null, 0));
const bad = blockInfo.filter(x => x.pix !== null && x.pix !== 4096);
console.log(`像素数不等于 4096 的 RLE 块: ${bad.length} 个`);
if (bad.length) console.log("  样例:", bad.slice(0, 5).map(x => `#${x.n} zip=${x.zipType}/rle=${x.rZipType} pix=${x.pix}`).join(", "));
fs.writeFileSync(process.argv[2].replace(/\.bin$/, ".blocks.json"), JSON.stringify(blockInfo));
