// Offline analysis of a captured Huawei iBMC KVM server stream.
import fs from "node:fs";
import crypto from "node:crypto";

const streamPath = process.argv[2];
const jnlpPath = process.argv[3];
const outDir = process.argv[4] || "/tmp/kvmanalyze";
fs.mkdirSync(outDir, { recursive: true });

const buf = fs.readFileSync(streamPath);
const xml = fs.readFileSync(jnlpPath, "utf8");
const P = {};
for (const m of xml.matchAll(/<param\s+name="([^"]+)"\s+value="([^"]*)"\s*\/>/g)) P[m[1]] = m[2];
const decry = Buffer.from(P.decrykey, "hex");
const userKey = decry.subarray(0, 16), userIv = decry.subarray(16, 32);

const aesDec = (data, key, iv) => { const d = crypto.createDecipheriv("aes-128-cbc", key, iv); d.setAutoPadding(false); return Buffer.concat([d.update(data), d.final()]); };
const reverse4 = (b) => { const k = Buffer.from(b); for (let i = 0; i + 4 <= k.length; i += 4) { [k[i], k[i + 3]] = [k[i + 3], k[i]]; [k[i + 1], k[i + 2]] = [k[i + 2], k[i + 1]]; } return k; };

// --- parse frames: FE F6 00 | dlen | payload ---
const frames = [];
let i = 0;
while (i + 4 <= buf.length) {
  if (!(buf[i] === 0xfe && buf[i + 1] === 0xf6 && buf[i + 2] === 0x00)) {
    const j = buf.indexOf(Buffer.from([0xfe, 0xf6, 0x00]), i);
    console.log(`!! 偏移 ${i} 不是帧头，跳到 ${j}`);
    if (j < 0) break;
    i = j; continue;
  }
  const dlen = buf[i + 3];
  if (i + 4 + dlen > buf.length) { console.log(`!! 末帧不完整: 偏移 ${i} dlen=${dlen} 剩余=${buf.length - i - 4}`); break; }
  frames.push(buf.subarray(i + 4, i + 4 + dlen));
  i += 4 + dlen;
}
console.log(`解析出 ${frames.length} 帧，消耗 ${i}/${buf.length} 字节 ${i === buf.length ? "（完美贴合 ✅）" : "（有剩余）"}`);
const byCmd = {};
for (const f of frames) { const c = "0x" + f[2].toString(16).padStart(2, "0"); byCmd[c] = (byCmd[c] || 0) + 1; }
console.log("命令分布:", JSON.stringify(byCmd));

// --- derive kvm_key from 0x40 ---
let kvmKey = null, reconnKey = null;
// suite negotiation was algo=3 / 10000 in this session
const hmacName = "sha256", iterations = 10000;
for (const p of frames) {
  if (p[2] !== 0x40) continue;
  const dataLen = p.length - 4;
  const pt = aesDec(p.subarray(4), userKey, userIv);
  if (dataLen === 48) {
    const pwd = pt.subarray(0, 32).toString("latin1");
    const salt = pt.subarray(32, 48);
    console.log(`\n[0x40 / 48B] 解密后 32 字节口令 = ${JSON.stringify(pwd)}`);
    console.log(`             16 字节 salt     = ${salt.toString("hex")}`);
    kvmKey = reverse4(crypto.pbkdf2Sync(Buffer.from(pwd, "latin1"), salt, iterations, 48, hmacName));
    console.log(`             kvm_key(48B)     = ${kvmKey.toString("hex")}`);
    console.log(`               [0..15]  数据密钥 = ${kvmKey.subarray(0, 16).toString("hex")}`);
    console.log(`               [16..31] 键盘密钥 = ${kvmKey.subarray(16, 32).toString("hex")}`);
    console.log(`               [32..47] IV       = ${kvmKey.subarray(32, 48).toString("hex")}`);
  } else if (dataLen === 128) {
    reconnKey = pt;
    console.log(`\n[0x40 / 128B] 重连密钥 = ${pt.subarray(0, 32).toString("hex")}... (共 ${pt.length}B)`);
  }
}

// --- reassemble 0x02 image sub-packets ---
// unPackData[i] = payload[i+2]; currentData = unPackData
//   seq = currentData[2..3] = payload[4..5]   frameNum = currentData[4] = payload[6]
//   seq==0 -> plaintext, imageData = payload[4..]
//   seq!=0 -> len = payload[7], pt = AES-dec(payload[8..], kvmKey[0:16], kvmKey[32:48])
//             imageData = payload[4..7) ++ pt[0..len)
const sub = [];   // { frameNo, seq, imageData }
for (const p of frames) {
  if (p[2] !== 0x02) continue;
  const seq = p.readUInt16BE(4), frameNo = p[6];
  let imageData;
  if (seq === 0) {
    imageData = Buffer.from(p.subarray(4));
  } else {
    if (!kvmKey) { console.log("!! 没有 kvm_key，无法解密子包"); continue; }
    const len = p[7];
    const ct = p.subarray(8);
    if (ct.length % 16 !== 0) { console.log(`!! #${seq} 密文长度 ${ct.length} 不是 16 的倍数`); continue; }
    const pt = aesDec(ct, kvmKey.subarray(0, 16), kvmKey.subarray(32, 48));
    imageData = Buffer.concat([p.subarray(4, 7), pt.subarray(0, len)]);
  }
  sub.push({ frameNo, seq, imageData, dlen: p.length });
}

// group by frameNo
const byFrame = new Map();
for (const s of sub) { if (!byFrame.has(s.frameNo)) byFrame.set(s.frameNo, []); byFrame.get(s.frameNo).push(s); }

console.log(`\n=== 图像子包：共 ${sub.length} 个，分属 ${byFrame.size} 个帧 ===`);
for (const [fn, list] of [...byFrame].sort((a, b) => a[0] - b[0])) {
  list.sort((a, b) => a.seq - b.seq);
  const seqs = list.map(s => s.seq);
  const contiguous = seqs.every((v, idx) => v === idx);
  const hdr = list[0].imageData;
  const len = hdr.readUInt32BE(3);
  const flags = hdr[7];
  const width = ((flags & 0x7f) << 8) | hdr[8];
  const height = hdr.readUInt16BE(9);
  const chunk = hdr[11];
  const rx = hdr.readUInt16BE(12), ry = hdr.readUInt16BE(14);
  const dqt = hdr[16] & 0x0f, iframe = (hdr[16] >> 7) & 1;
  const sumData = list.reduce((a, s) => a + s.imageData.length - 3, 0);
  console.log(`帧 ${String(fn).padStart(3)}: 子包 ${list.length} 个 序号 ${seqs[0]}..${seqs[seqs.length - 1]} ${contiguous ? "连续 ✅" : "有缺口 ❌"}`);
  console.log(`        声明总长=${len}  实际各子包数据之和=${sumData}  ${len + 1 === sumData ? "(差1)" : len === sumData ? "(相等)" : "(不等!)"}`);
  console.log(`        ${width}x${height}  差分=${(flags >> 7) & 1}  块高字节=${chunk}  remoteX/Y=${rx}/${ry}  DQT=${dqt} I帧=${iframe}`);
  // combine(): data[0]=diffFlag, then concat(list[i][3..]) for i>=1  (list[0] 只用于解析帧头)
  const parts = [Buffer.from([(flags >> 7) & 1])];
  for (const s of list.slice(1)) parts.push(s.imageData.subarray(3));
  const combined = Buffer.concat(parts);
  fs.writeFileSync(`${outDir}/frame-${fn}.bin`, combined);
  console.log(`        重组缓冲 ${combined.length} 字节 → frame-${fn}.bin（声明 ${len + 1}，尾部零填充 ${(len + 1) - combined.length} 字节）`);
  console.log(`        前 48 字节: ${combined.subarray(0, 48).toString("hex")}`);
}
console.log("\n输出目录:", outDir);
