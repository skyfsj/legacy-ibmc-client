// Fresh-session capture + reassembly. Read-only: drives handshake and observes video.
// Saves everything to disk for offline decode. No input injection, no power, no VMM.
import net from "node:net";
import fs from "node:fs";
import crypto from "node:crypto";

const jnlpPath = process.argv[2];
const outDir = process.argv[3] || "/tmp/kvmlive";
const listenMs = Number(process.argv[4] || 25000);
fs.mkdirSync(outDir, { recursive: true });

const xml = fs.readFileSync(jnlpPath, "utf8");
const P = {};
for (const m of xml.matchAll(/<param\s+name="([^"]+)"\s+value="([^"]*)"\s*\/>/g)) P[m[1]] = m[2];
const host = (xml.match(/codebase="https?:\/\/([^"\/]+)/) || [])[1];
const port = Number(P.port || 2198);

const TBL = new Int32Array(256);
for (let i = 0; i < 256; i++) { let w = i << 8; for (let j = 0; j < 8; j++) w = (w & 0x8000) ? ((w << 1) ^ 0x1021) & 0xffff : (w << 1) & 0xffff; TBL[i] = w; }
const crc16 = (b) => { let c = 0; for (const x of b) c = (TBL[((c >> 8) & 0xff) ^ x] ^ ((c << 8) & 0xffff)) & 0xffff; return c; };

function packData(id, data) {
  const b = Buffer.alloc(data.length + 10);
  b[0] = 0xfe; b[1] = 0xf6; b.writeUInt16BE(data.length + 2, 2); b.writeInt32BE(id | 0, 4);
  const c = crc16(data); b[8] = c >> 8; b[9] = c & 0xff; data.copy(b, 10); return b;
}
function encrypPackData(id24, data, length) {
  const len = length & 0x7fff;
  const b = Buffer.alloc(len + 30);
  b[0] = 0xfe; b[1] = 0xf6; b.writeUInt16BE((length + 2) & 0xffff, 2);
  Buffer.from(id24).copy(b, 4);
  const c = crc16(data.subarray(0, len)); b[28] = c >> 8; b[29] = c & 0xff;
  data.subarray(0, len).copy(b, 30); return b;
}
function reverse4(buf) {                       // reverse each 4-byte group
  const k = Buffer.from(buf);
  for (let i = 0; i + 4 <= k.length; i += 4) { [k[i], k[i + 3]] = [k[i + 3], k[i]]; [k[i + 1], k[i + 2]] = [k[i + 2], k[i + 1]]; }
  return k;
}

const codeKey = parseInt(P.verifyValue, 10) | 0;
const decry = Buffer.from(P.decrykey, "hex");
const userKey = decry.subarray(0, 16), userIv = decry.subarray(16, 32);
const aesDec = (data, key, iv) => { const d = crypto.createDecipheriv("aes-128-cbc", key, iv); d.setAutoPadding(false); return Buffer.concat([d.update(data), d.final()]); };

let encodeKey = null, kvmKey = null, reconnKey = null;
let hmacName = "sha256", iterations = 10000;

const sock = net.connect({ host, port }, () => console.log("connected", host + ":" + port));
const sock_ok = { connected: false };
sock.on("connect", () => { sock_ok.connected = true; });

function send(buf, label) { sock.write(buf); console.log(`tx ${label} (${buf.length}B)`); }

// ---- server frame parser ----
let acc = Buffer.alloc(0);
const frames = [];
const rawFile = fs.createWriteStream(`${outDir}/server.bin`);
sock.on("data", (chunk) => {
  rawFile.write(chunk);                                  // 原始流落盘，供 kvm-analyze 使用
  acc = Buffer.concat([acc, chunk]);
  for (;;) {
    if (acc.length < 4) break;
    if (!(acc[0] === 0xfe && acc[1] === 0xf6 && acc[2] === 0x00)) {
      const j = acc.indexOf(Buffer.from([0xfe, 0xf6, 0x00]), 1);
      if (j < 0) { acc = acc.subarray(Math.max(0, acc.length - 2)); break; }
      acc = acc.subarray(j); continue;
    }
    const dlen = acc[3];
    if (dlen < 3 || dlen > 250) { acc = acc.subarray(1); continue; }
    if (acc.length < 4 + dlen) break;
    const payload = Buffer.from(acc.subarray(4, 4 + dlen));
    acc = acc.subarray(4 + dlen);
    onFrame(payload);
  }
});

let sentConnect = false, gotVideo = 0;
function onFrame(p) {
  const cmd = p[2], n = frames.length;
  frames.push(p);
  const interesting = [0x40, 0x43, 0x08, 0x28, 0x25, 0x04, 0x51, 0x64];
  if (interesting.includes(cmd) || gotVideo < 3) console.log(`rx #${n} cmd=0x${cmd.toString(16).padStart(2, "0")} dlen=${p.length} ${p.subarray(0, Math.min(40, p.length)).toString("hex")}`);

  if (cmd === 0x43) {                                   // suite list
    const count = p[4];
    let chosen = null;
    for (let k = 0; k < count; k++) { const algo = p[5 + k * 5], iter = p.readUInt32BE(6 + k * 5); if (algo === 3) chosen = { algo, iter }; }
    if (!chosen) chosen = { algo: 2, iter: 10000 };
    hmacName = chosen.algo === 3 ? "sha256" : "sha1"; iterations = chosen.iter;
    encodeKey = reverse4(crypto.pbkdf2Sync(Buffer.from(P.verifyValueExt, "utf8"), userIv, iterations, 24, hmacName));
    send(packData(codeKey, Buffer.from([0x44, 0x00, chosen.algo, (iterations >>> 24) & 0xff, (iterations >>> 16) & 0xff, (iterations >>> 8) & 0xff, iterations & 0xff])), "SET_SUITE");
    setTimeout(doConnect, 250);
  }
  if (cmd === 0x40) {                                   // KVM_KEY_SET
    const dataLen = p.length - 4;
    const ct = p.subarray(4);
    const pt = aesDec(ct, userKey, userIv);
    if (dataLen === 48) {
      const pwd = pt.subarray(0, 32).toString("latin1");
      const salt = pt.subarray(32, 48);
      kvmKey = reverse4(crypto.pbkdf2Sync(Buffer.from(pwd, "latin1"), salt, iterations, 48, hmacName));
      console.log(`  -> kvm_key = ${kvmKey.toString("hex")}`);
      console.log(`     (口令=32字节ASCII, salt=${salt.toString("hex")})`);
    } else if (dataLen === 128) {
      reconnKey = pt;
      console.log(`  -> reconnKey(128B) 拿到`);
    }
  }
  if (cmd === 0x08) {
    console.log(`  -> CONNECT_STATE = ${p[4]} ${p[4] === 0 ? "(接受 ✅)" : "(拒绝 ❌)"}`);
  }
  if (cmd === 0x02) gotVideo++;
}

function doConnect() {
  if (sentConnect) return; sentConnect = true;
  send(encrypPackData(encodeKey, Buffer.from([0x06, 0x00, 0x02, 0x01, 0x01]), 0x8005), "CONNECT_BLADE");
  setTimeout(() => send(packData(codeKey, Buffer.from([0x24, 0x00, 0x02, 0x00, 0x00])), "MOUSE_MODE_SET(2)"), 300);
  setTimeout(() => send(packData(codeKey, Buffer.from([0x1c, 35])), "VIDEO_RATE(35)"), 500);
}

setTimeout(() => send(packData(codeKey, Buffer.from([0x09, 0x00])), "HEARTBEAT"), 100);
setTimeout(() => send(packData(codeKey, Buffer.from([0x42, 0x00])), "GET_SUITE"), 250);
const hb = setInterval(() => { if (sock.writable && !sock.destroyed) send(packData(codeKey, Buffer.from([0x09, 0x00])), "HEARTBEAT"); }, 5000);

sock.on("error", (e) => console.log("sock error", e.code || e.message));
sock.on("close", () => console.log("socket closed"));

setTimeout(() => {
  clearInterval(hb);
  fs.writeFileSync(`${outDir}/frames.json`, JSON.stringify(frames.map(f => f.toString("base64"))));
  console.log(`\n=== 保存 ${frames.length} 个服务端帧到 ${outDir}/frames.json ===`);
  const byCmd = {};
  for (const f of frames) byCmd["0x" + f[2].toString(16).padStart(2, "0")] = (byCmd["0x" + f[2].toString(16).padStart(2, "0")] || 0) + 1;
  console.log("命令分布:", JSON.stringify(byCmd));
  const meta = { kvmKey: kvmKey ? kvmKey.toString("hex") : null, reconnKey: reconnKey ? reconnKey.toString("hex") : null, hmacName, iterations, width: null, height: null };
  fs.writeFileSync(`${outDir}/meta.json`, JSON.stringify(meta, null, 2));
  console.log("kvmKey saved:", meta.kvmKey);
  sock.destroy();
  process.exit(0);
}, listenMs);
