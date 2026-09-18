// Read-only Huawei iBMC KVM protocol probe.
// Performs the documented handshake and CAPTURES server frames for protocol validation.
// It sends no keyboard input, no mouse position, no power control, no virtual media writes.
import net from "node:net";
import fs from "node:fs";
import crypto from "node:crypto";

const jnlpPath = process.argv[2];
const outPrefix = process.argv[3] || "/tmp/kvmcap";
const listenMs = Number(process.argv[4] || 20000);

const xml = fs.readFileSync(jnlpPath, "utf8");
const P = {};
for (const m of xml.matchAll(/<param\s+name="([^"]+)"\s+value="([^"]*)"\s*\/>/g)) P[m[1]] = m[2];
const host = (xml.match(/codebase="https?:\/\/([^"\/]+)/) || [])[1];
const port = Number(P.port || 2198);
const blade = 0;

console.log("=== session params ===");
console.log("host", host, "port", port, "compress", P.compress, "vmm_compress", P.vmm_compress);
console.log("verifyValue", P.verifyValue, "verifyValueExt", P.verifyValueExt, "decrykey len", (P.decrykey || "").length);

// ---- CRC-16/CCITT-FALSE (poly 0x1021, init 0, no reflect, no xorout) ----
const TBL = new Int32Array(256);
for (let i = 0; i < 256; i++) { let w = i << 8; for (let j = 0; j < 8; j++) w = (w & 0x8000) ? ((w << 1) ^ 0x1021) & 0xffff : (w << 1) & 0xffff; TBL[i] = w; }
function crc16(buf) { let c = 0; for (const b of buf) c = (TBL[((c >> 8) & 0xff) ^ b] ^ ((c << 8) & 0xffff)) & 0xffff; return c; }

// ---- frame builders ----
function packData(id, data) {
  const buf = Buffer.alloc(data.length + 10);
  buf[0] = 0xfe; buf[1] = 0xf6;
  buf.writeUInt16BE(data.length + 2, 2);
  buf.writeInt32BE(id | 0, 4);
  const c = crc16(data);
  buf[8] = (c >> 8) & 0xff; buf[9] = c & 0xff;
  data.copy(buf, 10);
  return buf;
}
function encrypPackData(id24, data, length) {
  const len = length & 0x7fff;
  const buf = Buffer.alloc(len + 30);
  buf[0] = 0xfe; buf[1] = 0xf6;
  buf.writeUInt16BE((length + 2) & 0xffff, 2);
  Buffer.from(id24).copy(buf, 4);
  const c = crc16(data.subarray(0, len));
  buf[28] = (c >> 8) & 0xff; buf[29] = c & 0xff;
  data.subarray(0, len).copy(buf, 30);
  return buf;
}

// ---- session material ----
const codeKey = parseInt(P.verifyValue, 10) | 0;
const decry = Buffer.from(P.decrykey, "hex");
const userKey = decry.subarray(0, 16), userIv = decry.subarray(16, 32);
let encodeKey = null;

function deriveEncodeKey(iterations, hmacName) {
  const raw = crypto.pbkdf2Sync(Buffer.from(P.verifyValueExt, "utf8"), userIv, iterations, 24, hmacName);
  const k = Buffer.from(raw);
  for (let i = 0; i < 6; i++) {                 // reverse each 4-byte group
    const j = i * 4;
    [k[j], k[j + 3]] = [k[j + 3], k[j]];
    [k[j + 1], k[j + 2]] = [k[j + 2], k[j + 1]];
  }
  return k;
}

let seenSuite = false, sentConnect = false;
const sock = net.connect({ host, port }, () => console.log("\n=== TCP connected to", host + ":" + port, "==="));

const serverRaw = fs.createWriteStream(outPrefix + "-server.bin");
const clientRaw = fs.createWriteStream(outPrefix + "-client.bin");
let frameIdx = 0, imageFrames = [];

function send(buf, label) {
  clientRaw.write(buf);
  sock.write(buf);
  console.log(`tx ${label} (${buf.length}B) ${buf.subarray(0, Math.min(40, buf.length)).toString("hex")}`);
}

// ---- server stream parser: FE F6 00 | len(<=250) | payload(len) ----
let acc = Buffer.alloc(0);
sock.on("data", (chunk) => {
  serverRaw.write(chunk);
  acc = Buffer.concat([acc, chunk]);
  for (;;) {
    let i = -1;
    for (let j = 0; j + 3 < acc.length; j++) if (acc[j] === 0xfe && acc[j + 1] === 0xf6 && acc[j + 2] === 0x00) { i = j; break; }
    if (i < 0) { if (acc.length > 3) acc = acc.subarray(acc.length - 3); break; }
    if (i > 0) acc = acc.subarray(i);
    if (acc.length < 4) break;
    const dlen = acc[3];
    if (dlen < 3 || dlen > 250) { acc = acc.subarray(1); continue; }
    if (acc.length < 4 + dlen) break;
    const payload = acc.subarray(4, 4 + dlen);
    acc = acc.subarray(4 + dlen);
    onFrame(Buffer.from(payload));
  }
});

function onFrame(payload) {
  const cmd = payload[2], p1 = payload[3];
  const n = frameIdx++;
  if (n < 40) console.log(`rx #${n} cmd=0x${cmd.toString(16).padStart(2, "0")} band=${p1} dlen=${payload.length} ${payload.subarray(0, Math.min(64, payload.length)).toString("hex")}`);
  else if (n % 50 === 0) console.log(`rx #${n} cmd=0x${cmd.toString(16).padStart(2, "0")} dlen=${payload.length} (streaming...)`);

  if (cmd === 0x43) {                              // suite list
    const count = payload[4];
    console.log(`  -> suite list: count=${count} (len check ${count * 5 + 3} vs ${payload.length - 2})`);
    let chosen = null;
    for (let k = 0; k < count; k++) {
      const algo = payload[5 + k * 5];
      const iter = payload.readUInt32BE(6 + k * 5);
      console.log(`     algo=${algo} iterations=${iter}`);
      if (algo === 3) chosen = { algo, iter };
    }
    if (!chosen) chosen = { algo: 2, iter: 10000 };
    encodeKey = deriveEncodeKey(chosen.iter, chosen.algo === 3 ? "sha256" : "sha1");
    console.log(`  -> encodeKey=${encodeKey.toString("hex")} (algo=${chosen.algo} iter=${chosen.iter})`);
    send(packData(codeKey, Buffer.from([0x44, blade, chosen.algo, (chosen.iter >>> 24) & 0xff, (chosen.iter >>> 16) & 0xff, (chosen.iter >>> 8) & 0xff, chosen.iter & 0xff])), "SET_SUITE");
    seenSuite = true;
    setTimeout(connectStep, 300);
  }
  if (cmd === 0x02) {                              // image data
    imageFrames.push(Buffer.from(payload));
    if (imageFrames.length <= 12) {
      console.log(`  -> IMAGE frame #${imageFrames.length} dlen=${payload.length} sub=${payload.subarray(2, 10).toString("hex")}`);
    }
  }
}

function connectStep() {
  if (sentConnect) return;
  sentConnect = true;
  // connectBlade(blade, colorBit) with compress=1: payload {6,blade,colorBit,1,1}, length 0x8005
  const data = Buffer.from([0x06, blade, 2, 0x01, 0x01]);
  send(encrypPackData(encodeKey, data, 0x8005), "CONNECT_BLADE(compressed)");
  setTimeout(() => send(packData(codeKey, Buffer.from([0x24, 0x00, 0x02, 0x00, 0x00])), "MOUSE_MODE_SET(2)"), 200);
  setTimeout(() => send(packData(codeKey, Buffer.from([0x1c, 35])), "VIDEO_RATE(35)"), 400);
}

// initial handshake
setTimeout(() => send(packData(codeKey, Buffer.from([0x09, 0x00])), "HEARTBEAT"), 100);
setTimeout(() => send(packData(codeKey, Buffer.from([0x42, blade])), "GET_SUITE"), 300);

const hb = setInterval(() => { if (sock.writable) send(packData(codeKey, Buffer.from([0x09, 0x00])), "HEARTBEAT"); }, 5000);

setTimeout(() => {
  clearInterval(hb);
  console.log(`\n=== capture summary ===`);
  console.log(`total server frames: ${frameIdx}, image frames: ${imageFrames.length}`);
  const byCmd = {};
  for (const f of imageFrames) byCmd[f[2]] = (byCmd[f[2]] || 0) + 1;
  if (imageFrames.length) {
    fs.writeFileSync(outPrefix + "-imageframes.json", JSON.stringify(imageFrames.map(f => f.toString("base64"))));
    console.log("image frames written to", outPrefix + "-imageframes.json");
  }
  sock.end();
  sock.destroy();
  process.exit(0);
}, listenMs);
sock.on("error", (e) => console.log("socket error", e.code || e.message));
sock.on("close", () => console.log("socket closed"));
