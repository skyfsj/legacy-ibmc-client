// Follow-up: does the BMC reassemble a client frame split across TCP writes?
// Read-only: GET_SUITE only.
import net from "node:net";
import fs from "node:fs";

const xml = fs.readFileSync(process.argv[2], "utf8");
const P = {};
for (const m of xml.matchAll(/<param\s+name="([^"]+)"\s+value="([^"]*)"\s*\/>/g)) P[m[1]] = m[2];
const host = (xml.match(/codebase="https?:\/\/([^"\/]+)/) || [])[1];
const port = Number(P.port || 2198);
const codeKey = parseInt(P.verifyValue, 10) | 0;

const TBL = new Int32Array(256);
for (let i = 0; i < 256; i++) { let w = i << 8; for (let j = 0; j < 8; j++) w = (w & 0x8000) ? ((w << 1) ^ 0x1021) & 0xffff : (w << 1) & 0xffff; TBL[i] = w; }
const crc16 = (buf) => { let c = 0; for (const b of buf) c = (TBL[((c >> 8) & 0xff) ^ b] ^ ((c << 8) & 0xffff)) & 0xffff; return c; };

function getSuiteFrame() {
  const payload = Buffer.from([0x42, 0x00]);
  const buf = Buffer.alloc(12);
  buf[0] = 0xfe; buf[1] = 0xf6; buf.writeUInt16BE(4, 2); buf.writeInt32BE(codeKey, 4);
  const c = crc16(payload); buf[8] = c >> 8; buf[9] = c & 0xff; payload.copy(buf, 10);
  return buf;
}

// split the 12-byte frame at `at`, with `gapMs` between the two writes
function caseSplit(label, at, gapMs) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    let acc = Buffer.alloc(0);
    sock.on("data", (c) => { acc = Buffer.concat([acc, c]); });
    sock.on("error", () => {});
    const f = getSuiteFrame();
    setTimeout(() => { sock.write(f.subarray(0, at)); }, 150);
    setTimeout(() => { sock.write(f.subarray(at)); }, 150 + gapMs);
    setTimeout(() => {
      const ok = acc.length > 0 && acc[0] === 0xfe;
      console.log(`  ${label.padEnd(42)} 切点=${String(at).padStart(2)} 间隔=${String(gapMs).padStart(4)}ms → ${ok ? "有应答 ✅" : "无应答 ❌"}`);
      sock.destroy(); resolve(ok);
    }, 2500);
  });
}

// repeat a case N times to check for flakiness
function caseRepeat(label, fn, n) {
  return new Promise(async (resolve) => {
    let ok = 0;
    for (let i = 0; i < n; i++) ok += (await fn()) ? 1 : 0;
    console.log(`  ${label.padEnd(42)} ${ok}/${n} 次有应答`);
    resolve(ok);
  });
}

function caseWhole(label, gapMs) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    let acc = Buffer.alloc(0);
    sock.on("data", (c) => { acc = Buffer.concat([acc, c]); });
    sock.on("error", () => {});
    setTimeout(() => { sock.write(getSuiteFrame()); }, 150);
    setTimeout(() => {
      const ok = acc.length > 0;
      console.log(`  ${label.padEnd(42)} → ${ok ? "有应答 ✅" : "无应答 ❌"}`);
      sock.destroy(); resolve(ok);
    }, 2500);
  });
}

(async () => {
  console.log("=== 整帧基线（重复 5 次，确认链路稳定）===");
  await caseRepeat("整帧一次 write", () => caseWhole("", 0), 5);

  console.log("\n=== 切点扫描（间隔 300ms，确认分片是否被重组）===");
  for (const at of [2, 4, 6, 8, 10, 11]) await caseSplit(`切在偏移 ${at}`, at, 300);

  console.log("\n=== 小间隔（可能被 TCP 合并成一个段）===");
  for (const gap of [0, 1, 5, 20, 60]) await caseSplit(`切在偏移 6`, 6, gap);

  console.log("\n=== 切点 6 重复 3 次（300ms，确认不是偶发）===");
  await caseRepeat("切在偏移 6, 300ms", () => caseSplit("", 6, 300), 3);

  console.log("\n=== CRC 字段被忽略：重复 3 次确认 ===");
  await new Promise(async (resolve) => {
    let ok = 0;
    for (let i = 0; i < 3; i++) {
      const r = await new Promise((res) => {
        const sock = net.connect({ host, port });
        let acc = Buffer.alloc(0);
        sock.on("data", (c) => { acc = Buffer.concat([acc, c]); });
        sock.on("error", () => {});
        const f = getSuiteFrame(); f[8] = 0; f[9] = 0;      // CRC = 0000
        setTimeout(() => sock.write(f), 150);
        setTimeout(() => { const o = acc.length > 0; sock.destroy(); res(o); }, 2500);
      });
      ok += r ? 1 : 0;
    }
    console.log(`  CRC=0000                                   ${ok}/3 次有应答 → BMC ${ok === 3 ? "不校验 CRC" : "可能校验"}`);
    resolve();
  });
  process.exit(0);
})();
