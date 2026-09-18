// Huawei iBMC KVM protocol — falsification probe.
// Read-only: only HEART_BEAT and GET_SUITE (queries). No input injection, no power, no VMM writes.
// Each case uses a FRESH TCP connection. Reports whether the BMC answered, and how.
import net from "node:net";
import fs from "node:fs";

const jnlpPath = process.argv[2];
const xml = fs.readFileSync(jnlpPath, "utf8");
const P = {};
for (const m of xml.matchAll(/<param\s+name="([^"]+)"\s+value="([^"]*)"\s*\/>/g)) P[m[1]] = m[2];
const host = (xml.match(/codebase="https?:\/\/([^"\/]+)/) || [])[1];
const port = Number(P.port || 2198);
const codeKey = parseInt(P.verifyValue, 10) | 0;

const TBL = new Int32Array(256);
for (let i = 0; i < 256; i++) { let w = i << 8; for (let j = 0; j < 8; j++) w = (w & 0x8000) ? ((w << 1) ^ 0x1021) & 0xffff : (w << 1) & 0xffff; TBL[i] = w; }
function crc16(buf) { let c = 0; for (const b of buf) c = (TBL[((c >> 8) & 0xff) ^ b] ^ ((c << 8) & 0xffff)) & 0xffff; return c; }

// ---------- hypothesis tests on the two received payloads ----------
const RX = {
  "0x43 suite list": Buffer.from("0000430003010000138802000027100300002710", "hex"),
  "0x08 connect": Buffer.from("0000080003000000", "hex"),
};
console.log("=== A. 接收帧前 2 字节是不是 CRC？ ===");
for (const [name, p] of Object.entries(RX)) {
  const stated = p.readUInt16BE(0);
  const over2 = crc16(p.subarray(2));
  const over3 = crc16(p.subarray(3));
  console.log(`${name} payload=${p.toString("hex")}`);
  console.log(`   前2字节=0x${stated.toString(16).padStart(4, "0")}  CRC16(payload[2..])=0x${over2.toString(16).padStart(4, "0")}  CRC16(payload[3..])=0x${over3.toString(16).padStart(4, "0")}`);
  console.log(`   → payload[2..] 假设: ${stated === over2 ? "命中 ✅" : "不成立 ❌"}`);
}

// ---------- frame builder with corruption knobs ----------
function buildGetSuite(opts = {}) {
  const payload = Buffer.from([0x42, 0x00]);
  const buf = Buffer.alloc(payload.length + 10);
  buf[0] = opts.magic1 ?? 0xfe;
  buf[1] = opts.magic2 ?? 0xf6;
  const lenField = (opts.lenOverride !== undefined) ? opts.lenOverride : payload.length + 2;
  buf.writeUInt16BE(lenField & 0xffff, 2);
  buf.writeInt32BE((opts.key !== undefined) ? opts.key : codeKey, 4);
  const c = (opts.crcOverride !== undefined) ? opts.crcOverride : crc16(payload);
  buf[8] = (c >> 8) & 0xff; buf[9] = c & 0xff;
  payload.copy(buf, 10);
  return buf;
}

function probe(label, frames, opts = {}) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    let acc = Buffer.alloc(0);
    let writeErr = null;
    const sentAt = [];
    sock.on("data", (chunk) => { acc = Buffer.concat([acc, chunk]); });
    sock.on("error", (e) => { writeErr = writeErr || (e.code || e.message); });
    const sent = [];
    setTimeout(() => {
      for (const f of frames) {
        try { sock.write(f); sent.push(f.length); }
        catch (e) { writeErr = writeErr || (e.code || e.message); }
        sentAt.push(Date.now());
      }
      if (opts.splitAfter) {
        // first half already written above; write the rest now
        const f = frames[0];
        // (frames[0] is the first half in this case)
      }
    }, 150);
    if (opts.split) {
      // send frames[0] in two halves 800ms apart
      setTimeout(() => { try { sock.write(frames[0]); sent.push(frames[0].length); } catch (e) { writeErr = writeErr || (e.code || e.message); } }, 150);
      setTimeout(() => { try { sock.write(frames[1]); sent.push(frames[1].length); } catch (e) { writeErr = writeErr || (e.code || e.message); } }, 950);
    }
    setTimeout(() => {
      // parse all FE F6 00 frames and verify tiling
      const framesOut = [];
      let i = 0, tiling = true, gapInfo = "";
      while (i + 4 <= acc.length) {
        if (!(acc[i] === 0xfe && acc[i + 1] === 0xf6 && acc[i + 2] === 0x00)) {
          const j = acc.indexOf(Buffer.from([0xfe, 0xf6, 0x00]), i);
          if (j < 0) { tiling = false; gapInfo = `偏移 ${i} 处不是帧头，剩余 ${acc.length - i} 字节`; break; }
          tiling = false; gapInfo = `偏移 ${i}..${j - 1} 有 ${j - i} 字节非帧数据`; i = j;
        }
        const dlen = acc[i + 3];
        if (i + 4 + dlen > acc.length) { tiling = false; gapInfo = `最后一帧声明 dlen=${dlen} 但只剩 ${acc.length - i - 4} 字节`; break; }
        framesOut.push({ cmd: acc[i + 6], dlen, payload: acc.subarray(i + 4, i + 4 + dlen) });
        i += 4 + dlen;
      }
      console.log(`\n--- ${label}`);
      console.log(`    收到原始 ${acc.length} 字节 → 解析出 ${framesOut.length} 帧` + (framesOut.length ? ` (cmd=${framesOut.map(f => "0x" + f.cmd.toString(16).padStart(2, "0")).join(",")})` : ""));
      console.log(`    分帧完整性: ${tiling ? "完美贴合 ✅" : "有缝 ❌ " + gapInfo}`);
      if (writeErr) console.log(`    写错误: ${writeErr}`);
      sock.destroy();
      resolve(framesOut.length);
    }, 3000);
  });
}

(async () => {
  console.log("\n=== B. 客户端帧各字段是否被 BMC 校验？（每例独立连接）===");
  const results = {};

  results["B1 基线：字段全对"] = await probe("B1 基线 GET_SUITE（预期收到 0x43）", [buildGetSuite()]);

  // two GET_SUITEs in one TCP write -> do we get two replies (multi-frame per read)?
  const g1 = buildGetSuite(), g2 = buildGetSuite();
  results["B2 一次 write 发两帧"] = await probe("B2 一次 write 发两个 GET_SUITE（预期 2 个 0x43）", [Buffer.concat([g1, g2])]);

  // frame split across two writes
  const gf = buildGetSuite();
  results["B3 一帧拆成两次 write"] = await probe("B3 同一帧拆两次 write（间隔 800ms）", [gf.subarray(0, 6), gf.subarray(6)]);

  results["B4 CRC 字段清零"] = await probe("B4 CRC 字段改成 0000（测试 CRC 是否被校验）", [buildGetSuite({ crcOverride: 0 })]);
  results["B5 codeKey 改成 0"] = await probe("B5 codeKey 改成 0（测试会话号是否被校验）", [buildGetSuite({ key: 0 })]);
  results["B6 codeKey 取反"] = await probe("B6 codeKey 全部取反", [buildGetSuite({ key: ~codeKey })]);
  results["B7 长度字段 +1"] = await probe("B7 长度字段改成 payload+3", [buildGetSuite({ lenOverride: 5 })]);
  results["B8 长度字段 -1"] = await probe("B8 长度字段改成 payload+1", [buildGetSuite({ lenOverride: 3 })]);
  results["B9 魔数改成 FE F5"] = await probe("B9 魔数改成 FE F5", [buildGetSuite({ magic2: 0xf5 })]);

  console.log("\n=== C. 汇总 ===");
  for (const [k, v] of Object.entries(results)) console.log(`  ${k}: ${v > 0 ? `BMC 有应答（${v} 帧）` : "BMC 无应答/无帧"}`);
  process.exit(0);
})();
