'use strict';
// Huawei iBMC KVM protocol core — frame codec, CRC, key derivation.
// Byte layouts here were validated against a real BMC; see the protocol notes in
// ../../huawei-ibmc-kvm-protocol/ (01-transport-and-frames.md, 02-handshake-and-crypto.md).

const crypto = require('node:crypto');

// ---- CRC-16/CCITT-FALSE: poly 0x1021, init 0, no reflection, no final xor ----
const CRC_TABLE = new Int32Array(256);
for (let i = 0; i < 256; i++) {
  let w = i << 8;
  for (let j = 0; j < 8; j++) w = (w & 0x8000) ? ((w << 1) ^ 0x1021) & 0xffff : (w << 1) & 0xffff;
  CRC_TABLE[i] = w;
}
function crc16(buf) {
  let c = 0;
  for (const b of buf) c = (CRC_TABLE[((c >> 8) & 0xff) ^ b] ^ ((c << 8) & 0xffff)) & 0xffff;
  return c;
}

// ---- AES-128-CBC with NO padding (protocol uses zero padding, length is explicit) ----
function aesEncrypt(src, key, iv) {
  const c = crypto.createCipheriv('aes-128-cbc', key, iv);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(src), c.final()]);
}
function aesDecrypt(src, key, iv) {
  const d = crypto.createDecipheriv('aes-128-cbc', key, iv);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(src), d.final()]);
}
/** Zero-pad to the next 16-byte boundary (the vendor client does this before every encrypt). */
function zeroPad(buf) {
  const n = Math.ceil(buf.length / 16) * 16;
  if (n === buf.length) return Buffer.from(buf);
  const out = Buffer.alloc(n);
  Buffer.from(buf).copy(out);
  return out;
}

/** Reverse the bytes inside each 4-byte group. The protocol applies this to every PBKDF2 result. */
function reverse4(buf) {
  const k = Buffer.from(buf);
  for (let i = 0; i + 4 <= k.length; i += 4) {
    [k[i], k[i + 3]] = [k[i + 3], k[i]];
    [k[i + 1], k[i + 2]] = [k[i + 2], k[i + 1]];
  }
  return k;
}

const HMAC_NAME = { 2: 'sha1', 3: 'sha256' };

/** encodeKey = PBKDF2(verifyValueExt, salt=user_iv, iterations, 24) then 4-byte-group reversed. */
function deriveEncodeKey(verifyValueExt, userIv, iterations, algo) {
  const raw = crypto.pbkdf2Sync(Buffer.from(verifyValueExt, 'utf8'), userIv, iterations, 24, HMAC_NAME[algo] || 'sha256');
  return reverse4(raw);
}

/**
 * kvm_key (48 bytes) from the 48-byte KVM_KEY_SET plaintext:
 *   [0..31]  = 32 ASCII chars -> PBKDF2 password
 *   [32..47] = 16 bytes       -> salt
 * result = PBKDF2(pwd, salt, iterations, 48) then 4-byte-group reversed.
 * Layout: [0:16] data key, [16:32] keyboard key, [32:48] shared IV.
 */
function deriveKvmKey(plain48, iterations, algo) {
  const pwd = Buffer.from(plain48.subarray(0, 32).toString('latin1'), 'latin1');
  const salt = plain48.subarray(32, 48);
  return reverse4(crypto.pbkdf2Sync(pwd, salt, iterations, 48, HMAC_NAME[algo] || 'sha256'));
}

// ---- client -> BMC frames ----
const MAGIC = [0xfe, 0xf6];

/** FE F6 | len(payload+2) | codeKey i32be | crc16 | payload */
function buildFrame(codeKey, payload) {
  const buf = Buffer.alloc(payload.length + 10);
  buf[0] = MAGIC[0]; buf[1] = MAGIC[1];
  buf.writeUInt16BE(payload.length + 2, 2);
  buf.writeInt32BE(codeKey | 0, 4);
  const c = crc16(payload);
  buf[8] = c >> 8; buf[9] = c & 0xff;
  Buffer.from(payload).copy(buf, 10);
  return buf;
}

/**
 * CONNECT_BLADE / "compressed" variant:
 * FE F6 | (length+2) with 0x8000 set | 24-byte encodeKey | crc16 | payload
 * `length` is the un-masked value (e.g. 0x8005), so the length field becomes 0x8007.
 */
function buildEncryptedFrame(encodeKey24, payload, length) {
  const len = length & 0x7fff;
  const buf = Buffer.alloc(len + 30);
  buf[0] = MAGIC[0]; buf[1] = MAGIC[1];
  buf.writeUInt16BE((length + 2) & 0xffff, 2);
  Buffer.from(encodeKey24).copy(buf, 4);
  const c = crc16(payload.subarray(0, len));
  buf[28] = c >> 8; buf[29] = c & 0xff;
  Buffer.from(payload).subarray(0, len).copy(buf, 30);
  return buf;
}

// ---- BMC -> client frame parser: FE F6 00 | dlen(1B, 3..250) | payload ----
class ServerFrameParser {
  constructor() { this.buf = Buffer.alloc(0); }
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : Buffer.from(chunk);
    const out = [];
    for (;;) {
      if (this.buf.length < 4) break;
      if (!(this.buf[0] === 0xfe && this.buf[1] === 0xf6 && this.buf[2] === 0x00)) {
        const j = this.buf.indexOf(Buffer.from([0xfe, 0xf6, 0x00]), 1);
        if (j < 0) { this.buf = this.buf.subarray(Math.max(0, this.buf.length - 2)); break; }
        this.buf = this.buf.subarray(j);
        continue;
      }
      const dlen = this.buf[3];
      if (dlen < 3 || dlen > 250) { this.buf = this.buf.subarray(1); continue; }
      if (this.buf.length < 4 + dlen) break;
      out.push(Buffer.from(this.buf.subarray(4, 4 + dlen)));
      this.buf = this.buf.subarray(4 + dlen);
    }
    return out;
  }
}

/** Suite list: payload = 00 00 | 43 | blade | count | (algo:1 + iterations:u32be) * count */
function parseSuiteList(p) {
  const count = p[4];
  const suites = [];
  for (let k = 0; k < count; k++) {
    suites.push({ algo: p[5 + k * 5], iterations: p.readUInt32BE(6 + k * 5) });
  }
  return { count, suites, lengthOk: count * 5 + 3 === p.length - 2 };
}

// ---- command codes (client -> BMC) ----
const CMD = {
  KEY_PACK: 0x03, KEY_STATE: 0x04, MOUSE_PACK: 0x05,
  CONNECT_BLADE: 0x06, INTERRUPT_BLADE: 0x07, I_REQ: 0x08, HEART_BEAT: 0x09,
  REQ_BLADE_PRESENT: 0x0b, REQ_BLADE_STATE: 0x14,
  REQ_BLADE_MONITOR: 0x17, INTERRUPT_MONITOR: 0x18, DELETE_USER: 0x19,
  REPLAY_SMM: 0x1a, COLOR_BIT: 0x1b, FRAME_COMM: 0x1c, RETRY_CONN: 0x1e,
  POWEROFF: 0x20, POWERON: 0x21, RESTART: 0x22, SAFETY_RESTART: 0x23,
  MOUSE_MODE_SET: 0x24, SAVE_POWEROFF: 0x25, DQT_MODE_SET: 0x27,
  USB_RESET: 0x30, REQ_VMM_CODEKEY: 0x31, SECURITY: 0x33, REQ_VMM_PORT: 0x35,
  VIDEO_ON: 0x40, VIDEO_OFF: 0x41, GET_SUITE: 0x42, SET_SUITE: 0x44,
};

// ---- command codes (BMC -> client), command byte sits at payload[2] ----
const RSP = {
  PRESENT_BLADE: 0x01, IMAGE_DATA: 0x02, KEY_STATE: 0x04, CONNECT_STATE: 0x08,
  BLADE_STATE: 0x15, CHANNEL_SWITCH: 0x1d, RAPCONNECT_BLADE: 0x21,
  MOUSE_MODE: 0x25, DQT_MODE: 0x28, VMM_CODEKEY: 0x32, VMM_PORT: 0x36,
  KVM_KEY_SET: 0x40, KVM_SUITE_LIST: 0x43, NOT_PRI: 0x51,
};

/** connectBlade payload: {06, blade, colorBit, 01, 01}; length field is 0x8005 when compress=1. */
function connectBladePayload(blade, colorBit) {
  return Buffer.from([CMD.CONNECT_BLADE, blade & 0xff, colorBit & 0xff, 0x01, 0x01]);
}

module.exports = {
  crc16, aesEncrypt, aesDecrypt, zeroPad, reverse4,
  deriveEncodeKey, deriveKvmKey,
  buildFrame, buildEncryptedFrame, ServerFrameParser,
  parseSuiteList, connectBladePayload,
  CMD, RSP,
};
