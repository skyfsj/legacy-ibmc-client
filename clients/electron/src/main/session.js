'use strict';
// KVM session: raw TCP to the BMC's console port, handshake, frame reassembly,
// and input injection. Mirrors the vendor client's BladeThread / DrawThread logic.
//
// Validated against a real iBMC (see ../../huawei-ibmc-kvm-protocol/07-live-verification.md).

const net = require('node:net');
const { EventEmitter } = require('node:events');
const P = require('./protocol');

const BLADE = 0;
const SUBPACKET_CHUNK = 220;      // vendor client hardcodes 220 when sizing the reassembly buffer

class KvmSession extends EventEmitter {
  constructor(opts) {
    super();
    this.host = opts.host;
    this.port = opts.port || 2198;
    this.params = opts.params || {};
    this.colorBit = opts.colorBit ?? 2;
    this.verbose = opts.verbose !== false;

    this.sock = null;
    this.parser = new P.ServerFrameParser();
    this.codeKey = parseInt(this.params.verifyValue, 10) | 0;
    this.encodeKey = null;
    this.kvmKey = null;
    this.reconnKey = null;
    this.algo = 3;
    this.iterations = 10000;

    this.connected = false;
    this.authenticated = false;
    this.width = 0; this.height = 0;
    this.blockX = 0; this.blockY = 0;
    this.dqt = 6;                 // table index; firmware default is 70 (= index 6)
    this.dqtSeen = false;         // set once the BMC reports its own quality
    this.mouseMode = null;
    this.frameNo = 0;
    this.framesReceived = 0;

    this.pending = null;          // current frame being reassembled
    this.heartbeatTimer = null;
    this.decry = Buffer.from(this.params.decrykey || '', 'hex');
  }

  log(...a) { if (this.verbose) this.emit('log', a.join(' ')); }

  connect() {
    return new Promise((resolve, reject) => {
      this.sock = net.connect({ host: this.host, port: this.port });
      this.sock.setNoDelay(true);
      const onErr = (e) => { cleanup(); reject(e); };
      const onConn = () => { cleanup(); this.connected = true; this.emit('connected'); resolve(); };
      const cleanup = () => { this.sock.off('error', onErr); this.sock.off('connect', onConn); };
      this.sock.once('error', onErr);
      this.sock.once('connect', onConn);

      this.sock.on('data', (chunk) => {
        for (const payload of this.parser.push(chunk)) {
          try { this.onFrame(payload); } catch (e) { this.emit('error', e); }
        }
      });
      this.sock.on('error', (e) => this.emit('error', e));
      this.sock.on('close', () => {
        this.connected = false;
        clearInterval(this.heartbeatTimer);
        this.emit('closed');
      });
    });
  }

  send(buf, label) {
    if (!this.sock || this.sock.destroyed) return false;
    // One write per frame: the BMC does not reassemble frames split across reads.
    this.sock.write(buf);
    if (label) this.log(`tx ${label} (${buf.length}B)`);
    return true;
  }

  startHandshake() {
    this.send(P.buildFrame(this.codeKey, Buffer.from([P.CMD.HEART_BEAT, 0x00])), 'HEARTBEAT');
    this.send(P.buildFrame(this.codeKey, Buffer.from([P.CMD.GET_SUITE, BLADE])), 'GET_SUITE');

    this.heartbeatTimer = setInterval(() => {
      this.send(P.buildFrame(this.codeKey, Buffer.from([P.CMD.HEART_BEAT, 0x00])));
    }, 5000);
  }

  finishHandshake() {
    // connectBlade with the 0x8000 "encrypted frame" variant carrying the 24-byte key proof
    const payload = P.connectBladePayload(BLADE, this.colorBit);
    this.send(P.buildEncryptedFrame(this.encodeKey, payload, 0x8000 | payload.length), 'CONNECT_BLADE');

    // Ask the BMC to pick the mouse mode (the vendor client sends mode 2 here, then
    // reads the effective mode back from the 0x25 reply).
    setTimeout(() => this.send(P.buildFrame(this.codeKey, Buffer.from([P.CMD.MOUSE_MODE_SET, 0x00, 0x02, 0x00, 0x00])), 'MOUSE_MODE_SET(2)'), 200);
    setTimeout(() => this.send(P.buildFrame(this.codeKey, Buffer.from([P.CMD.FRAME_COMM, 35])), 'FRAME_COMM(35)'), 400);
    // NOTE: deliberately NOT pushing a quality value on connect. The mapping from the
    // 0x27 quality number to the quantization table is only verified for the
    // firmware's own default (70 -> table index 6). Forcing any other value risked
    // decoding with a table finer than the encoder's, which dims the image.
  }

  onFrame(p) {
    const cmd = p[2];
    switch (cmd) {
      case P.RSP.KVM_SUITE_LIST: {
        const { count, suites, lengthOk } = P.parseSuiteList(p);
        this.log(`rx 套件表 count=${count} 长度自校验=${lengthOk ? 'OK' : '失败'}`);
        for (const s of suites) this.log(`   algo=${s.algo} iterations=${s.iterations}`);
        // Prefer SHA-256 (algo 3), else SHA-1 (algo 2); fall back to 5000/SHA-1.
        let chosen = suites.find((s) => s.algo === 3) || suites.find((s) => s.algo === 2) || { algo: 1, iterations: 5000 };
        this.algo = chosen.algo; this.iterations = chosen.iterations;
        this.encodeKey = P.deriveEncodeKey(this.params.verifyValueExt, this.decry.subarray(16, 32), this.iterations, this.algo);
        this.log(`选中 algo=${this.algo} iterations=${this.iterations}`);
        this.send(P.buildFrame(this.codeKey, Buffer.from([
          P.CMD.SET_SUITE, BLADE, this.algo,
          (this.iterations >>> 24) & 0xff, (this.iterations >>> 16) & 0xff,
          (this.iterations >>> 8) & 0xff, this.iterations & 0xff,
        ])), 'SET_SUITE');
        this.finishHandshake();
        break;
      }
      case P.RSP.KVM_KEY_SET: {
        const dataLen = p.length - 4;                 // payload after [00 00 40 blade]
        const ct = p.subarray(4);
        let pt;
        try { pt = P.aesDecrypt(ct, this.decry.subarray(0, 16), this.decry.subarray(16, 32)); }
        catch (e) { this.log(`KVM_KEY_SET 解密失败: ${e.message}`); break; }
        if (dataLen === 48) {
          this.kvmKey = P.deriveKvmKey(pt, this.iterations, this.algo);
          this.authenticated = true;
          this.log(`拿到 kvm_key (48B)，数据密钥 ${this.kvmKey.subarray(0, 8).toString('hex')}…`);
          this.emit('authenticated');
        } else if (dataLen === 128) {
          this.reconnKey = pt;
          this.log('拿到 128B 重连密钥');
        }
        break;
      }
      case P.RSP.CONNECT_STATE: {
        const state = p[4];
        this.log(`rx 连接状态 = ${state}`);
        this.emit('connectstate', state);
        break;
      }
      case P.RSP.MOUSE_MODE: {
        this.mouseMode = p[4];
        // 1 = absolute/synchronised, 0 = relative. Absolute is what the GUI drives.
        this.log(`rx 鼠标模式 = ${this.mouseMode}（${this.mouseMode === 1 ? '绝对/同步' : '相对'}）`);
        if (this.mouseMode !== 1 && !this.mouseModeForced) {
          this.mouseModeForced = true;
          this.log('请求切换到绝对/同步模式（1）…');
          setTimeout(() => this.send(P.buildFrame(this.codeKey, Buffer.from([P.CMD.MOUSE_MODE_SET, 0x00, 0x01, 0x00, 0x00])), 'MOUSE_MODE_SET(1)'), 150);
        }
        this.emit('mousemode', this.mouseMode);
        break;
      }
      case P.RSP.DQT_MODE: {
        const v = p[4];
        this.dqt = Math.max(0, Math.min(9, v / 10 - 1));
        this.dqtSeen = true;
        this.log(`rx DQT 档 = ${v}（索引 ${this.dqt}）`);
        this.emit('dqt', v);
        break;
      }
      case P.RSP.IMAGE_DATA:
        this.onImage(p);
        break;
      case P.RSP.KEY_STATE:
        this.emit('keystate', p[4]);
        break;
      case P.RSP.NOT_PRI:
        this.emit('notpri', p[4]);
        break;
      default:
        this.log(`rx cmd=0x${cmd.toString(16)} dlen=${p.length}`);
    }
  }

  /**
   * IMAGE_DATA payload layout (validated):
   *   [0..1] 00 00 | [2] 0x02 | [3] pad
   *   [4..5] sub-packet sequence (u16be), 0 = frame header sub-packet
   *   [6]    frame number
   *   [7..]  sub-packet body; for seq 0 this is PLAINTEXT, for seq != 0 it is
   *          [7]=plaintext length followed by AES-CBC ciphertext
   */
  onImage(p) {
    if (!this.kvmKey) return;
    const seq = p.readUInt16BE(4);
    const frameNo = p[6];
    let imageData;
    if (seq === 0) {
      imageData = Buffer.from(p.subarray(4));
    } else {
      const plainLen = p[7];
      const ct = p.subarray(8);
      if (ct.length === 0 || ct.length % 16 !== 0) return;
      let pt;
      try { pt = P.aesDecrypt(ct, this.kvmKey.subarray(0, 16), this.kvmKey.subarray(32, 48)); }
      catch { return; }
      imageData = Buffer.concat([p.subarray(4, 7), pt.subarray(0, plainLen)]);
    }

    if (seq === 0) {
      const total = imageData.readUInt32BE(3);
      const flags = imageData[7];
      this.width = ((flags & 0x7f) << 8) | imageData[8];
      this.height = imageData.readUInt16BE(9);
      this.blockX = Math.ceil(this.width / 64);
      this.blockY = Math.ceil(this.height / 64);
      // The frame header is authoritative for which quantization table to decode
      // with. Log it whenever it changes so a mismatch with the 0x27 setting (which
      // would show up as a dim or washed-out picture) is visible rather than guessed.
      const hdrDqt = imageData[16] & 0x0f;
      if (hdrDqt !== this.hdrDqt) {
        this.hdrDqt = hdrDqt;
        this.log(`帧头 DQT 索引 = ${hdrDqt}（量化表 _${hdrDqt * 10 + 10}）`);
        this.emit('hdrdqt', hdrDqt);
      }
      const n = Math.floor(total / SUBPACKET_CHUNK) + 1 + (total % SUBPACKET_CHUNK ? 1 : 0);
      this.pending = { frameNo, total, diff: (flags >> 7) & 1, dqt: imageData[16] & 0x0f, iframe: (imageData[16] >> 7) & 1, slots: new Array(n).fill(null), sum: 0, got: 1 };
      this.pending.slots[0] = imageData;
      if (total === 0) {
        this.framesReceived++;
        this.emit('frame', { nochange: true, frameNo });
        this.pending = null;
      }
      return;
    }

    const cur = this.pending;
    if (!cur || cur.frameNo !== frameNo) return;         // stale sub-packet from an aborted frame
    if (seq >= cur.slots.length) { this.pending = null; return; }
    if (!cur.slots[seq]) { cur.slots[seq] = imageData; cur.sum += imageData.length - 3; cur.got++; }
    if (cur.sum === cur.total) this.completeFrame();
  }

  completeFrame() {
    const cur = this.pending;
    this.pending = null;
    // combine(): data[0] = diff flag, then concatenate buf[3..] of every seq>=1 sub-packet.
    // packLenght counts only seq>=1 sub-packets, so this yields exactly total+1 bytes.
    const parts = [Buffer.from([cur.diff])];
    for (let i = 1; i < cur.slots.length; i++) {
      const s = cur.slots[i];
      if (!s) { this.log(`帧 ${cur.frameNo} 序号 ${i} 缺失，丢弃`); this.requestIFrame(); return; }
      parts.push(s.subarray(3));
    }
    const combined = Buffer.concat(parts);
    this.framesReceived++;
    this.frameNo = cur.frameNo;
    this.emit('frame', {
      frameNo: cur.frameNo,
      width: this.width, height: this.height,
      blockX: this.blockX, blockY: this.blockY,
      diff: cur.diff, dqt: cur.dqt, iframe: cur.iframe,
      stream: combined,
    });
  }

  // ---------- input ----------

  /** hidReport: 8 bytes [modifier, 0, k0..k5] */
  sendKeyboard(hidReport) {
    if (!this.authenticated && !this.kvmKey) return;
    let payload;
    if (this.kvmKey) {
      const enc = P.aesEncrypt(P.zeroPad(Buffer.from(hidReport)), this.kvmKey.subarray(16, 32), this.kvmKey.subarray(32, 48));
      payload = Buffer.concat([Buffer.from([P.CMD.KEY_PACK, BLADE]), enc]);
    } else {
      payload = Buffer.concat([Buffer.from([P.CMD.KEY_PACK, BLADE]), Buffer.from(hidReport)]);
    }
    this.send(P.buildFrame(this.codeKey, payload));
  }

  /** Absolute mouse in the BMC's normalised 0..3000 space (mode 1 / synchronised). */
  sendMouseAbs(x, y, buttons, wheel) {
    if (!this.kvmKey || !this.width || !this.height) return;
    const nx = Math.round((x * 3000) / this.width);
    const ny = Math.round((y * 3000) / this.height);
    // dedup on the normalised values (raw pixel coords jitter, normalised ones don't)
    if (this.lastMouse && nx === this.lastMouse[0] && ny === this.lastMouse[1] && !wheel) {
      if (buttons === this.lastButtons) return;
    }
    this.lastMouse = [nx, ny];
    this.lastButtons = buttons;
    const body = Buffer.alloc(6);
    body[0] = buttons & 0xff;
    body.writeUInt16BE(nx & 0xffff, 1);
    body.writeUInt16BE(ny & 0xffff, 3);
    body[5] = (wheel || 0) & 0xff;
    const enc = P.aesEncrypt(P.zeroPad(body), this.kvmKey.subarray(16, 32), this.kvmKey.subarray(32, 48));
    this.send(P.buildFrame(this.codeKey, Buffer.concat([Buffer.from([P.CMD.MOUSE_PACK, BLADE]), enc])));
  }

  /** Relative mouse (mode 0), deltas clamped to +/-120 per packet. */
  sendMouseRel(dx, dy, buttons) {
    if (!this.kvmKey) return;
    let leftX = Math.max(-120, Math.min(120, dx | 0));
    let leftY = Math.max(-120, Math.min(120, dy | 0));
    for (let i = 0; i < 16 && (leftX || leftY); i++) {
      const sx = Math.max(-120, Math.min(120, leftX));
      const sy = Math.max(-120, Math.min(120, leftY));
      const body = Buffer.from([buttons & 0xff, sx & 0xff, sy & 0xff, 0x00]);
      const enc = P.aesEncrypt(P.zeroPad(body), this.kvmKey.subarray(16, 32), this.kvmKey.subarray(32, 48));
      this.send(P.buildFrame(this.codeKey, Buffer.concat([Buffer.from([P.CMD.MOUSE_PACK, BLADE]), enc])));
      leftX -= sx; leftY -= sy;
    }
  }

  /**
   * Power control / USB reset. With compress=1 the BMC expects the 0x33 command
   * carrying a 16-byte AES-CBC block whose last byte is the real command
   * (key = kvm_key[0:16], iv = kvm_key[32:48]).
   */
  sendPower(cmd) {
    if (!this.kvmKey) return false;
    const body = Buffer.alloc(16);
    body[15] = cmd & 0xff;
    const enc = P.aesEncrypt(P.zeroPad(body), this.kvmKey.subarray(0, 16), this.kvmKey.subarray(32, 48));
    const payload = Buffer.concat([Buffer.from([P.CMD.SECURITY, 0x00]), enc]);
    return this.send(P.buildFrame(this.codeKey, payload), `POWER(0x${cmd.toString(16)})`);
  }

  requestIFrame() { this.send(P.buildFrame(this.codeKey, Buffer.from([P.CMD.I_REQ, BLADE])), 'I_REQ'); }

  /**
   * DQT quality. `type` mirrors the vendor client: 2 while the slider is being
   * dragged (continuous), 1 on release (commit).
   */
  setDqt(quality, type = 1) {
    this.send(P.buildFrame(this.codeKey, Buffer.from([P.CMD.DQT_MODE_SET, 0x00, quality & 0xff, type & 0xff, 0x00])), `DQT(${quality}, type=${type})`);
  }

  /** Ctrl+Alt+Del is sent as a HID report with modifier bits 0x01|0x04 and keycode 0x4C. */
  ctrlAltDel() {
    const down = [0x05, 0x00, 0x4c, 0, 0, 0, 0, 0];
    this.sendKeyboard(down);
    setTimeout(() => this.sendKeyboard([0, 0, 0, 0, 0, 0, 0, 0]), 90);
  }

  close() {
    clearInterval(this.heartbeatTimer);
    if (this.sock && !this.sock.destroyed) this.sock.destroy();
  }
}

module.exports = { KvmSession, BLADE };
