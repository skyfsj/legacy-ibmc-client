'use strict';
// Electron main process: owns the raw TCP socket (browsers cannot open raw TCP,
// which is why a pure web page cannot speak this protocol) and bridges to the UI.

const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require('node:path');
const fs = require('node:fs');

// Stable app-data directory regardless of how the app is launched, so saved
// machines live in one place (…/Application Support/huawei-ibmc-kvm-client/).
app.setName('huawei-ibmc-kvm-client');

const { loginAndGetJnlp, parseJnlpParams } = require('./ibmc');
const { KvmSession } = require('./session');
const store = require('./store');

let win = null;
let session = null;

// `--selftest` loads the UI, verifies the renderer booted without errors, then exits.
// `--replaytest <frame.bin> <w> <h> <dqt>` pushes a captured frame through the real
// renderer decoder (Chromium's JPEG decoder) and checks the result.
// Both exist because there is no way to click the window from a script.
const SELFTEST = process.argv.includes('--selftest');
const REPLAY_IDX = process.argv.indexOf('--replaytest');
const REPLAY = REPLAY_IDX >= 0 ? {
  width: Number(process.argv[REPLAY_IDX + 2]),
  height: Number(process.argv[REPLAY_IDX + 3]),
  dqt: Number(process.argv[REPLAY_IDX + 4]),
} : null;

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 860,
    backgroundColor: '#111417',
    title: 'iBMC 远程控制台',
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  // surface renderer problems on stdout so failures are visible outside DevTools
  const problems = [];
  win.webContents.on('console-message', (_e, level, message, line, source) => {
    const tag = ['debug', 'info', 'warning', 'error'][level] || 'log';
    console.log(`[renderer:${tag}] ${message}${source ? ` (${source}:${line})` : ''}`);
    if (tag === 'error') problems.push(message);
  });
  win.webContents.on('did-fail-load', (_e, code, desc, url) => {
    console.error(`[renderer] 页面加载失败 ${code} ${desc} ${url}`);
    problems.push(`did-fail-load ${code} ${desc}`);
  });
  win.webContents.on('render-process-gone', (_e, details) => {
    console.error(`[renderer] 渲染进程退出: ${JSON.stringify(details)}`);
    problems.push('render-process-gone');
  });
  win.webContents.on('preload-error', (_e, p, err) => {
    console.error(`[renderer] preload 失败 ${p}: ${err.message}`);
    problems.push(`preload-error ${err.message}`);
  });

  win.webContents.once('did-finish-load', async () => {
    // ask the renderer whether its modules actually evaluated
    try {
      const ok = await win.webContents.executeJavaScript(
        'Boolean(window.kvm && window.__appReady)', true);
      if (!ok) problems.push('window.kvm 或 __appReady 未就绪');
      console.log(`[selftest] 渲染进程就绪: ${ok}`);
    } catch (e) {
      problems.push(`executeJavaScript 失败: ${e.message}`);
    }

    if (REPLAY) {
      const framePath = process.argv[process.argv.indexOf('--replaytest') + 1];
      const { width, height, dqt } = REPLAY;
      ipcMain.once('test:replayResult', (_e, r) => {
        if (!r.ok) { console.log(`[replaytest] 失败: ${r.error}`); app.exit(1); return; }
        const s = r.stats;
        const expectBlocks = Math.ceil(width / 64) * Math.ceil(height / 64);
        const checks = [
          ['块流精确消耗', s.consumed === s.expected, `${s.consumed}/${s.expected}`],
          ['块数正确', s.blocks === expectBlocks, `${s.blocks}/${expectBlocks}`],
          ['JPEG 块无失败', s.jpegErrors === 0, `${s.jpeg} 个, 失败 ${s.jpegErrors}`],
          ['画面非全黑', r.nonBlack / r.total > 0.01, `${(100 * r.nonBlack / r.total).toFixed(2)}%`],
        ];
        console.log(`[replaytest] ${framePath} (${width}x${height}, dqt=${dqt})`);
        let bad = 0;
        for (const [name, ok2, detail] of checks) {
          console.log(`  ${ok2 ? '✅' : '❌'} ${name}: ${detail}`);
          if (!ok2) bad++;
        }
        console.log(bad ? `[replaytest] 失败 ${bad} 项` : '[replaytest] 全部通过（Chromium JPEG 解码器）');
        app.exit(bad ? 1 : 0);
      });
      const buf = fs.readFileSync(framePath);
      console.log(`[replaytest] 送入渲染进程: ${buf.length} 字节`);
      win.webContents.send('test:replay', {
        stream: Array.from(buf), width, height, dqt,
      });
      return;
    }

    if (SELFTEST) {
      setTimeout(() => {
        console.log(problems.length ? `[selftest] 失败: ${problems.join('; ')}` : '[selftest] 通过');
        app.exit(problems.length ? 1 : 0);
      }, 800);
    }
  });

  win.on('closed', () => { win = null; });
}

const send = (channel, payload) => { if (win && !win.isDestroyed()) win.webContents.send(channel, payload); };

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => {
  if (session) session.close();
  if (process.platform !== 'darwin') app.quit();
});

function attachSession(s) {
  s.on('log', (m) => send('kvm:log', m));
  s.on('connected', () => send('kvm:status', { state: 'tcp-connected' }));
  s.on('authenticated', () => send('kvm:status', { state: 'authenticated' }));
  s.on('connectstate', (v) => send('kvm:status', { state: 'connectstate', value: v }));
  s.on('mousemode', (v) => send('kvm:status', { state: 'mousemode', value: v }));
  s.on('dqt', (v) => send('kvm:status', { state: 'dqt', value: v }));
  s.on('keystate', (v) => send('kvm:status', { state: 'keystate', value: v }));
  s.on('notpri', (v) => send('kvm:status', { state: 'notpri', value: v }));
  s.on('closing', () => send('kvm:status', { state: 'closed' }));
  s.on('closed', () => send('kvm:status', { state: 'closed' }));
  s.on('error', (e) => send('kvm:status', { state: 'error', message: e.message }));
  s.on('frame', (f) => {
    send('kvm:frame', {
      nochange: !!f.nochange,
      frameNo: f.frameNo,
      width: f.width, height: f.height, blockX: f.blockX, blockY: f.blockY,
      diff: f.diff, dqt: f.dqt, iframe: f.iframe,
      // copy into a plain Uint8Array so it survives the IPC boundary
      stream: f.stream ? new Uint8Array(f.stream) : null,
    });
  });
}

ipcMain.handle('kvm:connect', async (_e, opts) => {
  try {
    if (session) { session.close(); session = null; }

    let jnlp, params, host, port;
    const httpsPort = Number(opts.httpsPort || 443);

    if (opts.jnlpXml) {
      // escape hatch: user pasted / picked a JNLP downloaded from the web UI
      jnlp = opts.jnlpXml;
      params = parseJnlpParams(jnlp);
      const m = jnlp.match(/codebase="https?:\/\/([^"\/]+)/i);
      host = m ? m[1].split(':')[0] : opts.host;
      port = Number(params.port || 2198);
      send('kvm:log', '使用手动提供的 JNLP');
    } else {
      // A saved machine may supply the password from the keychain (see store.resolvePassword).
      const resolved = store.resolvePassword(opts);
      const password = resolved.password;
      if (resolved.source === 'keychain') send('kvm:log', '使用已保存的密码（系统钥匙串）');
      if (!opts.host || !opts.username) throw new Error('缺少地址或用户名');
      if (!password) throw new Error('缺少密码');

      const r = await loginAndGetJnlp({
        host: opts.host, port: httpsPort, username: opts.username, password,
        log: (m) => send('kvm:log', m),
      });
      jnlp = r.jnlp; params = r.params; host = r.host;
      port = Number(params.port || 2198);
      send('kvm:log', `JNLP 获取成功，刀片数=${params.bladesize || '?'}，KVM 端口=${port}`);

      // NB: connecting never writes to the session store. The renderer asks the user
      // separately (save prompt) and calls sessions.save explicitly, so a one-off
      // connection does not leave anything behind.
    }

    session = new KvmSession({ host, port, params, colorBit: opts.colorBit ?? 2 });
    attachSession(session);
    await session.connect();
    session.startHandshake();
    return { ok: true, host, port };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

// ---- saved sessions ----
ipcMain.handle('kvm:sessions:list', () => store.list());
ipcMain.handle('kvm:sessions:save', (_e, rec) => {
  try { return { ok: true, session: store.save(rec), list: store.list() }; }
  catch (e) { return { ok: false, error: e.message }; }
});
ipcMain.handle('kvm:sessions:remove', (_e, id) => {
  store.remove(id);
  return { ok: true, list: store.list() };
});

ipcMain.handle('kvm:pickJnlp', async () => {
  const r = await dialog.showOpenDialog(win, {
    title: '选择 JNLP 文件',
    filters: [{ name: 'JNLP', extensions: ['jnlp'] }],
    properties: ['openFile'],
  });
  if (r.canceled || !r.filePaths.length) return null;
  return fs.readFileSync(r.filePaths[0], 'utf8');
});

ipcMain.on('kvm:key', (_e, report) => { if (session) session.sendKeyboard(Uint8Array.from(report)); });
ipcMain.on('kvm:mouseAbs', (_e, m) => { if (session) session.sendMouseAbs(m.x, m.y, m.buttons, m.wheel); });
ipcMain.on('kvm:mouseRel', (_e, m) => { if (session) session.sendMouseRel(m.dx, m.dy, m.buttons); });
ipcMain.on('kvm:ctrlAltDel', () => { if (session) session.ctrlAltDel(); });
ipcMain.on('kvm:dqt', (_e, m) => { if (session) session.setDqt(m.v, m.type ?? 1); });
ipcMain.on('kvm:iframe', () => { if (session) session.requestIFrame(); });
ipcMain.on('kvm:power', (_e, cmd) => { if (session) session.sendPower(cmd); });
// Virtual media is not implemented in the Electron build yet (the VMM channel lives in
// the Go client's internal/vmm package). Report that clearly instead of failing silently.
ipcMain.handle('kvm:media', () => ({
  ok: false,
  error: '虚拟介质尚未在 Electron 版实现，请使用 Go 版（clients/go）',
}));
ipcMain.on('kvm:disconnect', () => { if (session) { session.close(); session = null; } });
