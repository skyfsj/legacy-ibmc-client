// Renderer: session manager, video display, input capture, UI.
import { FrameDecoder } from './decoder.js';
import { KeyboardState } from './hid.js';

const $ = (id) => document.getElementById(id);
const screen = $('screen');
const ctx = screen.getContext('2d', { alpha: false });
const overlay = $('overlay');
const stage = $('stage');

const decoder = new FrameDecoder();
const keyboard = new KeyboardState();

let connected = false;
let firstFrame = true;
let lastW = 0, lastH = 0;
let remoteW = 0, remoteH = 0;
let wheelAcc = 0;
let skippedDiff = 0, framesDrawn = 0, lastStats = null;
let lastFrameAt = 0;
let closeCause = null;
let mouseMode = null;
let zoomMode = 'int';
let lastZoom = null;
let currentSessionId = null;
// Quality preference. Default 70 = the firmware's own value and the only one whose
// 0x27-number -> quantization-table mapping is verified; other values are sent only
// when the user actually moves the slider.
//
// One-time reset: an earlier build defaulted this to 100 AND pushed it on connect,
// which decoded with a table finer than the encoder's and dimmed the picture.
// Clear whatever that build stored.
const DQT_PREF_VERSION = '2';
if (localStorage.getItem('dqtPrefVersion') !== DQT_PREF_VERSION) {
  localStorage.removeItem('dqt');
  localStorage.setItem('dqtPrefVersion', DQT_PREF_VERSION);
}
let quality = Number(localStorage.getItem('dqt') || 70);

// ======================= 日志 / 轻提示 =======================
const logLines = [];
function log(msg) {
  const t = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  logLines.push(`[${t}] ${msg}`);
  if (logLines.length > 800) logLines.splice(0, 300);
  $('logPre').textContent = logLines.join('\n');
  const pre = $('logPre');
  pre.scrollTop = pre.scrollHeight;
}

// Transient confirmation of a user action (not debug output).
let toastTimer = null;
function toast(msg, kind = 'ok', ms = 4200) {
  const el = $('toast');
  el.textContent = msg;
  el.className = `toast ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), ms);
}

// ======================= 模态 =======================
function openDlg(id) { const d = $(id); if (!d.open) d.showModal(); }
function closeDlg(id) { const d = $(id); if (d.open) d.close(); }
for (const btn of document.querySelectorAll('[data-close]')) {
  btn.addEventListener('click', () => btn.closest('dialog').close());
}
// click on the backdrop closes
for (const d of document.querySelectorAll('dialog')) {
  d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
}

$('btnLog').addEventListener('click', () => openDlg('logDlg'));
$('btnStats').addEventListener('click', () => { renderStats(); openDlg('statsDlg'); });
$('btnClearLog').addEventListener('click', () => { logLines.length = 0; $('logPre').textContent = ''; });
$('btnCopyLog').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(logLines.join('\n')); $('btnCopyLog').textContent = '已复制'; }
  catch { $('btnCopyLog').textContent = '复制失败'; }
  setTimeout(() => { $('btnCopyLog').textContent = '复制'; }, 1200);
});

function renderStats() {
  if (!lastStats) { $('statsPre').textContent = '暂无数据'; return; }
  const s = lastStats;
  $('statsPre').textContent = [
    `分辨率        ${remoteW} × ${remoteH}`,
    `块网格        ${Math.ceil(remoteW / 64)} × ${Math.ceil(remoteH / 64)} = ${Math.ceil(remoteW / 64) * Math.ceil(remoteH / 64)} 块`,
    `本帧处理块数  ${s.blocks}`,
    `缩放          ${zoomMode === 'int' ? '整数倍（无损）' : zoomMode === 'fit' ? '适应窗口' : zoomMode + '×'}`,
    lastZoom ? `  实际倍率     CSS ${lastZoom.scale.toFixed(3)} × dpr ${lastZoom.dpr} = 设备 ${lastZoom.deviceScale.toFixed(3)} ${lastZoom.lossless ? '✅ 无损（整数）' : '⚠️ 分数，有损'}` : '  实际倍率     —',
    '',
    `块流消耗      ${s.consumed} / ${s.expected} 字节 ${s.consumed === s.expected ? '✅' : '❌'}`,
    `JPEG 块       ${s.jpeg}（失败 ${s.jpegErrors}）`,
    `RLE 块        ${s.rle}`,
    `复制块        ${s.copy}`,
    `空操作/无效   ${s.noop} / ${s.invalid}`,
    '',
    `已绘制帧      ${framesDrawn}`,
    `跳过的差分帧  ${skippedDiff}`,
    `距上一帧      ${lastFrameAt ? (Date.now() - lastFrameAt) + ' ms' : '—'}`,
    '',
    `鼠标模式      ${mouseMode === null ? '未知' : (mouseMode === 1 ? '1 = 绝对/同步' : '0 = 相对')}`,
    `键盘包 / 鼠标包  ${keySent} / ${mouseSent}`,
    `最近按键      ${lastKeyHex}`,
    `最近鼠标      ${lastMouseHex}`,
  ].join('\n');
}

// ======================= 会话管理器 =======================
let sessions = [];
let lastUsed = null;

async function refreshSessions(prefer) {
  const d = await window.kvm.sessions.list();
  sessions = d.sessions || [];
  lastUsed = d.lastUsed || null;
  renderSessions(prefer ?? currentSessionId);
}

function renderSessions(selectedId) {
  const ul = $('sessList');
  ul.textContent = '';
  $('sessEmpty').classList.toggle('hidden', sessions.length > 0);

  for (const s of sessions) {
    const li = document.createElement('li');
    if (s.id === selectedId) li.classList.add('active');

    const meta = document.createElement('div');
    meta.className = 'meta';
    const nm = document.createElement('div');
    nm.className = 'nm';
    nm.textContent = s.name || s.host;
    const sub = document.createElement('div');
    sub.className = 'sub';
    sub.textContent = `${s.username}@${s.host}:${s.httpsPort}`;
    meta.append(nm, sub);
    li.append(meta);

    if (s.hasPassword) {
      const b = document.createElement('span');
      b.className = 'badge';
      b.textContent = '已存密码';
      b.title = '密码已用系统钥匙串加密保存';
      li.append(b);
    }

    const ops = document.createElement('div');
    ops.className = 'ops';
    const btnGo = document.createElement('button');
    btnGo.textContent = '▶';
    btnGo.title = '连接';
    btnGo.addEventListener('click', (e) => { e.stopPropagation(); selectSession(s.id); connectCurrent(); });
    const btnDel = document.createElement('button');
    btnDel.textContent = '✕';
    btnDel.title = '删除';
    btnDel.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (!confirm(`删除机器「${s.name || s.host}」？\n（同时删除已保存的密码）`)) return;
      await window.kvm.sessions.remove(s.id);
      if (currentSessionId === s.id) { currentSessionId = null; fillForm(null); }
      refreshSessions();
    });
    ops.append(btnGo, btnDel);
    li.append(ops);

    // Single click only selects (so a mis-click cannot burn the single-use JNLP
    // session); connecting is the explicit ▶ button or a double click.
    li.addEventListener('click', () => selectSession(s.id));
    li.addEventListener('dblclick', () => { selectSession(s.id); connectCurrent(); });
    ul.append(li);
  }
}

function selectSession(id) {
  currentSessionId = id;
  const s = sessions.find((x) => x.id === id) || null;
  fillForm(s);
  renderSessions(id);
}

// Live hint: typing a password with 记住密码 unchecked would silently discard it.
// Made clickable so a record saved with remembering off is one click away from fixed.
function updateStoreHint() {
  const typed = $('fPass').value.length > 0;
  const remember = $('fRemember').checked;
  const el = $('pwStoreHint');
  el.textContent = '';
  if (!(typed && !remember)) { el.classList.add('hidden'); return; }
  el.classList.remove('hidden');
  el.append('⚠ 密码不会被保存（未勾选「记住密码」）— ');
  const a = document.createElement('a');
  a.href = '#';
  a.textContent = '改为记住';
  a.style.color = 'var(--accent)';
  a.addEventListener('click', (e) => {
    e.preventDefault();
    $('fRemember').checked = true;
    updateStoreHint();
  });
  el.append(a);
}
$('fPass').addEventListener('input', updateStoreHint);
$('fRemember').addEventListener('change', updateStoreHint);

function fillForm(s) {
  $('formTitle').textContent = s ? `编辑：${s.name || s.host}` : '新建连接';
  $('fName').value = s ? (s.name || '') : '';
  // For a new connection, prefill from the last machine used so nothing has to be
  // retyped — but stay in "new" mode, without selecting that machine for editing.
  const seed = s || sessions.find((x) => x.id === lastUsed) || null;
  $('fHost').value = seed ? seed.host : '192.168.1.100';
  $('fPort').value = seed ? seed.httpsPort : 443;
  $('fUser').value = seed ? seed.username : 'root';
  $('fColorBit').value = String(seed ? (seed.colorBit ?? 2) : 2);
  $('fPass').value = '';
  // Remembering is the default: a user who bothered to type a password almost always
  // wants it kept. The checkbox stays available to opt out.
  $('fRemember').checked = s ? (s.remember !== false) : true;
  // A stored password shows a fixed run of stars: it signals "there is a password"
  // without leaking its length. It is a PLACEHOLDER, never the value — submitting an
  // empty field is what tells the main process to use the keychain copy.
  const hasStored = !!(s && s.hasPassword);
  $('fPass').placeholder = hasStored ? '**********' : '';
  $('fPass').title = hasStored ? '已保存密码；直接输入新密码即可覆盖' : '';
  updateStoreHint();
  // Quality: only the global preference seeds the slider. A per-machine value is
  // not used for display, so a record written by the broken 100-default build
  // cannot resurface here.
  const q = Number(localStorage.getItem('dqt') || 70);
  $('dqt').value = q; $('dqtVal').textContent = q;
  quality = q;
  // "保存修改" only makes sense for an already-saved machine (rename, port change…)
  $('btnSaveOnly').classList.toggle('hidden', !s);
  $('homeErr').textContent = '';
}

function readForm() {
  return {
    id: currentSessionId || undefined,
    name: $('fName').value.trim(),
    host: $('fHost').value.trim(),
    httpsPort: Number($('fPort').value || 443),
    username: $('fUser').value.trim(),
    password: $('fPass').value,
    colorBit: Number($('fColorBit').value),
    dqt: quality,
    remember: $('fRemember').checked,
  };
}

$('btnNew').addEventListener('click', () => { selectSession(null); $('fName').focus(); });

// 保存修改：只给已保存的机器用（改名、改端口…），不触发连接
$('btnSaveOnly').addEventListener('click', async () => {
  const rec = readForm();
  if (!rec.id) return;
  const r = await window.kvm.sessions.save({ ...rec, password: rec.password || undefined });
  if (!r.ok) { $('homeErr').textContent = r.error; toast(`保存失败：${r.error}`, 'warn'); return; }
  await refreshSessions(r.session.id);
  fillForm(r.session);
  reportSaved(r.session);
});

// ---------- 连接后询问是否保存 ----------
let pendingSave = null;      // the form values of the session just connected

function askToSave(rec) {
  pendingSave = rec;
  $('saveTarget').textContent = `${rec.name || rec.host}  —  ${rec.username}@${rec.host}:${rec.httpsPort}`;
  $('saveRemember').checked = !!rec.remember;
  openDlg('saveDlg');
}

$('btnSaveYes').addEventListener('click', async () => {
  const rec = pendingSave;
  closeDlg('saveDlg');
  if (!rec) return;
  const remember = $('saveRemember').checked;
  $('fRemember').checked = remember;                 // keep the form in sync
  const r = await window.kvm.sessions.save({
    ...rec, remember,
    password: remember ? (rec.password || undefined) : undefined,
  });
  if (!r.ok) { log(`保存失败：${r.error}`); toast(`保存失败：${r.error}`, 'warn'); return; }
  currentSessionId = r.session.id;
  await refreshSessions(r.session.id);
  fillForm(r.session);
  reportSaved(r.session);
  pendingSave = null;
});

// Always say what actually happened to the password — silently dropping it is what
// made "I typed a password and it did not save" possible.
function reportSaved(s) {
  if (s.hasPassword) {
    log(`已保存机器「${s.name}」（密码已用系统钥匙串加密）`);
    toast(`已保存「${s.name}」，密码已加密保存`);
  } else {
    log(`已保存机器「${s.name}」（未保存密码）`);
    toast(`已保存「${s.name}」，但密码未保存（未勾选「记住密码」）`, 'warn', 6000);
  }
}

$('btnSaveNo').addEventListener('click', () => {
  closeDlg('saveDlg');
  log('未保存，仅本次连接（下次需要重新填写）');
  pendingSave = null;
});

// ---------- 需要密码时弹模态 ----------
function askPassword(rec, reason) {
  $('pwTitle').textContent = reason === 'stale' ? '密码可能已失效' : '需要密码';
  $('pwTarget').textContent = `${rec.username}@${rec.host}:${rec.httpsPort}`;
  $('pwInput').value = '';
  $('pwRemember').checked = !!rec.remember;
  $('pwHint').textContent = reason === 'stale'
    ? '已保存的密码没能通过认证，请重新输入。'
    : '';
  openDlg('pwDlg');
  setTimeout(() => $('pwInput').focus(), 60);
}

function submitPassword() {
  const pw = $('pwInput').value;
  if (!pw) { $('pwHint').textContent = '请输入密码'; return; }
  closeDlg('pwDlg');
  $('fPass').value = pw;
  $('fRemember').checked = $('pwRemember').checked;
  connectCurrent();
}
$('btnPwOk').addEventListener('click', submitPassword);
$('btnPwCancel').addEventListener('click', () => closeDlg('pwDlg'));
$('pwInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); submitPassword(); }
});

$('btnConnect').addEventListener('click', connectCurrent);

async function connectCurrent() {
  const rec = readForm();
  if (!rec.host || !rec.username) { $('homeErr').textContent = '地址和用户名必填'; return; }
  // Match by id, or by endpoint when the user typed an already-saved machine's
  // details manually — otherwise we would ask to save something we already have.
  const existing = sessions.find((s) => s.id === rec.id)
    || sessions.find((s) => s.host === rec.host && s.httpsPort === rec.httpsPort && s.username === rec.username);
  if (existing && !rec.id) { rec.id = existing.id; currentSessionId = existing.id; }
  const hasStored = !!(existing && existing.hasPassword);
  if (!rec.password && !hasStored) {
    // no password anywhere -> ask for it in a modal instead of an inline error
    $('homeErr').textContent = '';
    askPassword(rec, 'missing');
    return;
  }

  $('homeErr').textContent = '';
  $('btnConnect').disabled = true;
  $('btnSaveOnly').disabled = true;
  setStatus('登录中…');
  log('─── 开始连接 ───');

  const r = await window.kvm.connect({
    ...rec,
    // leave the password empty when we can fall back to the keychain copy
    password: rec.password || (hasStored ? undefined : ''),
  });

  $('btnConnect').disabled = false;
  $('btnSaveOnly').disabled = false;

  if (!r.ok) {
    $('homeErr').textContent = r.error;
    setStatus('连接失败', 'bad');
    log(`连接失败：${r.error}`);
    // A stored password that no longer authenticates would otherwise leave the user
    // stuck ("I saved it, why won't it connect?") — offer to retype it.
    if (hasStored && !rec.password && /密码|锁定|权限|过期|上限/.test(r.error)) {
      askPassword(rec, 'stale');
    }
    return;
  }

  // the machine already existed -> persist field edits (rename, port…) silently
  if (existing) {
    const saved = await window.kvm.sessions.save({ ...rec, password: rec.password || undefined });
    if (saved.ok) { currentSessionId = saved.session.id; refreshSessions(saved.session.id); }
  }

  $('home').classList.add('hidden');
  $('console').classList.remove('hidden');
  connected = true;
  showOverlay('已登录，等待远端画面…');
  screen.focus();

  // a machine we have never stored: offer to keep it, but never force it
  if (!existing) {
    rec.name = rec.name || rec.host;
    askToSave(rec);
  }
}

$('btnPick').addEventListener('click', async () => {
  const xml = await window.kvm.pickJnlp();
  if (!xml) return;
  $('homeErr').textContent = '';
  setStatus('使用 JNLP 文件…');
  const r = await window.kvm.connect({ jnlpXml: xml, host: $('fHost').value.trim() });
  if (!r.ok) { $('homeErr').textContent = r.error; return; }
  connected = true;
  $('home').classList.add('hidden');
  $('console').classList.remove('hidden');
  showOverlay('已登录，等待远端画面…');
  screen.focus();
});

$('btnDisconnect').addEventListener('click', () => {
  window.kvm.disconnect();
  connected = false;
  $('console').classList.add('hidden');
  $('home').classList.remove('hidden');
  setStatus('未连接');
  log('已断开');
  refreshSessions();
});

window.kvm.onSessions(() => refreshSessions());

// ======================= 状态 =======================
function setStatus(text, cls = '') {
  const s = $('status');
  s.textContent = text;
  s.className = 'status ' + cls;
}
function showOverlay(text) { overlay.textContent = text; overlay.classList.add('show'); }
function hideOverlay() { overlay.classList.remove('show'); }

window.kvm.onLog(log);

window.kvm.onStatus((s) => {
  switch (s.state) {
    case 'tcp-connected':
      setStatus('TCP 已连接，握手中…');
      log('TCP 已连接，开始握手');
      break;
    case 'authenticated':
      setStatus('已认证，等待画面…', 'ok');
      hideOverlay();
      screen.focus();
      inputUi();
      break;
    case 'connectstate':
      if (s.value === 0) { setStatus('连接已接受', 'ok'); hideOverlay(); }
      else {
        const why = {
          2: '已有其他用户占用控制台', 3: '会话无效（JNLP 会话是一次性的，请重新登录获取）',
          4: '分辨率超出范围', 5: '服务器被禁用', 7: '用户已被删除', 17: '会话超时',
        }[s.value] || `未知状态 ${s.value}`;
        closeCause = `连接被拒绝（状态 ${s.value}）\n${why}`;
        setStatus(`连接被拒：${why}`, 'bad');
        showOverlay(closeCause);
        // the overlay already explains it; the log is one click away if wanted
      }
      break;
    case 'dqt':
      // The slider is the user's intent and we push it to the BMC; do not let a
      // stale firmware value (70) yank it around. Just record what the remote says.
      log(`远端画质 = ${s.value}`);
      break;
    case 'mousemode':
      mouseMode = s.value;
      log(`远端鼠标模式 = ${s.value}（${s.value === 1 ? '绝对/同步' : '相对'}）`);
      inputUi();
      break;
    case 'keystate': log(`键盘锁定灯状态 = 0x${s.value.toString(16)}`); break;
    case 'notpri': log('⚠️ 无虚拟介质优先级'); break;
    case 'closed':
      connected = false;
      setStatus('连接已断开', 'bad');
      showOverlay(closeCause ? `${closeCause}\n\n连接已断开。` : '连接已断开');
      break;
    case 'error':
      setStatus(`错误：${s.message}`, 'bad');
      log(`错误：${s.message}`);
      break;
  }
});

// ======================= 画面缩放 =======================
function applyZoom() {
  if (!remoteW || !remoteH) return;
  const dpr = window.devicePixelRatio || 1;
  const availW = stage.clientWidth - 16;
  const availH = stage.clientHeight - 16;
  let scale;
  if (zoomMode === 'int') {
    // Lossless: pick the largest INTEGER device-pixel multiple that still fits.
    // A source pixel then occupies exactly n x n device pixels, so nothing is
    // resampled. (Fractional scales must either blur the image or drop whole
    // pixel rows, which slices thin console text.)
    const fits = Math.min(availW / remoteW, availH / remoteH) * dpr;
    const n = Math.max(1, Math.min(4, Math.floor(fits + 1e-6)));
    scale = n / dpr;
  } else if (zoomMode === 'fit') {
    scale = Math.min(availW / remoteW, availH / remoteH);
    scale = Math.max(0.1, Math.min(scale, 4));
  } else {
    scale = Number(zoomMode);
  }
  screen.style.width = Math.round(remoteW * scale) + 'px';
  screen.style.height = Math.round(remoteH * scale) + 'px';
  const zl = $('zoomLabel');
  if (zl) {
    // Say so when the chosen scale cannot fit: an integer multiple has no lossless
    // alternative, so the honest options are "scroll" or "switch to 适应窗口".
    const over = remoteW * scale > stage.clientWidth - 16 || remoteH * scale > stage.clientHeight - 16;
    zl.textContent = Math.round(scale * 100) + '%' + (over ? '·需滚动' : '');
    zl.title = over
      ? '当前倍率放不下窗口，需要滚动。想填满请改用「适应窗口」（会略微发糊）。'
      : '显示倍率';
  }
  // `pixelated` is nearest-neighbour: great when UPscaling (crisp pixels), but when
  // DOWNscaling it drops entire pixel rows, which slices thin console text into
  // horizontal fragments. Only use it at >= 1x.
  // Lossless only when one source pixel maps to a whole number of DEVICE pixels;
  // otherwise nearest-neighbour would drop rows on downscale and smoothing would blur.
  const deviceScale = scale * dpr;
  const lossless = Math.abs(deviceScale - Math.round(deviceScale)) < 1e-6;
  screen.style.imageRendering = lossless ? 'pixelated' : (deviceScale >= 1 ? 'pixelated' : 'auto');
  lastZoom = { scale, dpr, deviceScale, lossless };
  // centring is handled by #canvasWrap; #stage only scrolls
}
new ResizeObserver(() => { if (zoomMode === 'fit') applyZoom(); }).observe(stage);

// ======================= 帧 =======================
window.kvm.onFrame(async (f) => {
  if (f.nochange) return;
  // The vendor client skips differential frames in the new-algorithm path
  // (DrawThread: isDispDiff && !resolutionCh && !firstJudge -> continue).
  // Deltas are carried by copy-blocks inside diff==0 frames instead.
  const resChanged = f.width !== lastW || f.height !== lastH;
  if (f.diff === 1 && !firstFrame && !resChanged) { skippedDiff++; return; }

  if (resChanged) {
    remoteW = f.width; remoteH = f.height;
    screen.width = remoteW;               // backing store stays at native resolution
    screen.height = remoteH;
    ctx.fillStyle = '#000'; ctx.fillRect(0, 0, remoteW, remoteH);
    log(`分辨率 ${remoteW}x${remoteH}，块网格 ${f.blockX}x${f.blockY}`);
    firstFrame = true;
    applyZoom();
  }

  try {
    lastStats = await decoder.decode({ stream: f.stream, blockX: f.blockX, blockY: f.blockY, dqt: f.dqt });
    window.__lastStats = lastStats;
    decoder.drawTo(ctx);
    framesDrawn++;
    lastFrameAt = Date.now();
    firstFrame = false;
    lastW = f.width; lastH = f.height;
    if (connected && !overlay.classList.contains('show')) setStatus('已连接', 'ok');
  } catch (e) {
    log(`解码失败：${e.message}`);
  }
});

// ======================= 输入 =======================
// Captured on `window`: a canvas only receives key events when focused, which made
// the keyboard silently do nothing. Form fields are excluded so typing still works.
let keySent = 0, mouseSent = 0, lastKeyHex = '—', lastMouseHex = '—', lastButtons = 0;

// The live input readout is a debugging aid, so it is off unless asked for.
// It also writes DOM on every mouse move, which is pure overhead when hidden.
let debugOn = localStorage.getItem('debug') === '1';
let inputUiAt = 0;

function inputUi(force) {
  if (!debugOn) return;
  const now = performance.now();
  if (!force && now - inputUiAt < 100) return;      // throttle to ~10/s
  inputUiAt = now;
  const mode = mouseMode === null ? '模式?' : (mouseMode === 1 ? '绝对' : '相对');
  $('inputState').textContent =
    `输入：键 ${keySent} / 鼠 ${mouseSent} · 鼠标${mode} · 按键 ${lastButtons} · 最近 ${lastKeyHex} ${lastMouseHex}`;
}

function applyDebug() {
  $('inputState').classList.toggle('hidden', !debugOn);
  $('btnDebug').classList.toggle('on', debugOn);
  if (debugOn) inputUi(true);
}
$('btnDebug').addEventListener('click', () => {
  debugOn = !debugOn;
  localStorage.setItem('debug', debugOn ? '1' : '0');
  applyDebug();
});
function hex(b, n = 3) {
  return Array.from(b.slice(0, n)).map((x) => x.toString(16).padStart(2, '0')).join(' ');
}
function sendKey(report, label) {
  if (!report) return;
  window.kvm.key(report);
  keySent++;
  lastKeyHex = hex(report) + (label ? `(${label})` : '');
  inputUi();
}
function typingInField(t) {
  return t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' ||
    t.tagName === 'TEXTAREA' || t.isContentEditable);
}
window.addEventListener('keydown', (e) => {
  if (!connected || typingInField(e.target)) return;
  const r = keyboard.keydown(e.code);
  if (r) { sendKey(r, e.code); e.preventDefault(); e.stopPropagation(); }
}, true);
window.addEventListener('keyup', (e) => {
  if (!connected || typingInField(e.target)) return;
  const r = keyboard.keyup(e.code);
  if (r) { sendKey(r, e.code); e.preventDefault(); e.stopPropagation(); }
}, true);

function toRemote(e) {
  const rect = screen.getBoundingClientRect();
  const sx = screen.width / rect.width;
  const sy = screen.height / rect.height;
  return [Math.round((e.clientX - rect.left) * sx), Math.round((e.clientY - rect.top) * sy)];
}
function sendMouse(e, wheel) {
  if (!connected) return;
  const [x, y] = toRemote(e);
  const buttons = e.buttons & 7;          // 1=left, 2=right, 4=middle — same as the protocol
  window.kvm.mouseAbs({ x, y, buttons, wheel: wheel || 0 });
  mouseSent++;
  lastButtons = buttons;
  const nx = remoteW ? Math.round((x * 3000) / remoteW) : 0;
  const ny = remoteH ? Math.round((y * 3000) / remoteH) : 0;
  lastMouseHex = `→${nx},${ny}${wheel ? ' w' + wheel : ''}`;
  inputUi();
}
screen.addEventListener('mousemove', (e) => sendMouse(e, 0));
screen.addEventListener('mousedown', (e) => { screen.focus(); sendMouse(e, 0); e.preventDefault(); });
screen.addEventListener('mouseup', (e) => sendMouse(e, 0));
screen.addEventListener('contextmenu', (e) => e.preventDefault());
screen.addEventListener('wheel', (e) => {
  e.preventDefault();
  wheelAcc += e.deltaY;
  if (Math.abs(wheelAcc) < 50) return;
  const steps = Math.sign(wheelAcc);
  wheelAcc = 0;
  sendMouse(e, steps);
}, { passive: false });

$('btnCad').addEventListener('click', () => window.kvm.ctrlAltDel());
$('btnIframe').addEventListener('click', () => window.kvm.requestIFrame());

// Dragging sends type 2 (continuous), releasing sends type 1 (commit) — same as
// the vendor client, which sends 1 on mouse release.
function applyQuality(v, commit) {
  quality = v;
  $('dqt').value = v;
  $('dqtVal').textContent = v;
  localStorage.setItem('dqt', String(v));
  window.kvm.setDqt(v, commit ? 1 : 2);
}
$('dqt').addEventListener('input', (e) => { $('dqtVal').textContent = e.target.value; });
$('dqt').addEventListener('change', (e) => applyQuality(Number(e.target.value), true));


// ---------- 工具栏下拉菜单 ----------
function closeMenus(except) {
  for (const m of document.querySelectorAll('.toolbar .menu.open')) {
    if (m !== except) m.classList.remove('open');
  }
}
for (const m of document.querySelectorAll('.toolbar .menu')) {
  const trigger = m.querySelector('button.caret');
  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    const willOpen = !m.classList.contains('open');
    closeMenus();
    m.classList.toggle('open', willOpen);
  });
}
document.addEventListener('click', () => closeMenus());
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenus(); });

// 电源：破坏性操作，逐项二次确认
const POWER_ACTIONS = {
  32: ['关机', '立即断电，未保存的数据会丢失。'],
  33: ['开机', '给服务器上电。'],
  34: ['重启', '强制重启（相当于按复位键）。'],
  35: ['安全重启', '请求操作系统正常重启。'],
  37: ['保存并关机', '请求操作系统保存后关机。'],
  48: ['复位 USB', '复位远端 USB 总线，键鼠会短暂中断。'],
};
for (const btn of document.querySelectorAll('[data-power]')) {
  btn.addEventListener('click', () => {
    closeMenus();
    const cmd = Number(btn.dataset.power);
    const act = POWER_ACTIONS[cmd];
    if (!act) return;
    if (!connected) { toast('未连接', 'warn'); return; }
    if (!confirm(`对远端服务器执行「${act[0]}」？\n\n${act[1]}`)) return;
    log(`电源操作：${act[0]} (0x${cmd.toString(16)})`);
    Promise.resolve(window.kvm.power(cmd)).then((r) => {
      if (r && r.ok === false) { log(`电源操作失败：${r.error}`); toast(`电源操作失败：${r.error}`, 'warn', 6000); }
    }).catch((err) => log(`电源操作失败：${err}`));
  });
}

// 缩放
for (const btn of document.querySelectorAll('[data-zoom]')) {
  btn.addEventListener('click', () => {
    closeMenus();
    zoomMode = btn.dataset.zoom;
    applyZoom();
  });
}

// 虚拟介质：选本地镜像文件后交给 Go 侧挂载
function pickLocalFile(accept) {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.style.display = 'none';
    document.body.append(input);
    input.addEventListener('change', () => {
      const f = input.files && input.files[0];
      const p = f ? (f.path || '') : '';
      input.remove();
      // WKWebView does not expose a real filesystem path; fall back to the name so the
      // failure is explained rather than silent.
      resolve(p);
    });
    input.addEventListener('cancel', () => { input.remove(); resolve(null); });
    input.click();
  });
}
for (const btn of document.querySelectorAll('[data-media]')) {
  btn.addEventListener('click', async () => {
    closeMenus();
    const kind = btn.dataset.media;
    try {
      if (kind === 'status') {
        const r = await window.kvm.media('status', '');
        toast(r && r.mounted ? `已挂载（${r.state || '?'}）` : '未挂载');
        return;
      }
      if (kind === 'detach') {
        const r = await window.kvm.media('detach', '');
        if (r && r.ok === false) { toast(`卸载失败：${r.error}`, 'warn', 6000); return; }
        toast('已卸载虚拟介质');
        return;
      }
      const path = await pickLocalFile(kind === 'iso' ? '.iso,.img,application/x-iso9660-image' : '.img,.ima');
      if (!path) {
        log('未取得文件路径。浏览器环境无法读取本地路径，请用桌面版（webview 模式）的虚拟介质功能。');
        toast('未取得文件路径（浏览器模式不支持）', 'warn', 6000);
        return;
      }
      const r = await window.kvm.media(kind, path);
      if (r && r.ok === false) { log(`挂载失败：${r.error}`); toast(`挂载失败：${r.error}`, 'warn', 7000); return; }
      toast(kind === 'iso' ? 'ISO 已挂载' : '软盘镜像已挂载');
    } catch (err) {
      log(`虚拟介质操作失败：${err}`);
      toast(`虚拟介质操作失败：${err}`, 'warn', 7000);
    }
  });
}

window.addEventListener('blur', () => { if (connected) sendKey(keyboard.releaseAll(), 'blur'); });
document.addEventListener('visibilitychange', () => {
  if (document.hidden && connected) sendKey(keyboard.releaseAll(), 'hidden');
});

// ======================= 启动 =======================
(async () => {
  await refreshSessions();
  // Start on a blank "new machine" form: opening the app should not silently put
  // an existing machine into edit mode. Selecting one is an explicit action.
  currentSessionId = null;
  fillForm(null);
  renderSessions(null);
  applyDebug();
})();

// signal to the main process (and the selftest) that this module evaluated cleanly
window.__appReady = true;

// ---- test hook: replay a captured frame through the real decoder ----
window.kvm.onReplay(async ({ stream, width, height, dqt }) => {
  try {
    const bytes = Uint8Array.from(stream);
    const blockX = Math.ceil(width / 64), blockY = Math.ceil(height / 64);
    const c = document.createElement('canvas');
    c.width = width; c.height = height;
    const cx = c.getContext('2d', { alpha: false });
    cx.fillStyle = '#000'; cx.fillRect(0, 0, width, height);

    const d = new FrameDecoder();
    const stats = await d.decode({ stream: bytes, blockX, blockY, dqt });
    d.drawTo(cx);

    const px = cx.getImageData(0, 0, width, height).data;
    let nonBlack = 0;
    for (let i = 0; i < px.length; i += 4) if (px[i] | px[i + 1] | px[i + 2]) nonBlack++;
    window.kvm.replayResult({ ok: true, stats, nonBlack, total: width * height });
  } catch (e) {
    window.kvm.replayResult({ ok: false, error: e.message });
  }
});
