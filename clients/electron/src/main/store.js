'use strict';
// Session persistence: saved machines, optional remembered passwords.
//
// Passwords are encrypted with Electron's safeStorage (backed by the OS keychain)
// and never written in plaintext. If the OS cannot provide encryption we refuse to
// remember the password rather than silently storing it in the clear.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { app, safeStorage } = require('electron');

const FILE = () => path.join(app.getPath('userData'), 'sessions.json');

function read() {
  try {
    const raw = fs.readFileSync(FILE(), 'utf8');
    const data = JSON.parse(raw);
    if (data && Array.isArray(data.sessions)) return data;
  } catch { /* first run or unreadable -> start empty */ }
  return { version: 1, sessions: [] };
}

function write(data) {
  const file = FILE();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // write-then-rename so a crash cannot leave a truncated file
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** Strip secrets before anything leaves the main process. */
function publicView(rec) {
  const { passwordEnc, ...rest } = rec;
  return { ...rest, hasPassword: !!passwordEnc };
}

function list() {
  const d = read();
  return { sessions: d.sessions.map(publicView), lastUsed: d.lastUsed || null };
}

function idFor(host, httpsPort, username) {
  return crypto.createHash('sha1').update(`${username}@${host}:${httpsPort}`).digest('hex').slice(0, 12);
}

/**
 * Create or update a session.
 * @param rec {name, host, httpsPort, username, colorBit, remember, password?}
 * Only touches the stored password when `password` is provided.
 */
function save(rec) {
  const d = read();
  const id = rec.id || idFor(rec.host, rec.httpsPort, rec.username);
  let entry = d.sessions.find((s) => s.id === id);

  if (!entry) {
    entry = { id, createdAt: Date.now() };
    d.sessions.push(entry);
  }
  entry.name = rec.name || entry.name || `${rec.host}`;
  entry.host = rec.host;
  entry.httpsPort = rec.httpsPort || 443;
  entry.username = rec.username;
  entry.colorBit = rec.colorBit ?? 2;
  if (rec.dqt) entry.dqt = rec.dqt;
  entry.remember = !!rec.remember;
  entry.updatedAt = Date.now();

  if (rec.password) {
    if (entry.remember) {
      if (!safeStorage.isEncryptionAvailable()) {
        throw new Error('系统未提供加密存储（safeStorage 不可用），无法安全地记住密码');
      }
      entry.passwordEnc = safeStorage.encryptString(rec.password).toString('base64');
    } else {
      delete entry.passwordEnc;          // user turned remembering off
    }
  } else if (!entry.remember) {
    delete entry.passwordEnc;
  }

  d.lastUsed = id;
  write(d);
  return publicView(entry);
}

function remove(id) {
  const d = read();
  d.sessions = d.sessions.filter((s) => s.id !== id);
  if (d.lastUsed === id) d.lastUsed = null;
  write(d);
  return true;
}

/** Main-process only: returns the decrypted password for a saved session. */
function password(id) {
  const d = read();
  const entry = d.sessions.find((s) => s.id === id);
  if (!entry || !entry.passwordEnc) return null;
  try {
    return safeStorage.decryptString(Buffer.from(entry.passwordEnc, 'base64'));
  } catch {
    return null;                            // keychain changed / other machine
  }
}

function get(id) {
  const d = read();
  const entry = d.sessions.find((s) => s.id === id);
  return entry ? publicView(entry) : null;
}

function markUsed(id) {
  const d = read();
  if (d.sessions.some((s) => s.id === id)) { d.lastUsed = id; write(d); }
}

/**
 * Work out which password to use for a connect request.
 * Accepts both `sessionId` and `id`: the renderer's form record calls it `id`,
 * and a mismatch here silently disabled keychain lookup once already.
 *
 * @returns {{password: string|null, source: 'provided'|'keychain'|'none'}}
 * @throws if the record claims a stored password that cannot be decrypted
 */
function resolvePassword(opts = {}) {
  if (opts.password) return { password: opts.password, source: 'provided' };
  const sessionId = opts.sessionId || opts.id;
  if (sessionId) {
    const pw = password(sessionId);
    if (pw) return { password: pw, source: 'keychain' };
    if (get(sessionId)?.hasPassword) {
      throw new Error('已保存的密码无法解密（系统钥匙串条目可能已失效）。请重新输入密码，或取消「记住密码」后再连。');
    }
  }
  return { password: null, source: 'none' };
}

module.exports = { list, save, remove, password, get, markUsed, resolvePassword, idFor, file: FILE };
