'use strict';
// Verifies session persistence and that a remembered password is really encrypted
// on disk (no plaintext). Runs under Electron so safeStorage is available:
//
//   node_modules/.bin/electron test/store.test.js
//
const { app, safeStorage } = require('electron');
const fs = require('node:fs');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

// CRITICAL: this test deletes every session it finds, so it must never touch the
// real profile. Redirect userData to a throwaway directory before anything reads it.
const SANDBOX = path.join(os.tmpdir(), `ibmc-store-test-${Date.now()}`);
fs.mkdirSync(SANDBOX, { recursive: true });
app.setPath('userData', SANDBOX);

let passed = 0, failed = 0;
function check(name, fn) {
  try { fn(); console.log(`  ✅ ${name}`); passed++; }
  catch (e) { console.log(`  ❌ ${name}\n     ${e.message}`); failed++; }
}

app.whenReady().then(() => {
  const store = require('../src/main/store');
  const SECRET = 'S3cr3t-P@ssw0rd-must-not-leak-9f2a';

  console.log('=== 会话存储 / 凭据加密 ===');
  console.log(`  存储文件: ${store.file()}`);
  console.log(`  safeStorage 可用: ${safeStorage.isEncryptionAvailable()}`);

  // clean slate
  for (const s of store.list().sessions) store.remove(s.id);

  let saved;
  check('保存机器（勾选记住密码）', () => {
    saved = store.save({
      name: '测试机', host: '10.0.0.9', httpsPort: 443, username: 'root',
      colorBit: 2, remember: true, password: SECRET,
    });
    assert.strictEqual(saved.name, '测试机');
    assert.strictEqual(saved.host, '10.0.0.9');
    assert.strictEqual(saved.hasPassword, true);
  });

  check('list() 不泄露密码字段', () => {
    const d = store.list();
    const rec = d.sessions.find((s) => s.id === saved.id);
    assert.ok(rec, '应能列出');
    assert.strictEqual(rec.password, undefined);
    assert.strictEqual(rec.passwordEnc, undefined);
    assert.strictEqual(rec.hasPassword, true);
  });

  check('磁盘文件里没有明文密码', () => {
    const raw = fs.readFileSync(store.file(), 'utf8');
    assert.ok(!raw.includes(SECRET), '文件里出现了明文密码！');
    assert.ok(!raw.includes('S3cr3t'), '文件里出现了密码片段！');
    assert.ok(raw.includes('passwordEnc'), '应存在加密字段');
  });

  check('能解回原密码（走系统钥匙串）', () => {
    const got = store.password(saved.id);
    assert.strictEqual(got, SECRET);
  });

  check('未勾选记住密码时不保存', () => {
    const s2 = store.save({
      host: '10.0.0.10', httpsPort: 443, username: 'admin',
      remember: false, password: 'another-secret',
    });
    assert.strictEqual(s2.hasPassword, false);
    assert.strictEqual(store.password(s2.id), null);
    const raw = fs.readFileSync(store.file(), 'utf8');
    assert.ok(!raw.includes('another-secret'), '不该出现明文');
    store.remove(s2.id);
  });

  check('修改名称后密码仍在', () => {
    const s3 = store.save({ id: saved.id, name: '改过名的机器', host: '10.0.0.9', httpsPort: 443, username: 'root', remember: true });
    assert.strictEqual(s3.name, '改过名的机器');
    assert.strictEqual(s3.hasPassword, true);
    assert.strictEqual(store.password(saved.id), SECRET);
  });

  check('取消「记住密码」会删除已存密码', () => {
    const s4 = store.save({ id: saved.id, name: '改过名的机器', host: '10.0.0.9', httpsPort: 443, username: 'root', remember: false });
    assert.strictEqual(s4.hasPassword, false);
    assert.strictEqual(store.password(saved.id), null);
  });

  check('删除机器', () => {
    store.remove(saved.id);
    assert.strictEqual(store.list().sessions.find((s) => s.id === saved.id), undefined);
  });

  console.log('\n=== resolvePassword 的字段名契约 ===');
  // Regression: the renderer sends the session key as `id`, main used to read only
  // `sessionId`, so keychain lookup never ran and connecting said "缺少密码".
  let withPw;
  check('准备：保存一台带密码的机器', () => {
    withPw = store.save({
      name: '契约测试', host: '10.0.0.20', httpsPort: 443, username: 'root',
      remember: true, password: 'pw-for-contract-test',
    });
    assert.strictEqual(withPw.hasPassword, true);
  });

  check('显式提供密码时优先使用它（source=provided）', () => {
    const r = store.resolvePassword({ id: withPw.id, password: 'typed' });
    assert.strictEqual(r.password, 'typed');
    assert.strictEqual(r.source, 'provided');
  });

  check('用 id 取出钥匙串密码（source=keychain）', () => {
    const r = store.resolvePassword({ id: withPw.id });
    assert.strictEqual(r.password, 'pw-for-contract-test');
    assert.strictEqual(r.source, 'keychain');
  });

  check('用 sessionId 也能取出（两种字段名都接受）', () => {
    const r = store.resolvePassword({ sessionId: withPw.id });
    assert.strictEqual(r.password, 'pw-for-contract-test');
    assert.strictEqual(r.source, 'keychain');
  });

  check('未知 id 且无密码 → none（调用方报「缺少密码」）', () => {
    const r = store.resolvePassword({ id: 'nope', host: '10.0.0.20', username: 'root' });
    assert.strictEqual(r.password, null);
    assert.strictEqual(r.source, 'none');
  });

  check('空请求 → none', () => {
    assert.strictEqual(store.resolvePassword({}).source, 'none');
    assert.strictEqual(store.resolvePassword().source, 'none');
  });

  check('记录声称有密码但解不开时抛明确错误，而不是「缺少密码」', () => {
    // simulate a stale keychain entry by corrupting the ciphertext
    const raw = JSON.parse(fs.readFileSync(store.file(), 'utf8'));
    const rec = raw.sessions.find((s) => s.id === withPw.id);
    rec.passwordEnc = Buffer.from('not-a-valid-ciphertext').toString('base64');
    fs.writeFileSync(store.file(), JSON.stringify(raw));
    assert.throws(() => store.resolvePassword({ id: withPw.id }), /无法解密/);
    store.remove(withPw.id);
  });

  console.log('\n=== 改密码 / 覆盖已存密码 ===');
  let ov;
  check('准备：存一台带旧密码的机器', () => {
    ov = store.save({
      name: '覆盖测试', host: '10.0.0.30', httpsPort: 443, username: 'root',
      remember: true, password: 'OLD-password',
    });
    assert.strictEqual(store.password(ov.id), 'OLD-password');
  });

  check('输入新密码 → 覆盖旧的（且磁盘上仍是密文）', () => {
    store.save({ id: ov.id, host: '10.0.0.30', httpsPort: 443, username: 'root', remember: true, password: 'NEW-password' });
    assert.strictEqual(store.password(ov.id), 'NEW-password');
    const raw = fs.readFileSync(store.file(), 'utf8');
    assert.ok(!raw.includes('NEW-password'), '不该出现明文');
    assert.ok(!raw.includes('OLD-password'), '旧明文也不该残留');
  });

  check('不改密码时（password 未提供）保留原密码', () => {
    store.save({ id: ov.id, name: '改个名字', host: '10.0.0.30', httpsPort: 443, username: 'root', remember: true });
    assert.strictEqual(store.password(ov.id), 'NEW-password');
  });

  check('取消「记住密码」→ 删除已存密码', () => {
    store.save({ id: ov.id, host: '10.0.0.30', httpsPort: 443, username: 'root', remember: false });
    assert.strictEqual(store.password(ov.id), null);
    store.remove(ov.id);
  });

  console.log(`\n=== 结果：${passed} 通过, ${failed} 失败 ===`);
  app.exit(failed ? 1 : 0);
});
