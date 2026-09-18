'use strict';
// iBMC web login + JNLP retrieval.
//
// Flow reverse-engineered from the served frontend (/bmc/resources/js/login.js):
//   POST /bmc/php/processparameter.php
//        { check_pwd, logtype, user_name, func, IsKvmApp }
//   func = "AddSession"  -> normal web login
//   func = "DirectKVM"   -> granted a KVM session directly; the web UI then opens
//                           /bmc/pages/remote/kvm.php?kvmway=0  (this firmware serves the JNLP for both kvmway values)
// The session cookie from that POST is what authorises kvm.php, so we keep a cookie jar.

const https = require('node:https');
const crypto = require('node:crypto');

// The BMC ships a self-signed certificate; there is no CA to pin against.
// This mirrors what the vendor's own Java applet / browser flow accepts.
const agent = new https.Agent({ rejectUnauthorized: false, keepAlive: true });

class CookieJar {
  constructor() { this.cookies = new Map(); }
  store(res) {
    const set = res.headers['set-cookie'];
    if (!set) return;
    for (const line of set) {
      const [pair] = line.split(';');
      const i = pair.indexOf('=');
      if (i > 0) this.cookies.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
    }
  }
  header() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

function request(host, port, method, path, { headers = {}, body = null, jar = null, timeout = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const h = { ...headers };
    if (jar && jar.header()) h.Cookie = jar.header();
    if (body != null) h['Content-Length'] = Buffer.byteLength(body);
    const req = https.request({ host, port, method, path, headers: h, agent, timeout }, (res) => {
      if (jar) jar.store(res);
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
      }));
    });
    req.on('timeout', () => req.destroy(new Error('请求超时')));
    req.on('error', reject);
    if (body != null) req.write(body);
    req.end();
  });
}

/** Extract the JNLP URL from whatever kvm.php returns (JNLP itself, HTML, or a redirect target). */
function findJnlpUrl(text, base) {
  const patterns = [
    /<jnlp[\s>]/i,                                     // already the JNLP
    /["']([^"']*\.jnlp[^"']*)["']/i,
    /(?:href|src)\s*=\s*["']([^"']+)["']/i,
    /window\.open\(\s*["']([^"']+)["']/i,
    /(?:url|location\.href)\s*[=:]\s*["']([^"']+)["']/i,
  ];
  for (const re of patterns) {
    const m = text.match(re);
    if (m && m[1]) {
      let u = m[1];
      if (u.startsWith('//')) u = 'https:' + u;
      else if (u.startsWith('/')) u = base + u;
      else if (!/^https?:/i.test(u)) u = base + '/' + u.replace(/^\.?\//, '');
      return u;
    }
  }
  return null;
}

function parseJnlpParams(xml) {
  const params = {};
  for (const m of xml.matchAll(/<param\s+name="([^"]+)"\s+value="([^"]*)"\s*\/?>/gi)) params[m[1]] = m[2];
  return params;
}

/**
 * Log in and obtain a JNLP session descriptor.
 * Returns { jnlp, params, host, cookieHeader }.
 */
async function loginAndGetJnlp({ host, port = 443, username, password, log }) {
  const jar = new CookieJar();
  const base = `https://${host}:${port}`;
  const say = (m) => log && log(m);

  // warm up / pick up any pre-session cookie
  try { await request(host, port, 'GET', '/login.html', { jar }); } catch { /* optional */ }

  const form = new URLSearchParams({
    check_pwd: password,
    logtype: '0',
    user_name: username,
    func: 'DirectKVM',
    IsKvmApp: '0',
  }).toString();

  say('登录中（DirectKVM）…');
  let res = await request(host, port, 'POST', '/bmc/php/processparameter.php', {
    jar,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', Accept: 'application/json, text/javascript, */*; q=0.01' },
    body: form,
  });

  let json = null;
  try { json = JSON.parse(res.body.toString('utf8')); } catch { /* not json */ }

  let directOk = false;
  if (json && json.DirectKVM) {
    const ret = Array.isArray(json.DirectKVM) ? json.DirectKVM[0] : json.DirectKVM;
    if (ret === 0) directOk = true;
    else say(`DirectKVM 返回码 ${ret}`);
  } else if (json && json.AuthUser) {
    const ret = Array.isArray(json.AuthUser) ? json.AuthUser[0] : json.AuthUser;
    if (ret === 0) {
      say('DirectKVM 不被支持，改用 AddSession 普通登录…');
      const form2 = new URLSearchParams({ check_pwd: password, logtype: '0', user_name: username, func: 'AddSession', IsKvmApp: '0' }).toString();
      res = await request(host, port, 'POST', '/bmc/php/processparameter.php', {
        jar,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', Accept: 'application/json, text/javascript, */*; q=0.01' },
        body: form2,
      });
      try { json = JSON.parse(res.body.toString('utf8')); } catch { /* ignore */ }
      const sess = json && json.AddSession ? json.AddSession : null;
      if (sess && Array.isArray(sess) && sess[0] === 0 && sess[1]) directOk = true;
    } else {
      throw new Error(describeAuthCode(ret));
    }
  } else if (res.status === 200 && !json) {
    throw new Error('登录响应无法解析（可能地址或端口不对）');
  }

  if (!directOk) throw new Error('登录失败：未取得 KVM 会话');

  // Fetch the console entry point; it either returns the JNLP or a page pointing at it.
  // The frontend builds this URL as: kvmway = "jre" (default) | requestStr["openway"];
  //   way = (kvmway == "html5") ? "?kvmway=1" : "?kvmway=0"
  //   window.open("/bmc/pages/remote/kvm.php" + way, "_self")
  // On this firmware kvmway=1 also returns the JNLP (verified 2026-09-18): there is
  // no HTML5 console, the html5 branch in the frontend is dead code.
  const stamp = Date.now();
  const candidates = [
    '/bmc/pages/remote/kvm.php?kvmway=0',
    `/bmc/pages/remote/kvm.php?kvmway=0&random_str=${stamp}`,
    '/bmc/pages/remote/kvm.php',
  ];
  let jnlpText = null, jnlpUrl = null;
  for (const path of candidates) {
    // mimic the real top-level navigation so referer-based checks don't reject us
    const r = await request(host, port, 'GET', path, {
      jar,
      headers: { Accept: '*/*', Referer: `${base}/login.html` },
    });
    const text = r.body.toString('utf8');
    const ct = r.headers['content-type'] || '?';
    const cd = r.headers['content-disposition'] || '';
    say(`GET ${path} → ${r.status}, ${r.body.length}B, content-type=${ct}${cd ? `, disposition=${cd}` : ''}`);
    if (/<jnlp[\s>]/i.test(text)) { jnlpText = text; jnlpUrl = base + path; break; }
    const u = findJnlpUrl(text, base);
    if (u && u !== base + path) {
      const r2 = await request(host, port, 'GET', u.replace(base, ''), { jar, headers: { Accept: '*/*' } });
      const t2 = r2.body.toString('utf8');
      if (/<jnlp[\s>]/i.test(t2)) { jnlpText = t2; jnlpUrl = u; break; }
      say(`  指向的 ${u} 不是 JNLP（${r2.status}）`);
    }
    // Not a JNLP: show a snippet so the reason is visible instead of just "failed".
    const snippet = text.replace(/\s+/g, ' ').slice(0, 200);
    say(`  不是 JNLP，响应开头：${snippet || '(空)'}`);
    if (/html5|noVNC|novnc|websocket/i.test(text)) {
      say('  ⚠️ 该页面提到了 html5/websocket —— 可能另有 HTML5 控制台');
    }
  }
  if (!jnlpText) {
    throw new Error(
      '未能从 kvm.php 取得 JNLP。\n' +
      '请点「用 JNLP 文件连接…」，选一个从 Web UI 下载的 .jnlp 文件绕过这一步。\n' +
      '（每个 JNLP 只能用一次，所以每次都要重新下载。）'
    );
  }

  const params = parseJnlpParams(jnlpText);
  const m = jnlpText.match(/codebase="https?:\/\/([^"\/]+)/i);
  return {
    jnlp: jnlpText,
    params,
    jnlpUrl,
    host: m ? m[1].split(':')[0] : host,
    cookieHeader: jar.header(),
    raw: json,
  };
}

function describeAuthCode(code) {
  // 130 was observed live for a nonexistent user (verified 2026-09-18); the rest are
  // the codes the vendor's login.js maps explicitly.
  const map = {
    130: '用户名或密码错误',
    131: '账号已被锁定',
    136: '用户无访问权限',
    137: '用户名或密码已过期',
    144: '登录用户数已达上限',
  };
  return map[code] || `登录失败（返回码 ${code}）`;
}

/** Build the AES key/IV material out of the JNLP `decrykey` parameter. */
function sessionKeys(params) {
  const decry = Buffer.from(params.decrykey || '', 'hex');
  if (decry.length !== 32) throw new Error('decrykey 长度不是 32 字节');
  return { userKey: decry.subarray(0, 16), userIv: decry.subarray(16, 32) };
}

module.exports = { loginAndGetJnlp, parseJnlpParams, sessionKeys, request, CookieJar, describeAuthCode };
