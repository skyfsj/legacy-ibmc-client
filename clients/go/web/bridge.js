// Bridge: implements the same `window.kvm` interface the Electron preload exposed,
// but backed by Go bindings, with an HTTP fallback for the external-browser mode.
//
// Go side: see main.go (wv.Bind / jsCall / the /api endpoints).
// This file must load BEFORE app.js.
(function () {
  'use strict';

  const listeners = {
    frame: [], log: [], status: [], sessions: [], replay: [], connectResult: [],
  };
  const emit = (kind) => (payload) => {
    for (const cb of listeners[kind]) {
      try { cb(payload); } catch (e) { console.error(e); }
    }
  };

  // Reports through plain HTTP rather than a Go binding, so it still works when the
  // bindings are missing or broken — which is exactly when we need the output.
  const trace = (m) => {
    try { fetch('/api/trace?m=' + encodeURIComponent('bridge: ' + m)); } catch (e) { /* ignore */ }
  };

  // Go declares the transport via wv.Init. Do NOT sniff for a binding name: renaming
  // a binding once silently switched the page to the HTTP path (goConnect -> goConnectAsync).
  const HAS_BINDINGS = window.__kvmTransport === 'webview'
    || typeof window.goConnectAsync === 'function';
  trace('start transport=' + (HAS_BINDINGS ? 'webview' : 'http')
    + ' declared=' + window.__kvmTransport);

  // ---- events pushed from Go (webview transport) ----
  window.__kvmLog = emit('log');
  window.__kvmStatus = emit('status');
  window.__kvmSessions = emit('sessions');
  window.__kvmFrame = (f) => {
    if (f && typeof f.stream === 'string') f.stream = b64ToBytes(f.stream);
    emit('frame')(f);
  };
  window.__kvmConnectResult = emit('connectResult');

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---- transport ----
  const call = HAS_BINDINGS
    ? (name, ...args) => window[name](...args)
    : async (name, ...args) => {
      const r = await fetch('/api/call', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, args }),
      });
      if (!r.ok) throw new Error(await r.text());
      return r.text();
    };

  const parse = (r) => (typeof r === 'string' ? JSON.parse(r) : r);

  if (!HAS_BINDINGS) {
    // External-browser mode: server-sent events carry the same payloads the webview
    // receives through __kvm* globals.
    const es = new EventSource('/api/events');
    for (const name of ['log', 'status', 'sessions', 'frame', 'connectResult']) {
      es.addEventListener(name, (ev) => {
        let data;
        try { data = JSON.parse(ev.data); } catch (e) { return; }
        if (name === 'frame' && data && typeof data.stream === 'string') {
          data.stream = b64ToBytes(data.stream);
        }
        emit(name)(data);
      });
    }
    es.addEventListener('error', () => emit('log')('与本地服务的连接中断，正在重连…'));
    trace('sse subscribed');
  }

  // ---- JNLP file picker (no native dialog needed) ----
  function pickFile() {
    return new Promise((resolve) => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.jnlp,application/x-java-jnlp-file';
      input.style.display = 'none';
      document.body.append(input);
      input.addEventListener('change', () => {
        const file = input.files && input.files[0];
        input.remove();
        if (!file) return resolve(null);
        const fr = new FileReader();
        fr.onload = () => resolve(String(fr.result));
        fr.onerror = () => resolve(null);
        fr.readAsText(file);
      });
      input.addEventListener('cancel', () => { input.remove(); resolve(null); });
      input.click();
    });
  }

  window.kvm = {
    // Connecting performs an HTTPS login plus a TCP dial, so Go runs it off the UI
    // thread and reports back through an event. Doing it synchronously froze the
    // window for the whole login (and made the video stream back up).
    connect(opts) {
      return new Promise((resolve) => {
        listeners.connectResult.push((r) => resolve(r));
        Promise.resolve(call('goConnectAsync', JSON.stringify(opts || {}))).catch((e) => {
          listeners.connectResult.pop();
          resolve({ ok: false, error: String((e && e.message) || e) });
        });
      });
    },
    transport: HAS_BINDINGS ? 'webview' : 'http',

    pickJnlp: () => pickFile(),
    disconnect: () => { call('goDisconnect'); },

    key: (report) => { call('goKey', Array.from(report)); },
    mouseAbs: (m) => { call('goMouse', m.x | 0, m.y | 0, m.buttons | 0, m.wheel | 0); },
    mouseRel: (m) => { call('goMouseRel', m.dx | 0, m.dy | 0, m.buttons | 0); },
    ctrlAltDel: () => { call('goCtrlAltDel'); },
    power: async (cmd) => parse(await call('goPower', cmd | 0)),
    media: async (action, path) => parse(await call('goMedia', action, path || '')),
    setDqt: (v, type) => { call('goSetDqt', v | 0, type | 0); },
    requestIFrame: () => { call('goRequestIFrame'); },

    sessions: {
      list: async () => parse(await call('goSessionsList')),
      save: async (rec) => parse(await call('goSessionsSave', JSON.stringify(rec || {}))),
      remove: async (id) => parse(await call('goSessionsRemove', id)),
      storageInfo: async () => parse(await call('goStorageInfo')),
    },

    onFrame: (cb) => listeners.frame.push(cb),
    onLog: (cb) => listeners.log.push(cb),
    onStatus: (cb) => listeners.status.push(cb),
    onSessions: (cb) => listeners.sessions.push(cb),

    // Test hooks only exist for the Electron --replaytest path.
    onReplay: () => {},
    replayResult: () => {},
  };
  trace('window.kvm ready');

  // Tell Go once app.js has finished evaluating, so --selftest can assert that the
  // whole module graph (bridge -> app -> decoder/hid/tables) loaded cleanly.
  let waited = 0;
  (function waitReady() {
    if (window.__appReady) {
      trace('app.js ready');
      try { call('goReady'); } catch (e) { trace('goReady failed: ' + e); }
      return;
    }
    waited += 100;
    if (waited === 3000) trace('app.js not ready after 3s');
    setTimeout(waitReady, 100);
  })();

  window.addEventListener('error', (e) => trace('page error: ' + (e.message || e.type)));
})();
