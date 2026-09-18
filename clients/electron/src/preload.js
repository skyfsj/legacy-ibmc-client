'use strict';
// Bridge between the renderer (UI) and the main process (raw TCP + protocol).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kvm', {
  connect: (opts) => ipcRenderer.invoke('kvm:connect', opts),
  pickJnlp: () => ipcRenderer.invoke('kvm:pickJnlp'),
  disconnect: () => ipcRenderer.send('kvm:disconnect'),

  // saved sessions / machines
  sessions: {
    list: () => ipcRenderer.invoke('kvm:sessions:list'),
    save: (rec) => ipcRenderer.invoke('kvm:sessions:save', rec),
    remove: (id) => ipcRenderer.invoke('kvm:sessions:remove', id),
  },

  key: (report) => ipcRenderer.send('kvm:key', Array.from(report)),
  mouseAbs: (m) => ipcRenderer.send('kvm:mouseAbs', m),
  mouseRel: (m) => ipcRenderer.send('kvm:mouseRel', m),
  ctrlAltDel: () => ipcRenderer.send('kvm:ctrlAltDel'),
  setDqt: (v, type) => ipcRenderer.send('kvm:dqt', { v, type }),
  requestIFrame: () => ipcRenderer.send('kvm:iframe'),
  power: (cmd) => ipcRenderer.send('kvm:power', cmd),
  media: (action, path) => ipcRenderer.invoke('kvm:media', { action, path }),

  onFrame: (cb) => ipcRenderer.on('kvm:frame', (_e, f) => cb(f)),
  onLog: (cb) => ipcRenderer.on('kvm:log', (_e, m) => cb(m)),
  onStatus: (cb) => ipcRenderer.on('kvm:status', (_e, s) => cb(s)),
  onSessions: (cb) => ipcRenderer.on('kvm:sessions', (_e, d) => cb(d)),

  // test hook: replay a captured frame through the real decoder in Chromium
  onReplay: (cb) => ipcRenderer.on('test:replay', (_e, d) => cb(d)),
  replayResult: (r) => ipcRenderer.send('test:replayResult', r),
});
