const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  onState: (cb) => ipcRenderer.on('state', (_e, s) => cb(s)),
  togglePin: () => ipcRenderer.invoke('toggle-pin'),
  toggleCollapse: () => ipcRenderer.invoke('toggle-collapse'),
  hide: () => ipcRenderer.send('hide'),
  close: () => ipcRenderer.send('close'),
  openLogs: () => ipcRenderer.send('open-logs'),
  getConfig: () => ipcRenderer.invoke('get-config'),
  setConfig: (url) => ipcRenderer.invoke('set-config', url),
});