/**

BytesProtector — Preload / Context Bridge

Exposes safe IPC methods to the renderer.
*/

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('bp', {

// Window controls
minimize: () => ipcRenderer.send('window-minimize'),
maximize: () => ipcRenderer.send('window-maximize'),
close: () => ipcRenderer.send('window-close'),

// Settings
getSettings: () => ipcRenderer.invoke('get-settings'),
saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),

// Dialogs
chooseDirectory: () => ipcRenderer.invoke('choose-directory'),
chooseFiles: () => ipcRenderer.invoke('choose-files'),
chooseSavePath: (name) => ipcRenderer.invoke('choose-save-path', name),

// Scan
startScan: (opts) => ipcRenderer.invoke('start-scan', opts),
stopScan: () => ipcRenderer.send('stop-scan'),
onScanEvent: (callback) =>
ipcRenderer.on('scan-event', (_, data) => callback(data)),
offScanEvents: () => ipcRenderer.removeAllListeners('scan-event'),

// Quarantine
getQuarantine: () => ipcRenderer.invoke('get-quarantine'),
quarantineDeleteAll: () => ipcRenderer.invoke('quarantine-delete-all'),
quarantineRestore: (id) => ipcRenderer.invoke('quarantine-restore', id),
quarantineDeleteItem: (id) => ipcRenderer.invoke('quarantine-delete-item', id),

// Reports
getReport: () => ipcRenderer.invoke('get-report'),
exportReport: (path) => ipcRenderer.invoke('export-report', path),

// AI verdict (FIXES YOUR ERROR)
aiVerdict: (data) => ipcRenderer.invoke('ai-verdict', data)

});