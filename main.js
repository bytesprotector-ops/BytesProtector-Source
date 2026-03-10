/**
 * BytesProtector — Electron Main Process
 * Manages window, IPC, and spawns backend engine processes.
 */

const { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage } = require('electron');
const path  = require('path');
const fs    = require('fs');
const { spawn, execFile } = require('child_process');

// ─── Config paths ──────────────────────────────────────────────────────────
// ROOT = app source (inside asar in production — read-only, cannot mkdir here)
// DATA = writable user data dir (persists across updates, safe to mkdir)
const ROOT          = __dirname;
const ASSETS        = path.join(ROOT, 'assets');
// In packaged builds, backend is unpacked from asar to app.asar.unpacked
// __dirname is .../resources/app.asar  →  unpacked is .../resources/app.asar.unpacked
const UNPACKED_ROOT = ROOT.replace('app.asar', 'app.asar.unpacked');
const BACKEND_PY    = path.join(UNPACKED_ROOT, 'backend', 'python', 'engine.py');

// In packaged builds app.getPath('userData') is e.g.
//   C:\Users\<user>\AppData\Roaming\BytesProtector
// In dev it falls back to __dirname so paths stay the same
const IS_PACKED     = app.isPackaged;
const DATA_DIR      = IS_PACKED ? app.getPath('userData') : ROOT;
const CONFIG_PATH   = IS_PACKED
  ? path.join(DATA_DIR, 'settings.json')
  : path.join(ROOT, 'config', 'settings.json');
const QUAR_DIR      = path.join(DATA_DIR, 'quarantine');
const LOG_DIR       = path.join(DATA_DIR, 'logs');

// Ensure writable dirs exist (DATA_DIR is always a real directory)
[QUAR_DIR, LOG_DIR].forEach(d => {
  try { fs.mkdirSync(d, { recursive: true }); } catch(e) {
    console.error('Failed to create dir', d, e.message);
  }
});

// ─── Default settings ──────────────────────────────────────────────────────
let settings = {
  realtimeProtection: true,
  autoQuarantine: true,
  heuristicEngine: true,
  mlClassifier: true,
  rustHashVerifier: true,
  scanOnStartup: false,
  excludePaths: [],
};

function loadSettings() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      Object.assign(settings, JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')));
    }
  } catch (_) {}
}

function saveSettings() {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(settings, null, 2));
}

loadSettings();

// ─── Window ────────────────────────────────────────────────────────────────
let mainWindow;
let tray;

function createWindow() {
  mainWindow = new BrowserWindow({
    width:  1280,
    height: 800,
    minWidth:  1000,
    minHeight: 650,
    frame: false,           // Custom titlebar
    transparent: false,
    backgroundColor: '#080809',
    icon: path.join(ASSETS, 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(ROOT, 'preload.js'),
    },
    show: false,
  });

  mainWindow.loadFile('app/index.html');

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
  createWindow();

  // Tray
  try {
    const trayIcon = nativeImage.createFromPath(path.join(ASSETS, 'icon.png'))
      .resize({ width: 16, height: 16 });
    tray = new Tray(trayIcon);
    tray.setToolTip('BytesProtector');
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: 'Open',  click: () => mainWindow?.show()  },
      { label: 'Quit',  click: () => app.quit()          },
    ]));
    tray.on('double-click', () => mainWindow?.show());
  } catch (_) {}
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ─── Window controls IPC ───────────────────────────────────────────────────
ipcMain.on('window-minimize', () => mainWindow?.minimize());
ipcMain.on('window-maximize', () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize();
  else mainWindow?.maximize();
});
ipcMain.on('window-close', () => mainWindow?.close());

// ─── Settings IPC ─────────────────────────────────────────────────────────
ipcMain.handle('get-settings', () => settings);
ipcMain.handle('save-settings', (_, newSettings) => {
  Object.assign(settings, newSettings);
  saveSettings();
  return true;
});

// ─── File dialog ──────────────────────────────────────────────────────────
ipcMain.handle('choose-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('choose-files', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select files to scan',
    properties: ['openFile', 'multiSelections'],
    filters: [
      { name: 'Executable & Archives', extensions: ['exe','dll','zip','bat','cmd','ps1','vbs','msi','scr','jar','py','js'] },
      { name: 'All Files', extensions: ['*'] },
    ],
  });
  return result.canceled ? [] : result.filePaths;
});

ipcMain.handle('choose-save-path', async (_, defaultName) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: defaultName,
    filters: [{ name: 'JSON', extensions: ['json'] }],
  });
  return result.canceled ? null : result.filePath;
});

// ─── Scan IPC ─────────────────────────────────────────────────────────────
let scanProcess = null;

ipcMain.handle('start-scan', async (event, { paths, files, scanType }) => {
  if (scanProcess) return { error: 'Scan already running' };

  return new Promise((resolve) => {
    let args;

    if (scanType === 'endpoint') {
      // Launch endpoint daemon instead of scanner
      args = [BACKEND_PY, '--endpoint'];
    } else {
      args = [BACKEND_PY, '--scan', '--type', scanType,
              '--quarantine-dir', QUAR_DIR];
      if (files && files.length > 0) {
        args.push('--files', ...files);
      } else if (paths && paths.length > 0) {
        args.push('--paths', ...paths);
      }
    }

    // 'python3' on mac/linux, 'python' on windows
    const pyExe = process.platform === 'win32' ? 'python' : 'python3';
    scanProcess = spawn(pyExe, args);
    let output = '';

    scanProcess.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;
      // Stream each line as an event
      text.split('\n').filter(Boolean).forEach(line => {
        try {
          const msg = JSON.parse(line);
          mainWindow?.webContents.send('scan-event', msg);
        } catch (_) {
          mainWindow?.webContents.send('scan-event', { type: 'log', text: line });
        }
      });
    });

    scanProcess.stderr.on('data', (data) => {
      mainWindow?.webContents.send('scan-event', {
        type: 'log', text: data.toString(), level: 'warn'
      });
    });

    scanProcess.on('close', (code) => {
      scanProcess = null;
      mainWindow?.webContents.send('scan-event', { type: 'done', code });
      resolve({ code });
    });
  });
});

ipcMain.on('stop-scan', () => {
  if (scanProcess) {
    scanProcess.kill();
    scanProcess = null;
  }
});

// ─── Quarantine IPC ───────────────────────────────────────────────────────
ipcMain.handle('get-quarantine', () => {
  const idx = path.join(QUAR_DIR, 'index.json');
  try {
    return fs.existsSync(idx) ? JSON.parse(fs.readFileSync(idx, 'utf8')) : [];
  } catch (_) { return []; }
});

ipcMain.handle('quarantine-delete-all', () => {
  const idx = path.join(QUAR_DIR, 'index.json');
  let items = [];
  try { items = JSON.parse(fs.readFileSync(idx, 'utf8')); } catch (_) {}
  items.forEach(item => {
    try { fs.unlinkSync(item.quarfile); } catch (_) {}
  });
  fs.writeFileSync(idx, '[]');
  return true;
});

ipcMain.handle('quarantine-restore', (_, id) => {
  const idx = path.join(QUAR_DIR, 'index.json');
  let items = [];
  try { items = JSON.parse(fs.readFileSync(idx, 'utf8')); } catch (_) { return { ok: false, error: 'index read failed' }; }
  const item = items.find(i => i.id === id);
  if (!item) return { ok: false, error: 'item not found' };
  try {
    const enc = fs.readFileSync(item.quarfile);
    const dec = Buffer.from(enc.map(b => b ^ 0xAA));
    // Restore to original path, or Desktop if original is gone/unsafe
    let dest = item.path;
    const destDir = path.dirname(dest);
    if (!fs.existsSync(destDir)) {
      dest = path.join(require('os').homedir(), 'Desktop', item.name);
    }
    fs.writeFileSync(dest, dec);
    fs.unlinkSync(item.quarfile);
    const updated = items.filter(i => i.id !== id);
    fs.writeFileSync(idx, JSON.stringify(updated, null, 2));
    return { ok: true, path: dest };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('quarantine-delete-item', (_, id) => {
  const idx = path.join(QUAR_DIR, 'index.json');
  let items = [];
  try { items = JSON.parse(fs.readFileSync(idx, 'utf8')); } catch (_) { return false; }
  const item = items.find(i => i.id === id);
  if (!item) return false;
  try { fs.unlinkSync(item.quarfile); } catch (_) {}
  const updated = items.filter(i => i.id !== id);
  fs.writeFileSync(idx, JSON.stringify(updated, null, 2));
  return true;
});

// ─── Reports IPC ──────────────────────────────────────────────────────────
ipcMain.handle('get-report', () => {
  const rp = path.join(LOG_DIR, 'scan_history.json');
  try {
    return fs.existsSync(rp) ? JSON.parse(fs.readFileSync(rp, 'utf8')) : [];
  } catch (_) { return []; }
});

ipcMain.handle('export-report', (_, filePath) => {
  const rp = path.join(LOG_DIR, 'scan_history.json');
  try {
    const data = fs.existsSync(rp) ? fs.readFileSync(rp, 'utf8') : '[]';
    fs.writeFileSync(filePath, data);
    return true;
  } catch (_) { return false; }
});

// ─── AI Verdict IPC ───────────────────────────────────────────────────────
// Uses the local AI model (engine.py --verdict) — no external API needed.
ipcMain.handle('ai-verdict', async (_, { item }) => {
  return new Promise((resolve) => {
    const pyExe = process.platform === 'win32' ? 'python' : 'python3';
    const args  = [
      BACKEND_PY,
      '--verdict',
      '--quarfile',  item.quarfile || '',
      '--filename',  item.name     || '',
      '--threat',    item.threat   || '',
    ];

    let stdout = '';
    let stderr = '';
    const proc = require('child_process').spawn(pyExe, args);
    proc.stdout.on('data', d => stdout += d.toString());
    proc.stderr.on('data', d => stderr += d.toString());
    proc.on('close', () => {
      try {
        // engine.py prints one JSON line
        const line = stdout.trim().split('\n').pop();
        const data = JSON.parse(line);
        resolve(data);
      } catch (e) {
        resolve({ verdict: 'UNCERTAIN', confidence: 0, summary: 'Parse error: ' + stderr.slice(0, 200) });
      }
    });
    proc.on('error', (e) => {
      resolve({ verdict: 'UNCERTAIN', confidence: 0, summary: 'Failed to start Python: ' + e.message });
    });
  });
});