/**
 * BytesProtector — Scan Page
 * Supports: Quick / Full / Custom Folder / Scan Files
 */
router.register('scan', (el) => {
  let scanRunning  = false;
  let selectedMode = 'quick';
  let customPath   = null;
  let customFiles  = [];   // for file mode
  let filesCount   = 0;
  let threatCount  = 0;
  let startTime    = null;
  let elapsedTimer = null;

  el.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">Scan</div>
        <div class="page-subtitle text-mono">Multi-engine threat detection · C · Python · Rust</div>
      </div>
      <div class="flex gap-8">
        <button class="btn" id="scan-stop-btn" disabled>Stop</button>
        <button class="btn btn-primary" id="scan-start-btn">Start Scan</button>
      </div>
    </div>

    <!-- Mode selector: 4 options -->
    <div class="scan-modes mb-12" style="grid-template-columns:repeat(4,1fr)">
      <button class="scan-mode-btn active" data-mode="quick">
        <div class="scan-mode-name">Quick Scan</div>
        <div class="scan-mode-desc">Downloads · Desktop · Temp</div>
      </button>
      <button class="scan-mode-btn" data-mode="full">
        <div class="scan-mode-name">Full Scan</div>
        <div class="scan-mode-desc">Entire home folder</div>
      </button>
      <button class="scan-mode-btn" data-mode="folder">
        <div class="scan-mode-name">Scan Folder</div>
        <div class="scan-mode-desc" id="folder-label">Choose a folder…</div>
      </button>
      <button class="scan-mode-btn" data-mode="files">
        <div class="scan-mode-name">Scan Files</div>
        <div class="scan-mode-desc" id="files-label">Choose .exe, .zip…</div>
      </button>
    </div>

    <!-- Selected files preview (files mode only) -->
    <div id="files-preview" class="card mb-12" style="display:none">
      <div class="card-header">
        <span class="card-title">Selected Files</span>
        <button class="btn btn-sm" id="files-clear-btn">Clear</button>
      </div>
      <div id="files-list" style="max-height:120px;overflow-y:auto"></div>
    </div>

    <!-- Progress card -->
    <div class="card mb-12">
      <div class="card-header">
        <span class="card-title">Progress</span>
        <span class="text-mono" id="scan-speed" style="font-size:10px;color:var(--text-dim)">—</span>
      </div>
      <div class="progress-track mb-12">
        <div class="progress-fill" id="scan-progress-bar" style="width:0%"></div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:8px">
        <div class="stat-block">
          <div class="stat-value" id="scan-files-count">0</div>
          <div class="stat-label">Files Scanned</div>
        </div>
        <div class="stat-block">
          <div class="stat-value" id="scan-threats-count" style="color:var(--text-secondary)">0</div>
          <div class="stat-label">Threats Found</div>
        </div>
        <div class="stat-block">
          <div class="stat-value" id="scan-elapsed">0s</div>
          <div class="stat-label">Elapsed</div>
        </div>
      </div>
      <div id="scan-current-file"
           style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim);
                  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;height:16px"></div>
    </div>

    <!-- Engine log -->
    <div class="card" style="display:flex;flex-direction:column">
      <div class="card-header">
        <span class="card-title">Engine Log</span>
        <button class="btn btn-sm" id="scan-clear-log">Clear</button>
      </div>
      <div class="log-box" id="scan-log" style="height:200px;overflow-y:auto"></div>
    </div>
  `;

  // ── Refs ──────────────────────────────────────────────────────────────
  const startBtn    = el.querySelector('#scan-start-btn');
  const stopBtn     = el.querySelector('#scan-stop-btn');
  const logBox      = el.querySelector('#scan-log');
  const progBar     = el.querySelector('#scan-progress-bar');
  const speedEl     = el.querySelector('#scan-speed');
  const filesEl     = el.querySelector('#scan-files-count');
  const threatsEl   = el.querySelector('#scan-threats-count');
  const elapsedEl   = el.querySelector('#scan-elapsed');
  const curFileEl   = el.querySelector('#scan-current-file');
  const filesPreview = el.querySelector('#files-preview');
  const filesList   = el.querySelector('#files-list');
  const folderLabel = el.querySelector('#folder-label');
  const filesLabel  = el.querySelector('#files-label');

  // ── Helpers ───────────────────────────────────────────────────────────
  function log(text, cls = '') {
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
    const line = document.createElement('div');
    line.className = `log-line ${cls}`;
    line.innerHTML = `<span class="log-ts">${ts}</span><span class="log-msg">${esc(text)}</span>`;
    logBox.appendChild(line);
    logBox.scrollTop = logBox.scrollHeight;
  }

  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function resetStats() {
    filesCount  = 0;
    threatCount = 0;
    filesEl.textContent   = '0';
    threatsEl.textContent = '0';
    threatsEl.style.color = 'var(--text-secondary)';
    elapsedEl.textContent = '0s';
    progBar.style.width   = '0%';
    progBar.classList.remove('ok', 'danger');
    speedEl.textContent   = '—';
    curFileEl.textContent = '';
  }

  function setRunning(running) {
    scanRunning = running;
    startBtn.disabled = running;
    stopBtn.disabled  = !running;
    if (!running) curFileEl.textContent = '';
  }

  // ── Render selected files preview ─────────────────────────────────────
  function renderFilesPreview() {
    if (!customFiles.length) {
      filesPreview.style.display = 'none';
      filesLabel.textContent = 'Choose .exe, .zip…';
      return;
    }
    filesPreview.style.display = 'block';
    filesLabel.textContent = `${customFiles.length} file${customFiles.length > 1 ? 's' : ''} selected`;
    filesList.innerHTML = customFiles.map(f => `
      <div style="font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);
                  padding:4px 0;border-bottom:1px solid var(--border-dim);
                  white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(f)}">
        ${esc(f.split(/[/\\]/).pop())}
        <span style="color:var(--text-dim);margin-left:6px">${esc(f)}</span>
      </div>
    `).join('');
  }

  // ── Mode buttons ──────────────────────────────────────────────────────
  el.querySelectorAll('.scan-mode-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (scanRunning) return;

      const mode = btn.dataset.mode;

      if (mode === 'folder') {
        const dir = await window.bp?.chooseDirectory();
        if (!dir) return; // cancelled
        customPath = dir;
        folderLabel.textContent = dir.length > 30 ? '…' + dir.slice(-28) : dir;
      }

      if (mode === 'files') {
        const picked = await window.bp?.chooseFiles() || [];
        if (!picked.length) return; // cancelled
        customFiles = picked;
        renderFilesPreview();
      } else {
        // Hide preview when switching away from files mode
        if (selectedMode === 'files' && mode !== 'files') {
          filesPreview.style.display = 'none';
        }
      }

      el.querySelectorAll('.scan-mode-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      selectedMode = mode;
    });
  });

  el.querySelector('#files-clear-btn').addEventListener('click', () => {
    customFiles = [];
    renderFilesPreview();
  });

  // ── Start ─────────────────────────────────────────────────────────────
  startBtn.addEventListener('click', () => {
    if (scanRunning) return;

    // Validate file mode
    if (selectedMode === 'files' && !customFiles.length) {
      log('No files selected. Click "Scan Files" to pick files first.', 'warn');
      return;
    }
    if (selectedMode === 'folder' && !customPath) {
      log('No folder selected. Click "Scan Folder" to choose one.', 'warn');
      return;
    }

    runScan();
  });

  stopBtn.addEventListener('click', () => {
    window.bp?.stopScan();
    clearInterval(elapsedTimer);
    log('Scan stopped.', 'warn');
    setRunning(false);
  });

  el.querySelector('#scan-clear-log').addEventListener('click', () => {
    logBox.innerHTML = '';
  });

  // ── Run ───────────────────────────────────────────────────────────────
  async function runScan() {
    setRunning(true);
    resetStats();
    startTime = Date.now();

    elapsedTimer = setInterval(() => {
      elapsedEl.textContent = Math.round((Date.now() - startTime) / 1000) + 's';
    }, 500);

    const modeLabel = {
      quick:  'Quick Scan',
      full:   'Full Scan',
      folder: `Folder: ${customPath}`,
      files:  `${customFiles.length} file(s)`,
    }[selectedMode];

    log(`Starting ${modeLabel}…`, 'info');

    window.bp?.offScanEvents();
    window.bp?.onScanEvent(handleScanEvent);

    const opts = { scanType: selectedMode };

    if (selectedMode === 'files') {
      opts.files = customFiles;
    } else if (selectedMode === 'folder' && customPath) {
      opts.paths = [customPath];
    } else {
      opts.paths = [];
    }

    await window.bp?.startScan(opts).catch(err => {
      log(`Error: ${err?.message || err}`, 'threat');
    });
  }

  // ── Event handler ─────────────────────────────────────────────────────
  function handleScanEvent(msg) {
    switch (msg.type) {
      case 'progress':
        progBar.style.width = `${msg.pct}%`;
        if (msg.speed) speedEl.textContent = msg.speed;
        break;

      case 'file':
        filesCount = msg.count;
        filesEl.textContent = filesCount.toLocaleString();
        curFileEl.textContent = 'Scanning: ' + msg.path;
        break;

      case 'threat':
        threatCount++;
        threatsEl.textContent = threatCount;
        threatsEl.style.color = 'var(--danger)';

        // Shorten display path for zip entries
        const displayPath = msg.path.length > 80
          ? '…' + msg.path.slice(-77)
          : msg.path;

        log(`THREAT  ${msg.name}`, 'threat');
        log(`  ↳ ${displayPath}`, 'threat');
        break;

      case 'log':
        const cls = msg.level === 'warn'  ? 'threat'
                  : msg.text?.includes('clean') || msg.text?.includes('✓') ? 'ok'
                  : '';
        log(msg.text || '', cls);
        break;

      case 'done':
        clearInterval(elapsedTimer);
        progBar.style.width = '100%';
        if (threatCount === 0) {
          progBar.classList.add('ok');
        } else {
          progBar.classList.add('danger');
        }
        setRunning(false);
        break;
    }
  }

  // ── Boot message ──────────────────────────────────────────────────────
  log('Scan engine ready.', 'info');
  log('Engines: C heuristic · Python ML v2 (score-based) · Rust SHA-256', 'info');
  log('Tip: use "Scan Files" to scan individual .exe or .zip files.', 'info');
});
