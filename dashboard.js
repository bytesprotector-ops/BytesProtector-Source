/**
 * BytesProtector — Dashboard
 */
router.register('dashboard', (el) => {
  el.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">Dashboard</div>
        <div class="page-subtitle text-mono" id="dash-ts"></div>
      </div>
      <button class="btn btn-primary btn-sm" id="dash-quick-scan">Quick Scan</button>
    </div>

    <!-- Status banner -->
    <div id="status-banner" class="mb-12">
      <div id="status-shield-wrap">
        <img src="../assets/icon.png" id="status-icon" alt="">
      </div>
      <div id="status-text">
        <div class="flex items-center gap-8" style="margin-bottom:4px">
          <span class="status-dot ok pulse" id="status-dot"></span>
          <span id="status-headline" style="font-size:15px;font-weight:700;color:var(--text-bright)">System Protected</span>
          <span class="tag ok" id="status-tag">SECURE</span>
        </div>
        <div id="status-detail" style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim)">
          5 engines active &nbsp;·&nbsp; Endpoint protection running &nbsp;·&nbsp; Definitions current
        </div>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;align-items:flex-end">
        <a href="https://bytesprotectorav.org" target="_blank"
           style="font-family:var(--font-mono);font-size:9px;color:var(--text-dim);text-decoration:none;
                  letter-spacing:0.06em">bytesprotectorav.org</a>
        <span style="font-family:var(--font-mono);font-size:9px;color:var(--text-dim)" id="dash-users">513,248 users protected</span>
      </div>
    </div>

    <!-- Stats row -->
    <div class="stat-grid mb-12">
      <div class="stat-block accent-ok">
        <div class="stat-value" id="d-threats">0</div>
        <div class="stat-label">Threats Blocked</div>
      </div>
      <div class="stat-block accent-blue">
        <div class="stat-value" id="d-files">0</div>
        <div class="stat-label">Files Scanned</div>
      </div>
      <div class="stat-block">
        <div class="stat-value" id="d-last">—</div>
        <div class="stat-label">Last Scan</div>
      </div>
    </div>

    <!-- Engines + Recent threats (two col) -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">

      <div class="card">
        <div class="card-header"><span class="card-title">Detection Engines</span></div>
        <div class="engine-row">
          <span class="engine-lang">RS</span>
          <div><div class="engine-name">Hash Verifier</div>
          <div class="engine-desc">SHA-256/MD5 · exact signature match</div></div>
          <span class="status-dot ok"></span>
        </div>
        <div class="engine-row">
          <span class="engine-lang">YR</span>
          <div><div class="engine-name">YARA Rules</div>
          <div class="engine-desc">21 malware family rules</div></div>
          <span class="status-dot ok"></span>
        </div>
        <div class="engine-row">
          <span class="engine-lang">AI</span>
          <div><div class="engine-name">AI Nano Model</div>
          <div class="engine-desc">29-feature PE classifier · &lt;5ms/file</div></div>
          <span class="status-dot ok"></span>
        </div>
        <div class="engine-row">
          <span class="engine-lang">C</span>
          <div><div class="engine-name">Heuristic Engine</div>
          <div class="engine-desc">Entropy · PE analysis · dropper detect</div></div>
          <span class="status-dot" id="c-engine-dot"></span>
        </div>
        <div class="engine-row">
          <span class="engine-lang">PT</span>
          <div><div class="engine-name">Pattern Matcher</div>
          <div class="engine-desc">26 family strings · PHP webshells</div></div>
          <span class="status-dot ok"></span>
        </div>
        <div class="engine-row">
          <span class="engine-lang">EP</span>
          <div><div class="engine-name">Endpoint Protection</div>
          <div class="engine-desc">Process · Network · Registry · FS</div></div>
          <span class="status-dot ok pulse" id="ep-dot"></span>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">Recent Threat Feed</span>
          <span class="tag info" style="font-size:8px" id="threat-feed-count">0 today</span>
        </div>
        <div id="threat-feed" style="font-family:var(--font-mono);font-size:10px">
          <div style="color:var(--text-dim);padding:20px 0;text-align:center">No threats detected recently</div>
        </div>
      </div>

    </div>

    <!-- System info -->
    <div class="card" style="margin-top:12px">
      <div class="card-header"><span class="card-title">System</span></div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0">
        <div class="data-row" style="flex-direction:column;align-items:flex-start;padding:10px 16px">
          <div class="data-label">Platform</div>
          <div class="data-value" id="sys-platform">—</div>
        </div>
        <div class="data-row" style="flex-direction:column;align-items:flex-start;padding:10px 16px">
          <div class="data-label">YARA Rules</div>
          <div class="data-value">21 families</div>
        </div>
        <div class="data-row" style="flex-direction:column;align-items:flex-start;padding:10px 16px">
          <div class="data-label">AI Model</div>
          <div class="data-value">v3 · 24 trees</div>
        </div>
        <div class="data-row" style="flex-direction:column;align-items:flex-start;padding:10px 16px;border:none">
          <div class="data-label">DB Version</div>
          <div class="data-value">2025.03.09</div>
        </div>
      </div>
    </div>
  `;

  // Timestamp
  const ts = el.querySelector('#dash-ts');
  const tick = () => {
    ts.textContent = new Date().toLocaleString('en-US', {
      weekday:'long', month:'long', day:'numeric', hour:'2-digit', minute:'2-digit'
    });
  };
  tick();
  setInterval(tick, 30000);

  el.querySelector('#sys-platform').textContent = navigator.platform;

  // Load history
  window.bp?.getReport().then(history => {
    if (!Array.isArray(history)) return;
    const totalFiles   = history.reduce((a,e) => a + (e.files_scanned||0), 0);
    const totalThreats = history.reduce((a,e) => a + (e.threats_found||0), 0);
    el.querySelector('#d-threats').textContent = totalThreats;
    el.querySelector('#d-files').textContent   = totalFiles.toLocaleString();
    if (history.length) {
      const last = history[history.length-1];
      const d = new Date(last.timestamp);
      el.querySelector('#d-last').textContent =
        d.toLocaleDateString('en-US', {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
    }
  }).catch(() => {});

  el.querySelector('#dash-quick-scan').addEventListener('click', () => {
    window.router.navigate('scan');
    setTimeout(() => {
      const b = document.querySelector('[data-mode="quick"]');
      if (b && !b.classList.contains('active')) b.click();
      document.getElementById('scan-start-btn')?.click();
    }, 150);
  });

  // Listen for threat events from endpoint protection
  window._dashThreatCount = 0;
  window._dashThreatFeed = el.querySelector('#threat-feed');
  window._dashThreatFeedCount = el.querySelector('#threat-feed-count');
});

// Global threat feed updater (called by endpoint page)
window.addThreatToFeed = function(title, detail, severity) {
  const feed = window._dashThreatFeed;
  if (!feed) return;
  window._dashThreatCount = (window._dashThreatCount || 0) + 1;
  if (window._dashThreatFeedCount) {
    window._dashThreatFeedCount.textContent = `${window._dashThreatCount} today`;
  }
  // Remove empty state
  const empty = feed.querySelector('div[style*="text-center"]');
  if (empty) empty.remove();

  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  const color = severity === 'critical' ? 'var(--danger)' : severity === 'high' ? 'var(--warn)' : 'var(--text-secondary)';
  const row = document.createElement('div');
  row.style.cssText = `padding:6px 0;border-bottom:1px solid var(--border-dim);`;
  row.innerHTML = `
    <div style="display:flex;justify-content:space-between;margin-bottom:2px">
      <span style="color:${color};font-weight:500">${esc(title)}</span>
      <span style="color:var(--text-dim)">${ts}</span>
    </div>
    <div style="color:var(--text-dim);font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(detail)}</div>
  `;
  feed.insertBefore(row, feed.firstChild);
  // Keep max 8 items
  while (feed.children.length > 8) feed.removeChild(feed.lastChild);
};

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
