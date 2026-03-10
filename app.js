/**
 * BytesProtector — App Bootstrap
 * Wires up navigation and initializes first page.
 */
document.addEventListener('DOMContentLoaded', () => {

  // ── Window controls ────────────────────────────────────────
  document.getElementById('btn-minimize')?.addEventListener('click', () => window.bp?.minimize());
  document.getElementById('btn-maximize')?.addEventListener('click', () => window.bp?.maximize());
  document.getElementById('btn-close')?.addEventListener('click',    () => window.bp?.close());

  // ── Navigation ─────────────────────────────────────────────
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const page = btn.dataset.page;
      if (page) window.router.navigate(page);
    });
  });

  // ── Init first page ─────────────────────────────────────────
  const dashEl = document.getElementById('page-dashboard');
  if (dashEl) {
    window.router.pages['dashboard']?.init(dashEl);
    window.router.pages['dashboard'].ready = true;
  }

});
