/**
 * BytesProtector — Page Router
 */
class Router {
  constructor() {
    this.current = 'dashboard';
    this.pages   = {};
    this.onNav   = {};
  }

  register(name, initFn) {
    this.pages[name] = { init: initFn, ready: false };
  }

  navigate(name) {
    if (name === this.current) return;

    // Hide old page
    const oldEl = document.getElementById(`page-${this.current}`);
    if (oldEl) oldEl.classList.remove('active');

    // Deactivate old nav
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));

    // Show new page
    const newEl = document.getElementById(`page-${name}`);
    if (newEl) {
      newEl.classList.add('active');
      // Init once
      if (this.pages[name] && !this.pages[name].ready) {
        this.pages[name].init(newEl);
        this.pages[name].ready = true;
      }
    }

    // Activate new nav btn
    const navBtn = document.querySelector(`.nav-item[data-page="${name}"]`);
    if (navBtn) navBtn.classList.add('active');

    this.current = name;
  }
}

window.router = new Router();
