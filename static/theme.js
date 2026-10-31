'use strict';
// Loaded before CSS to avoid a light/dark flash. Store only the visual preference.
(() => {
  const T = window.panelT || (value => value);
  const root = document.documentElement;
  let manual = null;
  let system = null;
  try {
    const saved = localStorage.getItem('panel-theme');
    if (saved === 'light' || saved === 'dark') manual = saved;
  } catch (_) {}
  try {
    if (typeof window.matchMedia === 'function') system = window.matchMedia('(prefers-color-scheme: dark)');
  } catch (_) {}
  function apply(theme) {
    root.dataset.theme = theme;
    if (document.body) document.body.dataset.theme = theme;
    const button = document.querySelector('[data-theme-toggle]');
    if (button) {
      button.textContent = theme === 'dark' ? T('☀ حالت روشن') : T('☾ حالت تیره');
      button.setAttribute('aria-label', theme === 'dark' ? T('فعال‌کردن پوستهٔ روشن') : T('فعال‌کردن پوستهٔ تیره'));
    }
  }
  const preferred = () => manual || (system && system.matches ? 'dark' : 'light');
  apply(preferred());
  const onSystemChange = () => { if (!manual) apply(preferred()); };
  if (system) {
    if (typeof system.addEventListener === 'function') system.addEventListener('change', onSystemChange);
    else if (typeof system.addListener === 'function') system.addListener(onSystemChange);
  }
  document.addEventListener('DOMContentLoaded', () => {
    apply(preferred());
    const button = document.querySelector('[data-theme-toggle]');
    if (button) button.addEventListener('click', () => {
      manual = root.dataset.theme === 'dark' ? 'light' : 'dark';
      apply(manual);
      try { localStorage.setItem('panel-theme', manual); } catch (_) {}
    });
  });
})();
