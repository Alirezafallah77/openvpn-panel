'use strict';
document.querySelectorAll('[role="tablist"]').forEach(list => {
  const tabs = Array.from(list.querySelectorAll('[role="tab"]'));
  function select(tab, focus) {
    tabs.forEach(item => {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
      document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
    });
    if (focus) tab.focus();
  }
  select(tabs.find(tab => tab.getAttribute('aria-selected') === 'true') || tabs[0], false);
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => select(tab, false));
    tab.addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowLeft') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowRight') next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next !== undefined) { event.preventDefault(); select(tabs[next], true); }
    });
  });
});
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const input = document.getElementById(button.dataset.copy);
    const status = document.getElementById(button.dataset.feedback);
    try {
      await navigator.clipboard.writeText(input.value);
      status.textContent = 'لینک کپی شد؛ آمادهٔ ارسال است.';
    } catch (_) {
      input.focus(); input.select();
      status.textContent = 'لینک انتخاب شد؛ با Copy یا Ctrl+C کپی کنید.';
    }
  });
});
