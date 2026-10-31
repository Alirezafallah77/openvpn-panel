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
// Progressive enhancement: HTML fallback remains usable without JavaScript.
document.querySelectorAll('[data-create-user]').forEach(form => {
  const panel = form.closest('section');
  const status = panel.querySelector('[data-create-status]');
  const error = panel.querySelector('[data-create-error]');
  const results = panel.querySelector('[data-created-results]');
  const submit = form.querySelector('[type="submit"]');
  let busy = false;
  let count = 0;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    busy = true; submit.disabled = true;
    form.setAttribute('aria-busy', 'true');
    status.textContent = 'در حال ساخت کاربر…';
    error.hidden = true;
    try {
      const response = await fetch(form.action, {
        method: 'POST', body: new FormData(form), credentials: 'same-origin',
        headers: {'Accept': 'application/json'}
      });
      if (response.redirected || !response.headers.get('Content-Type')?.includes('application/json')) {
        throw new Error('پاسخ قابل تأیید نیست؛ ممکن است نشست ورود تمام شده باشد. پیش از تلاش دوباره، داشبورد را در تب دیگری بررسی کنید؛ احتمال دارد کاربر ساخته شده باشد.');
      }
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'ساخت کاربر ناموفق بود.');
      if (typeof data.name !== 'string' || typeof data.subscription_url !== 'string') throw new Error('پاسخ ساخت ناقص است؛ فهرست کاربران را قبل از تلاش دوباره بررسی کنید.');
      count += 1;
      const card = document.createElement('article'); card.className = 'created-user';
      const heading = document.createElement('h3'); heading.textContent = '✓ ' + data.name;
      const input = document.createElement('input'); input.readOnly = true; input.dir = 'ltr';
      input.className = 'share-input'; input.value = data.subscription_url;
      input.setAttribute('aria-label', 'لینک اشتراک ' + data.name);
      const copy = document.createElement('button'); copy.type = 'button'; copy.className = 'secondary'; copy.textContent = 'کپی لینک اشتراک';
      const feedback = document.createElement('p'); feedback.setAttribute('role', 'status');
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(input.value); feedback.textContent = 'لینک کپی شد.'; }
        catch (_) { input.focus(); input.select(); feedback.textContent = 'لینک انتخاب شد؛ با Copy یا Ctrl+C کپی کنید.'; }
      });
      const open = document.createElement('a'); open.href = data.subscription_url; open.target = '_blank'; open.rel = 'noopener noreferrer'; open.textContent = 'مشاهدهٔ اشتراک ↗';
      card.append(heading, input, copy, open, feedback);
      if (data.profile_url) {
        const download = document.createElement('form'); download.method = 'post'; download.action = data.profile_url;
        const csrf = document.createElement('input'); csrf.type = 'hidden'; csrf.name = 'csrf'; csrf.value = form.elements.csrf.value;
        const button = document.createElement('button'); button.textContent = 'دانلود فایل اتصال';
        download.append(csrf, button); card.append(download);
      }
      results.prepend(card);
      status.textContent = count + ' کاربر در این صفحه ساخته شد. لینک را کپی کنید یا نام کاربر بعدی را بنویسید.';
      form.elements.name.value = ''; form.elements.name.focus();
    } catch (failure) {
      status.textContent = '';
      error.textContent = failure instanceof TypeError ? 'ارتباط قطع شد؛ نتیجه نامشخص است. قبل از ارسال مجدد، فهرست کاربران را در تب دیگری بررسی کنید. لینک را با تکرار درخواست نمی‌توان بازیابی کرد.' : failure.message;
      error.hidden = false;
    } finally {
      busy = false; submit.disabled = false; form.removeAttribute('aria-busy');
    }
  });
});
