'use strict';
const T = window.panelT || (value => value);
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
      status.textContent = T('لینک کپی شد؛ آمادهٔ ارسال است.');
    } catch (_) {
      input.focus(); input.select();
      status.textContent = T('لینک انتخاب شد؛ با Copy یا Ctrl+C کپی کنید.');
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
    status.textContent = T('در حال ساخت کاربر…');
    error.hidden = true;
    try {
      const response = await fetch(form.action, {
        method: 'POST', body: new FormData(form), credentials: 'same-origin',
        headers: {'Accept': 'application/json'}
      });
      if (response.redirected || !response.headers.get('Content-Type')?.includes('application/json')) {
        throw new Error(T('پاسخ قابل تأیید نیست؛ ممکن است نشست ورود تمام شده باشد. پیش از تلاش دوباره، داشبورد را در تب دیگری بررسی کنید؛ احتمال دارد کاربر ساخته شده باشد.'));
      }
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || T('ساخت کاربر ناموفق بود.'));
      if (typeof data.name !== 'string' || typeof data.subscription_url !== 'string') throw new Error(T('پاسخ ساخت ناقص است؛ فهرست کاربران را قبل از تلاش دوباره بررسی کنید.'));
      count += 1;
      const card = document.createElement('article'); card.className = 'created-user';
      const heading = document.createElement('h3'); heading.textContent = '✓ ' + data.name;
      const input = document.createElement('input'); input.readOnly = true; input.dir = 'ltr';
      input.className = 'share-input'; input.value = data.subscription_url;
      input.setAttribute('aria-label', T('لینک اشتراک ') + data.name);
      const copy = document.createElement('button'); copy.type = 'button'; copy.className = 'secondary'; copy.textContent = T('کپی لینک اشتراک');
      const feedback = document.createElement('p'); feedback.setAttribute('role', 'status');
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(input.value); feedback.textContent = T('لینک کپی شد.'); }
        catch (_) { input.focus(); input.select(); feedback.textContent = T('لینک انتخاب شد؛ با Copy یا Ctrl+C کپی کنید.'); }
      });
      const open = document.createElement('a'); open.href = data.subscription_url; open.target = '_blank'; open.rel = 'noopener noreferrer'; open.textContent = T('مشاهدهٔ اشتراک ↗');
      card.append(heading, input, copy, open, feedback);
      if (data.profile_url) {
        const download = document.createElement('form'); download.method = 'post'; download.action = data.profile_url;
        const csrf = document.createElement('input'); csrf.type = 'hidden'; csrf.name = 'csrf'; csrf.value = form.elements.csrf.value;
        const button = document.createElement('button'); button.textContent = T('دانلود فایل اتصال');
        download.append(csrf, button); card.append(download);
      }
      results.prepend(card);
      status.textContent = count + T(' کاربر در این صفحه ساخته شد. لینک را کپی کنید یا نام کاربر بعدی را بنویسید.');
      form.elements.name.value = ''; form.elements.name.focus();
    } catch (failure) {
      status.textContent = '';
      error.textContent = failure instanceof TypeError ? T('ارتباط قطع شد؛ نتیجه نامشخص است. قبل از ارسال مجدد، فهرست کاربران را در تب دیگری بررسی کنید. لینک را با تکرار درخواست نمی‌توان بازیابی کرد.') : failure.message;
      error.hidden = false;
    } finally {
      busy = false; submit.disabled = false; form.removeAttribute('aria-busy');
    }
  });
});
const liveMetrics = document.querySelector('[data-live-metrics]');
if (liveMetrics) {
  const status = document.querySelector('[data-metrics-status]');
  let pending = false;
  let timer;
  const gib = value => (value / 1073741824).toFixed(2);
  async function updateMetrics() {
    clearTimeout(timer);
    if (pending) return;
    if (document.hidden) { timer = setTimeout(updateMetrics, 5000); return; }
    pending = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    try {
      const response = await fetch(liveMetrics.dataset.liveMetrics, {
        credentials: 'same-origin', headers: {'Accept': 'application/json'}, signal: controller.signal
      });
      if (!response.ok || response.redirected) throw new Error('metrics unavailable');
      const data = await response.json();
      for (const key of ['cpu', 'ram', 'swap', 'disk']) {
        const card = liveMetrics.querySelector('[data-metric="' + key + '"]');
        const value = data[key];
        const valid = typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100;
        card.querySelector('[data-metric-value]').textContent = !valid ? T('نامشخص') : key === 'swap' && data.swap_total === 0 ? T('بدون Swap') : value.toFixed(1) + '%';
        const bar = card.querySelector('progress');
        bar.hidden = !valid;
        if (valid) bar.value = value;
        if (key !== 'cpu') card.querySelector('.metric-detail').textContent = gib(data[key + '_used']) + ' / ' + gib(data[key + '_total']) + ' GiB';
      }
      status.textContent = data.cpu === null ? T('خواندن CPU ناموفق است؛ آمار CPU نامشخص است.') : T('آمار منابع به‌روز است؛ بروزرسانی هر ۵ ثانیه.');
    } catch (_) {
      status.textContent = T('آمار زنده در دسترس نیست؛ مقادیر قبلی ممکن است قدیمی باشند. اتصال و نشست ورود را بررسی کنید.');
    } finally {
      clearTimeout(timeout);
      pending = false;
      timer = setTimeout(updateMetrics, 5000);
    }
  }
  timer = setTimeout(updateMetrics, 5000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && !pending) updateMetrics(); });
}
document.querySelectorAll('[data-copy-user-link]').forEach(form => {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button=form.querySelector('button');
    if (button.disabled) return;
    button.disabled=true;
    const result=form.closest('td').querySelector('[data-row-link-result]');
    result.replaceChildren();
    const message=document.createElement('p'); message.setAttribute('role','status');
    result.append(message);
    try {
      async function send(url) {
        const response=await fetch(url,{method:'POST',body:new FormData(form),credentials:'same-origin',headers:{Accept:'application/json'}});
        if (response.redirected || !response.headers.get('Content-Type')?.includes('application/json')) throw new Error(T('نشست یا پاسخ معتبر نیست؛ دوباره وارد پنل شوید.'));
        return {response,data:await response.json()};
      }
      let {response,data}=await send(form.action);
      if (response.status===409 && data.needs_rotation) {
        if (!window.confirm(T('لینک این کاربر در نسخهٔ قدیمی فقط به‌صورت هش ذخیره شده است. لینک قبلی باطل و یک لینک جدید قابل کپی صادر شود؟ فایل VPN تغییر نمی‌کند.'))) {
          message.textContent=T('لغو شد؛ لینک قبلی تغییر نکرد.'); return;
        }
        ({response,data}=await send(form.dataset.rotateUrl));
      }
      if (!response.ok) throw new Error(data.error || T('دریافت لینک ناموفق بود.'));
      const input=document.createElement('input'); input.readOnly=true; input.dir='ltr';input.className='share-input';input.value=data.subscription_url;input.setAttribute('aria-label',T('لینک اشتراک'));
      result.prepend(input);
      try { await navigator.clipboard.writeText(input.value);message.textContent=T('لینک ساب کپی شد.'); }
      catch (_) { input.focus();input.select();message.textContent=T('لینک انتخاب شد؛ با Copy یا Ctrl+C کپی کنید.'); }
    } catch (_) { message.textContent=T('دریافت لینک ناموفق بود؛ نشست، ارتباط یا کلید ذخیرهٔ لینک را بررسی کنید. در خطای ارتباط بعد از صدور، دوباره کپی را بزنید؛ لینک جدید ذخیره شده و دوباره باطل نمی‌شود.'); }
    finally { button.disabled=false; }
  });
});
const userDialog=document.getElementById('user-action-dialog');
if (userDialog && typeof userDialog.showModal==='function') {
  let loading=false;
  userDialog.querySelector('[data-close-user-dialog]').addEventListener('click',()=>userDialog.close());
  document.querySelectorAll('[data-user-dialog]').forEach(link=>link.addEventListener('click',async event=>{
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    if (loading) return;
    loading=true;
    try {
      const response=await fetch(link.href,{credentials:'same-origin'});
      if (!response.ok || response.redirected) throw new Error('unavailable');
      const page=new DOMParser().parseFromString(await response.text(),'text/html');
      const panel=page.querySelector('.action-panel');
      if (!panel) throw new Error('missing action');
      const content=userDialog.querySelector('[data-dialog-content]');
      content.replaceChildren(document.importNode(panel,true));
      content.querySelectorAll('[data-action-cancel]').forEach(cancel=>cancel.addEventListener('click',e=>{e.preventDefault();userDialog.close();}));
      setupDatePickers(content);
      userDialog.showModal();
      content.querySelector('input:not([type=hidden])')?.focus();
    } catch (_) { window.location.assign(link.href); }
    finally { loading=false; }
  }));
}

// Accessible date picker: native selects use the selected calendar, while the
// canonical text fallback still works without JS. Backend validates leap days.
function setupDatePickers(root = document) {
  root.querySelectorAll('[data-calendar-picker]').forEach(picker => {
    if (picker.dataset.ready) return;
    picker.dataset.ready = '1';
    const input = picker.querySelector('[data-date-input]');
    const year = picker.querySelector('[data-date-year]');
    const month = picker.querySelector('[data-date-month]');
    const day = picker.querySelector('[data-date-day]');
    const parts = input.value.split('-').map(Number);
    if (parts.length !== 3 || parts.some(v => !Number.isFinite(v))) return;
    function option(select, value) {
      const element = document.createElement('option');
      element.value = String(value); element.textContent = String(value);
      select.append(element);
    }
    for (let y = parts[0]-10; y <= parts[0]+10; y++) option(year,y);
    for (let m = 1; m <= 12; m++) option(month,m);
    year.value=String(parts[0]); month.value=String(parts[1]);
    function daysInMonth() {
      const y = Number(year.value), m = Number(month.value);
      if (picker.dataset.calendar !== 'jalali') return new Date(Date.UTC(y,m,0)).getUTCDate();
      if (m <= 6) return 31;
      if (m <= 11) return 30;
      // Determine Esfand length using the browser calendar, not a simplistic
      // 33-year leap rule. Invalid dates are independently rejected on server.
      try {
        const fmt=new Intl.DateTimeFormat('en-u-ca-persian-nu-latn',{timeZone:'UTC',year:'numeric',month:'numeric',day:'numeric'});
        for (let d=18; d<=22; d++) {
          const parts=Object.fromEntries(fmt.formatToParts(new Date(Date.UTC(y+622,2,d))).map(p=>[p.type,p.value]));
          if (Number(parts.year)===y && Number(parts.month)===12 && Number(parts.day)===30) return 30;
        }
      } catch (_) { return 30; }
      return 29;
    }
    function rebuildDay(preferred) {
      day.replaceChildren();
      for (let d=1; d<=daysInMonth(); d++) option(day,d);
      day.value=String(Math.min(preferred,daysInMonth()));
    }
    function sync() { input.value=[year.value,month.value.padStart(2,'0'),day.value.padStart(2,'0')].join('-'); }
    rebuildDay(parts[2]);
    year.addEventListener('change',()=>{rebuildDay(Number(day.value));sync();});
    month.addEventListener('change',()=>{rebuildDay(Number(day.value));sync();});
    day.addEventListener('change',sync);
    input.addEventListener('change',()=>{
      const p=input.value.split('-').map(Number);
      if (p.length===3 && p[0]>=parts[0]-10 && p[0]<=parts[0]+10 && p[1]>=1 && p[1]<=12) {
        year.value=String(p[0]);month.value=String(p[1]);rebuildDay(p[2]);
      }
    });
    picker.querySelector('[data-date-selects]').hidden=false;
  });
}
setupDatePickers();

// Never resubmit the destructive POST. Poll the durable root-worker state across
// temporary web/broker restarts, then load the newly restored dashboard.
const restoreProgress = document.querySelector('[data-restore-progress]');
if (restoreProgress) {
  const fa = document.documentElement.lang === 'fa';
  const message = restoreProgress.querySelector('[data-restore-message]');
  const deadline = Date.now()+12*60*1000;
  async function pollRestore() {
    if (Date.now()>deadline) {
      message.textContent=fa?'زمان انتظار تمام شد؛ نتیجه نامشخص است. وضعیت بازیابی را بررسی کنید؛ درخواست را تکرار نکنید.':'Wait timed out; outcome unknown. Check restore status; do not resubmit.';
      return;
    }
    try {
      const response=await fetch(restoreProgress.dataset.statusUrl,{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
      if (!response.redirected && response.ok && response.headers.get('Content-Type')?.includes('application/json')) {
        const state=await response.json();
        if (state.job_id===restoreProgress.dataset.job) {
          if (state.status==='completed') {window.location.replace(restoreProgress.dataset.dashboardUrl);return;}
          if (state.status==='failed') {
            message.textContent=fa?'بازیابی ناموفق بود. برای بررسی فایل‌ها و سلامت سرویس‌ها از SSH و لاگ‌ها کمک بگیرید؛ نسخهٔ ایمنی پیش از بازیابی روی سرور حفظ شده است.':'Restore failed. Check service health and logs using SSH; any pre-restore safety snapshot is retained on the server.';
            return;
          }
          message.textContent=fa?'بازیابی در حال انجام است؛ صفحه را باز نگه دارید.':'Restoring; keep this page open.';
        }
      }
    } catch (_) { /* A short outage is expected; never infer success from it. */ }
    setTimeout(pollRestore,2000);
  }
  setTimeout(pollRestore,2000);
}
document.querySelectorAll('[data-restore-form]').forEach(form=>form.addEventListener('submit',()=>{
  form.querySelector('button').disabled=true;
}));
