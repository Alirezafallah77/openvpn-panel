# راهنمای عملیات نسخهٔ 0.1

## مسیرها و سرویس‌ها

| مسیر | کاربرد |
|---|---|
| `/opt/openvpn-panel` | کد و venv؛ فقط root مجاز به نوشتن |
| `/etc/openvpn-panel/panel.env` | هش رمز و کلید نشست؛ root:0600 |
| `/etc/openvpn-panel/pki` | CA، کلید و گواهی‌ها و فهرست صدور؛ root-only |
| `/etc/openvpn-panel/crl.pem` | ابطال گواهی کلاینت |
| `/etc/openvpn/server/panel.conf` | تنظیم OpenVPN |
| `/var/lib/openvpn-panel/quota.sqlite` | کاربران، هش لینک و حسابداری |
| `/var/lib/openvpn-panel-revocations` | درخواست‌های root-only قطع گواهی تعویض‌شده |
| `/run/openvpn-panel` | سوکت مدیریت root-only و heartbeat |
| `/run/openvpn-panel-pki` | سوکت PKI، فقط UID پنل پذیرفته می‌شود |

سرویس‌ها: `openvpn-panel`، `openvpn-panel-pki`، `openvpn-panel-accounting`، `openvpn-panel-network`، `openvpn-server@panel` و در حالت دامنه `caddy`.

## پس از restart یا قطع برق

سرویس‌ها با systemd فعال می‌شوند. پیش از شروع پردازهٔ جدید OpenVPN، نشست‌های باز قبلی بسته می‌شوند؛ مصرف قبلی حفظ می‌شود. هر نشست قدیمی که شمارندهٔ نهایی آن به دیسک نرسیده باشد ممکن است کسری مصرف داشته باشد.

برای راه‌اندازی مجدد از `sudo openvpn-panelctl restart` استفاده کنید؛ این دستور عمداً ترتیب stop/start سرویس حسابداری و VPN را رعایت می‌کند. restart کردن تنها OpenVPN ممکن است باعث EOF سوکت و توقف fail-closed آن شود.

اگر سرویس بالا نمی‌آید:

1. `sudo openvpn-panelctl status` و journal سرویس‌ها را بخوانید.
2. فضای آزاد و خطای دیتابیس/گواهی/مجوز فایل را بررسی کنید. **هیچ‌گاه heartbeat را دستی تازه نکنید یا hook را حذف نکنید.**
3. پس از رفع علت، `sudo openvpn-panelctl restart`.
4. اگر HTTPS کار نمی‌کند، DNS، پورت‌های میزبان و `journalctl -u caddy` را بررسی کنید. پورت 8000 نباید عمومی شود.

## نصب نیمه‌تمام

نصب‌کننده اگر مسیرهای قبلی را ببیند متوقف می‌شود تا CA و کاربران را پاک نکند. اجرای مجدد روش ارتقا نیست.

- پیش از هر حذف، اگر داده‌ای دارید snapshot/backup بگیرید و علت خطا را از خروجی نصب بخوانید.
- در نصب واقعاً تازه و بدون داده، ساده‌ترین راه امن بازسازی VPS و نصب دوباره بعد از رفع خطاست.
- فایل کلید یا دیتابیس را صرفاً برای عبور از پیش‌بررسی حذف نکنید. این نسخه هنوز rollback/upgrade خودکار ندارد.

## پشتیبان‌گیری

```bash
sudo openvpn-panelctl backup /root/panel-2026-10-31.tar.gz
sudo chmod 600 /root/panel-2026-10-31.tar.gz
```

ابزار با قفل PKI و API پشتیبان‌گیری SQLite snapshot سازگار می‌سازد. ترافیک می‌تواند ادامه داشته باشد و تغییرات بعد از snapshot در آن نیستند. بکاپ شامل تنظیمات/کلیدها و دیتابیس است، نه سیستم‌عامل، کد برنامه، قوانین خارجی فایروال یا DNS. فایل خروجی باید جدید باشد؛ فایل قبلی overwrite نمی‌شود. در خطای backup فایل ناقص را به‌عنوان بکاپ معتبر استفاده نکنید.

بکاپ را با ابزار مورداعتماد خود رمزگذاری، خارج از سرور ذخیره و بازیابی آن را روی VPS آزمایشی بررسی کنید. gzip رمزگذاری نیست.

## بازگردانی (ابتدا روی VPS آزمایشی)

بازیابی با downtime و root انجام می‌شود؛ آرشیو را فقط از منبع خودتان قبول کنید. کد و نسخهٔ وابستگی‌ها باید با نسخهٔ تهیهٔ بکاپ سازگار باشند.

1. Ubuntu 24.04 تازه را با **همان نسخهٔ پروژه** نصب کنید تا سرویس‌ها، کاربر سیستمی و شبکه ساخته شوند. رمز اولیه موقت است. endpoint دامنه/IP موردنیاز را همان زمان بدهید.
2. سرویس‌ها را متوقف کنید:

```bash
sudo systemctl stop openvpn-server@panel openvpn-panel-accounting openvpn-panel openvpn-panel-pki
```

3. محتوای آرشیو را ابتدا با `sudo tar -tzf /root/BACKUP.tar.gz` بررسی کنید. آرشیو تولیدشده تنها `etc/openvpn-panel`، `etc/openvpn/server/panel.conf` و `var/lib/openvpn-panel/quota.sqlite` دارد. آرشیو ناشناس را هرگز روی `/` استخراج نکنید.
4. پس از snapshot از حالت فعلی، بکاپ خودتان را بازگردانید:

```bash
sudo tar -xzf /root/BACKUP.tar.gz -C / --no-same-owner
sudo chown -R root:root /etc/openvpn-panel
sudo chmod 700 /etc/openvpn-panel /etc/openvpn-panel/pki
sudo chown openvpn-panel:openvpn-panel /var/lib/openvpn-panel/quota.sqlite
sudo chmod 660 /var/lib/openvpn-panel/quota.sqlite
sudo openvpn-panelctl password
sudo openvpn-panelctl restart
```

5. اگر دامنه/IP عوض شده، به‌عنوان root `vpn.json`، `panel.env` و Caddyfile را با دقت اصلاح کنید. فایل‌های `.ovpn` قبلی endpoint قبلی دارند؛ فایل جدید دانلود کنید. DNS و فایروال میزبان و رابط خروجی شبکه را بررسی کنید. تنظیم وب/دامنه در نصب جدید و تنظیمات بازگردانده‌شده باید یکسان باشند.
6. اتصال واقعی، حسابداری، قطع سهمیه و لینک وضعیت را بررسی کنید. مصرف از زمان snapshot به بعد از دست رفته است. لینک‌های وضعیت همان بکاپ دوباره معتبر می‌شوند؛ در صورت نیاز آن‌ها را از پنل بچرخانید.

## به‌روزرسانی

این نسخه اولین schema را دارد و ارتقا/مهاجرت خودکار پیاده‌سازی نشده است. **از اجرای مجدد install.sh روی نصب قبلی برای ارتقا استفاده نکنید.** پیش از نسخه‌های بعدی باید مسیر مهاجرت و rollback با بکاپ آزمایش شود. کد root-owned را درحال اجرای سرویس‌ها با `git pull` یا کپی ناقص جایگزین نکنید.

## حذف

اول بکاپ بگیرید. با توقف و disable کردن سرویس‌های بالا (از جمله instance `openvpn-server@panel`) دسترسی قطع می‌شود؛ توقف `openvpn-panel-network` تنها قواعد اختصاصی این پروژه را حذف می‌کند. Caddy را اگر سرویس دیگری استفاده می‌کند حذف نکنید. کلیدها و دیتابیس را بدون تصمیم آگاهانه پاک نکنید. فایل `/etc/sysctl.d/70-openvpn-panel.conf` forwarding را فعال نگه می‌دارد؛ غیرفعال‌کردن forwarding می‌تواند به سرویس‌های دیگر آسیب بزند، بنابراین آن را کورکورانه تغییر ندهید.
