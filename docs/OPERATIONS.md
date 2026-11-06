# راهنمای عملیات نسخهٔ 0.4

## ارتقا از نسخهٔ قبلی

روی سرور و در پوشهٔ checkout همین شاخه:

```bash
git pull --ff-only origin arena/c09c103f-openvpn-panel
sudo bash scripts/upgrade.sh
```

اسکریپت CA، کاربران، مصرف، رمز مدیر، تنظیمات endpoint و دامنه را حفظ می‌کند؛ پیش از تغییر بکاپ داده و کد قدیمی را در `/var/backups/openvpn-panel` با دسترسی root نگه می‌دارد. نصب‌کنندهٔ `install.sh` مخصوص نصب تازه است و برای ارتقا عمداً رد می‌شود. ارتقا downtime کوتاه VPN دارد؛ در خطا، پیام و لاگ را بررسی کنید، فایل‌های کاربر را پاک نکنید. اسکریپت ارتقا rollback خودکار کد/venv ندارد؛ snapshot ماشین پیش از ارتقا برای سرور عملیاتی توصیه می‌شود. آرشیو کد شامل venv نیست؛ برای rollback باید requirements همان نسخه نیز نصب شود.

## SSL Management، دامنه و پروتکل OpenVPN

بعد از ارتقا از بخش **SSL Management / OpenVPN Protocol** استفاده کنید. تغییرات نیاز به نشست مدیر، CSRF، رمز فعلی و تأیید دارند. وب فقط درخواست اعتبارسنجی‌شده را به broker محلی می‌دهد؛ هیچ مسیر فایل، متن shell یا نام سرویس دلخواه از درخواست کاربر اجرا نمی‌شود. اجرای تغییر در transient unit جدا با مهلت اجرا انجام می‌شود؛ صفحه وضعیت «در صف / در اجرا / موفق / ناموفق» دارد و باید به‌صورت دستی به‌روزرسانی شود.

### فعال‌کردن دامنه بعد از نصب SSH

1. یک FQDN مانند `panel.example.com` انتخاب کنید. رکورد A باید IPv4 این سرور باشد؛ AAAA نادرست را حذف کنید. TCP 80/443 و پورت VPN را در فایروال شرکت میزبان باز کنید.
2. دامنه را بدون scheme/port/path در SSL Management وارد و گزینهٔ کاربرد همان دامنه برای VPN را در صورت نیاز نگه دارید.
3. رمز مدیر و تأیید را وارد و ذخیره کنید. عملیات چند ثانیه بعد آغاز می‌شود؛ گرفتن گواهی ممکن است حدود سه دقیقه زمان ببرد. قبل از آماده‌بودن DNS ثبت/تکرار نکنید؛ CAها محدودیت صدور دارند.
4. تا تأیید گواهی، تنظیمات Host و Secure cookie پنل عوض نمی‌شود؛ هنگام تغییر دامنه، یک دامنهٔ HTTPS قبلی نیز در Caddy حفظ می‌شود. پس از تأیید، پنل وب restart و پاسخ HTTPS `/login` کنترل می‌شود. اگر این مرحله شکست بخورد، فایل‌های قبلی و سرویس‌ها بازگردانده می‌شوند.
5. آدرس HTTPS جدید را باز کنید؛ ورود دوباره لازم است. Caddy تمدید عادی را خودکار انجام می‌دهد، به شرط ادامهٔ دسترسی DNS و پورت‌ها. تنظیم دوبارهٔ همان دامنه، issuer فعلی متعلق به همین نصب را عوض نمی‌کند؛ گواهی خصوصی سازمانی که root قبلاً تنظیم کرده باشد هم بی‌اجازه جایگزین نمی‌شود. UI اعتبار را از دید trust store سیستم و نام دامنه بررسی می‌کند و صادرکننده/انقضا را نشان می‌دهد؛ کلاینت‌های شما هم باید به صادرکننده اعتماد داشته باشند.

گواهی HTTPS وب و PKI خصوصی OpenVPN مستقل‌اند. استفاده از دامنه در `.ovpn` یعنی تغییر `remote DOMAIN PORT`، نه جایگزینی CA خصوصی VPN با گواهی وب. فایل‌های قدیمی خودکار تغییر نمی‌کنند. اگر دامنهٔ پنل پشت CDN است و VPN روی همان دامنه می‌رود، HTTP proxy معمولی را خاموش کنید یا برای VPN دامنهٔ DNS-only جدا بگذارید.

### تغییر UDP/TCP و endpoint

پروتکل و آدرس VPN را از فرم جدا تنظیم کنید. `UDP → udp4` و `TCP → tcp4-server` در سرور و `tcp4-client` در فایل کلاینت اعمال می‌شود. transport IPv4 است؛ endpoint می‌تواند FQDN با رکورد A یا IPv4 باشد. پورت همان مقدار فعلی می‌ماند (پیش‌فرض 1194)، تغییر پورت در UI این نسخه وجود ندارد. TCP 1194 با HTTPS TCP 443 متفاوت است. Provider firewall را پیش از تغییر باز کنید.

با ذخیرهٔ این فرم، حتی اگر فقط endpoint تغییر کرده باشد، VPN با ترتیب حسابداری امن restart می‌شود. مصرف، تاریخ شروع و گواهی‌ها حفظ می‌شوند. کاربران قطع می‌شوند؛ سپس فایل `.ovpn` جدید بگیرند. UDP/TCP هم‌زمان در این نسخه وجود ندارد. بسته‌بودن پورت در فایروال بیرونی از داخل سرور به‌طور قابل اتکا قابل تشخیص نیست و ممکن است سرویس آماده باشد ولی کاربر نتواند وصل شود.

### خطا و بازگشت

در خطای عادی اعتبارسنجی Caddy، آماده‌نشدن TLS، پاسخ‌ندادن HTTPS یا شروع‌نشدن VPN، تنظیمات قبلی بازگردانده می‌شود. موفقیت صرفاً بر اساس «فعال بودن caddy» اعلام نمی‌شود: نام دامنه/زنجیرهٔ گواهی و پاسخ وب نیز بررسی می‌شوند. این تضمین تراکنش در برابر قطع برق، خطای دیسک یا کشته‌شدن پردازه در وسط تغییر نیست. دسترسی SSH را تا پایان حفظ کنید.

```bash
sudo openvpn-panelctl settings-rollback
sudo journalctl -u 'openvpn-panel-settings-*' -u caddy -u openvpn-server@panel -n 100 --no-pager
```

snapshot آخر در `/etc/openvpn-panel/settings-rollback.json` با مجوز `0600` است و اطلاعات محرمانهٔ محیط پنل دارد؛ منتشر نکنید. دستور rollback آخرین snapshot را بازیابی می‌کند، درخواست معلق را لغو و وب/VPN را restart می‌کند. پس از یک تغییر موفق، snapshot مربوط به قبل همان تغییر است، نه یک history نامحدود. هنگام اجرای تغییر شبکه، دستورهای تعمیر/ارتقای SSH را هم‌زمان اجرا نکنید. بازیابی بکاپ، قفل تغییر شبکه را رعایت و درخواست معلق را لغو می‌کند؛ تنظیمات دامنه/پروتکل مقصد در مهاجرت حفظ می‌شوند.

Caddy روی نصب تازهٔ SSH نیز نصب می‌شود ولی خاموش/غیرفعال می‌ماند تا HTTPS فعال شود. نصب و ارتقا تنها default تازهٔ پکیج یا قالب اختصاصی شناخته‌شدهٔ خود پروژه را به‌عنوان فایل تحت مدیریت می‌پذیرند؛ Caddy متعلق به سایت دیگر عمداً قابل‌ویرایش از UI نیست. فایل Caddy تحت مدیریت پروژه را برای میزبانی سایت‌های دیگر استفاده نکنید. در این حالت مدیریت چندسایت باید جدا و توسط ادمین بررسی شود، نه با ساخت دستی marker و دورزدن بررسی مالکیت.

## بکاپ وب و تلگرام

از داشبورد وارد **بکاپ، انتقال سرور و تلگرام** شوید:

1. یک رمز بکاپ حداقل ۱۶ کاراکتری وارد و تکرار کنید؛ آن را بیرون سرور نگه دارید. این رمز با رمز ورود مدیر متفاوت است.
2. برای ارسال تلگرام، توکن ربات، Chat ID و فاصلهٔ زمانی (مثلاً ۱۵ دقیقه) را وارد کنید، گزینهٔ زمان‌بندی را روشن و با رمز فعلی مدیر تأیید کنید.
3. ابتدا به ربات در مقصد خصوصی `/start` بدهید؛ در گروه/کانال ربات باید اجازهٔ ارسال سند داشته باشد. Chat ID عددی/شناسهٔ کانال را از ابزار مورداعتماد خود بگیرید؛ توکن را به ربات یا سرویس ناشناس ندهید.
4. دکمهٔ «بکاپ الآن و ارسال» را بزنید و زمان آخرین ارسال و نتیجه را ببینید. وجود بکاپ محلی به معنی ارسال موفق تلگرام نیست.

حداقل فاصله ۵ دقیقه، حداکثر یک هفته است. systemd هر دقیقه بررسی می‌کند؛ زمان‌بندی از آخرین تلاش با دقت حدود یک دقیقه و زمان اجرای کار محاسبه می‌شود. در شکست ارسال، نسخهٔ محلی حفظ و خطای عمومی ثبت می‌شود؛ تلاش بعدی در فاصلهٔ تنظیم‌شده انجام می‌شود. خاموش‌بودن وب مانع زمان‌بندی نیست. توکن و رمز در فایل root-only ذخیره و در UI/لاگ دوباره نمایش داده نمی‌شوند؛ خالی‌گذاشتن هنگام ویرایش، مقدار قبلی را حفظ می‌کند. غیرفعال‌کردن زمان‌بندی، اسرار ذخیره‌شده را پاک نمی‌کند.

فایل‌های `.ovpnbak` با **AES-256-GCM** و کلید مشتق‌شده با scrypt و salt/nonce تصادفی رمزگذاری می‌شوند؛ دست‌کاری یا رمز اشتباه قبل از توقف سرویس‌های مقصد رد می‌شود. تنها ۲۰ بکاپ محلی اخیر در `/var/lib/openvpn-panel-backups` نگهداری می‌شوند. فایل‌های داخل تلگرام خودکار حذف نمی‌شوند. حداکثر خروجی رمزگذاری‌شده ۴۵ MiB و مجموع محتوای بازشده ۲۵۶ MiB است؛ بیشتر از آن نیازمند راهکار خارج از این نسخه است.

**Telegram Bot API محرمانگی سرتاسری ندارد.** رمزگذاری خود فایل ضروری است. رمز بکاپ را در همان چت/پیام نفرستید. بدون رمز اولیه، بازیابی ممکن نیست؛ تغییر رمز، فایل‌های قبلی را با رمز جدید قابل بازکردن نمی‌کند. چون رمز برای زمان‌بندی روی سرور نگهداری می‌شود، compromise دسترسی root می‌تواند آن را افشا کند. اتصال HTTPS به `api.telegram.org` باید از سرور ممکن باشد. در این محیط ارسال واقعی به ربات شخصی آزمایش نشده؛ تست‌ها transport را mock می‌کنند.

بکاپ شامل کاربران، حجم/زمان/شروع اعتبار، مصرف، هش توکن‌های وضعیت، توکن‌های قابل‌کپیٔ رمزنگاری‌شده و فایل کلید مستقل آن‌ها (در صورت وجود)، CA، گواهی/کلیدهای سرور و کلاینت و CRL است. رمز مدیر، کلید نشست وب، دامنه، endpoint و تنظیمات تلگرام عمداً وارد فایل مهاجرت جدید نمی‌شوند تا تنظیمات مقصد حفظ شود. تهیهٔ بکاپ با قفل PKI و API snapshot SQLite است؛ مصرف بعد از snapshot در بکاپ نیست.

## انتقال سرور در چند دستور

### سرور قدیم

برای انتقال نهایی، ترافیک را متوقف کنید تا مصرف پس از snapshot گم نشود:

```bash
sudo systemctl stop openvpn-server@panel openvpn-panel-accounting
sudo openvpn-panelctl backup /root/migration.ovpnbak --encrypt
```

رمز بکاپ پرسیده می‌شود. فایل را با SCP انتقال دهید (نام کاربر و IP را عوض کنید):

```bash
scp /root/migration.ovpnbak root@NEW_SERVER_IP:/root/
```

بکاپ دستی وب نیز قابل استفاده است؛ اگر هنگام کار کاربران گرفته شود، مصرف پس از snapshot را شامل نمی‌شود.

### سرور جدید

۱. پنل نسخهٔ جدید را با `install.sh` روی Ubuntu 24.04 تازه، endpoint و دامنهٔ جدید نصب کنید.
۲. اجرا کنید:

```bash
sudo openvpn-panelctl restore /root/migration.ovpnbak
```

رمز بکاپ و سپس عبارت `RESTORE` پرسیده می‌شود. آرشیو و دیتابیس، مطابقت کلید/گواهی و امضای CRL قبل از توقف سرویس‌ها بررسی می‌شوند. symlink/hardlink، مسیر فرار، فایل اضافی و اندازهٔ بیش از حد رد می‌شوند. تنظیم OpenSSL از مقصد نگه داشته می‌شود، نه از آرشیو. پس از توقف سرویس‌ها، یک snapshot خصوصی قبل از بازیابی در `/var/backups/openvpn-panel/pre-restore-*.tar.gz` گرفته می‌شود؛ این فایل **خام و حاوی کلید خصوصی** است.

کاربران/مصرف/کلیدهای مقصد جایگزین می‌شوند؛ این عملیات merge دو دیتابیس نیست. نشست‌های باز قبلی بسته ولی مصرف و تاریخ شروع حفظ می‌شوند. IP، دامنه، فایروال، رمز مدیر و تنظیمات تلگرام مقصد حفظ می‌شوند. در خطای عادی هنگام جایگزینی فایل یا شروع سرویس، فایل‌های قبلی برگردانده می‌شوند. قطع برق/خرابی دیسک وسط بازیابی تراکنش سراسری فایل‌سیستم نیست و تضمین rollback ندارد؛ snapshot ماشین و بکاپ ایمن لازم است.

۳. اتصال واقعی، مصرف و وضعیت را بررسی کنید. اگر endpoint VPN عوض شده، DNS قبلی را به سرور جدید منتقل کنید یا فایل اتصال تازه دانلود کنید. برای حفظ URL کامل لینک‌های وضعیت، دامنهٔ قبلی را نیز منتقل کنید؛ هش توکن‌ها در دیتابیس حفظ شده است. زمان اعتبار در downtime متوقف نمی‌شود.
۴. تا اطمینان از انتقال، سرور قدیم و بکاپ را پاک نکنید. دو سرور را هم‌زمان با یک snapshot برای همان کاربران سرویس ندهید؛ مصرف مستقل ثبت و سهمیه دور زده می‌شود.

### بکاپ‌های قدیمی 0.1

CLI بکاپ‌های `.tar.gz` تولید همین پروژه را نیز می‌پذیرد، اما تنظیمات میزبان قدیمی (`panel.env`، `vpn.json` و تنظیم سرور) را وارد نمی‌کند. فقط آرشیو خودتان را بازگردانید. فایل رمزگذاری‌شدهٔ جدید به رمز اصلی نیاز دارد؛ گزینهٔ `--passphrase-file` صرفاً برای اتوماسیون و فایل معمولی root-owned با مجوز `0600` است. هیچ رمز یا توکنی را در argv یا history قرار ندهید.

## کنترل سرویس‌ها

از داشبورد، توقف/ری‌استارت **فقط پنل وب** با CSRF، رمز مدیر و تأیید انجام می‌شود. عملیات حدود سه ثانیه تأخیر دارد تا پاسخ مرورگر برگردد. VPN، حسابداری و زمان‌بندی ادامه دارند. پس از توقف وب، Caddy ممکن است 502 نشان دهد و لینک وضعیت هم تا شروع دوبارهٔ وب در دسترس نیست.

```bash
sudo openvpn-panelctl web-start
sudo openvpn-panelctl web-stop
sudo openvpn-panelctl web-restart
sudo openvpn-panelctl restart   # کل سامانه با ترتیب امن؛ اتصال VPN قطع می‌شود
sudo openvpn-panelctl password  # تغییر رمز و ابطال نشست‌های مدیریت
sudo openvpn-panelctl status
```

## آمار و جست‌وجو

CPU نمونهٔ لحظه‌ای ۱۰۰ میلی‌ثانیه‌ای، RAM بر اساس حافظهٔ در دسترس، Swap بر اساس مقدار مصرف‌شده و Disk مربوط به `/` است. CPU/RAM مصرف **سرور** هستند، نه تنها فرایند وب. صفحه با بازکردن/دکمهٔ به‌روزرسانی تازه می‌شود، تاریخچه/نمودار ذخیره نمی‌شود.

Online از فهرست واقعی OpenVPN در آخرین poll می‌آید، نه صرفاً نشست‌های باز دیتابیس. پس از ۱۵ ثانیه دادهٔ قدیمی، «نامشخص» نمایش داده می‌شود. Disabled یعنی غیرفعال‌سازی دستی؛ Expired مستقل از آن و بر اساس تاریخ است، پس این دو می‌توانند هم‌پوشانی داشته باشند. Total traffics مجموع دریافت+ارسال ثبت‌شدهٔ تمام کاربران است، نه تمام ترافیک کارت شبکهٔ میزبان. سرچ بخش/تمام نام، بدون حساسیت به حروف است؛ آمار کلی با سرچ تغییر نمی‌کند.

## مسیرها و عیب‌یابی

- کد: `/opt/openvpn-panel`؛ نوشتن فقط root.
- داده: `/var/lib/openvpn-panel/quota.sqlite`.
- تنظیمات وب/PKI: `/etc/openvpn-panel`؛ `telegram.json` و `backup-state.json` نیز root-only.
- وضعیت آنلاین: `/var/lib/openvpn-panel-status/online.json`، root-owned و فقط‌خواندنی برای گروه پنل.
- بکاپ زمان‌بندی: `openvpn-panel-backup.timer` / `openvpn-panel-backup.service`.

```bash
sudo journalctl -u openvpn-panel -u openvpn-panel-pki -u openvpn-panel-accounting -u openvpn-panel-backup -u openvpn-server@panel -n 100 --no-pager
sudo systemctl list-timers openvpn-panel-backup.timer
```

لاگ خطای reverse proxy در زمان خاموش‌بودن وب ممکن است مسیر درخواست، از جمله توکن لینک وضعیت را داشته باشد؛ لاگ‌ها را محرمانه نگه دارید و پیش از اشتراک‌گذاری توکن‌ها و IPها را حذف کنید.

در خطای نصب نیمه‌تمام، داده/CA را برای عبور از پیش‌بررسی پاک نکنید. روی VPS تازهٔ بدون داده، بازسازی VPS بعد از بررسی علت امن‌تر از حذف کور فایل‌هاست. برای خطای VPN، دیسک، مجوزها و journal را بررسی و بعد `openvpn-panelctl restart` کنید؛ heartbeat/hook را دستی دور نزنید.

## حذف

ابتدا بکاپ بگیرید؛ timer و سرویس‌های پروژه را stop/disable کنید، از جمله `openvpn-server@panel` و `openvpn-panel-network`. توقف network فقط قواعد اختصاصی پروژه را حذف می‌کند. Caddy یا IPv4 forwarding را اگر سرویس دیگری استفاده می‌کند کورکورانه حذف/خاموش نکنید. فایل `/etc/sysctl.d/70-openvpn-panel.conf` forwarding را فعال نگه می‌دارد. بکاپ‌ها، کلیدها و تنظیمات Telegram همچنان روی دیسک‌اند؛ پاک‌کردن آن‌ها نیازمند تصمیم آگاهانه و بکاپ امن است.


## خطای SSL پس از نصب بدون دامنه

وجود رکورد A به‌تنهایی کافی نیست. برای راه‌اندازی اولیه در Cloudflare ابر رکورد را خاکستری / DNS only کنید؛ A باید IPv4 همین VPS باشد. AAAA نامعتبر را حذف کنید. TCP 80 و 443 باید هم در فایروال سیستم و هم provider باز باشند؛ سرویس دیگری نباید این پورت‌ها را اشغال کرده باشد. پنل بدون اجازه nginx/Apache یا فایروال موجود را تغییر نمی‌دهد. CAA محدودکننده، ساعت نادرست، DNSSEC خراب، انتشار DNS و محدودیت/دسترسی خروجی ACME را نیز بررسی کنید.

در نسخهٔ 0.4 پس از یک تلاش تازه، کد و مرحلهٔ شکست در SSL Management ذخیره می‌شود. `tls_certificate` یعنی گواهی نام/زنجیرهٔ معتبر روی loopback در ۱۸۰ ثانیه آماده نشد؛ `panel_https` یعنی TLS تأیید شد ولی /login پاسخ 200 نداد. `caddy_start` و `caddy_validate` خطاهای شروع/پیکربندی هستند. خطاهای قدیمی کد جدید ندارند. قفل تراکنش و بازگردانی خودکار حفظ شده‌اند؛ سرویس گذرا سقف ۴۲۰ ثانیه دارد و درخواست هم‌زمان رد می‌شود.

```bash
sudo journalctl -u caddy -u openvpn-panel --since "15 minutes ago" --no-pager
sudo journalctl -u 'openvpn-panel-settings-*' --since "15 minutes ago" --no-pager
sudo ss -ltnp '( sport = :80 or sport = :443 )'
```

لاگ‌ها ممکن است دامنه، IP و در برخی خطاهای پراکسی URI حساس داشته باشند؛ قبل از ارسال بازبینی کنید. هرگز panel.env، کلید خصوصی، توکن یا فایل .ovpn ارسال نکنید. گواهی/نام میزبان را برای عبور از این خطا غیرفعال نکنید. اگر لازم شد: `sudo openvpn-panelctl settings-rollback`. پس از موفقیت، آدرس HTTPS جدید را باز و دوباره وارد شوید؛ برای اشتراک عمومی در حالت SSH، لینک localhost قابل استفادهٔ کاربران بیرون سرور نیست.

## کلید لینک‌های قابل کپی و حذف کاربر

کلید `/var/lib/openvpn-panel/quota.sqlite.links.key` باید همراه DB حفظ شود. توسط کاربر وب با mode 0600 ساخته می‌شود؛ عمداً با تغییر رمز مدیر یا restart عوض نمی‌شود. بکاپ جدید آن را وارد آرشیو می‌کند، ciphertextها را در برابر کلید بررسی می‌کند و در restore مالکیت فایل را به مالک DB می‌دهد. مقصد باید نسخهٔ جدید داشته باشد. اگر فایل گم شد، از بکاپ همان DB بازیابی کنید؛ کلید تصادفی جایگزین نکنید. از انتشار فایل، DB و tar.gz خام خودداری کنید؛ نسخهٔ encrypted را برای انتقال ترجیح دهید. دسترسی کامل به کاربر سیستم وب، امکان خواندن DB و کلید را می‌دهد؛ رمزنگاری جایگزین حفاظت از VPS و حساب مدیر نیست.

حذف از رابط، tombstone غیرفعال نگه می‌دارد تا گواهی قبلی با ساخت دوبارهٔ همان نام مجاز نشود. کاربران حذف‌شده در لیست نیستند، لینک‌ها نامعتبرند، اتصال در چرخهٔ حسابداری قطع می‌شود و ترافیک تاریخی در Total traffics می‌ماند. نام تازه برای کاربر جدید انتخاب کنید. restore بکاپ قدیمی ممکن است کاربر حذف‌شده را برگرداند؛ downgrade کد قدیمی روی همین DB می‌تواند قواعد حذف جدید را نشناسد، پس rollback را با بکاپ و نسخهٔ سازگار انجام دهید.

## Public panel address, language and calendar

On **Network settings → Panel address and port**:

- Panel Port is the public **HTTPS** port, not the localhost web service (8000),
  SSH port or OpenVPN port. The current effective port is displayed; 5000 is an
  example, not a default. Enable domain/SSL first. Allowed: 443 or 1024–65535,
  excluding internal 8000/2019 and the VPN port. Open the new TCP port in both
  server and hosting firewalls **before saving**. Keep TCP 80 open for ACME.
- Custom Admin URL enables one ASCII segment such as `/my-admin`. After success,
  use `https://panel.example.com:5000/my-admin/login`. Disabling it restores `/`.
  Old unprefixed admin routes return 404. This is not a substitute for authentication.
- Changes require the current admin password, CSRF token and explicit confirmation.
  The root worker snapshots settings, validates/reloads Caddy, restarts only the
  web service and verifies HTTPS at the new port/path locally. Failure restores
  the snapshot. **Local checks cannot detect a hosting firewall or prove public
  internet reachability.** Record the new address; keep your SSH session open.
- `/s/<token>` subscription links stay outside the admin prefix. When changing
  ports, former HTTPS ports retain only subscription routes, their static assets
  and browser preferences; admin routes return 404 there. Up to eight former ports
  are retained. Do not close those ports if you still distribute their old links.
  Existing VPN profiles, quotas and first-connection validity are not rewritten.
- Recovery: `sudo openvpn-panelctl settings-rollback` restores the most recent
  network/address snapshot. Like the pre-existing recovery command, this restarts
  web **and VPN**, so active VPN connections can be interrupted. For forgotten
  passwords use `sudo openvpn-panelctl password`.

The header language and calendar controls are **per-browser**, independent choices:
Persian/RTL or English/LTR; Gregorian or Jalali. Preferences apply to login,
admin pages, subscriber guides, dates and interactive messages. They are held in
allowlisted HttpOnly, SameSite cookies (Secure on HTTPS), not in the server's
settings or backups. Cookies must be allowed. Browser theme remains independent.

All date displays retain the **UTC** time zone. Databases continue to store UTC
Unix timestamps and validity days; selecting Jalali never changes expiry arithmetic.
On an activated user's edit form, the optional expiration-date picker uses the
selected calendar (including leap-day validation). Check the explicit date override
only if you want to replace the days field: it converts the chosen UTC calendar
date to whole validity days while preserving the original first-connect time of
day. Before first connection only duration is editable, so validity still starts
on first connection. Date text input remains available without JavaScript.

## Web restore and password-free backups (current behavior)

This section supersedes older encryption/SSH-only backup instructions above.
New manual and scheduled `.ovpnbak` files are compressed migration archives with
**no file password**, including Telegram copies. They contain the VPN CA/private
keys and subscription-link vault key. Anyone with a file can read and reuse its
contents: store and share it only through trusted private channels. HTTPS protects
transfer to the panel/Telegram, not the downloaded file at rest. Existing encrypted
files are unchanged and still require their original password for import.

In **Backups → Upload and restore backup**, choose the file (maximum 45 MiB), enter
this server's current **administrator password**, and confirm replacement. No new
backup password is needed. The collapsed legacy-password field is only for old
AES-encrypted files. The root broker receives bounded bytes, never a web-selected
filesystem path; it checks archive paths, types, compressed/expanded sizes, SQLite
integrity, certificates, keys and CRL before scheduling downtime. Decompression is
bounded before tar metadata is parsed. Passwords never appear in job arguments or
logs. Only the dedicated panel UID can use this broker operation.

An independent root worker takes the existing private pre-restore snapshot under
`/var/backups/openvpn-panel`, stops writers, restores users/usage/VPN keys and
restarts services. Current endpoint/domain/admin path/admin credentials/Telegram
settings remain unchanged. Existing file/startup-error rollback is retained.
Uploads are root-only temporary jobs and are removed after completion/failure.
Keep the acknowledgement page open: it tolerates short outages, polls authenticated
job status, and refreshes the dashboard **only after confirmed success**. It never
resubmits a restore automatically. A timeout is an unknown outcome, not success;
check `/backups/restore/status` under your admin prefix and SSH service journals.
Power loss or an unrecoverable service restart may still require SSH recovery.
Active VPN connections are interrupted. When migrating servers, move the original
DNS record or download profiles for the new endpoint as before.


## Per-user simultaneous connection limit

Create/edit a user and set **Simultaneous connections** (1–100; default 1).
Existing users and legacy backups default to 1, preserving the previous policy.
For a limit of 2, two active transports using that certificate are admitted and
its third is rejected synchronously in the client-connect hook. Closing a session
frees a slot. The count is transactional (`BEGIN IMMEDIATE`) so concurrent
handshakes cannot overbook. The same public IP may have multiple connections;
this counts connections, not unique people, IPs or hardware devices. All sessions
share the account's volume and first-connect validity. The value survives backups.

No new client profile is needed after editing the limit. Lowering a limit does
not evict already-active sessions: new connections are blocked until the active
count falls below the new cap. Existing disconnect/reset accounting releases slots.
Quota/expiry/disable/deletion and certificate revocation continue to apply to all
sessions. `duplicate-cn` is enabled in fresh installs and inserted during upgrade
so OpenVPN does not replace the previous same-certificate connection before the
panel can enforce the selected cap. Upgrade has the normal brief VPN restart.
