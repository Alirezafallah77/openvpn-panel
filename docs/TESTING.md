# گزارش آزمون نسخهٔ آزمایشی

تاریخ: ۲۰۲۶-۱۰-۳۱. آخرین گزارش زنده همیشه در [Actions](https://github.com/Alirezafallah77/openvpn-panel/actions) است.

## نتیجهٔ نسخهٔ 0.4 — پورتال مشترک و اولین فعال‌سازی SSL

- **۷۰ تست محلی موفق**؛ [تست‌های Python 3.12/3.13](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41214539197) و [هر سه حالت واقعی Ubuntu 24.04: SSH، HTTPS و ارتقا از 0.1](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41214539127) برای commit `b6fe0ba` موفق شدند.
- باگ `reset-failed` روی سرویس inactive/unloaded در مسیر **نصب بدون دامنه → فعال‌سازی SSL** در runner واقعی بازتولید شد، سپس با بررسی `is-failed` قبل از reset رفع شد. تست regression جدید Caddy واقعی را از حالت خاموش روشن می‌کند، برای دامنهٔ رزروشدهٔ `.invalid` شکست گواهی را انتظار دارد و برگشت بایت‌به‌بایت فایل‌ها و خاموش‌شدن مجدد Caddy را بررسی می‌کند. فقط مهلت تست کوتاه شده؛ اعتبارسنجی TLS دست‌نخورده است.
- دانلود فایل از **مسیر پورتال مشترک** در E2E انجام شد و همان فایل برای اتصال واقعی استفاده شد؛ تست‌های TCP/UDP و حفظ داده در ارتقا/backup/restore نیز موفق‌اند.
- تست واحد، CSRF، دانلود محدود به هویت داخل توکن، ناتوانی تعویض کلید از مسیر عمومی، ابطال لینک قبلی، منع دانلود کاربر غیرفعال/منقضی/بدون حجم، خطای broker، محدودیت نرخ دانلود و شروع‌نشدن اعتبار با دانلود را پوشش می‌دهد.
- بررسی واقعی Chromium در sandbox: صفحهٔ مشترک و مدیریت، نمای ۱۴۴۰ و ۳۹۰ پیکسل، جابه‌جایی تب راهنما/سیستم‌عامل، نبود overflow افقی صفحه و نبود خطای JavaScript/CSP. پس از اصلاح کنتراست، axe-core روی نمای کلی پورتال هیچ violation از مجموعهٔ WCAG 2 A/AA گزارش نکرد؛ این نتیجه جای ارزیابی کامل تمام صفحه‌ها با همهٔ مرورگرها/صفحه‌خوان‌ها را نمی‌گیرد. تست دستی روی خود Android/iPhone/Windows هنوز انجام نشده است.
- صدور عمومی ACME برای دامنهٔ واقعی شما همچنان آزمایش نشده است؛ تست مثبت HTTPS با CA خصوصی مورداعتماد runner است. رفع باگ شروع Caddy، جای تنظیم صحیح DNS، CAA، فایروال و رفع محدودیت CA را نمی‌گیرد.

## نتیجهٔ نسخهٔ 0.3 — SSL و پروتکل

- در commit `9eabf90`، [آزمون واحد Ubuntu 24.04/Python 3.12 و 3.13](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41205072436) و [هر سه مسیر SSH، HTTPS و upgrade واقعی از 0.1](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41205072447) موفق شدند.
- اتصال OpenVPN واقعی ابتدا با TCP و سپس با UDP، از طریق endpoint دامنه‌ای آزمایشی، برقرار و درخواست HTTPS واقعی اینترنت از داخل هر دو تونل موفق شد. پروتکل سرور و `proto`/`remote` فایل کلاینت بررسی شدند؛ تاریخ شروع اعتبار حفظ شد.
- SSL Management از UI روی دامنهٔ ازپیش‌تنظیم‌شدهٔ تست اجرا شد؛ اعتبار زنجیره/نام گواهی و پاسخ HTTPS کنترل و همان دامنه در فایل جدید VPN ثبت شد. از CA خصوصی مورداعتماد همان runner استفاده شد، نه صدور عمومی ACME.
- دامنهٔ جدید، قالب Caddy، شکست TLS، شروع‌نشدن VPN، بازگردانی فایل‌ها/تنظیمات، مرز مالکیت Caddy، جلوگیری از shell/path injection و درخواست هم‌زمان در تست واحد پوشش دارند.
- DNS نام‌های تست با `/etc/hosts` شبیه‌سازی شده است. صدور گواهی عمومی برای یک دامنهٔ تازه، propagation DNS، تنظیمات Cloudflare و فایروال شرکت میزبان هنوز نیاز به تست روی سرور/دامنهٔ واقعی شما دارند. نمی‌توان از نتیجهٔ CA خصوصی، موفقیت صدور عمومی را نتیجه گرفت.
- آخرین تست محلی شامل نگه‌داشتن alias قبلی پس از ثبت مجدد دامنهٔ یکسان نیز هست؛ شمارش فعلی ۶۲ آزمون است.

## نتیجهٔ نسخهٔ 0.2 — commit `6572e1e`

- **۵۱ آزمون محلی موفق** و [آزمون واحد روی Ubuntu 24.04/Python 3.12 و 3.13](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41194925174) موفق.
- [آزمون نصب/بازیابی/ارتقا](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41194925182): هر سه حالت **SSH، HTTPS و upgrade از 0.1 واقعی** موفق.
- داشبورد CPU/RAM/Swap/Disk، جست‌وجو و مشاهدهٔ آنلاین واقعی در runner بررسی شد.
- بکاپ رمزگذاری‌شده از وب ساخته و دانلود شد؛ سپس دادهٔ کاربر عمداً تغییر کرد، بکاپ از CLI بازگردانده شد و اتصال با گواهی قبلی و لینک وضعیت قدیمی دوباره موفق بود. حفظ endpoint و رمز/کلید نشست مقصد بررسی شد.
- توقف و ری‌استارت وب از UI با تأیید رمز، ادامهٔ VPN هنگام توقف وب و روشن‌کردن دوباره از CLI بررسی شد.
- ارتقا از commit `e755701` با نصب واقعی نسخهٔ قدیم انجام شد؛ CA و کاربر آزمایشی دارای مصرف، تاریخ شروع و وضعیت غیرفعال بعد از ارتقا حفظ شدند.
- رمز اشتباه، دست‌کاری AES-GCM، آرشیو با مسیر فرار/لینک/فایل اضافه/عضو تکراری، کلید نامعتبر و بازگشت فایل‌ها پس از شکست راه‌اندازی در تست‌های محلی بررسی شدند.
- تنظیمات تلگرام، پنهان‌ماندن توکن/رمز، فاصلهٔ زمانی، نگهداری ۲۰ فایل، خطای ارسال، و محتوای درخواست HTTPS Telegram با **transport شبیه‌سازی‌شده** آزموده شده‌اند. ارسال واقعی به ربات/Chat ID شخصی آزموده نشده است.
- بازیابی روی همان VM یک‌بارمصرف و در تست واحد به مسیر مقصد جدا انجام شده؛ دو VPS فیزیکی مجزا تست نشده‌اند. صدور ACME عمومی و کلاینت‌های موبایل همچنان نیازمند آزمون کاربر هستند.
- وابستگی‌های جدید cryptography/psutil/cffi/pycparser نیز در اطلاعات آسیب‌پذیری PyPI در تاریخ گزارش مورد اعلام‌شده‌ای نداشتند؛ این تضمین نبود آسیب‌پذیری یا ممیزی امنیتی نیست.

## نتیجهٔ اجرای نسخهٔ 0.1 (سابقه)

روی کد commit `427a758`:

- **۳۱ آزمون خودکار** محلی موفق؛ شامل OpenSSL واقعی برای صدور، ابطال و بازیابی پس از خطای شبیه‌سازی‌شدهٔ CRL.
- [آزمون واحد Ubuntu 24.04 / Python 3.12 و 3.13](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41192787422): موفق.
- [نصب و اتصال واقعی VPN در دو حالت SSH و HTTPS](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41192787483): هر دو موفق.
- نصب پکیج OpenVPN 2.6 از مخازن اوبونتو، سرویس‌های واقعی systemd، PKI واقعی و کلاینت OpenVPN داخل namespace شبکه آزمایش شدند.
- HTTPS با Caddy و CA خصوصی آزمایشی معتبر برای همان runner بررسی شده؛ صدور عمومی ACME نیاز به دامنه و دسترسی پورت‌های سرور شما دارد و در این آزمون شبیه‌سازی نشده است.

موارد سرتاسری موفق:

1. ورود مدیر، ساخت کاربر، لینک وضعیت و دانلود فایل کلاینت از وب.
2. handshake واقعی TLS، شروع اعتبار و ثبت مصرف زنده.
3. درخواست HTTPS واقعی به GitHub از داخل تونل و مسیر NAT.
4. پایان حجم: قطع اتصال فعال در سمت سرور و رد اتصال بعدی.
5. افزایش سهمیه و اتصال دوباره؛ غیرفعال‌سازی دستی و قطع نشست فعال.
6. انقضای زمانی و قطع نشست فعال؛ زمان انقضا با تغییر کنترل‌شدهٔ تاریخ شروع در دیتابیس تست شده، نه انتظار چندروزه.
7. ابطال گواهی قبلی، رد فایل قدیمی و اتصال با فایل جایگزین.
8. پشتیبان‌گیری خصوصی، وجود CA/دیتابیس در آرشیو و مجوز فایل `0600`.
9. دستور maintenance restart و بازگشت سرویس‌ها.
10. کشتن پردازهٔ حسابداری و توقف fail-closed سرور.
11. متوقف‌کردن پردازش با SIGSTOP و تشخیص watchdog و توقف VPN.

در بررسی اطلاعات آسیب‌پذیری نسخه‌های دقیق وابستگی‌ها از API PyPI، در این تاریخ مورد اعلام‌شده‌ای برای وابستگی‌های requirements گزارش نشد. این بررسی جای ممیزی امنیتی، پایش مداوم یا تضمین نبود آسیب‌پذیری نیست.

## محدودیت آزمون‌ها

- VPS شخصی کاربر، فایروال شرکت میزبان، صدور ACME عمومی و DNS واقعی پنل آزموده نشده‌اند.
- OpenVPN Connect روی Android/iOS/Windows، DNS leak و رفتار kill switch هر کلاینت نیاز به آزمون جدا دارند.
- قطع برق سخت‌افزاری و فایل‌سیستم خراب، ازدحام ۲۰۰ کاربر، چند روز اجرای مداوم و throughput بالا پوشش داده نشده‌اند.
- بازیابی خودکار روی runner در 0.2 موفق بوده، اما آزمون روی VPS دوم و فایروال/DNS واقعی کاربر همچنان لازم است.
- مصرف پس از خرابی ناگهانی ممکن است به‌اندازهٔ بازهٔ نمونه‌برداری ثبت نشده باشد؛ سقف حجم بایت‌به‌بایت و حسابداری مالی تضمین نمی‌شود.

## بهبود ساخت سریع کاربر

۷۴ تست محلی موفق شدند. تست‌های جدید پیش‌فرض 50 GiB و 30 روز در فرم و سرور، ساخت متوالی، حفظ سهمیهٔ سفارشی، خطای نام تکراری، CSRF، احراز هویت، عدم شروع اعتبار، لینک معتبر پورتال و فرم جایگزین بدون JavaScript را پوشش می‌دهند. بررسی Chromium در نماهای ۱۴۴۰ و ۳۹۰ پیکسل: ساخت دو کاربر بدون جابه‌جایی صفحه، حفظ هر دو لینک، پاک‌شدن نام و انتقال فوکوس، نمایش خطای نام تکراری بدون پاک‌کردن ورودی و نبود overflow افقی/خطای JavaScript یا CSP موفق بود. الگوی نام در HTML برای regex با پرچم جدید `v` مرورگرها اصلاح شد؛ اعتبارسنجی مستقل سرور حفظ شده است. این بررسی با دادهٔ ساختگی انجام شده و شامل ورود یا تغییر در پنل مرجع خارجی نیست.

## داشبورد تیره، فیلتر و صفحه‌بندی

۷۹ تست محلی موفق‌اند. پوشش جدید: پیش‌فرض ۲۰ و انتخاب ۵۰/۱۰۰، حفظ ترجیح در نشست، صفحهٔ اول/آخر/خارج بازه، ورودی نامعتبر/بسیار بزرگ، جست‌وجوی ترکیبی، فیلترهای وضعیت/نزدیک انقضا/نزدیک پایان حجم، آنلاین نامشخص، حفظ query در صفحه‌بندی و برگشت ویرایش به مسیر محلی (بدون open redirect)، مستقل‌ماندن پورتال کاربر از پوستهٔ مدیر. Chromium در ۱۴۴۰ و ۳۹۰ پیکسل: صفحه‌بندی ۲۰→۵۰ و بعدی، حفظ query، تغییر پوسته و ماندگاری پس از reload، نبود overflow و خطای JS/CSP؛ جریان قبلی ساخت پشت‌سرهم نیز دوباره موفق بود. داده‌های پیش‌نمایش ساختگی‌اند؛ هیچ نمودار تاریخی یا وضعیت سرویس ساختگی به محصول افزوده نشده است.


## تشخیص خودکار پوسته

۷ تست Node (`node --test tests/theme.test.cjs`) برای تنظیم روشن/تیرهٔ دستگاه، نبود matchMedia، ذخیره‌سازی مسدود، مقدار ذخیره‌شدهٔ نامعتبر، اولویت انتخاب دستی، تغییر زندهٔ تنظیم دستگاه و ماندگاری انتخاب دستی موفق شدند؛ در CI هم اجرا می‌شوند. ۷۹ تست Python نیز موفق‌اند. Chromium با شبیه‌سازی تنظیم دستگاه، رنگ واقعی CSS، تغییر تنظیم زنده، دکمهٔ تغییر تم، حفظ انتخاب بعد از reload و fallback روشن در نبود matchMedia بررسی شد؛ خطای JS/CSP مشاهده نشد.

## CPU و آمار زنده

۸۲ تست Python موفق‌اند؛ نمونهٔ یک‌ثانیه‌ای، cache سه‌ثانیه‌ای، انقضا و نمونه‌گیری مجدد، حفظ صفر واقعی، خطای خواندن و دسترسی فقط‌مدیر/عدم cache پاسخ API پوشش دارند. کارت‌ها هر پنج ثانیه از API خوانده می‌شوند؛ شکست ارتباط دادهٔ قبلی را با اخطار قدیمی‌بودن نگه می‌دارد. صحت خواندن CPU روی VPS واقعی کاربر هنوز بدون مشاهدهٔ همان سرور تأیید نشده است.

## میانبرهای مستقیم و لینک قابل کپی

- ۹۰ تست Python و ۷ تست Node موفق شدند؛ ویرایش/حذف/کپی نیاز به ورود و CSRF دارند. کپیِ تکراری توکن را عوض نمی‌کند؛ مسیر لینک قدیمی قبل از صدور، پاسخ نیازمند تأیید می‌دهد و خودِ درخواست کپی هیچ تغییری ایجاد نمی‌کند.
- تست واحد رمزنگاری لینک، مجوز 0600 کلید، نبود/اشتباه‌بودن کلید، جلوگیری از ساخت کلید جایگزین روی ciphertext موجود، ابطال لینک حذف‌شده، رزرو نام، منع فعال‌سازی مجدد، حفظ حسابداری نهایی و برگشت کلید/DB در شکست restore را پوشش می‌دهد.
- [Ubuntu واقعی در هر سه حالت SSH، HTTPS و upgrade](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41222244696) برای `752a296` موفق شد: کپی دوباره همان لینک، خواندن لینک با **UID وب پس از restore**، اتصال دوباره پس از مهاجرت، قطع کاربر آنلاین پس از حذف و رد اتصال مجدد با گواهی قدیمی تأیید شدند.
- Chromium: نمایش مستقیم هر سه آیکون بیرون از details، دو بار کپی بدون تغییر لینک، بازشدن dialog ویرایش و ذخیرهٔ سهمیه، انصراف از حذف، حذف با تأیید، 404 شدن لینک قبلی و نمای ۳۹۰ پیکسل بدون overflow/خطای JavaScript بررسی شدند. این بررسی روی دادهٔ ساختگی بوده است، نه VPS کاربر.

### Panel address and locale feature verification

- Local Python suite: **100 tests passing**, including mount isolation, public
  subscription/profile/static URL generation, admin/CSRF/password requirements,
  browser preference isolation and safe redirects, English template compilation,
  Gregorian/Jalali known boundaries and invalid leap days, unchanged activation
  timestamps, port conflicts, retained subscription listeners, transactional health
  failure rollback and SSH-only path changes.
- Node theme suite: **7 passing**; Python compilation, JavaScript syntax, shell
  syntax and `git diff --check` pass.
- Real Chromium: PASS for hidden legacy login, English/LTR login, Persian/RTL
  switching, Jalali date selects inside the edit dialog (1403/1402 Esfand leap
  boundary), actual current port/path display and 390px mobile layout. This caught
  and fixed the preferences return URL missing the admin mount prefix.
- Ubuntu integration now also exercises an actual root-worker path change (all
  modes), HTTPS public port 5000 (HTTPS mode), old admin 404, old subscription and
  asset availability, browser preference changes and SSH snapshot rollback before
  the existing real OpenVPN/backup/migration checks. See the feature commit's
  GitHub Actions result for live Ubuntu evidence; local mocks are not a substitute.


Verified on functional commit `f51e1f3`:

- Ubuntu 24.04 integration run [41225339795](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41225339795):
  **success** in SSH, HTTPS and legacy-upgrade modes. Diagnostics confirm the real
  address transaction, old admin 404, retained subscriptions/assets, browser
  preferences and SSH rollback, followed by all existing VPN/quota/migration tests.
  The HTTPS mode exercises port 5000 with a trusted **private test CA**, not public
  DNS/ACME issuance or the operator's external firewall.
- Python 3.12/3.13 and Node run [41225339786](https://github.com/Alirezafallah77/openvpn-panel/actions/runs/41225339786):
  **success** (100 Python tests and 7 theme tests).
- Added regression coverage for SSL Management's pending URL retaining the current
  custom port/path; upgraded catalogs have explicit world-readable code-file
  permissions so the unprivileged web worker can read them.
