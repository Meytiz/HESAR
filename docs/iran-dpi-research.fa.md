# شواهد DPI و انتخاب مسیر برای HESAR

تاریخ بررسی منابع: **2026-10-12**. سرور و ASN واقعی ایران برای آزمون ارائه نشده‌اند؛ نتایج اجرایی این نسخه آزمایشگاهی‌اند. تاریخ مطالعه منابع به معنی اندازه‌گیری امروز تمام شبکه‌های ایران نیست. «بهترین پروتکل» بدون مشخصات مسیر و انتقال دوطرفه قابل تعیین نیست.

## وضعیت ایران و توصیه لایه ۳

گزارش ژوئن ۲۰۲۶ یک نقطه اندازه‌گیری داخل ایران، رفتار allowlist قبل و بعد از بازگشت بخشی از ارتباط در ۲۶ مه را شرح می‌دهد. آزمایش GRE آن شامل شرایط ویژه مبدأ/جهت است؛ شواهدی برای کارکرد GRE استاندارد روی تمام مسیرها نیست. برداشت طراحی HESAR: انتخاب روش باید به IP مبدأ، مقصد، جهت و زمان وابسته سنجیده شود. [گزارش پژوهشگر در net4people، Issue 630](https://github.com/net4people/bbs/issues/630).

گزارش عملی سپتامبر ۲۰۲۶ در OmniTunnel، دانلود GRE و شکست آپلود روی یک مسیر را نشان می‌دهد. این شاهد محدود، جمله «لایه ۳ فعلاً جواب می‌دهد» را برای همان شرایط قابل بررسی می‌کند، نه یک قانون عمومی. در این نسخه GRE/IPIP واقعی با احراز هویت داخلی، MTU و source-route guard اضافه شده‌اند و انتقال رفت/برگشت ملاک است. [OmniTunnel](https://github.com/Free-Guy-IR/OmniTunnel).

گزارش اختلال فصل دوم Cloudflare بازگشت ترافیک را بررسی می‌کند؛ افزایش حجم مشاهده‌شده به‌تنهایی اثبات دسترسی آزاد نیست. همچنین مشاهده مسیر BGP با عبور واقعی ترافیک فرق دارد. [Cloudflare Q2 2026](https://blog.cloudflare.com/q2-2026-internet-disruption-summary/)، [پژوهش درباره دیدپذیری و اتصال](https://arxiv.org/html/2605.00187v1).

داده‌های دیتاسنتر، موبایل، شبکه ثابت، سازمانی و شبکه ملی باید جدا سنجیده شوند. نتیجه یک دیتاسنتر را به همراه اول/ایرانسل/رایتل تعمیم نمی‌دهیم. همراه هر تست باید ASN، ساعت تهران، IP خروجی و جهت ثبت شود. هیچ اپراتوری اینجا «بهترین» رتبه‌بندی نشده است.

## روش‌های انتخاب‌شده در لایه‌های مختلف

| سطح محدودیت | گزینه عملی در HESAR | محدودیت |
|---|---|---|
| L1/L2، قطع لینک یا MTU زیرساخت | تنظیم MTU و انتخاب مسیر با آزمون | نرم‌افزار قطع فیزیکی را ترمیم نمی‌کند |
| L3، encapsulation و routing | GRE/IPIP با transport احرازشده | پروتکل‌های IP 47/4 باید دوطرفه عبور کنند |
| L2/L4، conntrack و handshake | Paqet با بسته TCP خام، KCP و کلید مستقل | نیازمند packet capture؛ alpha و وابسته به مسیر |
| IP allowlist/null route | مقایسه مسیر و سرور خروجی | padding یا TLS جای دسترسی IP را نمی‌گیرد |
| DNS | IP مقصد مستقل از TLS server name | تغییر اجباری DNS میزبان انجام نمی‌شود |
| L4، مسدود بودن UDP | WSS یا Auto با QUIC→WSS | fallback فقط پیش از داده؛ اتصال فعال مهاجرت نمی‌کند |
| loss و ازدحام | QUIC، KCP یا Hysteria | سرعت برتر در ایران اندازه‌گیری نشده |
| TLS و fingerprint | REALITY/XHTTP از هسته Xray | دامنه پوشش و سازگاری مسیر لازم است |
| TLS fragmentation | قطعه‌بندی اختیاری اولین رکورد handshake | اثر مسیر باید اندازه‌گیری شود؛ هزینه تأخیر دارد |
| L7، probing و شکل ترافیک | WSS احرازشده و Shaped WSS آزمایشی | مرورگر کامل تقلید نمی‌شود؛ timing/IP قابل تحلیل‌اند |

هفت لایه OSI هفت محصول مستقل ضد DPI نیستند. انتخاب این نسخه چند حامل متفاوت و کنترل درست خطا است، نه ادعای رفع هر نوع محدودیت.

## منابع پروتکل‌ها و تصمیم‌های پیاده‌سازی

**Paqet:** پروژه اصلی TCP خام را بیرون از TCP stack معمول میزبان حمل می‌کند و KCP/smux فراهم می‌کند. به همین دلیل احتمال تفاوت رفتار با فایروال conntrack وجود دارد، اما «TCP واقعی مرورگر» فرض نمی‌شود. تنظیم کارت، IP، MAC و سه قاعده محدود از دستورالعمل upstream گرفته و در عامل محلی خودکار شده است. نسخه بسته‌شده `v1.0.0-alpha.21` است؛ باینری‌های Linux upstream statically linked هستند. [مخزن و دستورالعمل اصلی Paqet](https://github.com/hanselime/paqet).

**Xray:** بازنویسی ناقص REALITY انجام نشده؛ هسته upstream `v26.10.10` با VLESS/XHTTP استفاده می‌شود. UUID و مسیر XHTTP از کلید مشترک با domain separation مشتق می‌شوند. fingerprint انتخابی `chrome` در هسته تنظیم شده، اما این یک ادعای تقلید رفتار کامل مرورگر نیست. routing و `finalRules` فقط پورت loopback HESAR را اجازه می‌دهند. [تنظیم REALITY](https://xtls.github.io/en/config/transports/reality.html)، [بحث اصلی XHTTP](https://github.com/XTLS/Xray-core/discussions/4113)، [نسخه هسته](https://github.com/XTLS/Xray-core/releases/tag/v26.10.10).

هشدار pinning گواهی Xray برای چند transport در نسخه‌های قدیمی، ضرورت استفاده از نسخه اصلاح‌شده و پرهیز از غیرفعال کردن بررسی TLS را نشان می‌دهد. رفع upstream از `v26.7.11` ثبت شده است؛ بسته این نسخه جدیدتر است. این هشدار به معنی آسیب‌پذیری همه حالت‌های REALITY نیست. [اعلان امنیتی رسمی](https://github.com/XTLS/Xray-core/security/advisories/GHSA-5wf9-h793-w73c).

**Hysteria:** هسته `app/v2.13.0` با Salamander، کلید obfs مستقل و بررسی واقعی CA/SNI انتخاب شده است. نرخ اجباری Brutal حدسی تنظیم نمی‌شود. Gecko نیز در تحقیق و QA پیشین بررسی شد، ولی در پروفایل مدیریت‌شده این نسخه انتخاب نمی‌شود. UDP کاملاً مسدود با Hysteria اصلاح نمی‌شود. [تنظیم کلاینت](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)، [تنظیم سرور](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)، [Release رسمی](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.13.0).

**GRE/IPIP:** کرنل Linux از local outer واقعاً اختصاص‌یافته و دستگاه خروجی مشخص استفاده می‌کند. لینک با IP خصوصی، route اختصاصی peer و جدول دارای unreachable default محدود می‌شود؛ route پیش‌فرض میزبان تغییر نمی‌کند. هیچ spoofing مبدأ عمومی برای bypass پیاده نشده است. [ip-tunnel، مستند Linux](https://man7.org/linux/man-pages/man8/ip-tunnel.8.html).

**WSS/QUIC:** WSS از TLS معتبر و WebSocket استفاده می‌کند و handshake اختصاصی را داخل آن نگه می‌دارد. ClientHello آن Go TLS است. QUIC داخلی custom ALPN دارد؛ به‌عنوان HTTP/3 معرفی نشده است. uTLS امکان کنترل ClientHello را می‌دهد، ولی به‌تنهایی transport و دفاع probing نیست؛ قابلیت آن در این نسخه از مسیر Xray استفاده می‌شود. [uTLS upstream](https://github.com/refraction-networking/utls).

## طرح آزمایشی Shaped WSS

هدف این پیاده‌سازی، آزمون تغییر بعضی ویژگی‌های طول ارسال داخل WSS است: payload حداکثر 16KiB، padding حداکثر 1152 بایت، bucketهای محدود و jitter تصادفی. لایه TLS و AEAD موجود حفظ شده‌اند؛ رمزنگاری جدید طراحی نشده است. دریافت، header و تخصیص حافظه را قبل از ادامه محدود می‌کند.

padding ایده عمومی شناخته‌شده‌ای است. نمی‌توان ثابت کرد این ترکیب قبلاً در هیچ پروژه‌ای منتشر نشده یا با همه DPIها مقابله می‌کند. padding ممکن است signature تازه بسازد و overhead ارسال کوچک زیاد باشد. اثربخشی ایران هنوز آزموده نشده؛ گزینه آزمایشی برای A/B measurement است.

پژوهش تشخیص ترافیک رمز‌شده در چین نشان می‌دهد رمزنگاری یا شباهت سطحی به تنهایی کافی نیست. این پژوهش را شاهد مستقیم درباره ایران در نظر نمی‌گیریم. [Wu و همکاران، USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi).

## روش‌هایی که فقط بررسی شده‌اند

zapret2 راهبردهای desynchronization وابسته به DPI و مسیر دارد. تنظیم سراسری ثابت NFQUEUE/TTL در نصب HESAR قرار نگرفته است؛ چنین تغییری بدون آزمون همان مسیر ممکن است سرویس‌های دیگر را مختل کند. Cloak و Tor pluggable transports نیز پیاده‌سازی مستقل دارند و کپی ناقص آن‌ها قابلیت واقعی محسوب نمی‌شود. این‌ها گزینه انتخابی پنل این نسخه نیستند. [zapret2 upstream](https://github.com/bol-van/zapret2)، [Cloak upstream](https://github.com/cbeuw/Cloak)، [Tor PT specification](https://github.com/torproject/torspec/blob/main/pt-spec.txt).

## چه چیزی آزمایش شده و چه چیزی نشده است

آزمون Linux با دو network namespace، سیاست DROP فایروال محلی و لینک واقعی کرنل، TCP/QUIC/KCP روی GRE و IPIP، Paqet، Xray، Hysteria و WSS/Auto/Shaped WSS را از API پنل راه‌اندازی می‌کند. export/import جفت، حفظ کلید در ویرایش فعال، انتقال ۲ MiB با تطبیق بایت و حذف منابع بعد از Stop بررسی می‌شوند. آزمون L3 جداگانه لینک down و route اشتباه را رد می‌کند؛ آزمون نصب بسته ناقص/خراب را رد و نسل فعلی را حفظ می‌کند.

این‌ها شواهد درست بودن پیاده‌سازی محلی‌اند؛ اثبات عبور از فایروال ایران، ظرفیت دیتاسنتر یا سرعت واقعی نیستند. workflowهای GitHub پس از push همین تست‌ها را اجرا خواهند کرد؛ اجرای محلی جای نتیجه Actions مخزن شما را نمی‌گیرد.

برای انتخاب مسیر واقعی، ابتدا دسترسی IP و برنامه مقصد را بررسی کنید، سپس پروفایل‌ها را با حجم/زمان مشابه بسنجید. handshake، انتقال طولانی، دانلود و آپلود را جدا ثبت کنید. حداقل جدول نتایج: زمان تهران، ASN، مسیر/پروفایل، موفق/کل، زمان راه‌اندازی، latency، سرعت دوطرفه و قطع‌ها. راهنمای OONI نیز anomaly را از اثبات قطعی سانسور جدا می‌کند. [تفسیر داده OONI](https://ooni.org/support/interpreting-ooni-data/).
