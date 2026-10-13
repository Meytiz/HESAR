# HESAR

پلتفرم تانل معکوس و مدیریت مسیر شبکه برای اتصال سرور ایران (Bridge) و سرور خارج (Overseas) از طریق یک پنل وب یکپارچه.

> هیچ پروتکلی عبور قطعی از تمام انواع فیلترینگ، محدودیت‌های مسیر یا اختلال‌های لایه شبکه را تضمین نمی‌کند. پروفایل‌های متنوع در HESAR برای تطبیق سریع با شرایط مختلف شبکه طراحی شده‌اند.

---

## نصب سریع روی سرور لینوکس (Easy & Manual Install)

نصب HESAR نیازی به نصب Go، Node.js، کامپایلر یا تنظیم دستی فایل‌های کانفیگ روی سرور ندارد. بسته کامل انتشار شامل باینری پنل (`hesar`)، ایجنت محلی شبکه (`hesar-agent`) و هسته‌های مدیریت‌شده (`paqet`، `xray` و `hysteria`) است.

### ۱) نصب تعاملی با منوی مدیریت (پیشنهادی - مشابه شاخه `main`)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Meytiz/HESAR/main/scripts/hesar.sh)
```

از طریق این منو می‌توانید نصب آنلاین، نصب دستی/آفلاین، بررسی وضعیت سرویس‌ها، فعال‌سازی بهینه‌سازی کرنل و TCP BBR، مشاهده اطلاعات ورود به پنل و حذف کامل را انجام دهید.

### ۲) نصب خودکار تک‌خطی (بدون پرسش)

```bash
curl -fsSL https://raw.githubusercontent.com/Meytiz/HESAR/main/scripts/install-hesar.sh | sudo bash
```

### ۳) نصب دستی / آفلاین (مناسب سرورهای ایران بدون دسترسی مستقیم به GitHub)

فایل `hesar-linux-amd64.tar.gz` (یا `hesar-linux-arm64.tar.gz`) و اسکریپت `install-hesar.sh` (یا `hesar.sh`) را از بخش **GitHub Releases** دانلود کرده و به سرور منتقل کنید (مثلاً در `/root`):

```bash
sudo bash install-hesar.sh --offline /root/hesar-linux-amd64.tar.gz
```

یا اگر فایل `.tar.gz` در کنار اسکریپت در همان پوشه قرار داشته باشد:

```bash
sudo bash install-hesar.sh
```

### دستورات مدیریتی کاربردی

```bash
sudo bash install-hesar.sh --status        # وضعیت سرویس‌های hesar و hesar-agent
sudo bash install-hesar.sh --credentials   # نمایش آدرس پنل و رمز عبور اولیه
sudo bash install-hesar.sh --optimize      # فعال‌سازی TCP BBR و بهینه‌سازی بافرهای شبکه
sudo bash install-hesar.sh --logs          # مشاهده لاگ‌های زنده سرویس
sudo bash install-hesar.sh --update        # به‌روزرسانی به آخرین نسخه انتشار
sudo bash install-hesar.sh --uninstall     # توقف و حذف سرویس‌ها
```

پس از اتمام نصب، آدرس پنل (`http://SERVER_IP:8443`)، نام کاربری (`admin`) و رمز عبور اولیه مستقیماً در ترمینال نمایش داده شده و در مسیر `/etc/hesar/credentials.txt` نیز ذخیره می‌شود.

---

## راه‌اندازی تانل از داخل پنل وب

تمام مراحل ساخت تانل، تولید کلیدهای رمزنگاری، تنظیم هسته‌های مدیریت‌شده و خروجی گرفتن کانفیگ سرور مقابل از داخل پنل وب انجام می‌شود.

### گام اول: تنظیم سرور خارج (Overseas)

۱. وارد پنل سرور خارج شوید و به بخش **Tunnels → Add New Tunnel** بروید.
۲. فیلد **Server Side Role** را روی `Overseas (Node / Listener)` قرار دهید.
۳. از بخش **Network Profile Preset** یکی از پروفایل‌های زیر را متناسب با شرایط شبکه انتخاب کنید:

| پروفایل | پروتکل / حامل | کاربرد پیشنهادی |
|---|---|---|
| `Balanced (Auto QUIC/WSS)` | `auto` | شروع با QUIC و سوییچ خودکار به WSS در صورت اختلال UDP |
| `TCP / CDN Compatible (WSS)` | `wss` | مسیرهای TCP-only با گواهی TLS پین‌شده |
| `Fragmented TLS Handshake (WSS)` | `wss` | خرد کردن رکوردهای اولیه TLS ClientHello |
| `Shaped WSS (Padded Frames)` | `wss-shaped` | پدینگ فریم‌های باینری WebSocket روی TLS |
| `Lossy UDP / High RTT (QUIC)` | `quic` | مسیرهای UDP ناپایدار با غیرفعال‌سازی PMTU Discovery |
| `Raw Packet Bypass (Managed Paqet)` | `paqet + quic` | تانل سطح پکت خام KCP مدیریت‌شده توسط ایجنت |
| `XHTTP + REALITY (Managed Xray)` | `xray + tcp` | تانل VLESS + XHTTP + REALITY مدیریت‌شده توسط ایجنت |
| `UDP Obfuscated (Managed Hysteria 2)` | `hysteria + tcp` | تانل QUIC با مبهم‌سازی Salamander مدیریت‌شده توسط ایجنت |
| `Layer-3 GRE + HESAR` | `gre + quic` | رابط نقطه‌به‌نقطه GRE لایه ۳ + تانل داخلی HESAR |
| `Layer-3 IPIP + HESAR` | `ipip + quic` | رابط نقطه‌به‌نقطه IPIP لایه ۳ + تانل داخلی HESAR |

۴. آی‌پی عمومی سرور ایران را در **Other Server WAN IPv4**، پورت تانل را در **Connection Listen Port** و پورت سرویس مقصد محلی را در **Target Forward Port** وارد کنید.
۵. روی **Generate transport credentials** کلیک کنید تا کلید رمزنگاری، گواهی TLS و کلیدهای REALITY/Salamander/Paqet به‌صورت خودکار تولید شوند.
۶. تانل را ذخیره کرده، روی **Start** بزنید و سپس روی کارت تانل دکمه **Copy peer setup** را بزنید.

### گام دوم: تنظیم سرور ایران (Iran)

۱. وارد پنل سرور ایران شوید و در صفحه **Tunnels** روی **Import peer setup** کلیک کنید.
۲. متن JSON کپی‌شده از سرور خارج را جای‌گذاری کرده و روی **Apply peer setup** بزنید.
۳. پورت‌های ورودی کاربران در سرور ایران را در **Local Listen Port(s)** تنظیم کنید (مثلاً `443` یا `80,443` یا `10000-10010`).
۴. تانل را ذخیره کرده و روی **Start** کلیک کنید.

---

## معماری و ساختار مخزن

```text
backend/cmd/hesar/                      باینری پنل وب و موتور تانل HESAR
backend/cmd/hesar-agent/                ایجنت محلی شبکه با سطح دسترسی root و سوکت یونیکس
backend/internal/api/                   سرور HTTP، احراز هویت، مدیریت تانل‌ها و خروجی Peer Setup
backend/internal/config/                اعتبارسنجی کانفیگ، پروفایل‌های شبکه و مهاجرت نسخه‌ها
backend/internal/provision/             مدیریت GRE/IPIP، فایروال، هسته‌های Paqet/Xray/Hysteria و BBR
backend/internal/tunnel/                ترنسپورت‌های TCP، KCP، QUIC، WSS، Shaped-WSS و Auto
frontend/                               پنل مدیریت وب (React + TypeScript + Tailwind CSS)
scripts/build-linux-release.sh          بیلد کامل فرانت‌اند، بک‌اند و بسته‌بندی انتشار لینوکس
scripts/fetch-release-cores.py          دریافت و بررسی SHA-256 هسته‌های رسمی انتشار
scripts/package-linux-release.py        تولید آرشیوهای نهایی hesar-linux-amd64/arm64.tar.gz
scripts/install-hesar.sh                نصب‌کننده خودکار و آفلاین بسته کامل انتشار
scripts/hesar.sh                        منوی تعاملی نصب و مدیریت سرور
docs/architecture.md                    مستندات معماری فنی و جریان داده
```

---

## بیلد دستی از سورس (توسعه‌دهندگان)

برای ساخت بسته کامل انتشار لینوکس (`amd64` و `arm64`):

```bash
bash scripts/build-linux-release.sh v2.1.0
```

خروجی‌های نهایی در پوشه `release/` ساخته می‌شوند (`hesar-linux-amd64.tar.gz`، `hesar-linux-arm64.tar.gz`، `install-hesar.sh` و `checksums-sha256.txt`).
