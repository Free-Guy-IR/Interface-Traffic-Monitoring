# Interface-Traffic-Monitoring

مانیتورینگ ترافیک اینترفیس
<img width="1256" height="616" alt="Screenshot (165)" src="https://github.com/user-attachments/assets/0ed26721-bd57-4613-926d-9666bbc4a912" />




# مانیتورینگ ترافیک اینترفیس  
نرخ‌ها از `/sys/class/net/*/statistics` و اطلاعات پایه از `ip -json` خوانده می‌شوند.  
UI شامل کارت جدا برای هر اینترفیس، نمودار زنده، **Dark Mode** و جستجوی سریع است.


---

## ✨ قابلیت‌ها

داشبورد لحظه‌ای اینترفیس‌ها با نمودار زنده

پایش پینگ چند هدف + میانگین/۹۵٪/تلفات

ترافیک زنده بر اساس پورت (conntrack) + پاکسازی لاگ

مسدودسازی دامنه/IP/CIDR با ipset/dnsmasq

یادگیری خودکار SNI و افزودن IPهای جدید به بلاک‌لیست

حالت «صفحهٔ مسدودسازی» HTTP با سرور داخلی

بلاک‌لیست سراسری یا مخصوص هر اینترفیس

محدودیت پهنای‌باند آپلود/دانلود (tc) از داخل پنل

گزارش مصرف روزانه/ماهانه + مجموع‌های تجمعی

کنترل اینترفیس‌ها (روشن/خاموش) از داخل پنل

رابط فارسی، تیره/روشن، واکنش‌گرا (Tailwind)

سبک و بی‌نیاز از دیتابیس؛ 

گزینه‌های اختیاری: اجبار DNS داخلی، مسدودسازی DoT/DoQ، همگام‌سازی خودکار ipset



  



### الزامی
- Linux (تست‌شده روی **Ubuntu 22.04+**)
- **Python 3.10+** و `pip`
- **iproute2** (`ip`, `tc`)
- **iptables** و **ip6tables**
- **ipset**
- **conntrack-tools** (`conntrack`)
- **dnsmasq** (برای حالت ipset/dnsmasq)
- **ethtool**
- دسترسی **root** یا `sudo` بدون پسورد برای دستورات سیستمی
- **Flask** (از مخزن Ubuntu یا PyPI)

### نصب سریع (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y   python3 python3-pip python3-flask   iproute2 iptables ipset conntrack dnsmasq ethtool dnsutils
```

> اگر قبلاً با `pip` نسخه‌های ناسازگار Flask/Werkzeug نصب کرده‌اید و خطا می‌بینید، یا فقط از بسته‌های `apt` استفاده کنید، یا پکیج‌های قدیمی `pip` را پاک کرده و یک مجموعهٔ سازگار نصب کنید.

- `publicsuffix2` یا `tldextract` (تشخیص دامنهٔ ثبت‌پذیر)
- `scapy` برای **SNI learner** (اگر `AUTO_PIP_INSTALL=1` باشد خودش نصب می‌شود)
```bash
python3 -m pip install --upgrade publicsuffix2 || python3 -m pip install --upgrade tldextract

# فقط اگر SNI learner می‌خواهید:
python3 -m pip install --upgrade scapy
```

---

## ⚙️ آماده‌سازی سیستم (خیلی مهم)

برای اینکه مسدودسازی/ipset و محدودیت پهنای‌باند درست کار کند، چند سرویس/تنظیم را یک‌بار انجام دهید:

### 1) آزاد کردن پورت 53 برای `dnsmasq`
یکی از این دو روش را انتخاب کنید:

**روش A (پیشنهادی): غیرفعال کردن Stub در `systemd-resolved`**
```bash
sudo sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
sudo systemctl enable --now dnsmasq
```

**روش B: غیرفعال کردن کامل `systemd-resolved`**
```bash
sudo systemctl disable --now systemd-resolved
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
sudo systemctl enable --now dnsmasq
```

> اگر سرویس دیگری مثل `dnscrypt-proxy` یا `stubby` پورت 53 را گرفته است، آن را متوقف/غیرفعال کنید.




## 🚀 اجرا (Quick Start)
پیش‌فرض فایل برنامه `netdash.py` است (روی پورت `18080`).


```bash
python3 /path/to/netdash.py
# سپس در مرورگر:
# http://<SERVER-IP>:18080
```

اگر پورت اشغال بود، پورت را داخل فایل تغییر دهید:
```bash
sed -i 's/^PORT\s*=.*/PORT = 18181/' /path/to/netdash.py
```

اگر فایروال دارید:
```bash
sudo ufw allow 18080/tcp
```

---

## 🔧 پیکربندی
- **PORT**: در بالای فایل `netdash.py` مقدار `PORT` را تغییر دهید (پیش‌فرض 18080).
- **MAX_POINTS**: تعداد نقاط نگهداری‌شده در نمودار و Persist (پیش‌فرض 120). برای حدود ۱ ساعت نمونه‌برداری ۱ ثانیه‌ای، مقدار 3600 مناسب است.
- **Cache-Control**: برای جلوگیری از کش قدیمی UI، هدر `no-store` روی HTML ست شده است.
- **CDNها**: Tailwind و Chart.js از CDN لود می‌شوند؛ در صورت نبود اینترنت، می‌توانید نسخه‌های محلی را جایگزین کنید (fallback سادهٔ نمودار فعال است).

---

## 💾 محل ذخیره‌سازی داده‌ها (Persist)
برنامه به‌صورت خودکار یکی از این مسیرها را انتخاب می‌کند (به‌ترتیب اولویت):
1. `/var/lib/netdash/history.json`
2. `~/.local/share/netdash/history.json`
3. `/tmp/netdash/history.json`

---

## 🧪 APIهای سادهٔ تست
```bash
# نرخ‌های زنده
curl -s http://127.0.0.1:18080/api/live | jq .

# اطلاعات اینترفیس‌ها
curl -s http://127.0.0.1:18080/api/interfaces | jq .

# تاریخچهٔ Persist شده
curl -s http://127.0.0.1:18080/api/history | jq .
```

---

## 📦 اجرای مداوم به‌صورت سرویس (systemd)

### گزینه A) سریع و فوری (run as root)
فایل سرویس زیر را بسازید:
```bash
sudo tee /etc/systemd/system/netdash.service >/dev/null <<'UNIT'
[Unit]
Description=Network Interface Traffic Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/netdash.py
WorkingDirectory=/root
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT
```

فعال‌سازی و اجرا:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now netdash
```

وضعیت و لاگ:
```bash
systemctl status netdash
journalctl -u netdash -e -f
```

### گزینه B) تمیزتر/ایمن‌تر (کاربر جداگانه `netdash`)
ایجاد کاربر و مسیرها:
```bash
sudo useradd -r -s /usr/sbin/nologin netdash || true
sudo install -d -o netdash -g netdash /opt/netdash
sudo install -d -o netdash -g netdash /var/lib/netdash
sudo cp /root/netdash.py /opt/netdash/netdash.py
sudo chown netdash:netdash /opt/netdash/netdash.py
```

سرویس:
```bash
sudo tee /etc/systemd/system/netdash.service >/dev/null <<'UNIT'
[Unit]
Description=Network Interface Traffic Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=netdash
Group=netdash
WorkingDirectory=/opt/netdash
PermissionsStartOnly=true
ExecStartPre=/usr/bin/mkdir -p /var/lib/netdash
ExecStartPre=/usr/bin/chown -R netdash:netdash /var/lib/netdash
ExecStart=/usr/bin/python3 /opt/netdash/netdash.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now netdash
```

---

## 🛡️ اجرای Production-Grade (اختیاری)

### Gunicorn
```bash
sudo apt-get install -y gunicorn
sudo tee /etc/systemd/system/netdash.service >/dev/null <<'UNIT'
[Unit]
Description=Network Interface Traffic Monitor (gunicorn)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/usr/bin/gunicorn --bind 0.0.0.0:18080 --workers 2 --threads 4 netdash:app
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl restart netdash
```

> اگر فایل را به `/opt/netdash/netdash.py` منتقل کرده‌اید، `WorkingDirectory` را مطابق مسیر جدید تنظیم کنید.

### Nginx (ریورس‌پروکسی + دامنه/SSL) — خلاصه
```bash
sudo apt-get install -y nginx
sudo tee /etc/nginx/sites-available/netdash >/dev/null <<'NG'
server {
    listen 80;
    server_name YOUR_DOMAIN;

    location / {
        proxy_pass         http://127.0.0.1:18080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
NG
sudo ln -sf /etc/nginx/sites-available/netdash /etc/nginx/sites-enabled/netdash
sudo nginx -t && sudo systemctl reload nginx
```

---

## ❓ رفع اشکال‌های رایج
- **Address already in use**: پورت را عوض کنید یا پروسهٔ اشغال‌کننده را متوقف کنید:
  ```bash
  sudo ss -lntp '( sport = :18080 )'
  sudo fuser -vk 18080/tcp
  ```
- **ImportError مربوط به Flask/itsdangerous/Werkzeug**: از بسته‌های `apt` استفاده کنید یا مجموعهٔ نسخه‌های `pip` را یکدست کنید.
- **UI کش قدیمی**: یک بار Hard Refresh (Ctrl+F5) بزنید.
- **`iproute2` نصب نیست**:
  ```bash
  sudo apt-get install -y iproute2
  ```

---


---

## 🏷️ نام پروژه
**مانیتورینگ ترافیک اینترفیس**  
نام انگلیسی: **Network Interface Traffic Monitor** (*NetDash*)

