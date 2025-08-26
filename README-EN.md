
<div align="center">
  <strong><a href="README-EN.md">English</a></strong> | <strong><a href="README.md">فارسی</a></strong>
</div>
<br>

# NetDash — Real‑time Interface Traffic Monitoring

**NetDash** is a lightweight, no‑database network dashboard. Watch live bandwidth per interface, block domains/IPs with one click (with an optional user‑facing block page), set upload/download limits, and view clean daily/monthly usage — all from a mobile‑friendly Persian UI (English content here, UI language is Persian by default).

---

## ✨ Features

- **Live network dashboard**: see per‑interface rates, charts, and aggregates.
- **One‑click block list** (domain or IP/CIDR) + **pretty block page** (HTTP only).
- **Daily / monthly usage reports** (traffic accounting).
- **Instant rate limiting** (upload/download) per interface.
- **Interface control** (bring link up/down from the panel).
- **Ping/quality monitor** with basic loss/latency chips.
- **Dark/Light theme**, fully responsive mobile‑friendly UI.
- **No database, minimal deps, auto‑restore rules after reboot.**
- **Great fit** for VPN servers, routers, small offices/teams.

> ⚠️ Firewall rules (ipset/iptables) are automatically created by NetDash when it starts. No manual firewall setup required.

---

## 🧩 Requirements

- Linux (tested on **Ubuntu 22.04+**).
- **Python 3.10+**
- `iproute2` (for the `ip` command)
- `dnsmasq`, `ipset`, `iptables` (installed by the script)
- Flask (Ubuntu’s repo versions are fine)

**Quick install (Ubuntu/Debian, OS packages only):**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-flask iproute2
```

> If you previously installed incompatible Flask-related packages with `pip` (e.g., `itsdangerous` / `Werkzeug` mismatches), either stick to Ubuntu’s `apt` packages or remove old `pip` ones and reinstall a compatible set.

---

## 🚀 One‑line Installer (recommended)

Run the interactive installer menu (install/update/manage/remove):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Free-Guy-IR/Interface-Traffic-Monitoring/main/netdash-install.sh)
```

**What the installer can do:**
- Install or reinstall NetDash from GitHub.
- Install required packages: `python3`, `pip`, `dnsmasq`, `ipset`, `iptables`, `curl`, etc.
- Create/update a `systemd` service (`netdash.service`).
- Optionally **disable `systemd-resolved`** and configure **`dnsmasq`** to bind port **53**.
- Start/stop NetDash, view logs, fully remove, and more.

> The installer also handles most conflicts automatically (e.g., port 53 in use). See **Troubleshooting** below.

---

## 📦 Manual Run (without the menu)

Clone and run:

```bash
git clone https://github.com/Free-Guy-IR/Interface-Traffic-Monitoring.git
cd Interface-Traffic-Monitoring
python3 netdash.py
```

Default UI port: **18080** → open in your browser: `http://<server-ip>:18080/`

---

## 🔧 Post‑install: DNS service (if needed)

NetDash relies on **dnsmasq** + **ipset** for domain blocking. If `dnsmasq` fails to start because **port 53 is already in use**, stop the conflicting service and point `resolv.conf` to `127.0.0.1`:

```bash
sudo systemctl disable --now systemd-resolved
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
sudo systemctl enable --now dnsmasq
```

The installer can perform these steps for you when you choose the relevant menu item.

---

## 🧪 Service management

If you used the installer, a `systemd` unit is created:

```bash
# Start/Stop/Restart
sudo systemctl start netdash
sudo systemctl stop netdash
sudo systemctl restart netdash

# Status & logs
systemctl status netdash
journalctl -u netdash -f
```

You can also use the installer’s menu to **Start/Stop**, **View logs**, **Reinstall/Update**, or **Remove** NetDash entirely.

---

## 🔐 Security (control API)

For control endpoints (e.g., interface up/down, shaping) set a token:

- Set environment variable **`NETDASH_TOKEN="your-secret"`**.
- The UI/JS sends this token via header `X-Auth-Token` for protected routes.

Without a token, read‑only endpoints remain accessible; control endpoints will reject unauthenticated requests.

---

## ⚙️ Configuration (Environment variables)

You can export these before running NetDash or add them to the `systemd` service:

| Variable | Default | Meaning |
|---|---:|---|
| `NETDASH_MAX_POINTS` | `120` | Max chart points kept in the browser. |
| `NETDASH_PORT` | `18080` | Web UI HTTP port. |
| `NETDASH_BLOCK_PORT` | `18081` | Local HTTP block‑page port (for redirecting blocked HTTP). |
| `NETDASH_FLUSH_SETS_ON_REMOVE` | `1` | Flush ipsets when removing the last domain. |
| `NETDASH_IPSET_MODE` | `1` | Use `dnsmasq`+`ipset` backend (recommended). |
| `NETDASH_SNI_BLOCK` | `1` | Add SNI‑based drop rules (TLS ClientHello string match). |
| `NETDASH_PAGE_MODE` | `1` | Redirect blocked HTTP (port 80) to the local block page. |
| `NETDASH_SNI_LEARN` | `1` | Learn live server IPs from TLS traffic and add to ipsets. |
| `NETDASH_SNI_IFACES` | `` | CSV of interfaces to sniff for SNI learning (empty = all). |
| `NETDASH_ENFORCE_DNS` | `1` | Add NAT rules to force LAN DNS to local resolver. |
| `NETDASH_BLOCK_DOT` | `0` | Block DoT/DoQ (853/8853). |
| `NETDASH_PRELOAD_META` | `0` | Add a small default block list on bootstrap. |
| `NETDASH_AUTO_PIP` | `1` | Auto‑install `scapy` for SNI learning if missing. |
| `NETDASH_TOKEN` | `` | **Control token** required by privileged endpoints. |
| `NETDASH_DENY` | `` | CSV of interfaces **not** allowed to control. |
| `NETDASH_ALLOW` | `` | CSV of interfaces explicitly allowed (overrides deny). |
| `NETDASH_IPSET4` | `nd-bl4` | IPv4 global ipset (drop). |
| `NETDASH_IPSET6` | `nd-bl6` | IPv6 global ipset (drop). |
| `NETDASH_IPSET4_PAGE` | `ndp-bl4` | IPv4 ipset for HTTP redirect. |
| `NETDASH_IPSET6_PAGE` | `ndp-bl6` | IPv6 ipset for HTTP redirect. |
| `NETDASH_IPSET_TIMEOUT` | `3600` | ipset timeout in seconds. |
| `NETDASH_PORTS_MONITOR` | `1` | Enable conntrack‑based live traffic by port. |
| `NETDASH_PORTS_INTERVAL` | `1.0` | Polling interval (seconds) for ports monitor. |

---

## 💾 Data files (persisted)

NetDash picks the first writable base dir in the following order:

1. `/var/lib/netdash`
2. `~/.local/share/netdash`
3. `/tmp/netdash`

Inside that directory, these files are created/used:

| File | Purpose |
|---|---|
| `history.json` | Per‑interface time series (for the charts). |
| `totals.json` | Byte counters & last read positions for each interface. |
| `period_totals.json` | Aggregated daily & monthly usage. |
| `filters.json` | Your block list entries (domain/IP/CIDR, per‑iface, page mode, realized IPs, SNI rules metadata). |
| `blocks_registry.json` | Consolidated view of active blocks and their realized IPs (v4/v6). |
| `sni-seen.log` | Line‑by‑line log of SNI discoveries (host ⇄ dst IP). |
| `sni-index.json` | Compact index of domains/subs to learned IPs (used to preseed ipsets). |
| `ports_totals.json` | Accumulators for per‑port usage (for the “Live by Port” table). |

You can safely delete these files to reset state; NetDash will recreate them as needed.

---

## ❗ Troubleshooting

**`dnsmasq` fails to start (port 53 in use):**
```text
dnsmasq: failed to create listening socket for port 53: Address already in use
```
Fix:
```bash
sudo systemctl disable --now systemd-resolved
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
sudo systemctl enable --now dnsmasq
```

**Iptables/ipset modules missing:** the app tries to `modprobe` required modules (`xt_string`, `ifb`). Ensure your kernel provides them or install headers/modules.

**No traffic in the “Live by Port” table:** make sure `conntrack` is installed and accounting is enabled. NetDash tries to enable it:
```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

---

## 🗑️ Uninstall

Use the installer menu → **Remove NetDash completely**. It will stop the service, remove files, and clean up.

Manual:
```bash
sudo systemctl disable --now netdash
sudo rm -f /etc/systemd/system/netdash.service
sudo systemctl daemon-reload
# Optional: remove persisted data
sudo rm -rf /var/lib/netdash ~/.local/share/netdash /tmp/netdash
```

> If you had `dnsmasq` installed solely for NetDash and don’t need it anymore:
```bash
sudo systemctl disable --now dnsmasq
sudo apt-get purge -y dnsmasq-base dnsmasq
```

---

## 📜 License

MIT — see `LICENSE` if provided in the repository.

---

## 🙌 Star the project

If NetDash helps you, please consider giving the repo a ⭐ on GitHub.
