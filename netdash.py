#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import threading
import subprocess
import re
from collections import deque, defaultdict
from flask import Flask, jsonify, render_template_string, make_response, request, abort
import socket, ipaddress, uuid, random, string

# ---------------------- Config ----------------------
POLL_INTERVAL = 1.0   # seconds
MAX_POINTS    = int(os.environ.get("NETDASH_MAX_POINTS", "120"))
HOST          = "0.0.0.0"
PORT          = int(os.environ.get("NETDASH_PORT", "18080"))
BLOCK_PORT     = int(os.environ.get("NETDASH_BLOCK_PORT", "18081"))

# control (pause/resume)
CONTROL_ENABLED = True
CONTROL_TOKEN   = os.environ.get("NETDASH_TOKEN", "").strip()  # optional token
DENY_IFACES     = {x.strip() for x in os.environ.get("NETDASH_DENY", "").split(",") if x.strip()}
ALLOW_IFACES    = {x.strip() for x in os.environ.get("NETDASH_ALLOW", "").split(",") if x.strip()}
# ----------------------------------------------------

app = Flask(__name__)


# ---- Block Page Mini-Server (HTTP only) ----
blockapp = Flask("netdash_block")

BLOCK_PAGE_HTML = r"""
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>دسترسی مسدود شد</title>
<style>
  :root { --bg:#0f172a; --card:#111827; --txt:#e5e7eb; --acc:#22d3ee; }
  *{box-sizing:border-box} body{margin:0;background:linear-gradient(135deg,#0f172a,#111827);color:var(--txt);font-family:IRANSans, Vazirmatn, Inter, ui-sans-serif, system-ui}
  .wrap{min-height:100dvh;display:grid;place-items:center;padding:24px}
  .card{max-width:680px;width:100%;background:rgba(17,24,39,.85);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.06);border-radius:20px;box-shadow:0 10px 50px rgba(0,0,0,.4);padding:28px}
  .hdr{display:flex;align-items:center;gap:12px;margin-bottom:8px}
  .dot{width:10px;height:10px;border-radius:999px;background:linear-gradient(90deg,#ef4444,#f59e0b)}
  h1{font-size:22px;margin:0}
  p{opacity:.9;line-height:1.8;margin:.2rem 0}
  .host{direction:ltr;display:inline-block;padding:.2rem .5rem;background:#0b1220;border:1px dashed rgba(255,255,255,.08);border-radius:10px}
  .cta{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
  .btn{padding:10px 14px;border-radius:12px;border:1px solid rgba(255,255,255,.1);background:#0b1220;color:var(--txt);text-decoration:none}
  .btn.acc{background:linear-gradient(90deg,#06b6d4,#22d3ee);color:#0b1220;border:none;font-weight:700}
  .sub{font-size:12px;opacity:.7;margin-top:10px}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="hdr"><span class="dot"></span><h1>دسترسی به این مقصد مسدود شده است</h1></div>
    <p>این صفحه توسط سرویس‌دهندهٔ VPN شما مسدود شده است. لطفاً به پشتیبانی پیام دهید.</p>
    {% if host %}
      <p>مقصد درخواستی: <span class="host">{{ host }}</span></p>
    {% endif %}
    <div class="cta">
      <a class="btn acc" href="mailto:support@example.com">ارتباط با پشتیبانی</a>
      <a class="btn" href="/">بازگشت</a>
    </div>
    <div class="sub">کد: 451 | این صفحه به‌جای مقصد HTTP شما نمایش داده شده است.</div>
  </div>
</div>
</body>
</html>
"""

@blockapp.after_request
def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp

@blockapp.route("/", defaults={"path": ""})
@blockapp.route("/<path:path>")
def blocked_any(path):
    host = request.headers.get("Host","")
    return render_template_string(BLOCK_PAGE_HTML, host=host), 451

def start_block_server():
    th = threading.Thread(
        target=lambda: blockapp.run(host=HOST, port=BLOCK_PORT, debug=False, use_reloader=False),
        daemon=True
    )
    th.start()





def _pick_data_home():
    candidates = [
        "/var/lib/netdash",
        os.path.join(os.path.expanduser("~"), ".local", "share", "netdash"),
        "/tmp/netdash",
        os.getcwd(),
    ]
    for d in candidates:
        try:
            os.makedirs(d, exist_ok=True)
            testfile = os.path.join(d, ".wtest")
            with open(testfile, "w") as f:
                f.write("ok")
            os.remove(testfile)
            return d
        except Exception:
            continue
    return os.getcwd()

DATA_HOME = _pick_data_home()
FILTERS_FILE = os.path.join(DATA_HOME, "filters.json")
HISTORY_FILE = os.path.join(DATA_HOME, "history.json")
TOTALS_FILE  = os.path.join(DATA_HOME, "totals.json")
PERIOD_FILE  = os.path.join(DATA_HOME, "period_totals.json")

# ------------------ Helpers ------------------
def _run_ip_json(args):
    """Call `ip -json` and parse the JSON; return [] on failure."""
    try:
        out = subprocess.check_output(["ip"] + args, text=True)
        return json.loads(out)
    except Exception:
        return []

def can_control(iface: str) -> bool:
    if not CONTROL_ENABLED or not iface:
        return False
    if ALLOW_IFACES:
        return iface in ALLOW_IFACES
    if iface in DENY_IFACES:
        return False
    return True

def _read_file(path, to_int=False):
    try:
        with open(path, "r") as f:
            s = f.read().strip()
        return int(s) if to_int else s
    except Exception:
        return None

def _link_info_sysfs(iface):
    spd = _read_file(f"/sys/class/net/{iface}/speed", to_int=True)
    dup = _read_file(f"/sys/class/net/{iface}/duplex")
    if isinstance(spd, int) and spd < 0:
        spd = None
    if dup:
        dup = dup.lower()
    return spd, dup

def _link_info_ethtool(iface):
    try:
        out = subprocess.check_output(["ethtool", iface], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None, None
    m = re.search(r"Speed:\s*([0-9]+)\s*Mb/s", out)
    spd = int(m.group(1)) if m else None
    m = re.search(r"Duplex:\s*([A-Za-z!]+)", out)
    dup = m.group(1).replace("!", "").lower() if m else None
    if dup == "unknown":
        dup = None
    return spd, dup

def get_link_info(iface):
    spd, dup = _link_info_sysfs(iface)
    if spd is None and dup is None:
        es, ed = _link_info_ethtool(iface)
        if spd is None:
            spd = es
        if dup is None:
            dup = ed
    return {"speed": spd, "duplex": dup}

def get_interfaces_info():
    links = _run_ip_json(["-json", "link"])
    addrs = _run_ip_json(["-json", "addr"])
    by_index = {item.get("ifindex"): item for item in links}
    result = []
    for item in addrs:
        idx = item.get("ifindex")
        li = by_index.get(idx, {})
        name = item.get("ifname") or li.get("ifname")
        if not name:
            continue
        flags = li.get("flags") or item.get("flags", [])
        state = (li.get("operstate") or item.get("operstate") or "").upper()
        mtu = li.get("mtu") or item.get("mtu")
        mac = li.get("address") if li.get("link_type") != "none" else None
        info_kind = None
        try:
            info_kind = (li.get("linkinfo") or {}).get("info_kind")
        except Exception:
            info_kind = None
        is_up = ("UP" in (flags or [])) or (state == "UP")
        addresses = []
        for a in item.get("addr_info", []):
            fam = a.get("family")
            local = a.get("local")
            prefix = a.get("prefixlen")
            scope = a.get("scope")
            if local is not None and prefix is not None:
                addresses.append({"family": fam, "cidr": f"{local}/{prefix}", "scope": scope})
        result.append({
            "name": name, "ifindex": idx, "state": state or "UNKNOWN", "flags": flags or [],
            "mtu": mtu, "mac": mac, "addresses": addresses,
            "can_control": can_control(name), "is_up": is_up,
            "link": get_link_info(name) if name else {"speed": None, "duplex": None},
            "shape": tc_status(name),
            "shape": tc_status(name),
            "kind": info_kind,
        })
    # include links without addresses
    for idx, li in by_index.items():
        name = li.get("ifname")
        if not name or any(r["ifindex"] == idx for r in result):
            continue
        flags = li.get("flags", [])
        state = (li.get("operstate") or "").upper()
        info_kind = None
        try:
            info_kind = (li.get("linkinfo") or {}).get("info_kind")
        except Exception:
            info_kind = None
        is_up = ("UP" in (flags or [])) or (state == "UP")
        result.append({
            "name": name, "ifindex": idx, "state": state or "UNKNOWN", "flags": flags,
            "mtu": li.get("mtu"), "mac": li.get("address"), "addresses": [],
            "can_control": can_control(name), "is_up": is_up,
            "link": get_link_info(name) if name else {"speed": None, "duplex": None},
            "shape": tc_status(name),
            "kind": info_kind,
        })
    result.sort(key=lambda x: x["ifindex"] or 10**9)
    return result

def list_ifaces_fs():
    try:
        return [d for d in os.listdir("/sys/class/net") if os.path.isdir(os.path.join("/sys/class/net", d))]
    except Exception:
        return []

def read_counters(iface):
    base = f"/sys/class/net/{iface}/statistics"
    def read_one(fname):
        try:
            with open(os.path.join(base, fname), "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0
    return read_one("rx_bytes"), read_one("tx_bytes")

# ------------------ Stores ------------------
class HistoryStore:
    def __init__(self, filepath, max_points=120):
        self.filepath = filepath
        self.max_points = max_points
        self.hist = defaultdict(lambda: deque(maxlen=self.max_points))
        self.lock = threading.Lock()
        self._last_flush = 0.0
        self.flush_interval = 5.0

    def add(self, iface, ts, rx_bps, tx_bps):
        with self.lock:
            self.hist[iface].append((float(ts), float(rx_bps), float(tx_bps)))

    def export(self):
        with self.lock:
            out = {}
            for iface, dq in self.hist.items():
                ts_list = [t for (t, _, _) in dq]
                rx_mbps = [ (rb*8.0)/1e6 for (_, rb, _) in dq ]
                tx_mbps = [ (tb*8.0)/1e6 for (_, _, tb) in dq ]
                out[iface] = {"ts": ts_list, "rx_mbps": rx_mbps, "tx_mbps": tx_mbps}
            return out

    def flush(self, force=False):
        now = time.time()
        if not force and (now - self._last_flush) < self.flush_interval:
            return
        with self.lock:
            data = {iface: list(dq) for iface, dq in self.hist.items()}
        try:
            tmp = self.filepath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"v":1, "max_points": self.max_points, "data": data}, f)
            os.replace(tmp, self.filepath)
            self._last_flush = now
        except Exception:
            pass

    def load(self):
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                obj = json.load(f)
            maxp = int(obj.get("max_points", self.max_points))
            self.max_points = maxp
            raw = obj.get("data", {})
            with self.lock:
                self.hist.clear()
                for iface, arr in raw.items():
                    dq = deque(maxlen=self.max_points)
                    for tup in arr:
                        if isinstance(tup, list) and len(tup) >= 3:
                            dq.append( (float(tup[0]), float(tup[1]), float(tup[2])) )
                    self.hist[iface] = dq
        except Exception:
            pass

history = HistoryStore(HISTORY_FILE, MAX_POINTS)
history.load()

class TotalsStore:
    def __init__(self, filepath):
        self.filepath = filepath
        self.ifaces = {}
        self.lock = threading.Lock()
        self._last_flush = 0.0
        self.flush_interval = 5.0
        self.load()

    def load(self):
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                obj = json.load(f)
            self.ifaces = obj.get("ifaces", {})
        except Exception:
            self.ifaces = {}

    def flush(self, force=False):
        now = time.time()
        if not force and (now - self._last_flush) < self.flush_interval:
            return
        with self.lock:
            data = {"v":1, "ifaces": self.ifaces}
        try:
            tmp = self.filepath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.filepath)
            self._last_flush = now
        except Exception:
            pass

    def update(self, name, rx_bytes_now, tx_bytes_now):
        with self.lock:
            rec = self.ifaces.get(name) or {"rx_total": 0.0, "tx_total": 0.0, "last_rx": None, "last_tx": None, "t": 0}
            if rec["last_rx"] is None:
                rec["last_rx"] = int(rx_bytes_now)
            else:
                if rx_bytes_now >= rec["last_rx"]:
                    rec["rx_total"] += (rx_bytes_now - rec["last_rx"])
                else:
                    rec["rx_total"] += rx_bytes_now
                rec["last_rx"] = int(rx_bytes_now)
            if rec["last_tx"] is None:
                rec["last_tx"] = int(tx_bytes_now)
            else:
                if tx_bytes_now >= rec["last_tx"]:
                    rec["tx_total"] += (tx_bytes_now - rec["last_tx"])
                else:
                    rec["tx_total"] += tx_bytes_now
                rec["last_tx"] = int(tx_bytes_now)
            rec["t"] = time.time()
            self.ifaces[name] = rec
            return rec["rx_total"], rec["tx_total"]

totals = TotalsStore(TOTALS_FILE)

class PeriodStore:
    """Aggregates delta bytes into daily (YYYY-MM-DD) and monthly (YYYY-MM) buckets."""
    def __init__(self, filepath):
        self.filepath = filepath
        self.days = {}
        self.months = {}
        self.lock = threading.Lock()
        self._last_flush = 0.0
        self.flush_interval = 5.0
        self.load()

    def load(self):
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                obj = json.load(f)
            self.days = obj.get("days", {})
            self.months = obj.get("months", {})
        except Exception:
            self.days, self.months = {}, {}

    def flush(self, force=False):
        now = time.time()
        if not force and (now - self._last_flush) < self.flush_interval:
            return
        with self.lock:
            data = {"v":1, "days": self.days, "months": self.months}
        try:
            tmp = self.filepath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.filepath)
            self._last_flush = now
        except Exception:
            pass

    def update(self, name, delta_rx, delta_tx, t=None):
        if t is None:
            t = time.time()
        day = time.strftime("%Y-%m-%d", time.localtime(t))
        mon = time.strftime("%Y-%m", time.localtime(t))
        with self.lock:
            d = self.days.setdefault(day, {})
            m = self.months.setdefault(mon, {})
            di = d.setdefault(name, {"rx": 0, "tx": 0})
            mi = m.setdefault(name, {"rx": 0, "tx": 0})
            di["rx"] += int(max(0, delta_rx))
            di["tx"] += int(max(0, delta_tx))
            mi["rx"] += int(max(0, delta_rx))
            mi["tx"] += int(max(0, delta_tx))

    def get_scope(self, scope):
        with self.lock:
            if scope == "daily":
                key = time.strftime("%Y-%m-%d", time.localtime())
                data = self.days.get(key, {})
            else:
                key = time.strftime("%Y-%m", time.localtime())
                data = self.months.get(key, {})
            return key, data

periods = PeriodStore(PERIOD_FILE)

# ------------------ Monitor ------------------
class NetMonitor:
    def __init__(self, poll_interval=1.0):
        self.poll = poll_interval
        self.prev = {}
        self.data = {}
        self.lock = threading.Lock()
        self.running = False

    def _loop(self):
        while self.running:
            now = time.time()
            ifaces = list_ifaces_fs()
            with self.lock:
                for iface in ifaces:
                    rx, tx = read_counters(iface)
                    old = self.prev.get(iface)
                    if old:
                        rx0, tx0, t0 = old
                        dt = max(1e-6, now - t0)
                        rx_bps = max(0.0, (rx - rx0) / dt)
                        tx_bps = max(0.0, (tx - tx0) / dt)
                        delta_rx = (rx - rx0) if rx >= rx0 else rx
                        delta_tx = (tx - tx0) if tx >= tx0 else tx
                    else:
                        rx_bps = tx_bps = 0.0
                        delta_rx = delta_tx = 0
                    self.prev[iface] = (rx, tx, now)

                    rx_total, tx_total = totals.update(iface, rx, tx)

                    self.data[iface] = {
                        "rx_bps": rx_bps, "tx_bps": tx_bps,
                        "rx_bytes": rx, "tx_bytes": tx,
                        "rx_total": rx_total, "tx_total": tx_total,
                        "ts": now
                    }
                    history.add(iface, now, rx_bps, tx_bps)
                    periods.update(iface, delta_rx, delta_tx, now)
            history.flush()
            totals.flush()
            periods.flush()
            time.sleep(self.poll)

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def snapshot(self):
        with self.lock:
            return {"ts": time.time(), "rates": dict(self.data)}

monitor = NetMonitor(POLL_INTERVAL)
monitor.start()
start_block_server()

# ------------------ Controls ------------------
def _find_ip_binary():
    for p in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "ip"):
        if os.path.isabs(p) and os.path.exists(p):
            return p
    return "ip"

def _require_token():
    if CONTROL_TOKEN:
        tok = request.headers.get("X-Auth-Token", "")
        if tok != CONTROL_TOKEN:
            abort(401, description="Invalid token")

def iface_action(iface: str, action: str):
    if not can_control(iface):
        abort(403, description="Interface not permitted")
    _require_token()
    ipbin = _find_ip_binary()
    cmd = [ipbin, "link", "set", "dev", iface, "down" if action == "down" else "up"]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.2)
        return {"ok": True, "iface": iface, "action": action}
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": f"ip failed ({e})", "iface": iface, "action": action}, 500


# ------------------ Ping Monitor ------------------
class PingMonitor:
    def __init__(self, targets=None, interval=5.0, window=50, timeout=1.2):
        if targets is None:
            env = os.environ.get("NETDASH_PING_TARGETS", "1.1.1.1,8.8.8.8,9.9.9.9")
            targets = [t.strip() for t in env.split(",") if t.strip()]
        self.targets = targets
        self.interval = float(os.environ.get("NETDASH_PING_INTERVAL", str(interval)))
        self.window = int(os.environ.get("NETDASH_PING_WINDOW", str(window)))
        self.timeout = timeout
        self.stats = {t: {"rtt": deque(maxlen=self.window), "sent": 0, "recv": 0, "last": None} for t in self.targets}
        self.lock = threading.Lock()
        self.running = False

    def _ping_once(self, target):
        try:
            # -n numeric, -c 1 count, -W timeout(sec) on busybox; on iputils new it's -w deadline(sec)
            # We'll try -c 1 -w and fallback to -W.
            cmd = ["ping", "-n", "-c", "1", "-w", "1", target]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=self.timeout)
            except subprocess.CalledProcessError as e:
                out = e.output or ""
            except subprocess.TimeoutExpired:
                return None  # timeout
            m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", out)
            if m:
                return float(m.group(1))
            return None
        except Exception:
            return None

    def _loop(self):
        while self.running:
            with self.lock:
                targets = list(self.targets)
            for t in targets:
                rtt = self._ping_once(t)
                with self.lock:
                    st = self.stats[t]
                    st["sent"] += 1
                    st["last"] = time.time()
                    if rtt is not None:
                        st["recv"] += 1
                        st["rtt"].append(float(rtt))
            time.sleep(self.interval)

    def start(self):
        if self.running: return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def snapshot(self):
        out = {}
        with self.lock:
            for t, st in self.stats.items():
                arr = list(st["rtt"])
                avg = sum(arr)/len(arr) if arr else 0.0
                p95 = sorted(arr)[int(0.95*(len(arr)-1))] if arr else 0.0
                mx = max(arr) if arr else 0.0
                loss = 0.0
                if st["sent"] > 0:
                    loss = max(0.0, 100.0 * (1.0 - (st["recv"]/st["sent"])))
                out[t] = {"avg": avg, "p95": p95, "max": mx, "loss": loss, "n": len(arr)}
        return out

pingmon = PingMonitor()
pingmon.start()

# ------------------ Traffic Shaping (tc) ------------------

# ------------------ Address Filters (iptables) ------------------
def _iptables_bin(ipv6=False):
    candidates = ("/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables", "iptables") if not ipv6 else \
                 ("/usr/sbin/ip6tables", "/sbin/ip6tables", "/usr/bin/ip6tables", "ip6tables")
    for p in candidates:
        if os.path.isabs(p) and os.path.exists(p):
            return p
    return candidates[-1]

def _sudo_wrap(cmd):
    if os.geteuid() != 0:
        return ["sudo","-n"] + cmd
    return cmd

def _is_ip_or_cidr(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except Exception:
        try:
            ipaddress.ip_address(s)
            return True
        except Exception:
            return False

def _split_family(s):
    """return ('v4'|'v6'|None) for a single IP or CIDR; None for domain."""
    try:
        net = ipaddress.ip_network(s, strict=False)
        return 'v6' if net.version == 6 else 'v4'
    except Exception:
        try:
            addr = ipaddress.ip_address(s)
            return 'v6' if addr.version == 6 else 'v4'
        except Exception:
            return None

def _resolve_domain(name):
    v4, v6 = set(), set()
    try:
        infos = socket.getaddrinfo(name, None)
        for fam, _, _, _, sockaddr in infos:
            if fam == socket.AF_INET:
                v4.add(sockaddr[0])
            elif fam == socket.AF_INET6:
                v6.add(sockaddr[0])
    except Exception:
        pass
    return list(v4), list(v6)

def _mk_rule_cmds(dst_ip, chain, iface=None, proto="all", port=None, ipv6=False):
    """
    Build iptables/ip6tables -I commands to DROP traffic to dst_ip.
    Applies to OUTPUT (local) و FORWARD (روتر). اگر iface باشد، -o iface می‌گیرد.
    """
    binp = _iptables_bin(ipv6)
    base = [binp, "-I", chain]
    if iface:
        base += ["-o", iface]
    if proto and proto.lower() != "all":
        base += ["-p", proto.lower()]
        if port and str(port).isdigit():
            base += ["--dport", str(int(port))]
    base += ["-d", str(dst_ip), "-j", "DROP"]
    return _sudo_wrap(base)

def _del_equivalent(cmd):
    """convert a built -I rule to -D for deletion"""
    out = cmd[:]
    try:
        i = out.index("-I")
        out[i] = "-D"
    except ValueError:
        # fallback: if نبود، همان را با -D در اول جایگزین می‌کنیم
        out = [out[0], "-D"] + out[2:]
    return out



def _chk_equivalent(cmd):
    """یک دستور -I را به -C تبدیل می‌کند تا وجود قانون بررسی شود"""
    out = cmd[:]
    try:
        i = out.index("-I")
        out[i] = "-C"
    except ValueError:
        out = [out[0], "-C"] + out[2:]
    return out


def _mk_nat_redirect_http_cmd(dst_ip, chain, ipv6=False):
    """
    -t nat REDIRECT traffic destined to dst_ip:80 toward local BLOCK_PORT.
    chain: "OUTPUT" (local) یا "PREROUTING" (ترافیک عبوری/روتر)
    """
    binp = _iptables_bin(ipv6)
    base = [binp, "-t", "nat", "-I", chain, "-p", "tcp", "-d", str(dst_ip), "--dport", "80",
            "-j", "REDIRECT", "--to-ports", str(BLOCK_PORT)]
    return _sudo_wrap(base)

def _apply_nat_redirect(dst, chain, ipv6):
    cmd = _mk_nat_redirect_http_cmd(dst, chain, ipv6=ipv6)
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"cmd": cmd, "chain": chain, "ipv6": bool(ipv6)}
    except subprocess.CalledProcessError:
        return None



class FilterStore:
    """
    ذخیره و اعمال قوانین بلاک آدرس.
    هر آیتم: {
      id, pattern, iface, proto, port, created,
      realized: {v4:[], v6:[]},
      rules: [{cmd:list, chain:str, ipv6:bool}],
      show_page: bool
    }
    """
    def __init__(self, path):
        self.path = path
        self.items = {}
        self.lock = threading.Lock()
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            raw_items = obj.get("items", {})
        except Exception:
            raw_items = {}

        # نرمال‌سازی: همیشه دیکشنری با کلید id داشته باشیم
        items = {}
        if isinstance(raw_items, list):
            for it in raw_items:
                rid = (it or {}).get("id") or uuid.uuid4().hex[:12]
                it["id"] = rid
                items[rid] = it
        elif isinstance(raw_items, dict):
            for k, v in (raw_items or {}).items():
                rid = (v or {}).get("id") or str(k)
                v["id"] = rid
                items[rid] = v
        else:
            items = {}

        with self.lock:
            self.items = items

        # ری‌استور قوانین به iptables/ip6tables
        for rec in list(items.values()):
            for r in rec.get("rules", []):
                cmd = r.get("cmd") or []
                if not cmd or not isinstance(cmd, list):
                    continue
                try:
                    chk = _chk_equivalent(cmd)
                    subprocess.check_call(chk, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    continue  # قانون هست
                except subprocess.CalledProcessError:
                    pass
                try:
                    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    # fallback: بدون sudo
                    try:
                        base = [c for c in cmd if c not in ("sudo", "-n")]
                        subprocess.check_call(base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except Exception:
                        pass

    def flush(self):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"v": 1, "items": self.items}, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def list(self):
        with self.lock:
            return list(self.items.values())

    def _apply_one(self, dst, iface, proto, port, chain, ipv6):
        cmd = _mk_rule_cmds(dst, chain, iface=iface, proto=proto, port=port, ipv6=ipv6)
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {"cmd": cmd, "chain": chain, "ipv6": bool(ipv6)}
        except subprocess.CalledProcessError:
            return None

    def add(self, pattern, iface=None, proto="all", port=None, show_page=False):
        # تعیین لیست IPها
        fam = _split_family(pattern)
        if fam is None:
            v4, v6 = _resolve_domain(pattern)
        elif fam == 'v4':
            v4, v6 = [pattern], []
        else:
            v4, v6 = [], [pattern]

        if not v4 and not v6:
            raise ValueError("آدرس/دامنه قابل resolved نیست یا نامعتبر است.")

        fid = uuid.uuid4().hex[:12]
        rules = []
        chains = ["OUTPUT", "FORWARD"]  # هم محلی، هم مسیریابی

        # DROP فیلتر
        for ip in v4:
            for ch in chains:
                r = self._apply_one(ip, iface, proto, port, ch, ipv6=False)
                if r: rules.append(r)
        for ip in v6:
            for ch in chains:
                r = self._apply_one(ip, iface, proto, port, ch, ipv6=True)
                if r: rules.append(r)

        # ریدایرکت صفحه مسدودسازی (HTTP/80) به BLOCK_PORT
        if show_page:
            for ip in v4:
                for ch in ("OUTPUT", "PREROUTING"):
                    r = _apply_nat_redirect(ip, ch, ipv6=False)
                    if r: rules.append(r)
            for ip in v6:
                for ch in ("OUTPUT", "PREROUTING"):
                    r = _apply_nat_redirect(ip, ch, ipv6=True)
                    if r: rules.append(r)

        if not rules:
            raise RuntimeError("هیچ قانون iptables/ip6tables اعمال نشد.")

        rec = {
            "id": fid,
            "pattern": pattern,
            "iface": iface or None,
            "proto": (proto or "all").lower(),
            "port": (int(port) if port else None),
            "created": int(time.time()),
            "realized": {"v4": v4, "v6": v6},
            "rules": rules,
            "show_page": bool(show_page),
        }
        with self.lock:
            self.items[fid] = rec
            self.flush()
        return rec

    def remove(self, fid):
        with self.lock:
            rec = self.items.get(fid)
            if not rec:
                # فالس‌بک: اگر کلید dict با id یکی نیست، روی مقدارها جست‌وجو کن
                for k, v in list(self.items.items()):
                    if (v or {}).get("id") == fid:
                        fid, rec = k, v
                        break
            if not rec:
                return False

            # حذف هر قانون مرتبط (DROP و NAT) — هم با sudo و هم بدون sudo امتحان کن
            for r in rec.get("rules", []):
                cmd = r.get("cmd") or []
                dcmd = _del_equivalent(cmd)
                try:
                    subprocess.check_call(dcmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    # fallback 1: اگر sudo نبود، اضافه کن
                    try:
                        if "sudo" not in dcmd:
                            alt = ["sudo", "-n"] + dcmd
                            subprocess.check_call(alt, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            continue
                    except subprocess.CalledProcessError:
                        pass
                    # fallback 2: اگر sudo هست، بدون sudo هم تست کن
                    try:
                        base = [c for c in dcmd if c not in ("sudo", "-n")]
                        subprocess.check_call(base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except subprocess.CalledProcessError:
                        # نهایتاً رهایش کن (ممکنه قبلاً حذف شده باشه)
                        pass

            self.items.pop(fid, None)
            self.flush()
            return True




    def add(self, pattern, iface=None, proto="all", port=None, show_page=False):
        # تعیین لیست IP ها
        fam = _split_family(pattern)
        if fam is None:
            # domain → resolve
            v4, v6 = _resolve_domain(pattern)
        elif fam == 'v4':
            v4, v6 = [pattern], []
        else:
            v4, v6 = [], [pattern]

        if not v4 and not v6:
            raise ValueError("آدرس/دامنه قابل resolved نیست یا نامعتبر است.")

        fid = uuid.uuid4().hex[:12]
        rules = []
        chains = ["OUTPUT", "FORWARD"]  # هم محلی، هم مسیریابی

        # v4 → قوانین فیلتر (DROP)
        for ip in v4:
            for ch in chains:
                r = self._apply_one(ip, iface, proto, port, ch, ipv6=False)
                if r: rules.append(r)

        # v6 → قوانین فیلتر (DROP)
        for ip in v6:
            for ch in chains:
                r = self._apply_one(ip, iface, proto, port, ch, ipv6=True)
                if r: rules.append(r)

        # 🔽🔽🔽 اینجا قطعه‌ی نمایش صفحه را اضافه کن 🔽🔽🔽
        if show_page:
            # برای HTTP (پورت 80) ریدایرکت به BLOCK_PORT؛ هم برای ترافیک لوکال (OUTPUT) و هم عبوری (PREROUTING)
            for ip in v4:
                for ch in ("OUTPUT", "PREROUTING"):
                    r = _apply_nat_redirect(ip, ch, ipv6=False)
                    if r: rules.append(r)
            for ip in v6:
                for ch in ("OUTPUT", "PREROUTING"):
                    r = _apply_nat_redirect(ip, ch, ipv6=True)
                    if r: rules.append(r)
        # 🔼🔼🔼

        if not rules:
            raise RuntimeError("هیچ قانون iptables/ip6tables اعمال نشد.")

        rec = {
            "id": fid,
            "pattern": pattern,
            "iface": iface or None,
            "proto": (proto or "all").lower(),
            "port": (int(port) if port else None),
            "created": int(time.time()),
            "realized": {"v4": v4, "v6": v6},
            "rules": rules,
            "show_page": bool(show_page),
        }
        with self.lock:
            self.items[fid] = rec
            self.flush()
        return rec

filters = FilterStore(FILTERS_FILE)

#mohamamd#
def _tc_bin():
    for p in ("/sbin/tc","/usr/sbin/tc","/usr/bin/tc","tc"):
        if os.path.isabs(p) and os.path.exists(p):
            return p
    return "tc"

def tc_status(iface):
    try:
        out = subprocess.check_output([_tc_bin(), "qdisc", "show", "dev", iface], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return {"active": False, "algo": None, "rate_mbit": None}
    if " tbf " in out or out.strip().startswith("qdisc tbf"):
        m = re.search(r"rate\s+([0-9.]+)Mbit", out)
        rate = float(m.group(1)) if m else None
        return {"active": True, "algo": "tbf", "rate_mbit": rate}
    return {"active": False, "algo": None, "rate_mbit": None}

def tc_limit(iface, rate_mbit, burst_kbit=32, latency_ms=400):
    cmd = [_tc_bin(), "qdisc", "replace", "dev", iface, "root",
           "tbf", "rate", f"{float(rate_mbit)}mbit",
           "burst", f"{int(burst_kbit)}kbit",
           "latency", f"{int(latency_ms)}ms"]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def tc_clear(iface):
    cmd = [_tc_bin(), "qdisc", "del", "dev", iface, "root"]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass

# ------------------ UI ------------------
HTML = r"""
<!doctype html>
<html lang="fa" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetDash - داشبورد ترافیک شبکه</title>
  <script src="https://cdn.tailwindcss.com">
// === Keep pause/resume button next to status badges ===
(function(){
  function placeCtrlNextToState(card){
    try{
      const ctrl = card.querySelector('.ctrl-btn');
      if(!ctrl) return;
      // likely row for badges:
      const badgeRow = card.querySelector('.badge.state')?.parentElement;
      if(!badgeRow) return;
      const states = card.querySelectorAll('.badge.state');
      if(!states.length) return;
      const last = states[states.length-1];
      if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
        if (ctrl.parentElement && ctrl.parentElement !== badgeRow){
          try{ ctrl.parentElement.removeChild(ctrl); }catch{}
        }
        badgeRow.insertBefore(ctrl, last.nextSibling);
        ctrl.classList.add('badge-btn','shrink-0');
      }
    }catch(e){}
  }
  function placeAll(){ document.querySelectorAll('.card').forEach(placeCtrlNextToState); }
  window.addEventListener('load', placeAll);
  })();


// === Keep shape (محدودیت) button next to status badges and color it red ===
(function(){
  function placeShapeNextToState(card){
    try{
      const shape = card.querySelector('.shape-btn');
      if(!shape) return;
      const badgeRow = card.querySelector('.badge.state')?.parentElement;
      if(!badgeRow) return;
      const states = card.querySelectorAll('.badge.state');
      if(!states.length) return;
      const last = states[states.length-1];
      // place right after last state
      if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
        if (shape.parentElement && shape.parentElement !== badgeRow){
          try{ shape.parentElement.removeChild(shape); }catch{}
        }
        badgeRow.insertBefore(shape, last.nextSibling);
        shape.classList.add('badge-btn','shrink-0');
      }
      // enforce red/white style regardless of class toggling
      shape.classList.add('b-shape'); // ensure one of the classes is present
      shape.classList.remove('b-warn'); // remove old yellow if present
    }catch(e){}
  }
  function placeAll(){ document.querySelectorAll('.card').forEach(placeShapeNextToState); }
  window.addEventListener('load', placeAll);
  })();


// === NetDash helper: place control & shape buttons next to status badges (one-shot; called on load & after render) ===
function NetdashPlaceButtons(){
  try{
    document.querySelectorAll('.card').forEach(card => {
      // ctrl-btn
      try{
        const ctrl = card.querySelector('.ctrl-btn');
        const badgeRow = card.querySelector('.badge.state')?.parentElement;
        const states = card.querySelectorAll('.badge.state');
        if (ctrl && badgeRow && states.length){
          const last = states[states.length-1];
          if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
            if (ctrl.parentElement && ctrl.parentElement !== badgeRow){
              try{ ctrl.parentElement.removeChild(ctrl); }catch{}
            }
            badgeRow.insertBefore(ctrl, last.nextSibling);
            ctrl.classList.add('badge-btn','shrink-0');
          }
        }
      }catch(e){ console.error('ctrl-btn move error', e); }
      // shape-btn
      try{
        const shape = card.querySelector('.shape-btn');
        const badgeRow = card.querySelector('.badge.state')?.parentElement;
        const states = card.querySelectorAll('.badge.state');
        if (shape && badgeRow && states.length){
          const last = states[states.length-1];
          if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
            if (shape.parentElement && shape.parentElement !== badgeRow){
              try{ shape.parentElement.removeChild(shape); }catch{}
            }
            badgeRow.insertBefore(shape, last.nextSibling);
            shape.classList.add('badge-btn','shrink-0');
          }
          // force red/white style
          shape.classList.add('b-shape');
          shape.classList.remove('b-warn');
        }
      }catch(e){ console.error('shape-btn move error', e); }
    });
  }catch(e){}
}
window.addEventListener('load', NetdashPlaceButtons);
window.addEventListener('load', initStatWindowSelector);

</script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: { extend: { fontFamily: { sans: ['Vazirmatn', 'Inter', 'ui-sans-serif', 'system-ui'] } } }
    }
  
// === Keep pause/resume button next to status badges ===
(function(){
  function placeCtrlNextToState(card){
    try{
      const ctrl = card.querySelector('.ctrl-btn');
      if(!ctrl) return;
      // likely row for badges:
      const badgeRow = card.querySelector('.badge.state')?.parentElement;
      if(!badgeRow) return;
      const states = card.querySelectorAll('.badge.state');
      if(!states.length) return;
      const last = states[states.length-1];
      if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
        if (ctrl.parentElement && ctrl.parentElement !== badgeRow){
          try{ ctrl.parentElement.removeChild(ctrl); }catch{}
        }
        badgeRow.insertBefore(ctrl, last.nextSibling);
        ctrl.classList.add('badge-btn','shrink-0');
      }
    }catch(e){}
  }
  function placeAll(){ document.querySelectorAll('.card').forEach(placeCtrlNextToState); }
  window.addEventListener('load', placeAll);
  })();


// === Keep shape (محدودیت) button next to status badges and color it red ===
(function(){
  function placeShapeNextToState(card){
    try{
      const shape = card.querySelector('.shape-btn');
      if(!shape) return;
      const badgeRow = card.querySelector('.badge.state')?.parentElement;
      if(!badgeRow) return;
      const states = card.querySelectorAll('.badge.state');
      if(!states.length) return;
      const last = states[states.length-1];
      // place right after last state
      if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
        if (shape.parentElement && shape.parentElement !== badgeRow){
          try{ shape.parentElement.removeChild(shape); }catch{}
        }
        badgeRow.insertBefore(shape, last.nextSibling);
        shape.classList.add('badge-btn','shrink-0');
      }
      // enforce red/white style regardless of class toggling
      shape.classList.add('b-shape'); // ensure one of the classes is present
      shape.classList.remove('b-warn'); // remove old yellow if present
    }catch(e){}
  }
  function placeAll(){ document.querySelectorAll('.card').forEach(placeShapeNextToState); }
  window.addEventListener('load', placeAll);
  })();


// === NetDash helper: place control & shape buttons next to status badges (one-shot; called on load & after render) ===
function NetdashPlaceButtons(){
  try{
    document.querySelectorAll('.card').forEach(card => {
      // ctrl-btn
      try{
        const ctrl = card.querySelector('.ctrl-btn');
        const badgeRow = card.querySelector('.badge.state')?.parentElement;
        const states = card.querySelectorAll('.badge.state');
        if (ctrl && badgeRow && states.length){
          const last = states[states.length-1];
          if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
            if (ctrl.parentElement && ctrl.parentElement !== badgeRow){
              try{ ctrl.parentElement.removeChild(ctrl); }catch{}
            }
            badgeRow.insertBefore(ctrl, last.nextSibling);
            ctrl.classList.add('badge-btn','shrink-0');
          }
        }
      }catch(e){ console.error('ctrl-btn move error', e); }
      // shape-btn
      try{
        const shape = card.querySelector('.shape-btn');
        const badgeRow = card.querySelector('.badge.state')?.parentElement;
        const states = card.querySelectorAll('.badge.state');
        if (shape && badgeRow && states.length){
          const last = states[states.length-1];
          if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
            if (shape.parentElement && shape.parentElement !== badgeRow){
              try{ shape.parentElement.removeChild(shape); }catch{}
            }
            badgeRow.insertBefore(shape, last.nextSibling);
            shape.classList.add('badge-btn','shrink-0');
          }
          // force red/white style
          shape.classList.add('b-shape');
          shape.classList.remove('b-warn');
        }
      }catch(e){ console.error('shape-btn move error', e); }
    });
  }catch(e){}
}
window.addEventListener('load', NetdashPlaceButtons);
window.addEventListener('load', initStatWindowSelector);

</script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js">
// === Keep pause/resume button next to status badges ===
(function(){
  function placeCtrlNextToState(card){
    try{
      const ctrl = card.querySelector('.ctrl-btn');
      if(!ctrl) return;
      // likely row for badges:
      const badgeRow = card.querySelector('.badge.state')?.parentElement;
      if(!badgeRow) return;
      const states = card.querySelectorAll('.badge.state');
      if(!states.length) return;
      const last = states[states.length-1];
      if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
        if (ctrl.parentElement && ctrl.parentElement !== badgeRow){
          try{ ctrl.parentElement.removeChild(ctrl); }catch{}
        }
        badgeRow.insertBefore(ctrl, last.nextSibling);
        ctrl.classList.add('badge-btn','shrink-0');
      }
    }catch(e){}
  }
  function placeAll(){ document.querySelectorAll('.card').forEach(placeCtrlNextToState); }
  window.addEventListener('load', placeAll);
  })();


// === Keep shape (محدودیت) button next to status badges and color it red ===
(function(){
  function placeShapeNextToState(card){
    try{
      const shape = card.querySelector('.shape-btn');
      if(!shape) return;
      const badgeRow = card.querySelector('.badge.state')?.parentElement;
      if(!badgeRow) return;
      const states = card.querySelectorAll('.badge.state');
      if(!states.length) return;
      const last = states[states.length-1];
      // place right after last state
      if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
        if (shape.parentElement && shape.parentElement !== badgeRow){
          try{ shape.parentElement.removeChild(shape); }catch{}
        }
        badgeRow.insertBefore(shape, last.nextSibling);
        shape.classList.add('badge-btn','shrink-0');
      }
      // enforce red/white style regardless of class toggling
      shape.classList.add('b-shape'); // ensure one of the classes is present
      shape.classList.remove('b-warn'); // remove old yellow if present
    }catch(e){}
  }
  function placeAll(){ document.querySelectorAll('.card').forEach(placeShapeNextToState); }
  window.addEventListener('load', placeAll);
  })();


// === NetDash helper: place control & shape buttons next to status badges (one-shot; called on load & after render) ===
function NetdashPlaceButtons(){
  try{
    document.querySelectorAll('.card').forEach(card => {
      // ctrl-btn
      try{
        const ctrl = card.querySelector('.ctrl-btn');
        const badgeRow = card.querySelector('.badge.state')?.parentElement;
        const states = card.querySelectorAll('.badge.state');
        if (ctrl && badgeRow && states.length){
          const last = states[states.length-1];
          if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
            if (ctrl.parentElement && ctrl.parentElement !== badgeRow){
              try{ ctrl.parentElement.removeChild(ctrl); }catch{}
            }
            badgeRow.insertBefore(ctrl, last.nextSibling);
            ctrl.classList.add('badge-btn','shrink-0');
          }
        }
      }catch(e){ console.error('ctrl-btn move error', e); }
      // shape-btn
      try{
        const shape = card.querySelector('.shape-btn');
        const badgeRow = card.querySelector('.badge.state')?.parentElement;
        const states = card.querySelectorAll('.badge.state');
        if (shape && badgeRow && states.length){
          const last = states[states.length-1];
          if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
            if (shape.parentElement && shape.parentElement !== badgeRow){
              try{ shape.parentElement.removeChild(shape); }catch{}
            }
            badgeRow.insertBefore(shape, last.nextSibling);
            shape.classList.add('badge-btn','shrink-0');
          }
          // force red/white style
          shape.classList.add('b-shape');
          shape.classList.remove('b-warn');
        }
      }catch(e){ console.error('shape-btn move error', e); }
    });
  }catch(e){}
}
window.addEventListener('load', NetdashPlaceButtons);
window.addEventListener('load', initStatWindowSelector);

</script>
  <style>
    .card { border-radius: 1rem; box-shadow: 0 2px 24px rgba(0,0,0,0.06); border: 1px solid rgba(0,0,0,0.06); }
    .k { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; direction:ltr }
    .badge { display:inline-flex; align-items:center; gap:.4rem; padding:.2rem .5rem; border-radius:999px; font-size:.75rem; font-weight:600; }
    .b-up { background:#d1fae5; color:#065f46; }
    .b-down { background:#fee2e2; color:#991b1b; }
    .b-unk { background:#fde68a; color:#92400e; }
    .badge-btn { cursor:pointer; user-select:none; border: none; }
    .badge-btn:disabled { opacity:.75; cursor:not-allowed; }
    .ltr { direction:ltr }
  .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ltr{direction:ltr}
/* To enable two-line clamp, replace white-space with below:
.name{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;white-space:normal}
*/
.shape-btn{min-width:unset}
.shape-btn.b-warn{background:#fde68a;color:#4b3b05;border:1px solid #f59e0b}
.shape-btn.b-clear{background:#fecaca;color:#7f1d1d;border:1px solid #ef4444}
.b-shape{background:#dbeafe;color:#1e3a8a;border:1px solid #60a5fa}
.b-clear{background:#fecaca;color:#7f1d1d;border:1px solid #ef4444}
.name{white-space:normal !important;overflow-wrap:anywhere;word-break:break-word;text-overflow:clip !important}
.b-shape,.b-clear{background:#ef4444 !important;color:#ffffff !important;border:1px solid #b91c1c !important}
.badge-btn{display:inline-flex;align-items:center;justify-content:center;white-space:nowrap}
</style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-gray-900 dark:text-gray-100">
  <div class="max-w-7xl mx-auto p-4 sm:p-6">
    <div class="flex flex-wrap items-center justify-between gap-3 mb-6">
      <h1 class="text-2xl sm:text-3xl font-extrabold">NetDash</h1>
      <div class="grid grid-cols-[1fr_auto] items-center gap-2">
        <input id="filterInput" class="px-3 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm" placeholder="فیلتر اینترفیس‌ها...">
        <button id="darkBtn" class="px-3 py-2 rounded-xl card bg-white dark:bg-gray-800 text-sm">تیره / روشن</button>
        <select id="scopeSel" class="px-2 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm">
          <option value="daily">روزانه</option>
          <option value="monthly">ماهانه</option>
        </select>
        <select id="statSel" class="px-2 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm" title="پنجره آماری">
          <!-- پر می‌شود با JS براساس MAX_POINTS -->
        </select>
        <button id="reportBtn" class="px-3 py-2 rounded-xl card bg-white dark:bg-gray-800 text-sm">گزارش</button>
      </div>
    </div>

    <div id="summary" class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
      <div class="card p-4 bg-white dark:bg-gray-800">
        <div class="text-sm opacity-70 mb-1">تعداد اینترفیس‌ها</div>
        <div id="sum-ifaces" class="text-2xl font-bold ltr">-</div>
      </div>
      <div class="card p-4 bg-white dark:bg-gray-800">
        <div class="text-sm opacity-70 mb-1">مجموع دانلود (Mbps)</div>
        <div id="sum-rx" class="text-2xl font-bold ltr">-</div>
      </div>
      <div class="card p-4 bg-white dark:bg-gray-800">
        <div class="text-sm opacity-70 mb-1">مجموع آپلود (Mbps)</div>
        <div id="sum-tx" class="text-2xl font-bold ltr">-</div>
      </div>
    </div>

    <div class="card p-4 bg-white dark:bg-gray-800 mb-4">
      <div class="flex items-center justify-between mb-2">
        <div class="font-semibold">تاخیر و از‌دست‌رفت بسته</div>
        <div class="text-xs opacity-70">Targets: <span id="ping-targets" class="k"></span></div>
      </div>
      <div id="ping-chips" class="flex flex-wrap gap-2"></div>
    </div>
    <div class="card p-4 bg-white dark:bg-gray-800 mb-4">
      <div class="flex items-center justify-between mb-3">
        <div class="font-semibold">مسدودسازی آدرس‌ها (بلاک‌لیست)</div>
        <div class="text-xs opacity-70">قوانین سطح سیستم (iptables)</div>
      </div>
    
      <!-- فرم -->
      <div class="grid grid-cols-1 md:grid-cols-5 gap-2 items-end">
        <div>
          <label class="text-xs opacity-70">دامنه یا IP/CIDR</label>
          <input id="flt-pattern" class="px-3 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm w-full" placeholder="مثال: instagram.com یا 203.0.113.0/24">
        </div>
        <div>
          <label class="text-xs opacity-70">اینترفیس (اختیاری)</label>
          <select id="flt-iface" class="px-3 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm w-full">
            <option value="">همه</option>
          </select>
        </div>
        <div>
          <label class="text-xs opacity-70">پروتکل</label>
          <select id="flt-proto" class="px-3 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm w-full">
            <option value="all">all</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select>
        </div>
        <div>
          <label class="text-xs opacity-70">پورت (اختیاری)</label>
          <input id="flt-port" type="number" min="1" max="65535" class="px-3 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm w-full" placeholder="مثال: 443">
        </div>
        <div>
          <button id="flt-add" class="px-3 py-2 rounded-xl card bg-white dark:bg-gray-800 text-sm w-full">افزودن به بلاک‌لیست</button>
        </div>
    
        <!-- چک‌باکس صفحهٔ مسدودسازی -->
        <div class="md:col-span-5 flex items-center gap-2">
          <input id="flt-page" type="checkbox" class="h-4 w-4">
          <label for="flt-page" class="text-sm opacity-80">نمایش صفحهٔ مسدودسازی (فقط HTTP)</label>
        </div>
      </div>
    
      <!-- لیست -->
      <div class="mt-4">
        <div class="text-sm opacity-70 mb-2">موارد مسدود‌شده</div>
        <div class="overflow-auto">
          <table class="min-w-full text-sm">
            <thead>
              <tr class="text-left opacity-70">
                <th class="py-1 pr-4">الگو</th>
                <th class="py-1 pr-4">اینترفیس</th>
                <th class="py-1 pr-4">پروتکل/پورت</th>
                <th class="py-1 pr-4">Resolved</th>
                <th class="py-1 pr-4">عملیات</th>
              </tr>
            </thead>
            <tbody id="flt-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>
          </table>
        </div>
      </div>
    </div>
    <div id="cards" class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4"></div>
  </div>

  <template id="card-template">
    <div class="card p-4 bg-white dark:bg-gray-800 flex flex-col gap-3">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0 flex flex-col gap-1">
          <div class="grid grid-cols-[1fr_auto] items-center gap-2">
            <div class="font-bold text-lg k name truncate flex-1 min-w-0 ltr"></div>
            <button class="ctrl-btn hidden badge badge-btn b-up shrink-0">
              <span class="btn-label">توقف</span>
            </button>
            <button class="shape-btn hidden badge badge-btn b-unk shrink-0"><span class="shape-label">محدودیت</span></button>
          </div>
          <div class="text-xs opacity-80 flags"></div>
          <div class="text-xs opacity-80 meta"></div>
          <div class="text-xs opacity-80 addrs"></div>
          <div class="text-xs opacity-80 linkinfo"></div>
        </div>
        <div class="text-right text-sm">
          <div class="mb-2"><span class="badge state b-unk">نامشخص</span></div>
          <div>دانلود <span class="rx-rate font-semibold ltr">0</span></div>
          <div>آپلود <span class="tx-rate font-semibold ltr">0</span></div>
          <div class="opacity-60 text-[11px] mt-1">تجمعی: دانلود <span class="rx-tot ltr">0</span> | آپلود <span class="tx-tot ltr">0</span></div>
          <div class="opacity-70 text-[11px] mt-1 stats ltr"></div>
          <div class="opacity-70 text-[11px] mt-1 period ltr"></div>
        </div>
      </div>
      <div class="h-36 ltr"><canvas class="chart"></canvas></div>
    </div>
  </template>

  <script>

    // Friendly middle-ellipsis for long interface names
    function shortName(name){
      try{
        const s = String(name||''); 
        const max = 22; // target length
        if (s.length <= max) return s;
        const head = 12, tail = 8;
        return s.slice(0, head) + '…' + s.slice(-tail);
      }catch{ return name; }
    }

    (function ensureChart(){
      if (window.Chart) return;
      function MiniChart(ctx, config){
        this.ctx = ctx; this.data = config.data;
        this.update = function(){
          const c = this.ctx.canvas, w=c.width, h=c.height;
          const g = this.ctx; g.clearRect(0,0,w,h);
          const ds0 = this.data.datasets[0].data.map(Number);
          const ds1 = this.data.datasets[1].data.map(Number);
          const draw = (arr, color)=>{
            if(arr.length<2) return;
            const max = Math.max(1, ...arr);
            g.beginPath(); g.lineWidth = 2; g.strokeStyle = color;
            arr.forEach((v,i)=>{
              const x = i/(arr.length-1) * (w-10) + 5;
              const y = h - (v/max)*(h-10) - 5;
              if(i===0) g.moveTo(x,y); else g.lineTo(x,y);
            });
            g.stroke();
          };
          draw(ds0, "#3b82f6");
          draw(ds1, "#10b981");
        };
      }
      window.Chart = function(ctx, config){ return new MiniChart(ctx, config); };
    })();

    const MAX_POINTS = {{max_points}};
    const CONTROL_TOKEN = {{ token|tojson }};
    const cards = new Map();

let STAT_WINDOW = parseInt(localStorage.getItem('netdash-stat-window') || '60', 10);
if (isNaN(STAT_WINDOW) || STAT_WINDOW <= 0) STAT_WINDOW = Math.min(60, MAX_POINTS);

function initStatWindowSelector(){
  const sel = document.getElementById('statSel');
  if (!sel) return;
  // Build options dynamically from MAX_POINTS
  const opts = [];
  const candidates = [30, 60, 120, 300, 900];
  candidates.forEach(v => { if (v <= MAX_POINTS) opts.push(v); });
  if (!opts.length) opts.push(Math.min(60, MAX_POINTS));
  sel.innerHTML = opts.map(v => {
    const lbl = v>=60 ? (v%60===0 ? (v/60)+'m' : (Math.floor(v/60)+'m'+(v%60)+'s')) : (v+'s');
    return `<option value="${v}">پنجره: ${lbl}</option>`;
  }).join('');
  // select current
  sel.value = String(STAT_WINDOW);
  sel.addEventListener('change', ()=>{
    STAT_WINDOW = parseInt(sel.value,10)||60;
    localStorage.setItem('netdash-stat-window', String(STAT_WINDOW));
    // refresh stats on all cards immediately
    try{ for(const c of cards.values()) updateStatsForCard(c); }catch{}
  });
}

let LAST_PERIOD = {};   // name -> {rx, tx}
let PERIOD_SCOPE = 'daily';  // current selected scope


async function populateFilterIfaces(){
  try{
    const res = await fetch('/api/interfaces',{cache:'no-store'});
    const ifs = await res.json();
    const sel = document.getElementById('flt-iface');
    if(!sel) return;
    const cur = sel.value;
    sel.innerHTML = `<option value="">همه</option>` + ifs.map(x=>`<option value="${x.name}">${x.name}</option>`).join('');
    if (Array.from(sel.options).some(o=>o.value===cur)) sel.value = cur;
  }catch(e){}
}

async function refreshFilters(){
  try{
    const headers = CONTROL_TOKEN ? {"X-Auth-Token": CONTROL_TOKEN} : {};
    const res = await fetch('/api/filters', {headers, cache:'no-store'});
    if(!res.ok){ return; }
    const data = await res.json();
    const tbody = document.getElementById('flt-tbody');
    if(!tbody) return;
    tbody.innerHTML = '';
    for(const it of (data.items||[])){
      const pp = (it.proto||'all') + (it.port? (':'+it.port):'');
      const resolved = []
        .concat((it.realized&&it.realized.v4)||[])
        .concat((it.realized&&it.realized.v6)||[]);
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="py-1 pr-4 k">${it.pattern}</td>
        <td class="py-1 pr-4 k">${it.iface || '—'}</td>
        <td class="py-1 pr-4 k">${pp}</td>
        <td class="py-1 pr-4 k">${resolved.length? resolved.join(', '): '—'}</td>
        <td class="py-1 pr-4">
          <button class="badge badge-btn b-down" data-id="${it.id}">حذف</button>
        </td>`;
      tr.querySelector('button').onclick = async (ev)=>{
        if(!confirm('این مورد از بلاک‌لیست حذف شود؟')) return;
        const id = ev.currentTarget.getAttribute('data-id');
        try{
          const res = await fetch('/api/filters/'+encodeURIComponent(id), {
            method:'DELETE',
            headers: CONTROL_TOKEN ? {"X-Auth-Token": CONTROL_TOKEN} : {}
          });
          if(!res.ok){ alert('حذف نشد'); return; }
          refreshFilters();
        }catch(e){ alert('خطا در حذف: '+e); }
      };
      tbody.appendChild(tr);
    }
  }catch(e){}
}

async function addFilterFromForm(){
  const pattern = document.getElementById('flt-pattern').value.trim();
  const show_page = document.getElementById('flt-page').checked;

  const iface   = document.getElementById('flt-iface').value.trim();
  const proto   = document.getElementById('flt-proto').value.trim() || 'all';
  const portVal = document.getElementById('flt-port').value.trim();
  const port    = portVal ? parseInt(portVal,10) : null;

  if(!pattern){ alert('دامنه یا IP/CIDR را وارد کنید'); return; }
  const btn = document.getElementById('flt-add');
  const old = btn.textContent; btn.textContent='در حال افزودن...'; btn.setAttribute('disabled','disabled');
  try{
    const headers = {"Content-Type":"application/json"};
    if (CONTROL_TOKEN) headers["X-Auth-Token"] = CONTROL_TOKEN;
    const res = await fetch('/api/filters', {
      method:'POST',
      headers,
      body: JSON.stringify({pattern, iface: iface||null, proto, port, show_page})

    });
    if(!res.ok){
      const t = await res.text();
      alert('عدم موفقیت: '+ t);
    } else {
      document.getElementById('flt-pattern').value='';
      document.getElementById('flt-port').value='';
      refreshFilters();
    }
  }catch(e){ alert('خطا: '+e); }
  finally{ btn.textContent=old; btn.removeAttribute('disabled'); }
}

window.addEventListener('load', ()=>{
  try{
    populateFilterIfaces();
    refreshFilters();
    const btn = document.getElementById('flt-add');
    if(btn) btn.addEventListener('click', addFilterFromForm);
    setInterval(populateFilterIfaces, 30000);
    setInterval(refreshFilters, 15000);
  }catch(e){}
});




function applyPeriodToCards(){
  const title = (PERIOD_SCOPE==='daily'?'امروز':'ماه جاری');
  for (const [name, vals] of Object.entries(LAST_PERIOD)){
    const card = cards.get(name);
    if(!card) continue;
    const rx = fmtBytes(vals.rx||0);
    const tx = fmtBytes(vals.tx||0);
    card.el.querySelector('.period').textContent = `${title}: DL ${rx} | UL ${tx}`;
  }
}

    function fmtBytes(x){
      const units = ["B","KB","MB","GB","TB","PB"];
      let i=0, v=Number(x);
      while(v>=1024 && i<units.length-1){ v/=1024; i++; }
      return v.toFixed(v<10?2:1)+" "+units[i];
    }
    function badgeFor(state){
      state = (state||"").toUpperCase();
      if(state==="UP") return {text:"فعال", cls:"badge b-up"};
      if(state==="DOWN") return {text:"پایین", cls:"badge b-down"};
      return {text: "نامشخص", cls:"badge b-unk"};
    }

    function makeChart(canvas){
      const ctx = canvas.getContext('2d');
      return new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [
          { label: 'دانلود', data: [], tension: 0.35, fill: true },
          { label: 'آپلود', data: [], tension: 0.35, fill: true }
        ]},
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: true, position: 'bottom' } },
          scales: { x: { display: false }, y: { ticks: { callback: v => v+" Mbps" } } }
        }
      });
    }

    function styleButton(btn, isUp){
      btn.classList.remove('hidden');
      btn.classList.remove('b-up','b-down');
      if (isUp){
        btn.classList.add('b-down');
        btn.querySelector('.btn-label').textContent = 'توقف';
      } else {
        btn.classList.add('b-up');
        btn.querySelector('.btn-label').textContent = 'ازسرگیری';
      }
    }

    function mean(arr){ if(arr.length===0) return 0; return arr.reduce((a,b)=>a+b,0)/arr.length; }
    function percentile(arr, p){
      if(arr.length===0) return 0;
      const s = arr.slice().sort((a,b)=>a-b);
      const idx = Math.min(s.length-1, Math.max(0, Math.floor(p*(s.length-1))));
      return s[idx];
    }
    const WINDOW = Math.min(60, MAX_POINTS);

    async function controlIface(btn, name, action){
      const headers = CONTROL_TOKEN ? {"X-Auth-Token": CONTROL_TOKEN} : {};
      const confirmMsg = (action === 'down')
            ? `اینترفیس «${name}» متوقف شود؟\nهشدار: ممکن است اتصال شما قطع شود.`
            : `اینترفیس «${name}» فعال شود؟`;
      if(!confirm(confirmMsg)) return;
      const prevText = btn.querySelector('.btn-label').textContent;
      btn.setAttribute('disabled','disabled');
      btn.querySelector('.btn-label').textContent = 'در حال انجام...';
      try{
        const res = await fetch(`/api/iface/${encodeURIComponent(name)}/${action}`, {
          method: 'POST', headers
        });
        if(!res.ok){
          const t = await res.text();
          alert(`انجام نشد: ${res.status} ${t}`);
        }
      }catch(e){
        alert('خطا در انجام عملیات: '+e);
      }finally{
        btn.removeAttribute('disabled');
        btn.querySelector('.btn-label').textContent = prevText;
      }
    }

    async function loadInterfaces(){
      const res = await fetch('/api/interfaces',{cache:'no-store'});
      const ifaces = await res.json();
      document.getElementById('sum-ifaces').textContent = ifaces.length;

      const wrap = document.getElementById('cards');
      wrap.innerHTML = '';
      cards.clear();

      for(const it of ifaces){
        const tpl = document.getElementById('card-template').content.cloneNode(true);
        const card = tpl.querySelector('.card');
        card.dataset.iface = it.name;

        card.querySelector('.name').textContent = it.name;
        card.querySelector('.name').setAttribute('title', it.name);
        const b = badgeFor(it.state);
        const st = card.querySelector('.state');
        st.textContent = b.text;
        st.className = b.cls + " state";

        const flags = (it.flags||[]).join(",");
        const mac = it.mac ? (" | MAC: <span class='k'>" + it.mac + "</span>") : "";
        card.querySelector('.flags').innerHTML = "پرچم‌ها: " + (flags || "هیچ");
        card.querySelector('.meta').innerHTML = "MTU: " + (it.mtu ?? "-") + mac;

        const v4 = (it.addresses||[]).filter(a=>a.family==="inet").map(a=>a.cidr);
        const v6 = (it.addresses||[]).filter(a=>a.family==="inet6").map(a=>a.cidr);
        let addrHTML = "";
        if(v4.length) addrHTML += "IPv4: <span class='k'>" + v4.join(", ") + "</span>";
        if(v6.length) addrHTML += (addrHTML? "<br>" : "") + "IPv6: <span class='k'>" + v6.join(", ") + "</span>";
        card.querySelector('.addrs').innerHTML = addrHTML || "<span class='opacity-60'>بدون IP</span>";

        const li = it.link || {};
        const speedText = (li.speed !== null && li.speed !== undefined) ? (li.speed + " Mb/s") : "نامشخص";
        const duplexText = li.duplex ? li.duplex : "نامشخص";
        const extra = it.kind ? (" | نوع: " + it.kind) : "";
        card.querySelector('.linkinfo').innerHTML = "Link: <span class='k'>سرعت: " + speedText + " | دوبلکس: " + duplexText + extra + "</span>";

        const btn = card.querySelector('.ctrl-btn');
        const isUp = !!it.is_up;
        styleButton(btn, isUp);

        const sbtn = card.querySelector('.shape-btn');
        const shaped = (it.shape && it.shape.active);
        if (it.can_control){
          sbtn.classList.remove('hidden');
          sbtn.classList.remove('b-warn','b-clear','b-unk');
          sbtn.classList.add(shaped ? 'b-clear' : 'b-warn');
          sbtn.querySelector('.shape-label').textContent = shaped ? 'حذف محدودیت' : 'محدودیت';
          sbtn.onclick = async ()=>{

        // --- shape button next to state badges (safe DOM) ---
        try{
          let shapeBtn = card.querySelector('.shape-btn');
          const firstState = card.querySelector('.badge.state');
          if (!shapeBtn){
            shapeBtn = document.createElement('button');
            shapeBtn.className = 'shape-btn badge badge-btn shrink-0';
            const span = document.createElement('span');
            span.className = 'shape-label';
            shapeBtn.appendChild(span);
            if (firstState && firstState.parentElement){
              firstState.parentElement.insertBefore(shapeBtn, firstState);
            } else {
              const actions = card.querySelector('.actions') || (card.querySelector('.ctrl-btn') && card.querySelector('.ctrl-btn').parentElement);
              if (actions) actions.appendChild(shapeBtn);
            }
          } else if (firstState && firstState.parentElement && shapeBtn.parentElement !== firstState.parentElement){
            firstState.parentElement.insertBefore(shapeBtn, firstState);
          }
          const shaped = (it.shape && it.shape.active);
          shapeBtn.classList.remove('b-shape','b-clear','b-unk');
          shapeBtn.classList.add(shaped ? 'b-clear' : 'b-shape');
          shapeBtn.querySelector('.shape-label').textContent = shaped ? 'حذف محدودیت' : 'محدودیت';
          shapeBtn.onclick = async ()=>{
            try{
              const headers = Object.assign({"Content-Type":"application/json"}, CONTROL_TOKEN?{"X-Auth-Token": CONTROL_TOKEN}:{});
              if (!shaped){
                const v = prompt('سقف سرعت آپلود (Mbps) را وارد کنید:');
                if (!v) return;
                const rate = parseFloat(String(v).replace(',','.'));
                if (!(rate>0)){ alert('مقدار نامعتبر'); return; }
                const res = await fetch(`/api/shape/${encodeURIComponent(it.name)}/limit`, {method:'POST', headers, body: JSON.stringify({rate_mbit: rate})});
                if(!res.ok){ alert('خطا در اعمال محدودیت'); }
              }else{
                const res = await fetch(`/api/shape/${encodeURIComponent(it.name)}/clear`, {method:'POST', headers});
                if(!res.ok){ alert('خطا در حذف محدودیت'); }
              }
            } finally { await loadInterfaces(); }
          };
        }catch(e){ console.error('shape-btn error', e); }
                try{
              const headers = Object.assign({"Content-Type":"application/json"}, CONTROL_TOKEN?{"X-Auth-Token": CONTROL_TOKEN}:{});
              if (!shaped){
                const v = prompt('سقف سرعت آپلود (Mbps) را وارد کنید:');
                if (!v) return;
                const rate = parseFloat(String(v).replace(',','.'));
                if (!(rate>0)){ alert('مقدار نامعتبر'); return; }
                const res = await fetch(`/api/shape/${encodeURIComponent(it.name)}/limit`, {method:'POST', headers, body: JSON.stringify({rate_mbit: rate})});
                if(!res.ok){ alert('خطا در اعمال محدودیت'); }
              }else{
                const res = await fetch(`/api/shape/${encodeURIComponent(it.name)}/clear`, {method:'POST', headers});
                if(!res.ok){ alert('خطا در حذف محدودیت'); }
              }
            } finally { await loadInterfaces(); }
          };
        } else {
          sbtn.classList.add('hidden');
        }

        btn.onclick = async ()=>{
          const act = isUp ? 'down' : 'up';
          await controlIface(btn, it.name, act);
          await loadInterfaces();
        };

        wrap.appendChild(card);
        // restore last period line if we have it
        if (LAST_PERIOD[it.name]){
          const title = (PERIOD_SCOPE==='daily'?'امروز':'ماه جاری');
          const rx = fmtBytes(LAST_PERIOD[it.name].rx||0);
          const tx = fmtBytes(LAST_PERIOD[it.name].tx||0);
          card.querySelector('.period').textContent = `${title}: DL ${rx} | UL ${tx}`;
        }
        let chart;
        try { chart = makeChart(card.querySelector('.chart')); }
        catch(e){ chart = { data:{labels:[],datasets:[{data:[]},{data:[]}]}, update: ()=>{} }; }
        cards.set(it.name, { el: card, chart });
      }
    
  try{ NetdashPlaceButtons(); }catch(e){}
}

    async function loadHistory(){
      try{
        const res = await fetch('/api/history',{cache:'no-store'});
        const hist = await res.json();
        for(const [iface, series] of Object.entries(hist)){
          const card = cards.get(iface);
          if(!card) continue;
          const ch = card.chart;
          ch.data.labels = (series.ts || []).map(t => new Date(t*1000).toLocaleTimeString('fa-IR'));
          ch.data.datasets[0].data = (series.rx_mbps || []).map(v => Number(v).toFixed(2));
          ch.data.datasets[1].data = (series.tx_mbps || []).map(v => Number(v).toFixed(2));
          ch.update('none');
        }
      }catch(e){}
    }

    function updateStatsForCard(cardObj){
      const ch = cardObj.chart;
      const W = Math.max(1, Math.min(STAT_WINDOW, MAX_POINTS));
      const rx = ch.data.datasets[0].data.slice(-W).map(v=>Number(v));
      const tx = ch.data.datasets[1].data.slice(-W).map(v=>Number(v));
      const mean = arr => (arr.length? (arr.reduce((a,b)=>a+b,0)/arr.length):0);
      const percentile = (arr,p)=>{
        if(arr.length===0) return 0;
        const s = arr.slice().sort((a,b)=>a-b);
        const idx = Math.min(s.length-1, Math.max(0, Math.floor(p*(s.length-1))));
        return s[idx];
      };
      const dl = {mu: mean(rx), mx: (rx.length? Math.max(...rx):0), p95: percentile(rx,0.95)};
      const ul = {mu: mean(tx), mx: (tx.length? Math.max(...tx):0), p95: percentile(tx,0.95)};
      const line = `DL μ/max/۹۵٪: ${dl.mu.toFixed(1)}/${dl.mx.toFixed(1)}/${dl.p95.toFixed(1)} | UL μ/max/۹۵٪: ${ul.mu.toFixed(1)}/${ul.mx.toFixed(1)}/${ul.p95.toFixed(1)} [${W}s]`;
      cardObj.el.querySelector('.stats').textContent = line;
    }


    async function updatePing(){
      try{
        const res = await fetch('/api/ping',{cache:'no-store'});
        const data = await res.json();
        const wrap = document.getElementById('ping-chips');
        wrap.innerHTML = '';
        const tg = Object.keys(data);
        document.getElementById('ping-targets').textContent = tg.join(', ');
        for(const [host, m] of Object.entries(data)){
          const chip = document.createElement('div');
          chip.className = 'badge b-up';
          chip.innerHTML = `<span class="k">${host}</span> <span class="ltr">${m.avg.toFixed(1)} ms</span> <span class="ltr">(${m.loss.toFixed(1)}% loss)</span>`;
          // color if high loss
          if (m.loss > 5.0){ chip.className = 'badge b-down'; }
          else if (m.avg > 80){ chip.className = 'badge b-unk'; }
          wrap.appendChild(chip);
        }
      }catch(e){}
    }

    async function tick(){
      try{
        const res = await fetch('/api/live',{cache:'no-store'});
        const data = await res.json();
        const rates = data.rates || {};
        let sumRx = 0, sumTx = 0;

        for(const [iface, info] of Object.entries(rates)){
          const rxMbps = info.rx_bps * 8 / 1e6;
          const txMbps = info.tx_bps * 8 / 1e6;
          sumRx += rxMbps; sumTx += txMbps;

          const card = cards.get(iface);
          if(card){
            card.el.querySelector('.rx-rate').textContent = rxMbps.toFixed(1) + ' Mbps';
            card.el.querySelector('.tx-rate').textContent = txMbps.toFixed(1) + ' Mbps';
            const rxT = (info.rx_total !== null && info.rx_total !== undefined) ? info.rx_total : info.rx_bytes;
            const txT = (info.tx_total !== null && info.tx_total !== undefined) ? info.tx_total : info.tx_bytes;
            card.el.querySelector('.rx-tot').textContent  = fmtBytes(rxT);
            card.el.querySelector('.tx-tot').textContent  = fmtBytes(txT);

            const ch = card.chart;
            const label = new Date(info.ts*1000).toLocaleTimeString('fa-IR');
            ch.data.labels.push(label);
            ch.data.datasets[0].data.push(rxMbps.toFixed(2));
            ch.data.datasets[1].data.push(txMbps.toFixed(2));
            for(const ds of ch.data.datasets){ while(ds.data.length > MAX_POINTS) ds.data.shift(); }
            while(ch.data.labels.length > MAX_POINTS) ch.data.labels.shift();
            ch.update('none');

            updateStatsForCard(card);
          }
        }
        document.getElementById('sum-rx').textContent = sumRx.toFixed(1);
        document.getElementById('sum-tx').textContent = sumTx.toFixed(1);
      }catch(e){}
    }

    async function loadPeriod(scope){
      try{
        const res = await fetch('/api/report/'+scope, {cache:'no-store'});
        const rep = await res.json();
        PERIOD_SCOPE = scope;
        LAST_PERIOD = rep.ifaces || {};
        applyPeriodToCards();
        // small visual feedback on the Report button
        const btn = document.getElementById('reportBtn');
        const old = btn.textContent;
        btn.textContent = 'به‌روز شد';
        setTimeout(()=>btn.textContent = old, 800);
      } catch(e){}
    }

    // Filter
    const filterInput = document.getElementById('filterInput');
    filterInput.addEventListener('input', e=>{
      const q = e.target.value.trim().toLowerCase();
      for(const {el} of cards.values()){
        const name = (el.dataset.iface||"").toLowerCase();
        el.style.display = name.includes(q) ? '' : 'none';
      }
    });

    // Theme
    const darkBtn = document.getElementById('darkBtn');
    function applyTheme(){
      const on = localStorage.getItem('netdash-dark') === '1';
      document.documentElement.classList.toggle('dark', on);
    }
    darkBtn.addEventListener('click', ()=>{
      const cur = localStorage.getItem('netdash-dark') === '1';
      localStorage.setItem('netdash-dark', cur ? '0' : '1');
      applyTheme();
    });
    applyTheme();

    // Report
    const scopeSel = document.getElementById('scopeSel');
    const reportBtn = document.getElementById('reportBtn');
    reportBtn.addEventListener('click', ()=> loadPeriod(scopeSel.value));
scopeSel.addEventListener('change', ()=> loadPeriod(scopeSel.value));
setInterval(()=> loadPeriod(scopeSel.value), 15000);

    (async function init(){
      await loadInterfaces();
      await loadHistory();
      tick();
      setInterval(tick, 1000);
      setInterval(loadInterfaces, 30000);
      setInterval(updatePing, 5000);
      updatePing();
      loadPeriod(scopeSel.value);
    })();
  
// === Keep pause/resume button next to status badges ===
(function(){
  function placeCtrlNextToState(card){
    try{
      const ctrl = card.querySelector('.ctrl-btn');
      if(!ctrl) return;
      // likely row for badges:
      const badgeRow = card.querySelector('.badge.state')?.parentElement;
      if(!badgeRow) return;
      const states = card.querySelectorAll('.badge.state');
      if(!states.length) return;
      const last = states[states.length-1];
      if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
        if (ctrl.parentElement && ctrl.parentElement !== badgeRow){
          try{ ctrl.parentElement.removeChild(ctrl); }catch{}
        }
        badgeRow.insertBefore(ctrl, last.nextSibling);
        ctrl.classList.add('badge-btn','shrink-0');
      }
    }catch(e){}
  }
  function placeAll(){ document.querySelectorAll('.card').forEach(placeCtrlNextToState); }
  window.addEventListener('load', placeAll);
  })();


// === Keep shape (محدودیت) button next to status badges and color it red ===
(function(){
  function placeShapeNextToState(card){
    try{
      const shape = card.querySelector('.shape-btn');
      if(!shape) return;
      const badgeRow = card.querySelector('.badge.state')?.parentElement;
      if(!badgeRow) return;
      const states = card.querySelectorAll('.badge.state');
      if(!states.length) return;
      const last = states[states.length-1];
      // place right after last state
      if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
        if (shape.parentElement && shape.parentElement !== badgeRow){
          try{ shape.parentElement.removeChild(shape); }catch{}
        }
        badgeRow.insertBefore(shape, last.nextSibling);
        shape.classList.add('badge-btn','shrink-0');
      }
      // enforce red/white style regardless of class toggling
      shape.classList.add('b-shape'); // ensure one of the classes is present
      shape.classList.remove('b-warn'); // remove old yellow if present
    }catch(e){}
  }
  function placeAll(){ document.querySelectorAll('.card').forEach(placeShapeNextToState); }
  window.addEventListener('load', placeAll);
  })();


// === NetDash helper: place control & shape buttons next to status badges (one-shot; called on load & after render) ===
function NetdashPlaceButtons(){
  try{
    document.querySelectorAll('.card').forEach(card => {
      // ctrl-btn
      try{
        const ctrl = card.querySelector('.ctrl-btn');
        const badgeRow = card.querySelector('.badge.state')?.parentElement;
        const states = card.querySelectorAll('.badge.state');
        if (ctrl && badgeRow && states.length){
          const last = states[states.length-1];
          if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
            if (ctrl.parentElement && ctrl.parentElement !== badgeRow){
              try{ ctrl.parentElement.removeChild(ctrl); }catch{}
            }
            badgeRow.insertBefore(ctrl, last.nextSibling);
            ctrl.classList.add('badge-btn','shrink-0');
          }
        }
      }catch(e){ console.error('ctrl-btn move error', e); }
      // shape-btn
      try{
        const shape = card.querySelector('.shape-btn');
        const badgeRow = card.querySelector('.badge.state')?.parentElement;
        const states = card.querySelectorAll('.badge.state');
        if (shape && badgeRow && states.length){
          const last = states[states.length-1];
          if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
            if (shape.parentElement && shape.parentElement !== badgeRow){
              try{ shape.parentElement.removeChild(shape); }catch{}
            }
            badgeRow.insertBefore(shape, last.nextSibling);
            shape.classList.add('badge-btn','shrink-0');
          }
          // force red/white style
          shape.classList.add('b-shape');
          shape.classList.remove('b-warn');
        }
      }catch(e){ console.error('shape-btn move error', e); }
    });
  }catch(e){}
}
window.addEventListener('load', NetdashPlaceButtons);
window.addEventListener('load', initStatWindowSelector);

</script>
</body>
</html>
"""

# ------------------ Routes ------------------
@app.route("/")
def home():
    html = render_template_string(HTML, max_points=MAX_POINTS, token=CONTROL_TOKEN)
    resp = make_response(html)
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(get_interfaces_info())

@app.route("/api/live")
def api_live():
    return jsonify(monitor.snapshot())

@app.route("/api/history")
def api_history():
    return jsonify(history.export())

@app.route("/api/ping")
def api_ping():
    return jsonify(pingmon.snapshot())

@app.route("/api/report/<scope>")
def api_report(scope):
    if scope not in ("daily","monthly"):
        abort(400, "scope must be daily|monthly")
    key, data = periods.get_scope(scope)
    total_rx = sum(int(v.get("rx",0)) for v in data.values())
    total_tx = sum(int(v.get("tx",0)) for v in data.values())
    return jsonify({"scope": scope, "key": key, "ifaces": data, "sum": {"rx": total_rx, "tx": total_tx}})

@app.route("/api/iface/<iface>/down", methods=["POST"])
def api_iface_down(iface):
    return iface_action(iface, "down")

@app.route("/api/iface/<iface>/up", methods=["POST"])
def api_iface_up(iface):
    return iface_action(iface, "up")


@app.route("/api/shape/<iface>/limit", methods=["POST"])
def api_shape_limit(iface):
    if not can_control(iface):
        abort(403, description="Interface not permitted")
    _require_token()
    body = request.get_json(silent=True) or {}
    rate = float(body.get("rate_mbit", 0))
    if rate <= 0:
        abort(400, "rate_mbit must be > 0")
    burst = int(body.get("burst_kbit", 32))
    latency = int(body.get("latency_ms", 400))
    try:
        tc_limit(iface, rate, burst, latency)
        return jsonify({"ok": True, "iface": iface, "rate_mbit": rate})
    except subprocess.CalledProcessError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/filters", methods=["GET"])
def api_filters_list():
    _require_token()  # برای امنیت، هم‌راستای بقیه کنترل‌ها
    return jsonify({"items": filters.list()})

@app.route("/api/filters", methods=["POST"])
def api_filters_add():
    _require_token()
    body = request.get_json(silent=True) or {}
    pattern = (body.get("pattern") or "").strip()
    iface   = (body.get("iface") or "").strip() or None
    proto   = (body.get("proto") or "all").strip().lower()
    port    = body.get("port")
    show_page = bool(body.get("show_page"))

    if iface and not can_control(iface):
        abort(403, description="Interface not permitted")
    try:
        rec = filters.add(pattern, iface=iface, proto=proto, port=port, show_page=show_page)
        return jsonify({"ok": True, "item": rec})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
        
        

@app.route("/api/filters/<fid>", methods=["DELETE"])
def api_filters_del(fid):
    _require_token()
    ok = filters.remove(fid)
    if ok:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Not found"}), 404



@app.route("/api/shape/<iface>/clear", methods=["POST"])
def api_shape_clear(iface):
    if not can_control(iface):
        abort(403, description="Interface not permitted")
    _require_token()
    tc_clear(iface)
    return jsonify({"ok": True, "iface": iface})


def _flush_on_exit():
    try:
        history.flush(force=True)
        totals.flush(force=True)
        periods.flush(force=True)
    except Exception:
        pass

if __name__ == "__main__":
    try:
        app.run(host=HOST, port=PORT, debug=False)
    finally:
        _flush_on_exit()
