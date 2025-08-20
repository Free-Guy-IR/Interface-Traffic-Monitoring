#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetDash v1.4.8
- برچسب وضعیت UP از «بالاست» به «فعال» تغییر یافت
- چیدمان LTR برای جلوگیری از برعکس شدن عناصر، برچسب‌ها فارسی
"""
import os
import time
import json
import threading
import subprocess
from collections import deque, defaultdict
from flask import Flask, jsonify, render_template_string, make_response, request, abort

VERSION = "1.4.8"

POLL_INTERVAL = 1.0   # seconds
MAX_POINTS    = int(os.environ.get("NETDASH_MAX_POINTS", "120"))
HOST          = "0.0.0.0"
PORT          = int(os.environ.get("NETDASH_PORT", "18080"))

# --- control config ---
CONTROL_ENABLED = True
CONTROL_TOKEN   = os.environ.get("NETDASH_TOKEN", "").strip()  # optional
DENY_IFACES     = {x.strip() for x in os.environ.get("NETDASH_DENY", "").split(",") if x.strip()}
ALLOW_IFACES    = {x.strip() for x in os.environ.get("NETDASH_ALLOW", "").split(",") if x.strip()}

app = Flask(__name__)

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
HISTORY_FILE = os.path.join(DATA_HOME, "history.json")

def _run_ip_json(args):
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

def get_interfaces_info():
    links = _run_ip_json(["-json", "link"])
    addrs = _run_ip_json(["-json", "addr"])
    by_index = {item.get("ifindex"): item for item in links}
    result = []
    for item in addrs:
        idx = item.get("ifindex")
        li = by_index.get(idx, {})
        name = item.get("ifname") or li.get("ifname")
        flags = li.get("flags") or item.get("flags", [])
        state = (li.get("operstate") or item.get("operstate") or "").upper()
        mtu = li.get("mtu") or item.get("mtu")
        mac = li.get("address") if li.get("link_type") != "none" else None
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
            "can_control": can_control(name), "is_up": is_up
        })
    for idx, li in by_index.items():
        name = li.get("ifname")
        if not any(r["ifindex"] == idx for r in result):
            flags = li.get("flags", [])
            state = (li.get("operstate") or "").upper()
            is_up = ("UP" in (flags or [])) or (state == "UP")
            result.append({
                "name": name,
                "ifindex": idx,
                "state": state or "UNKNOWN",
                "flags": flags,
                "mtu": li.get("mtu"),
                "mac": li.get("address"),
                "addresses": [],
                "can_control": can_control(name),
                "is_up": is_up
            })
    result = [r for r in result if r.get("name")]
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
                    else:
                        rx_bps = tx_bps = 0.0
                    self.prev[iface] = (rx, tx, now)
                    self.data[iface] = {
                        "rx_bps": rx_bps, "tx_bps": tx_bps,
                        "rx_bytes": rx, "tx_bytes": tx,
                        "ts": now
                    }
                    history.add(iface, now, rx_bps, tx_bps)
            history.flush()
            time.sleep(self.poll)

    def start(self):
        if self.running: return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def snapshot(self):
        with self.lock:
            return {"ts": time.time(), "rates": dict(self.data)}

monitor = NetMonitor(POLL_INTERVAL)
monitor.start()

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
    cmd = [ipbin, "link", "set", "dev", iface, "down" if action=="down" else "up"]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.2)
        return {"ok": True, "iface": iface, "action": action}
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": f"ip failed ({e})", "iface": iface, "action": action}, 500

HTML = r"""
<!doctype html>
<html lang="fa" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetDash - داشبورد ترافیک شبکه</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: { extend: { fontFamily: { sans: ['Vazirmatn', 'Inter', 'ui-sans-serif', 'system-ui'] } } }
    }
  </script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
  </style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-gray-900 dark:text-gray-100">
  <div class="max-w-7xl mx-auto p-4 sm:p-6">
    <div class="flex flex-wrap items-center justify-between gap-3 mb-6">
      <h1 class="text-2xl sm:text-3xl font-extrabold">NetDash</h1>
      <div class="flex items-center gap-2">
        <input id="filterInput" class="px-3 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm" placeholder="فیلتر اینترفیس‌ها...">
        <button id="darkBtn" class="px-3 py-2 rounded-xl card bg-white dark:bg-gray-800 text-sm">تیره / روشن</button>
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

    <div id="cards" class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4"></div>
  </div>

  <template id="card-template">
    <div class="card p-4 bg-white dark:bg-gray-800 flex flex-col gap-3">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0 flex flex-col gap-1">
          <div class="flex items-center gap-2">
            <div class="font-bold text-lg k name truncate"></div>
            <button class="ctrl-btn hidden badge badge-btn b-up">
              <span class="btn-label">توقف</span>
            </button>
          </div>
          <div class="text-xs opacity-80 flags"></div>
          <div class="text-xs opacity-80 meta"></div>
          <div class="text-xs opacity-80 addrs"></div>
        </div>
        <div class="text-right text-sm">
          <div class="mb-2"><span class="badge state b-unk">نامشخص</span></div>
          <div>دانلود <span class="rx-rate font-semibold ltr">0</span></div>
          <div>آپلود <span class="tx-rate font-semibold ltr">0</span></div>
          <div class="opacity-60 text-[11px] mt-1">مجموع: دانلود <span class="rx-tot ltr">0</span> | آپلود <span class="tx-tot ltr">0</span></div>
        </div>
      </div>
      <div class="h-36 ltr"><canvas class="chart"></canvas></div>
    </div>
  </template>

  <script>
    (function ensureChart(){
      if (window.Chart) return;
      function MiniChart(ctx, config){
        this.ctx = ctx; this.data = config.data;
        this.update = function(){
          const c = this.ctx.canvas, w=c.width, h=c.height;
          const g = this.ctx; g.clearRect(0,0,w,h);
          g.strokeStyle = "#aaa"; g.lineWidth = 1; g.strokeRect(0,0,w,h);
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

    function fmtBitsPerSec(bytes_per_sec){
      const mbps = bytes_per_sec * 8 / 1e6;
      return mbps.toFixed(1) + " Mbps";
    }
    function fmtBytes(x){
      const units = ["B","KB","MB","GB","TB"];
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

        const btn = card.querySelector('.ctrl-btn');
        const isUp = !!it.is_up;
        styleButton(btn, isUp);
        btn.onclick = async ()=>{
          const act = isUp ? 'down' : 'up';
          await controlIface(btn, it.name, act);
          await loadInterfaces();
        };

        wrap.appendChild(card);
        let chart;
        try { chart = makeChart(card.querySelector('.chart')); }
        catch(e){ chart = { data:{labels:[],datasets:[{data:[]},{data:[]}]}, update: ()=>{} }; }
        cards.set(it.name, { el: card, chart });
      }
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
            card.el.querySelector('.rx-rate').textContent = fmtBitsPerSec(info.rx_bps);
            card.el.querySelector('.tx-rate').textContent = fmtBitsPerSec(info.tx_bps);
            card.el.querySelector('.rx-tot').textContent  = fmtBytes(info.rx_bytes);
            card.el.querySelector('.tx-tot').textContent  = fmtBytes(info.tx_bytes);

            const ch = card.chart;
            const label = new Date(info.ts*1000).toLocaleTimeString('fa-IR');
            ch.data.labels.push(label);
            ch.data.datasets[0].data.push(rxMbps.toFixed(2));
            ch.data.datasets[1].data.push(txMbps.toFixed(2));
            for(const ds of ch.data.datasets){ while(ds.data.length > MAX_POINTS) ds.data.shift(); }
            while(ch.data.labels.length > MAX_POINTS) ch.data.labels.shift();
            ch.update('none');
          }
        }
        document.getElementById('sum-rx').textContent = sumRx.toFixed(1);
        document.getElementById('sum-tx').textContent = sumTx.toFixed(1);
      }catch(e){}
    }

    const filterInput = document.getElementById('filterInput');
    filterInput.addEventListener('input', e=>{
      const q = e.target.value.trim().toLowerCase();
      for(const {el} of cards.values()){
        const name = (el.dataset.iface||"").toLowerCase();
        el.style.display = name.includes(q) ? '' : 'none';
      }
    });

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

    (async function init(){
      await loadInterfaces();
      await loadHistory();
      tick();
      setInterval(tick, 1000);
      setInterval(loadInterfaces, 30000);
    })();
  </script>
</body>
</html>
"""

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

@app.route("/api/iface/<iface>/down", methods=["POST"])
def api_iface_down(iface):
    return iface_action(iface, "down")

@app.route("/api/iface/<iface>/up", methods=["POST"])
def api_iface_up(iface):
    return iface_action(iface, "up")

def _flush_on_exit():
    try:
        history.flush(force=True)
    except Exception:
        pass

if __name__ == "__main__":
    try:
        app.run(host=HOST, port=PORT, debug=False)
    finally:
        _flush_on_exit()
