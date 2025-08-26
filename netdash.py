#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os 
import time 
import json 
import threading 
import subprocess 
import re 
from collections import deque ,defaultdict 
from flask import Flask ,jsonify ,render_template_string ,make_response ,request ,abort 
import socket ,ipaddress ,uuid ,random ,string 

try :
    from publicsuffix2 import get_sld as _psl_get_sld 
    def _registrable_domain (host :str )->str |None :
        h =(host or "").strip ().lower ().strip (".")
        if not h or "."not in h :return None 
        try :
            return _psl_get_sld (h )
        except Exception :
            return None 
except Exception :
    try :
        import tldextract 
        _tldx =tldextract .TLDExtract (suffix_list_urls =None )
        def _registrable_domain (host :str )->str |None :
            h =(host or "").strip ().lower ().strip (".")
            if not h or "."not in h :return None 
            ext =_tldx (h )
            if not ext .domain or not ext .suffix :return None 
            return f"{ext.domain}.{ext.suffix}"
    except Exception :

        _2nd ={"co.uk","org.uk","ac.uk","gov.uk","co.ir","ac.ir","gov.ir","com.au","net.au","org.au"}
        def _registrable_domain (host :str )->str |None :
            h =(host or "").strip ().lower ().strip (".")
            if not h or "."not in h :return None 
            parts =h .split (".")
            if len (parts )<2 :return None 
            suf2 =".".join (parts [-2 :])
            suf3 =".".join (parts [-3 :])
            if suf2 in _2nd and len (parts )>=3 :
                return ".".join (parts [-3 :])
            if suf3 in _2nd and len (parts )>=4 :
                return ".".join (parts [-4 :])
            return suf2 

POLL_INTERVAL =1.0 
MAX_POINTS =int (os .environ .get ("NETDASH_MAX_POINTS","120"))
HOST ="0.0.0.0"
PORT =int (os .environ .get ("NETDASH_PORT","18080"))
BLOCK_PORT =int (os .environ .get ("NETDASH_BLOCK_PORT","18081"))
FLUSH_SETS_ON_REMOVE =os .environ .get ("NETDASH_FLUSH_SETS_ON_REMOVE","1").lower ()in ("1","true","yes","on")
USE_DNSMASQ_IPSET =os .environ .get ("NETDASH_IPSET_MODE","1").lower ()in ("1","true","yes","on")
SNI_BLOCK_ENABLED =os .environ .get ("NETDASH_SNI_BLOCK","1").lower ()in ("1","true","yes","on")
PAGE_MODE_ENABLED =os .environ .get ("NETDASH_PAGE_MODE","1").lower ()in ("1","true","yes","on")
SNI_LEARN_ENABLED =os .environ .get ("NETDASH_SNI_LEARN","1").lower ()in ("1","true","yes","on")
AUTO_ENFORCE_DNS =os .environ .get ("NETDASH_ENFORCE_DNS","1").lower ()in ("1","true","yes","on")
AUTO_BLOCK_DOT =os .environ .get ("NETDASH_BLOCK_DOT","0").lower ()in ("1","true","yes","on")
AUTO_PRELOAD_META =os .environ .get ("NETDASH_PRELOAD_META","0").lower ()in ("1","true","yes","on")
AUTO_PIP_INSTALL =os .environ .get ("NETDASH_AUTO_PIP","1").lower ()in ("1","true","yes","on")
SNI_LEARN_IFACES =[x .strip ()for x in os .environ .get ("NETDASH_SNI_IFACES","").split (",")if x .strip ()]
CONTROL_ENABLED =True 
CONTROL_TOKEN =os .environ .get ("NETDASH_TOKEN","").strip ()
DENY_IFACES ={x .strip ()for x in os .environ .get ("NETDASH_DENY","").split (",")if x .strip ()}
ALLOW_IFACES ={x .strip ()for x in os .environ .get ("NETDASH_ALLOW","").split (",")if x .strip ()}
IPSET4 =os .environ .get ("NETDASH_IPSET4","nd-bl4")
IPSET6 =os .environ .get ("NETDASH_IPSET6","nd-bl6")
IPSET4P =os .environ .get ("NETDASH_IPSET4_PAGE","ndp-bl4")
IPSET6P =os .environ .get ("NETDASH_IPSET6_PAGE","ndp-bl6")
IPSET_TIMEOUT =int (os .environ .get ("NETDASH_IPSET_TIMEOUT","3600"))
DNSMASQ_CONF =os .environ .get ("NETDASH_DNSMASQ_CONF","/etc/dnsmasq.d/netdash-blocks.conf")



PORTS_MONITOR_ENABLED = os.environ.get("NETDASH_PORTS_MONITOR","1").lower() in ("1","true","yes","on")
PORTS_POLL_INTERVAL  = float(os.environ.get("NETDASH_PORTS_INTERVAL","1.0"))









app =Flask (__name__ )

def _try_modprobe (mod ):
    try :
        cmd =["modprobe",mod ]
        if os .geteuid ()!=0 :
            cmd =["sudo","-n"]+cmd 
        subprocess .check_call (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
    except Exception :
        pass 

blockapp =Flask ("netdash_block")

_try_modprobe ("xt_string")

BLOCK_PAGE_HTML =r"""
<!doctype html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetDash - داشبورد ترافیک شبکه</title>

  <!-- 1) اول: config مربوط به Tailwind -->
  <!-- Tailwind via CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: { extend: { fontFamily: { sans: ['Vazirmatn','Inter','ui-sans-serif','system-ui'] } } }
    }
  </script>

  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

  <!-- 3) فقط CSS — بدون JS سرگردان -->
  <style>
    .card { border-radius: 1rem; box-shadow: 0 2px 24px rgba(0,0,0,0.06); border: 1px solid rgba(0,0,0,0.06); }
    .k { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; direction:ltr }
    .badge { display:inline-flex; align-items:center; gap:.4rem; padding:.2rem .5rem; border-radius:999px; font-size:.75rem; font-weight:600; }
    .b-up { background:#d1fae5; color:#065f46; }
    .b-down { background:#fee2e2; color:#991b1b; }
    .b-unk { background:#fde68a; color:#92400e; }
    .badge-btn { cursor:pointer; user-select:none; border: none; display:inline-flex; align-items:center; justify-content:center; white-space:nowrap }
    .badge-btn:disabled { opacity:.75; cursor:not-allowed; }
    .ltr { direction:ltr }
    .name{white-space:normal !important;overflow-wrap:anywhere;word-break:break-word;text-overflow:clip !important}

    /* دکمه محدودیت: متمایز از «حذف محدودیت» */
    .b-shape{background:#dbeafe;color:#1e3a8a;border:1px solid #60a5fa}
    .b-clear{background:#fecaca;color:#7f1d1d;border:1px solid #ef4444}
    /* اگر قبلاً خط زیر را داشتی که هر دو را قرمز می‌کرد، حذفش کن:

    */
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

@blockapp .after_request 
def _no_cache (resp ):
    resp .headers ["Cache-Control"]="no-store, max-age=0"
    return resp 

@blockapp .route ("/",defaults ={"path":""})
@blockapp .route ("/<path:path>")
def blocked_any (path ):
    host =request .headers .get ("Host","")
    return render_template_string (BLOCK_PAGE_HTML ,host =host ),451 

def start_block_server ():
    if getattr (start_block_server ,"_started",False ):
        return 
    start_block_server ._started =True 

    def run_once (host ):
        try :
            blockapp .run (host =host ,port =BLOCK_PORT ,debug =False ,use_reloader =False )
        except OSError as e :
            print (f"[netdash] block server bind failed on {host}:{BLOCK_PORT}: {e}")

    host ="::"if socket .has_ipv6 else "0.0.0.0"

    t =threading .Thread (target =run_once ,args =(host ,),daemon =True )
    t .start ()

def _pick_data_home ():
    candidates =[
    "/var/lib/netdash",
    os .path .join (os .path .expanduser ("~"),".local","share","netdash"),
    "/tmp/netdash",
    os .getcwd (),
    ]
    for d in candidates :
        try :
            os .makedirs (d ,exist_ok =True )
            testfile =os .path .join (d ,".wtest")
            with open (testfile ,"w")as f :
                f .write ("ok")
            os .remove (testfile )
            return d 
        except Exception :
            continue 
    return os .getcwd ()

DATA_HOME =_pick_data_home ()
PORTS_TOTALS_FILE = os.path.join(DATA_HOME, "ports_totals.json")
SNI_LOG_FILE =os .path .join (DATA_HOME ,"sni-seen.log")
SNI_INDEX_FILE =os .path .join (DATA_HOME ,"sni-index.json")
SNI_INDEX_PRESEED_ON_ADD =True 

BLOCKS_REG_FILE =os .path .join (DATA_HOME ,"blocks_registry.json")

_SNI_LOG_LOCK =threading .Lock ()

FILTERS_FILE =os .path .join (DATA_HOME ,"filters.json")
HISTORY_FILE =os .path .join (DATA_HOME ,"history.json")
TOTALS_FILE =os .path .join (DATA_HOME ,"totals.json")
PERIOD_FILE =os .path .join (DATA_HOME ,"period_totals.json")

def _append_sni_log (kind ,host ,dst_ip ,fam =None ,base =None ,iface =None ):
    rec ={
    "ts":int (time .time ()),
    "kind":kind ,
    "host":host ,
    "dst_ip":dst_ip ,
    "fam":fam ,
    "base":base ,
    "iface":iface ,
    }
    try :
        os .makedirs (os .path .dirname (SNI_LOG_FILE ),exist_ok =True )

        line =json .dumps (rec ,ensure_ascii =False ,default =str )

        with _SNI_LOG_LOCK :
            with open (SNI_LOG_FILE ,"a",encoding ="utf-8")as f :
                f .write (line +"\n")
    except Exception as e :
        print ("[netdash] SNI log error:",e )

def _run_ip_json (args ):
    ipbin =_find_ip_binary ()
    try :
        out =subprocess .check_output ([ipbin ]+args ,text =True )
        return json .loads (out )
    except Exception :
        return []

def can_control (iface :str )->bool :
    if not CONTROL_ENABLED or not iface :
        return False 
    if ALLOW_IFACES :
        return iface in ALLOW_IFACES 
    if iface in DENY_IFACES :
        return False 
    return True 

def _read_file (path ,to_int =False ):
    try :
        with open (path ,"r")as f :
            s =f .read ().strip ()
        return int (s )if to_int else s 
    except Exception :
        return None 

def _link_info_sysfs (iface ):
    spd =_read_file (f"/sys/class/net/{iface}/speed",to_int =True )
    dup =_read_file (f"/sys/class/net/{iface}/duplex")
    if isinstance (spd ,int )and spd <0 :
        spd =None 
    if dup :
        dup =dup .lower ()
    return spd ,dup 

def _link_info_ethtool (iface ):
    try :
        out =subprocess .check_output (["ethtool",iface ],text =True ,stderr =subprocess .DEVNULL )
    except Exception :
        return None ,None 
    m =re .search (r"Speed:\s*([0-9]+)\s*Mb/s",out )
    spd =int (m .group (1 ))if m else None 
    m =re .search (r"Duplex:\s*([A-Za-z!]+)",out )
    dup =m .group (1 ).replace ("!","").lower ()if m else None 
    if dup =="unknown":
        dup =None 
    return spd ,dup 

def get_link_info (iface ):
    spd ,dup =_link_info_sysfs (iface )
    if spd is None and dup is None :
        es ,ed =_link_info_ethtool (iface )
        if spd is None :
            spd =es 
        if dup is None :
            dup =ed 
    return {"speed":spd ,"duplex":dup }

def get_interfaces_info ():
    links =_run_ip_json (["-json","link"])
    addrs =_run_ip_json (["-json","addr"])
    by_index ={item .get ("ifindex"):item for item in links }
    result =[]
    for item in addrs :
        idx =item .get ("ifindex")
        li =by_index .get (idx ,{})
        name =item .get ("ifname")or li .get ("ifname")
        if not name :
            continue 
        flags =li .get ("flags")or item .get ("flags",[])
        state =(li .get ("operstate")or item .get ("operstate")or "").upper ()
        mtu =li .get ("mtu")or item .get ("mtu")
        mac =li .get ("address")if li .get ("link_type")!="none"else None 
        info_kind =None 
        try :
            info_kind =(li .get ("linkinfo")or {}).get ("info_kind")
        except Exception :
            info_kind =None 
        is_up =("UP"in (flags or []))or (state =="UP")
        addresses =[]
        for a in item .get ("addr_info",[]):
            fam =a .get ("family")
            local =a .get ("local")
            prefix =a .get ("prefixlen")
            scope =a .get ("scope")
            if local is not None and prefix is not None :
                addresses .append ({"family":fam ,"cidr":f"{local}/{prefix}","scope":scope })
        result .append ({
        "name":name ,"ifindex":idx ,"state":state or "UNKNOWN","flags":flags or [],
        "mtu":mtu ,"mac":mac ,"addresses":addresses ,
        "can_control":can_control (name ),"is_up":is_up ,
        "link":get_link_info (name )if name else {"speed":None ,"duplex":None },
        "shape":tc_status (name ),
        "kind":info_kind ,
        })

    for idx ,li in by_index .items ():
        name =li .get ("ifname")
        if not name or any (r ["ifindex"]==idx for r in result ):
            continue 
        flags =li .get ("flags",[])
        state =(li .get ("operstate")or "").upper ()
        info_kind =None 
        try :
            info_kind =(li .get ("linkinfo")or {}).get ("info_kind")
        except Exception :
            info_kind =None 
        is_up =("UP"in (flags or []))or (state =="UP")
        result .append ({
        "name":name ,"ifindex":idx ,"state":state or "UNKNOWN","flags":flags ,
        "mtu":li .get ("mtu"),"mac":li .get ("address"),"addresses":[],
        "can_control":can_control (name ),"is_up":is_up ,
        "link":get_link_info (name )if name else {"speed":None ,"duplex":None },
        "shape":tc_status (name ),
        "kind":info_kind ,
        })
    result .sort (key =lambda x :x ["ifindex"]or 10 **9 )
    return result 

def list_ifaces_fs ():
    try :
        return [d for d in os .listdir ("/sys/class/net")if os .path .isdir (os .path .join ("/sys/class/net",d ))]
    except Exception :
        return []

def read_counters (iface ):
    base =f"/sys/class/net/{iface}/statistics"
    def read_one (fname ):
        try :
            with open (os .path .join (base ,fname ),"r")as f :
                return int (f .read ().strip ())
        except Exception :
            return 0 
    return read_one ("rx_bytes"),read_one ("tx_bytes")

class SNIIndex :
    def __init__ (self ,filepath ):
        self .filepath =filepath 
        self .idx ={"v":1 ,"domains":{}}
        self .lock =threading .Lock ()
        self ._last_flush =0.0 
        self .flush_interval =5.0 
        self .load ()

    def load (self ):
        try :
            with open (self .filepath ,"r",encoding ="utf-8")as f :
                obj =json .load (f )
            if isinstance (obj ,dict )and "domains"in obj :
                self .idx =obj 
        except Exception :
            self .idx ={"v":1 ,"domains":{}}

    def flush (self ,force =False ):
        now =time .time ()
        if not force and (now -self ._last_flush )<self .flush_interval :
            return 
        with self .lock :
            data =json .loads (json .dumps (self .idx ))
        tmp =self .filepath +".tmp"
        try :
            with open (tmp ,"w",encoding ="utf-8")as f :
                json .dump (data ,f ,ensure_ascii =False )
            os .replace (tmp ,self .filepath )
            self ._last_flush =now 
        except Exception :
            pass 

    def _upd_ipmap (self ,ipmap :dict ,ip :str ,ts :int ):
        try :
            ipmap [ip ]=int (ts )
        except Exception :
            pass 

    def update (self ,host :str ,dst_ip :str ,fam :str ,iface :str |None =None ,ts :int |None =None ):
        if not host or not dst_ip or fam not in ("v4","v6"):
            return 
        base =_registrable_domain (host )or _normalize_domain_or_none (host )or host .strip ().lower ().strip (".")
        if not base :
            return 
        t =int (ts or time .time ())
        with self .lock :
            dom =self .idx ["domains"].setdefault (base ,{
            "first_seen":t ,"last_seen":t ,
            "ips":{"v4":{},"v6":{}},
            "subs":{}
            })
            dom ["last_seen"]=t 
            self ._upd_ipmap (dom ["ips"][fam ],dst_ip ,t )
            if host !=base :
                sub =dom ["subs"].setdefault (host ,{"last_seen":t ,"ips":{"v4":{},"v6":{}}})
                sub ["last_seen"]=t 
                self ._upd_ipmap (sub ["ips"][fam ],dst_ip ,t )
        self .flush ()

    def get_ips_for_base (self ,base :str ):
        base =(base or "").strip ().lower ().strip (".")
        if not base :return [],[]
        v4 ,v6 =set (),set ()
        now =int (time .time ())
        with self .lock :
            dom =self .idx ["domains"].get (base )
            if not dom :return [],[]
            for ip ,ts in (dom .get ("ips",{}).get ("v4",{})or {}).items ():
                v4 .add (ip )
            for ip ,ts in (dom .get ("ips",{}).get ("v6",{})or {}).items ():
                v6 .add (ip )
            for sub in (dom .get ("subs")or {}).values ():
                for ip ,ts in (sub .get ("ips",{}).get ("v4",{})or {}).items ():
                    v4 .add (ip )
                for ip ,ts in (sub .get ("ips",{}).get ("v6",{})or {}).items ():
                    v6 .add (ip )
        return sorted (v4 ),sorted (v6 )

sni_index =SNIIndex (SNI_INDEX_FILE )

class HistoryStore :
    def __init__ (self ,filepath ,max_points =120 ):
        self .filepath =filepath 
        self .max_points =max_points 
        self .hist =defaultdict (lambda :deque (maxlen =self .max_points ))
        self .lock =threading .Lock ()
        self ._last_flush =0.0 
        self .flush_interval =5.0 

    def add (self ,iface ,ts ,rx_bps ,tx_bps ):
        with self .lock :
            self .hist [iface ].append ((float (ts ),float (rx_bps ),float (tx_bps )))

    def export (self ):
        with self .lock :
            out ={}
            for iface ,dq in self .hist .items ():
                ts_list =[t for (t ,_ ,_ )in dq ]
                rx_mbps =[(rb *8.0 )/1e6 for (_ ,rb ,_ )in dq ]
                tx_mbps =[(tb *8.0 )/1e6 for (_ ,_ ,tb )in dq ]
                out [iface ]={"ts":ts_list ,"rx_mbps":rx_mbps ,"tx_mbps":tx_mbps }
            return out 

    def flush (self ,force =False ):
        now =time .time ()
        if not force and (now -self ._last_flush )<self .flush_interval :
            return 
        with self .lock :
            data ={iface :list (dq )for iface ,dq in self .hist .items ()}
        try :
            tmp =self .filepath +".tmp"
            with open (tmp ,"w",encoding ="utf-8")as f :
                json .dump ({"v":1 ,"max_points":self .max_points ,"data":data },f )
            os .replace (tmp ,self .filepath )
            self ._last_flush =now 
        except Exception :
            pass 

    def load (self ):
        try :
            with open (self .filepath ,"r",encoding ="utf-8")as f :
                obj =json .load (f )
            maxp =int (obj .get ("max_points",self .max_points ))
            raw =obj .get ("data",{})
            with self .lock :
                self .max_points =maxp 
                self .hist .clear ()
                for iface ,arr in (raw or {}).items ():
                    dq =deque (maxlen =self .max_points )
                    for tup in arr :
                        if isinstance (tup ,(list ,tuple ))and len (tup )>=3 :
                            t ,rb ,tb =tup [0 ],tup [1 ],tup [2 ]
                            dq .append ((float (t ),float (rb ),float (tb )))
                    self .hist [iface ]=dq 
        except Exception :

            with self .lock :
                self .hist .clear ()

history =HistoryStore (HISTORY_FILE ,MAX_POINTS )
history .load ()

class TotalsStore :
    def __init__ (self ,filepath ):
        self .filepath =filepath 
        self .ifaces ={}
        self .lock =threading .Lock ()
        self ._last_flush =0.0 
        self .flush_interval =5.0 
        self .load ()

    def load (self ):
        try :
            with open (self .filepath ,"r",encoding ="utf-8")as f :
                obj =json .load (f )
            raw_ifaces =obj .get ("ifaces",{})
            if not isinstance (raw_ifaces ,dict ):
                raw_ifaces ={}
        except Exception :
            raw_ifaces ={}

        cleaned ={}
        for name ,rec in raw_ifaces .items ():
            if not isinstance (rec ,dict ):
                continue 
            cleaned [name ]={
            "rx_total":float (rec .get ("rx_total",0.0 )),
            "tx_total":float (rec .get ("tx_total",0.0 )),
            "last_rx":(int (rec ["last_rx"])if rec .get ("last_rx")is not None else None ),
            "last_tx":(int (rec ["last_tx"])if rec .get ("last_tx")is not None else None ),
            "t":float (rec .get ("t",0.0 )),
            }

        with self .lock :
            self .ifaces =cleaned 

    def flush (self ,force =False ):
        now =time .time ()
        if not force and (now -self ._last_flush )<self .flush_interval :
            return 
        with self .lock :
            data ={"v":1 ,"ifaces":self .ifaces }
        try :
            tmp =self .filepath +".tmp"
            with open (tmp ,"w",encoding ="utf-8")as f :
                json .dump (data ,f )
            os .replace (tmp ,self .filepath )
            self ._last_flush =now 
        except Exception :
            pass 

    def update (self ,name ,rx_bytes_now ,tx_bytes_now ):
        with self .lock :
            rec =self .ifaces .get (name )or {
            "rx_total":0.0 ,"tx_total":0.0 ,
            "last_rx":None ,"last_tx":None ,"t":0.0 
            }

            if rec ["last_rx"]is None :
                rec ["last_rx"]=int (rx_bytes_now )
            else :
                if rx_bytes_now >=rec ["last_rx"]:
                    rec ["rx_total"]+=(int (rx_bytes_now )-rec ["last_rx"])
                else :

                    rec ["rx_total"]+=int (rx_bytes_now )
                rec ["last_rx"]=int (rx_bytes_now )

            if rec ["last_tx"]is None :
                rec ["last_tx"]=int (tx_bytes_now )
            else :
                if tx_bytes_now >=rec ["last_tx"]:
                    rec ["tx_total"]+=(int (tx_bytes_now )-rec ["last_tx"])
                else :
                    rec ["tx_total"]+=int (tx_bytes_now )
                rec ["last_tx"]=int (tx_bytes_now )

            rec ["t"]=time .time ()
            self .ifaces [name ]=rec 
            return rec ["rx_total"],rec ["tx_total"]

    def reset(self, iface=None):
        with self.lock:
            if iface:
                rx, tx = read_counters(iface)
                self.ifaces[iface] = {
                    "rx_total": 0.0, "tx_total": 0.0,
                    "last_rx": int(rx), "last_tx": int(tx),
                    "t": time.time(),
                }
            else:
                for name in list_ifaces_fs():
                    rx, tx = read_counters(name)
                    self.ifaces[name] = {
                        "rx_total": 0.0, "tx_total": 0.0,
                        "last_rx": int(rx), "last_tx": int(tx),
                        "t": time.time(),
                    }
        self.flush(force=True)



totals =TotalsStore (TOTALS_FILE )

class PeriodStore :
    def __init__ (self ,filepath ):
        self .filepath =filepath 
        self .days ={}
        self .months ={}
        self .lock =threading .Lock ()
        self ._last_flush =0.0 
        self .flush_interval =5.0 
        self .load ()

    def load (self ):
        try :
            with open (self .filepath ,"r",encoding ="utf-8")as f :
                obj =json .load (f )
            self .days =obj .get ("days",{})
            self .months =obj .get ("months",{})
        except Exception :
            self .days ,self .months ={},{}

    def flush (self ,force =False ):
        now =time .time ()
        if not force and (now -self ._last_flush )<self .flush_interval :
            return 
        with self .lock :
            data ={"v":1 ,"days":self .days ,"months":self .months }
        try :
            tmp =self .filepath +".tmp"
            with open (tmp ,"w",encoding ="utf-8")as f :
                json .dump (data ,f )
            os .replace (tmp ,self .filepath )
            self ._last_flush =now 
        except Exception :
            pass 

    def update (self ,name ,delta_rx ,delta_tx ,t =None ):
        if t is None :
            t =time .time ()
        day =time .strftime ("%Y-%m-%d",time .localtime (t ))
        mon =time .strftime ("%Y-%m",time .localtime (t ))
        with self .lock :
            d =self .days .setdefault (day ,{})
            m =self .months .setdefault (mon ,{})
            di =d .setdefault (name ,{"rx":0 ,"tx":0 })
            mi =m .setdefault (name ,{"rx":0 ,"tx":0 })
            di ["rx"]+=int (max (0 ,delta_rx ))
            di ["tx"]+=int (max (0 ,delta_tx ))
            mi ["rx"]+=int (max (0 ,delta_rx ))
            mi ["tx"]+=int (max (0 ,delta_tx ))

    def get_scope (self ,scope ):
        with self .lock :
            if scope =="daily":
                key =time .strftime ("%Y-%m-%d",time .localtime ())
                data =self .days .get (key ,{})
            else :
                key =time .strftime ("%Y-%m",time .localtime ())
                data =self .months .get (key ,{})
            return key ,data 

class BlocksRegistry :
    def __init__ (self ,filepath ):
        self .filepath =filepath 
        self .lock =threading .Lock ()
        self .obj ={"v":1 ,"items":{}}
        self ._last_flush =0.0 
        self .flush_interval =2.0 
        self .load ()

    def load (self ):
        try :
            with open (self .filepath ,"r",encoding ="utf-8")as f :
                o =json .load (f )
            if isinstance (o ,dict )and "items"in o :
                self .obj =o 
        except Exception :
            self .obj ={"v":1 ,"items":{}}

    def flush (self ,force =False ):
        now =time .time ()
        if not force and (now -self ._last_flush )<self .flush_interval :
            return 
        with self .lock :
            data =json .loads (json .dumps (self .obj ,ensure_ascii =False ))
        tmp =self .filepath +".tmp"
        try :
            with open (tmp ,"w",encoding ="utf-8")as f :
                json .dump (data ,f ,ensure_ascii =False ,indent =2 )
            os .replace (tmp ,self .filepath )
            self ._last_flush =now 
        except Exception :
            pass 

    def _ensure_item (self ,fid ):
        it =self .obj ["items"].get (fid )
        if not it :
            it ={"id":fid ,"pattern":None ,"iface":None ,"proto":"all",
            "port":None ,"created":int (time .time ()),"show_page":False ,
            "realized":{"v4":[],"v6":[]}}
            self .obj ["items"][fid ]=it 
        if "realized"not in it :
            it ["realized"]={"v4":[],"v6":[]}
        return it 

    def upsert_from_rec (self ,rec :dict ):
        if not rec :return 
        fid =rec .get ("id")
        if not fid :return 
        with self .lock :
            it =self ._ensure_item (fid )
            it ["pattern"]=rec .get ("pattern")
            it ["iface"]=rec .get ("iface")or None 
            it ["proto"]=(rec .get ("proto")or "all").lower ()
            it ["port"]=rec .get ("port")
            it ["show_page"]=bool (rec .get ("show_page"))
            it ["created"]=int (rec .get ("created")or it .get ("created")or int (time .time ()))
            rv4 =list ((rec .get ("realized")or {}).get ("v4")or [])
            rv6 =list ((rec .get ("realized")or {}).get ("v6")or [])
            it ["realized"]["v4"]=sorted (set (it ["realized"]["v4"])|set (rv4 ))
            it ["realized"]["v6"]=sorted (set (it ["realized"]["v6"])|set (rv6 ))
        self .flush ()

    def set_realized (self ,fid :str ,v4 :list ,v6 :list ):
        with self .lock :
            it =self ._ensure_item (fid )
            it ["realized"]["v4"]=sorted (set (v4 or []))
            it ["realized"]["v6"]=sorted (set (v6 or []))
        self .flush ()

    def add_realized_ip (self ,fid :str ,fam :str ,ip :str ):
        if fam not in ("v4","v6")or not ip :return 
        with self .lock :
            it =self ._ensure_item (fid )
            arr =it ["realized"][fam ]
            if ip not in arr :
                arr .append (ip )
        self .flush ()

    def remove (self ,fid :str ):
        with self .lock :
            self .obj ["items"].pop (fid ,None )
        self .flush ()

periods =PeriodStore (PERIOD_FILE )
blocksreg =BlocksRegistry (BLOCKS_REG_FILE )

def _sync_registry_for (fid :str ):

    if not fid :
        return 
    with filters .lock :
        rec =filters .items .get (fid )
    if not rec :
        return 

    rv4 =list (((rec .get ("realized")or {}).get ("v4")or []))
    rv6 =list (((rec .get ("realized")or {}).get ("v6")or []))

    pat =(rec .get ("pattern")or "").strip ()
    if pat and _split_family (pat )is None :
        base =_registrable_domain (pat )or _normalize_domain_or_none (pat )or pat .strip ().lower ().strip (".")
        v4i ,v6i =sni_index .get_ips_for_base (base )
        rv4 =sorted (set (rv4 )|set (v4i or []))
        rv6 =sorted (set (rv6 )|set (v6i or []))

    try :
        blocksreg .upsert_from_rec (rec )
    except Exception :
        pass 
    blocksreg .set_realized (fid ,rv4 ,rv6 )

def _start_registry_autosync (interval =5.0 ):
    def loop ():
        while True :
            try :
                with filters .lock :
                    ids =[it .get ("id")for it in (filters .items or {}).values ()if it and it .get ("id")]
                for fid in ids :
                    _sync_registry_for (fid )
            except Exception as e :
                print ("[netdash] autosync warn:",e )
            time .sleep (interval )
    threading .Thread (target =loop ,daemon =True ).start ()

class NetMonitor :
    def __init__ (self ,poll_interval =1.0 ):
        self .poll =poll_interval 
        self .prev ={}
        self .data ={}
        self .lock =threading .Lock ()
        self .running =False 

    def _loop (self ):
        while self .running :
            now =time .time ()
            ifaces =list_ifaces_fs ()
            with self .lock :
                for iface in ifaces :
                    rx ,tx =read_counters (iface )
                    old =self .prev .get (iface )
                    if old :
                        rx0 ,tx0 ,t0 =old 
                        dt =max (1e-6 ,now -t0 )
                        rx_bps =max (0.0 ,(rx -rx0 )/dt )
                        tx_bps =max (0.0 ,(tx -tx0 )/dt )
                        delta_rx =(rx -rx0 )if rx >=rx0 else rx 
                        delta_tx =(tx -tx0 )if tx >=tx0 else tx 
                    else :
                        rx_bps =tx_bps =0.0 
                        delta_rx =delta_tx =0 
                    self .prev [iface ]=(rx ,tx ,now )

                    rx_total ,tx_total =totals .update (iface ,rx ,tx )

                    self .data [iface ]={
                    "rx_bps":rx_bps ,"tx_bps":tx_bps ,
                    "rx_bytes":rx ,"tx_bytes":tx ,
                    "rx_total":rx_total ,"tx_total":tx_total ,
                    "ts":now 
                    }
                    history .add (iface ,now ,rx_bps ,tx_bps )
                    periods .update (iface ,delta_rx ,delta_tx ,now )
            history .flush ()
            totals .flush ()
            periods .flush ()
            time .sleep (self .poll )

    def start (self ):
        if self .running :
            return 
        self .running =True 
        threading .Thread (target =self ._loop ,daemon =True ).start ()

    def snapshot (self ):
        with self .lock :
            return {"ts":time .time (),"rates":dict (self .data )}

monitor =NetMonitor (POLL_INTERVAL )
monitor.start()


def _find_ip_binary ():
    for p in ("/usr/sbin/ip","/sbin/ip","/usr/bin/ip","ip"):
        if os .path .isabs (p )and os .path .exists (p ):
            return p 
    return "ip"

def _require_token ():
    if CONTROL_TOKEN :
        tok =request .headers .get ("X-Auth-Token","")
        if tok !=CONTROL_TOKEN :
            abort (401 ,description ="Invalid token")

def iface_action (iface :str ,action :str ):
    if not can_control (iface ):
        abort (403 ,description ="Interface not permitted")
    _require_token ()
    ipbin =_find_ip_binary ()
    cmd =[ipbin ,"link","set","dev",iface ,"down"if action =="down"else "up"]
    if os .geteuid ()!=0 :
        cmd =["sudo","-n"]+cmd 
    try :
        subprocess .check_call (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
        time .sleep (0.2 )
        return {"ok":True ,"iface":iface ,"action":action }
    except subprocess .CalledProcessError as e :
        return {"ok":False ,"error":f"ip failed ({e})","iface":iface ,"action":action },500 

class PingMonitor :
    def __init__ (self ,targets =None ,interval =5.0 ,window =50 ,timeout =1.2 ):
        if targets is None :
            env =os .environ .get ("NETDASH_PING_TARGETS","1.1.1.1,8.8.8.8,9.9.9.9")
            targets =[t .strip ()for t in env .split (",")if t .strip ()]
        self .targets =targets 
        self .interval =float (os .environ .get ("NETDASH_PING_INTERVAL",str (interval )))
        self .window =int (os .environ .get ("NETDASH_PING_WINDOW",str (window )))
        self .timeout =timeout 
        self .stats ={t :{"rtt":deque (maxlen =self .window ),"sent":0 ,"recv":0 ,"last":None }for t in self .targets }
        self .lock =threading .Lock ()
        self .running =False 

    def _ping_once (self ,target ):

        for cmd in (
        ["ping","-n","-c","1","-w","1",target ],
        ["ping","-n","-c","1","-W","1",target ],
        ):
            try :
                out =subprocess .check_output (cmd ,stderr =subprocess .STDOUT ,text =True ,timeout =self .timeout )
            except subprocess .CalledProcessError as e :
                out =e .output or ""
            except subprocess .TimeoutExpired :
                return None 

            m =re .search (r"time[=<]\s*([0-9.]+)\s*ms",out )
            if m :
                return float (m .group (1 ))
        return None 

    def _loop (self ):
        while self .running :
            with self .lock :
                targets =list (self .targets )
            for t in targets :
                rtt =self ._ping_once (t )
                with self .lock :
                    st =self .stats [t ]
                    st ["sent"]+=1 
                    st ["last"]=time .time ()
                    if rtt is not None :
                        st ["recv"]+=1 
                        st ["rtt"].append (float (rtt ))
            time .sleep (self .interval )

    def start (self ):
        if self .running :return 
        self .running =True 
        threading .Thread (target =self ._loop ,daemon =True ).start ()

    def snapshot (self ):
        out ={}
        with self .lock :
            for t ,st in self .stats .items ():
                arr =list (st ["rtt"])
                avg =sum (arr )/len (arr )if arr else 0.0 
                p95 =sorted (arr )[int (0.95 *(len (arr )-1 ))]if arr else 0.0 
                mx =max (arr )if arr else 0.0 
                loss =0.0 
                if st ["sent"]>0 :
                    loss =max (0.0 ,100.0 *(1.0 -(st ["recv"]/st ["sent"])))
                out [t ]={"avg":avg ,"p95":p95 ,"max":mx ,"loss":loss ,"n":len (arr )}
        return out 


pingmon =PingMonitor ()
pingmon .start ()


def _conntrack_acct_enabled() -> bool:
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_acct","r") as f:
            return f.read().strip() == "1"
    except Exception:
        return False

def _enable_conntrack_acct_if_possible():
    if _conntrack_acct_enabled():
        return
    # تلاش ملایم برای فعال‌سازی
    try:
        cmd = ["sysctl","-w","net.netfilter.nf_conntrack_acct=1"]
        if os.geteuid()!=0: cmd = ["sudo","-n"] + cmd
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def _conntrack_lines():
    cmd = ["conntrack","-L","-o","extended"]
    if os.geteuid()!=0: cmd = ["sudo","-n"] + cmd
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=3.5)
        return out.splitlines()
    except Exception:
        return []




class PortsMonitor:
    def __init__(self, interval=1.0, max_ports=1000):
        self.interval = float(interval)
        self.prev_flows = {}
        self.totals = {}      # (proto,port) -> {"rx_total":int, "tx_total":int}
        self.rates  = {}
        self.lock = threading.Lock()
        self.running = False
        self.max_ports = max_ports
        # persist
        self.totals_file = PORTS_TOTALS_FILE
        self._last_flush = 0.0
        self.flush_interval = 5.0
        self._load_totals()   # ← مجموع‌های قبلی را از دیسک برگردان

    def _key_to_str(self, proto, port):
        return f"{proto}:{int(port)}"

    def _str_to_key(self, s):
        proto, p = s.split(":", 1)
        return (proto, int(p))

    def _load_totals(self):
        try:
            with open(self.totals_file, "r", encoding="utf-8") as f:
                raw = json.load(f) or {}
            tots = {}
            for k, v in raw.items():
                proto, port = self._str_to_key(k)
                tots[(proto, port)] = {
                    "rx_total": int(v.get("rx_total", 0)),
                    "tx_total": int(v.get("tx_total", 0)),
                }
            with self.lock:
                self.totals = tots
        except Exception:
            pass

    def _parse(self, line):
        """
        خروجی نمونه conntrack -L -o extended:
        tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=1.2.3.4 sport=51234 dport=443 packets=12 bytes=3456 ...
                                        src=1.2.3.4 dst=10.0.0.2 sport=443   dport=51234 packets=10 bytes=7890 ...
        """
        try:
            mproto = re.match(r'^(\w+)\s', line)
            if not mproto:
                return None
            proto = mproto.group(1).lower()

            # dport جریان اصلی
            mdport = re.search(r'\bdport=(\d+)', line)
            if not mdport:
                return None
            port = int(mdport.group(1))

            # bytes برای orig و reply (اولی orig، دومی reply)
            bytes_vals = re.findall(r'\bbytes=(\d+)', line)
            if not bytes_vals:
                return None
            ob = int(bytes_vals[0])
            rb = int(bytes_vals[1]) if len(bytes_vals) > 1 else 0

            # کلید یکتای جریان
            mflow = re.search(
                r'src=([0-9a-fA-F:.]+)\s+dst=([0-9a-fA-F:.]+)\s+sport=(\d+)\s+dport=(\d+)',
                line
            )
            if mflow:
                fkey = (proto, mflow.group(1), mflow.group(2), int(mflow.group(3)), int(mflow.group(4)))
            else:
                fkey = (proto, port, ob, rb)  # fallback

            pkey = (proto, port)
            return (fkey, pkey, ob, rb)
        except Exception:
            return None


    def _flush_totals(self, force=False):
        now = time.time()
        if not force and (now - self._last_flush) < self.flush_interval:
            return
        try:
            with self.lock:
                dump = { self._key_to_str(proto, port): vals
                         for (proto, port), vals in self.totals.items() }
            tmp = self.totals_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(dump, f)
            os.replace(tmp, self.totals_file)
            self._last_flush = now
        except Exception:
            pass

    def reset_totals(self):
        with self.lock:
            self.totals.clear()
        self._flush_totals(force=True)

    def _loop(self):
        while self.running:
            t1=time.time()
            lines=_conntrack_lines(); now=time.time()
            from collections import defaultdict
            port_rx=defaultdict(int); port_tx=defaultdict(int); port_flows=defaultdict(int)
            new_prev={}
            for ln in lines:
                parsed=self._parse(ln)
                if not parsed: continue
                fkey, pkey, ob, rb = parsed
                port_flows[pkey]+=1
                old=self.prev_flows.get(fkey)
                if not old:
                    new_prev[fkey]=(ob,rb,now); continue
                ob0,rb0,t0=old
                dob = ob - ob0 if ob >= ob0 else ob
                drb = rb - rb0 if rb >= rb0 else rb
                port_tx[pkey]+=max(0,dob)
                port_rx[pkey]+=max(0,drb)
                new_prev[fkey]=(ob,rb,now)
            with self.lock:
                self.prev_flows=new_prev
                self.rates.clear()
                for pkey in set(list(port_rx.keys())+list(port_tx.keys())):
                    rx_bps = port_rx[pkey] / max(1e-6, self.interval)
                    tx_bps = port_tx[pkey] / max(1e-6, self.interval)
                    self.rates[pkey]={"rx_bps":rx_bps,"tx_bps":tx_bps,"flows":port_flows.get(pkey,0)}
                    tot=self.totals.setdefault(pkey,{"rx_total":0,"tx_total":0})
                    tot["rx_total"]+=port_rx[pkey]
                    tot["tx_total"]+=port_tx[pkey]
            elapsed=time.time()-t1
            time.sleep(max(0.0, self.interval - elapsed))

    def start(self):
        if self.running: return
        _enable_conntrack_acct_if_possible()
        self.running=True
        threading.Thread(target=self._loop, daemon=True).start()

    def snapshot(self):
        with self.lock:
            rows=[]
            for (proto, port), r in self.rates.items():
                tot=self.totals.get((proto,port),{"rx_total":0,"tx_total":0})
                rows.append({
                    "proto":proto,"port":port,
                    "rx_bps":r["rx_bps"],"tx_bps":r["tx_bps"],
                    "rx_total":tot["rx_total"],"tx_total":tot["tx_total"],
                    "flows":r["flows"]
                })
            rows.sort(key=lambda x:(x["rx_bps"]+x["tx_bps"]), reverse=True)
            return {"ts": time.time(), "ports": rows[:self.max_ports]}

# instantiate & start
portsmon = PortsMonitor(interval=PORTS_POLL_INTERVAL)
if PORTS_MONITOR_ENABLED:
    try:
        portsmon.start()
        print(f"[netdash] Ports monitor started (interval={PORTS_POLL_INTERVAL}s)")
    except Exception as e:
        print("[netdash] ports monitor disabled:", e)

@app.route("/api/ports/reset", methods=["POST"])
def api_ports_reset():
    _require_token()
    try:
        portsmon.reset_totals()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/totals/reset", methods=["POST"])
def api_totals_reset():
    _require_token()
    try:
        data = request.get_json(silent=True) or {}
        iface = (data.get("iface") or "").strip() or None
        totals.reset(iface=iface)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



@app.route("/api/ports/live", endpoint="ports_live_api")
def api_ports_live_view():
    if not PORTS_MONITOR_ENABLED:
        return jsonify({"ok": False, "reason": "disabled"}), 503
    try:
        return jsonify(portsmon.snapshot())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500




def _run_root (cmd ):
    c =cmd [:]
    if os .geteuid ()!=0 :
        c =["sudo","-n"]+c 
    try :
        subprocess .check_call (c ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
        return 0 
    except subprocess .CalledProcessError :
        return 1 

def _ipt_ensure (args ,table =None ,v6 =False ):
    base =["ip6tables"]if v6 else ["iptables"]
    if table :
        base +=["-t",table ]
    check =base +["-C"]+args 
    insert =base +["-I"]+args 
    if _run_root (check )!=0 :
        _run_root (insert )

def _iface_suffix (iface :str |None )->str :
    if not iface :
        return ""
    s =re .sub (r'[^a-zA-Z0-9_.-]+','-',str (iface ))
    return "__"+s 

def _ipset_names_for (obj ,show_page :bool |None =None ):
    if isinstance (obj ,dict ):
        iface =obj .get ("iface")or None 
        sp =obj .get ("show_page",False )if show_page is None else bool (show_page )
    else :
        iface =obj or None 
        sp =bool (show_page )
    sfx =_iface_suffix (iface )
    if sp and PAGE_MODE_ENABLED :
        return f"{IPSET4P}{sfx}",f"{IPSET6P}{sfx}"
    return f"{IPSET4}{sfx}",f"{IPSET6}{sfx}"

def ensure_ipset_and_rules_for_iface (iface :str ,show_page :bool ):
    set4 ,set6 =_ipset_names_for (iface ,show_page )
    _run_root (["ipset","create",set4 ,"hash:net","family","inet","timeout",str (IPSET_TIMEOUT ),"-exist"])
    _run_root (["ipset","create",set6 ,"hash:net","family","inet6","timeout",str (IPSET_TIMEOUT ),"-exist"])

    _ipt_ensure (["FORWARD","-o",iface ,"-m","set","--match-set",set4 ,"dst","-j","DROP"])
    _ipt_ensure (["OUTPUT","-o",iface ,"-m","set","--match-set",set4 ,"dst","-j","DROP"])
    _ipt_ensure (["FORWARD","-o",iface ,"-m","set","--match-set",set6 ,"dst","-j","DROP"],v6 =True )
    _ipt_ensure (["OUTPUT","-o",iface ,"-m","set","--match-set",set6 ,"dst","-j","DROP"],v6 =True )

    if PAGE_MODE_ENABLED and show_page :
        _ipt_ensure (["OUTPUT","-p","tcp","-o",iface ,"-m","set","--match-set",set4 ,
        "dst","--dport","80","-j","REDIRECT","--to-ports",str (BLOCK_PORT )],table ="nat")
        _ipt_ensure (["OUTPUT","-p","tcp","-o",iface ,"-m","set","--match-set",set6 ,
        "dst","--dport","80","-j","REDIRECT","--to-ports",str (BLOCK_PORT )],table ="nat",v6 =True )

def ensure_ipset_and_rules ():

    _run_root (["ipset","create",IPSET4 ,"hash:net","family","inet","timeout",str (IPSET_TIMEOUT ),"-exist"])
    _run_root (["ipset","create",IPSET6 ,"hash:net","family","inet6","timeout",str (IPSET_TIMEOUT ),"-exist"])
    _run_root (["ipset","create",IPSET4P ,"hash:net","family","inet","timeout",str (IPSET_TIMEOUT ),"-exist"])
    _run_root (["ipset","create",IPSET6P ,"hash:net","family","inet6","timeout",str (IPSET_TIMEOUT ),"-exist"])

    _ipt_ensure (["FORWARD","-m","set","--match-set",IPSET4 ,"dst","-j","DROP"])
    _ipt_ensure (["OUTPUT","-m","set","--match-set",IPSET4 ,"dst","-j","DROP"])
    _ipt_ensure (["FORWARD","-m","set","--match-set",IPSET6 ,"dst","-j","DROP"],v6 =True )
    _ipt_ensure (["OUTPUT","-m","set","--match-set",IPSET6 ,"dst","-j","DROP"],v6 =True )

    if PAGE_MODE_ENABLED :
        for ch in ("OUTPUT","PREROUTING"):
            _ipt_ensure ([ch ,"-p","tcp","-m","set","--match-set",IPSET4P ,"dst","--dport","80","-j","REDIRECT","--to-ports",str (BLOCK_PORT )],table ="nat")
            _ipt_ensure ([ch ,"-p","tcp","-m","set","--match-set",IPSET6P ,"dst","--dport","80","-j","REDIRECT","--to-ports",str (BLOCK_PORT )],table ="nat",v6 =True )
    else :
        _ipt_ensure (["FORWARD","-m","set","--match-set",IPSET4P ,"dst","-j","DROP"])
        _ipt_ensure (["OUTPUT","-m","set","--match-set",IPSET4P ,"dst","-j","DROP"])
        _ipt_ensure (["FORWARD","-m","set","--match-set",IPSET6P ,"dst","-j","DROP"],v6 =True )
        _ipt_ensure (["OUTPUT","-m","set","--match-set",IPSET6P ,"dst","-j","DROP"],v6 =True )

def _dnsmasq_hup ():

    if _run_root (["pkill","-HUP","dnsmasq"])!=0 :
        _run_root (["systemctl","reload","dnsmasq"])

def _is_private_ipv4_cidr (cidr ):
    try :
        net =ipaddress .ip_network (cidr ,strict =False )
        return net .version ==4 and (net .is_private or str (net ).startswith ("100.64."))
    except Exception :
        return False 

def _lan_ifaces_guess ():
    lans =[]
    try :
        for it in get_interfaces_info ():
            if not it .get ("is_up"):
                continue 
            n =it .get ("name","")
            if n .startswith ("lo"):
                continue 
            addrs =it .get ("addresses")or []
            if any (_is_private_ipv4_cidr (a .get ("cidr",""))for a in addrs ):
                lans .append (n )
    except Exception :
        pass 
    return lans 

def _ensure_dns_redirection ():

    for lan in _lan_ifaces_guess ():
        for proto in ("udp","tcp"):

            _ipt_ensure (
            ["PREROUTING","-i",lan ,"-p",proto ,"--dport","53",
            "-j","REDIRECT","--to-ports","53"],
            table ="nat"
            )

            _ipt_ensure (
            ["PREROUTING","-i",lan ,"-p",proto ,"--dport","53",
            "-j","REDIRECT","--to-ports","53"],
            table ="nat",
            v6 =True 
            )

def _ensure_block_dot():
    for v6 in (False, True):
        for ch in ("OUTPUT","FORWARD"):
            _ipt_ensure([ch,"-p","tcp","--dport","853","-j","REJECT"], v6=v6)
            _ipt_ensure([ch,"-p","udp","--dport","8853","-j","REJECT"], v6=v6)  # DoQ


DEFAULT_BLOCKS =[

"instagram.com","cdninstagram.com","facebook.com","facebook.net","fbcdn.net",
"whatsapp.com","whatsapp.net",

"dns.google","cloudflare-dns.com","one.one.one.one","quad9.net","dns.quad9.net",
"adguard-dns.com","nextdns.io","dns.nextdns.io","dns.sb","doh.opendns.com"
]

def _preload_blocklist ():
    existing =set ()
    with filters .lock :
        existing ={(it or {}).get ("pattern","").strip ().lower ()for it in (filters .items or {}).values ()}
    for dom in DEFAULT_BLOCKS :
        if dom not in existing :
            try :

                filters .add (dom ,show_page =False )
            except Exception as e :
                print ("[netdash] preload add failed:",dom ,e )

def _prime_dnsmasq_for_items (items_dict ):
    domains =set ()
    for it in items_dict .values ():
        if (it or {}).get ("iface"):
            continue 
        pat =(it or {}).get ("pattern","").strip ()
        if pat and _split_family (pat )is None :
            domains .add (pat )

    def _prime_one (dom ,qtype ):
        cmds =[
        ["dig","+short",qtype ,dom ,"@127.0.0.1"],
        ["drill","-Q",dom ,qtype ,"@127.0.0.1"],
        ["host","-t",qtype ,dom ,"127.0.0.1"],
        ]
        for cmd in cmds :
            try :
                subprocess .run (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL ,timeout =2 )
                return 
            except Exception :
                continue 

    time .sleep (0.1 )
    for d in domains :
        _prime_one (d ,"A")
        _prime_one (d ,"AAAA")

def _rebuild_dnsmasq_conf_from_items (items_dict ):
    lines =[]
    for it in items_dict .values ():
        pat =(it or {}).get ("pattern","").strip ()

        if (it or {}).get ("iface"):
            continue 

        fam =_split_family (pat )
        if fam is None and pat :
            dom =_normalize_domain_or_none (pat )
            if not dom :
                continue 
            variants =_domain_variants (dom )
            if PAGE_MODE_ENABLED and it .get ("show_page"):
                for v in variants :
                    lines .append (f"ipset=/{v}/{IPSET4P}")
                    lines .append (f"ipset=/{v}/{IPSET6P}")
            else :
                for v in variants :
                    lines .append (f"ipset=/{v}/{IPSET4}")
                    lines .append (f"ipset=/{v}/{IPSET6}")

    content ="# netdash dynamic blocklist\n"+"\n".join (lines )+("\n"if lines else "")
    try :
        os .makedirs (os .path .dirname (DNSMASQ_CONF ),exist_ok =True )
    except Exception :
        pass 
    try :
        tmp =DNSMASQ_CONF +".tmp"
        with open (tmp ,"w",encoding ="utf-8")as f :
            f .write (content )
        os .replace (tmp ,DNSMASQ_CONF )
    except Exception as e :
        print ("[netdash] dnsmasq conf write failed:",e )
        return 

    _dnsmasq_hup ()
    _prime_dnsmasq_for_items (items_dict )

def _preseed_ipset_from_index (domain :str ,show_page :bool ):
    base =_registrable_domain (domain )or _normalize_domain_or_none (domain )or domain .strip ().lower ().strip (".")
    if not base :
        return 
    v4 ,v6 =sni_index .get_ips_for_base (base )
    set4 =IPSET4P if (show_page and PAGE_MODE_ENABLED )else IPSET4 
    set6 =IPSET6P if (show_page and PAGE_MODE_ENABLED )else IPSET6 
    for ip in v4 :
        _run_root (["ipset","add",set4 ,ip ,"timeout",str (IPSET_TIMEOUT ),"-exist"])
        print (f"[netdash] preseed: {ip} -> {set4} (base={base})")
    for ip in v6 :
        _run_root (["ipset","add",set6 ,ip ,"timeout",str (IPSET_TIMEOUT ),"-exist"])
        print (f"[netdash] preseed: {ip} -> {set6} (base={base})")

def _preseed_ipset_from_index_for (rec :dict ):
    pat =(rec or {}).get ("pattern","").strip ()
    iface =(rec or {}).get ("iface")or None 
    if not pat or not iface :return 
    base =_registrable_domain (pat )or _normalize_domain_or_none (pat )or pat .strip ().lower ().strip (".")
    if not base :return 
    set4 ,set6 =_ipset_names_for (rec )
    ensure_ipset_and_rules_for_iface (iface ,bool (rec .get ("show_page")))
    v4 ,v6 =sni_index .get_ips_for_base (base )
    for ip in v4 :_run_root (["ipset","add",set4 ,ip ,"timeout",str (IPSET_TIMEOUT ),"-exist"])
    for ip in v6 :_run_root (["ipset","add",set6 ,ip ,"timeout",str (IPSET_TIMEOUT ),"-exist"])

def _hostname_matches (host :str ,base :str )->bool :
    try :
        host =(host or "").strip ().lower ().strip (".")
        base =_normalize_domain_or_none (base )or (base or "").strip ().lower ()
        if not host or not base :
            return False 
        return host ==base or host .endswith ("."+base )
    except Exception :
        return False 

def _extract_sni_from_clienthello (data :bytes ):
    try :
        if not data or len (data )<5 :
            return None 

        if data [0 ]!=22 :
            return None 
        p =5 
        if len (data )<p +4 or data [p ]!=1 :
            return None 
        hs_len =int .from_bytes (data [p +1 :p +4 ],"big")
        p +=4 
        if len (data )<p +hs_len :
            return None 

        p +=2 +32 
        if len (data )<p +1 :return None 
        sid_len =data [p ];p +=1 +sid_len 
        if len (data )<p +2 :return None 
        cs_len =int .from_bytes (data [p :p +2 ],"big");p +=2 +cs_len 
        if len (data )<p +1 :return None 
        cm_len =data [p ];p +=1 +cm_len 
        if len (data )<p +2 :return None 
        ext_len =int .from_bytes (data [p :p +2 ],"big");p +=2 
        end =min (len (data ),p +ext_len )
        while p +4 <=end :
            etype =int .from_bytes (data [p :p +2 ],"big");p +=2 
            elen =int .from_bytes (data [p :p +2 ],"big");p +=2 
            if etype ==0 :
                if p +2 >len (data ):return None 
                list_len =int .from_bytes (data [p :p +2 ],"big");p +=2 
                q =p 
                while q +3 <=len (data )and q <p +list_len :
                    nt =data [q ];q +=1 
                    nl =int .from_bytes (data [q :q +2 ],"big");q +=2 
                    if nt ==0 and q +nl <=len (data ):
                        try :
                            return data [q :q +nl ].decode ("idna").lower ()
                        except Exception :
                            try :return data [q :q +nl ].decode ().lower ()
                            except Exception :return None 
                    q +=nl 
                return None 
            else :
                p +=elen 
        return None 
    except Exception :
        return None 

def _flush_all_ipsets ():
    for name in (IPSET4 ,IPSET6 ,IPSET4P ,IPSET6P ):
        try :
            _run_root (["ipset","flush",name ])
        except Exception :
            pass 

def _del_domain_from_iface_sets (rec :dict ):
    pat =(rec or {}).get ("pattern","").strip ()
    iface =(rec or {}).get ("iface")or None 
    if not pat or not iface :return 
    base =_domain_base (pat )
    if not base :return 
    v4 ,v6 =_collect_ips_for_base (base ,rec )
    set4 ,set6 =_ipset_names_for (rec )
    for ip in v4 :
        try :_run_root (["ipset","del",set4 ,ip ])
        except Exception :pass 
    for ip in v6 :
        try :_run_root (["ipset","del",set6 ,ip ])
        except Exception :pass 

def _del_domain_everywhere (rec ):
    try :
        pat =(rec or {}).get ("pattern","").strip ()
        if not pat :
            return 
        base =_registrable_domain (pat )or _normalize_domain_or_none (pat )or pat .strip ().lower ().strip (".")
        if not base :
            return 

        v4_idx ,v6_idx =sni_index .get_ips_for_base (base )

        v4_real =set (((rec .get ("realized")or {}).get ("v4")or []))
        v6_real =set (((rec .get ("realized")or {}).get ("v6")or []))

        v4_now ,v6_now =_resolve_domain (base )

        v4_all =sorted (set (v4_idx )|v4_real |set (v4_now ))
        v6_all =sorted (set (v6_idx )|v6_real |set (v6_now ))

        for ip in v4_all :
            _run_root (["ipset","del",IPSET4 ,ip ])
            _run_root (["ipset","del",IPSET4P ,ip ])
        for ip in v6_all :
            _run_root (["ipset","del",IPSET6 ,ip ])
            _run_root (["ipset","del",IPSET6P ,ip ])
    except Exception as e :
        print ("[netdash] purge domain failed:",e )

def _del_domain_from_ipsets (domain :str ,show_page :bool ):
    v4 ,v6 =_resolve_domain (domain )
    sets =[]
    if show_page :
        sets =[(IPSET4P ,v4 ),(IPSET6P ,v6 )]
    else :
        sets =[(IPSET4 ,v4 ),(IPSET6 ,v6 )]
    for setname ,arr in sets :
        for ip in arr :
            try :
                _run_root (["ipset","del",setname ,ip ])
            except Exception :
                pass 

def _iptables_bin (ipv6 =False ):
    candidates =("/usr/sbin/iptables","/sbin/iptables","/usr/bin/iptables","iptables")if not ipv6 else ("/usr/sbin/ip6tables","/sbin/ip6tables","/usr/bin/ip6tables","ip6tables")
    for p in candidates :
        if os .path .isabs (p )and os .path .exists (p ):
            return p 
    return candidates [-1 ]

def _sudo_wrap (cmd ):
    if os .geteuid ()!=0 :
        return ["sudo","-n"]+cmd 
    return cmd 

def _is_ip_or_cidr (s ):
    try :
        ipaddress .ip_network (s ,strict =False )
        return True 
    except Exception :
        try :
            ipaddress .ip_address (s )
            return True 
        except Exception :
            return False 

def _split_family (s ):
    try :
        net =ipaddress .ip_network (s ,strict =False )
        return 'v6'if net .version ==6 else 'v4'
    except Exception :
        try :
            addr =ipaddress .ip_address (s )
            return 'v6'if addr .version ==6 else 'v4'
        except Exception :
            return None 

def _resolve_domain (name ):
    v4 ,v6 =set (),set ()
    try :
        infos =socket .getaddrinfo (name ,None )
        for fam ,_ ,_ ,_ ,sockaddr in infos :
            if fam ==socket .AF_INET :
                v4 .add (sockaddr [0 ])
            elif fam ==socket .AF_INET6 :
                v6 .add (sockaddr [0 ])
    except Exception :
        pass 
    return list (v4 ),list (v6 )

def _normalize_domain_or_none (pat :str ):
    s =(pat or "").strip ().lower ()
    s =re .sub (r'^[a-z]+://','',s )
    s =s .split ('/',1 )[0 ]
    s =s .split (':',1 )[0 ]
    if s .startswith ('*.'):
        s =s [2 :]
    s =s .strip ('.')
    if not s or '.'not in s :
        return None 
    if not re .fullmatch (r'[0-9a-z.-]+',s ):
        pass 
    return s 

def _domain_variants (dom :str ):
    out =set ()
    try :
        puny =dom .encode ('idna').decode ('ascii')
    except Exception :
        puny =dom 
    for d in {dom ,puny }:
        d =d .strip ('.')
        out .add (d )
        out .add ('.'+d )
    return out 

def _mk_rule_cmds (dst_ip ,chain ,iface =None ,proto ="all",port =None ,ipv6 =False ):
    binp =_iptables_bin (ipv6 )
    base =[binp ,"-I",chain ]
    if iface :
        base +=["-o",iface ]
    if proto and proto .lower ()!="all":
        base +=["-p",proto .lower ()]
        if port and str (port ).isdigit ():
            base +=["--dport",str (int (port ))]
    base +=["-d",str (dst_ip ),"-j","DROP"]
    return _sudo_wrap (base )

def _del_equivalent (cmd ):
    out =cmd [:]
    try :
        i =out .index ("-I")
        out [i ]="-D"
    except ValueError :

        out =[out [0 ],"-D"]+out [2 :]
    return out 

def _chk_equivalent (cmd ):
    out =cmd [:]
    try :
        i =out .index ("-I")
        out [i ]="-C"
    except ValueError :
        out =[out [0 ],"-C"]+out [2 :]
    return out 

def _mk_nat_redirect_http_cmd (dst_ip ,chain ,ipv6 =False ):
    binp =_iptables_bin (ipv6 )
    base =[binp ,"-t","nat","-I",chain ,"-p","tcp","-d",str (dst_ip ),"--dport","80",
    "-j","REDIRECT","--to-ports",str (BLOCK_PORT )]
    return _sudo_wrap (base )

def _apply_nat_redirect (dst ,chain ,ipv6 ):
    cmd =_mk_nat_redirect_http_cmd (dst ,chain ,ipv6 =ipv6 )
    try :
        subprocess .check_call (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
        return {"cmd":cmd ,"chain":chain ,"ipv6":bool (ipv6 )}
    except subprocess .CalledProcessError :
        return None 

def _normalize_domain (pat :str )->str :
    d =_normalize_domain_or_none (pat )
    return d if d is not None else (pat or "").strip ().lower ()

def _add_sni_rules_for_domain (domain :str ,iface :str |None =None ):
    rules =[]
    dom =_normalize_domain (domain )
    if not dom :
        return rules 
    for ipv6 in (False ,True ):
        binp =_iptables_bin (ipv6 )
        for chain in ("FORWARD","OUTPUT"):
            cmd_insert =[binp ,"-I",chain ]
            if iface :
                cmd_insert +=["-o",iface ]
            cmd_insert +=[
            "-p","tcp","--dport","443",
            "-m","conntrack","--ctstate","NEW",
            "-m","string","--string",dom ,"--algo","bm","--icase",
            "-j","DROP"
            ]
            cmd_check =_chk_equivalent (cmd_insert )
            if _run_root (_sudo_wrap (cmd_check ))==0 :
                continue 
            if _run_root (_sudo_wrap (cmd_insert ))==0 :
                rules .append ({"cmd":cmd_insert ,"chain":chain ,"ipv6":ipv6 })
    return rules 

def _del_rule_obj (r ):
    cmd =(r or {}).get ("cmd")or []
    if not cmd :
        return 
    dcmd =_del_equivalent (cmd )
    _run_root (_sudo_wrap (dcmd ))

def _domain_base (s :str )->str |None :
    s =(s or "").strip ()
    base =_registrable_domain (s )or _normalize_domain_or_none (s )or s .strip ().lower ().strip (".")
    return base if base and "."in base else None 

def _iter_other_blocked_domains (except_id =None ,except_base =None ):
    try :
        with filters .lock :
            for rec in (filters .items or {}).values ():
                if not isinstance (rec ,dict ):
                    continue 
                if except_id and rec .get ("id")==except_id :
                    continue 
                pat =(rec .get ("pattern")or "").strip ()
                if not pat or _split_family (pat )is not None :
                    continue 
                base =_domain_base (pat )
                if not base :
                    continue 
                if except_base and base ==except_base :
                    continue 
                yield base ,rec 
    except Exception :
        return 

def _collect_ips_for_base (base :str ,rec :dict |None =None ):
    v4s ,v6s =set (),set ()

    try :
        v4i ,v6i =sni_index .get_ips_for_base (base )
        v4s .update (v4i or [])
        v6s .update (v6i or [])
    except Exception :
        pass 

    try :
        v4d ,v6d =_resolve_domain (base )
        v4s .update (v4d or [])
        v6s .update (v6d or [])
    except Exception :
        pass 

    if rec :
        try :
            v4s .update ((rec .get ("realized",{})or {}).get ("v4",[])or [])
            v6s .update ((rec .get ("realized",{})or {}).get ("v6",[])or [])
        except Exception :
            pass 
    return sorted (v4s ),sorted (v6s )

def _ip_needed_by_other_blocks (ip :str ,fam :str ,*,except_id =None ,except_base =None )->bool :
    for obase ,orec in _iter_other_blocked_domains (except_id =except_id ,except_base =except_base ):
        v4o ,v6o =_collect_ips_for_base (obase ,orec )
        if fam =="v4"and ip in v4o :
            return True 
        if fam =="v6"and ip in v6o :
            return True 
    return False 

def _del_ip_from_all_sets (ip :str ,fam :str ):
    if fam =="v4":
        for setname in (IPSET4 ,IPSET4P ):
            try :_run_root (["ipset","del",setname ,ip ])
            except Exception :pass 
    else :
        for setname in (IPSET6 ,IPSET6P ):
            try :_run_root (["ipset","del",setname ,ip ])
            except Exception :pass 

def _del_domain_everywhere_safe (rec :dict ):
    try :
        pat =(rec .get ("pattern")or "").strip ()
        base =_domain_base (pat )
        if not base :
            return 
        v4 ,v6 =_collect_ips_for_base (base ,rec )

        for ip in v4 :
            if not _ip_needed_by_other_blocks (ip ,"v4",except_id =rec .get ("id"),except_base =base ):
                _del_ip_from_all_sets (ip ,"v4")

        for ip in v6 :
            if not _ip_needed_by_other_blocks (ip ,"v6",except_id =rec .get ("id"),except_base =base ):
                _del_ip_from_all_sets (ip ,"v6")
    except Exception as e :
        print ("[netdash] safe-del error:",e )

class FilterStore :
    def __init__ (self ,path ):
        self .path =path 
        self .items ={}
        self .lock =threading .Lock ()
        self .load ()

    def load (self ):
        try :
            with open (self .path ,"r",encoding ="utf-8")as f :
                obj =json .load (f )
            raw_items =obj .get ("items",{})
        except Exception :
            raw_items ={}

        items ={}
        if isinstance (raw_items ,list ):
            for it in raw_items :
                rid =(it or {}).get ("id")or uuid .uuid4 ().hex [:12 ]
                it ["id"]=rid 
                items [rid ]=it 
        elif isinstance (raw_items ,dict ):
            for k ,v in (raw_items or {}).items ():
                rid =(v or {}).get ("id")or str (k )
                v ["id"]=rid 
                items [rid ]=v 

        with self .lock :
            self .items =items 

        try :
            for _rec in items .values ():
                blocksreg .upsert_from_rec (_rec )
                _sync_registry_for (_rec ["id"])

        except Exception :
            pass 

        if USE_DNSMASQ_IPSET :
            ensure_ipset_and_rules ()
            _rebuild_dnsmasq_conf_from_items (self .items )

            try :
                for _rec in items .values ():
                    if (_rec or {}).get ("iface"):
                        ensure_ipset_and_rules_for_iface (_rec ["iface"],bool (_rec .get ("show_page")))
            except Exception as e :
                print ("[netdash] per-iface ensure warn:",e )

            try :
                has_domains =any (_split_family ((v or {}).get ("pattern",""))is None for v in self .items .values ())
                if not has_domains :
                    _flush_all_ipsets ()
            except Exception :
                pass 

            if SNI_BLOCK_ENABLED :
                for rec in self .items .values ():
                    pat =(rec or {}).get ("pattern","").strip ()
                    if pat and _split_family (pat )is None :
                        try :
                            rec ["sni_rules"]=_add_sni_rules_for_domain (pat ,iface =(rec .get ("iface")or None ))

                        except Exception as e :
                            print (f"[netdash] SNI add failed for {pat}: {e}")
                self .flush ()
        else :

            for rec in list (items .values ()):
                for r in rec .get ("rules",[]):
                    cmd =r .get ("cmd")or []
                    if not cmd or not isinstance (cmd ,list ):
                        continue 
                    try :
                        chk =_chk_equivalent (cmd )
                        subprocess .check_call (chk ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
                        continue 
                    except subprocess .CalledProcessError :
                        pass 
                    try :
                        subprocess .check_call (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
                    except subprocess .CalledProcessError :
                        try :
                            base =[c for c in cmd if c not in ("sudo","-n")]
                            subprocess .check_call (base ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
                        except Exception :
                            pass 

    def flush (self ):
        try :
            tmp =self .path +".tmp"
            with open (tmp ,"w",encoding ="utf-8")as f :
                json .dump ({"v":1 ,"items":self .items },f ,ensure_ascii =False ,indent =2 )
            os .replace (tmp ,self .path )
        except Exception :
            pass 

    def list (self ):
        with self .lock :
            return list (self .items .values ())

    def add (self ,pattern ,iface =None ,proto ="all",port =None ,show_page =False ):
        pat =(pattern or "").strip ()
        if not pat :
            raise ValueError ("pattern empty")

        fam =_split_family (pat )
        fid =uuid .uuid4 ().hex [:12 ]
        rec ={
        "id":fid ,
        "pattern":pat ,
        "iface":iface or None ,
        "proto":(proto or "all").lower (),
        "port":(int (port )if port else None ),
        "created":int (time .time ()),
        "realized":{"v4":[],"v6":[]},
        "show_page":bool (show_page ),
        "backend":"ipset"if USE_DNSMASQ_IPSET else "legacy",
        }

        if USE_DNSMASQ_IPSET :

            if fam is None :

                with self .lock :
                    self .items [fid ]=rec 
                    self .flush ()
                try :
                    blocksreg .upsert_from_rec (rec )
                except Exception :
                    pass 

                _rebuild_dnsmasq_conf_from_items (self .items )

                if SNI_INDEX_PRESEED_ON_ADD and iface :
                    try :
                        _preseed_ipset_from_index_for (rec )
                        base =_registrable_domain (pat )or _normalize_domain_or_none (pat )or pat .strip ().lower ().strip (".")
                        v4i ,v6i =sni_index .get_ips_for_base (base )
                        rec ["realized"]["v4"]=sorted (set (rec ["realized"].get ("v4",[]))|set (v4i ))
                        rec ["realized"]["v6"]=sorted (set (rec ["realized"].get ("v6",[]))|set (v6i ))
                        with self .lock :
                            self .items [fid ]=rec 
                            self .flush ()
                        try :_sync_registry_for (fid )
                        except Exception :pass 
                        try :blocksreg .upsert_from_rec (rec )
                        except Exception :pass 
                    except Exception as e :
                        print ("[netdash] preseed per-iface failed:",e )

                if SNI_INDEX_PRESEED_ON_ADD and not iface :
                    try :
                        _preseed_ipset_from_index (pat ,show_page )
                        base =_registrable_domain (pat )or _normalize_domain_or_none (pat )or pat .strip ().lower ().strip (".")
                        v4i ,v6i =sni_index .get_ips_for_base (base )
                        rec ["realized"]["v4"]=list (sorted (set (rec ["realized"].get ("v4",[]))|set (v4i )))
                        rec ["realized"]["v6"]=list (sorted (set (rec ["realized"].get ("v6",[]))|set (v6i )))
                        with self .lock :
                            self .items [fid ]=rec 
                            self .flush ()
                        try :_sync_registry_for (fid )
                        except Exception :pass 
                        try :blocksreg .upsert_from_rec (rec )
                        except Exception :pass 
                    except Exception as e :
                        print ("[netdash] preseed from index failed:",e )

                if SNI_BLOCK_ENABLED :
                    try :
                        rec ["sni_rules"]=_add_sni_rules_for_domain (pat ,iface =iface )
                        with self .lock :
                            self .items [fid ]=rec 
                            self .flush ()
                        try :blocksreg .upsert_from_rec (rec )
                        except Exception :pass 
                        try :_sync_registry_for (fid )
                        except Exception :pass 
                    except Exception as e :
                        print (f"[netdash] SNI add failed for {pat}: {e}")

                return rec 

            if iface :
                ensure_ipset_and_rules_for_iface (iface ,show_page )
            s4 ,s6 =_ipset_names_for (rec )

            if fam =='v4':
                _run_root (["ipset","add",s4 ,pat ,"timeout",str (IPSET_TIMEOUT ),"-exist"])
                rec ["realized"]["v4"]=[pat ]
            else :
                _run_root (["ipset","add",s6 ,pat ,"timeout",str (IPSET_TIMEOUT ),"-exist"])
                rec ["realized"]["v6"]=[pat ]

            with self .lock :
                self .items [fid ]=rec 
                self .flush ()

            try :
                blocksreg .upsert_from_rec (rec )
            except Exception as e :
                print ("[netdash] blocksreg upsert (ip/cidr) failed:",e )

            return rec 

        rules =[]
        chains =["OUTPUT","FORWARD"]
        if fam is None :
            v4 ,v6 =_resolve_domain (pat )
        elif fam =='v4':
            v4 ,v6 =[pat ],[]
        else :
            v4 ,v6 =[],[pat ]

        if not v4 and not v6 :
            raise ValueError ("آدرس/دامنه قابل resolved نیست یا نامعتبر است.")

        for ip in v4 :
            for ch in chains :
                r =self ._apply_one (ip ,iface ,proto ,port ,ch ,ipv6 =False )
                if r :rules .append (r )
        for ip in v6 :
            for ch in chains :
                r =self ._apply_one (ip ,iface ,proto ,port ,ch ,ipv6 =True )
                if r :rules .append (r )

        if show_page :
            for ip in v4 :
                for ch in ("OUTPUT","PREROUTING"):
                    r =_apply_nat_redirect (ip ,ch ,ipv6 =False )
                    if r :rules .append (r )
            for ip in v6 :
                for ch in ("OUTPUT","PREROUTING"):
                    r =_apply_nat_redirect (ip ,ch ,ipv6 =True )
                    if r :rules .append (r )

        if not rules :
            raise RuntimeError ("هیچ قانون iptables/ip6tables اعمال نشد.")
        rec ["rules"]=rules 
        rec ["realized"]={"v4":v4 ,"v6":v6 }

        if SNI_BLOCK_ENABLED and fam is None :
            try :
                rec ["sni_rules"]=_add_sni_rules_for_domain (pat ,iface =iface )
            except Exception :
                pass 

        with self .lock :
            self .items [fid ]=rec 
            self .flush ()
        try :
            blocksreg .upsert_from_rec (rec )
        except Exception as e :
            print ("[netdash] blocksreg upsert (legacy) failed:",e )

        return rec 

    def _apply_one (self ,dst ,iface ,proto ,port ,chain ,ipv6 ):
        cmd =_mk_rule_cmds (dst ,chain ,iface =iface ,proto =proto ,port =port ,ipv6 =ipv6 )
        if _run_root (cmd )==0 :
            return {"cmd":cmd ,"chain":chain ,"ipv6":bool (ipv6 )}
        return None 

    def remove (self ,fid ):

        with self .lock :
            rec =self .items .get (fid )
            if not rec :
                for k ,v in list (self .items .items ()):
                    if (v or {}).get ("id")==fid :
                        fid ,rec =k ,v 
                        break 
            if not rec :
                return False 

        for r in (rec .get ("sni_rules")or []):
            try :
                _del_rule_obj (r )
            except Exception :
                pass 

        pat =(rec or {}).get ("pattern","").strip ()
        fam =_split_family (pat )

        if USE_DNSMASQ_IPSET :

            if fam is None :

                with self .lock :
                    self .items .pop (fid ,None )
                    self .flush ()

                _rebuild_dnsmasq_conf_from_items (self .items )

                try :
                    if (rec or {}).get ("iface"):
                        _del_domain_from_iface_sets (rec )
                except Exception as e :
                    print ("[netdash] per-iface purge warn:",e )

                try :
                    _del_domain_everywhere_safe (rec )
                except Exception as e :
                    print ("[netdash] safe-del warn:",e )

                any_domains =False 
                with self .lock :
                    for rr in self .items .values ():
                        if _split_family ((rr or {}).get ("pattern",""))is None :
                            any_domains =True 
                            break 
                if not any_domains :
                    _flush_all_ipsets ()

                try :
                    blocksreg .remove (fid )
                except Exception as e :
                    print ("[netdash] blocksreg remove (domain) failed:",e )

                return True 

            s4 ,s6 =_ipset_names_for (rec )
            if fam =='v4':
                try :_run_root (["ipset","del",s4 ,pat ])
                except Exception :pass 
            elif fam =='v6':
                try :_run_root (["ipset","del",s6 ,pat ])
                except Exception :pass 

            with self .lock :
                self .items .pop (fid ,None )
                self .flush ()

            try :
                blocksreg .remove (fid )
            except Exception as e :
                print ("[netdash] blocksreg remove (ip/cidr) failed:",e )

            return True 

        for r in (rec .get ("rules",[])or []):
            cmd =r .get ("cmd")or []
            dcmd =_del_equivalent (cmd )
            if _run_root (dcmd )!=0 :
                base =[c for c in dcmd if c not in ("sudo","-n")]
                _run_root (base )
        with self .lock :
            self .items .pop (fid ,None )
            self .flush ()

        try :
            blocksreg .remove (fid )
        except Exception as e :
            print ("[netdash] blocksreg remove (legacy) failed:",e )

        return True 

class SNILearner:
    def __init__(self, ifaces=None):
        self.ifaces = list(ifaces) if ifaces else None
        self.running = False
        self._recent = {}
        self._recent_ttl = 60.0
        # بافر ساده برای سرجمع‌کردن اولین بایت‌های TLS هر جریان
        # کلید: (v6?, src, dst, sport, dport)
        self._bufs = {}
        self._buf_limit = 4096  # فقط برای ClientHello کافی است

    def _match_any_blocked(self, host):
        try:
            with filters.lock:
                for rec in filters.items.values():
                    pat = (rec or {}).get("pattern", "").strip()
                    if not pat or _split_family(pat) is not None:
                        continue
                    if _hostname_matches(host, pat):
                        return rec
        except Exception:
            pass
        return None

    def _key_for_pkt(self, pkt, IP, IPv6, TCP):
        try:
            if IP in pkt:
                l3 = pkt[IP]; v6 = False
            elif IPv6 in pkt:
                l3 = pkt[IPv6]; v6 = True
            else:
                return None
            if not pkt.haslayer(TCP):
                return None
            tcp = pkt[TCP]
            return (v6, l3.src, l3.dst, int(tcp.sport), int(tcp.dport))
        except Exception:
            return None

    def _consume_clienthello(self, payload):
        # تلاش برای استخراج SNI از بایت‌های ابتدایی ClientHello
        return _extract_sni_from_clienthello(payload)

    def _learn_ip(self, rec, fam, dst_ip, host, iface_name):
        try:
            _append_sni_log(kind="sni", host=host, dst_ip=dst_ip, fam=fam,
                            base=rec.get("pattern"), iface=iface_name)
            base_page = bool(rec.get("show_page") and PAGE_MODE_ENABLED)
            keyfam = "v4" if fam == "v4" else "v6"

            if rec.get("iface"):
                ensure_ipset_and_rules_for_iface(rec["iface"], base_page)
                set4, set6 = _ipset_names_for(rec)
                try:
                    if fam == "v4":
                        _run_root(["ipset", "add", set4, dst_ip, "timeout", str(IPSET_TIMEOUT), "-exist"])
                    else:
                        _run_root(["ipset", "add", set6, dst_ip, "timeout", str(IPSET_TIMEOUT), "-exist"])
                    print(f"[netdash] SNI-add(per-iface): {dst_ip} -> {(set4 if fam=='v4' else set6)}  host={host}  iface={rec.get('iface')}")
                except Exception:
                    pass
            else:
                setname = {
                    ("v4", False): IPSET4,
                    ("v6", False): IPSET6,
                    ("v4", True):  IPSET4P,
                    ("v6", True):  IPSET6P,
                }[(fam, base_page)]
                try:
                    _run_root(["ipset", "add", setname, dst_ip, "timeout", str(IPSET_TIMEOUT), "-exist"])
                    print(f"[netdash] SNI-add: {dst_ip} -> {setname}  host={host}  matched={rec.get('pattern')}")
                except Exception:
                    pass

            # به‌روزرسانی realized + رجیستری
            try:
                with filters.lock:
                    rr = filters.items.get(rec["id"])
                    if rr:
                        arr = rr.setdefault("realized", {}).setdefault(keyfam, [])
                        if dst_ip not in arr:
                            arr.append(dst_ip)
                    filters.flush()
            except Exception:
                pass
            try:
                _sync_registry_for(rec["id"])
            except Exception:
                pass
            try:
                blocksreg.add_realized_ip(rec["id"], keyfam, dst_ip)
            except Exception:
                pass
        except Exception as e:
            print("[netdash] SNI learner (learn_ip) error:", e)

    def _handle_packet(self, pkt):
        try:
            from scapy.layers.inet import TCP, IP
            from scapy.layers.inet6 import IPv6

            if not pkt.haslayer(TCP):
                return
            tcp = pkt[TCP]
            if int(tcp.dport) != 443:
                return

            key = self._key_for_pkt(pkt, IP, IPv6, TCP)
            if not key:
                return

            # تجمیع بارِ TCP برای گرفتن ClientHello کامل
            payload = bytes(tcp.payload or b"")
            if not payload:
                return
            buf = self._bufs.get(key, b"") + payload
            if len(buf) > self._buf_limit:
                buf = buf[:self._buf_limit]
            self._bufs[key] = buf

            host = self._consume_clienthello(buf)
            if not host:
                # هنوز به اندازه کافی داده نداریم
                return

            # به محض یافتن SNI دیگر نیازی به بافر این جریان نیست
            try:
                del self._bufs[key]
            except KeyError:
                pass

            if IP in pkt:
                fam, dst_ip = "v4", pkt[IP].dst
            elif IPv6 in pkt:
                fam, dst_ip = "v6", pkt[IPv6].dst
            else:
                return
            iface_name = getattr(pkt, "sniffed_on", None)

            _append_sni_log(kind="sni", host=host, dst_ip=dst_ip, fam=fam, base=None, iface=iface_name)
            sni_index.update(host, dst_ip, fam, iface=iface_name)

            rec = self._match_any_blocked(host)
            if not rec:
                return

            # dedupe
            dedupe_key = (fam, dst_ip, (rec.get("iface") or "GLOBAL"))
            now = time.time()
            last = self._recent.get(dedupe_key)
            if last and (now - last) < self._recent_ttl:
                return
            self._recent[dedupe_key] = now

            self._learn_ip(rec, fam, dst_ip, host, iface_name)

        except Exception as e:
            print("[netdash] SNI learner error:", e)

    def start(self):
        if not SNI_LEARN_ENABLED:
            print("[netdash] SNI learner disabled (NETDASH_SNI_LEARN=0)")
            return
        try:
            from scapy.all import sniff
        except Exception as e:
            if AUTO_PIP_INSTALL:
                try:
                    import sys, subprocess
                    subprocess.check_call([sys.executable, "-m", "pip", "-q", "install", "scapy"])
                    from scapy.all import sniff
                except Exception as e2:
                    print("[netdash] SNI learner disabled: scapy install failed:", e2)
                    return
            else:
                print("[netdash] SNI learner disabled: scapy not available:", e)
                return

        self.running = True
        def run():
            flt = "tcp dst port 443"
            kwargs = {"filter": flt, "prn": self._handle_packet, "store": False}
            if self.ifaces:
                kwargs["iface"] = self.ifaces
            print(f"[netdash] SNI learner started on: {self.ifaces or 'ALL'}")
            try:
                sniff(**kwargs)
            except Exception as e:
                print("[netdash] SNI learner stopped:", e)
        threading.Thread(target=run, daemon=True).start()


filters =FilterStore (FILTERS_FILE )

try :
    if AUTO_ENFORCE_DNS :_ensure_dns_redirection ()
    if AUTO_BLOCK_DOT :_ensure_block_dot ()
    if AUTO_PRELOAD_META :_preload_blocklist ()
except Exception as e :
    print ("[netdash] bootstrap warning:",e )

def _tc_bin ():
    for p in ("/sbin/tc","/usr/sbin/tc","/usr/bin/tc","tc"):
        if os .path .isabs (p )and os .path .exists (p ):
            return p 
    return "tc"

def tc_status (iface ):
    res ={
    "up":{"active":False ,"rate_mbit":None },
    "down":{"active":False ,"rate_mbit":None },
    }
    try :
        out =subprocess .check_output ([_tc_bin (),"qdisc","show","dev",iface ],
        text =True ,stderr =subprocess .DEVNULL )
        if " tbf "in out or out .strip ().startswith ("qdisc tbf"):
            m =re .search (r"rate\s+([0-9.]+)Mbit",out )
            res ["up"]["active"]=True 
            res ["up"]["rate_mbit"]=float (m .group (1 ))if m else None 
    except Exception :
        pass 

    ifb =_ifb_name (iface )
    try :
        out2 =subprocess .check_output ([_tc_bin (),"qdisc","show","dev",ifb ],
        text =True ,stderr =subprocess .DEVNULL )
        if " tbf "in out2 or out2 .strip ().startswith ("qdisc tbf"):
            m2 =re .search (r"rate\s+([0-9.]+)Mbit",out2 )
            res ["down"]["active"]=True 
            res ["down"]["rate_mbit"]=float (m2 .group (1 ))if m2 else None 
    except Exception :
        pass 

    any_active =res ["up"]["active"]or res ["down"]["active"]
    if any_active :
        return {"active":True ,"algo":"tbf","rate_mbit":res ["up"]["rate_mbit"]or res ["down"]["rate_mbit"],"detail":res }
    return {"active":False ,"algo":None ,"rate_mbit":None ,"detail":res }

def tc_limit (iface ,rate_mbit ,burst_kbit =32 ,latency_ms =400 ):
    cmd =[_tc_bin (),"qdisc","replace","dev",iface ,"root",
    "tbf","rate",f"{float(rate_mbit)}mbit",
    "burst",f"{int(burst_kbit)}kbit",
    "latency",f"{int(latency_ms)}ms"]
    if os .geteuid ()!=0 :
        cmd =["sudo","-n"]+cmd 
    subprocess .check_call (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )

def tc_clear (iface ):
    cmd =[_tc_bin (),"qdisc","del","dev",iface ,"root"]
    if os .geteuid ()!=0 :
        cmd =["sudo","-n"]+cmd 
    try :
        subprocess .check_call (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
    except subprocess .CalledProcessError :
        pass 

def _safe_ifname (s ):
    return re .sub (r'[^a-zA-Z0-9_.-]+','-',str (s ))

def _ifb_name (iface ):

    base =_safe_ifname (iface )
    name =f"ifb-{base}"
    return name [:15 ]

def _ip_run (args ):
    ipbin =_find_ip_binary ()
    cmd =[ipbin ]+list (args )
    if os .geteuid ()!=0 :
        cmd =["sudo","-n"]+cmd 
    subprocess .check_call (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )

def _ensure_ifb (iface ):
    ifb =_ifb_name (iface )

    try :
        _ip_run (["link","show",ifb ])
    except subprocess .CalledProcessError :
        try :

            cmd =["modprobe","ifb"]
            if os .geteuid ()!=0 :cmd =["sudo","-n"]+cmd 
            subprocess .check_call (cmd ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
        except Exception :
            pass 
        _ip_run (["link","add",ifb ,"type","ifb"])
    _ip_run (["link","set",ifb ,"up"])
    return ifb 

def tc_limit_down (iface ,rate_mbit ,burst_kbit =32 ,latency_ms =400 ):
    ifb =_ensure_ifb (iface )

    cmd1 =[_tc_bin (),"qdisc","replace","dev",iface ,"ingress"]

    cmd2 =[_tc_bin (),"filter","add","dev",iface ,"parent","ffff:",
    "protocol","all","u32","match","u32","0","0",
    "action","mirred","egress","redirect","dev",ifb ]

    cmd3 =[_tc_bin (),"qdisc","replace","dev",ifb ,"root","tbf",
    "rate",f"{float(rate_mbit)}mbit",
    "burst",f"{int(burst_kbit)}kbit",
    "latency",f"{int(latency_ms)}ms"]
    for c in (cmd1 ,cmd2 ,cmd3 ):
        if os .geteuid ()!=0 :c =["sudo","-n"]+c 
        subprocess .check_call (c ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )

def tc_clear_down (iface ):
    ifb =_ifb_name (iface )

    for c in (
    [_tc_bin (),"qdisc","del","dev",iface ,"ingress"],
    [_tc_bin (),"qdisc","del","dev",ifb ,"root"],
    ):
        if os .geteuid ()!=0 :c =["sudo","-n"]+c 
        try :
            subprocess .check_call (c ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
        except subprocess .CalledProcessError :
            pass 

    try :
        _ip_run (["link","set",ifb ,"down"])
        _ip_run (["link","del",ifb ])
    except Exception :
        pass 

HTML =r"""
<!doctype html>
<html lang="fa" dir="ltr">
<head>

  <script>
    if (localStorage.getItem('netdash-dark') === '1') {
      document.documentElement.classList.add('dark');
    }
  </script>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetDash - داشبورد ترافیک شبکه</title>


  <!-- Tailwind via CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: { extend: { fontFamily: { sans: ['Vazirmatn','Inter','ui-sans-serif','system-ui'] } } }
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
    .badge-btn { cursor:pointer; user-select:none; border:none; display:inline-flex; align-items:center; justify-content:center; white-space:nowrap }
    .badge-btn:disabled { opacity:.75; cursor:not-allowed; }
    .ltr { direction:ltr }

    .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    /* اگر می‌خواهی دو خطی شود از این استفاده کن:
    .name{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;white-space:normal}
    */
    .name{white-space:normal !important;overflow-wrap:anywhere;word-break:break-word;text-overflow:clip !important}

    /* دکمه‌های محدودیت — دو حالت متمایز */
    .b-shape{background:#dbeafe;color:#1e3a8a;border:1px solid #60a5fa}   /* آبی: «اعمال محدودیت» */
    .b-clear{background:#fecaca;color:#7f1d1d;border:1px solid #ef4444}   /* قرمز روشن: «حذف محدودیت» */

    /* ⛔️ این خط مشکل‌ساز را عمداً نداریم:
       .b-shape,.b-clear{background:#ef4444 !important;color:#ffffff !important;border:1px solid #b91c1c !important}
    */
  </style>
</head>

<body class="bg-gray-50 text-gray-900 dark:bg-gray-900 dark:text-gray-100">
  <div class="max-w-7xl mx-auto p-4 sm:p-6">
    <div class="flex flex-wrap items-center justify-between gap-3 mb-6">
      <h1 class="text-2xl sm:text-3xl font-extrabold">NetDash</h1>
      <div class="flex flex-wrap items-center gap-2">
        <input id="filterInput" class="px-3 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm" placeholder="فیلتر اینترفیس‌ها...">
        <button id="darkBtn" class="px-3 py-2 rounded-xl card bg-white dark:bg-gray-800 text-sm">تیره / روشن</button>
      
        <!-- دکمهٔ چندرنگ پورت‌ها -->
        <button id="portsBtn" class="px-3 py-2 rounded-xl text-sm text-white bg-gradient-to-r from-indigo-500 via-fuchsia-500 to-emerald-500 shadow hover:opacity-90">
          پورت‌ها
        </button>


        <select id="statSel" class="px-2 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm" title="پنجره آماری"></select>
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

    <div class="card p-4 bg-white dark:bg-gray-800 mb-4" id="ports-inline-card">
      <div class="flex items-center justify-between mb-2">
        <h3 class="font-bold">پینگ زنده</h3>
        <div class="flex items-center gap-2">
        </div>
      </div>



      <div id="ping-chips" class="flex flex-wrap gap-2"></div>
    </div>

    <div class="card p-4 bg-white dark:bg-gray-800 mb-4">
      <div class="flex items-center justify-between mb-3">
        <div class="font-semibold">مسدودسازی آدرس‌ها (بلاک‌لیست)</div>
        <div class="text-xs opacity-70">قوانین سطح سیستم</div>
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

    <div id="cards" class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4"></div>
  </div>

  <template id="card-template">
    <div class="card p-4 bg-white dark:bg-gray-800 flex flex-col gap-3">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0 flex flex-col gap-1">
          <div class="grid grid-cols-[1fr_auto] items-center gap-2">
            <div class="font-bold text-lg k name truncate flex-1 min-w-0 ltr"></div>
            <button class="ctrl-btn hidden badge badge-btn b-up shrink-0"><span class="btn-label">توقف</span></button>
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
        </div>
      </div>
      <div class="h-36 ltr"><canvas class="chart"></canvas></div>
    </div>
  </template>

  <!-- Modal محدودیت -->

  <div id="shape-modal" class="fixed inset-0 z-50 hidden">
    <div class="absolute inset-0 bg-black/40" id="shape-overlay"></div>
    <div class="absolute inset-0 flex items-center justify-center p-4">
      <div class="w-full max-w-md card bg-white dark:bg-gray-800 p-4 rounded-xl">
        <div class="flex items-center justify-between mb-2">
          <h3 class="font-bold">محدودیت پهنای‌باند</h3>
          <button id="shape-close" class="text-sm opacity-70">✕</button>
        </div>
        <div class="text-xs opacity-70 mb-3">اینترفیس: <span id="shape-iface" class="k"></span></div>
        <div class="grid gap-3">
          <div class="flex gap-4">
            <label class="flex items-center gap-2"><input type="radio" name="shape-dir" value="up" checked> آپلود</label>
            <label class="flex items-center gap-2"><input type="radio" name="shape-dir" value="down"> دانلود</label>
          </div>
          <div>
            <label class="text-xs opacity-70">سقف سرعت (Mbps)</label>
            <input id="shape-rate" type="number" min="0.1" step="0.1"
                   class="px-3 py-2 rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-sm w-full">
          </div>
          <div class="flex flex-wrap gap-2">
            <button id="shape-apply" class="px-3 py-2 rounded-xl card bg-white dark:bg-gray-800 text-sm">اعمال</button>
            <button id="shape-clear" class="px-3 py-2 rounded-xl card bg-white dark:bg-gray-800 text-sm">حذف محدودیت</button>
          </div>
        </div>
      </div>
    </div>
  </div>
  <!-- Modal پورت‌ها (فقط یک‌بار) -->
  <div id="ports-modal" class="fixed inset-0 z-50 hidden">
    <div class="absolute inset-0 bg-black/40" id="ports-overlay"></div>
    <div class="absolute inset-0 flex items-center justify-center p-4">
      <div class="w-full max-w-3xl card bg-white dark:bg-gray-800 p-4 rounded-xl">
        <div class="flex items-center justify-between mb-2">
          <h3 class="font-bold">ترافیک زنده بر اساس پورت</h3>
          <div class="flex items-center gap-2">
            <button id="ports-reset-modal" class="text-sm px-3 py-1 rounded-xl bg-red-100 text-red-900 border border-red-300">
              پاکسازی لاگ
            </button>
            <button id="ports-modal-close" class="text-sm opacity-70">✕</button>
          </div>
        </div>
        <div class="text-xs opacity-70 mb-3">منبع داده: conntrack (kernel)</div>
        <div class="overflow-auto max-h-[70vh]">
          <table class="min-w-full text-sm">
            <thead>
              <tr class="text-left opacity-70">
                <th class="py-1 pr-4">Proto</th>
                <th class="py-1 pr-4">Port</th>
                <th class="py-1 pr-4">دانلود (Mbps)</th>
                <th class="py-1 pr-4">آپلود (Mbps)</th>
                <th class="py-1 pr-4">دانلود کل</th>
                <th class="py-1 pr-4">آپلود کل</th>
                <th class="py-1 pr-4">جریان‌ها</th>
              </tr>
            </thead>
            <tbody id="ports-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>


  
  



  <!-- اسکریپت یکپارچه -->

  <script>
    // اگر Chart.js نبود، مینی‌چارت ساده بساز
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
          draw(ds0, "#3b82f6"); draw(ds1, "#10b981");
        };
      }
      window.Chart = function(ctx, config){ return new MiniChart(ctx, config); };
    })();

    const MAX_POINTS = {{max_points}};
    const CONTROL_TOKEN = {{ token|tojson }};
    const cards = new Map();
    let STAT_WINDOW = parseInt(localStorage.getItem('netdash-stat-window') || '60', 10);
    if (isNaN(STAT_WINDOW) || STAT_WINDOW <= 0) STAT_WINDOW = Math.min(60, MAX_POINTS);


    // ---------- Utilities ----------
    function fmtBytes(x){
      const units = ["B","KB","MB","GB","TB","PB"];
      let i=0, v=Number(x);
      while(v>=1024 && i<units.length-1){ v/=1024; i++; }
      return v.toFixed(v<10?2:1)+" "+units[i];
    }
    
    function fmtMbps(bps){
      const mbps = (Number(bps) * 8) / 1e6; // bps→Mbps (اینجا ورودی بایت بر ثانیه است)
      return mbps.toFixed(mbps<10?2:1);
    }
    
    async function refreshPorts(){
      try{
        const res = await fetch('/api/ports/live', {cache:'no-store'});
        if(!res.ok) return;
        const data = await res.json();
        const tbody = document.getElementById('ports-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';
        for(const row of (data.ports || [])){
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="py-1 pr-4 k">${String(row.proto||'').toUpperCase()}</td>
            <td class="py-1 pr-4 k">${row.port}</td>
            <td class="py-1 pr-4 k">${((row.rx_bps||0)*8/1e6).toFixed(2)}</td>
            <td class="py-1 pr-4 k">${((row.tx_bps||0)*8/1e6).toFixed(2)}</td>
            <td class="py-1 pr-4 k">${fmtBytes(row.rx_total||0)}</td>
            <td class="py-1 pr-4 k">${fmtBytes(row.tx_total||0)}</td>
            <td class="py-1 pr-4 k">${row.flows||0}</td>`;
          tbody.appendChild(tr);
        }
      }catch(e){}
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
      btn.classList.remove('hidden','b-up','b-down');
      if (isUp){ btn.classList.add('b-down'); btn.querySelector('.btn-label').textContent = 'توقف'; }
      else { btn.classList.add('b-up'); btn.querySelector('.btn-label').textContent = 'ازسرگیری'; }
    }
    function updateStatsForCard(cardObj){
      const ch = cardObj.chart;
      const W = Math.max(1, Math.min(STAT_WINDOW, MAX_POINTS));
      const rx = ch.data.datasets[0].data.slice(-W).map(Number);
      const tx = ch.data.datasets[1].data.slice(-W).map(Number);
      const mean = a => a.length? a.reduce((x,y)=>x+y,0)/a.length : 0;
      const percentile = (arr,p)=>{ if(!arr.length) return 0; const s=arr.slice().sort((a,b)=>a-b); const i=Math.floor(p*(s.length-1)); return s[Math.min(s.length-1,Math.max(0,i))]; };
      const dl = {mu: mean(rx), mx: (rx.length? Math.max(...rx):0), p95: percentile(rx,0.95)};
      const ul = {mu: mean(tx), mx: (tx.length? Math.max(...tx):0), p95: percentile(tx,0.95)};
      const line = `DL μ/max/۹۵٪: ${dl.mu.toFixed(1)}/${dl.mx.toFixed(1)}/${dl.p95.toFixed(1)} | UL μ/max/۹۵٪: ${ul.mu.toFixed(1)}/${ul.mx.toFixed(1)}/${ul.p95.toFixed(1)} [${W}s]`;
      cardObj.el.querySelector('.stats').textContent = line;
    }


    // ---------- Reposition buttons next to badges ----------
    function placeCtrlNextToState(card){
      try{
        const ctrl = card.querySelector('.ctrl-btn'); if(!ctrl) return;
        const badgeRow = card.querySelector('.badge.state')?.parentElement; if(!badgeRow) return;
        const states = card.querySelectorAll('.badge.state'); if(!states.length) return;
        const last = states[states.length-1];
        if (ctrl.parentElement !== badgeRow || ctrl.previousElementSibling !== last){
          if (ctrl.parentElement && ctrl.parentElement !== badgeRow){ try{ ctrl.parentElement.removeChild(ctrl); }catch{} }
          badgeRow.insertBefore(ctrl, last.nextSibling);
          ctrl.classList.add('badge-btn','shrink-0');
        }
      }catch(e){}
    }
    function placeShapeNextToState(card){
      try{
        const shape = card.querySelector('.shape-btn'); if(!shape) return;
        const badgeRow = card.querySelector('.badge.state')?.parentElement; if(!badgeRow) return;
        const states = card.querySelectorAll('.badge.state'); if(!states.length) return;
        const last = states[states.length-1];
        if (shape.parentElement !== badgeRow || shape.previousElementSibling !== last){
          if (shape.parentElement && shape.parentElement !== badgeRow){ try{ shape.parentElement.removeChild(shape); }catch{} }
          badgeRow.insertBefore(shape, last.nextSibling);
          shape.classList.add('badge-btn','shrink-0');
        }
        shape.classList.add('b-shape');  // استایل آبی
        shape.classList.remove('b-warn');
      }catch(e){}
    }
    function NetdashPlaceButtons(){
      try{ document.querySelectorAll('.card').forEach(card=>{ placeCtrlNextToState(card); placeShapeNextToState(card); }); }catch(e){}
    }
    // اعمال دوباره‌ی فیلتر روی کارت‌های تازه‌ساخته‌شده
    const fi = document.getElementById('filterInput');
    if (fi) fi.dispatchEvent(new Event('input'));
    // ---------- Modal handlers ----------
    let SHAPE_IFACE = null;
    
    function openShapeModal(iface, detail){
      try{
        SHAPE_IFACE = iface;
        document.getElementById('shape-iface').textContent = iface;
        document.getElementById('shape-rate').value = '';
        document.getElementById('shape-modal').classList.remove('hidden');
        if (detail && detail.down && detail.down.active){
          document.querySelector('input[name="shape-dir"][value="down"]').checked = true;
        } else {
          document.querySelector('input[name="shape-dir"][value="up"]').checked = true;
        }
      }catch(e){}
    }
    function closeShapeModal(){
      try{
        document.getElementById('shape-modal').classList.add('hidden');
        SHAPE_IFACE = null;
      }catch(e){}
    }
    
    function openPortsModal(){
      try{
        document.getElementById('ports-modal').classList.remove('hidden');
        refreshPorts();                 // اولی
        window.__portsTimer = setInterval(refreshPorts, 1000);  // آپدیت هر ثانیه
      }catch(e){}
    }
    function closePortsModal(){
      try{
        document.getElementById('ports-modal').classList.add('hidden');
        if (window.__portsTimer){ clearInterval(window.__portsTimer); window.__portsTimer = null; }
      }catch(e){}
    }
    
    function bindShapeModalHandlers(){
      const closeBtn = document.getElementById('shape-close');
      const overlay  = document.getElementById('shape-overlay');
      if (closeBtn) closeBtn.onclick = closeShapeModal;
      if (overlay)  overlay.onclick  = closeShapeModal;
    
      const applyBtn = document.getElementById('shape-apply');
      if (applyBtn) applyBtn.onclick = async ()=>{
        const rate = parseFloat(String(document.getElementById('shape-rate').value).replace(',','.'));
        if (!(rate>0)){ alert('مقدار نامعتبر'); return; }
        const dir = document.querySelector('input[name="shape-dir"]:checked').value;
        const headers = Object.assign({"Content-Type":"application/json"}, CONTROL_TOKEN ? {"X-Auth-Token": CONTROL_TOKEN} : {});
        try{
          const res = await fetch(`/api/shape/${encodeURIComponent(SHAPE_IFACE)}/limit`, {
            method:'POST', headers, body: JSON.stringify({rate_mbit: rate, direction: dir})
          });
          if(!res.ok){ alert('خطا در اعمال محدودیت'); return; }
          closeShapeModal();
          if (typeof loadInterfaces==='function') await loadInterfaces();
        }catch(e){ alert('خطا: '+e); }
      };
    
      const clearBtn = document.getElementById('shape-clear');
      if (clearBtn) clearBtn.onclick = async ()=>{
        const dir = document.querySelector('input[name="shape-dir"]:checked').value;
        const headers = Object.assign({"Content-Type":"application/json"}, CONTROL_TOKEN ? {"X-Auth-Token": CONTROL_TOKEN} : {});
        try{
          const res = await fetch(`/api/shape/${encodeURIComponent(SHAPE_IFACE)}/clear`, {
            method:'POST', headers, body: JSON.stringify({direction: dir})
          });
          if(!res.ok){ alert('خطا در حذف محدودیت'); return; }
          closeShapeModal();
          if (typeof loadInterfaces==='function') await loadInterfaces();
        }catch(e){ alert('خطا: '+e); }
      };
    }
    

    // ---------- API/UI logic ----------
    
    function bindPortsModalHandlers(){
      const openBtn  = document.getElementById('portsBtn');
      const closeBtn = document.getElementById('ports-modal-close');
      const overlay  = document.getElementById('ports-overlay');
    
      if (openBtn)  openBtn.onclick  = openPortsModal;
      if (closeBtn) closeBtn.onclick = closePortsModal;
      if (overlay)  overlay.onclick  = closePortsModal;
    
      // فقط دکمهٔ ریست داخل مودال:
      const resetBtn = document.getElementById('ports-reset-modal');
      if (resetBtn) resetBtn.onclick = async ()=>{
        if(!confirm('لاگ پورت‌ها (دانلود کل/آپلود کل) صفر شود؟')) return;
        const headers = CONTROL_TOKEN ? {"X-Auth-Token": CONTROL_TOKEN} : {};
        try{
          const res = await fetch('/api/ports/reset', { method:'POST', headers });
          if(!res.ok){ alert('ریست نشد'); return; }
          // جدول پورت‌ها را فوری تازه کن
          if (typeof refreshPorts==='function') refreshPorts();
        }catch(e){
          alert('خطا: ' + e);
        }
      };
    }


    

        

    function initStatWindowSelector(){
      const sel = document.getElementById('statSel');
      if (!sel) return;
      const opts = []; [30, 60, 120, 300, 900].forEach(v => { if (v <= MAX_POINTS) opts.push(v); });
      if (!opts.length) opts.push(Math.min(60, MAX_POINTS));
      sel.innerHTML = opts.map(v => {
        const lbl = v>=60 ? (v%60===0 ? (v/60)+'m' : (Math.floor(v/60)+'m'+(v%60)+'s')) : (v+'s');
        return `<option value="${v}">پنجره: ${lbl}</option>`;
      }).join('');
      sel.value = String(STAT_WINDOW);
      sel.addEventListener('change', ()=>{
        STAT_WINDOW = parseInt(sel.value,10)||60;
        localStorage.setItem('netdash-stat-window', String(STAT_WINDOW));
        try{ for(const c of cards.values()) updateStatsForCard(c); }catch{}
      });
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
        const res = await fetch(`/api/iface/${encodeURIComponent(name)}/${action}`, { method: 'POST', headers });
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

      for (const it of ifaces){
        const tpl = document.getElementById('card-template').content.cloneNode(true);
        const card = tpl.querySelector('.card');
        card.dataset.iface = it.name;

        // نام
        card.querySelector('.name').textContent = it.name;
        card.querySelector('.name').setAttribute('title', it.name);

        // وضعیت
        const b = badgeFor(it.state);
        const st = card.querySelector('.state');
        st.textContent = b.text;
        st.className = b.cls + " state";

        // جزئیات
        const flags = (it.flags||[]).join(",");
        const mac   = it.mac ? (" | MAC: <span class='k'>" + it.mac + "</span>") : "";
        card.querySelector('.flags').innerHTML = "پرچم‌ها: " + (flags || "هیچ");
        card.querySelector('.meta').innerHTML  = "MTU: " + (it.mtu ?? "-") + mac;

        const v4 = (it.addresses||[]).filter(a=>a.family==="inet").map(a=>a.cidr);
        const v6 = (it.addresses||[]).filter(a=>a.family==="inet6").map(a=>a.cidr);
        let addrHTML = "";
        if(v4.length) addrHTML += "IPv4: <span class='k'>" + v4.join(", ") + "</span>";
        if(v6.length) addrHTML += (addrHTML? "<br>" : "") + "IPv6: <span class='k'>" + v6.join(", ") + "</span>";
        card.querySelector('.addrs').innerHTML = addrHTML || "<span class='opacity-60'>بدون IP</span>";

        const li = it.link || {};
        const speedText  = (li.speed !== null && li.speed !== undefined) ? (li.speed + " Mb/s") : "نامشخص";
        const duplexText = li.duplex ? li.duplex : "نامشخص";
        const extra      = it.kind ? (" | نوع: " + it.kind) : "";
        card.querySelector('.linkinfo').innerHTML = "Link: <span class='k'>سرعت: " + speedText + " | دوبلکس: " + duplexText + extra + "</span>";

        // دکمهٔ توقف/ازسرگیری
        const btn  = card.querySelector('.ctrl-btn');
        const isUp = !!it.is_up;
        styleButton(btn, isUp);
        btn.onclick = async ()=>{
          const act = isUp ? 'down' : 'up';
          await controlIface(btn, it.name, act);
          await loadInterfaces();
        };

        // دکمهٔ محدودیت (shape)
        const sbtn   = card.querySelector('.shape-btn');
        const shaped = !!(it.shape && (it.shape.active || (it.shape.detail && (it.shape.detail.up?.active || it.shape.detail.down?.active))));
        if (it.can_control){
          sbtn.classList.remove('hidden','b-warn','b-unk','b-clear','b-shape');
          sbtn.classList.add(shaped ? 'b-clear' : 'b-shape');
          sbtn.querySelector('.shape-label').textContent = shaped ? 'حذف محدودیت' : 'محدودیت';
          sbtn.onclick = () => openShapeModal(it.name, it.shape?.detail);
        } else {
          sbtn.classList.add('hidden');
        }

        wrap.appendChild(card);

        // آمار دوره‌ای


        // چارت
        let chart;
        try { chart = makeChart(card.querySelector('.chart')); }
        catch(e){ chart = { data:{labels:[],datasets:[{data:[]},{data:[]}]}, update: ()=>{} }; }
        cards.set(it.name, { el: card, chart });
      }

      // بعد از رندر کارت‌ها، جای‌گذاری دکمه‌ها
      NetdashPlaceButtons();
      const fi = document.getElementById('filterInput');
      if (fi) fi.dispatchEvent(new Event('input'));
            
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

    async function updatePing(){
      try{
        const res = await fetch('/api/ping',{cache:'no-store'});
        const data = await res.json();
        const wrap = document.getElementById('ping-chips');
        wrap.innerHTML = '';
        const tg = Object.keys(data);
        
        
        for(const [host, m] of Object.entries(data)){
          const chip = document.createElement('div');
          chip.className = 'badge b-up';
          chip.innerHTML = `<span class="k">${host}</span> <span class="ltr">${m.avg.toFixed(1)} ms</span> <span class="ltr">(${m.loss.toFixed(1)}% loss)</span>`;
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



    // Filter فرم‌ها
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
            <td class="py-1 pr-4"><button class="badge badge-btn b-down" data-id="${it.id}">حذف</button></td>`;
          tr.querySelector('button').onclick = async (ev)=>{
            if(!confirm('این مورد از بلاک‌لیست حذف شود؟')) return;
            const id = ev.currentTarget.getAttribute('data-id');
            try{
              const res = await fetch('/api/filters/'+encodeURIComponent(id), { method:'DELETE', headers: CONTROL_TOKEN ? {"X-Auth-Token": CONTROL_TOKEN} : {} });
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
        const res = await fetch('/api/filters', { method:'POST', headers, body: JSON.stringify({pattern, iface: iface||null, proto, port, show_page}) });
        if(!res.ok){
          const t = await res.text();
          alert('عدم موفقیت: '+ t);
        } else {
          document.getElementById('flt-pattern').value=''; document.getElementById('flt-port').value='';
          refreshFilters();
        }
      }catch(e){ alert('خطا: '+e); }
      finally{ btn.textContent=old; btn.removeAttribute('disabled'); }
    }


    function bindFilterInput(){
      const inp = document.getElementById('filterInput');
      if (!inp) return;
    
      const norm = s => String(s||'').toLowerCase().trim();
    
      function applyFilter(){
        const q = norm(inp.value);
        for (const [name, obj] of cards.entries()){
          const el = obj.el;
          const hay = norm([
            name,
            el.querySelector('.flags')?.innerText,
            el.querySelector('.meta')?.innerText,
            el.querySelector('.addrs')?.innerText,
            el.querySelector('.linkinfo')?.innerText
          ].join(' | '));
          el.style.display = (!q || hay.includes(q)) ? '' : 'none';
        }
      }
    
      inp.addEventListener('input', applyFilter, {passive:true});
      // در لود اولیه هم اعمال کن
      applyFilter();
    }

    // ---------- Init & events ----------
    window.addEventListener('load', ()=>{
      bindShapeModalHandlers();
      bindPortsModalHandlers();

      bindTotalsReset();
      initStatWindowSelector();
      populateFilterIfaces();
      loadInterfaces();
      loadHistory();
      updatePing();
      setInterval(tick, 1000);
    });

      // Filter events
      try{
        populateFilterIfaces();
        refreshFilters();
        const btn = document.getElementById('flt-add');
        if(btn) btn.addEventListener('click', addFilterFromForm);
        setInterval(populateFilterIfaces, 30000);
        setInterval(refreshFilters, 15000);
      }catch(e){}


      // Theme toggle (robust)
      (function attachTheme(){
        function applyTheme(){
          const on = localStorage.getItem('netdash-dark') === '1';
          document.documentElement.classList.toggle('dark', on);
        }
        applyTheme(); // اعمال در لود
      
        const darkBtn = document.getElementById('darkBtn');
        if (darkBtn) {
          darkBtn.addEventListener('click', ()=>{
            const cur = localStorage.getItem('netdash-dark') === '1';
            localStorage.setItem('netdash-dark', cur ? '0' : '1');
            applyTheme();
          }, {passive:true});
        }
      })();
      const portsBtn = document.getElementById('portsBtn');
      if (portsBtn) portsBtn.addEventListener('click', openPortsModal, {passive:true});
      


      // Live data
      (async function init(){
        await loadInterfaces();
        bindFilterInput();
        await loadHistory();
        tick();
        setInterval(tick, 1000);
        setInterval(loadInterfaces, 30000);
        setInterval(updatePing, 5000);
        updatePing();

      })();


    window.addEventListener('load', ()=>{
      // بایند مودال‌ها
      bindShapeModalHandlers();
    
      // اینیت‌های صفحه (اگر قبلاً نداشتی)
      initStatWindowSelector();
      populateFilterIfaces();
      loadInterfaces();
      loadHistory();
      updatePing();
      setInterval(tick, 1000);
    });




  </script>
</body>
</html>
"""






@app.route("/api/ports/live")
def api_ports_live():
    if not PORTS_MONITOR_ENABLED:
        return jsonify({"ok": False, "reason": "disabled"}), 503
    try:
        snap = portsmon.snapshot()
        return jsonify(snap)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



if PORTS_MONITOR_ENABLED:
    portsmon.start()





@app .route ("/api/debug/sync-registry-now",methods =["POST"])
def api_debug_sync_now ():
    _require_token ()
    with filters .lock :
        ids =[it .get ("id")for it in (filters .items or {}).values ()if it and it .get ("id")]
    for fid in ids :
        _sync_registry_for (fid )
    return jsonify ({"ok":True ,"n":len (ids )})

@app .route ("/api/debug/rebuild-reg",methods =["POST"])
def api_debug_rebuild_reg ():
    _require_token ()

    with blocksreg .lock :
        blocksreg .obj ={"v":1 ,"items":{}}
        blocksreg .flush (force =True )

    with filters .lock :
        for rec in filters .items .values ():
            try :
                blocksreg .upsert_from_rec (rec )
                pat =(rec .get ("pattern")or "").strip ()
                if pat and _split_family (pat )is None :
                    base =_registrable_domain (pat )or _normalize_domain_or_none (pat )or pat 
                    v4i ,v6i =sni_index .get_ips_for_base (base )
                    rv4 =sorted (set ((rec .get ("realized")or {}).get ("v4",[]))|set (v4i or []))
                    rv6 =sorted (set ((rec .get ("realized")or {}).get ("v6",[]))|set (v6i or []))
                    blocksreg .set_realized (rec ["id"],rv4 ,rv6 )
            except Exception as e :
                print ("[netdash] rebuild-reg warn:",e )

    return jsonify ({"ok":True ,"n":len (blocksreg .obj .get ('items',{}))})

@app .route ("/api/sni-index/<base>")
def api_sni_index_base (base ):
    base =(base or "").strip ().lower ().strip (".")
    v4 ,v6 =sni_index .get_ips_for_base (base )
    return jsonify ({"base":base ,"v4":v4 ,"v6":v6 })

@app .route ("/api/debug/why-ip/<ip>")
def api_debug_why_ip (ip ):
    ip =(ip or "").strip ()
    in_sets =[]
    for name in (IPSET4 ,IPSET4P ,IPSET6 ,IPSET6P ):
        try :
            if _run_root (["ipset","test",name ,ip ])==0 :
                in_sets .append (name )
        except Exception :
            pass 

    with filters .lock :
        blocks =[(r .get ("id"),r .get ("pattern"))for r in filters .items .values ()if r and _split_family (r .get ("pattern",""))is None ]

    seen_in =[]
    try :
        for bid ,pat in blocks :
            base =_registrable_domain (pat )or _normalize_domain_or_none (pat )or pat 
            v4 ,v6 =sni_index .get_ips_for_base (base )
            if ip in v4 or ip in v6 :
                seen_in .append (base )
    except Exception :
        pass 

    return jsonify ({"ip":ip ,"in_sets":in_sets ,"seen_in_bases":seen_in ,"blocked_domains_now":[p for _ ,p in blocks ]})

@app .route ("/")
def home ():
    html =render_template_string (HTML ,max_points =MAX_POINTS ,token =CONTROL_TOKEN )
    resp =make_response (html )
    resp .headers ["Cache-Control"]="no-store"
    return resp 

@app .route ("/api/filters/flush-sets",methods =["POST"])
def api_filters_flush_sets ():
    _require_token ()
    _flush_all_ipsets ()
    return jsonify ({"ok":True })

@app .route ("/api/interfaces")
def api_interfaces ():
    return jsonify (get_interfaces_info ())

@app .route ("/api/live")
def api_live ():
    return jsonify (monitor .snapshot ())

@app .route ("/api/history")
def api_history ():
    return jsonify (history .export ())

@app .route ("/api/ping")
def api_ping ():
    return jsonify (pingmon .snapshot ())

@app .route ("/api/report/<scope>")
def api_report (scope ):
    if scope not in ("daily","monthly"):
        abort (400 ,"scope must be daily|monthly")
    key ,data =periods .get_scope (scope )
    total_rx =sum (int (v .get ("rx",0 ))for v in data .values ())
    total_tx =sum (int (v .get ("tx",0 ))for v in data .values ())
    return jsonify ({"scope":scope ,"key":key ,"ifaces":data ,"sum":{"rx":total_rx ,"tx":total_tx }})

@app .route ("/api/iface/<iface>/down",methods =["POST"])
def api_iface_down (iface ):
    return iface_action (iface ,"down")

@app .route ("/api/iface/<iface>/up",methods =["POST"])
def api_iface_up (iface ):
    return iface_action (iface ,"up")

@app .route ("/api/shape/<iface>/limit",methods =["POST"])
def api_shape_limit (iface ):
    if not can_control (iface ):
        abort (403 ,description ="Interface not permitted")
    _require_token ()
    body =request .get_json (silent =True )or {}
    direction =(body .get ("direction")or "up").strip ().lower ()
    rate =float (body .get ("rate_mbit",0 ))
    if rate <=0 :
        abort (400 ,"rate_mbit must be > 0")
    burst =int (body .get ("burst_kbit",32 ))
    latency =int (body .get ("latency_ms",400 ))
    try :
        if direction =="down":
            tc_limit_down (iface ,rate ,burst ,latency )
        else :
            tc_limit (iface ,rate ,burst ,latency )
        return jsonify ({"ok":True ,"iface":iface ,"direction":direction ,"rate_mbit":rate })
    except subprocess .CalledProcessError as e :
        return jsonify ({"ok":False ,"error":str (e )}),500 

@app .route ("/api/filters",methods =["GET"])
def api_filters_list ():
    _require_token ()
    return jsonify ({"items":filters .list ()})

@app .route ("/api/filters",methods =["POST"])
def api_filters_add ():
    _require_token ()
    body =request .get_json (silent =True )or {}
    pattern =(body .get ("pattern")or "").strip ()
    iface =(body .get ("iface")or "").strip ()or None 
    proto =(body .get ("proto")or "all").strip ().lower ()
    port =body .get ("port")
    show_page =bool (body .get ("show_page"))

    if iface and not can_control (iface ):
        abort (403 ,description ="Interface not permitted")
    try :
        rec =filters .add (pattern ,iface =iface ,proto =proto ,port =port ,show_page =show_page )
        return jsonify ({"ok":True ,"item":rec })
    except ValueError as e :
        return jsonify ({"ok":False ,"error":str (e )}),400 
    except Exception as e :
        return jsonify ({"ok":False ,"error":str (e )}),500 

@app .route ("/api/filters/<fid>",methods =["DELETE"])
def api_filters_del (fid ):
    _require_token ()
    ok =filters .remove (fid )
    if ok :
        return jsonify ({"ok":True })
    return jsonify ({"ok":False ,"error":"Not found"}),404 

@app .route ("/api/shape/<iface>/clear",methods =["POST"])
def api_shape_clear (iface ):
    if not can_control (iface ):
        abort (403 ,description ="Interface not permitted")
    _require_token ()
    body =request .get_json (silent =True )or {}
    direction =(body .get ("direction")or "up").strip ().lower ()
    if direction in ("both","all"):
        tc_clear (iface )
        tc_clear_down (iface )
    elif direction =="down":
        tc_clear_down (iface )
    else :
        tc_clear (iface )
    return jsonify ({"ok":True ,"iface":iface ,"direction":direction })

def _flush_on_exit ():
    try :
        history .flush (force =True )
        totals .flush (force =True )
        periods .flush (force =True )
    except Exception :
        pass 

if __name__ =="__main__":
    try :
        monitor .start ()
        if PORTS_MONITOR_ENABLED:
            portsmon.start()
                
        start_block_server ()
        sni_learner =SNILearner (ifaces =SNI_LEARN_IFACES or None )
        sni_learner .start ()
        _start_registry_autosync (interval =5.0 )
        app .run (host =HOST ,port =PORT ,debug =False ,use_reloader =False )
    finally :
        _flush_on_exit ()
