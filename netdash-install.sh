#!/usr/bin/env bash
# NetDash one-click installer / manager
# Repo: https://github.com/Free-Guy-IR/Interface-Traffic-Monitoring
# File: netdash-install.sh
set -euo pipefail

# -------- util --------
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; CLR='\033[0m'
info(){ echo -e "${BLU}[i]${CLR} $*"; }
ok(){   echo -e "${GRN}[✓]${CLR} $*"; }
warn(){ echo -e "${YLW}[!]${CLR} $*"; }
err(){  echo -e "${RED}[x]${CLR} $*" >&2; }

require_root(){
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "Please run as root (sudo -i)"; exit 1
  fi
}

# -------- consts --------
NETDASH_DIR="/opt/netdash"
NETDASH_DATA="/var/lib/netdash"
ENV_FILE="/etc/netdash.env"
SERVICE_FILE="/etc/systemd/system/netdash.service"
REPO_RAW="https://raw.githubusercontent.com/Free-Guy-IR/Interface-Traffic-Monitoring/main"
NETDASH_PY_URL="${REPO_RAW}/netdash.py"

# -------- deps --------
install_packages(){
  info "Installing required packages…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  # core
  apt-get install -y --no-install-recommends \
    python3 python3-flask curl ca-certificates \
    iproute2 iptables ipset conntrack dnsmasq ethtool \
    netcat-openbsd procps \
    dnsutils ldnsutils bind9-host

  ok "Packages installed."
}

# -------- DNS: free port 53 and prep dnsmasq --------
ensure_dns_on_53(){
  info "Preparing port 53 for dnsmasq…"
  systemctl stop dnsmasq 2>/dev/null || true

  # Disable/mask potential conflicts
  systemctl stop systemd-resolved 2>/dev/null || true
  systemctl disable systemd-resolved 2>/dev/null || true
  systemctl mask systemd-resolved 2>/dev/null || true
  systemctl stop bind9 named unbound pdns-recursor 2>/dev/null || true
  systemctl disable bind9 named unbound pdns-recursor 2>/dev/null || true

  # resolv.conf points to local dnsmasq
  if [ -L /etc/resolv.conf ] || grep -q '127\.0\.0\.53' /etc/resolv.conf 2>/dev/null; then
    warn "/etc/resolv.conf is a stub or points to 127.0.0.53 → replacing"
    rm -f /etc/resolv.conf
    printf "nameserver 127.0.0.1\noptions edns0 trust-ad\n" > /etc/resolv.conf
  fi

  # Upstreams to avoid loop
  mkdir -p /etc/dnsmasq.d
  cat >/etc/dnsmasq.d/00-upstream.conf <<'EOF'
no-resolv
server=1.1.1.1
server=8.8.8.8
server=2606:4700:4700::1111
server=2001:4860:4860::8888
EOF
  # placeholder for NetDash ipset rules
  touch /etc/dnsmasq.d/netdash-blocks.conf

  systemctl enable --now dnsmasq || {
    err "dnsmasq failed to start. Showing recent logs:"
    journalctl -xeu dnsmasq --no-pager | tail -n 80 || true
    exit 1
  }

  if ss -lntup | grep -q ':53 '; then
    ok "dnsmasq is listening on port 53."
  else
    err "Port 53 is not open by dnsmasq. Check conflicts via: ss -lntup | grep :53"
    exit 1
  fi
}

# -------- deploy/update NetDash --------
deploy_netdash(){
  info "Deploying NetDash to ${NETDASH_DIR}…"
  mkdir -p "${NETDASH_DIR}" "${NETDASH_DATA}"
  curl -fsSL "${NETDASH_PY_URL}" -o "${NETDASH_DIR}/netdash.py"
  chmod 755 "${NETDASH_DIR}/netdash.py"

  # Default env (create if missing)
  if [ ! -f "${ENV_FILE}" ]; then
    cat >"${ENV_FILE}" <<'EOF'
# NetDash environment configuration
NETDASH_PORT=18080
NETDASH_BLOCK_PORT=18081
NETDASH_MAX_POINTS=300

# Security (optional token for write operations)
#NETDASH_TOKEN=

# Enable IPSET + dnsmasq integration (recommended)
NETDASH_IPSET_MODE=1
DNSMASQ_CONF=/etc/dnsmasq.d/netdash-blocks.conf

# Show block page for HTTP (80) if enabled per rule
NETDASH_PAGE_MODE=1

# TLS/SNI helpers
NETDASH_SNI_BLOCK=1
NETDASH_SNI_LEARN=1
NETDASH_SNI_IFACES=

# Auto stuff
NETDASH_ENFORCE_DNS=1
NETDASH_BLOCK_DOT=0
NETDASH_PRELOAD_META=0
NETDASH_AUTO_PIP=1

# Ports monitor
NETDASH_PORTS_MONITOR=1
NETDASH_PORTS_INTERVAL=1.0
EOF
    ok "Created default ${ENV_FILE}"
  fi

  # systemd unit
  cat >"${SERVICE_FILE}" <<EOF
[Unit]
Description=NetDash - Network Traffic Dashboard
After=network-online.target dnsmasq.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${NETDASH_DIR}
EnvironmentFile=-${ENV_FILE}
ExecStart=/usr/bin/python3 ${NETDASH_DIR}/netdash.py
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  ok "NetDash deployed."
}

start_service(){
  systemctl enable --now netdash
  ok "NetDash started. Open: http://<server-ip>:$(grep -E '^NETDASH_PORT=' ${ENV_FILE} | cut -d= -f2 | tr -d '\r' | sed 's/[^0-9]//g' || echo 18080)"
}

stop_service(){
  systemctl stop netdash || true
  ok "NetDash stopped."
}

status_service(){
  systemctl status netdash --no-pager || true
}

logs_service(){
  journalctl -u netdash -f --no-pager
}

update_netdash(){
  info "Updating netdash.py from GitHub…"
  curl -fsSL "${NETDASH_PY_URL}" -o "${NETDASH_DIR}/netdash.py"
  chmod 755 "${NETDASH_DIR}/netdash.py"
  systemctl restart netdash || true
  ok "NetDash updated."
}

edit_env(){
  ${EDITOR:-nano} "${ENV_FILE}"
  info "Reloading NetDash…"
  systemctl restart netdash || true
}

remove_all(){
  warn "This will stop NetDash and remove files. Continue? [y/N]"
  read -r a; a=${a:-N}
  if [[ "${a}" =~ ^[Yy]$ ]]; then
    systemctl stop netdash 2>/dev/null || true
    systemctl disable netdash 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload

    rm -rf "${NETDASH_DIR}"
    warn "Keep data at ${NETDASH_DATA}? [Y/n]"
    read -r b; b=${b:-Y}
    if [[ ! "${b}" =~ ^[Yy]$ ]]; then
      rm -rf "${NETDASH_DATA}"
    fi

    warn "Remove /etc/netdash.env ? [y/N]"
    read -r c; c=${c:-N}
    if [[ "${c}" =~ ^[Yy]$ ]]; then
      rm -f "${ENV_FILE}"
    fi

    warn "Remove dnsmasq NetDash rules file /etc/dnsmasq.d/netdash-blocks.conf ? [y/N]"
    read -r d; d=${d:-N}
    if [[ "${d}" =~ ^[Yy]$ ]]; then
      rm -f /etc/dnsmasq.d/netdash-blocks.conf
      systemctl restart dnsmasq || true
    fi

    ok "Removed."
  else
    info "Aborted."
  fi
}

# -------- menu --------
menu(){
  clear
  cat <<'BANNER'
############################################################
#                    NetDash Manager                       #
#    Intelligent Traffic Monitor & DNS/IP Blocking         #
############################################################
BANNER
  echo "1) Install or Reinstall NetDash"
  echo "2) Update NetDash from GitHub"
  echo "3) Edit Configuration (.env)"
  echo "4) View Live Logs"
  echo "5) Stop NetDash"
  echo "6) Start NetDash"
  echo "7) Remove NetDash Completely"
  echo "8) Status"
  echo "9) Exit"
  echo -n "Choose an option [1-9]: "
}

# -------- main actions --------
install_flow(){
  install_packages
  ensure_dns_on_53
  deploy_netdash
  start_service
  status_service
}

main(){
  require_root
  if [[ "${1:-}" == "--install" ]]; then
    install_flow; exit 0
  fi
  while true; do
    menu
    read -r opt || { echo; exit 0; }
    case "${opt}" in
      1) install_flow ;;
      2) update_netdash ;;
      3) edit_env ;;
      4) logs_service ;;
      5) stop_service ;;
      6) start_service ;;
      7) remove_all ;;
      8) status_service ;;
      9) exit 0 ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
    echo -e "\nPress Enter to return to menu…"
    read -r _ || true
  done
}

main "$@"
