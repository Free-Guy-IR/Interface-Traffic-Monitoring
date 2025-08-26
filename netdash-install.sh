#!/usr/bin/env bash
# NetDash - Interactive Installer & Manager
# Tested on Ubuntu/Debian. Run as root:  bash <(curl -fsSL https://example.com/install.sh)
set -Eeuo pipefail

APP_NAME="NetDash"
APP_USER="root"              # netdash needs root for iptables/ipset; app already uses sudo -n when not root
APP_DIR="/opt/netdash"
APP_BIN="$APP_DIR/netdash.py"
ENV_FILE="/etc/netdash.env"
SERVICE_FILE="/etc/systemd/system/netdash.service"
DNSMASQ_CONF_DIR="/etc/dnsmasq.d"
GITHUB_RAW="https://raw.githubusercontent.com/Free-Guy-IR/Interface-Traffic-Monitoring/main/netdash.py"

shopt -s extglob

color() { # $1=color $2=message
  local c="$1"; shift || true
  local t="$*"
  case "$c" in
    g) printf "\e[32m%s\e[0m\n" "$t" ;;
    r) printf "\e[31m%s\e[0m\n" "$t" ;;
    y) printf "\e[33m%s\e[0m\n" "$t" ;;
    c) printf "\e[36m%s\e[0m\n" "$t" ;;
    *) printf "%s\n" "$t" ;;
  esac
}

need_root() {
  if [[ $EUID -ne 0 ]]; then
    color r "[!] Please run as root (sudo -i)"
    exit 1
  fi
}

pause() { read -rp $'\nPress Enter to continue...'; }

header() {
cat <<'BANNER'
############################################################
#                                                          #
#                 NetDash: Installer/Manager               #
#         Intelligent Network Dashboard & Controls         #
#                                                          #
############################################################
BANNER
}

confirm() {
  # confirm "Question?" -> returns 0 for yes
  read -rp "$1 [y/N]: " ans
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

apt_install() {
  color c "[*] Installing prerequisites via apt..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    curl ca-certificates git nano \
    python3 python3-venv python3-pip python3-flask python3-publicsuffix2 python3-tldextract \
    iproute2 iptables ipset conntrack dnsmasq
  color g "[✓] Packages installed."
}

disable_systemd_resolved() {
  color y "[*] Disabling systemd-resolved and pointing resolv.conf to 127.0.0.1 ..."
  systemctl disable --now systemd-resolved || true

  # If resolv.conf is a symlink to /run/systemd/resolve/stub-resolv.conf, replace it.
  if [[ -L /etc/resolv.conf ]]; then
    mv -f /etc/resolv.conf /etc/resolv.conf.bak.$(date +%s)
  fi
  echo 'nameserver 127.0.0.1' > /etc/resolv.conf

  systemctl enable --now dnsmasq
  systemctl restart dnsmasq
  color g "[✓] DNS now handled by dnsmasq (127.0.0.1)."
}

write_env_file() {
  if [[ -f "$ENV_FILE" ]]; then
    color y "[*] $ENV_FILE exists; keeping it."
    return 0
  fi

  # Generate a random token
  TOKEN="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)"
  cat >"$ENV_FILE" <<EOF
# ===== NetDash Environment =====
# Listen addresses/ports
NETDASH_PORT=18080
NETDASH_BLOCK_PORT=18081

# Data retention / charts
NETDASH_MAX_POINTS=180

# Security token for control APIs (sent as X-Auth-Token)
NETDASH_TOKEN=$TOKEN

# Enable/disable features (1=on, 0=off)
NETDASH_PAGE_MODE=1
NETDASH_SNI_LEARN=1
NETDASH_ENFORCE_DNS=1
NETDASH_BLOCK_DOT=0
NETDASH_PRELOAD_META=0
NETDASH_AUTO_PIP=1

# Interfaces allow/deny (comma-separated), empty means allow all except explicit deny
NETDASH_DENY=
NETDASH_ALLOW=

# Optional per-feature config
NETDASH_IPSET_MODE=1
NETDASH_SNI_IFACES=
EOF
  chmod 0644 "$ENV_FILE"
  color g "[✓] Wrote $ENV_FILE"
}

write_service_file() {
  cat >"$SERVICE_FILE" <<'EOF'
[Unit]
Description=NetDash - Network Traffic Dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/netdash.env
WorkingDirectory=/opt/netdash
# Ensure Python stdout/stderr are not buffered
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/netdash/netdash.py
Restart=on-failure
RestartSec=2s
# Give raw network and iptables capabilities when not root; we run as root for simplicity.
# CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
# AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$SERVICE_FILE"
  systemctl daemon-reload
  color g "[✓] Wrote systemd unit."
}

download_app() {
  mkdir -p "$APP_DIR"
  curl -fsSL "$GITHUB_RAW" -o "$APP_BIN"
  chmod +x "$APP_BIN"
  color g "[✓] Downloaded netdash.py to $APP_BIN"
}

install_or_reinstall() {
  header
  need_root
  apt_install
  disable_systemd_resolved
  download_app
  write_env_file
  write_service_file
  systemctl enable --now netdash.service
  systemctl status --no-pager --lines=3 netdash.service || true
  color g "[✓] $APP_NAME installed & running on http://<server-ip>:${NETDASH_PORT:-18080}"
  pause
}

update_from_github() {
  header
  need_root
  color c "[*] Updating netdash.py from GitHub..."
  download_app
  systemctl restart netdash.service || true
  color g "[✓] Updated and restarted."
  pause
}

edit_env() {
  header
  need_root
  [[ -f "$ENV_FILE" ]] || write_env_file
  nano "$ENV_FILE"
  color y "[*] If you changed ports/features, restarting service..."
  systemctl restart netdash.service || true
}

view_logs() {
  header
  need_root
  journalctl -u netdash.service -n 50 --no-pager
  echo "---- live (Ctrl+C to quit) ----"
  journalctl -u netdash.service -f
}

stop_service() {
  header
  need_root
  systemctl stop netdash.service || true
  color g "[✓] Stopped."
  pause
}

start_service() {
  header
  need_root
  systemctl start netdash.service || true
  color g "[✓] Started."
  pause
}

remove_completely() {
  header
  need_root
  if ! confirm "This will stop and remove NetDash, service, env and /opt/netdash. Continue?"; then
    return
  fi
  systemctl disable --now netdash.service || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
  rm -rf "$APP_DIR"
  rm -f "$ENV_FILE"
  # optional cleanups (leave dnsmasq in place)
  rm -f /etc/dnsmasq.d/netdash-blocks.conf || true
  color g "[✓] Removed."
  pause
}

main_menu() {
  while true; do
    clear
    header
    cat <<MENU

  1) Install or Reinstall $APP_NAME
  2) Update from GitHub
  3) Edit Core Configuration (.env)
  4) View Live Logs
  5) Stop Service
  6) Start Service
  7) Remove Completely
  8) Exit

MENU
    read -rp "Choose an option [1-8]: " opt
    case "$opt" in
      1) install_or_reinstall ;;
      2) update_from_github ;;
      3) edit_env ;;
      4) view_logs ;;
      5) stop_service ;;
      6) start_service ;;
      7) remove_completely ;;
      8) exit 0 ;;
      *) color r "Invalid option"; sleep 1 ;;
    esac
  done
}

main_menu
