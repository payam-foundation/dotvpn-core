#!/usr/bin/env bash
# dotvpn-core installer. Usage:
#   curl -fsSL https://raw.githubusercontent.com/payam-foundation/dotvpn-core/main/deploy/install.sh | sudo bash -s -- --role allinone --domain vpn.example.com
#
# Roles: allinone | node | control
# Flags: --role R --domain D --email E --advertise H:P --listen A --decoy SPEC
#        --control URL --join-token T --trusted-key K
#        --cdnws-path P --webtunnel-path P --version vX.Y.Z --from-dir DIR
#        --upgrade | --rollback | --uninstall | --no-start | --no-firewall
set -euo pipefail

REPO="${DOTVPN_REPO:-payam-foundation/dotvpn-core}"
BIN=/usr/local/bin/dotvpn-core
CONF_DIR=/etc/dotvpn
DATA_DIR=/var/lib/dotvpn
USER_NAME=dotvpn

ROLE=allinone DOMAIN="" EMAIL="" ADVERTISE="" LISTEN="" DECOY="" CONTROL="" JOIN="" TRUSTED=""
CDNWS="" WEBTUNNEL="" VERSION="latest" FROM_DIR="" ACTION=install START=1 FIREWALL=1

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE=$2; shift 2 ;;
    --domain) DOMAIN=$2; shift 2 ;;
    --email) EMAIL=$2; shift 2 ;;
    --advertise) ADVERTISE=$2; shift 2 ;;
    --listen) LISTEN=$2; shift 2 ;;
    --decoy) DECOY=$2; shift 2 ;;
    --control) CONTROL=$2; shift 2 ;;
    --join-token) JOIN=$2; shift 2 ;;
    --trusted-key) TRUSTED=$2; shift 2 ;;
    --cdnws-path) CDNWS=$2; shift 2 ;;
    --webtunnel-path) WEBTUNNEL=$2; shift 2 ;;
    --version) VERSION=$2; shift 2 ;;
    --from-dir) FROM_DIR=$2; shift 2 ;;
    --upgrade) ACTION=upgrade; shift ;;
    --rollback) ACTION=rollback; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    --no-start) START=0; shift ;;
    --no-firewall) FIREWALL=0; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ "$(uname -s)" = Linux ] || die "the server installer supports Linux only"
command -v systemctl >/dev/null || die "systemd is required"

case "$ROLE" in allinone|node|control) ;; *) die "invalid --role $ROLE" ;; esac
UNIT="dotvpn-core-$ROLE"
[ "$ROLE" = allinone ] && UNIT=dotvpn-core

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
}

fetch() { # url dest
  if command -v curl >/dev/null; then curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null; then wget -q -O "$2" "$1"
  else die "curl or wget required"; fi
}

install_binary() {
  local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  local a; a=$(arch)
  if [ -n "$FROM_DIR" ]; then
    cp "$FROM_DIR/dotvpn-core_linux_$a" "$tmp/dotvpn-core"
  else
    local base
    if [ "$VERSION" = latest ]; then base="https://github.com/$REPO/releases/latest/download"
    else base="https://github.com/$REPO/releases/download/$VERSION"; fi
    local name="dotvpn-core_linux_$a"
    log "downloading $name ($VERSION)"
    fetch "$base/$name" "$tmp/dotvpn-core"
    fetch "$base/checksums.txt" "$tmp/checksums.txt"
    local want; want=$(awk -v n="$name" '$2==n {print $1}' "$tmp/checksums.txt")
    [ -n "$want" ] || die "no checksum for $name"
    local got; got=$(sha256sum "$tmp/dotvpn-core" | awk '{print $1}')
    [ "$want" = "$got" ] || die "checksum mismatch for $name"
  fi
  chmod 0755 "$tmp/dotvpn-core"
  "$tmp/dotvpn-core" version >/dev/null || die "downloaded binary does not run"
  [ -f "$BIN" ] && cp -f "$BIN" "$BIN.prev"
  install -m 0755 "$tmp/dotvpn-core" "$BIN.new"
  mv -f "$BIN.new" "$BIN"
}

ensure_user() {
  id "$USER_NAME" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$USER_NAME"
  install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$DATA_DIR"
  install -d -o root -g "$USER_NAME" -m 0750 "$CONF_DIR"
}

write_unit() {
  local cmd="$BIN $ROLE -config $CONF_DIR/config.yaml"
  cat >"/etc/systemd/system/$UNIT.service" <<EOF
[Unit]
Description=dotvpn $ROLE
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
Group=$USER_NAME
ExecStart=$cmd
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=$DATA_DIR
ReadOnlyPaths=$CONF_DIR
StateDirectory=dotvpn

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

tune_kernel() {
  cat >/etc/sysctl.d/99-dotvpn.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=7500000
net.core.wmem_max=7500000
EOF
  sysctl -p /etc/sysctl.d/99-dotvpn.conf >/dev/null 2>&1 || true
}

open_ports() {
  [ "$FIREWALL" -eq 1 ] || return 0
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw allow 443/udp >/dev/null
    log "opened 80/tcp 443/tcp 443/udp in ufw"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port=80/tcp --add-port=443/tcp --add-port=443/udp && firewall-cmd -q --reload
    log "opened 80/tcp 443/tcp 443/udp in firewalld"
  fi
}

do_init() {
  [ -f "$CONF_DIR/config.yaml" ] && { log "keeping existing $CONF_DIR/config.yaml"; return; }
  local args=(init -role "$ROLE" -config "$CONF_DIR/config.yaml" -data-dir "$DATA_DIR")
  [ -n "$DOMAIN" ] && args+=(-domain "$DOMAIN")
  [ -n "$EMAIL" ] && args+=(-email "$EMAIL")
  [ -n "$ADVERTISE" ] && args+=(-advertise "$ADVERTISE")
  [ -n "$LISTEN" ] && args+=(-listen "$LISTEN")
  [ -n "$DECOY" ] && args+=(-decoy "$DECOY")
  [ -n "$CONTROL" ] && args+=(-control "$CONTROL")
  [ -n "$JOIN" ] && args+=(-join-token "$JOIN")
  [ -n "$TRUSTED" ] && args+=(-trusted-key "$TRUSTED")
  [ -n "$CDNWS" ] && args+=(-cdnws-path "$CDNWS")
  [ -n "$WEBTUNNEL" ] && args+=(-webtunnel-path "$WEBTUNNEL")
  "$BIN" "${args[@]}"
  chown root:"$USER_NAME" "$CONF_DIR/config.yaml"
  chmod 0640 "$CONF_DIR/config.yaml"
}

case "$ACTION" in
  uninstall)
    for u in dotvpn-core dotvpn-core-node dotvpn-core-control; do
      systemctl disable --now "$u" 2>/dev/null || true
      rm -f "/etc/systemd/system/$u.service"
    done
    systemctl daemon-reload
    rm -f "$BIN" "$BIN.prev" /etc/sysctl.d/99-dotvpn.conf
    log "removed binary and units; kept $CONF_DIR and $DATA_DIR (delete them to drop keys and data)"
    exit 0 ;;
  rollback)
    [ -f "$BIN.prev" ] || die "no previous version at $BIN.prev"
    cp -f "$BIN" "$BIN.rolledback"; mv -f "$BIN.prev" "$BIN"
    systemctl restart "$UNIT"
    log "rolled back to $("$BIN" version)"
    exit 0 ;;
  upgrade)
    install_binary
    systemctl restart "$UNIT"
    log "upgraded to $("$BIN" version); previous binary kept as $BIN.prev"
    exit 0 ;;
esac

install_binary
ensure_user
do_init
case "$ROLE" in allinone|node) tune_kernel; open_ports ;; esac
write_unit
if [ "$START" -eq 1 ]; then
  systemctl enable --now "$UNIT"
  sleep 2
  systemctl is-active --quiet "$UNIT" || { journalctl -u "$UNIT" -n 30 --no-pager; die "service failed to start"; }
  log "$UNIT is running"
fi

case "$ROLE" in
  allinone|node)
    echo
    log "give users this invite string (static token valid 30 days):"
    sudo -u "$USER_NAME" "$BIN" invite -static -config "$CONF_DIR/config.yaml" || true
    echo
    log "client: dotvpn -invite '<string>'  (see the dotvpn-client repo)"
    ;;
esac
log "done. Check status: systemctl status $UNIT   Logs: journalctl -u $UNIT -f"
