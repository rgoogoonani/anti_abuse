#!/bin/bash
# Installer for anti_abuse (outbound SYN flood / port scan guard)
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/rgoogoonani/anti_abuse/main/install.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/rgoogoonani/anti_abuse/main/install.sh) --log-only
#   bash <(curl -fsSL https://raw.githubusercontent.com/rgoogoonani/anti_abuse/main/install.sh) --uninstall
set -e

REPO_RAW="https://raw.githubusercontent.com/rgoogoonani/anti_abuse/main"
BIN=/usr/local/sbin/abuse-guard.sh
CONF=/etc/abuse-guard.conf
SERVICE=/etc/systemd/system/abuse-guard.service
SYSCTL=/etc/sysctl.d/90-abuse-guard-conntrack.conf

info() { echo -e "\e[32m[INFO]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }
fail() { echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "Please run as root"

MODE="enforce"
case "$1" in
    --log-only) MODE="log" ;;
    --uninstall)
        info "Uninstalling abuse guard..."
        systemctl disable --now abuse-guard 2>/dev/null || true
        [ -x "$BIN" ] && "$BIN" stop || true
        rm -f "$BIN" "$SERVICE" "$SYSCTL"
        systemctl daemon-reload
        info "Uninstalled. Config kept at $CONF (remove it manually if not needed)"
        exit 0
        ;;
    "") ;;
    *) fail "Unknown option: $1 (use --log-only or --uninstall)" ;;
esac

# Dependencies
if ! command -v iptables >/dev/null || ! command -v curl >/dev/null; then
    info "Installing dependencies..."
    apt-get update -qq && apt-get install -y -qq iptables curl >/dev/null
fi

# Main script
info "Downloading abuse-guard.sh..."
curl -fsSL "$REPO_RAW/abuse-guard.sh" -o "$BIN" || fail "Download failed"
chmod +x "$BIN"

# Config (never overwrite an existing one, only update MODE)
if [ ! -f "$CONF" ]; then
    cat > "$CONF" <<EOF
# abuse-guard configuration. Apply changes with: systemctl restart abuse-guard
MODE="$MODE"                                   # enforce | log
LEGIT_PORTS="80,443,8443,853,5222,5223,5228,993,995"
SCAN_DST_RATE="20/sec";  SCAN_DST_BURST=40
SCAN_PORT_RATE="100/sec"; SCAN_PORT_BURST=200
WEB_DST_RATE="1500/sec"; WEB_DST_BURST=3000
BLOCK_PRIVATE="yes"                            # set "no" if you use Docker / provider private network
EOF
    info "Config created at $CONF"
else
    sed -i "s/^MODE=.*/MODE=\"$MODE\"/" "$CONF"
    info "Existing config kept at $CONF (mode set to $MODE)"
fi

# Docker warning
if ip -4 addr show 2>/dev/null | grep -qE 'inet (172\.(1[6-9]|2[0-9]|3[01])|10\.|192\.168\.)'; then
    warn "Private IPs detected on this host (Docker / private network?)."
    warn "If services use them, set BLOCK_PRIVATE=\"no\" in $CONF and restart."
fi

# Conntrack table size for high user counts (only if conntrack is in use; our rules are stateless)
if [ ! -e /proc/sys/net/netfilter/nf_conntrack_max ]; then
    info "Conntrack not loaded, nothing to tune (rules are stateless)"
elif [ "$(sysctl -n net.netfilter.nf_conntrack_max)" -lt 1048576 ]; then
    cat > "$SYSCTL" <<'EOF'
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
EOF
    sysctl -p "$SYSCTL" >/dev/null 2>&1 || warn "Could not apply conntrack sysctl now (will apply after module loads)"
    info "Conntrack max raised to 1048576"
fi

# systemd service
cat > "$SERVICE" <<EOF
[Unit]
Description=Outbound abuse guard (SYN flood / port scan limiter)
After=network-online.target ufw.service docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN start
ExecStop=$BIN stop
ExecReload=$BIN start
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable abuse-guard >/dev/null 2>&1
systemctl restart abuse-guard

info "Installation complete (mode: $MODE)"
echo
echo "  Status:     abuse-guard.sh status"
echo "  Logs:       journalctl -k | grep ABUSE_GUARD"
echo "  Config:     $CONF  (then: systemctl restart abuse-guard)"
echo "  Uninstall:  bash <(curl -fsSL $REPO_RAW/install.sh) --uninstall"
