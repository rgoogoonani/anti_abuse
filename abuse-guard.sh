#!/bin/bash
# Outbound abuse guard: limits SYN floods and port scans originating from this server
# Usage: abuse-guard.sh start|stop|status

CONF=/etc/abuse-guard.conf

# ---- Defaults (override in /etc/abuse-guard.conf) ----
MODE="enforce"                                   # enforce | log
LEGIT_PORTS="80,443,8443,853,5222,5223,5228,993,995"
SCAN_DST_RATE="20/sec";  SCAN_DST_BURST=40       # vertical scan (per destination IP, non-web ports)
SCAN_PORT_RATE="100/sec"; SCAN_PORT_BURST=200    # horizontal scan (per destination port, non-web ports)
WEB_DST_RATE="1500/sec"; WEB_DST_BURST=3000      # emergency flood cap (per destination IP, web ports)
BLOCK_PRIVATE="yes"                              # set "no" if you use Docker / provider private network
PRIVATE_NETS_V4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16"
PRIVATE_NETS_V6="fc00::/7 fe80::/10"

[ -f "$CONF" ] && . "$CONF"

CHAIN=ABUSE_GUARD
DROP_CHAIN=ABUSE_DROP
HT="--hashlimit-htable-size 65536 --hashlimit-htable-max 524288 --hashlimit-htable-expire 10000"

teardown() {
    local IPT=$1
    command -v $IPT >/dev/null || return 0
    while $IPT -D OUTPUT -p tcp --syn -j $CHAIN 2>/dev/null; do :; done
    $IPT -F $CHAIN 2>/dev/null || true; $IPT -X $CHAIN 2>/dev/null || true
    $IPT -F $DROP_CHAIN 2>/dev/null || true; $IPT -X $DROP_CHAIN 2>/dev/null || true
}

setup() {
    local IPT=$1; shift
    local PRIVATE_NETS="$*"

    command -v $IPT >/dev/null || { echo "[SKIP] $IPT not found"; return 0; }
    $IPT -L -n >/dev/null 2>&1 || { echo "[SKIP] $IPT not usable on this system"; return 0; }

    teardown $IPT
    $IPT -N $CHAIN
    $IPT -N $DROP_CHAIN

    # Log (rate-limited), then drop unless in log-only mode
    $IPT -A $DROP_CHAIN -m limit --limit 6/min -j LOG --log-prefix "ABUSE_GUARD: " --log-level 4
    [ "$MODE" = "enforce" ] && $IPT -A $DROP_CHAIN -j DROP

    # Hook only new outbound TCP connections
    $IPT -I OUTPUT 1 -p tcp --syn -j $CHAIN

    # Loopback is always allowed
    $IPT -A $CHAIN -o lo -j RETURN

    # Block private ranges
    if [ "$BLOCK_PRIVATE" = "yes" ]; then
        for net in $PRIVATE_NETS; do
            $IPT -A $CHAIN -p tcp -d "$net" -j REJECT --reject-with tcp-reset
        done
    fi

    # 1) Vertical scan: many new connections to one IP on non-web ports
    $IPT -A $CHAIN -p tcp -m multiport ! --dports $LEGIT_PORTS \
        -m hashlimit --hashlimit-name ${IPT}_dst \
        --hashlimit-mode dstip --hashlimit-above $SCAN_DST_RATE --hashlimit-burst $SCAN_DST_BURST \
        $HT -j $DROP_CHAIN

    # 2) Horizontal scan: same non-web port across many IPs
    $IPT -A $CHAIN -p tcp -m multiport ! --dports $LEGIT_PORTS \
        -m hashlimit --hashlimit-name ${IPT}_port \
        --hashlimit-mode dstport --hashlimit-above $SCAN_PORT_RATE --hashlimit-burst $SCAN_PORT_BURST \
        $HT -j $DROP_CHAIN

    # 3) Emergency flood cap on web ports per destination IP (very high on purpose)
    $IPT -A $CHAIN -p tcp -m multiport --dports $LEGIT_PORTS \
        -m hashlimit --hashlimit-name ${IPT}_web \
        --hashlimit-mode dstip --hashlimit-above $WEB_DST_RATE --hashlimit-burst $WEB_DST_BURST \
        $HT -j $DROP_CHAIN

    echo "[OK] $IPT rules applied (mode: $MODE)"
}

case "${1:-start}" in
    start)
        set -e
        setup iptables  $PRIVATE_NETS_V4
        setup ip6tables $PRIVATE_NETS_V6
        echo "[DONE] Abuse guard is active"
        ;;
    stop)
        teardown iptables
        teardown ip6tables
        echo "[DONE] Abuse guard rules removed"
        ;;
    status)
        echo "Mode: $MODE"
        iptables -L $CHAIN -v -n 2>/dev/null || echo "IPv4 chain not loaded"
        ip6tables -L $CHAIN -v -n 2>/dev/null || echo "IPv6 chain not loaded"
        ;;
    *)
        echo "Usage: $0 start|stop|status"; exit 1
        ;;
esac
