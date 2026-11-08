# anti_abuse

Outbound abuse guard for Linux proxy/VPN servers (Xray, V2Ray, etc.).
Stops users from running **SYN floods** and **port scans** through your server, which is the usual cause of abuse reports (Hetzner, OVH, ...).

Tuned for busy servers (thousands of users): normal web traffic (80/443 and other common ports) is not throttled, only scan-like behavior is.

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/rgoogoonani/anti_abuse/main/install.sh)
```

**Log-only mode** (recommended for the first few days, nothing is dropped, suspicious traffic is only logged):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/rgoogoonani/anti_abuse/main/install.sh) --log-only
```

Switch to enforce mode later by re-running the normal install command.

**Uninstall:**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/rgoogoonani/anti_abuse/main/install.sh) --uninstall
```

## What it does

All rules apply only to **new outbound TCP connections** (`OUTPUT` chain, SYN packets), so incoming traffic and established connections are untouched.

| Rule | Detects | Default limit |
|---|---|---|
| Private ranges | Scanning internal networks (10.x, 192.168.x, 172.16-31.x, 100.64.x, ...) | Rejected |
| Vertical scan | Many connections to one IP on non-web ports | 20/sec per IP |
| Horizontal scan | One port (22, 3389, 23, ...) across many IPs | 100/sec per port |
| Flood cap | Flood to one IP on web ports | 1500/sec per IP |

Both IPv4 and IPv6 are covered. The rules are stateless (no conntrack needed); if conntrack is already in use (e.g. ufw), the installer raises `nf_conntrack_max` to 1048576 if it is lower.

## Usage

```bash
abuse-guard.sh status                  # rules and packet counters
journalctl -k | grep ABUSE_GUARD       # blocked connections
systemctl restart abuse-guard          # apply config changes
```

Top blocked destinations in the last hour:

```bash
journalctl -k --since "1 hour ago" | grep ABUSE_GUARD | grep -oP 'DST=\S+|DPT=\S+' | sort | uniq -c | sort -rn | head -30
```

## Configuration

Edit `/etc/abuse-guard.conf`, then `systemctl restart abuse-guard`.

- `MODE` — `enforce` or `log`
- `LEGIT_PORTS` — ports excluded from scan rules
- `SCAN_DST_RATE`, `SCAN_PORT_RATE`, `WEB_DST_RATE` (+ `_BURST`) — thresholds
- `BLOCK_PRIVATE` — set to `no` if you use Docker or a provider private network (Hetzner Private Network, OVH vRack)

If a legitimate service gets blocked (check the logs), add its port to `LEGIT_PORTS` or raise the thresholds.

## Recommended Xray routing rules

Add these to the top of `routing.rules` as an extra layer:

```json
{ "type": "field", "ip": ["geoip:private"], "outboundTag": "block" },
{ "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" },
{ "type": "field", "port": "25,465,587", "outboundTag": "block" }
```

with an outbound `{ "protocol": "blackhole", "tag": "block" }`, and `sniffing` enabled on inbounds.

## Notes

- Xray connections all originate from the server itself, so the firewall cannot tell users apart. To find the abusing user, enable the Xray access log and match the destination IP from `ABUSE_GUARD` logs.
- WireGuard / AmneziaWG traffic goes through the `FORWARD` chain and is **not** covered by these rules.
- Designed for Ubuntu 24.04 and Debian.
