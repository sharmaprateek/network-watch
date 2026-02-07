#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA="$ROOT/data"
SITE="$ROOT/site"
STATE="$ROOT/state"
LOG="$ROOT/logs"

mkdir -p "$DATA" "$SITE" "$STATE" "$LOG"

TS_UTC="$(date -u +"%Y%m%dT%H%M%SZ")"
TS_HUMAN="$(date +"%Y-%m-%d %H:%M:%S %Z")"
IFACE="${NW_INTERFACE:-}"
SUBNET_CIDR="${NW_SUBNET:-}"
if [[ -z "$IFACE" || -z "$SUBNET_CIDR" ]]; then
  echo "ERROR: set NW_INTERFACE and NW_SUBNET (or pass them in environment)." >&2
  exit 2
fi

HOST_IP="$(ip -br addr show dev "$IFACE" | awk '{print $3}' | cut -d/ -f1 | head -n1)"

# 1) L2 inventory (arp-scan; in Docker we typically run as root with NET_RAW)
ARP_OUT="$DATA/${TS_UTC}_arp_scan.txt"
if /usr/sbin/arp-scan --interface="$IFACE" --localnet --plain --ignoredups --timeout=200 --retry=2 >"$ARP_OUT" 2>"$LOG/${TS_UTC}_arp_scan.err"; then
  :
else
  echo "WARN: arp-scan failed (need NET_RAW/NET_ADMIN or sudo)." >>"$LOG/${TS_UTC}_warnings.log"
fi

# 2) Host up list
# Prefer arp-scan results (fast, accurate on local L2) and avoid slow unprivileged nmap host discovery.
ALIVE_OUT="$DATA/${TS_UTC}_alive.txt"
if [[ -s "$ARP_OUT" ]]; then
  awk -F"\t" '{print $1}' "$ARP_OUT" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -V >"$ALIVE_OUT"
else
  /usr/bin/nmap -sn -n "$SUBNET_CIDR" -oG - | awk '/Up$/{print $2}' | sort -V >"$ALIVE_OUT"
fi

# 3) Top 100 ports + light service detection (reasonable hourly noise)
PORTSCAN_OUT="$DATA/${TS_UTC}_top${NW_TOP_PORTS:-100}.txt"
/usr/bin/nmap --top-ports "${NW_TOP_PORTS:-100}" -sV -n -T"${NW_NMAP_TIMING:-4}" ${NW_NMAP_VERSION:---version-light} --max-retries 2 --host-timeout 30s -iL "$ALIVE_OUT" -oN "$PORTSCAN_OUT" \
  >"$LOG/${TS_UTC}_nmap_top.stdout" 2>"$LOG/${TS_UTC}_nmap_top.stderr" || true

# 4) Web probing (read-only HTTP(S) HEAD/GET for title/headers on common web ports)
WEBPROBE_OUT="$DATA/${TS_UTC}_webprobe.json"
python3 "$ROOT/web_probe.py" --nmap "$PORTSCAN_OUT" --out "$WEBPROBE_OUT" --timeout 3 \
  >"$LOG/${TS_UTC}_webprobe.stdout" 2>"$LOG/${TS_UTC}_webprobe.stderr" || true

# 5) Enrichment (reverse DNS + safe SMB scripts when applicable)
ENRICH_OUT="$DATA/${TS_UTC}_enrich.json"
python3 "$ROOT/enrich.py" --nmap "$PORTSCAN_OUT" --webprobe "$WEBPROBE_OUT" --out "$ENRICH_OUT" --ts "$TS_UTC" --root "$ROOT" \
  >"$LOG/${TS_UTC}_enrich.stdout" 2>"$LOG/${TS_UTC}_enrich.stderr" || true

# 6) Render site (static)
python3 "$ROOT/render.py" \
  --root "$ROOT" \
  --timestamp-utc "$TS_UTC" \
  --timestamp-human "$TS_HUMAN" \
  --host-ip "$HOST_IP" \
  --subnet "$SUBNET_CIDR"

# 7) Alerts (best effort)
python3 "$ROOT/alert.py" \
  >"$LOG/${TS_UTC}_alert.stdout" 2>"$LOG/${TS_UTC}_alert.stderr" || true

# 8) Ensure web server is running (no-op in Docker if entrypoint already started it)
if [[ "${NW_NO_SERVER:-0}" != "1" ]]; then
  bash "$ROOT/server.sh" "$HOST_IP"
fi

echo "OK $TS_HUMAN"