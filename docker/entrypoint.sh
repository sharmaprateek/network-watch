#!/usr/bin/env bash
set -euo pipefail

: "${NW_SUBNET:?NW_SUBNET is required}"
: "${NW_INTERFACE:?NW_INTERFACE is required}"

NW_HTTP_PORT=${NW_HTTP_PORT:-8787}
NW_SCAN_EVERY_MINUTES=${NW_SCAN_EVERY_MINUTES:-60}

mkdir -p /app/data /app/logs /app/state

# Start HTTP server in background
# Bind to the host's LAN IP by default (more predictable with host networking).
# If NW_HTTP_BIND is explicitly set, use it.
if [[ -n "${NW_HTTP_BIND:-}" ]]; then
  BIND_IP="${NW_HTTP_BIND}"
else
  BIND_IP="$(ip -br addr show dev "${NW_INTERFACE}" | awk '{print $3}' | cut -d/ -f1 | head -n1)"
fi

python3 -m http.server "${NW_HTTP_PORT}" --bind "${BIND_IP}" --directory /app/site >/app/logs/http.log 2>&1 &

echo "[network-watch] http server: http://${BIND_IP}:${NW_HTTP_PORT}/"

# Run one scan immediately, then sleep loop
while true; do
  echo "[network-watch] scan starting at $(date -Is)"
  /app/scan.sh || echo "[network-watch] scan failed (continuing)"
  echo "[network-watch] scan done at $(date -Is)"
  sleep "$((NW_SCAN_EVERY_MINUTES*60))"
done
