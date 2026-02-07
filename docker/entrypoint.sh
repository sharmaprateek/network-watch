#!/usr/bin/env bash
set -euo pipefail

: "${NW_SUBNET:?NW_SUBNET is required}"
: "${NW_INTERFACE:?NW_INTERFACE is required}"

NW_HTTP_BIND=${NW_HTTP_BIND:-0.0.0.0}
NW_HTTP_PORT=${NW_HTTP_PORT:-8787}
NW_SCAN_EVERY_MINUTES=${NW_SCAN_EVERY_MINUTES:-60}

mkdir -p /app/data /app/logs /app/state

# Start HTTP server in background
python3 -m http.server "${NW_HTTP_PORT}" --bind "${NW_HTTP_BIND}" --directory /app/site >/app/logs/http.log 2>&1 &

# Run one scan immediately, then sleep loop
while true; do
  echo "[network-watch] scan starting at $(date -Is)"
  /app/scan.sh || echo "[network-watch] scan failed (continuing)"
  echo "[network-watch] scan done at $(date -Is)"
  sleep "$((NW_SCAN_EVERY_MINUTES*60))"
done
