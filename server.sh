#!/usr/bin/env bash
set -euo pipefail

HOST_IP="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE="$ROOT/site"
PIDFILE="$ROOT/state/http_server.pid"
PORT="${NW_HTTP_PORT:-8787}"

mkdir -p "$ROOT/state"

# If running, keep it.
if [[ -f "$PIDFILE" ]]; then
  PID="$(cat "$PIDFILE" || true)"
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    exit 0
  fi
fi

# Default bind: provided LAN IP; fallback: configured bind; final fallback: 0.0.0.0
BIND="${HOST_IP:-${NW_HTTP_BIND:-0.0.0.0}}"

# Start server
nohup python3 -m http.server "$PORT" --directory "$SITE" --bind "$BIND" >"$ROOT/logs/http_server.log" 2>&1 &
PID=$!
echo "$PID" >"$PIDFILE"
