# Network Watch

Inventory-first, LAN-only home network monitor.

- Hourly (or configurable) device inventory
- MAC-keyed identity (stable across IP churn)
- Lightweight exposure scan (top TCP ports + version-light)
- Safe enrichment (headers/titles, SSDP/UPnP, optional mDNS)
- Static dashboard + offline SPA (sidebar UI)

> This project is designed for **your own LAN**. Do not use it to scan networks you don't own or have permission to monitor.

## Quickstart (Docker)

### Requirements

- Docker + Docker Compose
- Linux host recommended for best results (ARP + raw sockets)

### Configuration

Edit `.env` (copied from `.env.example`). Common knobs:

- `NW_SUBNET` — LAN CIDR to monitor (e.g. `192.168.235.0/24`)
- `NW_INTERFACE` — interface connected to that LAN (e.g. `ens18`)
- `NW_HTTP_PORT` — web UI port
- `NW_SCAN_EVERY_MINUTES` — scan cadence

### Run

```bash
# local repo (no clone yet)
cd network-watch-public
cp .env.example .env
# edit .env with your subnet / interface

docker compose up --build
```

Then open (default):

- Dashboard: http://localhost:${NW_HTTP_PORT:-8787}/
- App (SPA): http://localhost:${NW_HTTP_PORT:-8787}/app/

Change the port by setting `NW_HTTP_PORT` in `.env`.
## How it works

A scan loop runs periodically:

1. Discovery (ARP scan + ping sweep fallback)
2. Port scan (nmap top ports)
3. Enrichment (web probe, SSDP)
4. Render static site artifacts

Artifacts are written to `./state/`, `./data/`, `./site/` and served over HTTP.

## Documentation

See `docs/`:

- `docs/setup.md` — configuration and deployment options
- `docs/security.md` — scanning scope and safety posture
- `docs/architecture.md` — pipeline + file formats
- `docs/troubleshooting.md`

## License

MIT — see `LICENSE`.
