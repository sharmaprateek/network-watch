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

### Run

```bash
git clone <this-repo>
cd network-watch
cp .env.example .env
# edit .env with your subnet / interface

docker compose up --build
```

Then open:

- Dashboard: http://localhost:8787/
- App (SPA): http://localhost:8787/app/

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

TBD (choose MIT/Apache-2.0/etc)
