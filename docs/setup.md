# Setup & Deploy

## Configuration

Copy the env file:

```bash
cp .env.example .env
```

Edit:

- `NW_SUBNET` — the LAN you want to monitor (e.g. `192.168.1.0/24`)
- `NW_INTERFACE` — the interface on the host connected to that LAN (e.g. `eth0`)
- `NW_SCAN_EVERY_MINUTES` — scan cadence

## Docker (recommended)

```bash
docker compose up --build
```

### Why `network_mode: host`?

For LAN discovery, ARP scanning and accurate host visibility usually require direct access to the host network stack.

If you cannot use host networking, you can still run **nmap-only** scans, but results may be incomplete.

## Bare metal (no Docker)

Install:

- `nmap`
- `arp-scan`
- Python 3.10+

Then run:

```bash
bash scan.sh
python3 -m http.server 8787 --bind 0.0.0.0 --directory site
```

## Binding note

In Docker (host network), leaving `NW_HTTP_BIND` blank will bind the server to the IP of `NW_INTERFACE`.
Set `NW_HTTP_BIND=0.0.0.0` if you explicitly want to listen on all addresses.
