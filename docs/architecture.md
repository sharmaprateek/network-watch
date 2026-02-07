# Architecture

## Pipeline

1. `scan.sh`
   - discovers alive hosts
   - runs nmap top ports scan
   - runs enrichment probes
   - calls `render.py` to generate the static site

2. `render.py`
   - merges latest enriched data + historical snapshots
   - writes `site/latest.json`, `site/history.json`, `site/device_stats.json`
   - renders HTML pages

## Data directories

- `state/` — snapshots and config (`aliases.json`, `overrides.json`, `alerts.json`)
- `data/` — raw scan outputs (nmap, webprobe, ssdp)
- `site/` — static website output served over HTTP
