# Security & Safety

## Scope

- Intended for **LAN-only** monitoring.
- Do not scan networks you do not own or do not have explicit permission to monitor.

## What Network Watch does

- Host discovery (ARP/ping sweep)
- Port scanning: **top N TCP ports**
- Lightweight service identification (`nmap -sV --version-light`)
- Safe enrichment:
  - HTTP(S) HEAD + title
  - TLS certificate summary
  - SSDP/UPnP M-SEARCH

## What it does NOT do

- No exploitation
- No credential attacks
- No brute forcing
- No vulnerability exploitation

Risk flags are **heuristics** intended to help you notice high-risk exposure (e.g. printer ports, SMB exposure).
