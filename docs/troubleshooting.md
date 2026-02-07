# Troubleshooting

## No devices found

- Confirm `NW_SUBNET` is correct
- Confirm `NW_INTERFACE` is correct
- If using Docker, prefer `network_mode: host`

## arp-scan permission errors

`arp-scan` often needs raw socket access.

In Docker:
- `cap_add: [NET_RAW, NET_ADMIN]`
- `network_mode: host`

## nmap slow/timeouts

- reduce `NW_TOP_PORTS`
- reduce timing (e.g. `T3`)
