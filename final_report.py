#!/usr/bin/env python3
import glob
import json
import os
from collections import defaultdict

def main():
    root = os.path.dirname(os.path.abspath(__file__))
    state = os.path.join(root, 'state')
    out_dir = os.path.join(root, 'reports')
    os.makedirs(out_dir, exist_ok=True)

    snapshots = []
    for p in sorted(glob.glob(os.path.join(state, '*.json'))):
        if p.endswith('latest.json'):
            continue
        try:
            with open(p, 'r') as f:
                snapshots.append(json.load(f))
        except Exception:
            pass

    if not snapshots:
        print('No snapshots found.')
        return

    first = snapshots[0]
    last = snapshots[-1]

    # Tally
    seen_counts = defaultdict(int)
    mac_by_ip = {}
    vendor_by_ip = {}
    ports_by_ip = defaultdict(lambda: defaultdict(int))  # ip -> rawportline -> count
    flags_by_ip = defaultdict(lambda: defaultdict(int))

    for s in snapshots:
        for d in s.get('devices', []):
            ip = d.get('ip')
            if not ip:
                continue
            seen_counts[ip] += 1
            if d.get('mac'):
                mac_by_ip[ip] = d['mac']
            if d.get('vendor'):
                vendor_by_ip[ip] = d['vendor']
            for p in d.get('open_ports', []) or []:
                raw = p.get('raw') or f"{p.get('port')} {p.get('service')} {p.get('version')}"
                ports_by_ip[ip][raw] += 1
            for fl in d.get('risk_flags', []) or []:
                flags_by_ip[ip][fl] += 1

    total = len(snapshots)

    lines = []
    lines.append(f"Network Watch Final Report")
    lines.append(f"Snapshots: {total}")
    lines.append(f"From: {first.get('timestamp_human')} ({first.get('timestamp_utc')})")
    lines.append(f"To:   {last.get('timestamp_human')} ({last.get('timestamp_utc')})")
    lines.append(f"Subnet: {last.get('subnet')}")
    lines.append("")

    # Sort by prevalence
    ips_sorted = sorted(seen_counts.keys(), key=lambda ip: (-seen_counts[ip], list(map(int, ip.split('.')))))

    for ip in ips_sorted:
        lines.append(f"{ip}  seen {seen_counts[ip]}/{total} hours")
        if ip in vendor_by_ip or ip in mac_by_ip:
            lines.append(f"  MAC: {mac_by_ip.get(ip,'')}  Vendor: {vendor_by_ip.get(ip,'')}")
        if flags_by_ip[ip]:
            top_flags = sorted(flags_by_ip[ip].items(), key=lambda kv: -kv[1])
            lines.append("  Risk flags:")
            for fl, c in top_flags[:10]:
                lines.append(f"    - {fl} ({c}h)")
        if ports_by_ip[ip]:
            top_ports = sorted(ports_by_ip[ip].items(), key=lambda kv: -kv[1])
            lines.append("  Open ports observed (top):")
            for raw, c in top_ports[:15]:
                lines.append(f"    - {raw} ({c}h)")
        lines.append("")

    out_path = os.path.join(out_dir, f"final_{last.get('timestamp_utc')}.txt")
    with open(out_path, 'w') as f:
        f.write("\n".join(lines))

    print(out_path)

if __name__ == '__main__':
    main()
