#!/usr/bin/env python3
import json
import os
import re
import subprocess
from datetime import datetime, timezone


def load_json(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 999, "", str(e)


def now_epoch():
    return int(datetime.now(timezone.utc).timestamp())


def format_device(d):
    name = (d.get('name') or '').strip()
    vendor = (d.get('vendor') or '').strip()
    mac = (d.get('mac') or '').strip()
    ip = (d.get('ip') or '').strip()
    primary = name or vendor or mac or d.get('id')
    return f"{primary} ({mac}) @ {ip}" if mac else f"{primary} @ {ip}"


def ports_set(d):
    s = set()
    for p in d.get('open_ports') or []:
        port = p.get('port')
        if port:
            s.add(port)
    return s


def risk_ports_changed(old, new):
    risky = {'22/tcp','139/tcp','445/tcp','548/tcp','5000/tcp','5001/tcp','8833/tcp','9100/tcp','515/tcp','2049/tcp','111/tcp'}
    added = (new - old) & risky
    removed = (old - new) & risky
    return added, removed


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    state = os.path.join(root, 'state')
    site = os.path.join(root, 'site')

    cfg = load_json(os.path.join(state, 'alerts.json')) or {}
    if not cfg.get('enabled', True):
        return
    mode = (cfg.get('mode') or 'all').strip().lower()
    include_ports = bool(cfg.get('includePortChanges', True))

    latest = load_json(os.path.join(state, 'latest.json'))
    if not latest:
        return

    # Find previous snapshot file by timestamp ordering
    snaps = sorted([p for p in os.listdir(state) if re.match(r'^\d{8}T\d{6}Z\.json$', p)])
    prev = None
    if len(snaps) >= 2:
        prev = load_json(os.path.join(state, snaps[-2]))

    if not prev:
        return

    # Rate limit
    rl_min = int(cfg.get('rateLimitMinutes', 5) or 5)
    last_alert_path = os.path.join(state, 'last_alert_epoch.txt')
    last_epoch = 0
    try:
        last_epoch = int(open(last_alert_path).read().strip())
    except Exception:
        last_epoch = 0

    if now_epoch() - last_epoch < rl_min * 60:
        return

    prev_by_id = {d.get('id'): d for d in (prev.get('devices') or []) if d.get('id')}
    now_by_id = {d.get('id'): d for d in (latest.get('devices') or []) if d.get('id')}

    new_ids = [i for i in now_by_id.keys() if i not in prev_by_id]
    gone_ids = [i for i in prev_by_id.keys() if i not in now_by_id]

    port_events = []
    for did, dnow in now_by_id.items():
        dold = prev_by_id.get(did)
        if not dold:
            continue
        oldp = ports_set(dold)
        newp = ports_set(dnow)
        added = newp - oldp
        removed = oldp - newp
        r_add, r_rem = risk_ports_changed(oldp, newp)
        if added or removed:
            port_events.append((dnow, added, removed, r_add, r_rem))

    # Minimal mode: only delta + link
    if mode == 'minimal':
        if not (new_ids or gone_ids):
            return
        lines = []
        lines.append(f"Network Watch ({latest.get('timestamp_human','')})")
        if new_ids:
            lines.append(f"+{len(new_ids)} new")
            for did in new_ids[:10]:
                lines.append("- " + format_device(now_by_id[did]))
            if len(new_ids) > 10:
                lines.append(f"- ... +{len(new_ids)-10} more")
        if gone_ids:
            lines.append(f"-{len(gone_ids)} gone")
            for did in gone_ids[:10]:
                lines.append("- " + format_device(prev_by_id[did]))
            if len(gone_ids) > 10:
                lines.append(f"- ... +{len(gone_ids)-10} more")
        lines.append("http://192.168.235.175:8787/")
        msg = "\n".join(lines)
    else:
        if not (new_ids or gone_ids or (include_ports and port_events)):
            return

        lines = []
        lines.append(f"Network Watch alert @ {latest.get('timestamp_human','')}")

        if new_ids:
            lines.append(f"New devices ({len(new_ids)}):")
            for did in new_ids[:15]:
                lines.append("- " + format_device(now_by_id[did]))
            if len(new_ids) > 15:
                lines.append(f"- ... +{len(new_ids)-15} more")

        if gone_ids:
            lines.append(f"Gone devices ({len(gone_ids)}):")
            for did in gone_ids[:15]:
                lines.append("- " + format_device(prev_by_id[did]))
            if len(gone_ids) > 15:
                lines.append(f"- ... +{len(gone_ids)-15} more")

        if include_ports:
            # Highlight risky port changes first
            risky_lines = []
            other_lines = []
            for d, added, removed, r_add, r_rem in port_events:
                if r_add or r_rem:
                    risky_lines.append((d, r_add, r_rem))
                elif added or removed:
                    other_lines.append((d, added, removed))

            if risky_lines:
                lines.append("Risky port changes:")
                for d, a, r in risky_lines[:10]:
                    lines.append(f"- {format_device(d)} +{sorted(a)} -{sorted(r)}")

            if other_lines:
                lines.append("Other port changes:")
                for d, a, r in other_lines[:10]:
                    lines.append(f"- {format_device(d)} +{len(a)} -{len(r)}")

        lines.append("Dashboard: http://192.168.235.175:8787/")
        msg = "\n".join(lines)

    # Wake with message
    run(['openclaw', 'gateway', 'wake', '--text', msg, '--mode', 'now'], timeout=10)

    with open(last_alert_path, 'w') as f:
        f.write(str(now_epoch()))


if __name__ == '__main__':
    main()
