#!/usr/bin/env python3
import argparse
import glob
import html
import json
import os
import re


def read_lines(path):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


def parse_arp_scan(txt_path):
    # arp-scan --plain: "IP\tMAC\tVENDOR"
    rows = []
    for line in read_lines(txt_path):
        parts = line.split('\t')
        if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            ip = parts[0].strip()
            mac = parts[1].strip().lower()
            vendor = parts[2].strip() if len(parts) >= 3 else ""
            rows.append({"ip": ip, "mac": mac, "vendor": vendor})
    return rows


def parse_alive(txt_path):
    ips = []
    for line in read_lines(txt_path):
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            ips.append(line)
    return ips


def parse_nmap_top(nmap_path):
    # Lightweight parser to extract open ports per host
    hosts = {}
    current = None
    for line in read_lines(nmap_path):
        if line.startswith('Nmap scan report for '):
            current = line.split()[-1]
            hosts.setdefault(current, {"ports": []})
        elif current and re.match(r"^\d+/tcp\s+", line):
            cols = line.split()
            if len(cols) >= 3:
                port = cols[0]
                state = cols[1]
                service = cols[2]
                version = ' '.join(cols[3:]) if len(cols) > 3 else ''
                if state == 'open':
                    hosts[current]["ports"].append({
                        "port": port,
                        "service": service,
                        "version": version,
                        "raw": line.strip(),
                    })
    return hosts


def risk_flags_for_ports(ports):
    risky = []
    p = {x["port"].split('/')[0]: x for x in ports}

    def has(port):
        return port in p

    if has('445') or has('139'):
        risky.append('SMB exposed (445/139)')
    if has('548'):
        risky.append('AFP/Netatalk exposed (548)')
    if has('5000') or has('5001'):
        risky.append('NAS/admin web surface (5000/5001)')
    if has('22'):
        risky.append('SSH exposed (22)')
    if has('8833'):
        risky.append('Gateway/admin HTTP surface (8833)')
    # Printing-related ports: 9100 (JetDirect/RAW) is strongly printer; 515 (LPD) can appear on other devices too.
    if has('9100'):
        risky.append('Printer port exposed (9100/JetDirect)')
    elif has('515'):
        risky.append('LPD printing port exposed (515)')
    if has('631'):
        risky.append('IPP printing port exposed (631)')
    if has('111') or has('2049'):
        risky.append('RPC/NFS surface (111/2049)')

    return risky


def ip_key(ip):
    try:
        return list(map(int, ip.split('.')))
    except Exception:
        return [999, 999, 999, 999]


def sparkline(values, width=520, height=80):
    if not values:
        return ""
    mn = min(values)
    mx = max(values)
    rng = (mx - mn) or 1
    pts = []
    for i, v in enumerate(values):
        x = int(i * (width - 2) / max(1, (len(values) - 1))) + 1
        y = int((height - 2) - ((v - mn) * (height - 2) / rng)) + 1
        pts.append(f"{x},{y}")
    return (
        f"<svg width='{width}' height='{height}' viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg'>"
        f"<rect x='0' y='0' width='{width}' height='{height}' fill='#fafafa' stroke='#ddd'/>"
        f"<polyline fill='none' stroke='#333' stroke-width='2' points='{' '.join(pts)}'/>"
        f"</svg>"
    )


def load_aliases(state_dir):
    path = os.path.join(state_dir, 'aliases.json')
    try:
        with open(path, 'r') as f:
            obj = json.load(f)
            aliases = obj.get('aliases', {}) if isinstance(obj, dict) else {}
            return {k.lower(): v for k, v in aliases.items()}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def load_overrides(state_dir):
    """User overrides keyed by MAC.

    File: state/overrides.json
    {
      "types": {"aa:bb:..": "tv"},
      "names": {"aa:bb:..": "Living Room TV"}
    }
    """
    path = os.path.join(state_dir, 'overrides.json')
    try:
        with open(path, 'r') as f:
            obj = json.load(f)
            if not isinstance(obj, dict):
                return {"types": {}, "names": {}}
            types = obj.get('types', {}) or {}
            names = obj.get('names', {}) or {}
            return {
                "types": {k.lower(): v for k, v in types.items()},
                "names": {k.lower(): v for k, v in names.items()},
            }
    except FileNotFoundError:
        return {"types": {}, "names": {}}
    except Exception:
        return {"types": {}, "names": {}}


def load_webprobe(data_dir, ts):
    path = os.path.join(data_dir, f"{ts}_webprobe.json")
    try:
        with open(path, 'r') as f:
            obj = json.load(f)
            res = obj.get('results', []) if isinstance(obj, dict) else []
            by_ip = {}
            for r in res:
                ip = r.get('ip')
                if not ip:
                    continue
                by_ip.setdefault(ip, []).append(r)
            return by_ip
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def load_enrich(data_dir, ts):
    path = os.path.join(data_dir, f"{ts}_enrich.json")
    try:
        with open(path, 'r') as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def device_id(ip, mac):
    if mac and mac != '00:00:00:00:00:00':
        return mac.lower()
    return f"ip:{ip}"


def type_guess(vendor, ports, hostname='', mdns_names=None):
    v = (vendor or '').lower()
    h = (hostname or '').lower()
    md = [x.lower() for x in (mdns_names or [])]
    ps = set(int(p['port'].split('/')[0]) for p in ports) if ports else set()

    # Strong signals first
    if 'firewalla' in v:
        return 'gateway'
    if 'synology' in v:
        return 'nas'
    if 'netgear' in v and (80 in ps or 443 in ps or 53 in ps):
        return 'ap'

    # Google Cast / TV-ish patterns
    # 8008/8009/8443 are commonly seen on Chromecast/Android TV devices.
    if (8008 in ps or 8009 in ps or 8443 in ps) and ('android' in h or any('android' in x for x in md) or 'tv' in h or any('tv' in x for x in md)):
        return 'tv'
    if (8008 in ps or 8009 in ps or 8443 in ps) and ('lg' in v or 'innotek' in v):
        return 'tv'

    # Printers
    if 9100 in ps or 515 in ps:
        return 'printer'

    # IoT vendors
    if 'ring' in v or 'wyze' in v or 'wiz' in v or 'nest' in v:
        return 'iot'

    # Clients
    if 'apple' in v or 'intel' in v:
        return 'client'

    if 'raspberry pi' in v:
        return 'server'

    if 445 in ps or 139 in ps or 5000 in ps or 5001 in ps:
        return 'server'

    return 'unknown'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--timestamp-utc', required=True)
    ap.add_argument('--timestamp-human', required=True)
    ap.add_argument('--host-ip', required=True)
    ap.add_argument('--subnet', required=True)
    args = ap.parse_args()

    # Public app packaging option: only render the offline SPA (+ JSON endpoints).
    # Skip legacy HTML pages (timeline/churn/graph/device/fancy).
    app_only = os.environ.get('NW_APP_ONLY', '').strip().lower() in ('1','true','yes','on')

    root = args.root
    data = os.path.join(root, 'data')
    site = os.path.join(root, 'site')
    state = os.path.join(root, 'state')
    os.makedirs(site, exist_ok=True)
    os.makedirs(state, exist_ok=True)

    aliases = load_aliases(state)
    overrides = load_overrides(state)

    ts = args.timestamp_utc
    arp_path = os.path.join(data, f'{ts}_arp_scan.txt')
    alive_path = os.path.join(data, f'{ts}_alive.txt')
    nmap_path = os.path.join(data, f'{ts}_top100.txt')

    arp_rows = parse_arp_scan(arp_path)
    alive_ips = parse_alive(alive_path)
    nmap_hosts = parse_nmap_top(nmap_path)
    webprobe_by_ip = load_webprobe(data, ts)
    enrich = load_enrich(data, ts)
    rdns = enrich.get('rdns', {}) if isinstance(enrich, dict) else {}
    mdns = enrich.get('mdns', {}) if isinstance(enrich, dict) else {}
    ssdp = enrich.get('ssdp', {}) if isinstance(enrich, dict) else {}

    inv_by_ip = {r['ip']: r for r in arp_rows}

    devices = []
    for ip in sorted(set(alive_ips) | set(inv_by_ip.keys()) | set(nmap_hosts.keys()), key=ip_key):
        inv = inv_by_ip.get(ip, {})
        mac = (inv.get('mac') or '').lower()
        vendor = inv.get('vendor', '')
        did = device_id(ip, mac)
        ports = nmap_hosts.get(ip, {}).get('ports', [])
        flags = risk_flags_for_ports(ports)
        name = aliases.get(mac, '') if mac else ''
        web = webprobe_by_ip.get(ip, [])
        hostname = rdns.get(ip, '')
        # mdns now includes hostnames/services
        mdns_names = []
        mdns_services = []
        if isinstance(mdns, dict):
            mdns_names = (mdns.get('hostnames', {}) or {}).get(ip, [])
            mdns_services = (mdns.get('services', {}) or {}).get(ip, [])

        dtype = type_guess(vendor, ports, hostname=hostname, mdns_names=mdns_names)

        # Apply user overrides by MAC
        if mac and overrides.get('types', {}).get(mac):
            dtype = overrides['types'][mac]
        if mac and overrides.get('names', {}).get(mac):
            name = overrides['names'][mac]

        devices.append({
            'id': did,
            'type': dtype,
            'name': name,
            'hostname': hostname,
            'mdns': mdns_names,
            'mdns_services': mdns_services,
            'ssdp': ssdp.get(ip, []) if isinstance(ssdp, dict) else [],
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'open_ports': ports,
            'web': web,
            'risk_flags': flags,
            'seen_alive': ip in alive_ips,
            'seen_arp': ip in inv_by_ip,
        })

    # Previous snapshot for diff (by device id) with debounce: require 2 consecutive misses
    prev_path = os.path.join(state, 'latest.json')
    prev = None
    if os.path.exists(prev_path):
        with open(prev_path, 'r') as f:
            prev = json.load(f)

    # second previous (timestamped snapshots only)
    prev2 = None
    snap_paths = sorted([
        p for p in glob.glob(os.path.join(state, '*.json'))
        if re.search(r'/\d{8}T\d{6}Z\.json$', p)
    ])
    if len(snap_paths) >= 2:
        try:
            with open(snap_paths[-2], 'r') as f:
                prev2 = json.load(f)
        except Exception:
            prev2 = None

    prev_ids = set(d.get('id') for d in (prev.get('devices', []) if prev else []) if d.get('id'))
    now_ids = set(d.get('id') for d in devices if d.get('id'))

    prev2_ids = set(d.get('id') for d in (prev2.get('devices', []) if prev2 else []) if d.get('id'))

    new_ids = sorted(now_ids - prev_ids)
    # Gone: present in prev and prev2, missing now
    gone_ids = sorted((prev_ids & prev2_ids) - now_ids)

    snapshot = {
        'timestamp_utc': ts,
        'timestamp_human': args.timestamp_human,
        'host_ip': args.host_ip,
        'subnet': args.subnet,
        'devices': devices,
        'diff': {'new_ids': new_ids, 'gone_ids': gone_ids},
    }

    with open(os.path.join(state, f'{ts}.json'), 'w') as f:
        json.dump(snapshot, f, indent=2)
    with open(prev_path, 'w') as f:
        json.dump(snapshot, f, indent=2)

    # History for timeline (up to last 72 timestamped snapshots)
    snap_paths = sorted([
        p for p in glob.glob(os.path.join(state, '*.json'))
        if re.search(r'/\d{8}T\d{6}Z\.json$', p)
    ])[-72:]
    history = []
    for p in snap_paths:
        try:
            with open(p, 'r') as f:
                history.append(json.load(f))
        except Exception:
            pass

    timeline_utc = [h.get('timestamp_utc', '') for h in history]
    counts = [len(h.get('devices', [])) for h in history]

    presence = {}  # device-id -> list[bool]
    meta = {}      # device-id -> summary
    ip_hist = {}   # device-id -> list[str]
    ports_hist = {}  # device-id -> list[list[str]]

    for idx, h in enumerate(history):
        ds = h.get('devices', []) or []
        ids = set(d.get('id') for d in ds if d.get('id'))
        for did in ids:
            presence.setdefault(did, [False] * len(history))
            presence[did][idx] = True
        for d in ds:
            did = d.get('id')
            if not did:
                continue
            meta.setdefault(did, {'name': '', 'vendor': '', 'mac': '', 'type': '', 'last_ip': '', 'hostname': ''})
            meta[did]['name'] = meta[did]['name'] or d.get('name', '')
            meta[did]['vendor'] = meta[did]['vendor'] or d.get('vendor', '')
            meta[did]['mac'] = meta[did]['mac'] or d.get('mac', '')
            # Prefer keeping a meaningful type; allow upgrading from unknown/empty when we later learn more.
            new_type = d.get('type', '')
            if new_type and (not meta[did]['type'] or meta[did]['type'] == 'unknown'):
                meta[did]['type'] = new_type
            elif new_type and meta[did]['type'] != new_type and meta[did]['type'] == 'printer' and new_type == 'tv':
                # allow correcting earlier misclassification
                meta[did]['type'] = new_type

            new_host = d.get('hostname', '')
            if new_host and not meta[did]['hostname']:
                meta[did]['hostname'] = new_host
            meta[did]['last_ip'] = d.get('ip', '') or meta[did]['last_ip']

            ip_hist.setdefault(did, [''] * len(history))
            ip_hist[did][idx] = d.get('ip', '')

            ports_hist.setdefault(did, [[] for _ in range(len(history))])
            plist = [p.get('port') for p in (d.get('open_ports') or []) if p.get('port')]
            ports_hist[did][idx] = sorted(plist)

    def did_sort(did):
        m = meta.get(did, {})
        return (
            0 if (m.get('name') or '').strip() else 1,
            (m.get('type') or ''),
            -sum(presence.get(did, [])),
            m.get('vendor', ''),
            m.get('mac', did),
        )

    did_order = sorted(presence.keys(), key=did_sort)

    def esc(s):
        return html.escape(s or '')

    # Helper to label IDs
    def label_for_id(did):
        m = meta.get(did, {})
        name = (m.get('name') or '').strip()
        vendor = (m.get('vendor') or '').strip()
        mac = (m.get('mac') or '').strip()
        primary = name or vendor or did
        suffix = mac or did
        return f"{primary} ({suffix})" if primary != suffix else primary

    new_html = "<br>".join(esc(label_for_id(x)) for x in new_ids) if new_ids else "(none)"
    gone_html = "<br>".join(esc(label_for_id(x)) for x in gone_ids) if gone_ids else "(none)"

    # Group counts by type
    by_type = {}
    for d in devices:
        by_type.setdefault(d['type'], 0)
        by_type[d['type']] += 1
    type_summary = ', '.join(f"{k}:{v}" for k, v in sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0])))

    # Index table
    rows_html = []
    for d in sorted(devices, key=lambda x: (0 if x.get('name') else 1, x.get('type', ''), ip_key(x['ip']))):
        ports = d['open_ports']
        port_lines = "<br>".join(esc(p['raw']) for p in ports) if ports else ""
        flags = ", ".join(esc(x) for x in d['risk_flags'])

        web_items = d.get('web') or []
        web_lines = []
        for w in sorted(web_items, key=lambda x: (x.get('port', 0), x.get('url', ''))):
            s = w.get('status')
            title = (w.get('title') or '').strip()
            server = (w.get('server') or '').strip()
            url = w.get('url')
            robots = (w.get('robots_txt') or '').strip()
            security = (w.get('security_txt') or '').strip()
            tls_sum = (w.get('tls') or {}).get('summary') if isinstance(w.get('tls'), dict) else None

            parts = []
            if url:
                parts.append(url)
            if s:
                parts.append(f"HTTP {s}")
            if title:
                parts.append(f"title=\"{title[:80]}\"")
            if server:
                parts.append(f"server=\"{server[:60]}\"")

            extra = []
            if robots:
                extra.append('robots.txt')
            if security:
                extra.append('security.txt')
            if tls_sum:
                extra.append('tls')

            line = " • ".join(parts)
            if extra:
                line += " • [" + ", ".join(extra) + "]"
            web_lines.append(line)
        web_html = "<br>".join(esc(x) for x in web_lines)

        display = d.get('name') or d.get('vendor') or ''
        host = d.get('hostname')
        mdns_list = d.get('mdns') or []
        mdns_s = mdns_list[0] if mdns_list else ''
        if mdns_s and mdns_s != host:
            host = mdns_s
        if host:
            display = f"{display} ({host})" if display else host

        device_link = f"/device.html?id={esc(d['id'])}"

        rows_html.append(
            f"<tr>"
            f"<td><b><a href=\"{device_link}\">{esc(display)}</a></b><div class='muted'>{esc(d.get('type',''))}</div></td>"
            f"<td>{esc(d['ip'])}</td>"
            f"<td>{esc(d['mac'])}</td>"
            f"<td>{esc(d['vendor'])}</td>"
            f"<td>{'yes' if d['seen_arp'] else ''}</td>"
            f"<td>{'yes' if d['seen_alive'] else ''}</td>"
            f"<td style='max-width:650px; word-break:break-word'>{port_lines}</td>"
            f"<td style='max-width:650px; word-break:break-word'>{web_html}</td>"
            f"<td>{flags}</td>"
            f"</tr>"
        )

    # If app-only mode: we already wrote the JSON artifacts above, so we can skip
    # generating legacy HTML pages and just ensure / redirects to /app/.
    if app_only:
        index_out = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <meta http-equiv=\"refresh\" content=\"0; url=/app/\" />
  <title>Network Watch</title>
</head>
<body>
  <p>Redirecting to <a href=\"/app/\">/app/</a>…</p>
</body>
</html>
"""
        with open(os.path.join(site, 'index.html'), 'w') as f:
            f.write(index_out)
        return

    # Timeline: last up to 48 snapshots
    N = min(len(history), 48)
    start_idx = max(0, len(history) - N)

    heatmap_rows = []
    for did in did_order:
        bits = presence[did][start_idx:]
        cells = []
        for j, on in enumerate(bits):
            utc = timeline_utc[start_idx + j]
            title = f"{label_for_id(did)} @ {utc}" if utc else label_for_id(did)
            cls = "cell on" if on else "cell off"
            cells.append(f"<div class='{cls}' title='{esc(title)}'></div>")
        m = meta.get(did, {})
        display = (m.get('name') or m.get('vendor') or did)
        sub = m.get('mac') or did
        heatmap_rows.append(
            f"<div class='row'>"
            f"<div class='id'><div class='primary'>{esc(display)}</div><div class='meta'>{esc(sub)} • type {esc(m.get('type',''))} • last IP {esc(m.get('last_ip',''))}</div></div>"
            f"<div class='cells'>{''.join(cells)}</div>"
            f"</div>"
        )

    timeline_html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Watch — Timeline</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 24px; }}
    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
    a {{ color: #0b57d0; }}
    .muted {{ color: #666; }}
    .row {{ display: grid; grid-template-columns: 420px 1fr; gap: 12px; padding: 8px 0; border-bottom: 1px solid #eee; }}
    .primary {{ font-weight: 700; }}
    .meta {{ font-weight: 400; font-size: 12px; color: #666; margin-top: 2px; word-break: break-word; }}
    .cells {{ display: grid; grid-auto-flow: column; grid-auto-columns: 10px; gap: 2px; align-items: center; }}
    .cell {{ width: 10px; height: 10px; border-radius: 2px; border: 1px solid #ddd; }}
    .cell.on {{ background: #1f6feb; border-color: #1f6feb; }}
    .cell.off {{ background: #fff; }}
    .legend {{ display: flex; gap: 10px; align-items: center; font-size: 12px; color: #666; }}
  </style>
</head>
<body>
  <h1>Network Watch — Timeline</h1>
  <p class="muted">Updated: <code>{esc(args.timestamp_human)}</code> • Showing last <code>{N}</code> hourly snapshots • keyed by MAC when available</p>
  <p><a href="/">← Back to latest</a> · <a href="/ip-history.html">IP history</a> · <a href="/churn.html">Churn</a> · <a href="/graph.html">Device↔Port graph</a></p>

  <h2>Device count over time (last {N} snapshots)</h2>
  {sparkline(counts[start_idx:])}
  <div class="legend"><span><b>min</b>: {min(counts[start_idx:]) if counts[start_idx:] else ''}</span><span><b>max</b>: {max(counts[start_idx:]) if counts[start_idx:] else ''}</span></div>

  <h2>Per-device presence heatmap</h2>
  <p class="muted">Each square is one hour. Blue = seen on LAN. Hover a square to see the timestamp (UTC).</p>
  {''.join(heatmap_rows) if heatmap_rows else '<p class="muted">Not enough data yet.</p>'}
</body>
</html>
"""

    with open(os.path.join(site, 'timeline.html'), 'w') as f:
        f.write(timeline_html)

    # --- IP History page ---
    def ip_color(ip):
        if not ip:
            return '#ffffff'
        # hash to pastel
        h = 0
        for ch in ip:
            h = (h * 131 + ord(ch)) % 0xFFFFFF
        r = 180 + (h & 0x3F)
        g = 180 + ((h >> 6) & 0x3F)
        b = 180 + ((h >> 12) & 0x3F)
        return f"rgb({r},{g},{b})"

    ip_rows = []
    for did in did_order:
        m = meta.get(did, {})
        display = (m.get('name') or m.get('vendor') or did)
        mac = (m.get('mac') or did)
        bits = presence[did][start_idx:]
        ips = (ip_hist.get(did) or [''] * len(history))[start_idx:]
        cells = []
        for j, on in enumerate(bits):
            ip = ips[j] if on else ''
            title = f"{display} @ {timeline_utc[start_idx+j]} ip={ip}".strip()
            bg = ip_color(ip)
            txt = ip.split('.')[-1] if ip else ''
            cells.append(f"<div class='cell' style='background:{bg}' title='{esc(title)}'>{esc(txt)}</div>")
        ip_rows.append(
            f"<div class='row'>"
            f"<div class='id'><div class='primary'>{esc(display)}</div><div class='meta'>{esc(mac)} • type {esc(m.get('type',''))}</div></div>"
            f"<div class='cells'>{''.join(cells)}</div>"
            f"</div>"
        )

    ip_history_html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Watch — IP History</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 24px; }}
    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
    a {{ color: #0b57d0; }}
    .muted {{ color: #666; }}
    .row {{ display: grid; grid-template-columns: 420px 1fr; gap: 12px; padding: 8px 0; border-bottom: 1px solid #eee; }}
    .primary {{ font-weight: 700; }}
    .meta {{ font-weight: 400; font-size: 12px; color: #666; margin-top: 2px; word-break: break-word; }}
    .cells {{ display: grid; grid-auto-flow: column; grid-auto-columns: 22px; gap: 2px; align-items: center; }}
    .cell {{ width: 22px; height: 16px; border-radius: 3px; border: 1px solid #ddd; font-size: 10px; line-height: 16px; text-align: center; overflow: hidden; }}
  </style>
</head>
<body>
  <h1>Network Watch — IP History</h1>
  <p class="muted">Updated: <code>{esc(args.timestamp_human)}</code> • Showing last <code>{N}</code> hourly snapshots (cell text is last octet)</p>
  <p><a href="/">← Back to latest</a> · <a href="/timeline.html">Timeline</a> · <a href="/churn.html">Churn</a> · <a href="/graph.html">Device↔Port graph</a></p>

  {''.join(ip_rows) if ip_rows else '<p class="muted">Not enough data yet.</p>'}
</body>
</html>
"""

    with open(os.path.join(site, 'ip-history.html'), 'w') as f:
        f.write(ip_history_html)

    # --- Churn page + export device_stats.json for the app ---
    churn_rows = []
    device_stats = {}
    total_hours = len(history)

    for did in did_order:
        pres = presence.get(did, [])
        if not pres:
            continue
        # flaps = count transitions
        flaps = 0
        for i in range(1, len(pres)):
            if pres[i] != pres[i-1]:
                flaps += 1
        ips_all = (ip_hist.get(did) or [])
        ips = [x for x in ips_all if x]
        unique_ips = len(set(ips))
        seen = sum(1 for x in pres if x)
        m = meta.get(did, {})
        display = (m.get('name') or m.get('vendor') or did)

        # last N IPs aligned to history window
        ip_tail = ips_all[start_idx:] if ips_all else []

        device_stats[did] = {
            'id': did,
            'display': display,
            'mac': m.get('mac', ''),
            'type': m.get('type', ''),
            'vendor': m.get('vendor', ''),
            'hostname': m.get('hostname', ''),
            'flaps': flaps,
            'uniqueIps': unique_ips,
            'seenHours': seen,
            'totalHours': total_hours,
            'ipTail': ip_tail,
        }

        churn_rows.append((flaps, unique_ips, -seen, display, did, m))

    # Write device stats for the SPA
    try:
        with open(os.path.join(site, 'device_stats.json'), 'w') as f:
            json.dump({'generatedAt': ts, 'window': N, 'devices': device_stats}, f)
    except Exception:
        pass

    churn_rows.sort(reverse=True)
    churn_html_rows = []
    for flaps, uips, _seen_neg, display, did, m in churn_rows[:100]:
        churn_html_rows.append(
            f"<tr><td><a href='/device.html?id={esc(did)}'>{esc(display)}</a></td><td>{esc(m.get('type',''))}</td><td><code>{esc(m.get('mac',did))}</code></td><td>{flaps}</td><td>{uips}</td><td>{sum(presence.get(did, []))}/{len(history)}</td></tr>"
        )

    churn_page = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Watch — Churn</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 24px; }}
    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
    a {{ color: #0b57d0; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ position: sticky; top: 0; background: #fff; }}
    .muted {{ color: #666; }}
  </style>
</head>
<body>
  <h1>Network Watch — Churn</h1>
  <p class="muted">Updated: <code>{esc(args.timestamp_human)}</code> • Flaps=count of present/absent transitions across the saved history</p>
  <p><a href="/">← Back to latest</a> · <a href="/timeline.html">Timeline</a> · <a href="/ip-history.html">IP history</a> · <a href="/graph.html">Device↔Port graph</a></p>

  <table>
    <thead><tr><th>Device</th><th>Type</th><th>MAC</th><th>Flaps</th><th>Unique IPs</th><th>Seen (hours)</th></tr></thead>
    <tbody>{''.join(churn_html_rows)}</tbody>
  </table>
</body>
</html>
"""

    with open(os.path.join(site, 'churn.html'), 'w') as f:
        f.write(churn_page)

    # --- Graph page (port-centric) ---
    # Compute port -> devices (from latest snapshot only)
    port_map = {}
    for d in devices:
        label = d.get('name') or d.get('hostname') or d.get('vendor') or d.get('id')
        for p in d.get('open_ports') or []:
            port = p.get('port')
            if not port:
                continue
            port_map.setdefault(port, []).append((label, d.get('id'), d.get('ip')))

    # Sort ports by fanout
    ports_sorted = sorted(port_map.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    port_sections = []
    for port, devs in ports_sorted[:50]:
        items = ''.join([f"<li><a href='/device.html?id={esc(did)}'>{esc(lbl)}</a> <span class='muted'>@ {esc(ip)}</span></li>" for lbl, did, ip in sorted(devs)])
        port_sections.append(f"<h3>{esc(port)} <span class='muted'>({len(devs)} devices)</span></h3><ul>{items}</ul>")

    graph_page = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Watch — Device↔Port</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 24px; }}
    a {{ color: #0b57d0; }}
    .muted {{ color: #666; }}
    h3 {{ margin-top: 18px; }}
  </style>
</head>
<body>
  <h1>Network Watch — Device↔Port</h1>
  <p class="muted">Updated: <code>{esc(args.timestamp_human)}</code> • Uses latest snapshot only (for now)</p>
  <p><a href="/">← Back to latest</a> · <a href="/timeline.html">Timeline</a> · <a href="/ip-history.html">IP history</a> · <a href="/churn.html">Churn</a></p>

  <h2>Ports → devices</h2>
  {''.join(port_sections) if port_sections else '<p class="muted">No open ports in latest snapshot.</p>'}
</body>
</html>
"""

    if not app_only:
        with open(os.path.join(site, 'graph.html'), 'w') as f:
            f.write(graph_page)

    # Copy latest snapshot into site so the static server can serve it
    try:
        with open(os.path.join(state, 'latest.json'), 'r') as f:
            latest_blob = f.read()
        with open(os.path.join(site, 'latest.json'), 'w') as f:
            f.write(latest_blob)
    except Exception:
        pass

    # Build a compact history.json (last up to 48 snapshots) for app charts
    try:
        t = []
        devices_s = []
        open_ports_s = []
        risks_s = []

        for h in history[-48:]:
            # use UTC for chart labels to avoid TZ surprises
            t.append(h.get('timestamp_utc', '')[-7:-1] if h.get('timestamp_utc') else '')
            ds = h.get('devices', []) or []
            devices_s.append(len(ds))
            op = 0
            rk = 0
            for d in ds:
                op += len(d.get('open_ports') or [])
                rk += len(d.get('risk_flags') or [])
            open_ports_s.append(op)
            risks_s.append(rk)

        with open(os.path.join(site, 'history.json'), 'w') as f:
            json.dump({
                't': t,
                'devices': devices_s,
                'openPorts': open_ports_s,
                'risks': risks_s,
            }, f)
    except Exception:
        pass

    if not app_only:
        # Device detail page (client-side render from latest.json)
        device_html = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Network Watch — Device</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 24px; }
    code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
    a { color: #0b57d0; }
    .muted { color: #666; }
    pre { background: #f6f6f6; padding: 12px; border-radius: 8px; overflow-x: auto; }
  </style>
</head>
<body>
  <p><a href=\"/\">← Back</a> · <a href=\"/timeline.html\">Timeline</a> · <a href=\"/ip-history.html\">IP history</a> · <a href=\"/churn.html\">Churn</a> · <a href=\"/graph.html\">Device↔Port graph</a></p>
  <h1 id=\"title\">Device</h1>
  <div id=\"content\" class=\"muted\">Loading…</div>

<script>
(async function(){
  const params = new URLSearchParams(location.search);
  const id = params.get('id');
  const resp = await fetch('/latest.json', {cache:'no-store'}).catch(()=>null);
  if(!resp){ document.getElementById('content').innerText = 'Failed to load latest.json'; return; }
  const data = await resp.json();
  const dev = (data.devices||[]).find(d => d.id === id);
  if(!dev){ document.getElementById('content').innerText = 'Device not found in latest snapshot.'; return; }

  const title = (dev.name || dev.vendor || dev.id) + ' — ' + (dev.ip || '');
  document.getElementById('title').innerText = title;

  const lines = [];
  lines.push('Type: ' + (dev.type||''));
  lines.push('IP: ' + (dev.ip||''));
  lines.push('MAC: ' + (dev.mac||''));
  lines.push('Vendor: ' + (dev.vendor||''));
  if(dev.hostname) lines.push('Hostname: ' + dev.hostname);
  if((dev.mdns||[]).length) lines.push('mDNS hostnames: ' + dev.mdns.join(', '));
  if((dev.mdns_services||[]).length) lines.push('mDNS services: ' + dev.mdns_services.join(', '));
  if((dev.ssdp||[]).length) {
    lines.push('SSDP/UPnP:');
    (dev.ssdp||[]).slice(0,8).forEach(s => {
      lines.push('  - ' + (s.st||'') + ' | ' + (s.server||'') + ' | ' + (s.location||''));
    });
  }
  lines.push('');
  lines.push('Open ports:');
  (dev.open_ports||[]).forEach(p => lines.push('  - ' + p.raw));
  lines.push('');
  lines.push('Web probe:');
  (dev.web||[]).forEach(w => {
    lines.push('  - ' + (w.url||'') + ' status=' + (w.status||'') + ' server=' + (w.server||'') + ' title=' + (w.title||''));
  });
  lines.push('');
  lines.push('Risk flags: ' + (dev.risk_flags||[]).join(', '));

  document.getElementById('content').innerHTML = '<pre>' + lines.join('\\n').replace(/[&<>]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])) + '</pre>';
})();
</script>
</body>
</html>
"""

        with open(os.path.join(site, 'device.html'), 'w') as f:
            f.write(device_html)

    if app_only:
        # Minimal index for app-only deployments
        index_out = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <meta http-equiv=\"refresh\" content=\"0; url=/app/\" />
  <title>Network Watch</title>
  <style>body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;margin:24px}</style>
</head>
<body>
  <p>Redirecting to <a href=\"/app/\">/app/</a>…</p>
</body>
</html>
"""
    else:
        index_out = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Watch</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 24px; }}
    code, pre {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ position: sticky; top: 0; background: #fff; }}
    .muted {{ color: #666; }}
    a {{ color: #0b57d0; }}
  </style>
</head>
<body>
  <h1>Network Watch</h1>
  <p class="muted">Updated: <code>{esc(args.timestamp_human)}</code> (UTC snapshot <code>{esc(ts)}</code>)</p>
  <p>Host: <code>{esc(args.host_ip)}</code> • Subnet: <code>{esc(args.subnet)}</code></p>
  <p>
    <a href="/timeline.html">Timeline</a> ·
    <a href="/ip-history.html">IP history</a> ·
    <a href="/churn.html">Churn</a> ·
    <a href="/graph.html">Device↔Port graph</a> ·
    <a href="/fancy.html">Fancy</a> ·
    <a href="/fancy-timeline.html">Fancy timeline</a> ·
    <a href="/app/">App</a>
  </p>

  <h2>Summary</h2>
  <ul>
    <li><strong>Devices:</strong> {len(devices)}</li>
    <li><strong>Types:</strong> {esc(type_summary)}</li>
    <li><strong>Note:</strong> Gone devices are debounced (must be missing 2 consecutive hours).</li>
  </ul>

  <h2>Changes since previous hour (by device id)</h2>
  <ul>
    <li><strong>New:</strong><br>{new_html}</li>
    <li><strong>Gone:</strong><br>{gone_html}</li>
  </ul>

  <h2>Devices seen (keyed by name → hostname → MAC → vendor)</h2>
  <p class="muted">Tip: edit <code>network-watch/state/aliases.json</code> to assign friendly names to MAC addresses.</p>
  <table>
    <thead>
      <tr>
        <th>Device</th><th>IP (current)</th><th>MAC</th><th>Vendor</th><th>ARP</th><th>Alive</th><th>Open ports (top-100 scan)</th><th>Web probe</th><th>Risk flags</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows_html)}
    </tbody>
  </table>

  <p class="muted">Note: “Risk flags” are heuristics based on exposed services, not confirmed exploits.</p>
</body>
</html>
"""

    with open(os.path.join(site, 'index.html'), 'w') as f:
        f.write(index_out)


if __name__ == '__main__':
    main()
