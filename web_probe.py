#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
from urllib.parse import urlparse

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8009, 5000, 5001, 8833, 8765, 5357, 3000}


def run(cmd, timeout=3):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 999, "", str(e)


def curl_head(url, timeout=3):
    # -k: allow self-signed (common on LAN); -I: HEAD; -L: follow limited redirects
    cmd = ["curl", "-k", "-I", "-L", "--max-redirs", "2", "--max-time", str(timeout), "--connect-timeout", str(timeout), url]
    rc, out, err = run(cmd, timeout=timeout + 1)
    headers = {}
    status = None
    # curl -I with redirects can output multiple header blocks; we keep last block.
    blocks = re.split(r"\r?\n\r?\n", out.strip()) if out.strip() else []
    last = blocks[-1] if blocks else out
    for line in last.splitlines():
        line = line.strip("\r")
        if line.lower().startswith("http/"):
            m = re.match(r"HTTP/\S+\s+(\d+)", line)
            if m:
                status = int(m.group(1))
        elif ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"rc": rc, "status": status, "headers": headers, "err": err.strip()}


def curl_get(url, timeout=3):
    cmd = ["curl", "-k", "-L", "--max-redirs", "2", "--max-time", str(timeout), "--connect-timeout", str(timeout), url]
    rc, out, err = run(cmd, timeout=timeout + 1)
    return rc, out, err


def curl_get_title(url, timeout=3):
    rc, out, err = curl_get(url, timeout=timeout)
    title = None
    if out:
        m = re.search(r"<title[^>]*>(.*?)</title>", out, re.IGNORECASE | re.DOTALL)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
    return {"rc": rc, "title": title, "bytes": len(out.encode('utf-8', 'ignore')), "err": err.strip()}


def curl_get_text(url, timeout=3, max_bytes=4096):
    rc, out, err = curl_get(url, timeout=timeout)
    if out:
        out_b = out.encode('utf-8', 'ignore')[:max_bytes]
        out = out_b.decode('utf-8', 'ignore')
    return {"rc": rc, "body": out, "bytes": len(out.encode('utf-8', 'ignore')), "err": err.strip()}


def parse_nmap_open_web(nmap_path):
    # returns list of (ip, port)
    items = []
    current = None
    for line in open(nmap_path, 'r', errors='replace'):
        line = line.rstrip("\n")
        if line.startswith("Nmap scan report for "):
            current = line.split()[-1]
        m = re.match(r"^(\d+)/tcp\s+open\s+", line)
        if current and m:
            port = int(m.group(1))
            if port in WEB_PORTS:
                items.append((current, port))
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nmap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=3)
    args = ap.parse_args()

    targets = parse_nmap_open_web(args.nmap)
    results = []

    seen = set()
    for ip, port in targets:
        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)
        scheme = "https" if port in (443, 5001, 8443) else "http"
        url = f"{scheme}://{ip}:{port}/"
        head = curl_head(url, timeout=args.timeout)
        get = curl_get_title(url, timeout=args.timeout)
        robots = curl_get_text(url.rstrip('/') + '/robots.txt', timeout=args.timeout)
        security = curl_get_text(url.rstrip('/') + '/.well-known/security.txt', timeout=args.timeout)

        server = head.get("headers", {}).get("server")
        powered = head.get("headers", {}).get("x-powered-by")

        # TLS cert metadata (only for https)
        tls = None
        if scheme == 'https':
            # Use openssl s_client to fetch leaf cert quickly
            cmd = [
                'bash', '-lc',
                f"echo | openssl s_client -servername {ip} -connect {ip}:{port} -showcerts 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null"
            ]
            rc, out, err = run(cmd, timeout=max(4, args.timeout + 1))
            tls = {"rc": rc, "summary": out.strip(), "err": err.strip()}

        results.append({
            "ip": ip,
            "port": port,
            "url": url,
            "status": head.get("status"),
            "server": server,
            "x_powered_by": powered,
            "title": get.get("title"),
            "bytes": get.get("bytes"),
            "robots_txt": robots.get('body'),
            "security_txt": security.get('body'),
            "tls": tls,
            "errors": {"head": head.get("err"), "get": get.get("err"), "robots": robots.get('err'), "security": security.get('err')},
        })

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w') as f:
        json.dump({"results": results}, f, indent=2)


if __name__ == "__main__":
    main()
