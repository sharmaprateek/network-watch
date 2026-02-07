#!/usr/bin/env python3
import argparse
import json
import os
import re
import socket
import subprocess


def run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 999, "", str(e)


def parse_nmap_open_ports(nmap_path):
    ports = {}
    current = None
    for line in open(nmap_path, 'r', errors='replace'):
        line = line.rstrip('\n')
        if line.startswith('Nmap scan report for '):
            current = line.split()[-1]
            ports.setdefault(current, set())
            continue
        if not current:
            continue
        m = re.match(r'^(\d+)/tcp\s+open\s+', line)
        if m:
            ports[current].add(int(m.group(1)))
    return ports


def rev_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def avahi_mdns(timeout=10):
    """Return dict with:
    - hostnames: ip -> [hostnames]
    - services:  ip -> [service-types]

    Uses avahi-browse -a -r -p -t.
    """
    cmd = ['avahi-browse', '-a', '-r', '-p', '-t']
    rc, out, err = run(cmd, timeout=timeout)
    hostnames_by_ip = {}
    services_by_ip = {}

    for line in out.splitlines():
        parts = line.split(';')
        # =;iface;proto;inst;_svc._tcp;domain;hostname;ip;port;...
        if len(parts) >= 9 and (parts[0].startswith('=') or parts[0].startswith('+')):
            svc = parts[4].strip()
            hostname = parts[6].strip()
            ip = parts[7].strip()
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                if hostname:
                    hostnames_by_ip.setdefault(ip, set()).add(hostname)
                if svc:
                    services_by_ip.setdefault(ip, set()).add(svc)

    return {
        'hostnames': {ip: sorted(list(v)) for ip, v in hostnames_by_ip.items()},
        'services': {ip: sorted(list(v)) for ip, v in services_by_ip.items()},
        'rc': rc,
        'err': (err or '').strip(),
    }


def nmap_smb_checks(ip, out_path):
    cmd = ['nmap', '-n', '-p', '445', '--script', 'smb2-security-mode,smb2-time', ip, '-oN', out_path]
    return run(cmd, timeout=60)


def ssdp_probe(root_dir, timeout=2.0):
    script = os.path.join(root_dir, 'ssdp_probe.py')
    if not os.path.exists(script):
        return {}
    rc, out, err = run(['python3', script, '--timeout', str(timeout)], timeout=int(timeout) + 2)
    if rc != 0:
        return {}
    try:
        obj = json.loads(out)
        return obj.get('ssdp', {}) if isinstance(obj, dict) else {}
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nmap', required=True)
    ap.add_argument('--webprobe', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--ts', required=True)
    ap.add_argument('--root', required=True)
    args = ap.parse_args()

    ports_by_ip = parse_nmap_open_ports(args.nmap)

    rdns = {}
    for ip in ports_by_ip.keys():
        name = rev_dns(ip)
        if name and name != ip:
            rdns[ip] = name

    mdns = {}
    try:
        mdns = avahi_mdns(timeout=10)
    except Exception:
        mdns = {}

    ssdp = {}
    try:
        ssdp = ssdp_probe(args.root, timeout=2.0)
    except Exception:
        ssdp = {}

    smb = {}
    base_dir = os.path.dirname(args.out)
    for ip, ports in ports_by_ip.items():
        if 445 in ports:
            outp = os.path.join(base_dir, f'{args.ts}_smb_{ip}.txt')
            rc, _out, err = nmap_smb_checks(ip, outp)
            smb[ip] = {'rc': rc, 'file': outp, 'err': (err or '').strip()}

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w') as f:
        json.dump({'rdns': rdns, 'mdns': mdns, 'ssdp': ssdp, 'smb': smb}, f, indent=2)


if __name__ == '__main__':
    main()
