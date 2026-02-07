#!/usr/bin/env python3
import argparse
import socket
import time
import re

MCAST_GRP = '239.255.255.250'
MCAST_PORT = 1900


def parse_headers(pkt: str):
    hdrs = {}
    for line in pkt.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            hdrs[k.strip().lower()] = v.strip()
    return hdrs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--timeout', type=float, default=2.0)
    ap.add_argument('--mx', type=int, default=1)
    args = ap.parse_args()

    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        f'HOST: {MCAST_GRP}:{MCAST_PORT}\r\n'
        'MAN: "ssdp:discover"\r\n'
        f'MX: {args.mx}\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    ).encode('utf-8')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(0.2)

    try:
        s.sendto(msg, (MCAST_GRP, MCAST_PORT))
    except Exception:
        pass

    end = time.time() + args.timeout
    by_ip = {}

    while time.time() < end:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            break

        ip = addr[0]
        text = data.decode('utf-8', 'ignore')
        hdrs = parse_headers(text)
        st = hdrs.get('st') or hdrs.get('nt')
        usn = hdrs.get('usn')
        server = hdrs.get('server')
        location = hdrs.get('location')
        if not st and not server and not location:
            continue
        # shrink
        item = {
            'st': (st or '')[:160],
            'server': (server or '')[:200],
            'location': (location or '')[:240],
            'usn': (usn or '')[:240],
        }
        by_ip.setdefault(ip, [])
        # de-dup by st+usn
        key = (item['st'], item['usn'])
        seen = {(x.get('st'), x.get('usn')) for x in by_ip[ip]}
        if key not in seen:
            by_ip[ip].append(item)

    # Print as a simple, parseable format (JSON-ish without importing json for speed)
    # We'll rely on enrich.py calling this and parsing stdout as JSON.
    import json
    print(json.dumps({'ssdp': by_ip}, indent=2))


if __name__ == '__main__':
    main()
