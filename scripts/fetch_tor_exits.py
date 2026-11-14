#!/usr/bin/env python3
"""Fetch the Tor Project's bulk exit list: the IPv4 addresses Tor exit
relays were seen exiting from. No auth.

  https://check.torproject.org/torbulkexitlist   (one IP per line)

Context, not a malicious signal: a Tor exit carries traffic for every Tor
user, so blocking it blocks all of them. The dashboard shows it as a badge
and a drawer note and keeps it out of the signal count.

Small (~1-2k IPs) and refreshed by the Tor Project through the day; a
full refresh once daily is enough for a context badge. If the fetch fails
or returns suspiciously few IPs, the previous data/tor_exits.json is kept.
"""

import ipaddress
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import now_iso

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(BASE, "data", "tor_exits.json")
TOR_URL = "https://check.torproject.org/torbulkexitlist"
HEADERS = {"User-Agent": "CyberThreatDashboard/1.0"}
TIMEOUT = 30
# The list normally holds 1,000-2,000 exits. Far fewer means a broken or
# partial response, which would silently drop badges for most of them.
MIN_IPS = 300
MAX_BYTES = 5 * 1024 * 1024  # the real list is ~20 KB


def parse(text):
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            addr = ipaddress.ip_address(line)
        except ValueError:
            continue
        # The page only matches IPv4, and the list is IPv4 today.
        if addr.version == 4:
            ips.add(str(addr))
    return sorted(ips, key=lambda ip: int(ipaddress.ip_address(ip)))


def main():
    try:
        resp = requests.get(TOR_URL, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        if len(resp.content) > MAX_BYTES:
            raise ValueError(f"{len(resp.content)} bytes, larger than expected")
        ips = parse(resp.text)
    except Exception as e:
        print(f"Tor exit list fetch failed: {e}; keeping the previous file.")
        return

    if len(ips) < MIN_IPS:
        print(f"Tor exit list: only {len(ips)} IPs parsed, possible format change; keeping the previous file.")
        return

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now_iso(), "source": TOR_URL, "count": len(ips), "ips": ips}, f, indent=2)
    print(f"Tor exit list: {len(ips)} exit IPs.")


if __name__ == "__main__":
    main()
