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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import fetch_capped, now_iso, write_atomic

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(BASE, "data", "tor_exits.json")
TOR_URL = "https://check.torproject.org/torbulkexitlist"
HEADERS = {"User-Agent": "CyberThreatDashboard/1.0"}
TIMEOUT = 30  # per socket read
DEADLINE_S = 60  # whole request; the real list downloads in well under a second
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
        body = fetch_capped(TOR_URL, MAX_BYTES, DEADLINE_S, headers=HEADERS, timeout=TIMEOUT)
        ips = parse(body.decode("utf-8", "replace"))
    except Exception as e:
        print(f"Tor exit list fetch failed: {e}; keeping the previous file.")
        return

    if len(ips) < MIN_IPS:
        print(f"Tor exit list: only {len(ips)} IPs parsed, possible format change; keeping the previous file.")
        return

    payload = {"generated_at": now_iso(), "source": TOR_URL, "count": len(ips), "ips": ips}
    write_atomic(OUT_PATH, json.dumps(payload, indent=2))
    print(f"Tor exit list: {len(ips)} exit IPs.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # never fail the workflow step
        print(f"fetch_tor_exits failed: {e}; keeping the previous file.")
