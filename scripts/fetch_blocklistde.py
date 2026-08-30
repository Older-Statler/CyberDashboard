#!/usr/bin/env python3
"""Fetch currently-attacking IPs from Blocklist.de. No auth required.

Pulls the per-category plain-text lists (rather than the single
combined all.txt) so each IP can be tagged with which attack type(s)
it was seen on. A failure on one sub-list doesn't blank the others.
"""

import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_raw

FEED = "blocklistde"
LISTS = {
    "ssh": "https://lists.blocklist.de/lists/ssh.txt",
    "bruteforcelogin": "https://lists.blocklist.de/lists/bruteforcelogin.txt",
    "apache": "https://lists.blocklist.de/lists/apache.txt",
    "mail": "https://lists.blocklist.de/lists/mail.txt",
}


def main():
    ip_lists = {}
    errors = []

    for label, url in LISTS.items():
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                ip = line.strip()
                if not ip:
                    continue
                ip_lists.setdefault(ip, set()).add(label)
        except Exception as e:
            errors.append(f"{label}: {e}")

    if not ip_lists:
        write_raw(FEED, [], error="; ".join(errors) or "no data")
        return

    items = [{"ip": ip, "lists": sorted(labels)} for ip, labels in ip_lists.items()]
    write_raw(FEED, items, error="; ".join(errors) if errors else None)


if __name__ == "__main__":
    main()
