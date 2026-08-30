#!/usr/bin/env python3
"""Fetch Spamhaus DROP (Don't Route Or Peer) — netblocks known to be
criminal-controlled or hijacked. No auth. EDROP has been merged into this
single file, so no separate edrop.txt fetch is needed.

Small, slow-changing dataset (low thousands of ranges) — full refresh
once daily is plenty, no incremental caching needed.
"""

import datetime
import json
import os

import requests

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DROP_PATH = os.path.join(BASE, "data", "spamhaus_drop.json")
DROP_URL = "https://www.spamhaus.org/drop/drop.txt"


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    try:
        resp = requests.get(DROP_URL, headers={"User-Agent": "CyberThreatDashboard/1.0"}, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"Spamhaus DROP fetch failed: {e}")
        return

    ranges = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(";")
        cidr = parts[0].strip()
        sbl_id = parts[1].strip() if len(parts) > 1 else None
        if "/" in cidr:
            ranges.append({"cidr": cidr, "sbl_id": sbl_id})

    if not ranges:
        print("Spamhaus DROP: parsed 0 ranges — possible format change, not writing over existing data.")
        return

    with open(DROP_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now_iso(), "ranges": ranges}, f, ensure_ascii=False, indent=2)

    print(f"Spamhaus DROP: {len(ranges)} ranges.")


if __name__ == "__main__":
    main()
