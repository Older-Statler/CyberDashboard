#!/usr/bin/env python3
"""Build the slim InternetDB / AbuseIPDB files the frontend loads.

data/internetdb.json and data/abuseipdb.json are lookup caches: they keep
every IP ever checked (so TTLs work) with every field the API returned.
The dashboard only needs entries for IPs in the current snapshot, and
only the fields its badges and signal scoring read. Shipping the full
caches cost several MB per page load, so this writes trimmed, compact
copies alongside them:

  data/internetdb_view.json   {generated_at, entries: {ip: {ports, vulns, hostnames}}}
  data/abuseipdb_view.json    {generated_at, entries: {ip: {abuseConfidenceScore, totalReports, isp}}}

No network calls, so it runs even when the API-key-gated fetchers no-op.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_json, now_iso
from lib.extract_ips import get_ips_from_snapshot

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")


def internetdb_entry(e):
    # Empty entries render no badge and add no signal, so leave them out.
    if e.get("no_data") or not (e.get("ports") or e.get("vulns")):
        return None
    return {k: e.get(k) or [] for k in ("ports", "vulns", "hostnames")}


def abuseipdb_entry(e):
    if e.get("abuseConfidenceScore") is None:
        return None
    return {k: e.get(k) for k in ("abuseConfidenceScore", "totalReports", "isp")}


VIEWS = [
    ("internetdb.json", "internetdb_view.json", internetdb_entry),
    ("abuseipdb.json", "abuseipdb_view.json", abuseipdb_entry),
]


def main():
    latest = load_json(os.path.join(DATA, "latest.json"))
    if not latest:
        print("data/latest.json not found; skipping view build.")
        return
    ips = get_ips_from_snapshot(latest)

    for src, dest, slim in VIEWS:
        cache = load_json(os.path.join(DATA, src))
        if not cache:
            print(f"{src} not found; skipping {dest}.")
            continue
        entries = {}
        for ip, e in cache.get("entries", {}).items():
            if ip in ips:
                row = slim(e)
                if row:
                    entries[ip] = row
        with open(os.path.join(DATA, dest), "w", encoding="utf-8") as f:
            json.dump({"generated_at": now_iso(), "entries": entries}, f, ensure_ascii=False, separators=(",", ":"))
        print(f"{dest}: {len(entries)} entries (from {len(cache.get('entries', {}))} cached).")


if __name__ == "__main__":
    main()
