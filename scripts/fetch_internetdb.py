#!/usr/bin/env python3
"""Fetch Shodan InternetDB data (open ports, CVEs, hostnames) for IPs seen
across the bulk feeds. No auth required.

Unlike the permanent geo cache, exposure changes over time — open ports
get closed, new CVEs get disclosed — so entries older than 30 days are
re-checked rather than skipped forever. No official rate limit is
published, so this self-imposes a courteous cap (300 new/re-checked
IPs/day) with a short delay between requests.
"""

import datetime
import json
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_json
from lib.extract_ips import get_ips_from_snapshot

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST_PATH = os.path.join(BASE, "data", "latest.json")
INTERNETDB_PATH = os.path.join(BASE, "data", "internetdb.json")

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
MAX_PER_RUN = 300
REQUEST_DELAY_SECONDS = 0.2
REFRESH_DAYS = 30


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def now_iso():
    return now().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(ts):
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def main():
    latest = load_json(LATEST_PATH)
    if not latest:
        print("data/latest.json not found; skipping InternetDB run.")
        return

    cache = load_json(INTERNETDB_PATH, default=None) or {"generated_at": None, "entries": {}}
    entries = cache.get("entries", {})

    candidates = get_ips_from_snapshot(latest)
    cutoff = now() - datetime.timedelta(days=REFRESH_DAYS)

    to_check = []
    for ip in candidates:
        cached = entries.get(ip)
        if cached:
            checked_dt = parse_iso(cached.get("checked_at"))
            if checked_dt and checked_dt > cutoff:
                continue
        to_check.append(ip)
        if len(to_check) >= MAX_PER_RUN:
            break

    checked = 0
    for ip in to_check:
        try:
            resp = requests.get(INTERNETDB_URL.format(ip=ip), timeout=15)
            if resp.status_code == 404:
                # No data for this IP in Shodan's database — a normal
                # outcome, not an error. Cache it so we don't re-check
                # daily; the 30-day TTL still applies to it like anything else.
                entries[ip] = {
                    "ports": [],
                    "vulns": [],
                    "cpes": [],
                    "hostnames": [],
                    "tags": [],
                    "no_data": True,
                    "checked_at": now_iso(),
                }
            else:
                resp.raise_for_status()
                data = resp.json()
                entries[ip] = {
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "cpes": data.get("cpes", []),
                    "hostnames": data.get("hostnames", []),
                    "tags": data.get("tags", []),
                    "no_data": False,
                    "checked_at": now_iso(),
                }
        except Exception as e:
            print(f"InternetDB lookup failed for {ip}: {e}")
        checked += 1
        if checked < len(to_check):
            time.sleep(REQUEST_DELAY_SECONDS)

    with open(INTERNETDB_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now_iso(), "entries": entries}, f, ensure_ascii=False, indent=2)

    print(f"InternetDB: checked {checked} IPs this run, {len(entries)} total cached.")


if __name__ == "__main__":
    main()
