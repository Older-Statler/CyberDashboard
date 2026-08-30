#!/usr/bin/env python3
"""Fetch AbuseIPDB crowd-sourced abuse reports for IPs seen across the
bulk feeds. Requires ABUSEIPDB_API_KEY — if unset, no-ops cleanly (same
graceful-degrade pattern as GreyNoise).

Free tier is 1,000 checks/day; self-imposed cap here is 500 new/re-checked
IPs/day, leaving headroom rather than brushing the ceiling. Unlike the
permanent geo cache, abuse reports accumulate over time, so entries older
than 14 days are re-checked rather than skipped forever.
"""

import datetime
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_json
from lib.extract_ips import get_ips_from_snapshot

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST_PATH = os.path.join(BASE, "data", "latest.json")
ABUSEIPDB_PATH = os.path.join(BASE, "data", "abuseipdb.json")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_PER_RUN = 500
REFRESH_DAYS = 14


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
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("ABUSEIPDB_API_KEY not set; skipping AbuseIPDB run.")
        return

    latest = load_json(LATEST_PATH)
    if not latest:
        print("data/latest.json not found; skipping AbuseIPDB run.")
        return

    cache = load_json(ABUSEIPDB_PATH, default=None) or {"generated_at": None, "entries": {}}
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
            resp = requests.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            entries[ip] = {
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "totalReports": data.get("totalReports"),
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "isTor": data.get("isTor"),
                "usageType": data.get("usageType"),
                "checked_at": now_iso(),
            }
        except Exception as e:
            print(f"AbuseIPDB lookup failed for {ip}: {e}")
        checked += 1

    with open(ABUSEIPDB_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now_iso(), "entries": entries}, f, ensure_ascii=False, indent=2)

    print(f"AbuseIPDB: checked {checked} IPs this run, {len(entries)} total cached.")


if __name__ == "__main__":
    main()
