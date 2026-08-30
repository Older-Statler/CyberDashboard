#!/usr/bin/env python3
"""Annotate IPs surfaced by the bulk feeds with GreyNoise Community
classifications (scanner noise vs. targeted).

Runs on its own once-daily schedule because the Community API's free
quota is tight (~50/week authenticated). If GREYNOISE_API_KEY isn't
set, this no-ops cleanly — the frontend simply doesn't show badges.
"""

import datetime
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST_PATH = os.path.join(BASE, "data", "latest.json")
ENRICHMENT_PATH = os.path.join(BASE, "data", "enrichment.json")

MAX_LOOKUPS_PER_RUN = int(os.environ.get("GREYNOISE_MAX_LOOKUPS", "10"))
CACHE_TTL_DAYS = 14


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def now_iso():
    return now().strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_ip(ioc, ioc_type):
    if not ioc or not ioc_type or "ip" not in ioc_type:
        return None
    return ioc.split(":")[0] if ":" in ioc else ioc


def collect_candidate_ips(latest):
    """Count how many feeds each IP appears in, to prioritize multi-feed IPs."""
    counts = {}
    feeds = latest.get("feeds", {})

    for item in feeds.get("threatfox", {}).get("items", []):
        ip = extract_ip(item.get("ioc"), item.get("ioc_type"))
        if ip:
            counts[ip] = counts.get(ip, 0) + 1

    for item in feeds.get("blocklistde", {}).get("items", []):
        ip = item.get("ip")
        if ip:
            counts[ip] = counts.get(ip, 0) + 1

    return counts


def main():
    api_key = os.environ.get("GREYNOISE_API_KEY")
    if not api_key:
        print("GREYNOISE_API_KEY not set; skipping enrichment run.")
        return

    latest = load_json(LATEST_PATH, default={})
    if not latest:
        print("data/latest.json not found; nothing to enrich yet.")
        return

    enrichment = load_json(ENRICHMENT_PATH, default={"generated_at": None, "lookups": {}})
    lookups = enrichment.get("lookups", {})

    candidates = collect_candidate_ips(latest)
    ordered = sorted(candidates.items(), key=lambda kv: kv[1], reverse=True)

    cutoff = now() - datetime.timedelta(days=CACHE_TTL_DAYS)
    to_check = []
    for ip, _count in ordered:
        cached = lookups.get(ip)
        if cached:
            checked_at = cached.get("checked_at")
            try:
                checked_dt = datetime.datetime.strptime(
                    checked_at, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=datetime.timezone.utc)
            except (TypeError, ValueError):
                checked_dt = None
            if checked_dt and checked_dt > cutoff:
                continue
        to_check.append(ip)
        if len(to_check) >= MAX_LOOKUPS_PER_RUN:
            break

    for ip in to_check:
        try:
            resp = requests.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": api_key},
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
            lookups[ip] = {
                "noise": data.get("noise", False),
                "classification": data.get("classification", "unknown"),
                "name": data.get("name", "unknown"),
                "last_seen": data.get("last_seen"),
                "checked_at": now_iso(),
            }
        except Exception as e:
            # Don't cache the failure — let it retry on the next run instead
            # of the error message sitting in the cache for 14 days.
            print(f"GreyNoise lookup failed for {ip}: {e}")

    enrichment = {"generated_at": now_iso(), "lookups": lookups}
    with open(ENRICHMENT_PATH, "w", encoding="utf-8") as f:
        json.dump(enrichment, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
