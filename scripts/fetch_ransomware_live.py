#!/usr/bin/env python3
"""Fetch recently disclosed ransomware victims from ransomware.live. No
auth, but rate-limited to 1 request/minute per endpoint — a real
constraint. This script calls exactly one endpoint once, so that's
trivially respected; if a second endpoint is ever added here, space the
calls by 60+ seconds.

Standalone contextual feed, not IOC enrichment — no IP extraction. The
endpoint itself returns "recent" data, so results are naturally small;
still capped defensively at 100 in case that ever changes.
"""

import datetime
import json
import os

import requests

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VICTIMS_PATH = os.path.join(BASE, "data", "ransomware_victims.json")
RECENT_VICTIMS_URL = "https://api.ransomware.live/v2/recentvictims"

MAX_ENTRIES = 100


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    try:
        resp = requests.get(RECENT_VICTIMS_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"ransomware.live fetch failed: {e}")
        return

    if not isinstance(data, list):
        print("ransomware.live: unexpected response shape, skipping.")
        return

    victims = []
    for entry in data[:MAX_ENTRIES]:
        victims.append(
            {
                "group": entry.get("group"),
                "victim": entry.get("victim"),
                "country": entry.get("country"),
                "sector": entry.get("activity"),
                "published": entry.get("discovered"),
                "domain": entry.get("domain"),
                "url": entry.get("url"),
            }
        )

    with open(VICTIMS_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now_iso(), "victims": victims}, f, ensure_ascii=False, indent=2)

    print(f"ransomware.live: {len(victims)} recent victims recorded.")


if __name__ == "__main__":
    main()
