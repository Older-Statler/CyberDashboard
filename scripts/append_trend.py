#!/usr/bin/env python3
"""Append today's per-feed item counts to data/trends.json.

Run once daily (piggybacked on the enrichment workflow). Idempotent: if
today's UTC date already has an entry, it's overwritten rather than
duplicated, so reruns on the same day are safe. Trimmed to the most
recent 90 entries so the file stays small.
"""

import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST_PATH = os.path.join(BASE, "data", "latest.json")
TRENDS_PATH = os.path.join(BASE, "data", "trends.json")

MAX_ENTRIES = 90
FEEDS = ["threatfox", "urlhaus", "malwarebazaar", "cisa_kev", "otx", "blocklistde"]


def main():
    latest = load_json(LATEST_PATH)
    if not latest:
        print("data/latest.json not found; nothing to record yet.")
        return

    counts = {feed: latest.get("feeds", {}).get(feed, {}).get("count", 0) for feed in FEEDS}
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    trends = load_json(TRENDS_PATH, default={"days": []})
    days = trends.get("days", [])

    days = [d for d in days if d.get("date") != today]
    days.append({"date": today, "counts": counts})
    days.sort(key=lambda d: d.get("date", ""))
    days = days[-MAX_ENTRIES:]

    with open(TRENDS_PATH, "w", encoding="utf-8") as f:
        json.dump({"days": days}, f, ensure_ascii=False, indent=2)

    print(f"Recorded trend entry for {today}: {counts}")


if __name__ == "__main__":
    main()
