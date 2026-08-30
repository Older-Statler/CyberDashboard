#!/usr/bin/env python3
"""Merge each feed's data/raw/<feed>.json into the single data/latest.json
the frontend reads.

Fault tolerance: if a feed's raw file is missing or marked status=="error"
(meaning it produced no usable items this run), the previous snapshot's
items for that feed are carried forward instead of wiping the section —
one feed going down should never blank the whole dashboard.
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RAW_DIR, load_json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST_PATH = os.path.join(BASE, "data", "latest.json")

FEEDS = ["threatfox", "urlhaus", "malwarebazaar", "cisa_kev", "otx", "blocklistde"]


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    previous = load_json(LATEST_PATH, default={"feeds": {}}) or {"feeds": {}}
    prev_feeds = previous.get("feeds", {})

    feeds = {}
    errors = []

    for feed in FEEDS:
        raw_path = os.path.join(RAW_DIR, f"{feed}.json")
        raw = load_json(raw_path)

        if raw is None:
            errors.append({"feed": feed, "message": "no output produced by fetch script"})
            prev = prev_feeds.get(feed)
            if prev:
                feeds[feed] = {**prev, "status": "error"}
            else:
                feeds[feed] = {"status": "error", "fetched_at": None, "count": 0, "items": []}
            continue

        if raw.get("error"):
            errors.append({"feed": feed, "message": raw["error"]})

        if raw.get("status") == "error":
            prev = prev_feeds.get(feed)
            if prev:
                feeds[feed] = {
                    "status": "error",
                    "fetched_at": prev.get("fetched_at"),
                    "count": prev.get("count", 0),
                    "items": prev.get("items", []),
                }
            else:
                feeds[feed] = {
                    "status": "error",
                    "fetched_at": raw.get("fetched_at"),
                    "count": 0,
                    "items": [],
                }
        else:
            feeds[feed] = {
                "status": "ok",
                "fetched_at": raw.get("fetched_at"),
                "count": raw.get("count", 0),
                "items": raw.get("items", []),
            }

    snapshot = {
        "generated_at": now_iso(),
        "feeds": feeds,
        "errors": errors,
    }

    os.makedirs(os.path.dirname(LATEST_PATH), exist_ok=True)
    with open(LATEST_PATH, "w", encoding="utf-8") as f:
        import json

        json.dump(snapshot, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
