"""Shared helpers for the feed-fetch scripts.

Every fetch_*.py script writes one file to data/raw/<feed>.json using
write_raw() below. build_snapshot.py then merges those raw files (plus
the previous data/latest.json, for fallback on error) into the single
snapshot the frontend reads. Keeping this contract in one place avoids
six copies of the same "write JSON, stamp status/timestamp" logic.
"""

import datetime
import json
import os

RAW_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "raw")


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_raw(feed_name, items, error=None):
    """Write data/raw/<feed_name>.json.

    status is only "error" when there is no usable data at all (items is
    empty) — a partial failure (e.g. one of several sub-lists in a feed
    failing) can still carry an `error` note while status stays "ok", so
    build_snapshot.py surfaces the warning without discarding good data.
    """
    os.makedirs(RAW_DIR, exist_ok=True)
    items = items or []
    status = "error" if (error and not items) else "ok"
    payload = {
        "status": status,
        "fetched_at": now_iso(),
        "count": len(items),
        "items": items,
    }
    if error:
        payload["error"] = str(error)
    path = os.path.join(RAW_DIR, f"{feed_name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return payload


def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
