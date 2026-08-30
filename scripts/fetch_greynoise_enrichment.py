#!/usr/bin/env python3
"""Annotate IPs surfaced by the bulk feeds with GreyNoise Community
classifications (scanner noise vs. targeted).

Runs on its own once-daily schedule because the Community API's free
quota is tight (~50/week authenticated). If GREYNOISE_API_KEY isn't
set, this no-ops cleanly — the frontend simply doesn't show badges.

Quota tracking: every actual outbound lookup call (regardless of
success/failure) is logged to usage.recent_lookups with a timestamp,
trimmed to the trailing 7 days on every run. This self-tracked count is
the reliable primary signal for "how much of the weekly quota is used" —
GreyNoise's exact rate-limit header/body field isn't documented, so any
rate-limit info found in a response is stored as a bonus under
usage.api_reported, not relied on.

Candidate IPs come from the shared lib.extract_ips helper (v3 refactor) —
this drops the earlier per-run "prioritize IPs seen in 2+ feeds first"
ordering in favor of one shared extraction path across all enrichers.
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
ENRICHMENT_PATH = os.path.join(BASE, "data", "enrichment.json")

# 7/day keeps rolling weekly usage under the ~50/week ceiling with a small
# safety margin (49/week), rather than the 8-10/day the original spec
# suggested, since going over risks the key being throttled.
MAX_LOOKUPS_PER_RUN = int(os.environ.get("GREYNOISE_MAX_LOOKUPS", "7"))
CACHE_TTL_DAYS = 14
USAGE_WINDOW_DAYS = 7


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def now_iso():
    return now().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(ts):
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def extract_rate_limit_info(resp):
    """Best-effort: look for anything rate-limit-shaped in headers or body.
    Not depended on for quota tracking — see module docstring."""
    found = {}
    for k, v in resp.headers.items():
        if "ratelimit" in k.lower() or "rate-limit" in k.lower():
            found[k] = v
    try:
        body = resp.json()
        if isinstance(body, dict):
            for key in ("rate_limit", "rateLimit", "quota"):
                if key in body:
                    found[key] = body[key]
    except Exception:
        pass
    return found or None


def main():
    api_key = os.environ.get("GREYNOISE_API_KEY")
    if not api_key:
        print("GREYNOISE_API_KEY not set; skipping enrichment run.")
        return

    latest = load_json(LATEST_PATH, default={})
    if not latest:
        print("data/latest.json not found; nothing to enrich yet.")
        return

    enrichment = load_json(ENRICHMENT_PATH, default={"generated_at": None, "lookups": {}, "usage": {}})
    lookups = enrichment.get("lookups", {})
    usage = enrichment.get("usage", {})
    recent_lookups = usage.get("recent_lookups", [])

    candidates = get_ips_from_snapshot(latest)

    cutoff = now() - datetime.timedelta(days=CACHE_TTL_DAYS)
    to_check = []
    for ip in candidates:
        cached = lookups.get(ip)
        if cached:
            checked_dt = parse_iso(cached.get("checked_at"))
            if checked_dt and checked_dt > cutoff:
                continue
        to_check.append(ip)
        if len(to_check) >= MAX_LOOKUPS_PER_RUN:
            break

    api_reported = None
    for ip in to_check:
        recent_lookups.append(now_iso())  # Every actual outbound call counts against quota.
        try:
            resp = requests.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": api_key},
                timeout=20,
            )
            rl_info = extract_rate_limit_info(resp)
            if rl_info:
                api_reported = rl_info
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

    usage_cutoff = now() - datetime.timedelta(days=USAGE_WINDOW_DAYS)
    recent_lookups = [ts for ts in recent_lookups if (parse_iso(ts) or usage_cutoff) > usage_cutoff]

    usage = {"recent_lookups": recent_lookups}
    if api_reported:
        usage["api_reported"] = api_reported

    enrichment = {"generated_at": now_iso(), "lookups": lookups, "usage": usage}
    with open(ENRICHMENT_PATH, "w", encoding="utf-8") as f:
        json.dump(enrichment, f, ensure_ascii=False, indent=2)

    print(f"Lookups this run: {len(to_check)}. Weekly usage: {len(recent_lookups)}/50.")


if __name__ == "__main__":
    main()
