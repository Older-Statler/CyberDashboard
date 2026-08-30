#!/usr/bin/env python3
"""Fetch community threat pulses from AlienVault OTX (LevelBlue).

Requires OTX_API_KEY. Defaults to the subscribed-pulses endpoint, which
only returns pulses the account has subscribed to (see README for the
one-time setup step of subscribing to a handful of active pulses). If
that comes back empty — e.g. a fresh account with no subscriptions yet
— falls back to the broader recent-activity endpoint.
"""

import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_raw

FEED = "otx"
SUBSCRIBED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1&limit=50"
ACTIVITY_URL = "https://otx.alienvault.com/api/v1/pulses/activity?page=1&limit=50"


def fetch_pulses(url, api_key):
    resp = requests.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("results", [])


def to_items(pulses):
    items = []
    for p in pulses:
        indicators = p.get("indicators") or []
        items.append(
            {
                "name": p.get("name"),
                "created": p.get("created"),
                "tags": p.get("tags") or [],
                "indicator_count": len(indicators) if indicators else p.get("indicator_count", 0),
                "indicators": [
                    {"indicator": i.get("indicator"), "type": i.get("type")}
                    for i in indicators[:25]
                ],
            }
        )
    return items


def main():
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        write_raw(FEED, [], error="OTX_API_KEY not set")
        return

    try:
        pulses = fetch_pulses(SUBSCRIBED_URL, api_key)
        if not pulses:
            pulses = fetch_pulses(ACTIVITY_URL, api_key)
        write_raw(FEED, to_items(pulses))
    except Exception as e:
        write_raw(FEED, [], error=str(e))


if __name__ == "__main__":
    main()
