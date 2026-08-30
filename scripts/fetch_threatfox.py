#!/usr/bin/env python3
"""Fetch recent IOCs from ThreatFox (abuse.ch). Requires THREATFOX_AUTH_KEY."""

import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_raw

FEED = "threatfox"
URL = "https://threatfox-api.abuse.ch/api/v1/"


def main():
    auth_key = os.environ.get("THREATFOX_AUTH_KEY")
    if not auth_key:
        write_raw(FEED, [], error="THREATFOX_AUTH_KEY not set")
        return

    try:
        resp = requests.post(
            URL,
            headers={"Auth-Key": auth_key},
            json={"query": "get_iocs", "days": 3},
            timeout=30,
        )
        resp.raise_for_status()
        payload = resp.json()

        if payload.get("query_status") != "ok":
            write_raw(FEED, [], error=f"query_status={payload.get('query_status')}")
            return

        items = [
            {
                "id": entry.get("id"),
                "ioc": entry.get("ioc"),
                "ioc_type": entry.get("ioc_type"),
                "malware_printable": entry.get("malware_printable"),
                "confidence_level": entry.get("confidence_level"),
                "first_seen": entry.get("first_seen"),
                "tags": entry.get("tags") or [],
                "reporter": entry.get("reporter"),
            }
            for entry in payload.get("data", [])
        ]
        write_raw(FEED, items)
    except Exception as e:
        write_raw(FEED, [], error=str(e))


if __name__ == "__main__":
    main()
