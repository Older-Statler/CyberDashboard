#!/usr/bin/env python3
"""Fetch the recent malicious-URL export from URLhaus (abuse.ch).

Requires URLHAUS_AUTH_KEY. The export is a CSV regenerated every 5
minutes server-side; a 30-minute cron is well inside that limit.
"""

import csv
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_raw

FEED = "urlhaus"

# abuse.ch comments out the header line too (e.g. "# id,dateadded,url,...")
# so it gets stripped along with the real comment lines below, and can't be
# parsed from the response. This is the live column order for the recent.csv
# export as of 2026-08 (verified against the public csv_recent mirror) —
# note it includes last_online, which some older docs omit.
FIELDNAMES = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]


def main():
    auth_key = os.environ.get("URLHAUS_AUTH_KEY")
    if not auth_key:
        write_raw(FEED, [], error="URLHAUS_AUTH_KEY not set")
        return

    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()

        lines = [line for line in resp.text.splitlines() if line and not line.startswith("#")]
        if not lines:
            write_raw(FEED, [], error="empty CSV response")
            return

        reader = csv.reader(lines, quotechar='"', delimiter=",")

        items = []
        skipped = 0
        for row in reader:
            if len(row) != len(FIELDNAMES):
                skipped += 1
                continue
            record = dict(zip(FIELDNAMES, row))
            items.append(
                {
                    "id": record.get("id"),
                    "date_added": record.get("dateadded"),
                    "url": record.get("url"),
                    "url_status": record.get("url_status"),
                    "last_online": record.get("last_online"),
                    "threat": record.get("threat"),
                    "tags": record.get("tags"),
                    "urlhaus_link": record.get("urlhaus_link"),
                    "reporter": record.get("reporter"),
                }
            )

        if not items and skipped:
            # Every row failed the column-count check, which almost always
            # means abuse.ch changed the CSV schema again (as happened once
            # already) rather than the feed genuinely being empty. Surface
            # this as an error instead of silently reporting "ok, count 0".
            write_raw(
                FEED,
                [],
                error=f"parsed 0 of {skipped} rows — CSV column count changed (expected {len(FIELDNAMES)} columns)",
            )
            return

        write_raw(FEED, items)
    except Exception as e:
        write_raw(FEED, [], error=str(e))


if __name__ == "__main__":
    main()
