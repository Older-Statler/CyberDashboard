#!/usr/bin/env python3
"""Fetch the CISA Known Exploited Vulnerabilities catalog.

No auth required. The primary CISA URL has intermittently 403'd on
scripted requests, so a realistic User-Agent is set and, on failure,
this falls back automatically to the GitHub mirror CISA itself
publishes and keeps in sync.
"""

import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_raw

FEED = "cisa_kev"
PRIMARY_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 CyberThreatDashboard/1.0"
    )
}


def fetch(url):
    resp = requests.get(url, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    return resp.json()


def main():
    payload = None
    errors = []
    for url in (PRIMARY_URL, MIRROR_URL):
        try:
            payload = fetch(url)
            break
        except Exception as e:
            errors.append(f"{url}: {e}")

    if payload is None:
        write_raw(FEED, [], error="; ".join(errors))
        return

    try:
        items = [
            {
                "cve_id": entry.get("cveID"),
                "vendor_project": entry.get("vendorProject"),
                "product": entry.get("product"),
                "vulnerability_name": entry.get("vulnerabilityName"),
                "date_added": entry.get("dateAdded"),
                "short_description": entry.get("shortDescription"),
                "required_action": entry.get("requiredAction"),
                "due_date": entry.get("dueDate"),
                "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse"),
            }
            for entry in payload.get("vulnerabilities", [])
        ]
        write_raw(FEED, items)
    except Exception as e:
        write_raw(FEED, [], error=str(e))


if __name__ == "__main__":
    main()
