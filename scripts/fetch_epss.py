#!/usr/bin/env python3
"""Fetch EPSS (Exploit Prediction Scoring System) scores for every CVE in
the CISA KEV catalog, from FIRST.org's public API. No auth required.

Full refresh every run — this is a small, bounded dataset (one entry per
KEV CVE), not something that needs incremental caching like the per-IP
enrichers.
"""

import datetime
import json
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST_PATH = os.path.join(BASE, "data", "latest.json")
EPSS_PATH = os.path.join(BASE, "data", "epss.json")

EPSS_URL = "https://api.first.org/data/v1/epss"
CHUNK_SIZE = 100


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_chunk(cve_ids):
    resp = requests.get(EPSS_URL, params={"cve": ",".join(cve_ids)}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("data", [])


def main():
    latest = load_json(LATEST_PATH)
    if not latest:
        print("data/latest.json not found; skipping EPSS run.")
        return

    cve_ids = sorted(
        {
            item.get("cve_id")
            for item in latest.get("feeds", {}).get("cisa_kev", {}).get("items", [])
            if item.get("cve_id")
        }
    )

    if not cve_ids:
        print("No KEV CVE IDs found; skipping EPSS run.")
        return

    scores = {}
    for i in range(0, len(cve_ids), CHUNK_SIZE):
        chunk = cve_ids[i : i + CHUNK_SIZE]
        try:
            for entry in fetch_chunk(chunk):
                cve = entry.get("cve")
                if not cve:
                    continue
                try:
                    scores[cve] = {
                        "epss": float(entry.get("epss")),
                        "percentile": float(entry.get("percentile")),
                        "date": entry.get("date"),
                    }
                except (TypeError, ValueError):
                    continue
        except Exception as e:
            print(f"EPSS chunk lookup failed for {len(chunk)} CVEs: {e}")

        if i + CHUNK_SIZE < len(cve_ids):
            time.sleep(0.3)

    with open(EPSS_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now_iso(), "scores": scores}, f, ensure_ascii=False, indent=2)

    print(f"EPSS: {len(scores)} of {len(cve_ids)} KEV CVEs scored.")


if __name__ == "__main__":
    main()
