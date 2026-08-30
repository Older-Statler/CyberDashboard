#!/usr/bin/env python3
"""Geolocate + ASN-tag IPs seen across the bulk feeds via ip-api.com's free
batch endpoint (no key required). Builds/maintains a permanent IP -> geo
cache (data/geo.json) and a recomputed aggregate summary
(data/geo_summary.json) for the dashboard's map/tables.

Coverage builds gradually: at most 500 new IPs are looked up per run (a
firm cap to stay fast and well inside ip-api's free-tier rate limit of
15 requests/minute), and an IP already in the cache is never re-fetched
since IP -> country/ASN is effectively permanent. Full coverage of large
feeds (e.g. Blocklist.de's ~21,500 unique IPs) builds up over roughly a
few weeks of daily runs — expected, not a bug.
"""

import datetime
import json
import os
import sys
import time
from urllib.parse import urlparse

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST_PATH = os.path.join(BASE, "data", "latest.json")
GEO_PATH = os.path.join(BASE, "data", "geo.json")
GEO_SUMMARY_PATH = os.path.join(BASE, "data", "geo_summary.json")

BATCH_URL = "http://ip-api.com/batch?fields=status,message,query,country,countryCode,lat,lon,as,asname"
BATCH_SIZE = 100
MAX_NEW_IPS_PER_RUN = 500


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_ip(raw):
    if not raw:
        return None
    raw = raw.strip()
    if raw.count(":") == 1:
        raw = raw.split(":")[0]
    parts = raw.split(".")
    if len(parts) != 4:
        return None
    try:
        if all(0 <= int(p) <= 255 for p in parts):
            return raw
    except ValueError:
        return None
    return None


def extract_host(url):
    if not url:
        return None
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def collect_candidate_ips(latest):
    ips = set()
    feeds = latest.get("feeds", {})

    for item in feeds.get("threatfox", {}).get("items", []):
        if "ip" in (item.get("ioc_type") or ""):
            ip = normalize_ip(item.get("ioc"))
            if ip:
                ips.add(ip)

    for item in feeds.get("urlhaus", {}).get("items", []):
        ip = normalize_ip(extract_host(item.get("url")))
        if ip:
            ips.add(ip)

    for item in feeds.get("blocklistde", {}).get("items", []):
        ip = normalize_ip(item.get("ip"))
        if ip:
            ips.add(ip)

    for item in feeds.get("otx", {}).get("items", []):
        for ind in item.get("indicators", []):
            if (ind.get("type") or "").lower() in ("ipv4", "ipv6"):
                ip = normalize_ip(ind.get("indicator"))
                if ip:
                    ips.add(ip)

    return ips


def fetch_batch(ips):
    resp = requests.post(BATCH_URL, json=list(ips), timeout=30)
    resp.raise_for_status()
    return resp.json()


def rebuild_summary(geo_cache):
    by_country = {}
    asn_counts = {}
    asn_names = {}

    for info in geo_cache.values():
        code = info.get("countryCode")
        if code:
            by_country[code] = by_country.get(code, 0) + 1
        asn = info.get("asn")
        if asn:
            asn_counts[asn] = asn_counts.get(asn, 0) + 1
            if info.get("asname"):
                asn_names[asn] = info["asname"]

    top_asns = sorted(
        ({"asn": asn, "name": asn_names.get(asn, ""), "count": count} for asn, count in asn_counts.items()),
        key=lambda a: a["count"],
        reverse=True,
    )[:25]

    return {
        "generated_at": now_iso(),
        "total_geotagged": len(geo_cache),
        "by_country": by_country,
        "top_asns": top_asns,
    }


def main():
    latest = load_json(LATEST_PATH)
    if not latest:
        print("data/latest.json not found; skipping geo run.")
        return

    geo_cache = load_json(GEO_PATH, default={}) or {}

    candidates = collect_candidate_ips(latest)
    new_ips = [ip for ip in candidates if ip not in geo_cache]
    to_fetch = new_ips[:MAX_NEW_IPS_PER_RUN]

    print(f"{len(candidates)} candidate IPs, {len(new_ips)} not yet cached, fetching {len(to_fetch)} this run.")

    for i in range(0, len(to_fetch), BATCH_SIZE):
        batch = to_fetch[i : i + BATCH_SIZE]
        try:
            results = fetch_batch(batch)
        except Exception as e:
            print(f"Batch lookup failed for {len(batch)} IPs: {e}")
            continue

        for entry in results:
            ip = entry.get("query")
            if not ip or entry.get("status") != "success":
                continue
            as_field = entry.get("as") or ""
            asn = as_field.split(" ", 1)[0] if as_field else None
            asname = entry.get("asname") or (as_field.split(" ", 1)[1] if " " in as_field else "")
            geo_cache[ip] = {
                "country": entry.get("country"),
                "countryCode": entry.get("countryCode"),
                "lat": entry.get("lat"),
                "lon": entry.get("lon"),
                "asn": asn,
                "asname": asname,
                "checked_at": now_iso(),
            }

        if i + BATCH_SIZE < len(to_fetch):
            time.sleep(2)  # Stay well under the 15 requests/minute free-tier limit.

    with open(GEO_PATH, "w", encoding="utf-8") as f:
        json.dump(geo_cache, f, ensure_ascii=False, indent=2)

    summary = rebuild_summary(geo_cache)
    with open(GEO_SUMMARY_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"geo.json now has {len(geo_cache)} cached IPs across {len(summary['by_country'])} countries.")


if __name__ == "__main__":
    main()
