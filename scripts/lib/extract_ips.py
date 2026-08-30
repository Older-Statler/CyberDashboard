"""Shared helper: the set of unique IPs seen across the IP-bearing feeds in
a data/latest.json snapshot. Every per-IP enrichment script (GreyNoise,
Geo, InternetDB, AbuseIPDB) imports get_ips_from_snapshot() instead of
re-implementing this extraction.
"""

from urllib.parse import urlparse


def _normalize_ip(raw):
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


def _extract_host(url):
    if not url:
        return None
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def get_ips_from_snapshot(snapshot):
    """Return a set of unique bare IPv4 strings seen across ThreatFox,
    URLhaus, Blocklist.de, and OTX items in a data/latest.json dict.
    """
    ips = set()
    feeds = snapshot.get("feeds", {})

    for item in feeds.get("threatfox", {}).get("items", []):
        if "ip" in (item.get("ioc_type") or ""):
            ip = _normalize_ip(item.get("ioc"))
            if ip:
                ips.add(ip)

    for item in feeds.get("urlhaus", {}).get("items", []):
        ip = _normalize_ip(_extract_host(item.get("url")))
        if ip:
            ips.add(ip)

    for item in feeds.get("blocklistde", {}).get("items", []):
        ip = _normalize_ip(item.get("ip"))
        if ip:
            ips.add(ip)

    for item in feeds.get("otx", {}).get("items", []):
        for ind in item.get("indicators", []):
            if (ind.get("type") or "").lower() in ("ipv4", "ipv6"):
                ip = _normalize_ip(ind.get("indicator"))
                if ip:
                    ips.add(ip)

    return ips
