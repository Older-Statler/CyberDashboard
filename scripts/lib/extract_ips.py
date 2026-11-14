"""Shared helper: the set of unique IPs seen across the IP-bearing feeds in
a data/latest.json snapshot. Every per-IP enrichment script (GreyNoise,
Geo, InternetDB, AbuseIPDB) imports get_ips_from_snapshot() instead of
re-implementing this extraction.

The quota-limited enrichers (GreyNoise, InternetDB, AbuseIPDB) use
get_ranked_ips_from_snapshot() instead, so their small per-run budgets
go to the most interesting IPs first rather than to arbitrary set order.
"""

import bisect
import ipaddress
import json
import os
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DROP_PATH = os.path.join(BASE, "data", "spamhaus_drop.json")
ABUSEIPDB_PATH = os.path.join(BASE, "data", "abuseipdb.json")

# AbuseIPDB confidence score at or above which an IP counts as "known bad"
# for ranking purposes.
ABUSE_SCORE_THRESHOLD = 75
# See get_ranked_ips_from_snapshot(): caps how much of the front of the
# ranking (where the per-run budgets go) one /24 can take.
MAX_PER_SLASH24_UP_FRONT = 2


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


def _iter_snapshot_ips(snapshot):
    """Yield (feed, ip, timestamp_or_None) for every IP occurrence in the
    IP-bearing feeds. Timestamps are the feeds' own "YYYY-MM-DD HH:MM:SS"
    strings (ThreatFox first_seen, URLhaus date_added), which sort
    correctly as strings."""
    feeds = snapshot.get("feeds", {})

    for item in feeds.get("threatfox", {}).get("items", []):
        if "ip" in (item.get("ioc_type") or ""):
            ip = _normalize_ip(item.get("ioc"))
            if ip:
                yield "threatfox", ip, item.get("first_seen")

    for item in feeds.get("urlhaus", {}).get("items", []):
        ip = _normalize_ip(_extract_host(item.get("url")))
        if ip:
            yield "urlhaus", ip, item.get("date_added")

    for item in feeds.get("blocklistde", {}).get("items", []):
        ip = _normalize_ip(item.get("ip"))
        if ip:
            yield "blocklistde", ip, None

    for item in feeds.get("otx", {}).get("items", []):
        for ind in item.get("indicators", []):
            if (ind.get("type") or "").lower() in ("ipv4", "ipv6"):
                ip = _normalize_ip(ind.get("indicator"))
                if ip:
                    yield "otx", ip, None


def get_ips_from_snapshot(snapshot):
    """Return a set of unique bare IPv4 strings seen across ThreatFox,
    URLhaus, Blocklist.de, and OTX items in a data/latest.json dict.
    """
    return {ip for _, ip, _ in _iter_snapshot_ips(snapshot)}


def _ip_to_int(ip):
    # ip has already passed _normalize_ip, so four 0-255 decimal parts.
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _load_json_quietly(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_drop_ranges(path=DROP_PATH):
    """CIDR strings from data/spamhaus_drop.json, or [] if the file is
    missing/corrupt. Ranking signal only, so failure just means no signal."""
    data = _load_json_quietly(path)
    if not isinstance(data, dict):
        return []
    ranges = data.get("ranges")
    if not isinstance(ranges, list):
        return []
    return [r.get("cidr") for r in ranges if isinstance(r, dict) and r.get("cidr")]


def load_abuse_entries(path=ABUSEIPDB_PATH):
    """The {ip: entry} dict from data/abuseipdb.json, or {} if missing/corrupt."""
    data = _load_json_quietly(path)
    if not isinstance(data, dict):
        return {}
    entries = data.get("entries")
    return entries if isinstance(entries, dict) else {}


def _build_drop_lookup(drop_ranges):
    """Merge IPv4 DROP CIDRs into sorted, non-overlapping (start, end) int
    intervals so membership is one bisect per IP."""
    intervals = []
    for cidr in drop_ranges or []:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except (TypeError, ValueError):
            continue
        if net.version != 4:
            continue
        intervals.append((int(net.network_address), int(net.broadcast_address)))
    intervals.sort()
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1] + 1:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])
    starts = [s for s, _ in merged]
    ends = [e for _, e in merged]

    def in_drop(ip_int):
        i = bisect.bisect_right(starts, ip_int) - 1
        return i >= 0 and ip_int <= ends[i]

    return in_drop


def _abuse_high(entry):
    if not isinstance(entry, dict):
        return False
    score = entry.get("abuseConfidenceScore")
    return isinstance(score, (int, float)) and score >= ABUSE_SCORE_THRESHOLD


def rank_ip_signals(snapshot, drop_ranges=None, abuse_entries=None):
    """Return {ip: signals} for every IP in the snapshot, where signals is
    a dict of feeds (sorted list), threatfox, in_drop, abuse_high, latest.
    Exposed separately from the ranked list so callers can inspect why an
    IP ranked where it did."""
    feeds_by_ip = {}
    latest_by_ip = {}
    for feed, ip, ts in _iter_snapshot_ips(snapshot):
        feeds_by_ip.setdefault(ip, set()).add(feed)
        if isinstance(ts, str) and ts:
            ts = ts[:19]
            if ts > latest_by_ip.get(ip, ""):
                latest_by_ip[ip] = ts

    in_drop = _build_drop_lookup(drop_ranges)
    abuse_entries = abuse_entries if isinstance(abuse_entries, dict) else {}

    signals = {}
    for ip, feeds in feeds_by_ip.items():
        signals[ip] = {
            "feeds": sorted(feeds),
            "threatfox": "threatfox" in feeds,
            "in_drop": in_drop(_ip_to_int(ip)),
            "abuse_high": _abuse_high(abuse_entries.get(ip)),
            "latest": latest_by_ip.get(ip, ""),
        }
    return signals


def get_ranked_ips_from_snapshot(snapshot, drop_ranges=None, abuse_entries=None):
    """Return the same IPs as get_ips_from_snapshot(), as a list ordered
    highest enrichment priority first. Ranking, in order of precedence:

      1. number of distinct feeds the IP appears in (more = higher)
      2. present in ThreatFox (C2 / botnet infrastructure)
      3. inside a Spamhaus DROP range (drop_ranges: CIDR strings)
      4. AbuseIPDB confidence score >= 75 (abuse_entries: {ip: entry})
      5. most recent ThreatFox first_seen / URLhaus date_added
      6. numeric IP value, ascending, so the order is fully deterministic

    drop_ranges and abuse_entries are optional; None or bad data simply
    means that signal is absent for every IP.

    Then a diversity pass: at most MAX_PER_SLASH24_UP_FRONT IPs from any one
    /24 keep their place; the rest of that /24 moves behind every other IP
    (still in rank order). Anyone can report IPs to ThreatFox and URLhaus,
    so without this a reporter could put their own block at the top and use
    up the small per-run budgets (GreyNoise is 7/day). They now need many
    netblocks to do that.
    """
    signals = rank_ip_signals(snapshot, drop_ranges, abuse_entries)
    # Python's sort is stable (including with reverse=True), so sort by
    # the final ascending tie-breaker first, then by the descending keys.
    ranked = sorted(signals, key=_ip_to_int)
    ranked.sort(
        key=lambda ip: (
            len(signals[ip]["feeds"]),
            signals[ip]["threatfox"],
            signals[ip]["in_drop"],
            signals[ip]["abuse_high"],
            signals[ip]["latest"],
        ),
        reverse=True,
    )

    front, deferred, per_net = [], [], {}
    for ip in ranked:
        net = ip.rsplit(".", 1)[0]
        n = per_net.get(net, 0)
        if n < MAX_PER_SLASH24_UP_FRONT:
            per_net[net] = n + 1
            front.append(ip)
        else:
            deferred.append(ip)
    return front + deferred
