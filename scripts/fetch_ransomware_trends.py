#!/usr/bin/env python3
"""Daily ransomware victim counts (last 90 days) from ransomware.live.

Writes data/ransomware_trends.json: per UTC day, the total number of
victims plus counts by group, country and sector. Counts only; no
per-victim records are kept (the project deliberately has no historical
archive).

Why this endpoint
-----------------
data/ransomware_victims.json comes from /v2/recentvictims, which returns
only the latest ~100 victims. The "every 30 minutes" feed workflow
actually runs every 5-8 hours, and busy days see well over 100 victims,
so counting those snapshots would undercount. Instead this script uses

    GET https://api.ransomware.live/v2/victims/<YYYY>/<MM>

which lists every victim whose `discovered` date (when ransomware.live
saw the post on the group's leak site) falls in that month. Counting by
`discovered` matches the 72h view on the page, which also uses it.

Requests per run
----------------
It runs once a day in daily-intel.yml. Normally that's ONE request:
the current month, re-counted in full each day. The previous month is
re-counted as well on days 1-7 of a month (and whenever it hasn't been
fetched since it ended), so its last days are complete and anything
ransomware.live removed or corrected after the fact is picked up. On
the 1st only the previous month is fetched, since the current month has
no complete day yet. When there's no history yet (first run), up to
MAX_MONTHS_PER_RUN months are fetched to fill the 90 days.
ransomware.live allows 1 request/minute per endpoint, so requests are
spaced REQUEST_SPACING_S apart.

Only complete days are recorded: up to yesterday (UTC). Today's partial
count would make the chart dip at the end.

Size
----
Each day stores the top TOP_N names per dimension and an "other" count
for the rest, so a day's dimension counts always add up to its total.
Normal days have fewer than TOP_N groups, so in practice this rarely
cuts anything. Names are trimmed to MAX_NAME_LEN characters.

Fault tolerance
---------------
A month's response is used only if it's a JSON list, at least 80% of its
records have a `discovered` date inside that month, and it isn't empty.
Records repeated within a month (same group, victim name and
`discovered` timestamp) are counted once. Then two sanity checks:

- Bounds: no day may exceed MAX_PER_DAY victims. Real days are tens.
- Agreement: over the days already stored for that month, the new count
  must be between MIN_KEEP_RATIO (0.5x) and MAX_GROWTH_RATIO (3x) of the
  stored one. Skipped when the stored days are themselves out of bounds,
  or too few to compare.

A response that fails either check is rejected and the month keeps its
previous days. Rejections are counted per month in the file
(months[<month>].rejected), so a ratchet can't last: after
REJECT_LIMIT consecutive rejections the next response is accepted
anyway, with a loud warning. That covers a real correction, such as
ransomware.live purging fake claims, and stored data that was wrong in
the first place. A month that is out of bounds or has pending rejections
is marked "suspect" and re-fetched every run even after it has ended.

Each month is handled on its own: a rejected or failed month doesn't stop
the others from being written. If the API can't be reached at all (DNS,
TLS, timeout, deadline), the remaining months are skipped. If nothing was
accepted or rejected, the existing file is left untouched. The file is
written atomically.

Each request is streamed with a byte cap (MAX_BYTES) and a wall-clock
deadline (DEADLINE_S), and must stay on https.
"""

import datetime
import json
import os
import re
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DeadlineExceeded, fetch_capped, load_json, now_iso, write_atomic

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRENDS_PATH = os.path.join(BASE, "data", "ransomware_trends.json")
MONTH_URL = "https://api.ransomware.live/v2/victims/{year:04d}/{month:02d}"
USER_AGENT = "CyberThreatDashboard/1.0 (ransomware trends; daily)"
# api.ransomware.live's TLS certificate expired in Nov 2026: wait for it to be renewed, never pass verify=False.
TIMEOUT_S = 60  # per socket read
DEADLINE_S = 120  # whole request; a month (a few MB) normally takes seconds
MAX_BYTES = 50 * 1024 * 1024  # a month is a few MB of JSON

DAYS_KEPT = 90
TOP_N = 15
MAX_NAME_LEN = 80
MAX_MONTHS_PER_RUN = 4
REQUEST_SPACING_S = 65  # 1 request/minute per endpoint, plus margin
PREV_MONTH_REFRESH_DAYS = 7
MIN_IN_MONTH_RATIO = 0.8
MIN_KEEP_RATIO = 0.5
# ransomware.live records tens of victims a day; even the biggest mass leak
# dumps (Clop's MOVEit / Cleo batches) were a few hundred names. A day above
# this is a broken or inflated response, not news.
MAX_PER_DAY = 1000
MAX_GROWTH_RATIO = 3
# Agreement checks need at least this many stored victims to compare with;
# below it the ratios are noise.
MIN_COMPARE_N = 30
# A month's 4th consecutive disagreeing response (after 3 rejected runs)
# is accepted.
REJECT_LIMIT = 3
UNKNOWN = "-"  # missing / placeholder group, country or sector

DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")
DIMENSIONS = ("groups", "countries", "sectors")


def month_key(year, month):
    return f"{year:04d}-{month:02d}"


def prev_month(year, month):
    return (year - 1, 12) if month == 1 else (year, month - 1)


def month_last_day(year, month):
    ny, nm = (year + 1, 1) if month == 12 else (year, month + 1)
    return datetime.date(ny, nm, 1) - datetime.timedelta(days=1)


def clean_name(value):
    s = " ".join(str(value or "").split())[:MAX_NAME_LEN]
    return s or UNKNOWN


def clean_country(value):
    s = str(value or "").strip()
    return s.upper() if COUNTRY_RE.match(s) else UNKNOWN


def clean_sector(value):
    s = clean_name(value)
    return UNKNOWN if s.lower() in ("not found", "unknown", "n/a") else s


def months_to_fetch(today, months_meta):
    """Months to request this run, most important first."""
    yesterday = today - datetime.timedelta(days=1)
    window_start = yesterday - datetime.timedelta(days=DAYS_KEPT - 1)
    cur = (today.year, today.month)
    prev = prev_month(*cur)

    def complete(ym):
        meta = months_meta.get(month_key(*ym)) or {}
        if meta.get("suspect"):
            return False
        fetched = str(meta.get("fetched_at") or "")[:10]
        return bool(fetched) and fetched > month_last_day(*ym).isoformat()

    wanted = []
    if today.day > 1:
        wanted.append(cur)
    if today.day <= PREV_MONTH_REFRESH_DAYS or not complete(prev):
        wanted.append(prev)
    ym = prev_month(*prev)
    while month_last_day(*ym) >= window_start:
        if not complete(ym):
            wanted.append(ym)
        ym = prev_month(*ym)
    return wanted[:MAX_MONTHS_PER_RUN]


class Unreachable(Exception):
    """Connection-level failure (DNS, TLS, refused, timeout): the other
    months would fail the same way, so the run stops instead of waiting
    REQUEST_SPACING_S before each."""


def fetch_month(year, month):
    """Raw JSON for one month, or None on an HTTP / JSON / size / redirect
    error. Raises Unreachable when the API can't be reached at all."""
    url = MONTH_URL.format(year=year, month=month)
    try:
        body = fetch_capped(
            url, MAX_BYTES, DEADLINE_S, timeout=TIMEOUT_S,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        return json.loads(body)
    except (requests.ConnectionError, requests.Timeout, DeadlineExceeded) as e:
        raise Unreachable(f"{month_key(year, month)}: {e}") from e
    except Exception as e:
        print(f"ransomware.live {month_key(year, month)}: fetch failed: {e}")
        return None


def count_month(data, year, month):
    """Per-day counters for one month's victims, or (None, reason) if the
    response looks wrong."""
    if not isinstance(data, list):
        return None, "unexpected response shape"
    records = [r for r in data if isinstance(r, dict)]
    prefix = month_key(year, month)
    days = {}
    in_month = 0
    seen = set()
    for r in records:
        discovered = str(r.get("discovered") or "")
        m = DATE_RE.match(discovered)
        if not m or f"{m.group(1)}-{m.group(2)}" != prefix:
            continue
        in_month += 1
        date = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        group = clean_name(r.get("group") or r.get("group_name"))
        # The full `discovered` timestamp, not just the day: some leak sites
        # post several victims under one placeholder name ("hidden", "****").
        victim = " ".join(str(r.get("victim") or r.get("post_title") or "").split()).casefold()
        dedup_key = (group.casefold(), victim, discovered)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        d = days.setdefault(date, {"total": 0, "groups": {}, "countries": {}, "sectors": {}})
        d["total"] += 1
        for dim, key in (
            ("groups", group),
            ("countries", clean_country(r.get("country"))),
            ("sectors", clean_sector(r.get("activity") or r.get("sector"))),
        ):
            d[dim][key] = d[dim].get(key, 0) + 1
    if not in_month:
        return None, "no victims in this month"
    if in_month < MIN_IN_MONTH_RATIO * len(data):
        return None, f"only {in_month} of {len(data)} records are dated in {prefix}"
    if in_month != len(seen):
        print(f"ransomware.live {prefix}: {in_month - len(seen)} duplicate records ignored.")
    return (days, len(seen)), None


def out_of_bounds(totals):
    """The first (date, total) above MAX_PER_DAY, or None."""
    for date in sorted(totals):
        if totals[date] > MAX_PER_DAY:
            return date, totals[date]
    return None


def sanity_check(key, counted, stored):
    """Why the month's new counts look wrong, or None if they look fine.
    `counted` is the new per-day counters; `stored` the {date: total} we
    already have for the days this run would overwrite."""
    bad = out_of_bounds({date: c["total"] for date, c in counted.items()})
    if bad:
        return f"{bad[1]} victims on {bad[0]} (limit {MAX_PER_DAY}/day)"
    if out_of_bounds(stored):
        print(f"WARNING ransomware.live {key}: stored counts are out of bounds; replacing them without comparing.")
        return None
    old_n = sum(stored.values())
    if old_n < MIN_COMPARE_N:
        return None
    new_n = sum((counted.get(date) or {}).get("total", 0) for date in stored)
    if new_n < MIN_KEEP_RATIO * old_n:
        return f"{new_n} victims vs {old_n} stored for the same days; looks truncated"
    if new_n > MAX_GROWTH_RATIO * old_n:
        return f"{new_n} victims vs {old_n} stored for the same days; looks inflated"
    return None


def day_entry(date, counts):
    entry = {"date": date, "total": 0}
    other = {}
    for dim in DIMENSIONS:
        entry[dim] = {}
    if counts:
        entry["total"] = counts["total"]
        for dim in DIMENSIONS:
            ranked = sorted(counts[dim].items(), key=lambda kv: (-kv[1], kv[0]))
            entry[dim] = dict(ranked[:TOP_N])
            rest = sum(n for _, n in ranked[TOP_N:])
            if rest:
                other[dim] = rest
    if other:
        entry["other"] = other
    return entry


def valid_existing_days(trends):
    days = trends.get("days") if isinstance(trends, dict) else None
    if not isinstance(days, list):
        return {}
    out = {}
    for d in days:
        if isinstance(d, dict) and isinstance(d.get("date"), str) and DATE_RE.match(d["date"]) and isinstance(d.get("total"), int):
            out[d["date"]] = d
    return out


def dump(payload):
    """One day per line: small, and daily diffs stay readable."""
    head = {k: v for k, v in payload.items() if k != "days"}
    lines = [json.dumps(d, ensure_ascii=False, separators=(",", ":")) for d in payload["days"]]
    body = json.dumps(head, ensure_ascii=False, indent=2)[:-2]
    return body + ',\n  "days": [\n    ' + ",\n    ".join(lines) + "\n  ]\n}\n"


def main(today=None):
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    yesterday = today - datetime.timedelta(days=1)
    window_start = yesterday - datetime.timedelta(days=DAYS_KEPT - 1)

    try:
        previous = load_json(TRENDS_PATH, default={})
    except Exception as e:
        print(f"Existing {TRENDS_PATH} unreadable ({e}); starting fresh.")
        previous = {}
    if not isinstance(previous, dict):
        previous = {}
    days = valid_existing_days(previous)
    months_meta = previous.get("months") if isinstance(previous.get("months"), dict) else {}
    months_meta = {k: dict(v) for k, v in months_meta.items() if isinstance(v, dict)}
    # Stored days that are out of bounds (e.g. written before these checks
    # existed) make their month suspect, so it's re-fetched and replaced.
    for date, d in days.items():
        if d["total"] > MAX_PER_DAY:
            months_meta.setdefault(date[:7], {})["suspect"] = True

    changed = 0
    for i, (year, month) in enumerate(months_to_fetch(today, months_meta)):
        if i:
            time.sleep(REQUEST_SPACING_S)
        key = month_key(year, month)
        try:
            data = fetch_month(year, month)
        except Unreachable as e:
            print(f"ransomware.live unreachable ({e}); not trying further months this run.")
            break
        if data is None:
            continue
        result, reason = count_month(data, year, month)
        if result is None:
            print(f"ransomware.live {key}: {reason}; keeping previous counts.")
            continue
        counted, n = result
        last = min(month_last_day(year, month), yesterday)
        span = []
        d = max(datetime.date(year, month, 1), window_start)
        while d <= last:
            span.append(d.isoformat())
            d += datetime.timedelta(days=1)
        stored = {iso: days[iso]["total"] for iso in span if iso in days}
        meta = months_meta.get(key, {})
        rejected = meta.get("rejected") if isinstance(meta.get("rejected"), int) and meta["rejected"] > 0 else 0
        problem = sanity_check(key, counted, stored)
        suspect = False
        if problem and rejected < REJECT_LIMIT:
            meta = dict(meta, rejected=rejected + 1, suspect=True)
            months_meta[key] = meta
            changed += 1
            print(f"ransomware.live {key}: {problem}; keeping previous counts (rejection {rejected + 1} of {REJECT_LIMIT}).")
            continue
        if problem:
            # Bounded ratchet: the same disagreement REJECT_LIMIT runs in a
            # row is more likely real than a repeat glitch.
            print(f"WARNING ransomware.live {key}: {problem}, but {rejected} runs in a row disagreed with the stored counts; accepting the new response.")
            suspect = out_of_bounds({iso: c["total"] for iso, c in counted.items()}) is not None
        for iso in span:
            days[iso] = day_entry(iso, counted.get(iso))
        months_meta[key] = {"fetched_at": now_iso(), "count": n}
        if suspect:
            months_meta[key]["suspect"] = True
        changed += 1
        print(f"ransomware.live {key}: {n} victims.")

    if not changed:
        print("No usable ransomware.live month data this run; leaving the trends file unchanged.")
        return

    kept = sorted((d for date, d in days.items() if window_start.isoformat() <= date <= yesterday.isoformat()), key=lambda d: d["date"])
    first_month = month_key(window_start.year, window_start.month)
    months_meta = {k: months_meta[k] for k in sorted(months_meta) if k >= first_month}
    payload = {
        "generated_at": now_iso(),
        "source": "ransomware.live /v2/victims/<year>/<month>",
        "date_field": "discovered",
        "days_kept": DAYS_KEPT,
        "top_n": TOP_N,
        "through": kept[-1]["date"] if kept else None,
        "months": months_meta,
        "days": kept,
    }
    write_atomic(TRENDS_PATH, dump(payload))
    print(f"Wrote {len(kept)} days to {TRENDS_PATH}.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # never fail the workflow step
        print(f"fetch_ransomware_trends failed: {e}")
