#!/usr/bin/env python3
"""EPSS movers: CVEs whose exploitation probability jumped over the last
week, plus the highest-scoring CVEs that are not (yet) in CISA KEV. This
can flag a vulnerability before it reaches KEV, whereas fetch_epss.py only
scores CVEs already in KEV.

Source: the daily full-score CSVs from FIRST.org / Empirical Security (no
auth). The FIRST API can't sort by change, so computing movers from it
would mean paging through all ~400k CVEs for both days (80+ requests);
the two gzipped CSVs are ~2.8 MB each and one request apiece.

  current:  https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  dated:    https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz

The change is measured against the score from WINDOW_DAYS (7) ago, not
yesterday: day-to-day changes are small and noisy, a week shows sustained
rises, and the daily workflow is sometimes delayed or skipped by GitHub,
which a one-day window would turn into gaps.

Only the small summary is committed (data/epss_movers.json); the full
score files are never written to the repo. If either download fails, a
file looks truncated or stale, the KEV list in data/latest.json looks
incomplete, or no CVE rose, the previous data/epss_movers.json is kept.

Downloads are streamed with a byte cap and a wall-clock deadline, and the
gzip is inflated incrementally with an output cap, so neither a huge body
nor a gzip bomb can exhaust the runner's memory.
"""

import csv
import datetime
import itertools
import json
import os
import re
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import fetch_capped, load_json, now_iso, write_atomic

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST_PATH = os.path.join(BASE, "data", "latest.json")
OUT_PATH = os.path.join(BASE, "data", "epss_movers.json")

EPSS_BASE_URL = "https://epss.empiricalsecurity.com"
CURRENT_URL = f"{EPSS_BASE_URL}/epss_scores-current.csv.gz"
DATED_URL = EPSS_BASE_URL + "/epss_scores-{date}.csv.gz"
# identity: the file is already gzip; this stops requests from inflating a
# Content-Encoding layer on top of it before the byte cap sees it.
HEADERS = {"User-Agent": "CyberThreatDashboard/1.0", "Accept-Encoding": "identity"}
TIMEOUT = 60  # per socket read
DEADLINE_S = 120  # per download; the ~3 MB file normally takes about a second

WINDOW_DAYS = 7
# If the exact comparison day's file is missing, try these offsets instead.
FALLBACK_DAYS = (8, 6, 9)
TOP_MOVERS = 100
TOP_NON_KEV = 50
# The full file has ~400k CVEs. Anything far below that is a truncated or
# broken download, and diffing against it would produce nonsense movers.
MIN_ROWS = 100_000
MAX_BYTES = 50 * 1024 * 1024  # compressed; the real file is ~3 MB
# Inflated; the real file is ~12 MB. A gzip bomb stops here.
MAX_INFLATED = 200 * 1024 * 1024
INFLATE_CHUNK = 1024 * 1024
MAX_LINE = 4096  # real lines are ~40 bytes; bounds the partial-line buffer
# The real file scores ~410k CVEs (~250 bytes of memory each once parsed).
# More than this is junk, and would cost memory even under MAX_INFLATED.
MAX_ROWS = 1_000_000
# data/latest.json normally lists ~1,800 KEV CVEs. A much shorter list is a
# truncated snapshot and would put KEV CVEs in "Highest EPSS, not in KEV".
MIN_KEV = 1000
# The current file's score_date must be this recent (days before today, UTC).
MAX_AGE_DAYS = 3

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
META_RE = re.compile(r"(\w{1,40}):([^,]*)")
META_VALUE_RE = re.compile(r"^[\w.\-]{1,40}$")


def download(url):
    return fetch_capped(url, MAX_BYTES, DEADLINE_S, headers=HEADERS, timeout=TIMEOUT)


def gunzip_lines(raw_gz):
    """Yield the decoded lines of a gzip body, inflating INFLATE_CHUNK at a
    time. Raises ValueError past MAX_INFLATED bytes or on a line longer
    than MAX_LINE, and on a truncated stream (like gzip.decompress)."""
    data = raw_gz
    inflated = 0
    pending = b""
    while data:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)  # one gzip member
        while not d.eof:
            chunk = d.decompress(data, INFLATE_CHUNK)
            data = d.unconsumed_tail
            if not chunk and not data:
                raise ValueError("truncated gzip stream")
            inflated += len(chunk)
            if inflated > MAX_INFLATED:
                raise ValueError(f"inflates past {MAX_INFLATED} bytes")
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()
            if len(pending) > MAX_LINE:
                raise ValueError(f"line longer than {MAX_LINE} bytes")
            for line in lines:
                yield line.rstrip(b"\r").decode("utf-8")
        data = d.unused_data  # a following gzip member, if any
    if pending:
        yield pending.rstrip(b"\r").decode("utf-8")


def parse_meta(line):
    """{key: value} from "#model_version:v2025.03.14,score_date:...".
    Values that aren't 1-40 word characters, dots or hyphens are dropped,
    except that score_date is cut to its leading YYYY-MM-DD first."""
    meta = {}
    for key, value in META_RE.findall(line[1:]):
        value = value.strip()
        if key == "score_date":
            value = value[:10]
        if META_VALUE_RE.match(value):
            meta[key] = value
    return meta


def parse_scores(raw_gz):
    """Return (meta, {cve: (epss, percentile)}) from a gzipped EPSS CSV.

    The first line is a comment like
    "#model_version:v2025.03.14,score_date:2025-11-14T12:00:00Z".
    """
    lines = gunzip_lines(raw_gz)
    meta = {}
    first = next(lines, None)
    if first is None:
        return meta, {}
    if first.startswith("#"):
        meta = parse_meta(first)
    else:
        lines = itertools.chain([first], lines)
    scores = {}
    for row in csv.DictReader(lines):
        cve = (row.get("cve") or "").strip()
        if not CVE_RE.match(cve):
            continue
        try:
            epss = float(row.get("epss"))
            pct = float(row.get("percentile"))
        except (TypeError, ValueError):
            continue
        if 0 <= epss <= 1 and 0 <= pct <= 1:
            scores[cve] = (epss, pct)
            if len(scores) > MAX_ROWS:
                raise ValueError(f"more than {MAX_ROWS} CVEs")
    return meta, scores


def score_date(meta):
    raw = meta.get("score_date") or ""
    try:
        return datetime.date.fromisoformat(raw)
    except ValueError:
        return None


def fetch_comparison(today):
    """Scores from WINDOW_DAYS before `today` (or the nearest fallback day
    that has a file). Returns (date, meta, scores) or None."""
    for days in (WINDOW_DAYS,) + FALLBACK_DAYS:
        day = today - datetime.timedelta(days=days)
        try:
            meta, scores = parse_scores(download(DATED_URL.format(date=day.isoformat())))
        except Exception as e:
            print(f"EPSS movers: comparison file for {day} unavailable: {e}")
            continue
        if len(scores) < MIN_ROWS:
            print(f"EPSS movers: comparison file for {day} has only {len(scores)} rows; skipping it.")
            continue
        if score_date(meta) != day:
            print(f"EPSS movers: comparison file for {day} says score_date {meta.get('score_date')!r}; skipping it.")
            continue
        return day, meta, scores
    return None


def kev_ids(latest):
    items = (latest or {}).get("feeds", {}).get("cisa_kev", {}).get("items", [])
    return {i.get("cve_id") for i in items if isinstance(i, dict) and i.get("cve_id")}


def r5(x):
    return round(x, 5)


def build(cur_scores, prev_scores, kev):
    movers = []
    for cve, (epss, pct) in cur_scores.items():
        prev = prev_scores.get(cve)
        # A CVE missing from the older file is new, not a mover.
        if prev is None:
            continue
        delta = epss - prev[0]
        if delta > 0:
            movers.append((delta, epss, cve, pct, prev))
    movers.sort(key=lambda m: (-m[0], -m[1], m[2]))
    mover_rows = [
        {
            "cve": cve,
            "epss": r5(epss),
            "percentile": r5(pct),
            "prev_epss": r5(prev[0]),
            "prev_percentile": r5(prev[1]),
            "delta": r5(delta),
            "in_kev": cve in kev,
        }
        for delta, epss, cve, pct, prev in movers[:TOP_MOVERS]
    ]

    non_kev = sorted(
        ((epss, pct, cve) for cve, (epss, pct) in cur_scores.items() if cve not in kev),
        key=lambda t: (-t[0], -t[1], t[2]),
    )[:TOP_NON_KEV]
    top_rows = []
    for epss, pct, cve in non_kev:
        prev = prev_scores.get(cve)
        top_rows.append(
            {
                "cve": cve,
                "epss": r5(epss),
                "percentile": r5(pct),
                "prev_epss": r5(prev[0]) if prev else None,
                "delta": r5(epss - prev[0]) if prev else None,
            }
        )
    return mover_rows, top_rows


def main():
    latest = load_json(LATEST_PATH)
    kev = kev_ids(latest)
    if len(kev) < MIN_KEV:
        # Without the full KEV list rows would be mislabelled; keep the old file.
        print(f"EPSS movers: only {len(kev)} KEV CVEs in data/latest.json (expected >= {MIN_KEV}); keeping the previous file.")
        return

    try:
        cur_meta, cur_scores = parse_scores(download(CURRENT_URL))
    except Exception as e:
        print(f"EPSS movers: current score file failed: {e}; keeping the previous file.")
        return
    if len(cur_scores) < MIN_ROWS:
        print(f"EPSS movers: current file has only {len(cur_scores)} rows; keeping the previous file.")
        return

    today = score_date(cur_meta)
    now = datetime.datetime.now(datetime.timezone.utc).date()
    # -1 allows for a file dated "tomorrow" by a clock just ahead of ours.
    if today is None or not -1 <= (now - today).days <= MAX_AGE_DAYS:
        print(f"EPSS movers: current file's score_date {cur_meta.get('score_date')!r} isn't within {MAX_AGE_DAYS} days of {now}; keeping the previous file.")
        return
    comparison = fetch_comparison(today)
    if not comparison:
        print("EPSS movers: no usable comparison file; keeping the previous file.")
        return
    prev_day, prev_meta, prev_scores = comparison

    movers, top_non_kev = build(cur_scores, prev_scores, kev)
    if not movers:
        # e.g. the comparison file is a copy of the current one.
        print("EPSS movers: no CVE rose against the comparison file; keeping the previous file.")
        return

    cur_model = cur_meta.get("model_version")
    prev_model = prev_meta.get("model_version")
    out = {
        "generated_at": now_iso(),
        "score_date": today.isoformat(),
        "compare_date": prev_day.isoformat(),
        "window_days": (today - prev_day).days,
        "model_version": cur_model,
        "compare_model_version": prev_model,
        # A new EPSS model re-scores everything at once, so the change then
        # reflects the model, not new exploitation evidence.
        "model_changed": bool(cur_model and prev_model and cur_model != prev_model),
        "total_scored": len(cur_scores),
        "movers": movers,
        "top_non_kev": top_non_kev,
    }
    write_atomic(OUT_PATH, json.dumps(out, ensure_ascii=False, indent=2))
    print(
        f"EPSS movers: {len(movers)} movers, {len(top_non_kev)} top non-KEV "
        f"({today} vs {prev_day}, {len(cur_scores)} CVEs scored)."
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # never fail the workflow step
        print(f"fetch_epss_movers failed: {e}; keeping the previous file.")
