#!/usr/bin/env python3
"""Fetch cyber security headlines from UK-based outlets via their public
RSS/Atom feeds and keep only items published in the last 48 hours.

Writes data/uk_news.json: {generated_at, window_hours, sources, items}.
Each item is {title, link, source, published, summary, uk_focus}.
`uk_focus` is a keyword guess for "this story is about the UK" (the
outlets are UK-based but also cover international news), which the page
offers as a filter.

No auth. One request per source per run. A failing source is recorded in
`sources` and skipped; if every source fails, the previous file is left
untouched so the page keeps showing the last good headlines.
"""

import datetime
import email.utils
import html
import json
import os
import re
import xml.etree.ElementTree as ET

import requests

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(BASE, "data", "uk_news.json")

WINDOW_HOURS = 48
MAX_PER_SOURCE = 40
SUMMARY_CHARS = 280
USER_AGENT = "cyberdashboard/1.0 (+https://github.com/; RSS reader)"

# (name, url, needs_cyber_filter). General tech feeds get a keyword filter
# so only security stories come through.
SOURCES = [
    ("NCSC", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", False),
    ("The Register", "https://www.theregister.com/security/headlines.atom", False),
    ("Computer Weekly", "https://www.computerweekly.com/rss/IT-security.xml", False),
    ("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/", False),
    ("The Guardian", "https://www.theguardian.com/technology/data-computer-security/rss", False),
    ("ITPro", "https://www.itpro.com/security/feed", False),
    ("Graham Cluley", "https://grahamcluley.com/feed/", False),
    ("BBC News", "https://feeds.bbci.co.uk/news/technology/rss.xml", True),
    ("Tech Monitor", "https://techmonitor.ai/feed", True),
]

CYBER_RE = re.compile(
    r"\b(cyber\w*|hack\w*|ransomware|malware|phishing|breach\w*|data leak\w*|"
    r"vulnerabilit\w*|exploit\w*|zero[- ]day|ddos|spyware|scam\w*|fraud|"
    r"ncsc|infosec|security flaw|patch\w*|botnet|stolen data|cyber-?attack\w*)\b",
    re.I,
)

UK_RE = re.compile(
    r"\b(UK|U\.K\.|United Kingdom|Britain|British|England|English|Scotland|Scottish|"
    r"Wales|Welsh|Northern Ireland|London|NHS|NCSC|GCHQ|Ofcom|ICO|"
    r"Information Commissioner|Home Office|Whitehall|Westminster|HMRC|"
    r"Ministry of Defence|MoD|National Crime Agency|NCA|Met Police|"
    r"Metropolitan Police|Bank of England|FCA|Downing Street|Parliament)\b"
)

ATOM = "{http://www.w3.org/2005/Atom}"
TAG_RE = re.compile(r"<[^>]+>")


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(text):
    """RSS uses RFC 822 dates, Atom uses ISO 8601. Returns aware UTC or None."""
    if not text:
        return None
    text = text.strip()
    try:
        dt = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        dt = None
    if dt is None:
        try:
            dt = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def clean_text(raw):
    if not raw:
        return ""
    text = html.unescape(TAG_RE.sub(" ", raw))
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > SUMMARY_CHARS:
        text = text[:SUMMARY_CHARS].rsplit(" ", 1)[0] + "…"
    return text


def child_text(el, *names):
    for name in names:
        found = el.find(name)
        if found is not None and (found.text or "").strip():
            return found.text
    return ""


def parse_feed(xml_bytes):
    """Yield (title, link, published_dt, summary) from RSS 2.0 or Atom."""
    root = ET.fromstring(xml_bytes)
    if root.tag == f"{ATOM}feed":
        for entry in root.findall(f"{ATOM}entry"):
            link = ""
            for l in entry.findall(f"{ATOM}link"):
                if l.get("rel", "alternate") == "alternate" and l.get("href"):
                    link = l.get("href")
                    break
            yield (
                child_text(entry, f"{ATOM}title"),
                link,
                parse_date(child_text(entry, f"{ATOM}published", f"{ATOM}updated")),
                child_text(entry, f"{ATOM}summary", f"{ATOM}content"),
            )
    else:
        for item in root.iter("item"):
            yield (
                child_text(item, "title"),
                child_text(item, "link", "guid"),
                parse_date(child_text(item, "pubDate", "{http://purl.org/dc/elements/1.1/}date")),
                child_text(item, "description"),
            )


def fetch_source(name, url, needs_filter, cutoff):
    resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    items = []
    for title, link, published, summary in parse_feed(resp.content):
        title = clean_text(title)
        link = (link or "").strip()
        if not title or not link.startswith(("https://", "http://")):
            continue
        if published is None or published < cutoff:
            continue
        summary = clean_text(summary)
        if needs_filter and not CYBER_RE.search(f"{title} {summary}"):
            continue
        items.append(
            {
                "title": title,
                "link": link,
                "source": name,
                "published": iso(published),
                "summary": summary,
                "uk_focus": name == "NCSC" or bool(UK_RE.search(f"{title} {summary}")),
            }
        )
        if len(items) >= MAX_PER_SOURCE:
            break
    return items


def main():
    now = now_utc()
    cutoff = now - datetime.timedelta(hours=WINDOW_HOURS)
    all_items, sources = [], []

    for name, url, needs_filter in SOURCES:
        try:
            items = fetch_source(name, url, needs_filter, cutoff)
            sources.append({"name": name, "status": "ok", "count": len(items)})
            all_items.extend(items)
        except Exception as e:
            print(f"UK news: {name} failed: {e}")
            sources.append({"name": name, "status": "error", "count": 0, "error": str(e)[:200]})

    if not any(s["status"] == "ok" for s in sources):
        print("UK news: every source failed, keeping previous file.")
        return

    # Same story syndicated twice (or listed in two NCSC sub-feeds): keep one.
    seen, deduped = set(), []
    for item in sorted(all_items, key=lambda i: i["published"], reverse=True):
        key = item["link"].split("?")[0].rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    payload = {
        "generated_at": iso(now),
        "window_hours": WINDOW_HOURS,
        "sources": sources,
        "items": deduped,
    }
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"UK news: {len(deduped)} headlines from the last {WINDOW_HOURS}h.")


if __name__ == "__main__":
    main()
