# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A static threat-intel dashboard. There is no backend and no build step: GitHub Actions runs Python scripts that fetch feeds and commit JSON into `data/`, and GitHub Pages serves `index.html` / `app.js` / `styles.css`, which read those JSON files same-origin. README.md has the full feature tour, setup (repo secrets, OTX subscriptions) and per-feed operational gotchas.

## Commands

```bash
pip install -r requirements.txt              # only dependency is requests

# Serve the dashboard locally (same as .claude/launch.json)
python -m http.server 8791                   # then open http://localhost:8791

# Run one feed fetch, then rebuild the snapshot (main 30-min pipeline)
python scripts/fetch_kev.py                  # writes data/raw/cisa_kev.json (gitignored)
python scripts/build_snapshot.py             # merges data/raw/*.json -> data/latest.json

# Daily enrichment scripts read data/latest.json and write their own data/*.json
python scripts/fetch_epss.py
```

Keyed fetchers read their key from env vars (`THREATFOX_AUTH_KEY`, `URLHAUS_AUTH_KEY`, `MALWAREBAZAAR_AUTH_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`, `ABUSEIPDB_API_KEY`). Without one, the script records an error or no-ops; it does not crash.

There are no tests, linter, or JS tooling. Verify changes by running the scripts and loading the page in a browser.

## Architecture

**Two pipelines, two workflows:**

- `.github/workflows/fetch-feeds.yml` (every 30 min): the six bulk feeds (ThreatFox, URLhaus, MalwareBazaar, CISA KEV, OTX, Blocklist.de), plus ransomware.live and UK news headlines (`fetch_uk_news.py`, RSS, last 48h), which write their own `data/ransomware_victims.json` / `data/uk_news.json` and are committed alongside `latest.json`. Each `fetch_*.py` calls `common.write_raw()` to produce `data/raw/<feed>.json` with `{status, fetched_at, count, items, error?}`. `build_snapshot.py` merges these into `data/latest.json`. If a feed's raw file is missing or `status == "error"`, it **carries forward the previous snapshot's items** for that feed, so one broken feed never blanks the dashboard. Only `data/latest.json` is committed.
- `.github/workflows/daily-intel.yml` (06:00 UTC): enrichment and auxiliary sources (GreyNoise, geo/ASN, EPSS, InternetDB, AbuseIPDB, Spamhaus DROP, trend rollup). These **read `data/latest.json`** instead of `data/raw/`, and each writes its own committed file in `data/`. Per-IP enrichers get their IP set from `scripts/lib/extract_ips.get_ips_from_snapshot()`; use that rather than re-implementing extraction. `internetdb.json` and `abuseipdb.json` are full lookup caches the scripts depend on; the page loads the slim `*_view.json` copies written by `build_enrichment_views.py`. If you add a field the page reads, add it to that script too.

Every step uses `continue-on-error: true`, and each script catches its own exceptions. Keep new scripts fault-tolerant in the same way.

**Rate and quota caps are deliberate.** Several scripts self-limit to stay inside free tiers: GreyNoise about 7/day, which is why it runs in the daily workflow and not the 30-min cron; geo max 500 new IPs per run with a permanent cache; InternetDB 300 per run with a 30-day TTL; AbuseIPDB 500/day with a 14-day TTL; EPSS chunks of 100 CVEs; ransomware.live 1 request/min per endpoint. Don't raise these without checking the provider's limits (see README "Operational notes").

**Frontend (`app.js`):** a single IIFE with one `state` object. `loadData()` fetches `latest.json` (streamed with progress) plus every auxiliary JSON via `fetchJsonBestEffort`. A missing or failed auxiliary file must degrade silently, with no badge or panel shown and nothing broken. `render()` then builds everything client-side: KPIs, per-feed tables (`renderTable` with sort, search and export), cross-feed correlation and signal-count scoring (`buildCorrelation` / `computeSignalCount`), triage digest, watchlist (stored in `localStorage` only), sparklines, and the geo choropleth from `assets/world-map.svg`. All HTML is built from strings, so pass feed data through `escapeHtml()`.

Layout: a full-width command center (KPIs and triage | ransomware globe | live 72h victim feed), then a tabbed "data deck" holding every table. Section ids such as `section-<feed>` and `geo-section` are what `scrollToMatch` and the tabs target, so keep them stable; `activateTab()` must run before scrolling to a section. The globe (`initGlobe` / `updateGlobe`) lazy-loads globe.gl, topojson-client and world-atlas from jsDelivr at pinned versions, and the page must keep working if that fails or WebGL is off. `render()` processes every IP in every feed, so per-IP lookups must stay cheap: an uncached Spamhaus DROP check once took over a minute of CPU.

**Hard constraints (by design):**
- The browser never calls external threat-intel APIs, and API keys live only in Actions secrets. New data sources go through a Python script plus a committed JSON file.
- No backend or shared storage: watchlist stays per-browser, there's no alerting, and there's no historical IOC archive. `trends.json` holds daily counts only, capped at 90 entries.

**Adding a bulk feed** touches several hard-coded lists: `FEEDS` in `build_snapshot.py` and `append_trend.py`, `FEED_LABELS` and the table/column definitions in `app.js`, `get_ips_from_snapshot()` if the feed carries IPs, a section in `index.html`, and a step plus secret in `fetch-feeds.yml`. Daily scripts also need their output path added to the `git add` line in `daily-intel.yml`.

## Repo conventions

- `data/*.json` is bot-committed with `[skip ci]` messages, and most of git history is these commits. Expect frequent upstream data commits, so pull before pushing. Avoid hand-editing data files except to test.
- Scheduled workflows auto-disable after 60 days without repo activity; successful data commits normally keep them alive.
