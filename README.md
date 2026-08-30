# Cyber Threat Dashboard

A static, browser-based dashboard of current IOCs, known-exploited vulnerabilities, and
attack-source IPs, pulled from six free/open-source threat intel feeds. There is no server
to run: a GitHub Actions cron job does the fetching and commits a JSON snapshot; GitHub
Pages serves the static site that reads it.

## How it works

```
GitHub Actions (cron, every 30 min)
   -> scripts/fetch_*.py pull each feed (using repo secrets for auth)
   -> scripts/build_snapshot.py merges them into data/latest.json
   -> commits data/latest.json if it changed
   -> GitHub Pages serves the repo, including data/latest.json

Browser
   -> loads index.html / app.js
   -> fetches data/latest.json (same-origin, no CORS issue, no keys involved)
   -> renders everything client-side
```

A second workflow (`fetch-enrichment.yml`) runs once a day and does three things, all
committed as small JSON files the frontend reads the same way it reads `latest.json`:

- annotates IPs seen across the feeds with GreyNoise Community classifications
  (`data/enrichment.json`) — separate from the main cron because GreyNoise's free tier is
  quota-limited (~50/week); bundling it into a 30-minute cron would exhaust it in hours.
- geolocates + ASN-tags IPs via ip-api.com's free batch endpoint, building a permanent
  cache (`data/geo.json`) and a recomputed aggregate (`data/geo_summary.json`) for the
  world map / top-countries / top-ASNs view.
- appends today's per-feed item counts to a small rolling history (`data/trends.json`,
  capped at 90 days) that drives the sparklines in each feed's header.

Feeds are not called directly from the browser because none of them serve permissive
CORS headers, and several require an API key that can't be safely shipped in client-side
JS. Doing the fetch inside GitHub Actions keeps keys server-side (as encrypted secrets)
while keeping the actual dashboard 100% static. Everything added in this second phase
(correlation, triage digest, watchlist, export) follows the same rule and runs entirely
client-side from data already loaded — no new external calls from the browser at all.

## Feature tour (phase 2)

- **Cross-feed correlation** — computed client-side from the loaded snapshot: IOCs
  (normalized IPs/domains/hashes) seen independently in 2+ feeds surface in their own
  section above the individual tables, sorted by feed-count then recency. Clicking a row
  filters and scrolls to the matching feed table.
- **Triage digest** — top 5 each of: ransomware-tied KEV entries, GreyNoise-confirmed
  `malicious` IPs, and top correlated IOCs. Each card hides itself independently if its
  underlying data is empty/missing — never a partial-broken-looking panel.
- **Watchlist** — paste IPs, CIDR ranges, or domains (one per line) into the Watchlist
  box. Stored only in `localStorage`, per-browser, never transmitted anywhere — clearing
  your browser data or opening the dashboard elsewhere starts fresh. Matching rows get a
  highlighted background and surface in a "Watchlist matches" panel.
- **Export** — every feed table (and the correlated-IOC panel) has CSV/JSON export
  buttons that respect whatever search filter is currently active, built entirely
  client-side via a `Blob` + temporary download link.
- **GreyNoise quota meter** — a small usage meter ("GreyNoise: N / 50 this week") next to
  the last-updated timestamp, computed from a rolling 7-day log the enrichment script
  keeps in `data/enrichment.json`. The self-imposed cap was tightened from the original
  8–10/day to **7/day (≈49/week)** to stay under the ~50/week ceiling with a small margin.
- **Trend sparklines** — a small 30-day trend line in each feed section's header, from
  `data/trends.json`. Degrades silently (no sparkline shown) until 2+ days of history
  exist.
- **Geo/ASN world map** — a log-scaled choropleth (world map SVG:
  [simple-world-map](https://github.com/flekschas/simple-world-map) by Al MacDonald /
  Fritz Lekschas, [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/) —
  attribution kept in the page footer per the license) plus accessible Top 10
  countries/ASNs tables and bars. Coverage builds gradually: at most 500 new IPs are
  geolocated per day and cached permanently in `data/geo.json` (an IP's country/ASN is
  effectively permanent, so it's never re-fetched) — full coverage of large feeds like
  Blocklist.de's ~21,500 unique IPs takes roughly a few weeks of daily runs. This is
  expected, not a bug.

## Repository structure

```
.github/workflows/
  fetch-feeds.yml        # main cron: all 6 bulk feeds, every 30 min
  fetch-enrichment.yml   # GreyNoise + geo/ASN + trend rollup, once daily
assets/
  world-map.svg           # ISO-tagged world map for the choropleth (CC BY-SA 3.0)
scripts/
  common.py                       # shared write_raw()/load_json() helpers
  fetch_threatfox.py
  fetch_urlhaus.py
  fetch_malwarebazaar.py
  fetch_kev.py
  fetch_otx.py
  fetch_blocklistde.py
  fetch_greynoise_enrichment.py   # + usage/quota tracking
  fetch_geo.py                    # ip-api.com geolocation + ASN, permanent cache
  append_trend.py                 # daily per-feed count rollup, capped at 90 entries
  build_snapshot.py               # merges data/raw/*.json -> data/latest.json
data/
  latest.json             # overwritten every main-cron run
  enrichment.json         # overwritten every enrichment run; adds a "usage" block
  geo.json                # permanent IP -> country/ASN cache, grows over time
  geo_summary.json        # aggregated counts for the map, rebuilt every run
  trends.json             # daily per-feed count rollup, capped at 90 entries
  raw/                    # per-feed intermediate output, gitignored
index.html / styles.css / app.js  # the dashboard itself
```

## Setup

1. **Add repo secrets** — Settings → Secrets and variables → Actions:
   - `THREATFOX_AUTH_KEY`, `URLHAUS_AUTH_KEY`, `MALWAREBAZAAR_AUTH_KEY` — all three come
     from the same abuse.ch Authentication Portal (`auth.abuse.ch`), free account.
   - `OTX_API_KEY` — free account at otx.alienvault.com, key from account settings.
   - `GREYNOISE_API_KEY` (optional) — free Community key from greynoise.io. If omitted,
     the enrichment workflow no-ops and the dashboard simply shows no GreyNoise badges.

2. **Subscribe to some OTX pulses.** The default endpoint
   (`/api/v1/pulses/subscribed`) only returns pulses the account is subscribed to. Before
   the feed will show anything, log into OTX and subscribe to 5–10 active pulses (search
   for terms like "ransomware", "phishing", "botnet"). If the subscribed-pulses call ever
   comes back empty, `fetch_otx.py` automatically falls back to the broader
   `/api/v1/pulses/activity` endpoint — but a real subscription list gives more relevant,
   curated results. **Note:** OTX's API has been evolving under LevelBlue's ownership;
   re-check both endpoints still behave as documented if the OTX section ever goes empty.

3. **Enable GitHub Pages** — Settings → Pages → Deploy from branch → `main` / root.

4. **Trigger the first run manually** — Actions tab → "Fetch Threat Intel Feeds" →
   Run workflow (this is the `workflow_dispatch` trigger). This generates the first real
   `data/latest.json` instead of waiting for the next scheduled run.

5. **Verify** — open the Pages URL and confirm real data renders in each section.

## Operational notes / known gotchas

- **CISA KEV 403s.** The primary CISA JSON endpoint has intermittently returned 403 to
  non-browser requests. `fetch_kev.py` sets a realistic User-Agent and automatically
  falls back to the GitHub mirror (`cisagov/kev-data`) CISA itself publishes, with no
  manual intervention needed.
- **Fault isolation.** Each `fetch_*.py` script catches its own exceptions and writes a
  `status: "error"` record rather than crashing. `build_snapshot.py` then carries forward
  the *previous* run's items for any feed that errored, so one broken feed never blanks
  the rest of the dashboard — it just shows a stale/error badge for that section.
- **Polling limits respected.** URLhaus's export regenerates every 5 minutes server-side;
  the 30-minute cron is comfortably within that and every other feed's stated minimum.
- **Scheduled workflows auto-disable after 60 days of repo inactivity.** Since successful
  cron runs commit to the repo, this is normally self-sustaining. But if a feed's API
  changes and every fetch starts failing for an extended period with no other commits,
  the schedule can lapse silently — check the Actions tab and re-enable it manually if
  runs seem to have stopped.
- **No client-side keys, ever.** All API keys live only in GitHub Actions secrets and
  are used server-side inside the workflow runs. The shipped frontend (`index.html`,
  `app.js`, `styles.css`) makes no calls to any external threat-intel API.

## Out of scope (by design)

- **Proactive alerting** (Slack/Discord/email/webhooks) — deferred by request.
- **Any per-user/shared (cross-browser) watchlist** — would require actual backend
  storage, contradicting the no-backend-infrastructure constraint. The watchlist is
  intentionally `localStorage`-only, per browser.
- **Full historical IOC archives** — `data/trends.json` is a deliberate, small exception
  to "no persistence": daily *counts* only (capped at 90 entries, a few KB), not a growing
  database of individual IOCs.
- User accounts/authentication, and writing data back to any feed.
