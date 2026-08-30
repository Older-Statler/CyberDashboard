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

A second workflow (`daily-intel.yml`) runs once a day and pulls eight more sources, each
as its own independently-fault-tolerant step, all committed as small JSON files the
frontend reads the same way it reads `latest.json`:

- annotates IPs seen across the feeds with GreyNoise Community classifications
  (`data/enrichment.json`) — separate from the main cron because GreyNoise's free tier is
  quota-limited (~50/week); bundling it into a 30-minute cron would exhaust it in hours.
- geolocates + ASN-tags IPs via ip-api.com's free batch endpoint, building a permanent
  cache (`data/geo.json`) and a recomputed aggregate (`data/geo_summary.json`) for the
  world map / top-countries / top-ASNs view.
- scores every KEV CVE's exploit probability via FIRST.org's EPSS API (`data/epss.json`).
- looks up what's actually exposed on IPs via Shodan InternetDB (`data/internetdb.json`).
- looks up crowd-sourced abuse reports via AbuseIPDB (`data/abuseipdb.json`) — optional,
  needs a free key.
- fetches Spamhaus DROP's criminal-controlled netblocks (`data/spamhaus_drop.json`).
- fetches recent ransomware victims from ransomware.live (`data/ransomware_victims.json`).
- appends today's per-feed item counts to a small rolling history (`data/trends.json`,
  capped at 90 days) that drives the sparklines in each feed's header.

Feeds are not called directly from the browser because none of them serve permissive
CORS headers, and several require an API key that can't be safely shipped in client-side
JS. Doing the fetch inside GitHub Actions keeps keys server-side (as encrypted secrets)
while keeping the actual dashboard 100% static. Everything added in phases 2 and 3
(correlation, triage digest, watchlist, export, the extended signal-count scoring) follows
the same rule and runs entirely client-side from data already loaded — no new external
calls from the browser at all.

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

## Feature tour (phase 3)

- **EPSS scores** — every CISA KEV entry gets an EPSS score + percentile column (sortable)
  from FIRST.org, showing the probability a CVE gets exploited in the next 30 days —
  CISA KEV tells you it *has* been exploited, EPSS tells you how likely it is to be
  exploited *again*. The triage panel adds a card for KEV entries that are both
  ransomware-tagged and in EPSS's top 10th percentile — about as urgent as this data gets.
- **Shodan InternetDB** — a badge on any IP with exposed ports/CVEs/hostnames on record
  ("3 ports, 1 CVE"), hover for the detail. Entries are re-checked after 30 days since
  exposure changes over time, unlike the permanent geo cache.
- **AbuseIPDB** — a color-coded badge (reusing the dashboard's existing ok/warning/danger
  colors, never color alone) by abuse-confidence-score band. Optional — needs a free
  `ABUSEIPDB_API_KEY`; badges simply don't appear without one.
- **Spamhaus DROP** — criminal-controlled netblocks, one level up from individual IPs. Any
  IP inside a DROP range gets a "netblock flagged" badge, plus its own KPI tile. Reuses the
  same CIDR-matching helper originally built for the watchlist.
- **Ransomware Activity** — a new section listing recent ransomware.live victim
  disclosures (group, victim, sector, country, date) — the organizational complement to
  the ransomware-tagged KEV entries: one says "this vulnerability is used by ransomware
  operators," this says "and here's who they've hit lately." The 5 most recent surface in
  the triage panel too. Intentionally *not* cross-referenced against the IOC feeds —
  victim data isn't shaped for that kind of matching.
- **Extended correlation scoring** — "Correlated IOCs" is now "Correlated / High-Confidence
  IOCs," ranked by total *signal count* rather than raw feed-count alone: appearing in 2+
  feeds is one signal, and GreyNoise `malicious`, AbuseIPDB ≥ 75, a Spamhaus DROP match,
  and an InternetDB CVE each add one more. A single-feed IP corroborated by two enrichment
  sources now ranks alongside one seen in two raw feeds, instead of being excluded
  entirely as it was in phase 2.
- **Shared IP-extraction helper** (`scripts/lib/extract_ips.py`) — the "which IPs appear
  across the bulk feeds" logic used to be duplicated in the GreyNoise and geo scripts;
  now every per-IP enricher (GreyNoise, geo, InternetDB, AbuseIPDB) imports one function.

## Repository structure

```
.github/workflows/
  fetch-feeds.yml        # main cron: all 6 bulk feeds, every 30 min
  daily-intel.yml        # GreyNoise, geo/ASN, EPSS, InternetDB, AbuseIPDB, Spamhaus
                          # DROP, ransomware.live, trend rollup — once daily
assets/
  world-map.svg           # ISO-tagged world map for the choropleth (CC BY-SA 3.0)
scripts/
  common.py                       # shared write_raw()/load_json() helpers
  lib/
    extract_ips.py                # shared "unique IPs across the bulk feeds" helper
  fetch_threatfox.py
  fetch_urlhaus.py
  fetch_malwarebazaar.py
  fetch_kev.py
  fetch_otx.py
  fetch_blocklistde.py
  fetch_greynoise_enrichment.py   # + usage/quota tracking; uses lib/extract_ips.py
  fetch_geo.py                    # ip-api.com geolocation + ASN, permanent cache; uses lib/extract_ips.py
  fetch_epss.py                   # FIRST.org EPSS scores for every KEV CVE
  fetch_internetdb.py             # Shodan InternetDB per-IP exposure, 30-day TTL cache
  fetch_abuseipdb.py              # AbuseIPDB per-IP abuse reports, 14-day TTL cache
  fetch_spamhaus_drop.py          # Spamhaus DROP netblocks, full refresh daily
  fetch_ransomware_live.py        # ransomware.live recent victims
  append_trend.py                 # daily per-feed count rollup, capped at 90 entries
  build_snapshot.py               # merges data/raw/*.json -> data/latest.json
data/
  latest.json             # overwritten every main-cron run
  enrichment.json         # overwritten every enrichment run; adds a "usage" block
  geo.json                # permanent IP -> country/ASN cache, grows over time
  geo_summary.json        # aggregated counts for the map, rebuilt every run
  epss.json               # full refresh every run — one entry per KEV CVE
  internetdb.json         # IP -> exposure cache, 30-day TTL
  abuseipdb.json          # IP -> abuse report cache, 14-day TTL
  spamhaus_drop.json      # full refresh every run — CIDR ranges + SBL IDs
  ransomware_victims.json # full refresh every run — ~100 most recent victims
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
     that step no-ops and the dashboard simply shows no GreyNoise badges.
   - `ABUSEIPDB_API_KEY` (optional) — free key from abuseipdb.com. If omitted, that step
     no-ops and the dashboard simply shows no AbuseIPDB badges. EPSS, Shodan InternetDB,
     Spamhaus DROP, and ransomware.live need no key at all.

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
- **ransomware.live is rate-limited to 1 request/minute per endpoint.** `fetch_ransomware_live.py`
  only calls one endpoint (`/recentvictims`) once per run, so this is trivially respected —
  but if a second endpoint is ever added there, the calls need to be spaced 60+ seconds apart.
- **Shodan InternetDB has no documented rate limit**, so `fetch_internetdb.py` self-imposes
  one anyway: 300 new/re-checked IPs per run with a ~200ms delay between requests, out of
  courtesy to a free public service.
- **AbuseIPDB's free tier is 1,000 checks/day**; `fetch_abuseipdb.py` self-caps at 500/day,
  leaving real headroom rather than brushing the ceiling.
- **EPSS chunking.** ~1,700 KEV CVEs would make an unreasonably long URL in one request, so
  `fetch_epss.py` batches in chunks of 100 CVE IDs per call.
- Considered and **excluded**: abuse.ch's Feodo Tracker. Its datasets are currently empty
  (attributed to law-enforcement takedowns — Emotet 2021, Operation Endgame 2024), not
  worth building against right now. If botnet C2 tracking is wanted later, abuse.ch's own
  FAQ points to Spamhaus's Botnet Controller List as the modern replacement.

## Out of scope (by design)

- **Proactive alerting** (Slack/Discord/email/webhooks) — deferred by request.
- **Any per-user/shared (cross-browser) watchlist** — would require actual backend
  storage, contradicting the no-backend-infrastructure constraint. The watchlist is
  intentionally `localStorage`-only, per browser.
- **Full historical IOC archives** — `data/trends.json` is a deliberate, small exception
  to "no persistence": daily *counts* only (capped at 90 entries, a few KB), not a growing
  database of individual IOCs.
- User accounts/authentication, and writing data back to any feed.
- Feodo Tracker / botnet C2 tracking (dataset currently empty — revisit if abuse.ch or
  Spamhaus's Botnet Controller List becomes relevant later).
- Cross-referencing ransomware.live victim data against the IOC feeds (different data
  shape, not a clean match — see Ransomware Activity above).
- A second map layer for ransomware-victims-by-country (the ranked table covers it for
  now; revisit if the existing choropleth should support a toggleable second dataset).
