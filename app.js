(() => {
  "use strict";

  // The feed workflow is scheduled every 30 minutes, but GitHub throttles
  // scheduled runs and in practice they land every 5-8 hours. Only flag the
  // snapshot as stale once it's clearly past that, so the banner means
  // "something is wrong" rather than showing most of the time.
  const STALE_AFTER_HOURS = 12;
  const GREYNOISE_WEEKLY_CAP = 50;

  const FEED_LABELS = {
    threatfox: "ThreatFox",
    urlhaus: "URLhaus",
    malwarebazaar: "MalwareBazaar",
    cisa_kev: "CISA KEV",
    otx: "OTX",
    blocklistde: "Blocklist.de",
  };

  const state = {
    snapshot: null,
    enrichment: null,
    trends: null,
    geoSummary: null,
    epss: null,
    internetdb: null,
    abuseipdb: null,
    spamhausDrop: null,
    dropRangesParsed: [],
    dropCache: new Map(), // ip -> matching DROP range (or null), reset when ranges change
    ransomwareVictims: null,
    ransomwareTrends: null,
    rwTrendDays: 30, // Ransomware tab trends window, one of RWT_WINDOWS
    ukNews: null,
    newsQuery: "",
    newsUkOnly: false,
    tableState: {}, // feed -> { sortKey, sortDir, query, lastFiltered }
    correlated: [],
    iocIndex: new Map(), // "type|value" -> correlation entries (with source item), see buildCorrelation
    drawer: null, // { type, value, trigger, scope, fromLink } while the IOC drawer is open
    hashPendingIoc: null, // { type, value } from the URL fragment, opened once the data is complete
    dataComplete: false, // latest.json and the auxiliary files have loaded at least once
    triage: { ransomwareKev: [], epssCriticalKev: [], maliciousIps: [], topCorrelated: [] },
    rw: null, // ransomware victims in the last RW_WINDOW_HOURS, see computeRansomwareWindow
    rwCountry: null, // country code selected on the globe / bars, filters the live feed
    watchlistText: "",
    watchlistMatches: [],
    watchlistMatchKeys: new Set(),
    // KEV vendor/product watchlist, see "KEV vendor / product watchlist".
    kevWatch: {
      text: "",
      terms: null, // compiled matchers for `text`
      matches: [], // matching KEV items, most recently added first
      termFor: new Map(), // cve_id -> the watchlist term that matched it
      watchedOnly: false, // KEV table "watched only" filter
      ranked: [], // KEV vendors by entry count, for suggestions
    },
    // "New since your last visit", see the section of that name below.
    since: {
      enabled: false, // false when localStorage is blocked/full: no badges, no summary
      record: null, // validated contents of SEEN_KEY
      baseline: null, // category -> Set of ids (or null = no baseline for it)
      current: null, // category -> array of ids in the data on screen (or null)
      newSets: { kev: new Set(), rw: new Set(), ioc: new Set(), news: new Set() },
      newOnly: {}, // table ("cisa_kev" / "ransomware_victims" / "correlated") -> "new only" filter on
    },
  };

  function $(id) {
    return document.getElementById(id);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // The fetcher no longer stores urlhaus_link (it's always derivable from
  // the id); older snapshots still carry it, so prefer it when present.
  function urlhausLink(item) {
    if (item.urlhaus_link) return item.urlhaus_link;
    return item.id ? `https://urlhaus.abuse.ch/url/${encodeURIComponent(item.id)}/` : "";
  }

  function fmtDate(iso) {
    if (!iso) return "&mdash;";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return escapeHtml(iso);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function relativeTime(iso) {
    if (!iso) return "unknown";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "unknown";
    const diffMs = Date.now() - d.getTime();
    const mins = Math.round(diffMs / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins} min ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return `${hrs} hr ago`;
    const days = Math.round(hrs / 24);
    return `${days} day${days === 1 ? "" : "s"} ago`;
  }

  // ---------- IOC normalization (shared by correlation + watchlist) ----------

  const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

  function isIpv4(str) {
    if (!str) return false;
    const m = IPV4_RE.exec(String(str).trim());
    if (!m) return false;
    return m.slice(1).every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
  }

  function normalizeIp(raw) {
    if (!raw) return null;
    let v = String(raw).trim();
    const portMatch = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$/.exec(v);
    if (portMatch) v = portMatch[1];
    return isIpv4(v) ? v : null;
  }

  function normalizeDomain(raw) {
    if (!raw) return null;
    let v = String(raw).trim().toLowerCase();
    if (v.endsWith(".")) v = v.slice(0, -1);
    return v || null;
  }

  function extractHost(url) {
    if (!url) return null;
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (e) {
      const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(url) || /^([^/:?#]+)/i.exec(url);
      return m ? m[1].toLowerCase() : null;
    }
  }

  function normalizeHash(raw) {
    if (!raw) return null;
    const v = String(raw).trim().toUpperCase();
    return /^[A-F0-9]{32,64}$/.test(v) ? v : null;
  }

  function normalizeIocValue(raw, kindHint) {
    if (!raw) return null;
    if (kindHint === "ip") {
      const ip = normalizeIp(raw);
      return ip ? { type: "ip", value: ip } : null;
    }
    if (kindHint === "domain") {
      const d = normalizeDomain(raw);
      return d ? { type: "domain", value: d } : null;
    }
    if (kindHint === "url") {
      const host = extractHost(raw);
      if (!host) return null;
      const ip = normalizeIp(host);
      if (ip) return { type: "ip", value: ip };
      const d = normalizeDomain(host);
      return d ? { type: "domain", value: d } : null;
    }
    if (kindHint === "hash") {
      const h = normalizeHash(raw);
      return h ? { type: "hash", value: h } : null;
    }
    return null;
  }

  // ---------- Data loading ----------

  async function fetchJsonBestEffort(path) {
    try {
      const resp = await fetch(path, { cache: "no-cache" });
      if (!resp.ok) return null;
      return await resp.json();
    } catch (e) {
      return null;
    }
  }

  // data/latest.json is by far the largest fetch (multi-MB and growing with
  // the feeds). A plain fetch()+.json() gives no feedback until it's fully
  // done, which reads as a hang on a slow connection — this streams the
  // response and reports real byte progress instead. Falls back to a plain
  // fetch if the server doesn't send Content-Length or streaming isn't
  // available (e.g. very old browsers).
  async function fetchJsonWithProgress(path, onProgress) {
    const resp = await fetch(path, { cache: "no-cache" });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const totalStr = resp.headers.get("Content-Length");
    const total = totalStr ? parseInt(totalStr, 10) : 0;
    if (!resp.body || !total) {
      return await resp.json();
    }

    const reader = resp.body.getReader();
    const chunks = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      if (onProgress) onProgress(received, total);
    }
    const text = await new Blob(chunks).text();
    return JSON.parse(text);
  }

  async function loadWorldMapSvg() {
    const container = $("world-map-container");
    if (!container) return;
    try {
      const resp = await fetch("assets/world-map.svg", { cache: "force-cache" });
      if (!resp.ok) return;
      container.innerHTML = await resp.text();
      const svg = container.querySelector("svg");
      if (svg) svg.removeAttribute("height");
    } catch (e) {
      // Map asset is optional — the bars/tables next to it still work without it.
    }
  }

  async function loadData() {
    // Start the smaller files now so they download alongside latest.json
    // instead of waiting for it to finish.
    let auxReady = false;
    const auxPromise = Promise.all([
      fetchJsonBestEffort("data/enrichment.json"),
      fetchJsonBestEffort("data/trends.json"),
      fetchJsonBestEffort("data/geo_summary.json"),
      fetchJsonBestEffort("data/epss.json"),
      fetchJsonBestEffort("data/internetdb_view.json"),
      fetchJsonBestEffort("data/abuseipdb_view.json"),
      fetchJsonBestEffort("data/spamhaus_drop.json"),
      fetchJsonBestEffort("data/ransomware_victims.json"),
      fetchJsonBestEffort("data/uk_news.json"),
      fetchJsonBestEffort("data/ransomware_trends.json"),
      loadWorldMapSvg(),
    ]).then((results) => {
      auxReady = true;
      return results;
    });

    try {
      state.snapshot = await fetchJsonWithProgress("data/latest.json", (received, total) => {
        const pct = Math.min(100, Math.round((received / total) * 100));
        $("last-updated").textContent = `Loading data… ${pct}% (${(total / 1024 / 1024).toFixed(1)} MB)`;
      });
    } catch (e) {
      // On an auto-refresh, the previous data is still on screen; say so.
      $("last-updated").textContent = state.snapshot
        ? `Refresh failed · showing data from ${relativeTime(state.snapshot.generated_at)}`
        : "Failed to load data/latest.json";
      console.error("Failed to load snapshot:", e);
      return;
    }

    $("last-updated").textContent = "Processing…";

    // Show the feed tables as soon as latest.json is in. Every enrichment
    // panel/badge already hides itself when its data is missing, so the
    // second render() below just fills them in.
    if (!auxReady) {
      render();
      applyInitialHash();
      $("last-updated").textContent += " · loading enrichment…";
    }

    const [enrichment, trends, geoSummary, epss, internetdb, abuseipdb, spamhausDrop, ransomwareVictims, ukNews, ransomwareTrends] =
      await auxPromise;
    state.enrichment = enrichment;
    state.trends = trends;
    state.geoSummary = geoSummary;
    state.epss = epss;
    state.internetdb = internetdb;
    state.abuseipdb = abuseipdb;
    state.spamhausDrop = spamhausDrop;
    state.ransomwareVictims = ransomwareVictims;
    state.ukNews = ukNews;
    state.ransomwareTrends = ransomwareTrends;

    render();
    applyInitialHash(); // no-op after the first load
    sinceAfterLoad();
    // A linked IOC may only be known from the enrichment files, so it waits for them.
    state.dataComplete = true;
    openPendingHashIoc();
  }

  // ---------- Auto-refresh ----------

  // Re-fetch every data file and re-render in place (not a browser reload),
  // so search boxes, the selected tab, scroll position and the globe survive.
  // Matches the 30-min fetch workflow. Hidden tabs skip the download and
  // catch up as soon as they're visible again.
  const REFRESH_MINUTES = 30;
  let lastLoadAt = Date.now();
  let refreshing = false;

  async function refreshIfDue() {
    if (refreshing || document.hidden) return;
    if (Date.now() - lastLoadAt < REFRESH_MINUTES * 60000) return;
    refreshing = true;
    renderRefreshCountdown();
    try {
      await loadData();
    } finally {
      lastLoadAt = Date.now();
      refreshing = false;
      renderRefreshCountdown();
    }
  }

  function renderRefreshCountdown() {
    const el = $("refresh-countdown");
    if (!el) return;
    el.classList.toggle("is-busy", refreshing);
    if (refreshing) {
      el.textContent = "Refreshing…";
      return;
    }
    const left = Math.max(0, Math.ceil((lastLoadAt + REFRESH_MINUTES * 60000 - Date.now()) / 1000));
    const mm = String(Math.floor(left / 60)).padStart(2, "0");
    const ss = String(left % 60).padStart(2, "0");
    el.textContent = `Next refresh ${mm}:${ss}`;
  }

  function initAutoRefresh() {
    setInterval(refreshIfDue, 1000);
    document.addEventListener("visibilitychange", refreshIfDue);
  }

  // ---------- KPIs / header ----------

  function renderHeader() {
    const snap = state.snapshot;
    const generatedAt = snap.generated_at;

    if (!generatedAt) {
      $("last-updated").textContent = "No data yet — waiting for first workflow run";
    } else {
      $("last-updated").textContent = `Last updated ${fmtDate(generatedAt)} (${relativeTime(generatedAt)})`;
    }

    const staleBanner = $("stale-banner");
    if (generatedAt) {
      const ageHours = (Date.now() - new Date(generatedAt).getTime()) / 3600000;
      staleBanner.hidden = ageHours <= STALE_AFTER_HOURS;
    } else {
      staleBanner.hidden = true;
    }
  }

  function renderKpis() {
    const feeds = state.snapshot.feeds || {};

    const iocFeeds = ["threatfox", "urlhaus", "malwarebazaar", "blocklistde"];
    const totalIocs = iocFeeds.reduce((sum, f) => sum + (feeds[f]?.count || 0), 0);
    $("kpi-total-iocs").textContent = totalIocs.toLocaleString();

    const kevItems = feeds.cisa_kev?.items || [];
    const sevenDaysAgo = Date.now() - 7 * 24 * 3600 * 1000;
    const newKev = kevItems.filter((v) => {
      const d = new Date(v.date_added);
      return !isNaN(d.getTime()) && d.getTime() >= sevenDaysAgo;
    }).length;
    $("kpi-new-kev").textContent = newKev.toLocaleString();

    const ransomwareKev = kevItems.filter((v) => v.known_ransomware_campaign_use === "Known").length;
    $("kpi-ransomware-kev").textContent = ransomwareKev.toLocaleString();

    const errorFeeds = Object.values(feeds).filter((f) => f.status === "error").length;
    $("kpi-errors").textContent = errorFeeds.toLocaleString();
    $("kpi-errors-card").classList.toggle("has-errors", errorFeeds > 0);

    const dropCount = countIpsInDrop(feeds);
    $("kpi-drop-count").textContent = dropCount.toLocaleString();

    const errorPanel = $("error-panel");
    const errorList = $("error-list");
    const errors = state.snapshot.errors || [];
    if (errors.length) {
      errorPanel.hidden = false;
      errorList.innerHTML = errors
        .map((e) => `<li><strong>${escapeHtml(e.feed)}:</strong> ${escapeHtml(e.message)}</li>`)
        .join("");
    } else {
      errorPanel.hidden = true;
    }
  }

  function renderFeedStatus(feed) {
    const def = FEED_DEFS[feed];
    const info = def && def.getItems ? def.getItems() : state.snapshot.feeds?.[feed];
    const el = $(`status-${feed}`);
    if (!info || !el) return;
    el.textContent = info.status;
    el.className = `feed-status ${info.status}`;
  }

  // ---------- GreyNoise badges + quota meter ----------

  function greynoiseBadge(ip) {
    const lookup = state.enrichment?.lookups?.[ip];
    if (!lookup) return "";
    const cls = lookup.classification || "unclassified";
    let badgeClass = "badge-unclassified";
    let label = "unclassified";
    if (cls === "malicious") {
      badgeClass = "badge-malicious";
      label = "malicious";
    } else if (cls === "benign" || lookup.noise) {
      badgeClass = "badge-noise";
      label = "known scanner";
    }
    return ` <span class="badge ${badgeClass}" title="GreyNoise: ${escapeHtml(cls)}">${label}</span>`;
  }

  function extractIpFromIoc(ioc, iocType) {
    if (!ioc || !iocType || !iocType.includes("ip")) return null;
    return ioc.includes(":") ? ioc.split(":")[0] : ioc;
  }

  function renderQuotaMeter() {
    const el = $("quota-meter");
    const usage = state.enrichment?.usage;
    const count = usage?.recent_lookups?.length;
    if (count === undefined || count === null) {
      el.hidden = true;
      return;
    }
    el.hidden = false;
    const pct = Math.min(100, Math.round((count / GREYNOISE_WEEKLY_CAP) * 100));
    $("quota-fill").style.width = `${pct}%`;
    $("quota-label").textContent = `GreyNoise: ${count} / ${GREYNOISE_WEEKLY_CAP} this week`;
    el.classList.toggle("quota-warn", count >= GREYNOISE_WEEKLY_CAP * 0.8);
  }

  // ---------- Spamhaus DROP (reuses the watchlist's CIDR-match helpers) ----------

  function buildDropRanges() {
    const ranges = state.spamhausDrop?.ranges || [];
    state.dropRangesParsed = ranges
      .map((r) => {
        const cidr = parseCidr(r.cidr);
        return cidr ? { ...cidr, sbl_id: r.sbl_id, raw: r.cidr } : null;
      })
      .filter(Boolean);
    state.dropCache = new Map();
  }

  // Called for every IP in every feed (KPI, correlation scoring, badges), so
  // parse each IP once and remember the answer — re-parsing the IP for each
  // of the ~1,700 DROP ranges used to freeze the page for over a minute.
  function isIpInDrop(ip) {
    if (!ip || !state.dropRangesParsed.length) return null;
    const cache = state.dropCache;
    if (cache.has(ip)) return cache.get(ip);
    let hit = null;
    if (isIpv4(ip)) {
      const n = ipToInt(ip);
      for (const r of state.dropRangesParsed) {
        if ((n & r.mask) === r.network) {
          hit = r;
          break;
        }
      }
    }
    cache.set(ip, hit);
    return hit;
  }

  function countIpsInDrop(feeds) {
    const entries = extractCorrelationEntries(feeds);
    const ips = new Set(entries.filter((e) => e.norm.type === "ip").map((e) => e.norm.value));
    let count = 0;
    for (const ip of ips) {
      if (isIpInDrop(ip)) count++;
    }
    return count;
  }

  // ---------- EPSS / InternetDB / AbuseIPDB / DROP badges ----------

  function epssFor(cveId) {
    return state.epss?.scores?.[cveId] || null;
  }

  function internetdbBadge(ip) {
    const entry = state.internetdb?.entries?.[ip];
    if (!entry || entry.no_data) return "";
    const portCount = (entry.ports || []).length;
    const vulnCount = (entry.vulns || []).length;
    if (!portCount && !vulnCount) return "";
    const tooltipParts = [
      portCount ? `Ports: ${entry.ports.join(", ")}` : "",
      vulnCount ? `CVEs: ${entry.vulns.join(", ")}` : "",
      (entry.hostnames || []).length ? `Hostnames: ${entry.hostnames.join(", ")}` : "",
    ].filter(Boolean);
    const label = `${portCount} port${portCount === 1 ? "" : "s"}${vulnCount ? `, ${vulnCount} CVE${vulnCount === 1 ? "" : "s"}` : ""}`;
    return ` <span class="badge badge-info" title="InternetDB — ${escapeHtml(tooltipParts.join(" | "))}">${escapeHtml(label)}</span>`;
  }

  function abuseipdbBadge(ip) {
    const entry = state.abuseipdb?.entries?.[ip];
    const score = entry?.abuseConfidenceScore;
    if (score === undefined || score === null) return "";
    let cls = "badge-abuse-ok";
    let label = "fine";
    if (score >= 75) {
      cls = "badge-abuse-severe";
      label = "severe";
    } else if (score >= 50) {
      cls = "badge-abuse-concerning";
      label = "concerning";
    } else if (score >= 25) {
      cls = "badge-abuse-caution";
      label = "caution";
    }
    const tooltip = `AbuseIPDB — ${entry.totalReports || 0} reports, ISP: ${entry.isp || "unknown"}`;
    return ` <span class="badge ${cls}" title="${escapeHtml(tooltip)}">AbuseIPDB ${score} (${label})</span>`;
  }

  function dropBadge(ip) {
    const match = isIpInDrop(ip);
    if (!match) return "";
    const tooltip = `Spamhaus DROP: ${match.raw}${match.sbl_id ? ` (${match.sbl_id})` : ""}`;
    return ` <span class="badge badge-drop" title="${escapeHtml(tooltip)}">netblock flagged</span>`;
  }

  function ipBadges(ip) {
    return greynoiseBadge(ip) + internetdbBadge(ip) + abuseipdbBadge(ip) + dropBadge(ip);
  }

  // ---------- Correlation ----------

  // Per-feed IOC normalisation, shared by the correlation index and the
  // drawer triggers in the feed tables so both agree on an IOC's key.
  function threatfoxNorm(item) {
    const t = (item.ioc_type || "").toLowerCase();
    let kind = null;
    if (t.includes("ip")) kind = "ip";
    else if (t.includes("domain")) kind = "domain";
    else if (t.includes("url")) kind = "url";
    else if (t.includes("hash") || t.includes("md5") || t.includes("sha")) kind = "hash";
    return normalizeIocValue(item.ioc, kind);
  }

  function urlhausNorm(item) {
    const host = extractHost(item.url);
    if (!host) return null;
    const ip = normalizeIp(host);
    return ip ? { type: "ip", value: ip } : normalizeIocValue(host, "domain");
  }

  function otxNorm(ind) {
    const type = (ind.type || "").toLowerCase();
    let kind = null;
    if (type.includes("ipv4") || type.includes("ipv6")) kind = "ip";
    else if (type.includes("domain") || type.includes("hostname")) kind = "domain";
    else if (type.includes("url")) kind = "url";
    else if (type.includes("hash") || type.includes("md5") || type.includes("sha")) kind = "hash";
    return normalizeIocValue(ind.indicator, kind);
  }

  // Each entry keeps a reference to its source item (and, for OTX, the
  // indicator) so the IOC drawer can show per-feed details without
  // rescanning the feeds.
  function extractCorrelationEntries(feeds) {
    const entries = [];

    for (const item of feeds.threatfox?.items || []) {
      const norm = threatfoxNorm(item);
      if (norm) {
        entries.push({ norm, feed: "threatfox", label: item.malware_printable || item.ioc_type, seenAt: item.first_seen, item });
      }
    }

    for (const item of feeds.urlhaus?.items || []) {
      const norm = urlhausNorm(item);
      if (norm) {
        entries.push({ norm, feed: "urlhaus", label: item.threat || "malicious URL", seenAt: item.date_added, item });
      }
    }

    for (const item of feeds.malwarebazaar?.items || []) {
      const norm = normalizeIocValue(item.sha256_hash, "hash");
      if (norm) {
        entries.push({ norm, feed: "malwarebazaar", label: item.signature || "malware sample", seenAt: item.first_seen, item });
      }
    }

    for (const item of feeds.otx?.items || []) {
      for (const ind of item.indicators || []) {
        const norm = otxNorm(ind);
        if (norm) {
          entries.push({ norm, feed: "otx", label: item.name, seenAt: item.created, item, indicator: ind });
        }
      }
    }

    const blFetchedAt = feeds.blocklistde?.fetched_at || null;
    for (const item of feeds.blocklistde?.items || []) {
      const norm = normalizeIocValue(item.ip, "ip");
      if (norm) {
        entries.push({ norm, feed: "blocklistde", label: (item.lists || []).join(", ") || "blocklist", seenAt: blFetchedAt, item });
      }
    }

    return entries;
  }

  // A correlated IOC's "signal count" combines raw multi-feed overlap with
  // enrichment corroboration, so a single-feed IP independently confirmed
  // by e.g. AbuseIPDB + Spamhaus DROP ranks alongside one seen in 2 feeds,
  // rather than requiring 2+ raw feeds to appear in this panel at all.
  function computeSignalCount(type, value, feedsSeen) {
    let count = 0;
    const breakdown = [];

    if (feedsSeen.length >= 2) {
      count += 1;
      breakdown.push("2+ feeds");
    }

    if (type === "ip") {
      if (state.enrichment?.lookups?.[value]?.classification === "malicious") {
        count += 1;
        breakdown.push("GreyNoise malicious");
      }
      const abuse = state.abuseipdb?.entries?.[value];
      if (abuse && abuse.abuseConfidenceScore >= 75) {
        count += 1;
        breakdown.push("AbuseIPDB ≥ 75");
      }
      if (isIpInDrop(value)) {
        count += 1;
        breakdown.push("Spamhaus DROP");
      }
      const idb = state.internetdb?.entries?.[value];
      if (idb && (idb.vulns || []).length > 0) {
        count += 1;
        breakdown.push("InternetDB CVE");
      }
    }

    return { count, breakdown };
  }

  function buildCorrelation() {
    const feeds = state.snapshot.feeds || {};
    const entries = extractCorrelationEntries(feeds);
    const map = new Map();

    for (const e of entries) {
      const key = `${e.norm.type}|${e.norm.value}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(e);
    }

    // The full index (every IOC, not just those with a signal) backs the
    // IOC drawer.
    state.iocIndex = map;

    const correlated = [];
    for (const list of map.values()) {
      const feedsSeen = Array.from(new Set(list.map((e) => e.feed)));
      const { type, value } = list[0].norm;
      const { count, breakdown } = computeSignalCount(type, value, feedsSeen);
      if (count < 1) continue;
      const mostRecent = list.reduce((latest, e) => {
        const t = e.seenAt ? new Date(e.seenAt).getTime() : 0;
        return !isNaN(t) && t > latest ? t : latest;
      }, 0);
      correlated.push({
        type,
        value,
        feeds: feedsSeen,
        labels: Array.from(new Set(list.map((e) => e.label).filter(Boolean))),
        mostRecent,
        signalCount: count,
        signalBreakdown: breakdown,
      });
    }

    correlated.sort((a, b) => {
      if (b.signalCount !== a.signalCount) return b.signalCount - a.signalCount;
      return b.mostRecent - a.mostRecent;
    });

    state.correlated = correlated;
  }

  // The correlated list as shown and exported: all of it, or just the new
  // IOCs when the "new only" filter is on.
  function correlatedRows() {
    const list = state.correlated || [];
    if (!isNewOnly("correlated")) return list;
    const newSet = state.since.newSets.ioc;
    return list.filter((c) => newSet.has(iocSeenKey(c)));
  }

  function renderCorrelated() {
    const tbody = $("correlated-tbody");
    const emptyNote = $("correlated-empty");
    const table = $("table-correlated");
    const list = state.correlated || [];
    syncNewOnlyToggle("correlated");

    if (!list.length) {
      table.querySelector("thead").innerHTML = "";
      tbody.innerHTML = "";
      emptyNote.hidden = false;
      return;
    }
    emptyNote.hidden = true;

    table.querySelector("thead").innerHTML =
      "<tr><th>IOC</th><th>Feeds</th><th>Signals</th><th>Malware / Threat</th><th>Most Recent</th></tr>";

    const newSet = state.since.newSets.ioc;
    const rows = correlatedRows().slice(0, 300);
    tbody.innerHTML = rows
      .map((c) => {
        const feedTags = c.feeds.map((f) => `<span class="tag feed-tag">${escapeHtml(FEED_LABELS[f] || f)}</span>`).join("");
        const signalBadge = `<span class="badge badge-info" title="${escapeHtml(c.signalBreakdown.join(", "))}">${c.signalCount} signal${c.signalCount === 1 ? "" : "s"}</span>`;
        const labels = c.labels.slice(0, 3).map((l) => escapeHtml(l)).join(", ");
        const recent = c.mostRecent ? fmtDate(new Date(c.mostRecent).toISOString()) : "&mdash;";
        const isNew = newSet.has(iocSeenKey(c));
        return `<tr class="correlated-row${isNew ? " is-new" : ""}" ${iocAttrs(c.type, c.value)}>
          <td>${iocButton(c)}<span class="mono">${escapeHtml(c.value)}</span>${isNew ? NEW_BADGE : ""}</td>
          <td>${feedTags || "&mdash;"}</td>
          <td>${signalBadge}</td>
          <td>${labels || "&mdash;"}</td>
          <td>${recent}</td>
        </tr>`;
      })
      .join("");
    // Row clicks open the IOC drawer via the delegated handler in initIocDrawer.
  }

  // scrollTarget: what to bring into view (default: the whole section).
  function scrollToMatch(feed, value, scrollTarget) {
    const input = document.querySelector(`.search-box[data-feed="${feed}"]`);
    const section = $(`section-${feed}`);
    if (!input || !section) return;
    input.value = value;
    if (!state.tableState[feed]) state.tableState[feed] = { sortKey: null, sortDir: "asc", query: "" };
    state.tableState[feed].query = value;
    // The match may not be a new or watched row; don't let those filters hide it.
    state.since.newOnly[feed] = false;
    if (feed === "cisa_kev") state.kevWatch.watchedOnly = false;
    renderFeed(feed);
    activateTab(section.id, true);
    (scrollTarget || section).scrollIntoView({ behavior: "smooth", block: "start" });
    section.classList.add("flash-highlight");
    setTimeout(() => section.classList.remove("flash-highlight"), 1500);
  }

  // ---------- IOC detail drawer ----------
  //
  // Everything the page already knows about one IOC, looked up from
  // state.iocIndex (built once per render() in buildCorrelation) plus the
  // enrichment maps. Triggers are any element carrying data-ioc-type /
  // data-ioc-value; one delegated click handler (initIocDrawer) opens it.
  // Lookup links are plain outbound links — the page never fetches them.

  const DRAWER_FEED_ORDER = ["threatfox", "urlhaus", "malwarebazaar", "otx", "blocklistde"];
  const DRAWER_MAX_HITS = 25;
  const IOC_TYPE_LABELS = { ip: "IPv4 address", domain: "Domain", hash: "File hash" };

  function iocAttrs(type, value) {
    return `data-ioc-type="${escapeHtml(type)}" data-ioc-value="${escapeHtml(value)}"`;
  }

  function iocButton(norm) {
    if (!norm) return "";
    return `<button type="button" class="ioc-open" ${iocAttrs(norm.type, norm.value)} title="Show IOC details" aria-label="Show details for ${escapeHtml(norm.value)}">i</button>`;
  }

  // Still worth showing (or keeping open across a refresh) when it's in a
  // feed, or for an IP that only the enrichment sources know about.
  function iocKnown(type, value) {
    if (state.iocIndex.has(`${type}|${value}`)) return true;
    if (type !== "ip") return false;
    return Boolean(state.enrichment?.lookups?.[value] || state.abuseipdb?.entries?.[value] || state.internetdb?.entries?.[value]);
  }

  // rows: [label, html] — html must already be escaped; empty values are skipped.
  function drawerFields(rows) {
    const html = rows
      .filter(([, v]) => v !== "" && v !== null && v !== undefined)
      .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`)
      .join("");
    return html ? `<dl class="drawer-fields">${html}</dl>` : "";
  }

  function drawerTags(list) {
    // Feed data can change shape; a lone string is one tag, anything else none.
    const arr = Array.isArray(list) ? list : typeof list === "string" && list ? [list] : [];
    return arr
      .filter((t) => t !== null && t !== undefined && t !== "")
      .map((t) => `<span class="tag">${escapeHtml(t)}</span>`)
      .join("");
  }

  function drawerDate(iso) {
    return iso ? fmtDate(iso) : "";
  }

  function extLink(href, text) {
    return `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`;
  }

  function drawerShowButton(feed, query, text) {
    return `<button type="button" class="drawer-show" data-drawer-feed="${escapeHtml(feed)}" data-drawer-q="${escapeHtml(query)}">${escapeHtml(text)}</button>`;
  }

  const DRAWER_HIT_RENDERERS = {
    threatfox: (e) => {
      const i = e.item;
      return drawerFields([
        ["IOC", `<span class="mono">${escapeHtml(i.ioc)}</span>`],
        ["Type", escapeHtml(i.ioc_type)],
        ["Malware", escapeHtml(i.malware_printable)],
        ["Confidence", escapeHtml(i.confidence_level)],
        ["First seen", drawerDate(i.first_seen)],
        ["Tags", drawerTags(i.tags)],
        ["Reporter", escapeHtml(i.reporter)],
        ["Record", i.id ? extLink(`https://threatfox.abuse.ch/ioc/${encodeURIComponent(i.id)}/`, "ThreatFox IOC record") : ""],
      ]);
    },
    urlhaus: (e) => {
      const i = e.item;
      const href = urlhausLink(i);
      const tags = i.tags && i.tags !== "None" ? escapeHtml(i.tags) : "";
      return drawerFields([
        // Shown as text: linking straight to a live malware URL is a footgun.
        ["URL", `<span class="mono">${escapeHtml(i.url)}</span>`],
        ["Status", escapeHtml(i.url_status)],
        ["Threat", escapeHtml(i.threat)],
        ["Date added", drawerDate(i.date_added)],
        ["Last online", drawerDate(i.last_online)],
        ["Tags", tags],
        ["Reporter", escapeHtml(i.reporter)],
        ["Record", href ? extLink(href, "URLhaus URL record") : ""],
      ]);
    },
    malwarebazaar: (e) => {
      const i = e.item;
      return drawerFields([
        ["File name", escapeHtml(i.file_name)],
        ["SHA256", `<span class="mono">${escapeHtml(i.sha256_hash)}</span>`],
        ["Family", escapeHtml(i.signature)],
        ["First seen", drawerDate(i.first_seen)],
        ["Last seen", drawerDate(i.last_seen)],
        ["Tags", drawerTags(i.tags)],
      ]);
    },
    otx: (e) => {
      const i = e.item;
      return (
        drawerFields([
          ["Pulse", escapeHtml(i.name)],
          ["Created", drawerDate(i.created)],
          ["Indicator", `<span class="mono">${escapeHtml(e.indicator?.indicator)}</span> <span class="drawer-dim">${escapeHtml(e.indicator?.type)}</span>`],
          ["Pulse tags", drawerTags((i.tags || []).slice(0, 10))],
        ]) + drawerShowButton("otx", i.name || "", "Show pulse in OTX table")
      );
    },
    blocklistde: (e) => drawerFields([["Lists", drawerTags(e.item.lists)]]),
  };

  function drawerFeedGroup(feed, hits, type, value) {
    const label = FEED_LABELS[feed] || feed;
    let list = hits;
    if (feed === "otx") {
      // One block per pulse, even if it lists the IOC under two types.
      const seen = new Set();
      list = hits.filter((e) => {
        const k = e.item.name || "";
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
    }
    const shown = list.slice(0, DRAWER_MAX_HITS);
    const items = shown.map((e) => `<li class="drawer-hit">${DRAWER_HIT_RENDERERS[feed](e)}</li>`).join("");
    const more =
      list.length > shown.length ? `<p class="drawer-note">+ ${list.length - shown.length} more ${escapeHtml(label)} entries not shown.</p>` : "";
    // The OTX table only searches pulse name/tags, so its buttons live on each pulse instead.
    const query = type === "hash" ? value.toLowerCase() : value;
    const headBtn = feed === "otx" ? "" : drawerShowButton(feed, query, `Show in ${label} table`);
    return `<section class="drawer-section">
      <div class="drawer-section-head"><h3>${escapeHtml(label)} <span class="drawer-count">${list.length}</span></h3>${headBtn}</div>
      <ul class="drawer-hits">${items}</ul>${more}
    </section>`;
  }

  function greynoiseClassBadge(cls) {
    const c = cls || "unclassified";
    const badge = c === "malicious" ? "badge-malicious" : c === "benign" ? "badge-noise" : "badge-unclassified";
    return `<span class="badge ${badge}">${escapeHtml(c)}</span>`;
  }

  function drawerEnrichment(ip) {
    const blocks = [];

    const gn = state.enrichment?.lookups?.[ip];
    if (gn) {
      blocks.push([
        "GreyNoise",
        drawerFields([
          ["Classification", greynoiseClassBadge(gn.classification)],
          ["Internet scanner", gn.noise === undefined ? "" : gn.noise ? "yes" : "no"],
          ["Actor", gn.name && gn.name !== "unknown" ? escapeHtml(gn.name) : ""],
          ["Last seen", escapeHtml(gn.last_seen)],
          ["Checked", drawerDate(gn.checked_at)],
        ]),
      ]);
    }

    const abuse = state.abuseipdb?.entries?.[ip];
    if (abuse && abuse.abuseConfidenceScore !== undefined && abuse.abuseConfidenceScore !== null) {
      blocks.push([
        "AbuseIPDB",
        drawerFields([
          ["Confidence", abuseipdbBadge(ip).trim()],
          ["Reports", escapeHtml(abuse.totalReports ?? 0)],
          ["ISP", escapeHtml(abuse.isp)],
        ]),
      ]);
    }

    const idb = state.internetdb?.entries?.[ip];
    if (idb && !idb.no_data) {
      const fields = drawerFields([
        ["Ports", drawerTags(idb.ports)],
        ["CVEs", drawerTags(idb.vulns)],
        ["Hostnames", drawerTags(idb.hostnames)],
        ["Tags", drawerTags(idb.tags)],
      ]);
      if (fields) blocks.push(["InternetDB", fields]);
    }

    const drop = isIpInDrop(ip);
    if (drop) {
      blocks.push([
        "Spamhaus DROP",
        drawerFields([
          ["Range", `<span class="mono">${escapeHtml(drop.raw)}</span>`],
          ["SBL id", escapeHtml(drop.sbl_id)],
        ]),
      ]);
    }

    if (!blocks.length) return "";
    return `<section class="drawer-section">
      <div class="drawer-section-head"><h3>Enrichment</h3></div>
      ${blocks.map(([title, html]) => `<div class="drawer-enrich"><h4>${escapeHtml(title)}</h4>${html}</div>`).join("")}
    </section>`;
  }

  function drawerLookupLinks(type, value) {
    const v = encodeURIComponent(type === "hash" ? value.toLowerCase() : value);
    const links = [];
    if (type === "ip") {
      links.push(
        ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${v}`],
        ["Shodan", `https://www.shodan.io/host/${v}`],
        ["AbuseIPDB", `https://www.abuseipdb.com/check/${v}`],
        ["GreyNoise", `https://viz.greynoise.io/ip/${v}`]
      );
    } else if (type === "domain") {
      links.push(["VirusTotal", `https://www.virustotal.com/gui/domain/${v}`]);
    } else if (type === "hash") {
      links.push(["VirusTotal", `https://www.virustotal.com/gui/file/${v}`]);
      const algo = { 32: "md5", 40: "sha1", 64: "sha256" }[value.length];
      if (algo === "sha256") links.push(["MalwareBazaar", `https://bazaar.abuse.ch/sample/${v}/`]);
      else if (algo) links.push(["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=${encodeURIComponent(`${algo}:`)}${v}`]);
    }
    links.push(["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=${encodeURIComponent("ioc:")}${v}`]);
    if (type === "ip" || type === "domain") links.push(["URLhaus host", `https://urlhaus.abuse.ch/host/${v}/`]);
    if (type === "ip") {
      const drop = isIpInDrop(value);
      if (drop && drop.sbl_id) {
        links.push([`Spamhaus ${drop.sbl_id}`, `https://check.spamhaus.org/results?query=${encodeURIComponent(drop.sbl_id)}`]);
      }
    }
    return `<section class="drawer-section">
      <div class="drawer-section-head"><h3>Look up</h3></div>
      <p class="drawer-note">Opens the provider's site in a new tab. This page makes no requests to them.</p>
      <ul class="drawer-links">${links.map(([text, href]) => `<li>${extLink(href, text)}</li>`).join("")}</ul>
    </section>`;
  }

  function renderIocDrawer() {
    const d = state.drawer;
    if (!d) return;
    const { type, value } = d;
    const hits = state.iocIndex.get(`${type}|${value}`) || [];
    const feedsSeen = DRAWER_FEED_ORDER.filter((f) => hits.some((e) => e.feed === f));
    const { count, breakdown } = computeSignalCount(type, value, feedsSeen);

    $("ioc-drawer-type").textContent = IOC_TYPE_LABELS[type] || type;
    $("ioc-drawer-title").textContent = value;

    const signalCls = count >= 2 ? "badge-malicious" : count === 1 ? "badge-unclassified" : "badge-info";
    const summary = drawerFields([
      ["Signals", `<span class="badge ${signalCls}">${count} signal${count === 1 ? "" : "s"}</span>`],
      ["Breakdown", breakdown.length ? drawerTags(breakdown) : `<span class="drawer-dim">no corroborating signals</span>`],
      [
        "Feeds",
        feedsSeen.length
          ? feedsSeen.map((f) => `<span class="tag feed-tag">${escapeHtml(FEED_LABELS[f] || f)}</span>`).join("")
          : `<span class="drawer-dim">not in any current feed</span>`,
      ],
    ]);

    const groups = feedsSeen.map((f) => drawerFeedGroup(f, hits.filter((e) => e.feed === f), type, value)).join("");

    $("ioc-drawer-body").innerHTML =
      `<section class="drawer-section drawer-summary">${summary}</section>` +
      groups +
      (type === "ip" ? drawerEnrichment(value) : "") +
      drawerLookupLinks(type, value);
  }

  function setBackgroundInert(on) {
    document.querySelectorAll(".topbar, main.page").forEach((el) => {
      el.inert = on;
      if (on) el.setAttribute("aria-hidden", "true");
      else el.removeAttribute("aria-hidden");
    });
    document.body.classList.toggle("drawer-open", on);
  }

  // fromLink: opened from the URL fragment, so there's no trigger to return focus to.
  function openIocDrawer(type, value, trigger, fromLink = false) {
    const drawer = $("ioc-drawer");
    if (!drawer || !type || !value) return;
    // A correlated row isn't focusable itself; return focus to its button.
    const focusEl = trigger && (trigger.matches("button, a") ? trigger : trigger.querySelector("button"));
    state.drawer = { type, value, trigger: focusEl || null, scope: trigger?.closest("[id]")?.id || null, fromLink };
    try {
      renderIocDrawer();
    } catch (e) {
      // Don't leave state.drawer set on a drawer that never opened: the
      // click handler ignores clicks while it's set, so nothing would open.
      state.drawer = null;
      console.error("IOC drawer failed to render:", e);
      return;
    }
    $("ioc-drawer-body").scrollTop = 0;
    resetCopyUi("drawer");
    drawer.hidden = false;
    $("ioc-drawer-backdrop").hidden = false;
    setBackgroundInert(true);
    $("ioc-drawer-close").focus();
    scheduleHashSync();
  }

  function closeIocDrawer(restoreFocus = true) {
    const d = state.drawer;
    if (!d) return;
    state.drawer = null;
    $("ioc-drawer").hidden = true;
    $("ioc-drawer-backdrop").hidden = true;
    setBackgroundInert(false);
    scheduleHashSync();
    if (!restoreFocus) return;
    if (d.fromLink) {
      // Nothing on the page opened it; land on the active tab instead of <body>.
      document.querySelector('.deck-tab[aria-selected="true"]')?.focus({ preventScroll: true });
      return;
    }
    let target = d.trigger && d.trigger.isConnected ? d.trigger : null;
    if (!target && d.scope && window.CSS?.escape) {
      // The trigger was re-rendered (auto-refresh); find its replacement.
      target = $(d.scope)?.querySelector(
        `button[data-ioc-type="${CSS.escape(d.type)}"][data-ioc-value="${CSS.escape(d.value)}"]`
      );
    }
    if (target) target.focus();
  }

  // Called at the end of render(): keep an open drawer in step with new data.
  function refreshIocDrawer() {
    const d = state.drawer;
    if (!d) return;
    if (!iocKnown(d.type, d.value)) {
      closeIocDrawer();
      return;
    }
    const body = $("ioc-drawer-body");
    const scrollTop = body.scrollTop;
    const hadFocus = $("ioc-drawer").contains(document.activeElement) && document.activeElement !== $("ioc-drawer-close");
    try {
      renderIocDrawer();
    } catch (e) {
      console.error("IOC drawer failed to refresh:", e);
      closeIocDrawer();
      return;
    }
    body.scrollTop = scrollTop;
    // The focused element may have been replaced by the re-render.
    if (hadFocus && !$("ioc-drawer").contains(document.activeElement)) $("ioc-drawer-close").focus();
  }

  function drawerFocusables() {
    return Array.from($("ioc-drawer").querySelectorAll("button, a[href], input")).filter((el) => !el.disabled && el.offsetParent !== null);
  }

  function initIocDrawer() {
    const drawer = $("ioc-drawer");
    if (!drawer) return;

    document.addEventListener("click", (ev) => {
      if (state.drawer) return;
      const trigger = ev.target.closest("[data-ioc-type][data-ioc-value]");
      if (!trigger || ev.target.closest("a")) return; // leave outbound links alone
      ev.preventDefault();
      openIocDrawer(trigger.getAttribute("data-ioc-type"), trigger.getAttribute("data-ioc-value"), trigger);
    });

    $("ioc-drawer-close").addEventListener("click", () => closeIocDrawer());
    $("ioc-drawer-backdrop").addEventListener("click", () => closeIocDrawer());

    $("ioc-drawer-body").addEventListener("click", (ev) => {
      const btn = ev.target.closest(".drawer-show");
      if (!btn) return;
      const feed = btn.getAttribute("data-drawer-feed");
      closeIocDrawer(false);
      scrollToMatch(feed, btn.getAttribute("data-drawer-q"));
      const input = document.querySelector(`.search-box[data-feed="${feed}"]`);
      if (input) input.focus({ preventScroll: true });
    });

    document.addEventListener("keydown", (ev) => {
      if (!state.drawer) return;
      if (ev.key === "Escape") {
        ev.preventDefault();
        closeIocDrawer();
        return;
      }
      // Belt and braces alongside `inert`: keep Tab inside the dialog.
      if (ev.key === "Tab") {
        const els = drawerFocusables();
        if (!els.length) return;
        const first = els[0];
        const last = els[els.length - 1];
        if (ev.shiftKey && (document.activeElement === first || !drawer.contains(document.activeElement))) {
          last.focus();
          ev.preventDefault();
        } else if (!ev.shiftKey && (document.activeElement === last || !drawer.contains(document.activeElement))) {
          first.focus();
          ev.preventDefault();
        }
      }
    });
  }

  // ---------- Triage / digest panel ----------

  function findFeedsContainingIp(ip) {
    const feeds = state.snapshot.feeds || {};
    const found = new Set();
    for (const item of feeds.threatfox?.items || []) {
      if (normalizeIp(item.ioc) === ip) found.add("threatfox");
    }
    for (const item of feeds.blocklistde?.items || []) {
      if (item.ip === ip) found.add("blocklistde");
    }
    for (const item of feeds.urlhaus?.items || []) {
      if (normalizeIp(extractHost(item.url)) === ip) found.add("urlhaus");
    }
    return Array.from(found);
  }

  function buildTriage() {
    const feeds = state.snapshot.feeds || {};

    const kevItems = feeds.cisa_kev?.items || [];
    const ransomwareKev = kevItems
      .filter((v) => v.known_ransomware_campaign_use === "Known")
      .slice()
      .sort((a, b) => String(b.date_added ?? "").localeCompare(String(a.date_added ?? "")))
      .slice(0, 5);

    const epssCriticalKev = kevItems
      .filter((v) => v.known_ransomware_campaign_use === "Known")
      .map((v) => ({ item: v, epss: epssFor(v.cve_id) }))
      .filter((x) => x.epss && x.epss.percentile >= 0.9)
      .sort((a, b) => b.epss.percentile - a.epss.percentile)
      .slice(0, 5);

    const lookups = state.enrichment?.lookups || {};
    const maliciousIps = Object.entries(lookups)
      .filter(([, v]) => v.classification === "malicious")
      .sort((a, b) => (b[1].checked_at || "").localeCompare(a[1].checked_at || ""))
      .slice(0, 5)
      .map(([ip, v]) => ({ ip, checkedAt: v.checked_at, feeds: findFeedsContainingIp(ip) }));

    const topCorrelated = (state.correlated || []).slice(0, 5);

    state.triage = { ransomwareKev, epssCriticalKev, maliciousIps, topCorrelated };
  }

  function renderTriage() {
    const panel = $("triage-panel");
    const t = state.triage;
    const watched = state.kevWatch.matches;
    const hasAny =
      watched.length || t.ransomwareKev.length || t.epssCriticalKev.length || t.maliciousIps.length || t.topCorrelated.length;
    panel.hidden = !hasAny;
    if (!hasAny) return;

    const vendorCard = $("triage-vendors").closest(".triage-card");
    vendorCard.hidden = !watched.length;
    $("triage-vendors-count").textContent = watched.length ? `(${watched.length.toLocaleString()})` : "";
    $("triage-vendors").innerHTML = watched
      .slice(0, 5)
      .map(
        (v) =>
          `<li>${kevWatchLink(v)} — ${escapeHtml(v.vendor_project)} / ${escapeHtml(v.product)}<span class="triage-date">${escapeHtml(v.date_added)}</span></li>`
      )
      .join("");

    const kevCard = $("triage-kev").closest(".triage-card");
    kevCard.hidden = !t.ransomwareKev.length;
    $("triage-kev").innerHTML = t.ransomwareKev
      .map(
        (v) =>
          `<li><a href="#section-cisa_kev" class="triage-link" data-feed="cisa_kev" data-q="${escapeHtml(v.cve_id)}">${escapeHtml(v.cve_id)}</a> — ${escapeHtml(v.vendor_project)} / ${escapeHtml(v.product)}<span class="triage-date">${escapeHtml(v.date_added)}</span></li>`
      )
      .join("");

    const epssCard = $("triage-epss-critical").closest(".triage-card");
    epssCard.hidden = !t.epssCriticalKev.length;
    $("triage-epss-critical").innerHTML = t.epssCriticalKev
      .map(
        (x) =>
          `<li><a href="#section-cisa_kev" class="triage-link" data-feed="cisa_kev" data-q="${escapeHtml(x.item.cve_id)}">${escapeHtml(x.item.cve_id)}</a> — ${escapeHtml(x.item.vendor_project)} / ${escapeHtml(x.item.product)}<span class="triage-date">${(x.epss.percentile * 100).toFixed(1)}th pct</span></li>`
      )
      .join("");

    const maliciousCard = $("triage-malicious").closest(".triage-card");
    maliciousCard.hidden = !t.maliciousIps.length;
    $("triage-malicious").innerHTML = t.maliciousIps
      .map((m) => {
        const tags = m.feeds.map((f) => `<span class="tag feed-tag">${escapeHtml(FEED_LABELS[f] || f)}</span>`).join("");
        return `<li><button type="button" class="triage-link link-btn" ${iocAttrs("ip", m.ip)}><span class="mono">${escapeHtml(m.ip)}</span></button> ${tags}<span class="triage-date">${relativeTime(m.checkedAt)}</span></li>`;
      })
      .join("");

    const correlatedCard = $("triage-correlated").closest(".triage-card");
    correlatedCard.hidden = !t.topCorrelated.length;
    $("triage-correlated").innerHTML = t.topCorrelated
      .map((c) => {
        const tags = c.feeds.map((f) => `<span class="tag feed-tag">${escapeHtml(FEED_LABELS[f] || f)}</span>`).join("");
        return `<li><button type="button" class="triage-link link-btn" ${iocAttrs(c.type, c.value)}><span class="mono">${escapeHtml(c.value)}</span></button> ${tags}</li>`;
      })
      .join("");

    // KEV links scroll to the KEV table; IOC buttons open the drawer via
    // the delegated handler in initIocDrawer.
    panel.querySelectorAll("a.triage-link[data-feed]").forEach((a) => {
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        scrollToMatch(a.getAttribute("data-feed"), a.getAttribute("data-q"));
      });
    });
  }

  // ---------- Watchlist ----------

  const WATCHLIST_KEY = "threatDashboardWatchlist";

  function loadWatchlist() {
    try {
      return localStorage.getItem(WATCHLIST_KEY) || "";
    } catch (e) {
      return "";
    }
  }

  function saveWatchlist(text) {
    try {
      localStorage.setItem(WATCHLIST_KEY, text);
    } catch (e) {
      /* ignore — watchlist just won't persist this session */
    }
  }

  function ipToInt(ip) {
    return ip.split(".").reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
  }

  function parseCidr(cidrStr) {
    const parts = cidrStr.split("/");
    if (parts.length !== 2) return null;
    const [base, bitsStr] = parts;
    const bits = Number(bitsStr);
    if (!isIpv4(base) || isNaN(bits) || bits < 0 || bits > 32) return null;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return { network: ipToInt(base) & mask, mask };
  }

  function ipInCidr(ip, cidr) {
    if (!isIpv4(ip)) return false;
    return (ipToInt(ip) & cidr.mask) === cidr.network;
  }

  function parseWatchlist(text) {
    const lines = (text || "")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    const entries = [];
    for (const line of lines) {
      if (line.includes("/")) {
        const cidr = parseCidr(line);
        if (cidr) entries.push({ type: "cidr", ...cidr });
        continue;
      }
      if (isIpv4(line)) {
        entries.push({ type: "ip", ip: line });
        continue;
      }
      const domain = normalizeDomain(line);
      if (domain) entries.push({ type: "domain", domain });
    }
    return entries;
  }

  function watchlistMatchesIp(ip, entries) {
    return entries.some((e) => (e.type === "ip" ? e.ip === ip : e.type === "cidr" ? ipInCidr(ip, e) : false));
  }

  function watchlistMatchesDomain(domain, entries) {
    return entries.some((e) => e.type === "domain" && e.domain === domain);
  }

  function buildWatchlistMatches() {
    const entries = parseWatchlist(state.watchlistText);
    const matches = [];
    const matchKeys = new Set();

    if (!entries.length) {
      state.watchlistMatches = matches;
      state.watchlistMatchKeys = matchKeys;
      return;
    }

    const feeds = state.snapshot.feeds || {};

    for (const item of feeds.threatfox?.items || []) {
      const t = (item.ioc_type || "").toLowerCase();
      if (t.includes("ip")) {
        const ip = normalizeIp(item.ioc);
        if (ip && watchlistMatchesIp(ip, entries)) {
          matches.push({ feed: "threatfox", value: item.ioc, label: item.malware_printable, norm: { type: "ip", value: ip } });
          matchKeys.add(`threatfox::${item.ioc}`);
        }
      } else if (t.includes("domain")) {
        const d = normalizeDomain(item.ioc);
        if (d && watchlistMatchesDomain(d, entries)) {
          matches.push({ feed: "threatfox", value: item.ioc, label: item.malware_printable, norm: { type: "domain", value: d } });
          matchKeys.add(`threatfox::${item.ioc}`);
        }
      }
    }

    for (const item of feeds.urlhaus?.items || []) {
      const host = extractHost(item.url);
      const ip = normalizeIp(host);
      if (ip && watchlistMatchesIp(ip, entries)) {
        matches.push({ feed: "urlhaus", value: item.url, label: item.threat, norm: { type: "ip", value: ip } });
        matchKeys.add(`urlhaus::${item.url}`);
      } else {
        const d = normalizeDomain(host);
        if (d && watchlistMatchesDomain(d, entries)) {
          matches.push({ feed: "urlhaus", value: item.url, label: item.threat, norm: { type: "domain", value: d } });
          matchKeys.add(`urlhaus::${item.url}`);
        }
      }
    }

    for (const item of feeds.blocklistde?.items || []) {
      if (item.ip && watchlistMatchesIp(item.ip, entries)) {
        matches.push({ feed: "blocklistde", value: item.ip, label: (item.lists || []).join(", "), norm: normalizeIocValue(item.ip, "ip") });
        matchKeys.add(`blocklistde::${item.ip}`);
      }
    }

    // OTX indicators aren't rendered as individual table rows (one row per
    // pulse), so matches surface in the panel below but don't drive a
    // per-row highlight the way the other feeds' rowKey does.
    for (const item of feeds.otx?.items || []) {
      for (const ind of item.indicators || []) {
        const type = (ind.type || "").toLowerCase();
        if (type.includes("ipv4")) {
          const ip = normalizeIp(ind.indicator);
          if (ip && watchlistMatchesIp(ip, entries)) {
            matches.push({ feed: "otx", value: ind.indicator, label: item.name, norm: { type: "ip", value: ip } });
          }
        } else if (type.includes("domain") || type.includes("hostname")) {
          const d = normalizeDomain(ind.indicator);
          if (d && watchlistMatchesDomain(d, entries)) {
            matches.push({ feed: "otx", value: ind.indicator, label: item.name, norm: { type: "domain", value: d } });
          }
        }
      }
    }

    state.watchlistMatches = matches;
    state.watchlistMatchKeys = matchKeys;
  }

  function renderWatchlistPanel() {
    const card = $("watchlist-matches-card");
    const list = $("watchlist-matches-list");
    const matches = state.watchlistMatches || [];
    const total = matches.length + state.kevWatch.matches.length;
    $("tabcount-watchlist").textContent = total ? String(total) : "";
    renderKevWatchList();
    card.hidden = !total;
    list.hidden = !matches.length;
    list.innerHTML = matches
      .slice(0, 30)
      .map(
        (m) =>
          `<li><span class="tag feed-tag">${escapeHtml(FEED_LABELS[m.feed] || m.feed)}</span> ${iocButton(m.norm)}<span class="mono">${escapeHtml(m.value)}</span>${m.label ? ` — ${escapeHtml(m.label)}` : ""}</li>`
      )
      .join("");
  }

  function initWatchlist() {
    const textarea = $("watchlist-input");
    state.watchlistText = loadWatchlist();
    textarea.value = state.watchlistText;

    let debounceTimer = null;
    textarea.addEventListener("input", () => {
      state.watchlistText = textarea.value;
      saveWatchlist(textarea.value);
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        buildWatchlistMatches();
        renderWatchlistPanel();
        Object.keys(FEED_DEFS).forEach(renderFeed);
      }, 300);
    });
  }

  // ---------- KEV vendor / product watchlist ----------
  //
  // A second list on the Watchlist tab: vendor or product names, one per
  // line, matched against CISA KEV's vendor_project / product. Stored as
  // plain text (like the IOC list) under VENDOR_WATCH_KEY.
  //
  // Matching rules (both the term and the KEV fields go through
  // normVendorText first: case, accents and runs of whitespace are ignored):
  //   - A plain term matches whole words in "vendor product", so "Fortinet",
  //     "Exchange" (-> "Exchange Server") and "Microsoft Windows" (vendor
  //     Microsoft + product Windows...) all work. A "word" edge is anything
  //     that isn't a letter or digit, so "SAP" doesn't match inside
  //     "Sapido", but "Link" does match "D-Link" and ".NET" doesn't match
  //     "ASP.NET".
  //   - "Vendor / Product" (a slash with a space on at least one side, so
  //     "TCP/IP" or "Erlang/OTP" stay single terms) requires the vendor part
  //     in vendor_project and the product part in product. Leaving one side
  //     empty ("/ Exchange") checks only the other field.
  // Terms are regex-escaped and compiled once per edit (compileVendorWatch);
  // per-row haystacks are cached per KEV item object.

  const VENDOR_WATCH_KEY = "threatDashboardKevVendors";
  const VENDOR_WATCH_MAX_TERMS = 200;
  const VENDOR_WATCH_MAX_TERM_LEN = 120;
  const VENDOR_WATCH_PANEL_MAX = 50;
  const VENDOR_CHIPS = 8;
  const VENDOR_PAIR_SEP = /\s+\/\s*|\s*\/\s+/;
  const vendorHayCache = new WeakMap(); // KEV item -> { v, p, vp }

  function loadVendorWatch() {
    try {
      const raw = localStorage.getItem(VENDOR_WATCH_KEY);
      return typeof raw === "string" ? raw : "";
    } catch (e) {
      return "";
    }
  }

  function saveVendorWatch(text) {
    try {
      localStorage.setItem(VENDOR_WATCH_KEY, text);
    } catch (e) {
      /* ignore — the list just won't persist this session */
    }
  }

  function normVendorText(s) {
    return String(s ?? "")
      .normalize("NFKD")
      .replace(/[̀-ͯ]/g, "") // combining accents, left after NFKD
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();
  }

  // Lookbehind needs Safari / iOS 16.4+. Older engines throw a SyntaxError
  // on the pattern, so detect once and use an equivalent that consumes the
  // preceding character instead (fine, since we only ever call .test()).
  const HAS_LOOKBEHIND = (() => {
    try {
      new RegExp("(?<!a)b", "u");
      return true;
    } catch (e) {
      return false;
    }
  })();

  // Whole-word matcher for an already-normalized term, or null if empty or
  // it can't be compiled (callers then skip the term rather than match all).
  function vendorWordRe(term) {
    if (!term) return null;
    const esc = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const before = HAS_LOOKBEHIND ? "(?<![\\p{L}\\p{N}])" : "(?:^|[^\\p{L}\\p{N}])";
    try {
      return new RegExp(`${before}${esc}(?![\\p{L}\\p{N}])`, "u");
    } catch (e) {
      return null;
    }
  }

  // Returns { terms, skipped }: skipped counts lines that were too long,
  // past the term cap, or couldn't be compiled, so the UI can say so.
  function compileVendorWatch(text) {
    const seen = new Set();
    const terms = [];
    let skipped = 0;
    for (const rawLine of String(text || "").split("\n")) {
      const line = rawLine.trim();
      if (!line) continue;
      if (line.length > VENDOR_WATCH_MAX_TERM_LEN || terms.length >= VENDOR_WATCH_MAX_TERMS) {
        skipped++;
        continue;
      }
      const parts = line.split(VENDOR_PAIR_SEP);
      let term;
      if (parts.length === 2) {
        const v = normVendorText(parts[0]);
        const p = normVendorText(parts[1]);
        if (!v && !p) continue;
        term = { label: line, key: `${v}/${p}`, v, p, vendor: vendorWordRe(v), product: vendorWordRe(p), any: null };
        // A part that's present but didn't compile must not turn into "match anything".
        if ((v && !term.vendor) || (p && !term.product)) {
          skipped++;
          continue;
        }
      } else {
        const n = normVendorText(line);
        if (!n) continue;
        term = { label: line, key: n, n, vendor: null, product: null, any: vendorWordRe(n) };
        if (!term.any) {
          skipped++;
          continue;
        }
      }
      if (seen.has(term.key)) continue;
      seen.add(term.key);
      terms.push(term);
    }
    return { terms, skipped };
  }

  function vendorHay(item) {
    let h = vendorHayCache.get(item);
    if (!h) {
      const v = normVendorText(item.vendor_project);
      const p = normVendorText(item.product);
      h = { v, p, vp: `${v} ${p}` };
      vendorHayCache.set(item, h);
    }
    return h;
  }

  // The substring checks skip the (much slower) word-boundary regex for the
  // vast majority of rows that can't match.
  function vendorTermMatches(t, h) {
    if (t.any) return h.vp.includes(t.n) && t.any.test(h.vp);
    return (!t.vendor || (h.v.includes(t.v) && t.vendor.test(h.v))) && (!t.product || (h.p.includes(t.p) && t.product.test(h.p)));
  }

  function setVendorWatchText(text) {
    const w = state.kevWatch;
    if (text === w.text && w.terms) return;
    w.text = text;
    const { terms, skipped } = compileVendorWatch(text);
    w.terms = terms;
    w.skipped = skipped;
    const note = $("vendor-watch-skipped");
    if (note) {
      note.hidden = !skipped;
      note.textContent = skipped
        ? `${skipped} line${skipped === 1 ? "" : "s"} ignored: the list is limited to ${VENDOR_WATCH_MAX_TERMS} terms of up to ${VENDOR_WATCH_MAX_TERM_LEN} characters each.`
        : "";
    }
  }

  // Matches sorted most recently added first; ids drive the row highlight.
  function buildKevWatchMatches() {
    const w = state.kevWatch;
    const terms = w.terms || [];
    const matches = [];
    const termFor = new Map();
    if (terms.length && state.snapshot) {
      for (const item of state.snapshot.feeds?.cisa_kev?.items || []) {
        if (!item || !item.cve_id) continue;
        const h = vendorHay(item);
        const t = terms.find((x) => vendorTermMatches(x, h));
        if (!t) continue;
        matches.push(item);
        termFor.set(item.cve_id, t.label);
      }
      matches.sort(
        (a, b) => String(b.date_added ?? "").localeCompare(String(a.date_added ?? "")) || String(b.cve_id).localeCompare(String(a.cve_id))
      );
    }
    w.matches = matches;
    w.termFor = termFor;
  }

  function isKevWatched(item) {
    return state.kevWatch.termFor.has(item.cve_id);
  }

  function isWatchedOnly(table) {
    return table === "cisa_kev" && state.kevWatch.watchedOnly && state.kevWatch.matches.length > 0;
  }

  // The "watched only" checkbox only shows while there are matches.
  function syncWatchedOnlyToggle(table) {
    const input = document.querySelector(`.watched-only[data-feed="${table}"]`);
    if (!input) return;
    const n = table === "cisa_kev" ? state.kevWatch.matches.length : 0;
    const label = input.closest(".watched-only-toggle");
    label.hidden = n === 0;
    input.checked = isWatchedOnly(table);
    const count = label.querySelector(".watched-only-count");
    if (count) count.textContent = n ? `(${n.toLocaleString()})` : "";
  }

  function kevWatchLink(v) {
    return `<a href="#section-cisa_kev" class="triage-link" data-feed="cisa_kev" data-q="${escapeHtml(v.cve_id)}">${escapeHtml(v.cve_id)}</a>`;
  }

  // The KEV half of the Watchlist matches card (renderWatchlistPanel owns
  // the card and the tab count).
  function renderKevWatchList() {
    const block = $("watchlist-kev");
    const matches = state.kevWatch.matches;
    block.hidden = !matches.length;
    if (!matches.length) {
      $("watchlist-kev-list").innerHTML = "";
      return;
    }
    $("watchlist-kev-count").textContent = `(${matches.length.toLocaleString()})`;
    $("watchlist-kev-list").innerHTML = matches
      .slice(0, VENDOR_WATCH_PANEL_MAX)
      .map(
        (v) =>
          `<li>${kevWatchLink(v)} — ${escapeHtml(v.vendor_project)} / ${escapeHtml(v.product)}<span class="triage-date">${escapeHtml(v.date_added)}</span> <span class="watch-term" title="Matched watchlist term">${escapeHtml(state.kevWatch.termFor.get(v.cve_id))}</span></li>`
      )
      .join("");
    const more = $("watchlist-kev-more");
    more.hidden = matches.length <= VENDOR_WATCH_PANEL_MAX;
    more.innerHTML = more.hidden
      ? ""
      : `Showing the ${VENDOR_WATCH_PANEL_MAX} most recent of ${matches.length.toLocaleString()}. <button type="button" class="link-btn" id="watchlist-kev-all">View all in the KEV table</button>`;
  }

  // KEV tab with only the watched rows on screen.
  function showWatchedKev() {
    const section = $("section-cisa_kev");
    if (!section) return;
    const input = document.querySelector('.search-box[data-feed="cisa_kev"]');
    if (input) input.value = "";
    if (state.tableState.cisa_kev) state.tableState.cisa_kev.query = "";
    state.since.newOnly.cisa_kev = false;
    state.kevWatch.watchedOnly = true;
    renderFeed("cisa_kev");
    activateTab(section.id, true);
    section.scrollIntoView({ behavior: "smooth", block: "start" });
    section.classList.add("flash-highlight");
    setTimeout(() => section.classList.remove("flash-highlight"), 1500);
  }

  // Datalist of every KEV vendor (most entries first) plus a few one-click
  // chips for the most common ones not already on the list.
  function renderVendorSuggestions() {
    const counts = new Map(); // normalized -> { name, n }
    for (const item of state.snapshot?.feeds?.cisa_kev?.items || []) {
      const name = String(item?.vendor_project ?? "").trim();
      const key = normVendorText(name);
      if (!key) continue;
      const c = counts.get(key);
      if (c) c.n++;
      else counts.set(key, { name, n: 1 });
    }
    const ranked = Array.from(counts.values()).sort((a, b) => b.n - a.n || a.name.localeCompare(b.name));
    $("vendor-add-form").hidden = !ranked.length;
    $("vendor-suggestions").innerHTML = ranked.map((c) => `<option value="${escapeHtml(c.name)}"></option>`).join("");
    state.kevWatch.ranked = ranked;
    renderVendorChips();
  }

  function renderVendorChips() {
    const have = new Set((state.kevWatch.terms || []).map((t) => t.key));
    const chips = (state.kevWatch.ranked || []).filter((c) => !have.has(normVendorText(c.name))).slice(0, VENDOR_CHIPS);
    $("vendor-chips").innerHTML = chips.length
      ? `<span class="vendor-chips-label">Common:</span>` +
        chips
          .map(
            (c) =>
              `<button type="button" class="vendor-chip" data-vendor="${escapeHtml(c.name)}" title="${c.n.toLocaleString()} KEV entries">+ ${escapeHtml(c.name)}</button>`
          )
          .join("")
      : "";
  }

  // Everything that depends on the vendor list (cheaper than render()).
  function rerenderKevWatch() {
    if (!state.snapshot) return;
    buildKevWatchMatches();
    renderFeed("cisa_kev");
    renderWatchlistPanel();
    renderTriage();
    renderSinceSummary();
    renderVendorChips();
  }

  function initVendorWatch() {
    const textarea = $("vendor-watch-input");
    const text = loadVendorWatch();
    textarea.value = text;
    setVendorWatchText(text);

    const commit = () => {
      saveVendorWatch(textarea.value);
      setVendorWatchText(textarea.value);
      rerenderKevWatch();
    };

    let debounceTimer = null;
    textarea.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(commit, 300);
    });

    const addTerm = (term) => {
      term = String(term || "").trim();
      if (!term) return;
      const key = normVendorText(term);
      const lines = textarea.value.split("\n");
      if (!lines.some((l) => normVendorText(l) === key)) {
        const base = textarea.value.replace(/\s+$/, "");
        textarea.value = base ? `${base}\n${term}` : term;
      }
      clearTimeout(debounceTimer);
      commit();
    };

    $("vendor-add-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      const input = $("vendor-add-input");
      addTerm(input.value);
      input.value = "";
    });
    $("vendor-chips").addEventListener("click", (ev) => {
      const chip = ev.target.closest(".vendor-chip");
      if (chip) addTerm(chip.getAttribute("data-vendor"));
    });

    // CVE links and "view all" in the matches card.
    $("watchlist-matches-card").addEventListener("click", (ev) => {
      if (ev.target.closest("#watchlist-kev-all")) {
        showWatchedKev();
        return;
      }
      const a = ev.target.closest("a.triage-link[data-feed]");
      if (!a) return;
      ev.preventDefault();
      scrollToMatch(a.getAttribute("data-feed"), a.getAttribute("data-q"));
    });

    document.addEventListener("change", (ev) => {
      const input = ev.target.closest(".watched-only[data-feed]");
      if (!input) return;
      state.kevWatch.watchedOnly = input.checked;
      renderFeed(input.getAttribute("data-feed"));
    });
  }

  // ---------- Export (CSV / JSON, respects current filter) ----------

  function csvEscape(val) {
    let s = val === null || val === undefined ? "" : String(val);
    // Feed fields (file names, URLs, tags, victim names) are attacker-controlled.
    // A cell starting with = + - @ (or tab/CR) runs as a formula when the
    // CSV is opened in Excel or Sheets, so prefix it with a quote. Excel in
    // locales whose list separator is ";" (much of Europe) also starts a new
    // cell at every ";" (quotes only count at the start of a cell), and list
    // fields are joined with ";", so do the same after each ";". Leading
    // whitespace is allowed for. Plain numbers are left alone.
    if (typeof val === "string" && !/^-?\d+(\.\d+)?$/.test(s)) {
      s = s.replace(/(^|;)(\s*?)(?=[=+\-@\t\r])/g, "$1$2'");
    }
    if (/[",;\t\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  }

  function toCsv(headers, rows, toCsvRow) {
    const lines = [headers.map(csvEscape).join(",")];
    for (const row of rows) {
      lines.push(toCsvRow(row).map(csvEscape).join(","));
    }
    return lines.join("\r\n");
  }

  function downloadBlob(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function timestampForFilename() {
    return new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
  }

  function exportFeed(feed, format) {
    const def = FEED_DEFS[feed];
    if (!def) return;
    const ts = state.tableState[feed];
    const rows = (ts && ts.lastFiltered) || state.snapshot.feeds?.[feed]?.items || [];
    if (!rows.length) return;
    const stamp = timestampForFilename();
    if (format === "json") {
      downloadBlob(JSON.stringify(rows, null, 2), `${feed}-${stamp}.json`, "application/json");
    } else {
      downloadBlob(toCsv(def.csvHeaders, rows, def.toCsvRow), `${feed}-${stamp}.csv`, "text/csv");
    }
  }

  function exportCorrelated(format) {
    const rows = correlatedRows();
    if (!rows.length) return;
    const stamp = timestampForFilename();
    if (format === "json") {
      downloadBlob(JSON.stringify(rows, null, 2), `correlated-${stamp}.json`, "application/json");
    } else {
      const headers = ["Value", "Type", "Feeds", "Signal Count", "Signals", "Labels", "Most Recent"];
      const toCsvRow = (c) => [
        c.value,
        c.type,
        c.feeds.join(";"),
        c.signalCount,
        c.signalBreakdown.join(";"),
        c.labels.join(";"),
        c.mostRecent ? new Date(c.mostRecent).toISOString() : "",
      ];
      downloadBlob(toCsv(headers, rows, toCsvRow), `correlated-${stamp}.csv`, "text/csv");
    }
  }

  function wireExportButtons() {
    document.addEventListener("click", (ev) => {
      const btn = ev.target.closest(".export-btn");
      if (!btn) return;
      const feed = btn.getAttribute("data-feed");
      const format = btn.getAttribute("data-format");
      if (feed === "correlated") exportCorrelated(format);
      else exportFeed(feed, format);
    });
  }

  // ---------- Trend sparklines ----------

  function buildSparklineSvg(series) {
    const w = 100,
      h = 24,
      pad = 2;
    const min = Math.min(...series);
    const max = Math.max(...series);
    const range = max - min || 1;
    const stepX = series.length > 1 ? (w - pad * 2) / (series.length - 1) : 0;
    const points = series
      .map((v, i) => {
        const x = pad + i * stepX;
        const y = h - pad - ((v - min) / range) * (h - pad * 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
    const lastX = pad + (series.length - 1) * stepX;
    const lastY = h - pad - ((series[series.length - 1] - min) / range) * (h - pad * 2);
    return `<svg viewBox="0 0 ${w} ${h}" class="sparkline-svg" preserveAspectRatio="none">
      <polyline points="${points}" fill="none" stroke="var(--sparkline-color)" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" />
      <circle cx="${lastX.toFixed(1)}" cy="${lastY.toFixed(1)}" r="1.8" fill="var(--sparkline-color)" />
    </svg>`;
  }

  function renderSparkline(feed) {
    const el = document.querySelector(`.sparkline[data-feed="${feed}"]`);
    if (!el) return;
    const days = state.trends?.days || [];
    const series = days.slice(-30).map((d) => d.counts?.[feed] ?? 0);
    if (series.length < 2) {
      el.innerHTML = "";
      return;
    }
    el.innerHTML = buildSparklineSvg(series);
    el.title = `${series.length}-day trend: ${series[0].toLocaleString()} → ${series[series.length - 1].toLocaleString()}`;
  }

  // ---------- Geo / ASN ----------

  function countryName(code) {
    try {
      const dn = new Intl.DisplayNames(["en"], { type: "region" });
      return dn.of(code.toUpperCase()) || code;
    } catch (e) {
      return code;
    }
  }

  function geoColorForCount(count, max) {
    if (!count) return getComputedStyle(document.documentElement).getPropertyValue("--border").trim() || "#888";
    const ramp = [0, 1, 2, 3, 4].map((i) =>
      getComputedStyle(document.documentElement).getPropertyValue(`--geo-ramp-${i}`).trim()
    );
    const logVal = Math.log(count + 1);
    const logMax = Math.log(Math.max(max, 1) + 1);
    const t = logMax > 0 ? Math.min(1, logVal / logMax) : 0;
    const idx = Math.min(ramp.length - 1, Math.floor(t * ramp.length));
    return ramp[idx] || ramp[ramp.length - 1];
  }

  function renderWorldMap(byCountry) {
    const container = $("world-map-container");
    if (!container) return;
    // Multi-part countries (US, Russia, China, Canada, ...) are wrapped as
    // <g id="us"> containing un-id'd child <path> segments (mainland,
    // islands, etc.) rather than the id living on a <path> directly — the
    // group needs to be selected too, or every large/split country (which
    // is most of the top entries) never gets colored.
    const nodes = container.querySelectorAll("path[id], g[id]");
    if (!nodes.length) return; // Map asset not loaded/present — bars/tables still show the data.

    const counts = Object.values(byCountry);
    const max = counts.length ? Math.max(...counts) : 0;

    nodes.forEach((node) => {
      const code = node.id.toUpperCase();
      const count = byCountry[code] || 0;
      // fill/stroke are inheritable SVG presentation attributes, so setting
      // them on a <g> wrapper colors its un-id'd <path> children too.
      node.setAttribute("fill", geoColorForCount(count, max));
      node.classList.add("geo-country-path");
      let title = node.querySelector(":scope > title");
      if (!title) {
        title = document.createElementNS("http://www.w3.org/2000/svg", "title");
        node.insertBefore(title, node.firstChild);
      }
      title.textContent = count ? `${countryName(code)}: ${count.toLocaleString()} geotagged IPs` : `${countryName(code)}: no data`;
    });
  }

  function renderGeo() {
    const section = $("geo-section");
    const summary = state.geoSummary;
    if (!summary || !summary.total_geotagged) {
      section.hidden = true;
      return;
    }
    section.hidden = false;

    $("geo-total").textContent = summary.total_geotagged.toLocaleString();
    $("geo-generated-at").textContent = summary.generated_at ? fmtDate(summary.generated_at) : "—";

    const byCountry = summary.by_country || {};
    const countries = Object.entries(byCountry).sort((a, b) => b[1] - a[1]);
    const topCountries = countries.slice(0, 10);

    const max = topCountries.length ? topCountries[0][1] : 0;
    $("geo-bars").innerHTML = topCountries
      .map(([code, count]) => {
        const pct = max ? Math.max(4, Math.round((count / max) * 100)) : 0;
        return `<div class="geo-bar-row" title="${escapeHtml(countryName(code))}">
          <span class="geo-bar-label">${escapeHtml(code)}</span>
          <span class="geo-bar-track"><span class="geo-bar-fill" style="width:${pct}%"></span></span>
          <span class="geo-bar-count">${count.toLocaleString()}</span>
        </div>`;
      })
      .join("");

    const asns = (summary.top_asns || []).slice(0, 10);
    $("geo-asns-tbody").innerHTML = asns
      .map(
        (a, i) =>
          `<tr><td>${i + 1}</td><td class="mono">${escapeHtml(a.asn)}</td><td>${escapeHtml(a.name)}</td><td>${a.count.toLocaleString()}</td></tr>`
      )
      .join("");

    renderWorldMap(byCountry);
  }

  // ---------- Generic sortable/searchable table ----------

  function renderTable(feed, columns, searchFn, defaultSort, getItems) {
    const info = getItems ? getItems() : state.snapshot.feeds?.[feed];
    const items = info?.items || [];
    const emptyNote = $(`empty-${feed}`);
    const table = $(`table-${feed}`);
    const def = FEED_DEFS[feed];
    syncNewOnlyToggle(feed);
    syncWatchedOnlyToggle(feed);
    scheduleHashSync(); // search / sort may have changed

    if (!items.length) {
      table.querySelector("thead").innerHTML = "";
      table.querySelector("tbody").innerHTML = "";
      emptyNote.hidden = false;
      if (!state.tableState[feed]) state.tableState[feed] = { sortKey: defaultSort.key, sortDir: defaultSort.dir, query: "" };
      state.tableState[feed].lastFiltered = [];
      return;
    }
    emptyNote.hidden = true;

    if (!state.tableState[feed]) {
      state.tableState[feed] = { sortKey: defaultSort.key, sortDir: defaultSort.dir, query: "" };
    }
    const ts = state.tableState[feed];

    const thead = table.querySelector("thead");
    thead.innerHTML =
      "<tr>" +
      columns
        .map((col) => {
          const arrow = ts.sortKey === col.key ? (ts.sortDir === "asc" ? "↑" : "↓") : "";
          const ariaSort = ts.sortKey === col.key ? (ts.sortDir === "asc" ? "ascending" : "descending") : "none";
          return `<th data-key="${escapeHtml(col.key)}" tabindex="0" aria-sort="${ariaSort}">${escapeHtml(col.label)}<span class="sort-arrow">${arrow}</span></th>`;
        })
        .join("") +
      "</tr>";

    thead.querySelectorAll("th").forEach((th) => {
      const sortBy = (fromKeyboard) => {
        const key = th.getAttribute("data-key");
        if (ts.sortKey === key) {
          ts.sortDir = ts.sortDir === "asc" ? "desc" : "asc";
        } else {
          ts.sortKey = key;
          ts.sortDir = "asc";
        }
        renderTable(feed, columns, searchFn, defaultSort, getItems);
        // The header row is rebuilt, so put keyboard focus back on the same column.
        if (fromKeyboard) table.querySelector(`thead th[data-key="${CSS.escape(key)}"]`)?.focus();
      };
      th.addEventListener("click", () => sortBy(false));
      th.addEventListener("keydown", (ev) => {
        if (ev.key !== "Enter" && ev.key !== " ") return;
        ev.preventDefault();
        sortBy(true);
      });
    });

    const newSet = def?.sinceCat ? state.since.newSets[def.sinceCat] : null;

    let filtered = items;
    if (newSet && isNewOnly(feed)) {
      filtered = filtered.filter((item) => newSet.has(def.sinceKey(item)));
    }
    if (def?.isWatched && isWatchedOnly(feed)) {
      filtered = filtered.filter(def.isWatched);
    }
    if (ts.query) {
      const q = ts.query.toLowerCase();
      filtered = filtered.filter((item) => searchFn(item).toLowerCase().includes(q));
    }

    const sortCol = columns.find((c) => c.key === ts.sortKey);
    if (sortCol) {
      filtered = filtered.slice().sort((a, b) => {
        const va = sortCol.sortValue ? sortCol.sortValue(a) : "";
        const vb = sortCol.sortValue ? sortCol.sortValue(b) : "";
        if (va < vb) return ts.sortDir === "asc" ? -1 : 1;
        if (va > vb) return ts.sortDir === "asc" ? 1 : -1;
        return 0;
      });
    }

    ts.lastFiltered = filtered;

    const MAX_ROWS = 500;
    const shown = filtered.slice(0, MAX_ROWS);

    const rowKeyFn = def?.rowKey;
    const matchKeys = state.watchlistMatchKeys;
    const hasNew = newSet && newSet.size > 0;

    const tbody = table.querySelector("tbody");
    tbody.innerHTML = shown
      .map((item) => {
        const isMatch =
          (rowKeyFn && matchKeys && matchKeys.has(`${feed}::${rowKeyFn(item)}`)) || (def?.isWatched && def.isWatched(item));
        const isNew = hasNew && newSet.has(def.sinceKey(item));
        const classes = [isMatch ? "watchlist-match" : "", isNew ? "is-new" : ""].filter(Boolean).join(" ");
        const cls = classes ? ` class="${classes}"` : "";
        // The NEW badge goes at the end of the first cell.
        return `<tr${cls}>${columns.map((c, i) => `<td>${c.render(item)}${isNew && i === 0 ? NEW_BADGE : ""}</td>`).join("")}</tr>`;
      })
      .join("");

    // Say so when the search or filters hide everything, so an empty-looking
    // table can't be mistaken for an empty feed (e.g. a link whose search
    // term is invisible).
    if (!filtered.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columns.length;
      td.className = "empty-note";
      td.textContent = `No rows match the current search or filters (0 of ${items.length.toLocaleString()}). Clear the search box or untick the filters to see them.`;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }

    if (filtered.length > MAX_ROWS) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columns.length;
      td.className = "empty-note";
      td.textContent = `Showing first ${MAX_ROWS} of ${filtered.length} matching rows. Narrow your search to see more (export uses all ${filtered.length}).`;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }

  function wireSearchBoxes() {
    document.querySelectorAll(".search-box[data-feed]").forEach((input) => {
      input.addEventListener("input", () => {
        const feed = input.getAttribute("data-feed");
        if (!state.tableState[feed]) state.tableState[feed] = { sortKey: null, sortDir: "asc", query: "" };
        state.tableState[feed].query = input.value;
        renderFeed(feed);
      });
    });
  }

  // ---------- Per-feed render definitions ----------

  const FEED_DEFS = {
    threatfox: {
      columns: [
        {
          key: "ioc",
          label: "IOC",
          sortValue: (i) => (i.ioc || "").toLowerCase(),
          render: (i) => {
            const ip = extractIpFromIoc(i.ioc, i.ioc_type);
            return `${iocButton(threatfoxNorm(i))}<span class="mono">${escapeHtml(i.ioc)}</span>${ip ? ipBadges(ip) : ""}`;
          },
        },
        { key: "ioc_type", label: "Type", sortValue: (i) => i.ioc_type || "", render: (i) => escapeHtml(i.ioc_type) },
        {
          key: "malware_printable",
          label: "Malware",
          sortValue: (i) => (i.malware_printable || "").toLowerCase(),
          render: (i) => escapeHtml(i.malware_printable || "—"),
        },
        {
          key: "confidence_level",
          label: "Confidence",
          sortValue: (i) => Number(i.confidence_level) || 0,
          render: (i) => escapeHtml(i.confidence_level ?? "—"),
        },
        {
          key: "first_seen",
          label: "First Seen",
          sortValue: (i) => i.first_seen || "",
          render: (i) => fmtDate(i.first_seen),
        },
      ],
      searchFn: (i) => `${i.ioc || ""} ${i.malware_printable || ""} ${(i.tags || []).join(" ")}`,
      defaultSort: { key: "first_seen", dir: "desc" },
      rowKey: (i) => i.ioc,
      csvHeaders: ["IOC", "Type", "Malware", "Confidence", "First Seen", "Tags", "Reporter"],
      toCsvRow: (i) => [i.ioc, i.ioc_type, i.malware_printable, i.confidence_level, i.first_seen, (i.tags || []).join(";"), i.reporter],
    },

    urlhaus: {
      columns: [
        {
          key: "url",
          label: "URL",
          sortValue: (i) => (i.url || "").toLowerCase(),
          render: (i) => {
            const href = urlhausLink(i);
            const link = href
              ? `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(i.url)}</a>`
              : escapeHtml(i.url);
            return `${iocButton(urlhausNorm(i))}<span class="mono">${link}</span>`;
          },
        },
        { key: "url_status", label: "Status", sortValue: (i) => i.url_status || "", render: (i) => escapeHtml(i.url_status) },
        { key: "threat", label: "Threat", sortValue: (i) => i.threat || "", render: (i) => escapeHtml(i.threat) },
        {
          key: "date_added",
          label: "Date Added",
          sortValue: (i) => i.date_added || "",
          render: (i) => fmtDate(i.date_added),
        },
      ],
      searchFn: (i) => `${i.url || ""} ${i.threat || ""} ${i.tags || ""}`,
      defaultSort: { key: "date_added", dir: "desc" },
      rowKey: (i) => i.url,
      csvHeaders: ["URL", "Status", "Threat", "Date Added", "Last Online", "Tags", "URLhaus Link", "Reporter"],
      toCsvRow: (i) => [i.url, i.url_status, i.threat, i.date_added, i.last_online, i.tags, urlhausLink(i), i.reporter],
    },

    malwarebazaar: {
      columns: [
        { key: "file_name", label: "File Name", sortValue: (i) => (i.file_name || "").toLowerCase(), render: (i) => escapeHtml(i.file_name || "—") },
        {
          key: "sha256_hash",
          label: "SHA256",
          sortValue: (i) => i.sha256_hash || "",
          render: (i) =>
            `${iocButton(normalizeIocValue(i.sha256_hash, "hash"))}<span class="mono" title="${escapeHtml(i.sha256_hash)}">${escapeHtml((i.sha256_hash || "").slice(0, 16))}&hellip;</span>`,
        },
        { key: "signature", label: "Family", sortValue: (i) => (i.signature || "").toLowerCase(), render: (i) => escapeHtml(i.signature || "—") },
        { key: "first_seen", label: "First Seen", sortValue: (i) => i.first_seen || "", render: (i) => fmtDate(i.first_seen) },
        { key: "last_seen", label: "Last Seen", sortValue: (i) => i.last_seen || "", render: (i) => fmtDate(i.last_seen) },
      ],
      searchFn: (i) => `${i.file_name || ""} ${i.signature || ""} ${i.sha256_hash || ""} ${(i.tags || []).join(" ")}`,
      defaultSort: { key: "first_seen", dir: "desc" },
      rowKey: (i) => i.sha256_hash,
      csvHeaders: ["File Name", "SHA256", "Family", "First Seen", "Last Seen", "Tags"],
      toCsvRow: (i) => [i.file_name, i.sha256_hash, i.signature, i.first_seen, i.last_seen, (i.tags || []).join(";")],
    },

    cisa_kev: {
      columns: [
        { key: "cve_id", label: "CVE ID", sortValue: (i) => i.cve_id || "", render: (i) => `<span class="mono">${escapeHtml(i.cve_id)}</span>` },
        {
          key: "vendor_project",
          label: "Vendor / Product",
          sortValue: (i) => (i.vendor_project || "").toLowerCase(),
          render: (i) => `${escapeHtml(i.vendor_project)} / ${escapeHtml(i.product)}`,
        },
        { key: "vulnerability_name", label: "Name", sortValue: (i) => i.vulnerability_name || "", render: (i) => escapeHtml(i.vulnerability_name) },
        { key: "date_added", label: "Date Added", sortValue: (i) => i.date_added || "", render: (i) => escapeHtml(i.date_added) },
        { key: "due_date", label: "Due Date", sortValue: (i) => i.due_date || "", render: (i) => escapeHtml(i.due_date) },
        {
          key: "known_ransomware_campaign_use",
          label: "Ransomware",
          sortValue: (i) => i.known_ransomware_campaign_use || "",
          render: (i) =>
            i.known_ransomware_campaign_use === "Known"
              ? `<span class="ransomware-yes">Known</span>`
              : escapeHtml(i.known_ransomware_campaign_use || "—"),
        },
        {
          key: "epss_score",
          label: "EPSS",
          sortValue: (i) => epssFor(i.cve_id)?.epss ?? -1,
          render: (i) => {
            const e = epssFor(i.cve_id);
            if (!e) return "—";
            const pct = `${(e.epss * 100).toFixed(1)}%`;
            return e.percentile >= 0.9 ? `<span class="epss-high">${pct}</span>` : pct;
          },
        },
        {
          key: "epss_percentile",
          label: "EPSS %ile",
          sortValue: (i) => epssFor(i.cve_id)?.percentile ?? -1,
          render: (i) => {
            const e = epssFor(i.cve_id);
            if (!e) return "—";
            const pct = `${(e.percentile * 100).toFixed(1)}%`;
            return e.percentile >= 0.9 ? `<span class="epss-high">${pct}</span>` : pct;
          },
        },
      ],
      searchFn: (i) => `${i.cve_id || ""} ${i.vendor_project || ""} ${i.product || ""} ${i.vulnerability_name || ""}`,
      defaultSort: { key: "date_added", dir: "desc" },
      rowKey: (i) => i.cve_id,
      isWatched: (i) => isKevWatched(i), // vendor/product watchlist
      sinceCat: "kev",
      sinceKey: (i) => i.cve_id,
      csvHeaders: ["CVE ID", "Vendor", "Product", "Name", "Date Added", "Due Date", "Ransomware Use", "EPSS Score", "EPSS Percentile", "Description"],
      toCsvRow: (i) => {
        const e = epssFor(i.cve_id);
        return [
          i.cve_id,
          i.vendor_project,
          i.product,
          i.vulnerability_name,
          i.date_added,
          i.due_date,
          i.known_ransomware_campaign_use,
          e?.epss ?? "",
          e?.percentile ?? "",
          i.short_description,
        ];
      },
    },

    otx: {
      columns: [
        { key: "name", label: "Pulse Name", sortValue: (i) => (i.name || "").toLowerCase(), render: (i) => escapeHtml(i.name) },
        {
          key: "tags",
          label: "Tags",
          sortValue: (i) => (i.tags || []).join(","),
          render: (i) => (i.tags || []).map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join(""),
        },
        {
          key: "indicator_count",
          label: "Indicators",
          sortValue: (i) => i.indicator_count || 0,
          render: (i) => escapeHtml(i.indicator_count ?? 0),
        },
        { key: "created", label: "Created", sortValue: (i) => i.created || "", render: (i) => fmtDate(i.created) },
      ],
      searchFn: (i) => `${i.name || ""} ${(i.tags || []).join(" ")}`,
      defaultSort: { key: "created", dir: "desc" },
      rowKey: (i) => i.name,
      csvHeaders: ["Pulse Name", "Tags", "Indicator Count", "Created"],
      toCsvRow: (i) => [i.name, (i.tags || []).join(";"), i.indicator_count, i.created],
    },

    blocklistde: {
      columns: [
        {
          key: "ip",
          label: "IP",
          sortValue: (i) => i.ip || "",
          render: (i) => `${iocButton(normalizeIocValue(i.ip, "ip"))}<span class="mono">${escapeHtml(i.ip)}</span>${ipBadges(i.ip)}`,
        },
        {
          key: "lists",
          label: "Seen On",
          sortValue: (i) => (i.lists || []).join(","),
          render: (i) => (i.lists || []).map((l) => `<span class="tag">${escapeHtml(l)}</span>`).join(""),
        },
      ],
      searchFn: (i) => `${i.ip || ""} ${(i.lists || []).join(" ")}`,
      defaultSort: { key: "ip", dir: "asc" },
      rowKey: (i) => i.ip,
      csvHeaders: ["IP", "Seen On"],
      toCsvRow: (i) => [i.ip, (i.lists || []).join(";")],
    },

    ransomware_victims: {
      columns: [
        { key: "group", label: "Group", sortValue: (i) => (i.group || "").toLowerCase(), render: (i) => escapeHtml(i.group || "—") },
        { key: "victim", label: "Victim", sortValue: (i) => (i.victim || "").toLowerCase(), render: (i) => escapeHtml(i.victim || "—") },
        { key: "sector", label: "Sector", sortValue: (i) => (i.sector || "").toLowerCase(), render: (i) => escapeHtml(i.sector || "—") },
        { key: "country", label: "Country", sortValue: (i) => i.country || "", render: (i) => escapeHtml(i.country || "—") },
        { key: "published", label: "Published", sortValue: (i) => i.published || "", render: (i) => fmtDate(i.published) },
      ],
      searchFn: (i) => `${i.group || ""} ${i.victim || ""} ${i.sector || ""} ${i.country || ""} ${i.domain || ""}`,
      defaultSort: { key: "published", dir: "desc" },
      rowKey: (i) => i.url || i.victim,
      sinceCat: "rw",
      sinceKey: (i) => rwSeenKey(i),
      csvHeaders: ["Group", "Victim", "Sector", "Country", "Published", "Domain", "URL"],
      toCsvRow: (i) => [i.group, i.victim, i.sector, i.country, i.published, i.domain, i.url],
      // Not one of data/latest.json's feeds — sourced from its own file
      // (data/ransomware_victims.json), so renderTable/renderFeedStatus
      // pull items via this instead of state.snapshot.feeds[feed].
      getItems: () =>
        state.ransomwareVictims
          ? { status: "ok", items: state.ransomwareVictims.victims || [] }
          : { status: "pending", items: [] },
    },
  };

  function renderFeed(feed) {
    const def = FEED_DEFS[feed];
    if (!def) return;
    renderFeedStatus(feed);
    renderTable(feed, def.columns, def.searchFn, def.defaultSort, def.getItems);
    renderSparkline(feed);
  }

  function render() {
    renderHeader();
    buildDropRanges();
    renderKpis();
    renderQuotaMeter();
    buildCorrelation();
    computeSince();
    buildTriage();
    buildWatchlistMatches();
    buildKevWatchMatches();
    renderVendorSuggestions();
    renderCorrelated();
    renderTriage();
    renderWatchlistPanel();
    Object.keys(FEED_DEFS).forEach(renderFeed);
    renderGeo();
    state.rw = computeRansomwareWindow();
    renderRansomwarePanels();
    renderRwTrends();
    updateGlobe();
    renderUkNews();
    renderTabCounts();
    syncTabs();
    renderSinceSummary();
    refreshIocDrawer();
  }

  // ---------- Header clock ----------

  function startClock() {
    const el = $("utc-clock");
    if (!el) return;
    const tick = () => {
      el.textContent = `${new Date().toISOString().slice(11, 19)} UTC`;
      renderRefreshCountdown();
    };
    tick();
    setInterval(tick, 1000);
  }

  // ---------- Data deck tabs ----------

  const TAB_KEY = "ctd-tab";
  const DEFAULT_TAB = "section-correlated";

  function tabButtons() {
    return Array.from(document.querySelectorAll(".deck-tab"));
  }

  // `remember` = a user choice: stored, and re-applied when a hidden tab
  // (e.g. geo before its data loads) becomes available again.
  function activateTab(id, remember) {
    if (remember) {
      state.preferredTab = id;
      try {
        localStorage.setItem(TAB_KEY, id);
      } catch (e) {
        /* localStorage unavailable */
      }
    }
    const buttons = tabButtons();
    const btn = buttons.find((b) => b.dataset.tab === id && !b.hidden) || buttons.find((b) => !b.hidden);
    if (!btn) return;
    buttons.forEach((b) => {
      const on = b === btn;
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
    document.querySelectorAll(".deck-panel").forEach((p) => p.classList.toggle("is-active", p.id === btn.dataset.tab));
    scheduleHashSync();
  }

  function initTabs() {
    let saved = null;
    try {
      saved = localStorage.getItem(TAB_KEY);
    } catch (e) {
      /* localStorage unavailable */
    }
    // A shared link's tab wins over the saved one (applied in full after the
    // first render; set here too so the saved tab doesn't flash first).
    state.preferredTab = initialHashTab() || saved || DEFAULT_TAB;

    const buttons = tabButtons();
    buttons.forEach((b) => {
      b.setAttribute("aria-controls", b.dataset.tab);
      b.addEventListener("click", () => activateTab(b.dataset.tab, true));
      b.addEventListener("keydown", (ev) => {
        if (ev.key !== "ArrowRight" && ev.key !== "ArrowLeft") return;
        const visible = tabButtons().filter((x) => !x.hidden);
        const i = visible.indexOf(b);
        const next = visible[(i + (ev.key === "ArrowRight" ? 1 : -1) + visible.length) % visible.length];
        activateTab(next.dataset.tab, true);
        next.focus();
        ev.preventDefault();
      });
    });
    syncTabs();
  }

  // A tab hides along with its panel (geo stays hidden until it has data).
  function syncTabs() {
    tabButtons().forEach((b) => {
      const panel = $(b.dataset.tab);
      b.hidden = !panel || panel.hidden;
    });
    activateTab(state.preferredTab || DEFAULT_TAB, false);
  }

  function compactNumber(n) {
    if (n >= 100000) return `${Math.round(n / 1000)}k`;
    if (n >= 10000) return `${(n / 1000).toFixed(1)}k`;
    return n.toLocaleString();
  }

  function renderTabCounts() {
    Object.keys(FEED_DEFS).forEach((feed) => {
      const el = $(`tabcount-${feed}`);
      if (!el) return;
      const def = FEED_DEFS[feed];
      const info = def.getItems ? def.getItems() : state.snapshot.feeds?.[feed];
      const n = info?.items?.length || 0;
      el.textContent = n ? compactNumber(n) : "";
    });
    const n = (state.correlated || []).length;
    $("tabcount-correlated").textContent = n ? compactNumber(n) : "";
  }

  // ---------- Shareable links (URL fragment) ----------
  //
  // The view is mirrored into the fragment so a link opens the same thing
  // for someone else. The fragment is never sent to the server or put in a
  // Referer, so IOCs in links don't end up in logs. Format, `&`-separated
  // key=value pairs (percent-encoded; ":" "/" "@" "," left readable):
  //
  //   tab=<name>        data-deck tab: correlated (default, omitted), cisa_kev,
  //                     ransomware_victims, uk_news, threatfox, urlhaus,
  //                     malwarebazaar, otx, blocklistde, geo, watchlist
  //   q=<text>          that tab's search box (feed tables and uk_news)
  //   sort=<key>:<dir>  that tab's sort column (a column key) and asc|desc;
  //                     omitted when it's the table's default sort
  //   uk=1              uk_news only: "UK stories only"
  //   ioc=<type>:<v>    open IOC drawer; type is ip, domain or hash
  //   cc=<XX>           ransomware country filter (two letters)
  //   rwt=<7|30|90>     ransomware_victims only: trends window; omitted at
  //                     the default (30)
  //
  // e.g. #tab=cisa_kev&q=fortinet&sort=date_added:asc  or  #ioc=ip:1.2.3.4
  // A bare legacy anchor like #section-cisa_kev is read as its tab.
  //
  // Per-browser state (watchlists, "New only", "Watched only", the "new
  // since" baseline) is deliberately left out. The fragment is untrusted
  // input: every value is checked against an allow-list or pattern, length
  // capped, and anything unknown, malformed, oversized or repeated is
  // dropped. Values only ever reach the page via input .value, textContent
  // or the existing escaped render paths. Updates use replaceState, so the
  // Back button isn't filled with every keystroke.

  const HASH_MAX_LEN = 4096; // whole fragment; anything longer is ignored outright
  const HASH_Q_MAX = 200;
  const HASH_IOC_MAX = 500;
  const HASH_SYNC_MS = 300;
  const HASH_KEYS = new Set(["tab", "q", "sort", "uk", "ioc", "cc", "rwt"]);
  const HASH_TABS = new Map([
    ["correlated", "section-correlated"],
    ["cisa_kev", "section-cisa_kev"],
    ["ransomware_victims", "section-ransomware_victims"],
    ["uk_news", "section-uk_news"],
    ["threatfox", "section-threatfox"],
    ["urlhaus", "section-urlhaus"],
    ["malwarebazaar", "section-malwarebazaar"],
    ["otx", "section-otx"],
    ["blocklistde", "section-blocklistde"],
    ["geo", "geo-section"],
    ["watchlist", "section-watchlist"],
  ]);
  const HASH_TAB_NAMES = new Map(Array.from(HASH_TABS, ([name, id]) => [id, name]));
  const HASH_IOC_TYPES = new Set(["ip", "domain", "hash"]); // what the drawer supports

  // ready: the initial fragment has been applied, so syncing may overwrite it.
  const hashSync = { ready: false, timer: null };

  function hashTableFor(tabName) {
    return tabName && Object.prototype.hasOwnProperty.call(FEED_DEFS, tabName) ? tabName : null;
  }

  function searchBoxFor(feed) {
    return document.querySelector(`.search-box[data-feed="${CSS.escape(feed)}"]`);
  }

  // Raw fragment -> Map of decoded values for known keys. A pair that fails
  // to decode is skipped; a key given more than once is dropped entirely.
  function readHashPairs(raw) {
    const out = new Map();
    let s = String(raw || "");
    if (s.startsWith("#")) s = s.slice(1);
    if (!s || s.length > HASH_MAX_LEN) return out;
    if (!s.includes("=")) {
      // Legacy anchor, e.g. "#section-cisa_kev".
      const name = HASH_TAB_NAMES.get(s);
      if (name) out.set("tab", name);
      return out;
    }
    const dupes = new Set();
    for (const part of s.split("&")) {
      const eq = part.indexOf("=");
      if (eq <= 0) continue;
      let key, value;
      try {
        key = decodeURIComponent(part.slice(0, eq).replace(/\+/g, " "));
        value = decodeURIComponent(part.slice(eq + 1).replace(/\+/g, " "));
      } catch (e) {
        continue; // malformed percent-encoding
      }
      if (!HASH_KEYS.has(key)) continue;
      if (out.has(key)) dupes.add(key);
      else out.set(key, value);
    }
    for (const key of dupes) out.delete(key);
    return out;
  }

  // Validated IOC, or null.
  function parseHashIoc(raw) {
    if (!raw || raw.length > HASH_IOC_MAX + 10) return null;
    const i = raw.indexOf(":");
    if (i <= 0) return null;
    const type = raw.slice(0, i);
    const value = raw.slice(i + 1);
    if (!HASH_IOC_TYPES.has(type) || !value || value.length > HASH_IOC_MAX) return null;
    if (/[\s\p{Cc}\p{Cf}]/u.test(value)) return null; // whitespace, control and invisible format chars
    const norm = normalizeIocValue(value, type);
    return norm && norm.type === type ? norm : null;
  }

  // Fragment -> validated view state. Never throws on any input string.
  function parseHashState(raw) {
    const p = readHashPairs(raw);
    const h = { tab: null, q: null, sort: null, uk: false, ioc: null, cc: null, rwt: null, any: false };

    const tab = p.get("tab");
    if (tab && HASH_TABS.has(tab)) h.tab = tab;

    const table = hashTableFor(h.tab);
    const searchable = (table && searchBoxFor(table)) || h.tab === "uk_news";
    // Drop a search containing control or invisible format characters
    // (zero-width space, bidi overrides): a link could otherwise fill the
    // search box with something that looks empty, or reads as another term,
    // and silently hide every row.
    const q = (p.get("q") || "").trim();
    if (searchable && q && q.length <= HASH_Q_MAX && !/[\p{Cc}\p{Cf}]/u.test(q)) h.q = q;

    const sort = /^([a-z_]{1,40}):(asc|desc)$/.exec(p.get("sort") || "");
    if (table && sort && FEED_DEFS[table].columns.some((c) => c.key === sort[1])) h.sort = { key: sort[1], dir: sort[2] };

    if (h.tab === "uk_news" && p.get("uk") === "1") h.uk = true;

    h.ioc = parseHashIoc(p.get("ioc"));

    const cc = p.get("cc");
    if (cc && /^[A-Za-z]{2}$/.test(cc)) h.cc = cc.toUpperCase();

    const rwt = p.get("rwt");
    if (h.tab === "ransomware_victims" && /^\d{1,2}$/.test(rwt || "") && RWT_WINDOWS.includes(Number(rwt))) h.rwt = Number(rwt);

    h.any = Boolean(h.tab || h.q || h.sort || h.uk || h.ioc || h.cc || h.rwt);
    return h;
  }

  // Used by initTabs, before any data: the linked tab, or null.
  function initialHashTab() {
    try {
      const h = parseHashState(location.hash);
      return h.any ? HASH_TABS.get(h.tab || "correlated") : null;
    } catch (e) {
      return null;
    }
  }

  // Apply everything except the IOC (callers handle that, since it may have
  // to wait for the enrichment files). A link describes the whole view, so
  // what it leaves out goes back to the default.
  function applyHashState(h) {
    const tabName = h.tab || "correlated";
    state.preferredTab = HASH_TABS.get(tabName); // not saved: following a link isn't choosing a tab

    const table = hashTableFor(tabName);
    if (table) {
      const def = FEED_DEFS[table];
      if (!state.tableState[table]) state.tableState[table] = { sortKey: def.defaultSort.key, sortDir: def.defaultSort.dir, query: "" };
      const ts = state.tableState[table];
      const input = searchBoxFor(table);
      if (input) {
        input.value = h.q || "";
        ts.query = input.value; // read back: the input strips line breaks
      }
      ts.sortKey = h.sort ? h.sort.key : def.defaultSort.key;
      ts.sortDir = h.sort ? h.sort.dir : def.defaultSort.dir;
      // Per-browser filters could hide what the link points at.
      if (h.q || h.ioc) {
        state.since.newOnly[table] = false;
        if (table === "cisa_kev") state.kevWatch.watchedOnly = false;
      }
      renderFeed(table);
    } else if (tabName === "uk_news") {
      const search = $("news-search");
      const ukOnly = $("news-uk-only");
      if (search) {
        search.value = h.q || "";
        state.newsQuery = search.value;
      }
      if (ukOnly) ukOnly.checked = h.uk;
      state.newsUkOnly = h.uk;
      renderUkNews();
    }

    if ((h.cc || null) !== state.rwCountry) setRwCountry(h.cc);
    if ((h.rwt || RWT_DEFAULT_WINDOW) !== state.rwTrendDays) setRwTrendDays(h.rwt || RWT_DEFAULT_WINDOW);
    syncTabs();
  }

  // Once, after the first render() of the page.
  function applyInitialHash() {
    if (hashSync.ready) return;
    hashSync.ready = true;
    try {
      const h = parseHashState(location.hash);
      if (h.any) {
        applyHashState(h);
        state.hashPendingIoc = h.ioc;
      }
    } catch (e) {
      console.error("Couldn't apply the link's view state:", e);
    }
    scheduleHashSync();
  }

  // Open the linked IOC once the data is complete, if the page knows it.
  function openPendingHashIoc() {
    const p = state.hashPendingIoc;
    if (!p || !state.dataComplete) return;
    state.hashPendingIoc = null;
    try {
      const d = state.drawer;
      if (d && d.type === p.type && d.value === p.value) return;
      if (d) closeIocDrawer(false);
      if (iocKnown(p.type, p.value)) openIocDrawer(p.type, p.value, null, true);
    } catch (e) {
      console.error("Couldn't open the linked IOC:", e);
    }
    scheduleHashSync();
  }

  function onHashChange() {
    // Before the first render, applyInitialHash will read the new fragment.
    if (!hashSync.ready) return;
    try {
      const h = parseHashState(location.hash);
      applyHashState(h);
      state.hashPendingIoc = h.ioc;
      if (!h.ioc && state.drawer) closeIocDrawer();
      openPendingHashIoc();
    } catch (e) {
      console.error("Couldn't apply the link's view state:", e);
    }
    scheduleHashSync();
  }

  // Readable percent-encoding: only what would break parsing is escaped.
  function encodeHashValue(v) {
    return encodeURIComponent(v).replace(/%3A/gi, ":").replace(/%2F/gi, "/").replace(/%40/gi, "@").replace(/%2C/gi, ",");
  }

  // Current view -> fragment string without "#", or "" for the default view.
  // mode:
  //   "live" (default) what the address bar shows as you work. Search text
  //                    and the open IOC are left out: they'd otherwise be
  //                    written to browser history (and history sync) on
  //                    every keystroke, and analysts paste internal IPs and
  //                    client domains into searches.
  //   "view"           everything, for the deck's "Copy link" button.
  //   "ioc"            only the open IOC, for the drawer's "Copy link".
  function buildHash(mode = "live") {
    if (mode === "ioc") {
      const d = state.drawer;
      return d ? `ioc=${encodeHashValue(`${d.type}:${d.value}`)}` : "";
    }
    const full = mode === "view";
    const pairs = [];
    const tabName = HASH_TAB_NAMES.get(state.preferredTab) || null;
    if (tabName && tabName !== "correlated") pairs.push(["tab", tabName]);

    const table = hashTableFor(tabName);
    if (table) {
      const ts = state.tableState[table];
      const def = FEED_DEFS[table].defaultSort;
      if (full && ts?.query) pairs.push(["q", ts.query.slice(0, HASH_Q_MAX)]);
      if (ts?.sortKey && (ts.sortKey !== def.key || ts.sortDir !== def.dir)) pairs.push(["sort", `${ts.sortKey}:${ts.sortDir}`]);
    } else if (tabName === "uk_news") {
      if (full && state.newsQuery) pairs.push(["q", state.newsQuery.slice(0, HASH_Q_MAX)]);
      if (state.newsUkOnly) pairs.push(["uk", "1"]);
    }
    if (tabName === "ransomware_victims" && state.rwTrendDays !== RWT_DEFAULT_WINDOW && rwTrendsModel()) {
      pairs.push(["rwt", String(state.rwTrendDays)]);
    }

    const ioc = full && (state.drawer || state.hashPendingIoc);
    if (ioc) pairs.push(["ioc", `${ioc.type}:${ioc.value}`]);
    if (state.rwCountry) pairs.push(["cc", state.rwCountry]);

    return pairs.map(([k, v]) => `${k}=${encodeHashValue(v)}`).join("&");
  }

  function shareUrl(mode) {
    const frag = buildHash(mode);
    return location.href.split("#")[0] + (frag ? `#${frag}` : "");
  }

  function writeHashNow() {
    clearTimeout(hashSync.timer);
    hashSync.timer = null;
    if (!hashSync.ready) return;
    try {
      const frag = buildHash();
      const hasHash = location.href.includes("#");
      if (frag ? location.hash === `#${frag}` : !hasHash) return;
      const base = location.pathname + location.search;
      history.replaceState(history.state, "", frag ? `${base}#${frag}` : base);
    } catch (e) {
      /* history API unavailable (sandboxed frame etc.): the URL just won't track */
    }
  }

  // Called from anything that changes shareable state; cheap, so callers
  // don't need to check whether anything actually changed.
  function scheduleHashSync() {
    if (!hashSync.ready) return;
    clearTimeout(hashSync.timer);
    hashSync.timer = setTimeout(writeHashNow, HASH_SYNC_MS);
  }

  // ---- "Copy link" buttons ----

  const COPY_UI = {
    deck: { btn: "deck-copy-link", status: "deck-copy-status", fallback: "deck-copy-fallback" },
    drawer: { btn: "drawer-copy-link", status: "drawer-copy-status", fallback: "drawer-copy-fallback", row: "drawer-copy-row" },
  };
  const copyTimers = {};

  // The drawer keeps its status and fallback in a row of their own, shown only when in use.
  function syncCopyRow(which) {
    const ui = COPY_UI[which];
    const row = ui.row && $(ui.row);
    if (row) row.hidden = !$(ui.status)?.textContent && $(ui.fallback)?.hidden !== false;
  }

  function resetCopyUi(which) {
    const ui = COPY_UI[which];
    clearTimeout(copyTimers[which]);
    const status = $(ui.status);
    const fallback = $(ui.fallback);
    if (status) status.textContent = "";
    if (fallback) {
      fallback.hidden = true;
      fallback.value = "";
    }
    syncCopyRow(which);
  }

  async function writeClipboard(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) {
      /* denied, or not a secure context */
    }
    return false;
  }

  async function copyLink(which) {
    const ui = COPY_UI[which];
    const status = $(ui.status);
    const fallback = $(ui.fallback);
    writeHashNow();
    // The address bar leaves out search text and the IOC (see buildHash);
    // the copied link has them. The drawer's button shares only its IOC.
    const url = shareUrl(which === "drawer" ? "ioc" : "view");
    resetCopyUi(which);
    let ok = await writeClipboard(url);
    if (!ok && fallback) {
      // Show the link selected so it can be copied by hand.
      fallback.value = url;
      fallback.hidden = false;
      syncCopyRow(which);
      fallback.focus();
      fallback.select();
      try {
        ok = document.execCommand("copy");
      } catch (e) {
        ok = false;
      }
    }
    if (status) status.textContent = ok ? "Copied" : "Copy the selected link";
    syncCopyRow(which);
    if (ok) {
      copyTimers[which] = setTimeout(() => {
        if (status) status.textContent = "";
        syncCopyRow(which);
      }, 2000);
    }
  }

  function initShareLinks() {
    // Coalesce bursts (e.g. a script rewriting the fragment in a loop) into
    // one apply per frame; the handler reads location.hash itself.
    let hashFrame = 0;
    window.addEventListener("hashchange", () => {
      if (hashFrame) return;
      hashFrame = requestAnimationFrame(() => {
        hashFrame = 0;
        onHashChange();
      });
    });
    window.addEventListener("pagehide", writeHashNow);
    for (const which of Object.keys(COPY_UI)) {
      const btn = $(COPY_UI[which].btn);
      if (btn) btn.addEventListener("click", () => copyLink(which));
      const fallback = $(COPY_UI[which].fallback);
      if (fallback)
        fallback.addEventListener("blur", () => {
          fallback.hidden = true;
          syncCopyRow(which);
        });
    }
  }

  // ---------- UK cyber security news (last 48h) ----------

  const NEWS_WINDOW_HOURS = 48;

  // The fetcher already trims to 48h, but re-check against the browser's
  // clock so a stale data file never shows week-old headlines.
  function ukNewsItems() {
    const cutoff = Date.now() - NEWS_WINDOW_HOURS * 3600 * 1000;
    return (state.ukNews?.items || []).filter((i) => {
      const t = new Date(i.published).getTime();
      return !isNaN(t) && t >= cutoff;
    });
  }

  function renderUkNews() {
    const section = $("section-uk_news");
    if (!section) return;
    scheduleHashSync(); // search / "UK only" may have changed
    // No data file yet: keep the tab hidden rather than show an empty panel.
    section.hidden = !state.ukNews;
    if (!state.ukNews) return;

    const all = ukNewsItems();
    const q = state.newsQuery.trim().toLowerCase();
    const shown = all.filter(
      (i) =>
        (!state.newsUkOnly || i.uk_focus) &&
        (!q || `${i.title} ${i.summary} ${i.source}`.toLowerCase().includes(q))
    );

    const sources = state.ukNews.sources || [];
    const failed = sources.filter((s) => s.status !== "ok").map((s) => s.name);
    const status = $("status-uk_news");
    status.className = `feed-status ${failed.length ? "pending" : "ok"}`;
    status.textContent = failed.length ? `${failed.length} source${failed.length === 1 ? "" : "s"} down` : "ok";
    status.title = failed.length ? `Failed: ${failed.join(", ")}` : "";

    const gen = state.ukNews.generated_at;
    $("news-meta").textContent =
      `${shown.length} of ${all.length} headlines · ${sources.length} UK outlets · ` +
      `synced ${gen ? relativeTime(gen) : "unknown"}`;

    const newSet = state.since.newSets.news;
    $("news-list").innerHTML = shown
      .map((i) => {
        const safeLink = /^https?:\/\//i.test(i.link || "") ? i.link : "#";
        const isNew = newSet.has(i.link);
        return `<li class="news-item${isNew ? " is-new" : ""}">
          <div class="news-line">
            <span class="news-source">${escapeHtml(i.source)}</span>
            ${i.uk_focus ? `<span class="news-uk" title="Story mentions the UK">UK</span>` : ""}
            ${isNew ? NEW_BADGE : ""}
            <time datetime="${escapeHtml(i.published)}" title="${escapeHtml(i.published)}">${escapeHtml(relativeTime(i.published))}</time>
          </div>
          <a class="news-title" href="${escapeHtml(safeLink)}" target="_blank" rel="noopener noreferrer">${escapeHtml(i.title)}</a>
          ${i.summary ? `<p class="news-summary">${escapeHtml(i.summary)}</p>` : ""}
        </li>`;
      })
      .join("");
    const empty = $("news-empty");
    empty.hidden = shown.length > 0;
    empty.textContent = all.length
      ? `None of the ${all.length} headlines match the current search or filter. Clear the search box to see them.`
      : `No headlines in the last ${NEWS_WINDOW_HOURS} hours.`;

    const count = $("tabcount-uk_news");
    if (count) count.textContent = all.length ? String(all.length) : "";
  }

  function initUkNews() {
    const search = $("news-search");
    const ukOnly = $("news-uk-only");
    if (search)
      search.addEventListener("input", () => {
        state.newsQuery = search.value;
        renderUkNews();
      });
    if (ukOnly)
      ukOnly.addEventListener("change", () => {
        state.newsUkOnly = ukOnly.checked;
        renderUkNews();
      });
  }

  // ---------- "New since your last visit" ----------
  //
  // Items are tracked by identity, not by date: feeds backdate entries and
  // KEV's date_added is only a day. Four categories: KEV (cve_id),
  // ransomware victims (url, else group|victim), correlated IOCs with at
  // least SEEN_IOC_MIN_SIGNALS signals (type|value) and UK news (link). The
  // bulk feeds churn too much for "new" to mean anything, so they're left out.
  //
  // localStorage holds two keys:
  //   SEEN_ACTIVE_KEY  last time the page was in use (ms since epoch)
  //   SEEN_KEY         { v, baseline, baselineAt, baselineKind, pending, pendingAt }
  // `baseline` is what an item is compared against for the whole visit: the
  // ids on screen at the end of the previous visit. `pending` is re-captured
  // after every full load of this visit (including auto-refresh), so it
  // always holds the latest ids, and becomes the baseline when the next
  // visit starts. A visit starts when the page is loaded, or the
  // tab comes back into view, more than VISIT_GAP_MINUTES after it was last
  // in use, so reloads and the 30-min auto-refresh keep the same baseline.
  // Every id list is { kev, rw, ioc, news }, each an array of strings, or
  // null when there's nothing to compare against for that category.

  const SEEN_KEY = "ctd-seen";
  const SEEN_ACTIVE_KEY = "ctd-seen-active";
  const VISIT_GAP_MINUTES = 60;
  const SEEN_IOC_MIN_SIGNALS = 2;
  const SEEN_MAX_IDS = 20000; // per category; anything bigger is treated as corrupt
  const SEEN_CATS = ["kev", "rw", "ioc", "news"];
  const NEW_BADGE = ` <span class="badge badge-new" title="New since your last visit">NEW</span>`;

  // Summary order, wording, and where each part jumps to.
  const SINCE_PARTS = [
    { cat: "kev", one: "KEV", many: "KEV", tab: "section-cisa_kev", table: "cisa_kev" },
    { cat: "rw", one: "victim", many: "victims", tab: "section-ransomware_victims", table: "ransomware_victims" },
    { cat: "ioc", one: "correlated IOC", many: "correlated IOCs", tab: "section-correlated", table: "correlated" },
    { cat: "news", one: "headline", many: "headlines", tab: "section-uk_news", table: null },
  ];

  function rwSeenKey(v) {
    return typeof v.url === "string" && v.url ? v.url : `${v.group || ""}|${v.victim || ""}`;
  }

  function iocSeenKey(c) {
    return `${c.type}|${c.value}`;
  }

  // Distinct non-empty strings, or null when there are none (an empty or
  // missing source carries the previous baseline forward rather than
  // making every item in it look new next time).
  function seenIdList(ids) {
    const out = Array.from(new Set(ids.filter((x) => typeof x === "string" && x)));
    // Same cap the reader enforces (parseSeenLists rejects longer lists), so a
    // category that ever outgrows it can't silently disable the feature.
    // Unreachable today (KEV, the largest, is ~1,800).
    return out.length ? out.slice(0, SEEN_MAX_IDS) : null;
  }

  // undefined = malformed (the whole record is then ignored).
  function parseSeenLists(raw) {
    if (raw === null) return null;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
    const out = {};
    for (const cat of SEEN_CATS) {
      const list = raw[cat];
      if (list === null || list === undefined) {
        out[cat] = null;
      } else if (Array.isArray(list) && list.length <= SEEN_MAX_IDS && list.every((x) => typeof x === "string")) {
        out[cat] = list;
      } else {
        return undefined;
      }
    }
    return out;
  }

  // Rejects times more than a day in the future too: beyond JS's date range
  // (8.64e15 ms) toISOString() throws, and no real stored time is ahead of now.
  function seenTime(x) {
    return typeof x === "number" && Number.isFinite(x) && x > 0 && x <= Date.now() + 86400000 ? x : null;
  }

  // Anything unexpected reads as "no baseline", i.e. a first visit.
  function readSeenRecord() {
    let raw = null;
    try {
      raw = localStorage.getItem(SEEN_KEY);
    } catch (e) {
      return null;
    }
    if (!raw) return null;
    let rec;
    try {
      rec = JSON.parse(raw);
    } catch (e) {
      return null;
    }
    if (!rec || typeof rec !== "object" || Array.isArray(rec) || rec.v !== 1) return null;
    const baseline = parseSeenLists(rec.baseline);
    const pending = parseSeenLists(rec.pending);
    if (baseline === undefined || pending === undefined) return null;
    return {
      v: 1,
      baseline,
      baselineAt: seenTime(rec.baselineAt),
      baselineKind: rec.baselineKind === "marked" ? "marked" : "visit",
      pending,
      pendingAt: seenTime(rec.pendingAt),
    };
  }

  function writeSeenRecord(rec) {
    try {
      localStorage.setItem(SEEN_KEY, JSON.stringify(rec));
      return true;
    } catch (e) {
      return false;
    }
  }

  function readLastActive() {
    try {
      const raw = localStorage.getItem(SEEN_ACTIVE_KEY);
      return raw ? seenTime(Number(raw)) : null;
    } catch (e) {
      return null;
    }
  }

  function touchActive() {
    try {
      localStorage.setItem(SEEN_ACTIVE_KEY, String(Date.now()));
      return true;
    } catch (e) {
      return false;
    }
  }

  function setSeenRecord(rec) {
    const s = state.since;
    s.record = rec;
    s.baseline = null;
    if (rec && rec.baseline) {
      s.baseline = {};
      for (const cat of SEEN_CATS) s.baseline[cat] = rec.baseline[cat] ? new Set(rec.baseline[cat]) : null;
    }
  }

  // Storage blocked or full: drop the feature (and its record, so a stale
  // half-written state can't come back later) and clear any badges.
  function disableSince() {
    const s = state.since;
    s.enabled = false;
    s.newOnly = {};
    setSeenRecord(null);
    try {
      localStorage.removeItem(SEEN_KEY);
    } catch (e) {
      /* storage unavailable */
    }
    rerenderSince();
  }

  // The previous visit's capture becomes this visit's baseline.
  function startVisit() {
    const rec = readSeenRecord();
    if (!rec) {
      setSeenRecord(null); // first visit (or unreadable record): nothing is new
      return;
    }
    const next = rec.pending
      ? { ...rec, baseline: rec.pending, baselineAt: rec.pendingAt, baselineKind: "visit", pending: null, pendingAt: null }
      : rec; // the last visit never finished loading; keep its baseline
    if (next !== rec && !writeSeenRecord(next)) {
      disableSince();
      return;
    }
    setSeenRecord(next);
  }

  // A timestamp from the future (clock changed) counts as idle too, so a
  // wrong clock can't hold one visit open indefinitely.
  function isIdle(lastActive) {
    const gap = Date.now() - (lastActive ?? 0);
    return lastActive === null || gap > VISIT_GAP_MINUTES * 60000 || gap < -60000;
  }

  // Built once per render; rows then check membership in O(1).
  function computeSince() {
    const s = state.since;
    s.newSets = { kev: new Set(), rw: new Set(), ioc: new Set(), news: new Set() };
    if (!s.enabled) {
      s.current = null;
      return;
    }
    s.current = {
      kev: seenIdList((state.snapshot.feeds?.cisa_kev?.items || []).map((v) => v.cve_id)),
      rw: state.ransomwareVictims ? seenIdList((state.ransomwareVictims.victims || []).map(rwSeenKey)) : null,
      ioc: seenIdList((state.correlated || []).filter((c) => c.signalCount >= SEEN_IOC_MIN_SIGNALS).map(iocSeenKey)),
      news: state.ukNews ? seenIdList(ukNewsItems().map((i) => i.link)) : null,
    };
    if (!s.baseline) return;
    for (const cat of SEEN_CATS) {
      const base = s.baseline[cat];
      const cur = s.current[cat];
      if (base && cur) s.newSets[cat] = new Set(cur.filter((id) => !base.has(id)));
    }
  }

  // Current ids per category, falling back to `fallback` where a source is
  // empty or didn't load.
  function currentSeenLists(fallback) {
    const out = {};
    for (const cat of SEEN_CATS) out[cat] = state.since.current?.[cat] || fallback?.[cat] || null;
    return out;
  }

  // After each complete load: record activity, and capture the ids now on
  // screen. The last capture of a visit becomes the next visit's baseline,
  // so items first seen part-way through this visit aren't flagged again.
  // The capture replaces the previous one rather than adding to it (feeds
  // drop old items, so a running union would only grow); a source that is
  // empty or failed this time keeps its previous ids.
  function sinceAfterLoad() {
    const s = state.since;
    if (!s.enabled) return;
    touchActive();
    const rec = s.record;
    const now = Date.now();
    const next = rec
      ? { ...rec, pending: currentSeenLists(rec.pending || rec.baseline), pendingAt: now }
      : { v: 1, baseline: null, baselineAt: null, baselineKind: "visit", pending: currentSeenLists(null), pendingAt: now };
    if (!writeSeenRecord(next)) {
      disableSince();
      return;
    }
    setSeenRecord(next);
  }

  function markAllSeen() {
    const s = state.since;
    if (!s.enabled) return;
    const lists = currentSeenLists(s.record?.baseline);
    const now = Date.now();
    const next = { v: 1, baseline: lists, baselineAt: now, baselineKind: "marked", pending: lists, pendingAt: now };
    if (!writeSeenRecord(next)) {
      disableSince();
      return;
    }
    setSeenRecord(next);
    s.newOnly = {};
    rerenderSince();
  }

  // Re-render just what shows "new" state (cheaper than a full render()).
  function rerenderSince() {
    if (!state.snapshot) return;
    computeSince();
    renderCorrelated();
    renderFeed("cisa_kev");
    renderFeed("ransomware_victims");
    renderRansomwarePanels();
    renderUkNews();
    renderSinceSummary();
  }

  function isNewOnly(table) {
    const part = SINCE_PARTS.find((p) => p.table === table);
    return Boolean(part && state.since.newOnly[table] && state.since.newSets[part.cat].size > 0);
  }

  // The "new only" checkbox only shows while that table has new rows.
  function syncNewOnlyToggle(table) {
    const input = document.querySelector(`.new-only[data-feed="${table}"]`);
    if (!input) return;
    const part = SINCE_PARTS.find((p) => p.table === table);
    const n = part ? state.since.newSets[part.cat].size : 0;
    const label = input.closest(".new-only-toggle");
    label.hidden = n === 0;
    input.checked = isNewOnly(table);
    const count = label.querySelector(".new-only-count");
    if (count) count.textContent = n ? `(${n.toLocaleString()})` : "";
  }

  function renderSinceSummary() {
    const panel = $("since-panel");
    if (!panel) return;
    const s = state.since;
    const parts = SINCE_PARTS.filter((p) => s.newSets[p.cat].size > 0);
    panel.hidden = !s.enabled || !s.baseline || !parts.length;
    if (panel.hidden) return;

    const at = s.record?.baselineAt;
    $("since-title").textContent = s.record?.baselineKind === "marked" ? "Since you marked all as seen" : "Since your last visit";
    // relativeTime() takes the number directly and returns "unknown" for a bad date, never throws.
    $("since-when").textContent = at ? `(${relativeTime(at)})` : "";
    $("since-list").innerHTML = parts
      .map((p) => {
        const n = s.newSets[p.cat].size;
        let watched = 0;
        if (p.cat === "kev") for (const id of s.newSets.kev) if (state.kevWatch.termFor.has(id)) watched++;
        const watchedBtn = watched
          ? ` <button type="button" class="since-jump since-watched link-btn" data-since-cat="kev" data-since-watched="1" title="New KEV entries matching your vendor watchlist">(${watched.toLocaleString()} watched)</button>`
          : "";
        return `<li><button type="button" class="since-jump link-btn" data-since-cat="${escapeHtml(p.cat)}"><span class="since-n">${n.toLocaleString()}</span> ${escapeHtml(n === 1 ? p.one : p.many)}</button>${watchedBtn}</li>`;
      })
      .join("");
  }

  // Jump to a category's tab; for tables, switch on "new only" so the new
  // rows are what's on screen (and, for "(n watched)", "watched only" too).
  function jumpToNew(cat, watched) {
    const part = SINCE_PARTS.find((p) => p.cat === cat);
    const section = part && $(part.tab);
    if (!section || section.hidden) return;
    if (part.table) {
      state.since.newOnly[part.table] = true;
      if (part.table === "cisa_kev") state.kevWatch.watchedOnly = Boolean(watched);
      if (part.table === "correlated") renderCorrelated();
      else renderFeed(part.table);
    }
    activateTab(section.id, true);
    section.scrollIntoView({ behavior: "smooth", block: "start" });
    section.classList.add("flash-highlight");
    setTimeout(() => section.classList.remove("flash-highlight"), 1500);
  }

  function initSince() {
    // Blocked storage: the feature never switches on.
    const lastActive = readLastActive();
    if (!touchActive()) return;
    state.since.enabled = true;
    if (isIdle(lastActive)) startVisit();
    else setSeenRecord(readSeenRecord());

    // Hidden = stopped looking. Coming back after the gap starts a new
    // visit; the auto-refresh that follows captures its ids.
    document.addEventListener("visibilitychange", () => {
      if (!state.since.enabled) return;
      if (!document.hidden && isIdle(readLastActive())) {
        startVisit();
        if (state.since.enabled) rerenderSince();
      }
      touchActive();
    });
    window.addEventListener("pagehide", () => {
      if (state.since.enabled) touchActive();
    });
    // Another tab started a visit or marked all as seen.
    window.addEventListener("storage", (ev) => {
      if (!state.since.enabled || (ev.key !== null && ev.key !== SEEN_KEY)) return;
      setSeenRecord(readSeenRecord());
      rerenderSince();
    });

    const panel = $("since-panel");
    if (panel) {
      panel.addEventListener("click", (ev) => {
        const jump = ev.target.closest(".since-jump");
        if (jump) {
          jumpToNew(jump.getAttribute("data-since-cat"), jump.hasAttribute("data-since-watched"));
          return;
        }
        if (ev.target.closest("#since-mark-seen")) {
          markAllSeen();
          // The panel (and the focused button) just hid; keep focus nearby.
          const tab = document.querySelector('.deck-tab[aria-selected="true"]');
          if (tab) tab.focus({ preventScroll: true });
        }
      });
    }

    document.addEventListener("change", (ev) => {
      const input = ev.target.closest(".new-only[data-feed]");
      if (!input) return;
      const table = input.getAttribute("data-feed");
      state.since.newOnly[table] = input.checked;
      if (table === "correlated") renderCorrelated();
      else renderFeed(table);
    });
  }

  // ---------- Ransomware: last 72h (globe + side panels) ----------

  const RW_WINDOW_HOURS = 72;
  const RW_FRESH_HOURS = 6;

  // ransomware.live's "discovered" date (stored as `published`) is when the
  // victim appeared on a leak site, not when the attack happened.
  // ransomware.live dates look like "2026-10-22T23:40:29.746474+00:00" (or
  // with a space instead of "T", no zone). Trim to millisecond precision and
  // assume UTC when no zone is given, so every browser parses them the same.
  function parseRwTime(str) {
    if (!str) return NaN;
    let s = String(str).trim().replace(" ", "T").replace(/(\.\d{3})\d+/, "$1");
    if (!/(Z|[+-]\d{2}:?\d{2})$/.test(s)) s += "Z";
    return new Date(s).getTime();
  }

  function computeRansomwareWindow() {
    const cutoff = Date.now() - RW_WINDOW_HOURS * 3600 * 1000;
    const victims = (state.ransomwareVictims?.victims || [])
      .map((v) => ({ v, t: parseRwTime(v.published) }))
      .filter((x) => !isNaN(x.t) && x.t >= cutoff)
      .sort((a, b) => b.t - a.t);

    const byCountry = new Map();
    const byGroup = new Map();
    let unlocated = 0;
    for (const { v, t } of victims) {
      const group = (v.group || "").trim() || "unknown";
      byGroup.set(group, (byGroup.get(group) || 0) + 1);
      const code = (v.country || "").trim().toUpperCase();
      if (!/^[A-Z]{2}$/.test(code)) {
        unlocated += 1;
        continue;
      }
      let c = byCountry.get(code);
      if (!c) {
        c = { code, count: 0, groups: new Map(), latest: 0 };
        byCountry.set(code, c);
      }
      c.count += 1;
      c.groups.set(group, (c.groups.get(group) || 0) + 1);
      c.latest = Math.max(c.latest, t);
    }
    return { loaded: !!state.ransomwareVictims, victims, byCountry, byGroup, unlocated };
  }

  function barListHtml(entries, labelFn, titleFn, dataAttr) {
    const max = entries.length ? entries[0][1] : 0;
    return entries
      .map(([key, count]) => {
        const pct = max ? Math.max(4, Math.round((count / max) * 100)) : 0;
        const attr = dataAttr ? ` ${dataAttr}="${escapeHtml(key)}" tabindex="0" role="button"` : "";
        return `<div class="bar-row"${attr} title="${escapeHtml(titleFn(key, count))}">
          <span class="bar-label">${escapeHtml(labelFn(key))}</span>
          <span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span>
          <span class="bar-count">${count}</span>
        </div>`;
      })
      .join("");
  }

  function renderRansomwarePanels() {
    const rw = state.rw;
    if (!rw) return;
    const dash = "—";
    $("rw-stat-victims").textContent = rw.loaded ? rw.victims.length : dash;
    $("rw-stat-countries").textContent = rw.loaded ? rw.byCountry.size : dash;
    $("rw-stat-groups").textContent = rw.loaded ? rw.byGroup.size : dash;
    $("rw-stat-unlocated").textContent = rw.unlocated
      ? `${rw.unlocated} victim${rw.unlocated === 1 ? "" : "s"} without a listed country (not on globe)`
      : "";
    const gen = state.ransomwareVictims?.generated_at;
    $("globe-sub").textContent = gen ? `ransomware.live · synced ${relativeTime(gen)}` : "ransomware.live";

    // Live feed, optionally filtered to the country picked on the globe.
    const filter = state.rwCountry;
    const filterBtn = $("rw-filter");
    filterBtn.hidden = !filter;
    if (filter) filterBtn.textContent = `${countryName(filter)} ✕`;

    const freshCutoff = Date.now() - RW_FRESH_HOURS * 3600 * 1000;
    const rows = rw.victims.filter(({ v }) => !filter || (v.country || "").toUpperCase() === filter);
    const newSet = state.since.newSets.rw;
    $("rw-feed").innerHTML = rows
      .map(({ v, t }) => {
        const code = (v.country || "").trim().toUpperCase();
        const chip = /^[A-Z]{2}$/.test(code)
          ? `<span class="cc-chip" title="${escapeHtml(countryName(code))}">${escapeHtml(code)}</span>`
          : `<span class="cc-chip cc-unknown" title="No country listed">??</span>`;
        const isNew = newSet.has(rwSeenKey(v));
        const cls = [t >= freshCutoff ? "is-fresh" : "", isNew ? "is-new" : ""].filter(Boolean).join(" ");
        return `<li tabindex="0" data-q="${escapeHtml(v.victim || "")}" class="${cls}">
          <span class="rw-victim" title="${escapeHtml(v.victim || "")}">${escapeHtml(v.victim || "Unknown victim")}</span>
          <span class="rw-group">${escapeHtml(v.group || "unknown group")}${isNew ? NEW_BADGE : ""}</span>
          <span class="rw-meta">${chip}<span>${escapeHtml(relativeTime(new Date(t).toISOString()))}</span></span>
        </li>`;
      })
      .join("");
    $("rw-feed-empty").hidden = !rw.loaded || rows.length > 0;

    const countries = Array.from(rw.byCountry.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)
      .map((c) => [c.code, c.count]);
    $("rw-countries").innerHTML = barListHtml(
      countries,
      (code) => code,
      (code, n) => `${countryName(code)}: ${n} victim${n === 1 ? "" : "s"} — click to filter`,
      "data-country"
    );

    const groups = Array.from(rw.byGroup.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
    $("rw-groups").innerHTML = barListHtml(groups, (g) => g, (g, n) => `${g}: ${n} victim${n === 1 ? "" : "s"}`, null);
  }

  function setRwCountry(code) {
    state.rwCountry = code || null;
    renderRansomwarePanels();
    scheduleHashSync();
    const c = code && globeState.centroids?.[code];
    if (globeState.globe && c) {
      globeState.globe.controls().autoRotate = false;
      globeState.globe.pointOfView({ lat: c[0], lng: c[1], altitude: 1.7 }, 1200);
    } else if (globeState.globe && !code) {
      globeState.globe.controls().autoRotate = !prefersReducedMotion();
    }
  }

  // Delegated once; the lists themselves are re-rendered on each render().
  function initRansomwarePanels() {
    const activate = (ev, fn) => {
      if (ev.type === "keydown" && ev.key !== "Enter" && ev.key !== " ") return;
      if (ev.type === "keydown") ev.preventDefault();
      fn();
    };
    const feed = $("rw-feed");
    ["click", "keydown"].forEach((type) =>
      feed.addEventListener(type, (ev) => {
        const li = ev.target.closest("li[data-q]");
        if (li) activate(ev, () => scrollToMatch("ransomware_victims", li.getAttribute("data-q")));
      })
    );
    const bars = $("rw-countries");
    ["click", "keydown"].forEach((type) =>
      bars.addEventListener(type, (ev) => {
        const row = ev.target.closest("[data-country]");
        if (row) activate(ev, () => setRwCountry(row.getAttribute("data-country")));
      })
    );
    $("rw-filter").addEventListener("click", () => setRwCountry(null));
  }

  // ---------- Ransomware: 90-day trends (data/ransomware_trends.json) ----------
  //
  // Daily counts from scripts/fetch_ransomware_trends.py, by the same
  // `discovered` date as the 72h view. Each day has a total plus its top
  // names per group / country / sector and an "other" count for the rest,
  // so window totals are exact and per-name sums very close. Names come
  // from ransomware.live (attacker-influenced) and are escaped everywhere.
  // A missing or malformed file keeps the whole area hidden.

  const RWT_WINDOWS = [7, 30, 90];
  const RWT_DEFAULT_WINDOW = 30;
  const RWT_AXIS_DAYS = 90;
  const RWT_TOP = 8;
  const RWT_RISING = 5;
  const RWT_RISING_MIN = 3; // a rise to fewer victims than this is noise
  const RWT_UNKNOWN = "-"; // the script's key for a missing country / sector / group
  const RWT_DIMS = ["groups", "countries", "sectors"];
  const RWT_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
  const rwtCache = { raw: null, model: null };

  function rwtCount(v) {
    return Number.isInteger(v) && v >= 0 && v <= 1e6 ? v : null;
  }

  function rwtCounts(obj) {
    const out = new Map();
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return out;
    for (const [k, v] of Object.entries(obj)) {
      const n = rwtCount(v);
      if (n && k.length <= 200) out.set(k, n);
    }
    return out;
  }

  function rwtAddDays(date, delta) {
    const t = Date.UTC(+date.slice(0, 4), +date.slice(5, 7) - 1, +date.slice(8, 10)) + delta * 86400000;
    return new Date(t).toISOString().slice(0, 10);
  }

  function rwtDayLabel(date) {
    return new Date(`${date}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
  }

  // Validated, gap-aware model of the file, or null. Rebuilt only when a
  // new file has been loaded, so render() stays cheap.
  function rwTrendsModel() {
    const raw = state.ransomwareTrends;
    if (rwtCache.raw === raw) return rwtCache.model;
    rwtCache.raw = raw;
    rwtCache.model = null;
    if (!raw || typeof raw !== "object" || !Array.isArray(raw.days)) return null;

    const byDate = new Map();
    for (const d of raw.days) {
      if (!d || typeof d !== "object" || typeof d.date !== "string" || !RWT_DATE_RE.test(d.date)) continue;
      const total = rwtCount(d.total);
      if (total === null || isNaN(Date.parse(d.date))) continue;
      const day = { total, other: {} };
      for (const dim of RWT_DIMS) {
        day[dim] = rwtCounts(d[dim]);
        day.other[dim] = rwtCount(d.other?.[dim]) || 0;
      }
      byDate.set(d.date, day);
    }
    if (!byDate.size) return null;

    const last = Array.from(byDate.keys()).sort().pop();
    const axis = [];
    for (let i = RWT_AXIS_DAYS - 1; i >= 0; i--) axis.push(rwtAddDays(last, -i));
    const series = axis.map((date) => (byDate.has(date) ? byDate.get(date).total : null));
    // Trailing 7-day mean over the days that have data; a break where fewer than 4 do.
    const avg = series.map((_, i) => {
      const win = series.slice(Math.max(0, i - 6), i + 1).filter((v) => v !== null);
      return win.length >= 4 ? win.reduce((a, b) => a + b, 0) / win.length : null;
    });
    rwtCache.model = { byDate, last, axis, series, avg, labels: axis.map(rwtDayLabel), generatedAt: raw.generated_at };
    return rwtCache.model;
  }

  // Sums over `n` axis days ending `offset` days before the last one.
  function rwtWindow(m, n, offset) {
    const dates = m.axis.slice(m.axis.length - offset - n, m.axis.length - offset);
    const w = { n, total: 0, covered: 0, other: { groups: 0, countries: 0, sectors: 0 } };
    for (const dim of RWT_DIMS) w[dim] = new Map();
    for (const date of dates) {
      const day = m.byDate.get(date);
      if (!day) continue;
      w.covered += 1;
      w.total += day.total;
      for (const dim of RWT_DIMS) {
        for (const [k, v] of day[dim]) w[dim].set(k, (w[dim].get(k) || 0) + v);
        w.other[dim] += day.other[dim];
      }
    }
    return w;
  }

  // The window and the one before it; prior is null when it isn't in the file.
  function rwtCompare(m, n) {
    return { cur: rwtWindow(m, n, 0), prior: 2 * n <= m.axis.length ? rwtWindow(m, n, n) : null };
  }

  function rwtSigned(n) {
    return n > 0 ? `+${n.toLocaleString()}` : n < 0 ? `−${Math.abs(n).toLocaleString()}` : "0";
  }

  function rwtNiceMax(v) {
    if (v <= 5) return 5;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const s of [1, 2, 2.5, 5, 10]) if (s * p >= v) return s * p;
    return 10 * p;
  }

  function rwtName(dim, key) {
    if (key === RWT_UNKNOWN) return dim === "countries" ? "Not listed" : "Unknown";
    return dim === "countries" ? `${key} · ${countryName(key)}` : key;
  }

  function rwtChartHtml(m, n) {
    const W = m.axis.length;
    const peak = Math.max(1, ...m.series.map((v) => v || 0));
    const top = rwtNiceMax(peak);
    const y = (v) => (100 - (v / top) * 100).toFixed(2);
    const bars = m.series
      .map((v, i) => (v ? `<rect class="rwt-bar" x="${i + 0.15}" y="${y(v)}" width="0.7" height="${((v / top) * 100).toFixed(2)}"/>` : ""))
      .join("");
    let path = "";
    let pen = false;
    m.avg.forEach((v, i) => {
      if (v === null) {
        pen = false;
        return;
      }
      path += `${pen ? "L" : "M"}${(i + 0.5).toFixed(1)} ${y(v)}`;
      pen = true;
    });
    const grid = [0, 0.5, 1]
      .map((f) => `<line class="rwt-grid" x1="0" x2="${W}" y1="${(100 - f * 100).toFixed(2)}" y2="${(100 - f * 100).toFixed(2)}" vector-effect="non-scaling-stroke"/>`)
      .join("");

    const present = m.series.filter((v) => v !== null);
    const sum = present.reduce((a, b) => a + b, 0);
    const peakIdx = m.series.indexOf(peak);
    const label =
      `Daily ransomware victims by discovered date, ${m.labels[0]} to ${m.labels[W - 1]}: ` +
      `${sum.toLocaleString()} victims over ${present.length} days with data, ` +
      `average ${(sum / Math.max(1, present.length)).toFixed(1)} a day, peak ${peak.toLocaleString()} on ${m.labels[peakIdx] || "?"}. ` +
      `Full figures are in the daily counts table.`;
    const mid = Math.floor((W - 1) / 2);
    return `<div class="rwt-plot">
        <span class="rwt-ylab" style="top:0">${top.toLocaleString()}</span>
        <span class="rwt-ylab" style="top:50%">${(top / 2).toLocaleString()}</span>
        <span class="rwt-ylab" style="top:100%">0</span>
        <svg class="rwt-svg" viewBox="0 0 ${W} 100" preserveAspectRatio="none" role="img" aria-label="${escapeHtml(label)}">
          <rect class="rwt-window" x="${W - n}" y="0" width="${n}" height="100"/>
          ${grid}${bars}
          <path class="rwt-avg" d="${path}" vector-effect="non-scaling-stroke"/>
          <rect class="rwt-hover" id="rwt-hover" x="0" y="0" width="1" height="100" visibility="hidden"/>
        </svg>
        <div class="rwt-tip" id="rwt-tip" hidden></div>
      </div>
      <div class="rwt-xlabs" aria-hidden="true"><span>${escapeHtml(m.labels[0])}</span><span>${escapeHtml(m.labels[mid])}</span><span>${escapeHtml(m.labels[W - 1])}</span></div>`;
  }

  function rwtTableHtml(m) {
    const rows = m.axis
      .map((date, i) => {
        const v = m.series[i];
        const a = m.avg[i];
        return `<tr><td>${escapeHtml(date)}</td><td class="num">${v === null ? "no data" : v.toLocaleString()}</td><td class="num">${a === null ? "—" : a.toFixed(1)}</td></tr>`;
      })
      .reverse()
      .join("");
    return `<table class="rwt-table"><thead><tr><th scope="col">Date (UTC)</th><th scope="col">Victims</th><th scope="col">7-day avg</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  function rwtDeltaHtml(cur, prior, n) {
    if (prior === null) return "";
    const d = cur - prior;
    const cls = d > 0 ? "up" : d < 0 ? "down" : "flat";
    const txt = prior === 0 && cur > 0 ? "new" : rwtSigned(d);
    return `<span class="rwt-delta ${cls}">${txt}<span class="sr-only"> vs prior ${n} days</span></span>`;
  }

  // Top rows for one dimension. Groups and sectors filter the table below.
  function rwtListHtml(dim, cmp) {
    const { cur, prior } = cmp;
    const n = cur.n;
    const entries = Array.from(cur[dim].entries())
      .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
      .slice(0, RWT_TOP);
    if (!entries.length) return `<p class="rwt-empty">No victims in this window.</p>`;
    const max = entries[0][1];
    const clickable = dim !== "countries";
    const rows = entries
      .map(([key, count]) => {
        const p = prior ? prior[dim].get(key) || 0 : null;
        const name = rwtName(dim, key);
        const pct = Math.max(4, Math.round((count / max) * 100));
        const vs = p === null ? "" : `; ${p.toLocaleString()} in the prior ${n} (${rwtSigned(count - p)})`;
        const canFilter = clickable && key !== RWT_UNKNOWN;
        const tip = `${name}: ${count.toLocaleString()} victim${count === 1 ? "" : "s"} in the last ${n} days${vs}${canFilter ? ". Click to search the recent-victims table" : ""}`;
        const attr = canFilter ? ` data-rwt-q="${escapeHtml(key)}" tabindex="0" role="button"` : "";
        return `<div class="rwt-row${canFilter ? " is-link" : ""}"${attr} title="${escapeHtml(tip)}">
          <span class="bar-label">${escapeHtml(name)}</span>
          <span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span>
          <span class="bar-count">${count.toLocaleString()}</span>
          ${rwtDeltaHtml(count, p, n)}
        </div>`;
      })
      .join("");
    const other = cur.other[dim];
    const note = other ? `<p class="rwt-foot">${other.toLocaleString()} more on busy days not broken out by name.</p>` : "";
    return rows + note;
  }

  // Biggest increases among groups and countries (not "unknown").
  function rwtRisingHtml(cmp) {
    const { cur, prior } = cmp;
    const out = [];
    for (const dim of ["groups", "countries"]) {
      for (const [key, count] of cur[dim]) {
        if (key === RWT_UNKNOWN || count < RWT_RISING_MIN) continue;
        const p = prior[dim].get(key) || 0;
        if (count > p) out.push({ dim, key, count, p, d: count - p });
      }
    }
    out.sort((a, b) => b.d - a.d || b.count - a.count || (a.key < b.key ? -1 : 1));
    const rows = out.slice(0, RWT_RISING);
    if (!rows.length) return `<p class="rwt-empty">Nothing rising against the prior ${cur.n} days.</p>`;
    return `<ol class="rwt-rising">${rows
      .map((r) => {
        const name = rwtName(r.dim, r.key);
        const kind = r.dim === "groups" ? "group" : "country";
        const tip = `${name}: ${r.count} victims in the last ${cur.n} days, ${r.p} in the prior ${cur.n}`;
        return `<li title="${escapeHtml(tip)}"><span class="rwt-kind">${kind}</span><span class="rwt-rname">${escapeHtml(name)}</span><span class="rwt-delta up">${r.p === 0 ? "new" : rwtSigned(r.d)}</span><span class="rwt-rvs">${r.count} vs ${r.p}</span></li>`;
      })
      .join("")}</ol>`;
  }

  function renderRwTrends() {
    const wrap = $("rw-trends");
    if (!wrap) return;
    const m = rwTrendsModel();
    wrap.hidden = !m;
    if (!m) return;
    const n = RWT_WINDOWS.includes(state.rwTrendDays) ? state.rwTrendDays : RWT_DEFAULT_WINDOW;

    wrap.querySelectorAll("[data-rwt-days]").forEach((b) => b.setAttribute("aria-pressed", String(Number(b.dataset.rwtDays) === n)));
    const synced = m.generatedAt ? ` · synced ${relativeTime(m.generatedAt)}` : "";
    $("rwt-sub").textContent = `to ${m.labels[m.labels.length - 1]} (UTC)${synced}`;

    const cmp = rwtCompare(m, n);
    const { cur, prior } = cmp;
    const gaps = cur.covered < n ? ` (data for ${cur.covered} of ${n} days)` : "";
    let vs = "";
    if (prior && prior.covered) {
      const d = cur.total - prior.total;
      const pct = prior.total ? ` (${rwtSigned(Math.round((d / prior.total) * 100))}%)` : "";
      vs = ` · <span class="rwt-delta ${d > 0 ? "up" : d < 0 ? "down" : "flat"}">${rwtSigned(d)}${pct}</span> vs prior ${n} days`;
    }
    $("rwt-summary").innerHTML =
      `<strong>${cur.total.toLocaleString()}</strong> victims in the last ${n} days${escapeHtml(gaps)} · ` +
      `${(cur.total / Math.max(1, cur.covered)).toFixed(1)} a day${vs}`;

    $("rwt-chart").innerHTML = rwtChartHtml(m, n);
    $("rwt-table").innerHTML = rwtTableHtml(m);
    const vsLabel = prior ? `change vs prior ${n}d` : `no prior ${n}d in the 90-day history`;
    wrap.querySelectorAll(".rwt-vs").forEach((el) => (el.textContent = vsLabel));
    $("rwt-groups").innerHTML = rwtListHtml("groups", cmp);
    $("rwt-countries").innerHTML = rwtListHtml("countries", cmp);
    $("rwt-sectors").innerHTML = rwtListHtml("sectors", cmp);
    // 90 days has nothing before it in the file, so "rising" compares 30 days there.
    const risingCmp = prior ? cmp : rwtCompare(m, 30);
    $("rwt-rising-sub").textContent = `last ${risingCmp.cur.n}d vs prior ${risingCmp.cur.n}d`;
    $("rwt-rising").innerHTML = rwtRisingHtml(risingCmp);
  }

  function setRwTrendDays(n) {
    if (!RWT_WINDOWS.includes(n) || n === state.rwTrendDays) return;
    state.rwTrendDays = n;
    renderRwTrends();
    scheduleHashSync();
  }

  function initRwTrends() {
    const wrap = $("rw-trends");
    if (!wrap) return;
    wrap.addEventListener("click", (ev) => {
      const b = ev.target.closest("[data-rwt-days]");
      if (b) setRwTrendDays(Number(b.dataset.rwtDays));
    });
    const lists = ["click", "keydown"];
    lists.forEach((type) =>
      wrap.addEventListener(type, (ev) => {
        const row = ev.target.closest("[data-rwt-q]");
        if (!row) return;
        if (type === "keydown" && ev.key !== "Enter" && ev.key !== " ") return;
        ev.preventDefault();
        const table = document.querySelector("#section-ransomware_victims .table-wrap");
        scrollToMatch("ransomware_victims", row.getAttribute("data-rwt-q"), table);
      })
    );

    // Hover / touch tooltip on the chart: the day under the pointer.
    const chart = $("rwt-chart");
    const hide = () => {
      const tip = $("rwt-tip");
      const hl = $("rwt-hover");
      if (tip) tip.hidden = true;
      if (hl) hl.setAttribute("visibility", "hidden");
    };
    const show = (ev) => {
      const m = rwTrendsModel();
      const svg = chart.querySelector(".rwt-svg");
      const tip = $("rwt-tip");
      const hl = $("rwt-hover");
      if (!m || !svg || !tip || !hl) return;
      const r = svg.getBoundingClientRect();
      if (!r.width) return;
      const i = Math.min(m.axis.length - 1, Math.max(0, Math.floor(((ev.clientX - r.left) / r.width) * m.axis.length)));
      const v = m.series[i];
      const a = m.avg[i];
      tip.textContent = `${m.labels[i]}: ${v === null ? "no data" : `${v.toLocaleString()} victim${v === 1 ? "" : "s"}`}${a === null ? "" : ` · 7-day avg ${a.toFixed(1)}`}`;
      tip.hidden = false;
      const x = ((i + 0.5) / m.axis.length) * r.width;
      const tw = tip.offsetWidth;
      tip.style.left = `${Math.min(Math.max(0, x - tw / 2), Math.max(0, r.width - tw))}px`;
      hl.setAttribute("x", String(i));
      hl.setAttribute("visibility", "visible");
    };
    chart.addEventListener("pointermove", show);
    chart.addEventListener("pointerdown", show);
    chart.addEventListener("pointerleave", hide);
  }

  // ---------- 3D globe (globe.gl, loaded lazily from jsDelivr) ----------

  const GLOBE_LIB_URL = "https://cdn.jsdelivr.net/npm/globe.gl@2.46.2/dist/globe.gl.min.js";
  const TOPOJSON_LIB_URL = "https://cdn.jsdelivr.net/npm/topojson-client@3.1.0/dist/topojson-client.min.js";
  const WORLD_ATLAS_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json";

  const globeState = { globe: null, centroids: null, max: 1 };

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = src;
      s.async = true;
      s.crossOrigin = "anonymous";
      s.onload = resolve;
      s.onerror = () => reject(new Error(`Failed to load ${src}`));
      document.head.appendChild(s);
    });
  }

  async function fetchJsonStrict(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`);
    return resp.json();
  }

  function hasWebGL() {
    try {
      const c = document.createElement("canvas");
      return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
    } catch (e) {
      return false;
    }
  }

  function prefersReducedMotion() {
    return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }

  // world-atlas has a few degenerate rings (North Korea includes a "polygon"
  // that is one point repeated), which makes H3 throw while dotting the land.
  // Keep only polygons whose outer ring has at least 3 distinct points.
  function cleanLandFeatures(features) {
    const distinctPoints = (ring) => new Set(ring.map((pt) => `${pt[0]},${pt[1]}`)).size;
    return features
      .map((f) => {
        const g = f.geometry;
        const polys = !g ? [] : g.type === "Polygon" ? [g.coordinates] : g.type === "MultiPolygon" ? g.coordinates : [];
        const kept = polys.filter((poly) => poly[0] && distinctPoints(poly[0]) >= 3);
        return kept.length ? { ...f, geometry: { type: "MultiPolygon", coordinates: kept } } : null;
      })
      .filter(Boolean);
  }

  function globeTooltip(d) {
    const groups = Array.from(d.groups.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([g, n]) => `${escapeHtml(g)}${n > 1 ? ` ×${n}` : ""}`)
      .join(", ");
    return `<div class="globe-tip"><strong>${escapeHtml(countryName(d.code))}</strong> · ${d.count} victim${d.count === 1 ? "" : "s"}
      <div class="tip-groups">${groups}</div>
      <div class="tip-groups">latest ${escapeHtml(relativeTime(new Date(d.latest).toISOString()))}</div></div>`;
  }

  async function initGlobe() {
    const container = $("globe-container");
    const status = $("globe-status");
    if (!container) return;
    if (!hasWebGL()) {
      status.textContent = "3D globe unavailable: WebGL is turned off in this browser. The lists still work.";
      return;
    }
    try {
      const [, , atlas, centroids] = await Promise.all([
        loadScript(GLOBE_LIB_URL),
        loadScript(TOPOJSON_LIB_URL),
        fetchJsonStrict(WORLD_ATLAS_URL),
        fetchJsonStrict("assets/country-centroids.json"),
      ]);
      globeState.centroids = centroids;
      const land = cleanLandFeatures(window.topojson.feature(atlas, atlas.objects.countries).features);
      const reduced = prefersReducedMotion();
      const scale = (d) => Math.sqrt(d.count / globeState.max);

      const globe = new window.Globe(container, { animateIn: !reduced })
        .width(container.clientWidth)
        .height(container.clientHeight)
        .backgroundColor("rgba(0,0,0,0)")
        .atmosphereColor("#00e5ff")
        .atmosphereAltitude(0.2)
        // Land as a field of glowing dots.
        .hexPolygonsData(land)
        .hexPolygonResolution(3)
        .hexPolygonMargin(0.4)
        .hexPolygonUseDots(true)
        .hexPolygonColor(() => "rgba(0, 229, 255, 0.5)")
        .hexPolygonLabel((f) => `<div class="globe-tip">${escapeHtml(f.properties?.name || "")}</div>`)
        // Victim countries: a red column (height ~ victims) plus pulsing rings.
        .pointLat("lat")
        .pointLng("lng")
        .pointColor(() => "#ff3b5c")
        .pointAltitude((d) => 0.02 + 0.1 * scale(d))
        .pointRadius((d) => 0.45 + 0.7 * scale(d))
        .pointLabel(globeTooltip)
        .pointsTransitionDuration(reduced ? 0 : 900)
        .onPointClick((d) => setRwCountry(d.code))
        .ringLat("lat")
        .ringLng("lng")
        .ringColor(() => (t) => `rgba(255, 59, 92, ${Math.max(0, 1 - t).toFixed(3)})`)
        .ringMaxRadius((d) => 2.5 + 5 * scale(d))
        .ringPropagationSpeed(2.2)
        .ringRepeatPeriod((d) => 1600 - 900 * scale(d))
        .labelLat("lat")
        .labelLng("lng")
        .labelText("code")
        .labelSize(1.9)
        .labelDotRadius(0.35)
        .labelColor(() => "rgba(216, 243, 255, 0.9)")
        .labelResolution(2)
        .labelAltitude(0.012)
        .labelLabel(globeTooltip)
        .onLabelClick((d) => setRwCountry(d.code));

      const mat = globe.globeMaterial();
      if (mat.color) mat.color.set("#041726");
      if (mat.emissive) mat.emissive.set("#020b14");
      mat.shininess = 6;

      const controls = globe.controls();
      controls.autoRotate = !reduced;
      controls.autoRotateSpeed = 0.5;
      // Pause the spin while the pointer is on the globe so it's easy to aim.
      container.addEventListener("pointerenter", () => {
        controls.autoRotate = false;
      });
      container.addEventListener("pointerleave", () => {
        controls.autoRotate = !reduced && !state.rwCountry;
      });
      globe.pointOfView({ lat: 28, lng: -40, altitude: 2.3 });
      // A country filter set before the globe loaded (e.g. from a shared link).
      const picked = state.rwCountry && centroids[state.rwCountry];
      if (Array.isArray(picked)) {
        controls.autoRotate = false;
        globe.pointOfView({ lat: picked[0], lng: picked[1], altitude: 1.7 });
      }

      new ResizeObserver(() => {
        if (container.clientWidth && container.clientHeight) {
          globe.width(container.clientWidth).height(container.clientHeight);
        }
      }).observe(container);
      // Stop rendering while the globe is scrolled out of view.
      new IntersectionObserver((entries) => {
        if (entries[0].isIntersecting) globe.resumeAnimation();
        else globe.pauseAnimation();
      }).observe(container);

      globeState.globe = globe;
      status.hidden = true;
      updateGlobe();
    } catch (e) {
      console.error("Globe failed to initialize:", e);
      status.textContent = "3D globe failed to load (CDN blocked or offline). The lists still work.";
    }
  }

  function updateGlobe() {
    const globe = globeState.globe;
    const rw = state.rw;
    if (!globe || !rw) return;
    const centroids = globeState.centroids || {};
    const points = [];
    for (const c of rw.byCountry.values()) {
      const ll = centroids[c.code];
      if (ll) points.push({ ...c, lat: ll[0], lng: ll[1] });
    }
    globeState.max = Math.max(1, ...points.map((p) => p.count));
    const top = points.slice().sort((a, b) => b.count - a.count).slice(0, 8);
    globe.pointsData(points).ringsData(points).labelsData(top);

    const status = $("globe-status");
    if (rw.loaded && !points.length) {
      status.textContent = `No located ransomware victims in the last ${RW_WINDOW_HOURS} hours.`;
      status.hidden = false;
    } else {
      status.hidden = true;
    }
  }

  // ---------- Init ----------

  document.addEventListener("DOMContentLoaded", () => {
    // Framed by another site (see the script in index.html's <head>): don't
    // load or wire anything, just offer to open the dashboard directly.
    if (document.documentElement.classList.contains("is-framed")) {
      const note = document.createElement("p");
      note.className = "framed-note";
      note.append("This dashboard can't be used inside another site. ");
      const a = document.createElement("a");
      a.href = location.href.split("#")[0];
      a.target = "_top";
      a.rel = "noopener noreferrer";
      a.textContent = "Open it directly";
      note.append(a, ".");
      document.body.prepend(note);
      return;
    }
    startClock();
    initTabs();
    initRansomwarePanels();
    initRwTrends();
    initGlobe();
    initUkNews();
    wireSearchBoxes();
    wireExportButtons();
    initWatchlist();
    // Optional feature: if it ever throws (e.g. an engine quirk with a stored
    // term), the rest of the page must still load its data.
    try {
      initVendorWatch();
    } catch (e) {
      console.error("Vendor watchlist failed to initialize:", e);
    }
    initIocDrawer();
    try {
      initShareLinks();
    } catch (e) {
      console.error("Shareable links failed to initialize:", e);
    }
    initSince();
    loadData();
    initAutoRefresh();
  });
})();
