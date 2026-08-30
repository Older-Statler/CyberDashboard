(() => {
  "use strict";

  const CRON_INTERVAL_MINUTES = 30;
  const STALE_AFTER_CYCLES = 2;
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
    ransomwareVictims: null,
    tableState: {}, // feed -> { sortKey, sortDir, query, lastFiltered }
    correlated: [],
    triage: { ransomwareKev: [], epssCriticalKev: [], maliciousIps: [], topCorrelated: [], recentVictims: [] },
    watchlistText: "",
    watchlistMatches: [],
    watchlistMatchKeys: new Set(),
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

  // ---------- Theme ----------

  function initTheme() {
    let saved = null;
    try {
      saved = localStorage.getItem("ctd-theme");
    } catch (e) {
      /* localStorage unavailable */
    }
    const theme = saved || "dark";
    document.documentElement.setAttribute("data-theme", theme);
    updateThemeIcon(theme);

    $("theme-toggle").addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme");
      const next = current === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      updateThemeIcon(next);
      try {
        localStorage.setItem("ctd-theme", next);
      } catch (e) {
        /* ignore */
      }
      // Re-render the map so its ramp/legend follow the new theme's CSS vars.
      renderWorldMap((state.geoSummary && state.geoSummary.by_country) || {});
    });
  }

  function updateThemeIcon(theme) {
    $("theme-toggle-icon").textContent = theme === "light" ? "☼" : "☽";
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
      const resp = await fetch(path, { cache: "no-store" });
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
    const resp = await fetch(path, { cache: "no-store" });
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
    try {
      state.snapshot = await fetchJsonWithProgress("data/latest.json", (received, total) => {
        const pct = Math.min(100, Math.round((received / total) * 100));
        $("last-updated").textContent = `Loading data… ${pct}% (${(total / 1024 / 1024).toFixed(1)} MB)`;
      });
    } catch (e) {
      $("last-updated").textContent = "Failed to load data/latest.json";
      console.error("Failed to load snapshot:", e);
      return;
    }

    $("last-updated").textContent = "Processing…";

    const [enrichment, trends, geoSummary, epss, internetdb, abuseipdb, spamhausDrop, ransomwareVictims] = await Promise.all([
      fetchJsonBestEffort("data/enrichment.json"),
      fetchJsonBestEffort("data/trends.json"),
      fetchJsonBestEffort("data/geo_summary.json"),
      fetchJsonBestEffort("data/epss.json"),
      fetchJsonBestEffort("data/internetdb.json"),
      fetchJsonBestEffort("data/abuseipdb.json"),
      fetchJsonBestEffort("data/spamhaus_drop.json"),
      fetchJsonBestEffort("data/ransomware_victims.json"),
      loadWorldMapSvg(),
    ]);
    state.enrichment = enrichment;
    state.trends = trends;
    state.geoSummary = geoSummary;
    state.epss = epss;
    state.internetdb = internetdb;
    state.abuseipdb = abuseipdb;
    state.spamhausDrop = spamhausDrop;
    state.ransomwareVictims = ransomwareVictims;

    render();
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
      const ageMinutes = (Date.now() - new Date(generatedAt).getTime()) / 60000;
      staleBanner.hidden = ageMinutes <= CRON_INTERVAL_MINUTES * STALE_AFTER_CYCLES;
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
  }

  function isIpInDrop(ip) {
    if (!ip || !state.dropRangesParsed.length) return null;
    return state.dropRangesParsed.find((r) => ipInCidr(ip, r)) || null;
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

  function extractCorrelationEntries(feeds) {
    const entries = [];

    for (const item of feeds.threatfox?.items || []) {
      const t = (item.ioc_type || "").toLowerCase();
      let kind = null;
      if (t.includes("ip")) kind = "ip";
      else if (t.includes("domain")) kind = "domain";
      else if (t.includes("url")) kind = "url";
      else if (t.includes("hash") || t.includes("md5") || t.includes("sha")) kind = "hash";
      const norm = normalizeIocValue(item.ioc, kind);
      if (norm) {
        entries.push({ norm, feed: "threatfox", label: item.malware_printable || item.ioc_type, seenAt: item.first_seen });
      }
    }

    for (const item of feeds.urlhaus?.items || []) {
      const host = extractHost(item.url);
      if (!host) continue;
      const ip = normalizeIp(host);
      const norm = ip ? { type: "ip", value: ip } : normalizeIocValue(host, "domain");
      if (norm) {
        entries.push({ norm, feed: "urlhaus", label: item.threat || "malicious URL", seenAt: item.date_added });
      }
    }

    for (const item of feeds.malwarebazaar?.items || []) {
      const norm = normalizeIocValue(item.sha256_hash, "hash");
      if (norm) {
        entries.push({ norm, feed: "malwarebazaar", label: item.signature || "malware sample", seenAt: item.first_seen });
      }
    }

    for (const item of feeds.otx?.items || []) {
      for (const ind of item.indicators || []) {
        const type = (ind.type || "").toLowerCase();
        let kind = null;
        if (type.includes("ipv4") || type.includes("ipv6")) kind = "ip";
        else if (type.includes("domain") || type.includes("hostname")) kind = "domain";
        else if (type.includes("url")) kind = "url";
        else if (type.includes("hash") || type.includes("md5") || type.includes("sha")) kind = "hash";
        const norm = normalizeIocValue(ind.indicator, kind);
        if (norm) {
          entries.push({ norm, feed: "otx", label: item.name, seenAt: item.created });
        }
      }
    }

    const blFetchedAt = feeds.blocklistde?.fetched_at || null;
    for (const item of feeds.blocklistde?.items || []) {
      const norm = normalizeIocValue(item.ip, "ip");
      if (norm) {
        entries.push({ norm, feed: "blocklistde", label: (item.lists || []).join(", ") || "blocklist", seenAt: blFetchedAt });
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

    const correlated = [];
    for (const [key, list] of map.entries()) {
      const feedsSeen = Array.from(new Set(list.map((e) => e.feed)));
      const [type, value] = key.split("|");
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

  function renderCorrelated() {
    const tbody = $("correlated-tbody");
    const emptyNote = $("correlated-empty");
    const table = $("table-correlated");
    const list = state.correlated || [];

    if (!list.length) {
      table.querySelector("thead").innerHTML = "";
      tbody.innerHTML = "";
      emptyNote.hidden = false;
      return;
    }
    emptyNote.hidden = true;

    table.querySelector("thead").innerHTML =
      "<tr><th>IOC</th><th>Feeds</th><th>Signals</th><th>Malware / Threat</th><th>Most Recent</th></tr>";

    const rows = list.slice(0, 300);
    tbody.innerHTML = rows
      .map((c, idx) => {
        const feedTags = c.feeds.map((f) => `<span class="tag feed-tag">${escapeHtml(FEED_LABELS[f] || f)}</span>`).join("");
        const signalBadge = `<span class="badge badge-info" title="${escapeHtml(c.signalBreakdown.join(", "))}">${c.signalCount} signal${c.signalCount === 1 ? "" : "s"}</span>`;
        const labels = c.labels.slice(0, 3).map((l) => escapeHtml(l)).join(", ");
        const recent = c.mostRecent ? fmtDate(new Date(c.mostRecent).toISOString()) : "&mdash;";
        return `<tr class="correlated-row" data-idx="${idx}">
          <td><span class="mono">${escapeHtml(c.value)}</span></td>
          <td>${feedTags || "&mdash;"}</td>
          <td>${signalBadge}</td>
          <td>${labels || "&mdash;"}</td>
          <td>${recent}</td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll("tr.correlated-row").forEach((tr) => {
      tr.addEventListener("click", () => {
        const idx = Number(tr.getAttribute("data-idx"));
        scrollToMatch(rows[idx].feeds[0], rows[idx].value);
      });
    });
  }

  function scrollToMatch(feed, value) {
    const input = document.querySelector(`.search-box[data-feed="${feed}"]`);
    const section = $(`section-${feed}`);
    if (!input || !section) return;
    input.value = value;
    if (!state.tableState[feed]) state.tableState[feed] = { sortKey: null, sortDir: "asc", query: "" };
    state.tableState[feed].query = value;
    renderFeed(feed);
    section.scrollIntoView({ behavior: "smooth", block: "start" });
    section.classList.add("flash-highlight");
    setTimeout(() => section.classList.remove("flash-highlight"), 1500);
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
      .sort((a, b) => (b.date_added || "").localeCompare(a.date_added || ""))
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

    const recentVictims = (state.ransomwareVictims?.victims || [])
      .slice()
      .sort((a, b) => (b.published || "").localeCompare(a.published || ""))
      .slice(0, 5);

    state.triage = { ransomwareKev, epssCriticalKev, maliciousIps, topCorrelated, recentVictims };
  }

  function renderTriage() {
    const panel = $("triage-panel");
    const t = state.triage;
    const hasAny =
      t.ransomwareKev.length || t.epssCriticalKev.length || t.maliciousIps.length || t.topCorrelated.length || t.recentVictims.length;
    panel.hidden = !hasAny;
    if (!hasAny) return;

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

    const victimsCard = $("triage-victims").closest(".triage-card");
    victimsCard.hidden = !t.recentVictims.length;
    $("triage-victims").innerHTML = t.recentVictims
      .map(
        (v) =>
          `<li><a href="#" class="triage-link" data-feed="ransomware_victims" data-q="${escapeHtml(v.victim || "")}">${escapeHtml(v.victim || "Unknown")}</a> — ${escapeHtml(v.group || "unknown group")}<span class="triage-date">${escapeHtml(v.country || "")}</span></li>`
      )
      .join("");

    const maliciousCard = $("triage-malicious").closest(".triage-card");
    maliciousCard.hidden = !t.maliciousIps.length;
    $("triage-malicious").innerHTML = t.maliciousIps
      .map((m) => {
        const primaryFeed = m.feeds[0] || "blocklistde";
        const tags = m.feeds.map((f) => `<span class="tag feed-tag">${escapeHtml(FEED_LABELS[f] || f)}</span>`).join("");
        return `<li><a href="#" class="triage-link" data-feed="${primaryFeed}" data-q="${escapeHtml(m.ip)}"><span class="mono">${escapeHtml(m.ip)}</span></a> ${tags}<span class="triage-date">${relativeTime(m.checkedAt)}</span></li>`;
      })
      .join("");

    const correlatedCard = $("triage-correlated").closest(".triage-card");
    correlatedCard.hidden = !t.topCorrelated.length;
    $("triage-correlated").innerHTML = t.topCorrelated
      .map((c) => {
        const tags = c.feeds.map((f) => `<span class="tag feed-tag">${escapeHtml(FEED_LABELS[f] || f)}</span>`).join("");
        return `<li><a href="#" class="triage-link" data-feed="${c.feeds[0]}" data-q="${escapeHtml(c.value)}"><span class="mono">${escapeHtml(c.value)}</span></a> ${tags}</li>`;
      })
      .join("");

    panel.querySelectorAll(".triage-link").forEach((a) => {
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
          matches.push({ feed: "threatfox", value: item.ioc, label: item.malware_printable });
          matchKeys.add(`threatfox::${item.ioc}`);
        }
      } else if (t.includes("domain")) {
        const d = normalizeDomain(item.ioc);
        if (d && watchlistMatchesDomain(d, entries)) {
          matches.push({ feed: "threatfox", value: item.ioc, label: item.malware_printable });
          matchKeys.add(`threatfox::${item.ioc}`);
        }
      }
    }

    for (const item of feeds.urlhaus?.items || []) {
      const host = extractHost(item.url);
      const ip = normalizeIp(host);
      if (ip && watchlistMatchesIp(ip, entries)) {
        matches.push({ feed: "urlhaus", value: item.url, label: item.threat });
        matchKeys.add(`urlhaus::${item.url}`);
      } else {
        const d = normalizeDomain(host);
        if (d && watchlistMatchesDomain(d, entries)) {
          matches.push({ feed: "urlhaus", value: item.url, label: item.threat });
          matchKeys.add(`urlhaus::${item.url}`);
        }
      }
    }

    for (const item of feeds.blocklistde?.items || []) {
      if (item.ip && watchlistMatchesIp(item.ip, entries)) {
        matches.push({ feed: "blocklistde", value: item.ip, label: (item.lists || []).join(", ") });
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
            matches.push({ feed: "otx", value: ind.indicator, label: item.name });
          }
        } else if (type.includes("domain") || type.includes("hostname")) {
          const d = normalizeDomain(ind.indicator);
          if (d && watchlistMatchesDomain(d, entries)) {
            matches.push({ feed: "otx", value: ind.indicator, label: item.name });
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
    if (!matches.length) {
      card.hidden = true;
      list.innerHTML = "";
      return;
    }
    card.hidden = false;
    list.innerHTML = matches
      .slice(0, 30)
      .map(
        (m) =>
          `<li><span class="tag feed-tag">${escapeHtml(FEED_LABELS[m.feed] || m.feed)}</span> <span class="mono">${escapeHtml(m.value)}</span>${m.label ? ` — ${escapeHtml(m.label)}` : ""}</li>`
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

  // ---------- Export (CSV / JSON, respects current filter) ----------

  function csvEscape(val) {
    const s = val === null || val === undefined ? "" : String(val);
    if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
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
    const rows = state.correlated || [];
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
          return `<th data-key="${escapeHtml(col.key)}">${escapeHtml(col.label)}<span class="sort-arrow">${arrow}</span></th>`;
        })
        .join("") +
      "</tr>";

    thead.querySelectorAll("th").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.getAttribute("data-key");
        if (ts.sortKey === key) {
          ts.sortDir = ts.sortDir === "asc" ? "desc" : "asc";
        } else {
          ts.sortKey = key;
          ts.sortDir = "asc";
        }
        renderTable(feed, columns, searchFn, defaultSort);
      });
    });

    let filtered = items;
    if (ts.query) {
      const q = ts.query.toLowerCase();
      filtered = items.filter((item) => searchFn(item).toLowerCase().includes(q));
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

    const rowKeyFn = FEED_DEFS[feed]?.rowKey;
    const matchKeys = state.watchlistMatchKeys;

    const tbody = table.querySelector("tbody");
    tbody.innerHTML = shown
      .map((item) => {
        const isMatch = rowKeyFn && matchKeys && matchKeys.has(`${feed}::${rowKeyFn(item)}`);
        const cls = isMatch ? ' class="watchlist-match"' : "";
        return `<tr${cls}>${columns.map((c) => `<td>${c.render(item)}</td>`).join("")}</tr>`;
      })
      .join("");

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
    document.querySelectorAll(".search-box").forEach((input) => {
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
            return `<span class="mono">${escapeHtml(i.ioc)}</span>${ip ? ipBadges(ip) : ""}`;
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
            const link = i.urlhaus_link
              ? `<a href="${escapeHtml(i.urlhaus_link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(i.url)}</a>`
              : escapeHtml(i.url);
            return `<span class="mono">${link}</span>`;
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
      toCsvRow: (i) => [i.url, i.url_status, i.threat, i.date_added, i.last_online, i.tags, i.urlhaus_link, i.reporter],
    },

    malwarebazaar: {
      columns: [
        { key: "file_name", label: "File Name", sortValue: (i) => (i.file_name || "").toLowerCase(), render: (i) => escapeHtml(i.file_name || "—") },
        {
          key: "sha256_hash",
          label: "SHA256",
          sortValue: (i) => i.sha256_hash || "",
          render: (i) => `<span class="mono">${escapeHtml((i.sha256_hash || "").slice(0, 16))}&hellip;</span>`,
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
          render: (i) => `<span class="mono">${escapeHtml(i.ip)}</span>${ipBadges(i.ip)}`,
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
    buildTriage();
    buildWatchlistMatches();
    renderCorrelated();
    renderTriage();
    renderWatchlistPanel();
    Object.keys(FEED_DEFS).forEach(renderFeed);
    renderGeo();
  }

  // ---------- Init ----------

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    wireSearchBoxes();
    wireExportButtons();
    initWatchlist();
    loadData();
  });
})();
