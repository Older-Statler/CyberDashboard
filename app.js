(() => {
  "use strict";

  const CRON_INTERVAL_MINUTES = 30;
  const STALE_AFTER_CYCLES = 2;

  const state = {
    snapshot: null,
    enrichment: null,
    tableState: {}, // feed -> { sortKey, sortDir, query }
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
    });
  }

  function updateThemeIcon(theme) {
    $("theme-toggle-icon").textContent = theme === "light" ? "☼" : "☽";
  }

  // ---------- Data loading ----------

  async function loadData() {
    try {
      const resp = await fetch("data/latest.json", { cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      state.snapshot = await resp.json();
    } catch (e) {
      $("last-updated").textContent = "Failed to load data/latest.json";
      console.error("Failed to load snapshot:", e);
      return;
    }

    try {
      const resp = await fetch("data/enrichment.json", { cache: "no-store" });
      if (resp.ok) {
        state.enrichment = await resp.json();
      }
    } catch (e) {
      // Enrichment is best-effort; missing file must not break the page.
      state.enrichment = null;
    }

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
    const info = state.snapshot.feeds?.[feed];
    const el = $(`status-${feed}`);
    if (!info) {
      el.textContent = "";
      return;
    }
    el.textContent = info.status;
    el.className = `feed-status ${info.status}`;
  }

  // ---------- GreyNoise badges ----------

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

  // ---------- Generic sortable/searchable table ----------

  function renderTable(feed, columns, searchFn, defaultSort) {
    const info = state.snapshot.feeds?.[feed];
    const items = info?.items || [];
    const emptyNote = $(`empty-${feed}`);
    const table = $(`table-${feed}`);

    if (!items.length) {
      table.querySelector("thead").innerHTML = "";
      table.querySelector("tbody").innerHTML = "";
      emptyNote.hidden = false;
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

    const MAX_ROWS = 500;
    const shown = filtered.slice(0, MAX_ROWS);

    const tbody = table.querySelector("tbody");
    tbody.innerHTML = shown.map((item) => `<tr>${columns.map((c) => `<td>${c.render(item)}</td>`).join("")}</tr>`).join("");

    if (filtered.length > MAX_ROWS) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columns.length;
      td.className = "empty-note";
      td.textContent = `Showing first ${MAX_ROWS} of ${filtered.length} matching rows. Narrow your search to see more.`;
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
            return `<span class="mono">${escapeHtml(i.ioc)}</span>${ip ? greynoiseBadge(ip) : ""}`;
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
    },

    urlhaus: {
      columns: [
        {
          key: "url",
          label: "URL",
          sortValue: (i) => (i.url || "").toLowerCase(),
          render: (i) => {
            const link = i.urlhaus_link ? `<a href="${escapeHtml(i.urlhaus_link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(i.url)}</a>` : escapeHtml(i.url);
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
      ],
      searchFn: (i) => `${i.cve_id || ""} ${i.vendor_project || ""} ${i.product || ""} ${i.vulnerability_name || ""}`,
      defaultSort: { key: "date_added", dir: "desc" },
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
    },

    blocklistde: {
      columns: [
        {
          key: "ip",
          label: "IP",
          sortValue: (i) => i.ip || "",
          render: (i) => `<span class="mono">${escapeHtml(i.ip)}</span>${greynoiseBadge(i.ip)}`,
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
    },
  };

  function renderFeed(feed) {
    const def = FEED_DEFS[feed];
    if (!def) return;
    renderFeedStatus(feed);
    renderTable(feed, def.columns, def.searchFn, def.defaultSort);
  }

  function render() {
    renderHeader();
    renderKpis();
    Object.keys(FEED_DEFS).forEach(renderFeed);
  }

  // ---------- Init ----------

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    wireSearchBoxes();
    loadData();
  });
})();
