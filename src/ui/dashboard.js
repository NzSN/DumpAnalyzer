/*
 * DumpAnalyzer dashboard behaviour.
 *
 * Loaded by the Gentelella shell as `<script src="/assets/dashboard.js" defer>
 * </script>`. All data flows through the daemon's same-origin `/api/*` and
 * `/-/*` endpoints; there are no external requests and no inline styles or
 * event-handler attributes are produced (the CSP forbids them).
 *
 * The pure report-rendering helper region (from the `statusLabel` helper
 * through the detail-request canceller) is deliberately DOM-free: the node test
 * `tests/dashboard_javascript.mjs` executes it (plus the `const esc` line) in a
 * bare VM to verify report rendering and escaping.
 */

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const PHASES = [["claimed", "blue"], ["fetching", "amber"], ["staged", "amber"], ["analyzing", "amber"], ["reporting", "purple"]];
const phaseColor = (phase) => (PHASES.find(([name]) => name === phase) || ["", "gray"])[1];
const activePhase = (phase) => PHASES.some(([name]) => name === phase);
const PANELS = ["queue", "dumps", "reports", "settings"];
const PANEL_CRUMBS = { queue: "Queue", dumps: "Dumps", reports: "Reports", settings: "Settings" };
const PANEL_TITLES = { queue: "Work queue", dumps: "Dumps explorer", reports: "Local reports", settings: "Settings" };
const PAGE_SIZE = 25;
const SHADE_STATUS = { blue: "status-blue", amber: "status-yellow", purple: "status-purple", green: "status-green", red: "status-red", gray: "status-muted" };
const statusClass = (shade) => SHADE_STATUS[shade] || "status-muted";
const states = {
  dumps: { customerId: "", caseId: "", q: "", page: 1, data: null, key: "", loading: false, error: "", controller: null, version: 0, signature: "" },
  reports: { reportId: "", q: "", outcome: "all", delivery: "all", page: 1, data: null, key: "", loading: false, error: "", controller: null, version: 0, signature: "" },
};
let selectedPanel = "queue", filterText = "", filterPhase = null, jobsData = [], jobsLoaded = false;
let capabilities = { analyzer: false, rescan: false, explorer: false }, capabilitiesLoaded = false;
let statusRequest = null, jobsRequest = null, actionPending = false;
let searchTimers = {};
const detailCache = new Map();
const DETAIL_CACHE_LIMIT = 3;
const detailState = { id: "", data: null, loading: false, error: "", controller: null, version: 0, signature: "" };

/* ---------- Shared markup helpers ---------- */

function statusPill(label, toneClass) {
  return `<span class="status ${toneClass}">${esc(label)}</span>`;
}
function emptyStateMarkup(title, description) {
  return `<div class="empty-state"><strong class="empty-state-title">${esc(title)}</strong><p class="empty-state-desc">${esc(description)}</p></div>`;
}
function emptyTableRow(colspan, title, description) {
  return `<tr><td colspan="${colspan}" class="table-empty">${emptyStateMarkup(title, description)}</td></tr>`;
}

/* ---------- Data / hashing helpers ---------- */

function humanSize(value) {
  if (value == null || value === "") return "Size unavailable";
  const size = Number(value);
  if (!Number.isFinite(size) || size < 0) return "Size unavailable";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const unit = size > 0 ? Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1) : 0;
  return `${(size / 1024 ** unit).toFixed(unit ? 1 : 0)} ${units[unit]}`;
}
function analysisLabel(phase) {
  return !phase || phase === "discovered" ? "Ready" : phase === "done" ? "Completed" : phase;
}
function positivePage(value) {
  const page = Number(value);
  return Number.isSafeInteger(page) && page > 0 ? page : 1;
}
function paramsFor(panel, overrides = {}) {
  const state = { ...states[panel], ...overrides };
  const params = new URLSearchParams();
  if (panel === "dumps") {
    if (state.customerId) params.set("customerId", state.customerId);
    if (state.customerId && state.caseId) params.set("caseId", state.caseId);
  }
  if (state.q) params.set("q", state.q);
  if (panel === "reports") {
    if (state.outcome !== "all") params.set("outcome", state.outcome);
    if (state.delivery !== "all") params.set("delivery", state.delivery);
    if (state.reportId) params.set("reportId", state.reportId);
  }
  if (state.page > 1) params.set("page", state.page);
  return params;
}
function panelHash(panel, overrides = {}) {
  const params = states[panel] ? paramsFor(panel, overrides).toString() : "";
  return "#" + panel + (params ? "?" + params : "");
}
function updatePanelLinks() {
  document.querySelectorAll("a[data-panel]").forEach((link) => {
    const panel = link.dataset.panel;
    link.setAttribute("href", panelHash(panel));
    if (link.classList.contains("nav-link")) {
      const active = panel === selectedPanel;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
  });
}
function replaceHash() {
  history.replaceState(null, "", panelHash(selectedPanel));
  updatePanelLinks();
}

/* ---------- Theme ---------- */

const THEME_KEY = "dump-analyzer-theme";
const THEME_MODES = ["system", "light", "dark"];
const THEME_COLORS = { light: "#f5f7fb", dark: "#0f1623" };
let themeMedia = null;
try {
  themeMedia = typeof window.matchMedia === "function" ? window.matchMedia("(prefers-color-scheme: dark)") : null;
} catch {
  themeMedia = null;
}
function savedTheme() {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return THEME_MODES.includes(value) ? value : "system";
  } catch {
    return "system";
  }
}
function applyTheme(mode) {
  const preference = THEME_MODES.includes(mode) ? mode : "system";
  const dark = preference === "dark" || (preference === "system" && Boolean(themeMedia?.matches));
  const resolved = dark ? "dark" : "light";
  document.documentElement.dataset.theme = resolved;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", THEME_COLORS[resolved]);
  const select = $("theme-select");
  if (select) select.value = preference;
  try { localStorage.setItem(THEME_KEY, preference); } catch {}
}
function initTheme() {
  const select = $("theme-select");
  if (select) select.addEventListener("change", (event) => applyTheme(event.target.value));
  if (themeMedia) {
    const onSystemThemeChange = () => applyTheme(savedTheme());
    if (typeof themeMedia.addEventListener === "function") themeMedia.addEventListener("change", onSystemThemeChange);
    else if (typeof themeMedia.addListener === "function") themeMedia.addListener(onSystemThemeChange);
  }
  applyTheme(savedTheme());
}

/* ---------- Sidebar shell (desktop rail / mobile drawer) ---------- */

const RAIL_KEY = "dump-analyzer.sidebar-rail";
const DESKTOP_QUERY = "(min-width: 769px)";
let desktopMedia = null;
try {
  desktopMedia = typeof window.matchMedia === "function" ? window.matchMedia(DESKTOP_QUERY) : null;
} catch {
  desktopMedia = null;
}
function isDesktop() {
  // Environments without matchMedia are treated as desktop (Gentelella rail).
  return desktopMedia ? desktopMedia.matches : true;
}
function readRail() {
  try { return localStorage.getItem(RAIL_KEY) === "1"; } catch { return false; }
}
function storeRail(value) {
  try { localStorage.setItem(RAIL_KEY, value ? "1" : "0"); } catch {}
}
function drawerOpen() {
  return document.body.classList.contains("sidebar-open");
}
function syncSidebarToggle() {
  const button = $("sidebar-toggle");
  if (!button) return;
  if (isDesktop()) {
    const rail = document.body.classList.contains("sidebar-rail");
    button.setAttribute("aria-expanded", "false");
    button.setAttribute("aria-pressed", rail ? "true" : "false");
    button.setAttribute("aria-label", rail ? "Expand sidebar" : "Collapse sidebar");
    button.title = rail ? "Expand sidebar" : "Collapse sidebar";
  } else {
    const open = drawerOpen();
    button.setAttribute("aria-expanded", open ? "true" : "false");
    button.setAttribute("aria-pressed", "false");
    button.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    button.title = open ? "Close menu" : "Open menu";
  }
}
function closeDrawer() {
  document.body.classList.remove("sidebar-open");
  $("sidebar")?.classList.remove("open");
  const backdrop = $("sidebar-backdrop");
  if (backdrop) {
    backdrop.hidden = true;
    backdrop.setAttribute("aria-hidden", "true");
  }
  syncSidebarToggle();
}
function openDrawer() {
  document.body.classList.add("sidebar-open");
  $("sidebar")?.classList.add("open");
  const backdrop = $("sidebar-backdrop");
  if (backdrop) {
    backdrop.hidden = false;
    backdrop.setAttribute("aria-hidden", "true");
  }
  syncSidebarToggle();
}
function applyRailPreference() {
  document.body.classList.toggle("sidebar-rail", isDesktop() && readRail());
  syncSidebarToggle();
}
function initSidebar() {
  applyRailPreference();
  $("sidebar-toggle")?.addEventListener("click", () => {
    if (isDesktop()) {
      const next = !document.body.classList.contains("sidebar-rail");
      document.body.classList.toggle("sidebar-rail", next);
      storeRail(next);
      syncSidebarToggle();
    } else if (drawerOpen()) {
      closeDrawer();
    } else {
      openDrawer();
    }
  });
  $("sidebar-backdrop")?.addEventListener("click", () => {
    closeDrawer();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && drawerOpen()) closeDrawer();
  });
  document.addEventListener("click", (event) => {
    const link = event.target.closest?.("a.nav-link[data-panel]");
    if (link && !isDesktop()) closeDrawer();
  });
  if (desktopMedia) {
    const onDesktopChange = (event) => {
      if (event.matches) closeDrawer();
      document.body.classList.toggle("sidebar-rail", event.matches && readRail());
      syncSidebarToggle();
    };
    if (typeof desktopMedia.addEventListener === "function") desktopMedia.addEventListener("change", onDesktopChange);
    else if (typeof desktopMedia.addListener === "function") desktopMedia.addListener(onDesktopChange);
  }
}

/* ---------- Status, stats, pipeline, jobs ---------- */

const STAT_ICONS = {
  jobs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path></svg>',
  reports: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M22 2 11 13"></path><path d="M22 2 15 22l-4-9-9-4Z"></path></svg>',
  dumps: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><ellipse cx="12" cy="5" rx="8" ry="3"></ellipse><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"></path><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"></path></svg>',
};

function renderPipeline(status) {
  const phases = status.jobs.byPhase || {};
  const present = PHASES.filter(([phase]) => phases[phase]);
  const total = Math.max(1, Number(status.jobs.total) || 0);
  let offset = 0;
  const rects = present.map(([phase]) => {
    const width = Math.min(100 - offset, Math.max(0, (Number(phases[phase]) || 0) / total * 100));
    const rect = `<rect class="phase-${phase}" x="${offset.toFixed(3)}" y="0" width="${width.toFixed(3)}" height="8"></rect>`;
    offset += width;
    return rect;
  }).join("");
  const label = present.map(([phase]) => `${phase}: ${phases[phase]}`).join(", ") || "No active jobs";
  const container = $("pipeline");
  container.innerHTML = `<svg class="pipeline-bar" viewBox="0 0 100 8" preserveAspectRatio="none" role="img" aria-label="${esc(label)}">${rects}</svg>`;
  // The shell statically labels this container role="img"; keep its name in sync.
  container.setAttribute("aria-label", label);
  $("pipeline-key").innerHTML = present.map(([phase]) => `<span class="key"><span class="swatch phase-${phase}"></span>${esc(phase)} ${esc(phases[phase])}</span>`).join("") || '<span class="muted">No active jobs</span>';
}
function renderPhaseChips() {
  const chips = [["All", null], ...PHASES.map(([phase]) => [phase, phase])];
  const signature = JSON.stringify(filterPhase);
  const container = $("phase-chips");
  if (!container || container.dataset.signature === signature) return;
  container.innerHTML = chips.map(([label, phase]) => `<button type="button" class="chip${filterPhase === phase ? " active" : ""}" aria-pressed="${filterPhase === phase}" data-phase="${phase || ""}">${esc(label)}</button>`).join("");
  container.dataset.signature = signature;
}
function renderDiagnostics(status) {
  const values = [["Ledger", status.baseUrl], ["Event cursor", status.eventCursor ?? "—"], ["Uptime", `${status.upSeconds}s`], ["Poll interval", `${status.pollIntervalMs} ms`], ["SSH", status.sshConfigured ? "Configured" : "Not configured"]];
  $("diagnostics").innerHTML = values.map(([label, value]) => `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>`).join("");
}
function renderStats(status) {
  const cards = [
    ["Jobs in queue", status.jobs.total, "Claimed, running, reporting", "teal", STAT_ICONS.jobs],
    ["Pending reports", status.reports.pending, "Awaiting remote delivery", "yellow", STAT_ICONS.reports],
    ["Local reports", status.reports.total ?? "—", "Saved on this daemon", "blue", STAT_ICONS.dumps],
  ];
  $("stats").innerHTML = cards.map(([label, value, subtext, tone, icon]) => `<div class="card"><div class="stat"><div class="stat-icon ${tone}" aria-hidden="true">${icon}</div><div class="stat-content"><div class="stat-label">${esc(label)}</div><div class="stat-value-row"><span class="stat-value">${esc(value)}</span></div><div class="stat-subtext">${esc(subtext)}</div></div></div></div>`).join("");
  renderPipeline(status);
  renderPhaseChips();
  renderDiagnostics(status);
}
async function refreshStatus() {
  if (statusRequest) return statusRequest;
  statusRequest = (async () => {
    try {
      const status = await api("/api/status");
      $("ver").textContent = "v" + status.version;
      $("base").textContent = status.baseUrl;
      renderStats(status);
      $("live-dot").className = "dot ok";
      $("live-dot").setAttribute("aria-label", "Daemon connected");
      $("live-text").textContent = "Live";
      $("updated").textContent = new Date().toLocaleTimeString();
      $("updated").title = "Last successful status update";
    } catch {
      $("live-dot").className = "dot err";
      $("live-dot").setAttribute("aria-label", "Daemon unavailable");
      $("live-text").textContent = "Offline";
      $("updated").textContent = "Connection lost";
    } finally { statusRequest = null; }
  })();
  return statusRequest;
}
function renderJobs() {
  const queue = jobsData.filter((job) => activePhase(job.phase));
  const rows = queue.filter((job) => (!filterPhase || job.phase === filterPhase) && (!filterText || `${job.dumpId} ${job.kind}`.toLowerCase().includes(filterText)));
  $("jobs").innerHTML = rows.length
    ? rows.map((job) => `<tr><td class="mono">${esc(job.dumpId)}</td><td>${esc(job.kind)}</td><td>${statusPill(job.phase, statusClass(phaseColor(job.phase)))}</td><td>${esc(job.attempts)}</td><td class="muted">${esc(job.updatedAt)}</td></tr>`).join("")
    : emptyTableRow(5,
      queue.length ? "No active jobs match these filters." : "No active jobs.",
      queue.length ? "Adjust the phase filter or job search to see active work." : "Claimed, running, and reporting jobs appear here. The queue refreshes every 5 s.");
  $("jobs-status").textContent = `${rows.length} of ${queue.length} active job(s)`;
}
async function refreshJobs() {
  if (jobsRequest) return jobsRequest;
  jobsRequest = (async () => {
    try {
      const data = await api("/api/jobs");
      jobsData = data.jobs || [];
      jobsLoaded = true;
      renderJobs();
    } catch {
      $("jobs-status").textContent = "Could not refresh jobs." + (jobsLoaded ? " Showing the last loaded queue." : " Retrying shortly.");
    } finally { jobsRequest = null; }
  })();
  return jobsRequest;
}

/* ---------- Routing ---------- */

function cancelSearch(panel) {
  clearTimeout(searchTimers[panel]);
  searchTimers[panel] = null;
}
function cancelPanelRequest(panel) {
  const state = states[panel];
  if (!state) return;
  state.version++;
  state.controller?.abort();
  state.controller = null;
  state.loading = false;
}
function syncRouteChrome(panel) {
  const crumb = $("topbar-crumb");
  if (crumb) crumb.textContent = PANEL_CRUMBS[panel] || PANEL_CRUMBS.queue;
  document.title = `${PANEL_TITLES[panel] || PANEL_TITLES.queue} · DumpAnalyzer`;
}
function selectRoute(moveFocus = false) {
  const [rawPanel, query = ""] = location.hash.slice(1).split("?", 2);
  const panel = PANELS.includes(rawPanel) ? rawPanel : "queue";
  const changedPanel = selectedPanel !== panel;
  if (changedPanel) {
    cancelPanelRequest(selectedPanel);
    cancelSearch(selectedPanel);
  }
  cancelDetailRequest();
  selectedPanel = panel;
  const state = states[panel];
  if (state) {
    const params = new URLSearchParams(query);
    cancelPanelRequest(panel);
    cancelSearch(panel);
    state.q = params.get("q") || "";
    state.page = positivePage(params.get("page"));
    if (panel === "dumps") {
      state.customerId = params.get("customerId") || "";
      state.caseId = state.customerId ? params.get("caseId") || "" : "";
      $("dump-filter").value = state.q;
      renderExplorer();
    } else {
      state.reportId = params.get("reportId") || "";
      state.outcome = ["completed", "failed"].includes(params.get("outcome")) ? params.get("outcome") : "all";
      state.delivery = ["pending", "posted"].includes(params.get("delivery")) ? params.get("delivery") : "all";
      $("report-filter").value = state.q;
      $("report-outcome").value = state.outcome;
      $("report-delivery").value = state.delivery;
      syncReportView();
    }
  }
  for (const name of PANELS) $("panel-" + name).hidden = name !== panel;
  updatePanelLinks();
  syncRouteChrome(panel);
  if (!PANELS.includes(rawPanel)) replaceHash();
  if (moveFocus) {
    const heading = { queue: "queue-heading", dumps: "explorer-heading", reports: "reports-heading", settings: "settings-heading" }[panel];
    $(panel === "reports" && states.reports.reportId ? "report-detail-heading" : panel === "dumps" && !changedPanel ? "browse-heading" : heading).focus();
  }
  refreshSelected();
}
window.addEventListener("hashchange", () => selectRoute(true));

/* ---------- API ---------- */

async function api(path, signal) {
  const response = await fetch(path, { cache: "no-store", signal });
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}

/* ---------- Dumps explorer ---------- */

function browseKey() { return paramsFor("dumps").toString(); }
function reportKey() { const params = paramsFor("reports"); params.delete("reportId"); return params.toString(); }
function restoreFocus(container, key) {
  if (key && document.activeElement === document.body) Array.from(container.querySelectorAll("[data-focus-key]")).find((node) => node.dataset.focusKey === key)?.focus();
}
function actionMarkup(kind, id, label, reason, key) {
  if (!capabilities.analyzer) return "";
  const attrs = ["type=\"button\"", "class=\"btn btn-outline btn-sm\"", `data-analyze="${esc(kind)}"`, `data-id="${esc(id)}"`, `data-focus-key="${esc(key)}"`];
  if (reason || actionPending) attrs.push("disabled");
  if (reason) attrs.push(`aria-describedby="${esc(key)}-reason"`);
  const hint = reason ? `<span class="hint" id="${esc(key)}-reason">${esc(reason)}</span>` : "";
  return `<button ${attrs.join(" ")}>${esc(label)}</button>${hint}`;
}
function renderPager(prefix, data, loading) {
  $(prefix + "-prev").disabled = loading || !data || data.page <= 1;
  $(prefix + "-next").disabled = loading || !data || data.page >= data.totalPages;
  const start = data?.matching ? (data.page - 1) * data.pageSize + 1 : 0;
  const end = data ? Math.min(data.page * data.pageSize, data.matching) : 0;
  $(prefix + "-range").textContent = data ? `${start}–${end} of ${data.matching} · Page ${data.page} of ${Math.max(1, data.totalPages)}` : "";
}
function renderExplorer() {
  const state = states.dumps, data = state.data;
  const stale = Boolean(data && state.key !== browseKey());
  const customer = data?.customer, caseInfo = data?.case;
  const rootLink = panelHash("dumps", { customerId: "", caseId: "", page: 1 });
  const crumbs = [`<li>${state.customerId ? `<a href="${esc(rootLink)}">Customers</a>` : '<span aria-current="location">Customers</span>'}</li>`];
  if (state.customerId) {
    const label = customer?.customerId === state.customerId ? customer.displayName || state.customerId : state.customerId;
    const customerLink = panelHash("dumps", { caseId: "", page: 1 });
    crumbs.push(`<li>${state.caseId ? `<a href="${esc(customerLink)}">${esc(label)}</a>` : `<span aria-current="location">${esc(label)}</span>`}</li>`);
  }
  if (state.caseId) crumbs.push(`<li><span aria-current="location">${esc(caseInfo?.caseId === state.caseId ? caseInfo.title || state.caseId : state.caseId)}</span></li>`);
  const breadcrumbMarkup = crumbs.join("");
  if ($("dump-breadcrumbs").dataset.signature !== breadcrumbMarkup) {
    $("dump-breadcrumbs").innerHTML = breadcrumbMarkup;
    $("dump-breadcrumbs").dataset.signature = breadcrumbMarkup;
  }
  $("browse-heading").textContent = state.caseId ? "Dumps" : state.customerId ? "Cases" : "Customers";
  $("explorer-list").setAttribute("aria-busy", String(state.loading));
  let message = state.loading ? "Loading…" : state.error;
  if (!message && data) message = `${data.total} available dump(s) · ${data.scopeDumpCount} in this scope${state.q ? " · search applied" : ""}`;
  if (!message && !capabilitiesLoaded) message = "Loading capabilities…";
  if (!message && !capabilities.explorer) message = "Dumps explorer is unavailable on this daemon.";
  if (state.error && data) message += " Showing the last loaded results.";
  if (stale && !state.error) message += " Previous results remain visible until the new scope loads.";
  $("explorer-status").textContent = message;
  const controlSignature = JSON.stringify([state.customerId, state.caseId, stale, capabilities.analyzer, data?.scopeDumpCount, actionPending]);
  if ($("explorer-action").dataset.signature !== controlSignature) {
    const scopeReason = stale ? "Wait for this scope to load." : data?.scopeDumpCount > 64 ? "More than 64 dumps; choose a smaller scope." : !data || !data.scopeDumpCount ? "No available dumps in this scope." : "";
    $("explorer-action").innerHTML = state.customerId ? actionMarkup(state.caseId ? "case" : "customer", state.caseId || state.customerId, state.caseId ? "Analyze case" : "Analyze customer", scopeReason, "scope-action") : "";
    $("explorer-action").dataset.signature = controlSignature;
  }
  const signature = JSON.stringify([data, stale, actionPending, capabilities.analyzer]);
  if (state.signature !== signature) {
    const list = $("explorer-list");
    const focusKey = list.contains(document.activeElement) ? document.activeElement.dataset.focusKey : null;
    const navState = { q: state.q, page: 1 };
    if (!data) {
      list.innerHTML = emptyStateMarkup(state.loading ? "Loading catalog…" : "No catalog loaded yet.", state.loading ? "Customers, cases, and dumps load from the local ledger." : "Open the Dumps panel to load the local and remote catalog.");
    } else if (data.level === "customers") {
      const items = (data.customers || []).slice(0, PAGE_SIZE);
      list.innerHTML = items.length
        ? '<ul class="browse-list">' + items.map((item) => `<li class="browse-row"><a class="browse-link" data-focus-key="customer-${esc(item.customerId)}" href="${esc(panelHash("dumps", { ...navState, customerId: item.customerId, caseId: "" }))}"><strong>${esc(item.displayName || item.customerId)}</strong><span class="muted mono">${esc(item.customerId)}</span></a><span class="browse-count">${esc(item.caseCount)} cases · ${esc(item.dumpCount)} dumps</span></li>`).join("") + "</ul>"
        : "";
    } else if (data.level === "cases") {
      const items = (data.cases || []).slice(0, PAGE_SIZE);
      list.innerHTML = items.length
        ? '<ul class="browse-list">' + items.map((item) => `<li class="browse-row"><a class="browse-link" data-focus-key="case-${esc(item.caseId)}" href="${esc(panelHash("dumps", { ...navState, customerId: data.customer.customerId, caseId: item.caseId }))}"><strong>${esc(item.title || item.caseId)}</strong><span class="muted mono">${esc(item.caseId)}</span></a><span class="browse-count">${esc(item.dumpCount)} dumps</span></li>`).join("") + "</ul>"
        : "";
    } else {
      const rows = (data.dumps || []).slice(0, PAGE_SIZE).map((dump) => {
        const reason = stale ? "Wait for this scope to load." : !dump.sha256 ? "Waiting for a SHA-256 fingerprint." : activePhase(dump.analysisPhase) ? "Analysis is already in progress." : "";
        const shade = dump.analysisPhase === "done" ? "green" : phaseColor(dump.analysisPhase);
        return `<tr><td><div>${esc(dump.originalName || dump.dumpId)}</div><div class="mono muted">${esc(dump.dumpId)}</div></td><td class="muted">${esc(humanSize(dump.byteSize))}${dump.receivedAt ? " · " + esc(dump.receivedAt) : ""}</td><td>${statusPill(analysisLabel(dump.analysisPhase), statusClass(shade))}</td><td>${actionMarkup("dump", dump.dumpId, "Analyze dump", reason, "dump-" + dump.dumpId)}</td></tr>`;
      }).join("");
      list.innerHTML = '<div class="table-responsive"><table class="table"><thead><tr><th scope="col">Dump</th><th scope="col">Size / received</th><th scope="col">State</th><th scope="col">Action</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
    }
    if (data && !data.matching) {
      const kind = data.level === "customers" ? "customers" : data.level === "cases" ? "cases" : "dumps";
      list.innerHTML = emptyStateMarkup(
        state.q ? "No results match this search in this scope." : `No available ${kind}.`,
        state.q ? "Adjust the search or choose another customer or case." : "Dumps appear here once the catalog reports them as available.");
    }
    state.signature = signature;
    restoreFocus(list, focusKey);
  }
  renderPager("dump", data, state.loading || stale);
}

/* ---------- Report list ---------- */

function renderReports() {
  const state = states.reports, data = state.data, stale = Boolean(data && state.key !== reportKey());
  $("reports-status").textContent = state.loading ? "Loading reports…" : state.error ? state.error + (data ? " Showing the last loaded reports." : "") : data ? `${data.total} local report(s) · ${data.pending} pending delivery${state.q || state.outcome !== "all" || state.delivery !== "all" ? " · filters applied" : ""}` : "No reports loaded yet.";
  $("reports").setAttribute("aria-busy", String(state.loading));
  const signature = JSON.stringify([data, reportKey()]);
  if (data && state.signature !== signature) {
    const table = $("reports");
    const focused = table.contains(document.activeElement) ? document.activeElement.dataset.focusKey : null;
    table.innerHTML = data.reports.length ? data.reports.slice(0, PAGE_SIZE).map((report) => {
      const key = String(report.reportId || "");
      const detailLink = key ? `<a class="btn btn-outline btn-sm report-detail-link" href="${esc(panelHash("reports", { reportId: key }))}" data-focus-key="report-${esc(key)}" aria-label="Report details for ${esc(report.dumpId)}">Details</a>` : '<span class="muted">Detail unavailable</span>';
      return `<tr><td class="mono">${esc(report.dumpId)}</td><td>${statusPill(report.outcome, report.outcome === "completed" ? "status-green" : "status-red")}</td><td>${esc(deliveryLabel(report.fullDelivery))}</td><td class="muted">${esc(report.createdAt)}</td><td class="report-summary"><div class="report-preview">${esc(report.summary)}</div>${detailLink}${report.schemaVersion === 1 ? ' <span class="muted">Legacy</span>' : ""}</td></tr>`;
    }).join("") : emptyTableRow(5, "No local reports match these filters.", "Analysis reports appear here once the pipeline stores them. Reports update every 15 s.");
    state.signature = signature;
    restoreFocus(table, focused);
  }
  renderPager("report", data, state.loading || stale);
}
function deliveryLabel(value) {
  return ({ localOnly: "Local only", pendingFull: "Full delivery pending", summaryOnly: "Summary only", fullyDelivered: "Fully delivered", abandoned: "Delivery abandoned" })[value] || "Delivery unknown";
}
function deliveryDescription(value) {
  return ({ localOnly: "Stored locally; full remote delivery has not been requested.", pendingFull: "The full report is awaiting remote delivery.", summaryOnly: "Only the compact summary was delivered. Full detail remains local.", fullyDelivered: "The full report was acknowledged by the remote store.", abandoned: "Full delivery was abandoned. Local evidence remains available." })[value] || "Remote delivery has not been established.";
}

/* ---------- Pure report rendering helpers (DOM-free at definition time) ---------- */

function statusLabel(value) {
  return ({ timedOut: "Timed out", exportsOnly: "Exports only", otherThread: "Other thread", unavailable: "Unavailable", unverified: "Unverified", unknown: "Unknown" })[value] || (value ? String(value).replace(/([a-z])([A-Z])/g, "$1 $2") : "Unknown");
}
const arrayOf = (value) => Array.isArray(value) ? value : [];
const known = (value) => value === null || value === undefined || value === "" ? "Unknown / not captured" : String(value);
function detailFields(rows) {
  return '<dl class="detail-fields">' + rows.map(([label, value]) => `<dt>${esc(label)}</dt><dd>${esc(known(value))}</dd>`).join("") + '</dl>';
}
function detailItems(title, values, empty) {
  const items = arrayOf(values);
  return `<h4>${esc(title)}</h4>` + (items.length ? `<ul>${items.map((value) => `<li>${esc(value)}</li>`).join("")}</ul>` : `<p class="muted">${esc(empty)}</p>`);
}
function evidenceReferences(refs, report) {
  const evidence = arrayOf(report.evidence);
  const references = arrayOf(refs);
  return references.length ? '<div class="hint">Evidence: ' + references.map((id) => {
    const index = evidence.findIndex((entry) => entry.id === id);
    return index < 0 ? `<span>${esc(id)} (unavailable)</span>` : `<button type="button" class="reference" data-evidence-index="${index}">${esc(id)}</button>`;
  }).join(" ") + '</div>' : '<p class="hint">No evidence references recorded.</p>';
}
function detailCard(title, body) {
  return `<section class="card"><div class="card-header"><h3 class="card-title">${esc(title)}</h3></div><div class="card-body">${body}</div></section>`;
}
function javascriptStackMarkup(report) {
  const queries = arrayOf(report.evidence).filter((entry) => typeof entry.command === "string" && entry.command.startsWith("Forensicator MCP javascript_stack;")).map((entry) => {
    let data = null;
    try {
      const parsed = JSON.parse(entry.text);
      if (parsed?.kind === "forensicator.javascriptStack.v1" && Array.isArray(parsed.frames)) data = parsed;
    } catch { /* Failed or older queries may have no complete JSON result. */ }
    return { entry, data };
  });
  if (!queries.length) return "";
  let body = '<p class="hint">Forensicator recovery from captured V8 memory. These are physical-frame observations; inlined logical frames and async ancestry are unavailable. Function-start lines are not exact executing source locations.</p>';
  for (const {entry, data} of queries) {
    body += `<h4>Recovery query ${esc(entry.id)} · ${esc(statusLabel(entry.status))}</h4>` + evidenceReferences([entry.id], report);
    if (entry.error) body += `<p class="detail-warning">${esc(entry.error)}</p>`;
    if (!data) {
      body += '<p class="muted">No complete JavaScript recovery result was retained. Missing recovery does not establish that JavaScript frames were absent.</p>';
      continue;
    }
    body += detailFields([["OS thread", data.threadId ?? "All observed threads"], ["Frames with function metadata", data.recoveredFrameCount], ["Optimized frames with metadata", data.optimizedFrameCount], ["Frame candidates", data.candidateFrameCount], ["Frames omitted from this excerpt", data.omittedFrameCount], ["V8 cage memory observed", data.heapCaptured ? "Yes" : "Not established"]]);
    if (data.frames.length) {
      body += '<div class="table-responsive" role="region" aria-label="Recovered JavaScript frames" tabindex="0"><table class="stack-table"><thead><tr><th scope="col">Thread / depth</th><th scope="col">JavaScript function</th><th scope="col">Frame evidence</th><th scope="col">JIT metadata</th></tr></thead><tbody>';
      body += data.frames.map((frame) => `<tr><td>${esc(frame.threadId)} / ${esc(frame.depth)}<br>${esc(frame.frameType)}</td><td><span class="mono">${esc(frame.function || "Unresolved function candidate")}</span><div class="muted">${esc(frame.script || "Script unavailable")}${frame.functionStartLine != null ? " · function starts at line " + esc(frame.functionStartLine) : " · function-start line unavailable"}</div><div class="muted">${frame.metadataRecovered ? "Function metadata recovered" : "Classification only; function metadata unavailable"}</div></td><td class="mono">${detailFields([["Frame PC", frame.framePc], ["Frame pointer", frame.framePointer]])}</td><td>${frame.jit ? detailFields([["Code object", frame.jit.codeResolution?.codeObject], ["Entrypoint", frame.jit.codeResolution?.entrypoint], ["Feedback vector", frame.jit.feedbackVector], ["Feedback slots", frame.jit.slotCount], ["SFI cross-check", frame.jit.sfiCrosscheck ? "Passed" : "Not established"]]) : '<span class="muted">Not requested or unavailable</span>'}</td></tr>`).join("");
      body += '</tbody></table></div>';
    } else {
      body += '<p class="muted">No JavaScript frame candidates were recovered for the selected thread scope.</p>';
    }
    body += detailItems("Recovery limitations", data.limitations, "Completeness was not established.");
  }
  return detailCard("JavaScript and optimized frames", body);
}
function cancelDetailRequest() {
  detailState.version++;
  detailState.controller?.abort();
  detailState.controller = null;
  detailState.loading = false;
}

/* ---------- Report detail ---------- */

function syncReportView() {
  const id = states.reports.reportId;
  $("reports-list-view").hidden = Boolean(id);
  $("report-detail-view").hidden = !id;
  $("report-detail-back").setAttribute("href", panelHash("reports", { reportId: "" }));
  if (detailState.id !== id) {
    detailState.id = id;
    detailState.data = null;
    detailState.error = "";
    detailState.signature = "";
  }
  if (id) renderReportDetail();
}
function richReportMarkup(envelope) {
  const report = envelope.report, identity = report.identity || {}, root = report.rootCause || {}, mechanism = root.mechanism || {};
  const exception = report.exception || {}, context = report.context || {}, stack = report.stack || {}, symbols = report.symbols || {}, provenance = report.provenance || {}, completeness = report.completeness || {};
  const modules = arrayOf(symbols.modules), frames = arrayOf(stack.frames), evidence = arrayOf(report.evidence);
  const matched = modules.filter((module) => module.quality === "matched").length;
  const symbolSummary = modules.length ? `${matched}/${modules.length} modules matched; ${Array.from(new Set(modules.map((module) => statusLabel(module.quality)))).join(", ")}` : "No module identity verification captured";
  const quality = [["Exception", statusLabel(exception.status)], ["Stack coverage", `${statusLabel(stack.status)} · ${frames.length} frames`], ["Symbols", symbolSummary], ["Underlying cause", statusLabel(root.status)]];

  let conclusion = `<p>${esc(report.summary || "No summary captured.")}</p><div class="quality-strip">${quality.map(([label, value]) => `<div class="quality-item"><span>${esc(label)}</span>${esc(value)}</div>`).join("")}</div>`;
  if (envelope.warning) conclusion += `<p class="detail-warning">${esc(envelope.warning)}</p>`;
  if (completeness.truncated) conclusion += '<p class="detail-warning">Report truncated — captured sections may be incomplete.</p>';
  conclusion += detailFields([["Underlying cause", statusLabel(root.status)], ["Conclusion", root.conclusion || "The underlying cause is unknown."], ["Immediate mechanism", mechanism.description || "No immediate mechanism established."], ["Mechanism status", statusLabel(mechanism.status)], ["Confirmation rule", root.ruleId]]);
  conclusion += evidenceReferences(root.evidenceRefs, report) + evidenceReferences(mechanism.evidenceRefs, report);
  conclusion += detailItems("Missing evidence", root.missingEvidence, "No missing evidence was recorded; this does not establish completeness.");
  conclusion += detailItems("Next verification steps", root.nextChecks, "No next checks recorded.");
  if (arrayOf(root.hypotheses).length) conclusion += '<h4>Competing hypotheses</h4>' + root.hypotheses.map((hypothesis) => `<details><summary>${esc(hypothesis.explanation || "Unspecified hypothesis")}</summary>${evidenceReferences(hypothesis.evidenceRefs, report)}${detailItems("Missing evidence", hypothesis.missingEvidence, "Not recorded.")}${detailItems("Next checks", hypothesis.nextChecks, "Not recorded.")}</details>`).join("");
  conclusion += detailItems("Capture omissions", completeness.omissions, "No omissions were recorded.");
  let markup = detailCard("Analysis conclusion", conclusion);

  let contextBody = detailFields([["Capture status", statusLabel(exception.status)], ["Exception code", exception.code], ["Flags", exception.flags], ["Exception address", exception.address], ["Associated record", exception.recordPointer], ["Parameter count", exception.parameterCount]]) + "<h4>Raw exception parameters</h4>";
  contextBody += arrayOf(exception.parameters).length ? '<ol start="0" class="mono">' + exception.parameters.map((value) => `<li>${esc(value)}</li>`).join("") + "</ol>" : `<p class="muted">${exception.parameterCount === 0 ? "No exception parameters." : "Parameters were not captured."}</p>`;
  if (exception.access) contextBody += detailFields([["Decoded operation", exception.access.operation], ["Access target address", exception.access.address], ["Underlying status", exception.access.underlyingStatus]]);
  contextBody += evidenceReferences(exception.evidenceRefs, report);
  contextBody += "<h4>Saved context</h4>" + detailFields([["Context source", statusLabel(context.source)], ["Context thread", context.threadId], ["Process", provenance.processId], ["Architecture", provenance.architecture], ["Pointer width", provenance.pointerWidth]]);
  if (context.source !== "exception") contextBody += '<p class="detail-warning">Exception context was not established. These registers must not be assumed to describe the faulting context.</p>';
  contextBody += evidenceReferences(context.evidenceRefs, report);
  const registers = context.registers && typeof context.registers === "object" ? Object.entries(context.registers) : [];
  contextBody += "<h4>Registers</h4>" + (registers.length ? detailFields(registers) : '<p class="muted">Registers were not captured.</p>');
  contextBody += "<h4>Fault-site instruction</h4>";
  const instruction = context.faultInstruction;
  contextBody += instruction ? detailFields([["Instruction address", instruction.address], ["Bytes", instruction.bytes], ["Disassembly", instruction.disassembly], ["Effective address", instruction.effectiveAddress]]) + evidenceReferences(instruction.evidenceRefs, report) : '<p class="muted">Instruction bytes and disassembly were not captured.</p>';
  markup += detailCard("Exception record and context", contextBody);

  let stackBody = detailFields([["Stack status", statusLabel(stack.status)], ["Stack thread", stack.threadId]]) + '<p class="hint">Symbol attribution and unwind reliability are independent. Addresses retain their captured precision. This is the captured native stack.</p>';
  if (frames.length) stackBody += '<div class="table-responsive" role="region" aria-label="Captured native stack" tabindex="0"><table class="stack-table"><thead><tr><th scope="col">Frame</th><th scope="col">Location</th><th scope="col">Addresses</th><th scope="col">Resolution / unwind</th></tr></thead><tbody>' + frames.map((frame) => `<tr><td>${esc(frame.index)}</td><td>${esc(frame.module || "Unknown module")}<br><span class="mono">${esc(frame.function || "Unresolved function")}${frame.displacement ? " + " + esc(frame.displacement) : ""}</span>${frame.sourceFile ? '<div class="muted">' + esc(frame.sourceFile) + (frame.sourceLine != null ? ":" + esc(frame.sourceLine) : " · line unavailable") + "</div>" : '<div class="muted">Source location not captured</div>'}${evidenceReferences(frame.evidenceRefs, report)}</td><td class="mono">${detailFields([["Instruction pointer", frame.instructionPointer], ["Stack pointer", frame.stackPointer], ["Frame pointer", frame.framePointer], ["Return address", frame.returnAddress], ["Module RVA", frame.moduleRva]])}</td><td>${esc(statusLabel(frame.resolution))}<br><span class="muted">Unwind: ${esc(statusLabel(frame.unwind))}</span></td></tr>`).join("") + "</tbody></table></div>";
  else stackBody += '<p class="muted">No stack frames were captured.</p>';
  stackBody += detailItems("Stack limitations", stack.limitations, "No stack limitations recorded; unwind quality still follows each frame's status.");
  markup += detailCard("Native stack", stackBody);

  markup += javascriptStackMarkup(report);

  let symbolsBody = "<h4>Module and PDB provenance</h4>";
  const pdb = (value) => value ? `${known(value.guid)} · age ${known(value.age)}` : "Not captured";
  symbolsBody += modules.length ? modules.map((module) => `<details><summary>${esc(module.module || "Unknown module")} · ${esc(statusLabel(module.quality))}</summary>${detailFields([["Image base", module.imageBase], ["Image size", module.imageSize], ["Timestamp", module.timestamp], ["Expected PDB GUID / age", pdb(module.expectedPdb)], ["Loaded PDB GUID / age", pdb(module.loadedPdb)], ["PDB path", module.pdbPath]])}${evidenceReferences(module.evidenceRefs, report)}</details>`).join("") : '<p class="muted">No module identity records were captured. Function names alone do not establish matching symbols.</p>';
  symbolsBody += detailItems("Symbol limitations", symbols.limitations, "No symbol limitations recorded.");
  symbolsBody += "<h4>Captured command evidence</h4>";
  symbolsBody += evidence.length ? evidence.map((entry, index) => `<details id="report-evidence-${index}"><summary>${esc(entry.id)} · ${esc(entry.command || "Acquisition method unavailable")} · ${esc(statusLabel(entry.status))}${entry.truncated ? " · Truncated" : ""}</summary>${entry.error ? `<p class="detail-warning">${esc(entry.error)}</p>` : ""}${entry.truncated ? '<p class="detail-warning">This evidence section was truncated.</p>' : ""}<pre>${esc(entry.text || "No retained evidence text.")}</pre></details>`).join("") : '<p class="muted">No command evidence was retained.</p>';
  markup += detailCard("Symbols and evidence", symbolsBody);

  const provenanceBody = detailFields([["Report ID", envelope.reportId], ["Schema version", envelope.schemaVersion], ["Dump ID", identity.dumpId], ["Input SHA-256", identity.inputSha256], ["Kind", identity.kind], ["Analyzer", identity.analyzerName], ["Analyzer version", identity.analyzerVersion], ["Execution outcome", report.outcome], ["Provider", provenance.provider], ["Debugger version", provenance.debuggerVersion], ["Model", provenance.model], ["Analysis revision", provenance.analysisRevision], ["Document digest", envelope.digest], ["Full report delivery", deliveryLabel(envelope.fullDelivery)]]) + `<p class="hint">${esc(deliveryDescription(envelope.fullDelivery))}</p>`;
  markup += detailCard("Report provenance and delivery", provenanceBody);
  return markup;
}
function legacyReportMarkup(envelope) {
  const legacy = envelope.legacy;
  if (!legacy) return detailCard("Detailed report unavailable", `<p class="detail-warning">${esc(envelope.warning || "The saved detail is unavailable. Missing exception, stack, and root-cause sections cannot be reconstructed from a summary.")}</p>${detailFields([["Report ID", envelope.reportId], ["Schema version", envelope.schemaVersion], ["Delivery", deliveryLabel(envelope.fullDelivery)]])}`);
  return detailCard("Legacy report — detailed sections were not captured", `<p>${esc(legacy.summary || "No summary retained.")}</p>${envelope.warning ? `<p class="detail-warning">${esc(envelope.warning)}</p>` : ""}${detailFields([["Report ID", envelope.reportId], ["Dump ID", legacy.identity?.dumpId ?? legacy.identity?.dump_id], ["Outcome", legacy.outcome], ["Created", legacy.createdAt], ["Summary posted", legacy.posted ? "Yes — summary only" : "No"], ["Full delivery", deliveryLabel(envelope.fullDelivery)]])}<p class="muted">Exception records, registers, resolved stack, and causal assessment were not captured in this legacy report. Reanalysis is required to obtain them.</p><details><summary>Retained legacy facts</summary><pre>${esc(JSON.stringify(legacy.facts ?? {}, null, 2))}</pre></details>`);
}
function renderReportDetail() {
  const id = states.reports.reportId;
  if (!id) return;
  const data = detailState.id === id ? detailState.data : null;
  $("report-detail-heading").textContent = data?.report?.identity?.dumpId ? "Report · " + data.report.identity.dumpId : "Report detail";
  $("report-detail-status").textContent = detailState.loading ? "Loading selected report…" : detailState.error || (data ? "Saved report detail. No background evidence refresh." : "");
  $("report-detail-retry").hidden = !detailState.error;
  $("report-download").disabled = !data || detailState.loading;
  $("report-detail-content").setAttribute("aria-busy", String(detailState.loading));
  const signature = JSON.stringify([id, data]);
  if (detailState.signature !== signature) {
    $("report-detail-content").innerHTML = data ? (data.report ? richReportMarkup(data) : legacyReportMarkup(data)) : "";
    detailState.signature = signature;
  }
}
async function loadReportDetail(retry = false) {
  const id = states.reports.reportId;
  if (selectedPanel !== "reports" || !id || detailState.loading) return;
  if (detailState.id !== id) syncReportView();
  if (detailCache.has(id)) {
    const data = detailCache.get(id);
    detailCache.delete(id);
    detailCache.set(id, data);
    detailState.data = data;
    detailState.error = "";
    renderReportDetail();
    return;
  }
  if (detailState.error && !retry) return;
  const controller = new AbortController(), version = ++detailState.version;
  detailState.controller = controller;
  detailState.loading = true;
  detailState.error = "";
  renderReportDetail();
  try {
    const data = await api("/api/reports/" + encodeURIComponent(id), controller.signal);
    if (version !== detailState.version || selectedPanel !== "reports" || states.reports.reportId !== id) return;
    if (data.reportId !== id) throw new Error("The response belongs to a different report");
    detailState.data = data;
    detailCache.set(id, data);
    while (detailCache.size > DETAIL_CACHE_LIMIT) detailCache.delete(detailCache.keys().next().value);
  } catch (error) {
    if (version !== detailState.version || error.name === "AbortError") return;
    detailState.error = "Could not load this report. " + error.message + ".";
  } finally {
    if (version === detailState.version) {
      detailState.controller = null;
      detailState.loading = false;
      renderReportDetail();
    }
  }
}

/* ---------- Panel list refresh ---------- */

async function refreshList(panel) {
  if (selectedPanel !== panel || (panel === "reports" && states.reports.reportId)) return;
  if (panel === "dumps" && (!capabilitiesLoaded || !capabilities.explorer)) { renderExplorer(); return; }
  const state = states[panel];
  if (state.loading) return;
  const key = panel === "reports" ? reportKey() : browseKey();
  const controller = new AbortController(), version = ++state.version;
  state.controller = controller;
  state.loading = true;
  state.error = "";
  const render = panel === "dumps" ? renderExplorer : renderReports;
  render();
  const params = paramsFor(panel);
  params.delete("reportId");
  params.set("pageSize", String(PAGE_SIZE));
  const path = (panel === "dumps" ? "/api/dumps/browse" : "/api/reports") + "?" + params;
  try {
    const data = await api(path, controller.signal);
    if (version !== state.version || selectedPanel !== panel) return;
    state.page = positivePage(data.page);
    state.data = data;
    state.key = panel === "reports" ? reportKey() : browseKey();
    if (key !== state.key) replaceHash();
  } catch (error) {
    if (version !== state.version || error.name === "AbortError") return;
    state.error = "Could not refresh " + (panel === "dumps" ? "dumps" : "reports") + ". " + error.message + ".";
  } finally {
    if (version === state.version) {
      state.loading = false;
      state.controller = null;
      render();
    }
  }
}
function refreshSelected() {
  if (selectedPanel === "queue") return refreshJobs();
  if (selectedPanel === "reports" && states.reports.reportId) return loadReportDetail();
  if (selectedPanel === "dumps" || selectedPanel === "reports") return refreshList(selectedPanel);
  return Promise.resolve();
}
async function loadCapabilities() {
  try { capabilities = await api("/api/capabilities"); }
  catch { capabilities = { analyzer: false, rescan: false, explorer: false }; }
  capabilitiesLoaded = true;
  $("actions-card").hidden = !capabilities.analyzer && !capabilities.rescan;
  for (const act of ["dump", "case", "customer"]) {
    const node = $("act-" + act) || document.querySelector('[data-act="' + act + '"]');
    if (node) node.hidden = !capabilities.analyzer;
  }
  const rescanNode = $("act-rescan") || document.querySelector('[data-act="rescan"]');
  if (rescanNode) rescanNode.hidden = !capabilities.rescan;
  if (selectedPanel === "dumps") refreshList("dumps");
}
function applyListChange(panel, updates, debounce = false) {
  const state = states[panel];
  cancelPanelRequest(panel);
  Object.assign(state, updates, { page: 1 });
  cancelSearch(panel);
  replaceHash();
  if (panel === "dumps") renderExplorer();
  else renderReports();
  if (debounce) searchTimers[panel] = setTimeout(() => { searchTimers[panel] = null; refreshList(panel); }, 250);
  else refreshList(panel);
}

/* ---------- Actions and token store ---------- */

async function runAction(act, id, button, feedbackId = "toast") {
  if (actionPending || (act === "rescan" ? !capabilities.rescan : !capabilities.analyzer)) return;
  const routes = { dump: ["/-/analyze", { dumpId: id }], case: ["/-/analyze-case", { caseId: id }], customer: ["/-/analyze-customer", { customerId: id }], rescan: ["/-/rescan", {}] };
  const [route, payload] = routes[act];
  const show = (ok, message) => { const target = $(feedbackId); target.className = "toast " + (ok ? "ok" : "err"); target.textContent = message; };
  const label = button.textContent, focusKey = button.dataset.focusKey;
  actionPending = true;
  document.querySelectorAll(".actions-grid button").forEach((node) => { node.disabled = true; });
  button.classList.add("spin"); button.textContent = "Running…";
  renderExplorer();
  show(true, `${act}: running (a real dump takes minutes)…`);
  try {
    const response = await fetch(route, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) show(false, `${act}: ${response.status} ${body.message ?? body.error ?? ""}`);
    else if (act === "rescan") show(true, `rescan: ${body.inserted} new dump(s) discovered`);
    else if (body.reports) show(true, `${act}: ${body.considered} considered, ${body.reports.length} reported, ${(body.skipped || []).length} skipped`);
    else show(true, `${act}: ${body.report?.outcome ?? "done"} — ${body.report?.summary ?? ""}`);
  } catch (error) { show(false, `${act}: ${error.message}`); }
  finally {
    // Hidden panels fetch on entry; completion refreshes only the current panel and cheap status.
    cancelPanelRequest("dumps");
    cancelPanelRequest("reports");
    await Promise.all([refreshStatus(), refreshSelected()]);
    actionPending = false;
    document.querySelectorAll(".actions-grid button").forEach((node) => { node.disabled = false; });
    if (button.isConnected) { button.classList.remove("spin"); button.textContent = label; }
    renderExplorer();
    if (selectedPanel === "dumps") restoreFocus($("explorer-card") || $("panel-dumps"), focusKey);
  }
}

/* ---------- Event wiring ---------- */

$("report-detail-retry").addEventListener("click", () => loadReportDetail(true));
$("report-detail-content").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-evidence-index]");
  if (!button) return;
  const evidence = $("report-evidence-" + button.dataset.evidenceIndex);
  if (evidence) { evidence.open = true; evidence.querySelector("summary").focus(); evidence.scrollIntoView({ block: "nearest" }); }
});
$("report-download").addEventListener("click", () => {
  const data = detailState.data;
  if (!data || detailState.id !== states.reports.reportId) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "report-" + detailState.id.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 120) + ".json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

$("dump-filter").addEventListener("input", (event) => applyListChange("dumps", { q: event.target.value.trim() }, true));
$("report-filter").addEventListener("input", (event) => applyListChange("reports", { q: event.target.value.trim() }, true));
$("report-outcome").addEventListener("change", (event) => applyListChange("reports", { outcome: event.target.value }));
$("report-delivery").addEventListener("change", (event) => applyListChange("reports", { delivery: event.target.value }));
for (const [prefix, panel] of [["dump", "dumps"], ["report", "reports"]]) {
  for (const [direction, step] of [["prev", -1], ["next", 1]]) $(prefix + "-" + direction).addEventListener("click", () => {
    const state = states[panel];
    const next = state.page + step;
    if (state.loading || !state.data || next < 1 || next > state.data.totalPages) return;
    location.hash = panelHash(panel, { page: next });
  });
}
$("phase-chips").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-phase]");
  if (!button) return;
  filterPhase = button.dataset.phase || null;
  $("phase-chips").querySelectorAll("button").forEach((chip) => {
    const active = (chip.dataset.phase || null) === filterPhase;
    chip.classList.toggle("active", active);
    chip.setAttribute("aria-pressed", String(active));
  });
  $("phase-chips").dataset.signature = JSON.stringify(filterPhase);
  renderJobs();
});
$("job-filter").addEventListener("input", (event) => { filterText = event.target.value.toLowerCase(); renderJobs(); });

document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-analyze]");
  if (!button || button.disabled) return;
  runAction(button.dataset.analyze, button.dataset.id, button, "explorer-toast");
});
document.querySelectorAll(".actions-grid form").forEach((form) => form.addEventListener("submit", (event) => {
  event.preventDefault();
  runAction(form.dataset.act, form.querySelector("input[name=id]")?.value.trim() || "", form.querySelector("button"));
}));
$("store-token-btn").addEventListener("click", async () => {
  const input = $("new-token"), token = input.value.trim(), button = $("store-token-btn"), target = $("token-toast");
  const show = (ok, message) => { target.className = "toast " + (ok ? "ok" : "err"); target.textContent = message; };
  if (!token) return show(false, "Paste a token first.");
  button.disabled = true;
  try {
    const response = await fetch("/-/store-token", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) return show(false, body.message ?? `Not stored (${response.status}).`);
    input.value = "";
    show(true, "Stored. Actions can use it immediately; the pipeline uses it from the next boot.");
  } catch (error) { show(false, error.message); }
  finally { button.disabled = false; }
});

/* ---------- Bootstrap ---------- */

initTheme();
initSidebar();
selectRoute();
refreshStatus();
loadCapabilities();
setInterval(() => {
  if (document.hidden) return;
  refreshStatus();
  if (selectedPanel === "queue") refreshJobs();
}, 5000);
setInterval(() => {
  if (!document.hidden && states[selectedPanel] && !searchTimers[selectedPanel] && !(selectedPanel === "reports" && states.reports.reportId)) refreshSelected();
}, 15000);
