const severityWeights = { critical: 4, high: 3, medium: 2, low: 1 };
const severityColors = { critical: "#d93025", high: "#e65c00", medium: "#d4860b", low: "#2e7d32" };
const directDetections = new Set([
  "malware_detected","powershell_abuse","registry_persistence","lateral_movement",
  "container_escape","data_exfiltration","privilege_escalation","dns_tunnel",
  "beaconing","web_attack","file_integrity","geo_impossible_travel","service_disabled"
]);
const presetDays = { "24h": 1, "3d": 3, "7d": 7, all: null };
const threatFeedPressure = {
  finance: 92, cloud: 86, identity: 81, web: 76,
  engineering: 73, corporate: 64, operations: 58, technology: 68
};
const subnetBaselines = {
  perimeter: 18, dmz: 16, "user-lan": 34, "server-core": 24,
  cloud: 22, saas: 20, operations: 28
};
const assetCatalog = {
  "vpn-gateway":          { criticality: 95, vulnerability: 82, industry: "identity",    subnet: "perimeter" },
  "rdp-gateway":          { criticality: 91, vulnerability: 84, industry: "identity",    subnet: "perimeter" },
  "endpoint-protection":  { criticality: 88, vulnerability: 58, industry: "operations",  subnet: "user-lan" },
  "domain-controller":    { criticality: 99, vulnerability: 79, industry: "identity",    subnet: "server-core" },
  "o365-portal":          { criticality: 87, vulnerability: 61, industry: "identity",    subnet: "saas" },
  "portal.company.local": { criticality: 84, vulnerability: 77, industry: "web",         subnet: "dmz" },
  "payments-api":         { criticality: 93, vulnerability: 81, industry: "finance",     subnet: "cloud" },
  "SRV-DB-01":            { criticality: 94, vulnerability: 73, industry: "finance",     subnet: "server-core" },
  "SRV-APP-02":           { criticality: 89, vulnerability: 72, industry: "finance",     subnet: "server-core" },
  "WEB-01":               { criticality: 82, vulnerability: 78, industry: "web",         subnet: "dmz" }
};
const mitreStages = [
  { key: "reconnaissance",      label: "Reconnaissance" },
  { key: "initial-access",      label: "Initial Access" },
  { key: "execution",           label: "Execution" },
  { key: "persistence",         label: "Persistence" },
  { key: "privilege-escalation",label: "Privilege Escalation" },
  { key: "defense-evasion",     label: "Defense Evasion" },
  { key: "lateral-movement",    label: "Lateral Movement" },
  { key: "command-and-control", label: "Command and Control" },
  { key: "exfiltration",        label: "Exfiltration" },
  { key: "impact",              label: "Impact" }
];
const mitreMap = {
  port_scan:              { stage: "reconnaissance",       technique: "Active Scanning" },
  web_attack:             { stage: "initial-access",       technique: "Exploit Public-Facing Application" },
  failed_login:           { stage: "initial-access",       technique: "Valid Accounts" },
  geo_impossible_travel:  { stage: "initial-access",       technique: "Valid Accounts" },
  powershell_abuse:       { stage: "execution",            technique: "PowerShell" },
  malware_detected:       { stage: "execution",            technique: "User Execution" },
  registry_persistence:   { stage: "persistence",          technique: "Registry Run Keys / Startup Folder" },
  privilege_escalation:   { stage: "privilege-escalation", technique: "Account Manipulation" },
  service_disabled:       { stage: "defense-evasion",      technique: "Impair Defenses" },
  lateral_movement:       { stage: "lateral-movement",     technique: "Remote Services" },
  dns_tunnel:             { stage: "command-and-control",  technique: "DNS" },
  beaconing:              { stage: "command-and-control",  technique: "Application Layer Protocol" },
  data_exfiltration:      { stage: "exfiltration",         technique: "Exfiltration Over C2 Channel" },
  container_escape:       { stage: "impact",               technique: "Escape to Host" },
  file_integrity:         { stage: "impact",               technique: "Defacement / Modify System Image" }
};
const fallbackReviewApiUrl = "http://127.0.0.1:3000/api/reviews";
const reviewDraftStorageKey = "siem-alert-reviews-fallback";

const el = {
  metricsGrid:            document.getElementById("metricsGrid"),
  exposureMap:            document.getElementById("exposureMap"),
  dwellForecast:          document.getElementById("dwellForecast"),
  attackPathGraph:        document.getElementById("attackPathGraph"),
  categoryChart:          document.getElementById("categoryChart"),
  severityChart:          document.getElementById("severityChart"),
  trendChart:             document.getElementById("trendChart"),
  alertsList:             document.getElementById("alertsList"),
  topSources:             document.getElementById("topSources"),
  eventsTable:            document.getElementById("eventsTable"),
  severityFilter:         document.getElementById("severityFilter"),
  categoryFilter:         document.getElementById("categoryFilter"),
  searchInput:            document.getElementById("searchInput"),
  simulateBtn:            document.getElementById("simulateBtn"),
  streamBtn:              document.getElementById("streamBtn"),
  resetBtn:               document.getElementById("resetBtn"),
  exportReportsBtn:       document.getElementById("exportReportsBtn"),
  detailPanel:            document.getElementById("detailPanel"),
  timelineStream:         document.getElementById("timelineStream"),
  lastUpdated:            document.getElementById("lastUpdated"),
  feedStatus:             document.getElementById("feedStatus"),
  alertCountNote:         document.getElementById("alertCountNote"),
  investigatedCountNote:  document.getElementById("investigatedCountNote"),
  investigatedAlertsList: document.getElementById("investigatedAlertsList"),
  eventCountNote:         document.getElementById("eventCountNote"),
  timeRangeButtons:       document.getElementById("timeRangeButtons"),
  startDateInput:         document.getElementById("startDateInput"),
  endDateInput:           document.getElementById("endDateInput"),
  windowSummary:          document.getElementById("windowSummary"),
  uploadInput:            document.getElementById("uploadInput"),
  uploadBtn:              document.getElementById("uploadBtn"),
  uploadStatus:           document.getElementById("uploadStatus"),
  uploadDropzone:         document.getElementById("uploadDropzone")
};

let nextEventId = 1;
let simulationClock = null;

const state = {
  logs: [], windowLogs: [], filteredLogs: [], alerts: [], filteredAlerts: [],
  alertReviews: {},
  filters: { severity: "all", category: "all", search: "", timePreset: "7d", startDate: "", endDate: "" },
  selected: null, streamTimer: null, scenarioCursor: 0,
  severityChartType: "donut",   // "donut" | "bar" | "histogram"
  severityDrilldown: null       // null | "critical" | "high" | "medium" | "low"
};

const sortByNewest = (a, b) => new Date(b.timestamp) - new Date(a.timestamp);
const withId = (log) => ({ ...log, id: `evt-${nextEventId++}` });

async function loadLogs() {
  const response = await fetch("./data/sample-logs.json");
  const data = await response.json();
  state.logs = rebaseLogs(data).map(withId).sort(sortByNewest);
  state.alertReviews = await loadAlertReviews();
  simulationClock = new Date(state.logs[0]?.timestamp || new Date().toISOString());
  syncDateBounds();
  applyTimePreset("7d", false);
  recalculate(true);
}

function rebaseLogs(logs) {
  if (!logs.length) return [];
  const latest = Math.max(...logs.map((log) => new Date(log.timestamp).getTime()));
  const anchor = new Date();
  anchor.setSeconds(0, 0);
  return logs.map((log) => ({
    ...log,
    timestamp: new Date(anchor.getTime() + new Date(log.timestamp).getTime() - latest).toISOString()
  }));
}

function recalculate(autoSelect = false) {
  state.windowLogs = state.logs.filter(matchesTimeWindow);
  state.alerts = buildAlerts(state.windowLogs);
  state.filteredLogs = state.windowLogs.filter(matchesLogFilters);
  state.filteredAlerts = state.alerts.filter(matchesAlertFilters);
  renderCategoryOptions();
  syncSelection(autoSelect);
  render();
}

function buildAlerts(logs) {
  const alerts = [];
  const logins = new Map();
  const scans = new Map();
  logs.forEach((log) => {
    if (log.event_type === "failed_login") {
      const key = `${log.source}|${log.target}`;
      const bucket = logins.get(key) || [];
      bucket.push(log);
      logins.set(key, bucket);
    }
    if (log.event_type === "port_scan") {
      const bucket = scans.get(log.source) || [];
      bucket.push(log);
      scans.set(log.source, bucket);
    }
    if (directDetections.has(log.event_type)) {
      alerts.push({
        id: `alert-${log.id}`, name: toTitle(log.event_type), severity: log.severity,
        source: log.source, target: log.target, category: log.category,
        rule: `Direct detection for ${toTitle(log.event_type)}`,
        detail: log.message, timestamp: log.timestamp, relatedEventIds: [log.id]
      });
    }
  });
  logins.forEach((bucket, key) => {
    if (bucket.length < 3) return;
    const [source, target] = key.split("|");
    alerts.push({
      id: `alert-bruteforce-${source}-${target}`, name: "Brute Force Suspected",
      severity: bucket.length >= 5 ? "critical" : "high", source, target, category: "identity",
      rule: "3 or more failed logins from the same source to the same target",
      detail: `${bucket.length} failed authentication attempts observed inside the active date window`,
      timestamp: bucket[0].timestamp, relatedEventIds: bucket.map((log) => log.id)
    });
  });
  scans.forEach((bucket, source) => {
    if (bucket.length < 2) return;
    alerts.push({
      id: `alert-portscan-${source}`, name: "Port Scan Pattern",
      severity: "medium", source, target: "Multiple DMZ hosts", category: "reconnaissance",
      rule: "Repeated port-scan events from the same source",
      detail: `${bucket.length} reconnaissance events indicate scanning behavior in the current date window`,
      timestamp: bucket[0].timestamp, relatedEventIds: bucket.map((log) => log.id)
    });
  });
  return alerts.sort((a, b) => severityWeights[b.severity] - severityWeights[a.severity] || sortByNewest(a, b));
}

function matchesTimeWindow(log) {
  const time = new Date(log.timestamp);
  return (!state.filters.startDate || time >= startOfDay(state.filters.startDate))
    && (!state.filters.endDate || time <= endOfDay(state.filters.endDate));
}
function matchesLogFilters(log) {
  const query = state.filters.search.trim().toLowerCase();
  const text = [log.event_type, log.source, log.target, log.message, log.status, log.category].join(" ").toLowerCase();
  return (state.filters.severity === "all" || log.severity === state.filters.severity)
    && (state.filters.category === "all" || log.category === state.filters.category)
    && (!query || text.includes(query));
}
function matchesAlertFilters(alert) {
  const query = state.filters.search.trim().toLowerCase();
  const text = [alert.name, alert.source, alert.target, alert.detail, alert.rule, alert.category].join(" ").toLowerCase();
  return (state.filters.severity === "all" || alert.severity === state.filters.severity)
    && (state.filters.category === "all" || alert.category === state.filters.category)
    && (!query || text.includes(query));
}
function isReviewSaved(review) {
  return Boolean(review.savedAt) || review.saveState === "saved" || review.saveState === "saved-local";
}
function isInvestigatedAlert(alert) {
  const review = getAlertReview(alert.id);
  return isReviewSaved(review) && ["true-positive", "false-positive"].includes(review.savedVerdict || "");
}
function getActiveAlerts(alerts = state.filteredAlerts) { return alerts.filter((alert) => !isInvestigatedAlert(alert)); }
function getInvestigatedAlerts(alerts = state.filteredAlerts) { return alerts.filter((alert) => isInvestigatedAlert(alert)); }

function syncSelection(autoSelect) {
  if (state.selected?.type === "alert" && state.filteredAlerts.some((item) => item.id === state.selected.id)) return;
  if (state.selected?.type === "log" && state.filteredLogs.some((item) => item.id === state.selected.id)) return;
  const activeAlerts = getActiveAlerts();
  const investigatedAlerts = getInvestigatedAlerts();
  if (autoSelect && activeAlerts[0]) { state.selected = { type: "alert", id: activeAlerts[0].id }; return; }
  if (autoSelect && investigatedAlerts[0]) { state.selected = { type: "alert", id: investigatedAlerts[0].id }; return; }
  state.selected = state.filteredLogs[0] ? { type: "log", id: state.filteredLogs[0].id } : null;
}

function render() {
  renderPresetButtons(); renderMetrics(); renderExposureMap(); renderDwellForecast();
  renderAttackPathGraph(); renderCategoryChart(); renderSeverityChart(); renderTrendChart();
  renderAlerts(); renderInvestigatedAlerts(); renderTopSources(); renderTimeline();
  renderTable(); renderDetails(); updateStatus();
  // v2 UI extras
  _v2SyncNavBadge();
  _v2RenderReportCases();
}

// ── v2 UI: nav badge sync ──────────────────────────────────────
function _v2SyncNavBadge() {
  if (window.__updateNavBadge) window.__updateNavBadge(getActiveAlerts().length);
}

// ── v2 UI: report cases section ───────────────────────────────
function _v2RenderReportCases() {
  const reportEl = document.getElementById("investigatedAlertsReport");
  if (!reportEl) return;
  const investigated = getInvestigatedAlerts(state.alerts);
  if (!investigated.length) {
    reportEl.innerHTML = '<div class="empty-state">No investigated cases yet. Save TP or FP verdicts in the Alert Queue to build your report.</div>';
    return;
  }
  reportEl.innerHTML = investigated.map((alert) => {
    const review = getAlertReview(alert.id);
    const sv = review.savedVerdict || review.verdict;
    return `<div class="detail-card">
      <div class="detail-header"><h3>${escapeHtml(alert.name)}</h3><span class="badge ${alert.severity}">${escapeHtml(alert.severity)}</span></div>
      <p class="detail-description">${escapeHtml(alert.detail)}</p>
      <dl class="detail-list">
        <div><dt>Verdict</dt><dd><span class="review-chip ${sv}">${escapeHtml(verdictLabel(sv))}</span></dd></div>
        <div><dt>Source</dt><dd>${escapeHtml(alert.source)}</dd></div>
        <div><dt>Target</dt><dd>${escapeHtml(alert.target)}</dd></div>
        <div><dt>Saved</dt><dd>${escapeHtml(review.savedAt ? formatTime(review.savedAt) : "Browser draft")}</dd></div>
        <div><dt>Notes</dt><dd>${escapeHtml(review.notes || "No notes added")}</dd></div>
      </dl>
    </div>`;
  }).join("");
}

function renderPresetButtons() {
  el.timeRangeButtons.querySelectorAll("[data-preset]").forEach((button) => {
    button.classList.toggle("is-selected", button.dataset.preset === state.filters.timePreset);
  });
}

function renderMetrics() {
  const activeAlerts = getActiveAlerts();
  const investigatedAlerts = getInvestigatedAlerts();
  const cards = [
    { label: "Events Ingested",    value: state.logs.length,        chip: "total" },
    { label: "Window Events",      value: state.windowLogs.length,  chip: "window" },
    { label: "Active Alerts",      value: activeAlerts.length,      chip: "triage" },
    { label: "Investigated Cases", value: investigatedAlerts.length, chip: "cases" }
  ];
  el.metricsGrid.innerHTML = cards.map((card) => `
    <article class="metric-card">
      <p>${escapeHtml(card.label)}</p>
      <h3>${card.value}</h3>
      <span class="metric-chip">${escapeHtml(card.chip)}</span>
    </article>
  `).join("");
}

function renderExposureMap() {
  const assets = buildAssetExposureModel().slice(0, 8);
  if (!assets.length) { el.exposureMap.innerHTML = `<div class="empty-state">No assets have enough telemetry for exposure scoring yet.</div>`; return; }
  el.exposureMap.innerHTML = assets.map((asset) => `
    <button class="exposure-card" type="button" data-asset="${escapeHtml(asset.name)}" style="--risk:${asset.exposureScore}">
      <div class="exposure-head">
        <strong>${escapeHtml(asset.name)}</strong>
        <span class="badge ${scoreBand(asset.exposureScore)}">${asset.exposureScore}</span>
      </div>
      <div class="exposure-meta">
        <span>Criticality ${asset.criticality}</span>
        <span>Vulnerability ${asset.vulnerability}</span>
        <span>Threat feed ${asset.feedPressure}</span>
        <span>${escapeHtml(toTitle(asset.subnet))} | ${escapeHtml(toTitle(asset.industry))}</span>
      </div>
    </button>
  `).join("");
}

function renderDwellForecast() {
  const forecasts = buildDwellForecast();
  if (!forecasts.length) { el.dwellForecast.innerHTML = `<div class="empty-state">Dwell-time forecasting needs subnet or asset telemetry to estimate coverage.</div>`; return; }
  el.dwellForecast.innerHTML = forecasts.map((forecast) => `
    <article class="forecast-card">
      <div class="forecast-head">
        <strong>${escapeHtml(toTitle(forecast.subnet))}</strong>
        <span class="badge ${scoreBand(forecast.riskScore)}">${escapeHtml(forecast.confidence)}</span>
      </div>
      <div class="forecast-hours">${forecast.dwellHours}h</div>
      <div class="forecast-meta">
        <span>Top exposed asset: ${escapeHtml(forecast.primaryAsset)}</span>
        <span>Coverage signals: ${forecast.signals}</span>
        <span>Predicted exposure pressure: ${forecast.riskScore}</span>
      </div>
    </article>
  `).join("");
}

function renderAttackPathGraph() {
  const attackPath = buildAttackPathModel();
  el.attackPathGraph.innerHTML = `
    <div class="attack-summary">
      <strong>Chain confidence ${attackPath.confidence}%</strong>
      <p>${escapeHtml(attackPath.chainText)}</p>
      <p>${attackPath.lowSignals} lower-severity signals are contributing to the modeled attack path in the current view.</p>
    </div>
    <div class="attack-track">
      ${attackPath.stages.map((stage) => `
        <button class="attack-node ${stage.count ? "is-active" : ""} ${stage.lowSignals >= 2 ? "is-hot" : ""}" type="button" data-attack-event="${escapeHtml(stage.events[0] || "")}">
          <span>${escapeHtml(stage.label)}</span>
          <strong>${stage.count} signals</strong>
          <span>${escapeHtml(stage.techniques[0] || "Waiting for mapped telemetry")}</span>
        </button>
      `).join("")}
    </div>
  `;
}

function buildAssetExposureModel() {
  const scopeLogs = getPredictiveScopeLogs();
  const activeAlerts = getActiveAlerts();
  const assets = new Set();
  scopeLogs.forEach((log) => { [log.source, log.target].forEach((entity) => { if (isAssetCandidate(entity)) assets.add(entity); }); });
  return [...assets].map((name) => {
    const profile = getAssetProfile(name);
    const relatedLogs = scopeLogs.filter((log) => log.source === name || log.target === name);
    const relatedAlerts = activeAlerts.filter((alert) => alert.source === name || alert.target === name);
    const highRiskSignals = relatedLogs.filter((log) => severityWeights[log.severity] >= 3).length;
    const feedPressure = clampScore((threatFeedPressure[profile.industry] || 65) + highRiskSignals * 4 + relatedAlerts.length * 6);
    const exposureScore = clampScore(Math.round(
      profile.criticality * 0.34 + profile.vulnerability * 0.26 + feedPressure * 0.24
      + Math.min(16, relatedLogs.length * 2 + relatedAlerts.length * 4)
    ));
    return { ...profile, name, signals: relatedLogs.length, alerts: relatedAlerts.length, feedPressure, exposureScore };
  }).sort((a, b) => b.exposureScore - a.exposureScore);
}

function buildDwellForecast() {
  const assets = buildAssetExposureModel();
  if (!assets.length) return [];
  const grouped = new Map();
  assets.forEach((asset) => { const bucket = grouped.get(asset.subnet) || []; bucket.push(asset); grouped.set(asset.subnet, bucket); });
  return [...grouped.entries()].map(([subnet, subnetAssets]) => {
    const signals = subnetAssets.reduce((sum, asset) => sum + asset.signals + asset.alerts, 0);
    const riskScore = Math.round(subnetAssets.reduce((sum, asset) => sum + asset.exposureScore, 0) / subnetAssets.length);
    const dwellHours = clampRange(Math.round((subnetBaselines[subnet] || 24) + riskScore * 0.16 - Math.min(18, signals * 0.8)), 6, 96);
    const primaryAsset = subnetAssets.sort((a, b) => b.exposureScore - a.exposureScore)[0]?.name || "None";
    const confidence = signals >= 16 ? "High" : signals >= 8 ? "Medium" : "Low";
    return { subnet, dwellHours, primaryAsset, signals, confidence, riskScore };
  }).sort((a, b) => b.dwellHours - a.dwellHours);
}

function buildAttackPathModel() {
  const scopeLogs = getPredictiveScopeLogs();
  const stages = mitreStages.map((stage) => ({ ...stage, count: 0, lowSignals: 0, techniques: [], events: [] }));
  const stageIndex = Object.fromEntries(stages.map((stage, index) => [stage.key, index]));
  scopeLogs.forEach((log) => {
    const mapping = mitreMap[log.event_type];
    if (!mapping) return;
    const stage = stages[stageIndex[mapping.stage]];
    stage.count += 1;
    if (severityWeights[log.severity] <= 2) stage.lowSignals += 1;
    if (!stage.techniques.includes(mapping.technique)) stage.techniques.push(mapping.technique);
    if (!stage.events.includes(log.event_type)) stage.events.push(log.event_type);
  });
  let currentChain = 0, longestChain = 0;
  stages.forEach((stage) => {
    if (stage.count) { currentChain += 1; longestChain = Math.max(longestChain, currentChain); } else { currentChain = 0; }
  });
  const activeLabels = stages.filter((stage) => stage.count).map((stage) => stage.label);
  const lowSignals = stages.reduce((sum, stage) => sum + stage.lowSignals, 0);
  const confidence = clampScore(Math.round((longestChain / mitreStages.length) * 70 + Math.min(30, lowSignals * 4)));
  return {
    stages, lowSignals, confidence,
    chainText: activeLabels.length ? activeLabels.join(" → ") : "No active multi-stage attack chain is forming right now."
  };
}

function getPredictiveScopeLogs() { return state.filteredLogs.length ? state.filteredLogs : state.windowLogs; }

function isAssetCandidate(value) {
  const text = String(value || "").trim();
  if (!text || !/[A-Za-z]/.test(text)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) return false;
  if (/^user:/i.test(text)) return false;
  if (/\.exe$/i.test(text)) return false;
  if ((text.includes("\\") || text.includes("/")) && !/^(WS-|SRV-|WEB-|K8S-)/i.test(text)) return false;
  return true;
}

function getAssetProfile(name) {
  if (assetCatalog[name]) return assetCatalog[name];
  const upper = String(name).toUpperCase();
  if (upper.startsWith("WS-FIN")) return { criticality: 79, vulnerability: 66, industry: "finance", subnet: "user-lan" };
  if (upper.startsWith("WS-"))    return { criticality: 68, vulnerability: 62, industry: "corporate", subnet: "user-lan" };
  if (upper.startsWith("SRV-"))   return { criticality: 88, vulnerability: 71, industry: "technology", subnet: "server-core" };
  if (upper.startsWith("WEB-"))   return { criticality: 81, vulnerability: 76, industry: "web", subnet: "dmz" };
  if (upper.startsWith("K8S-"))   return { criticality: 92, vulnerability: 79, industry: "cloud", subnet: "cloud" };
  if (/gateway/i.test(name))      return { criticality: 90, vulnerability: 80, industry: "identity", subnet: "perimeter" };
  if (/portal|resolver/i.test(name)) return { criticality: 84, vulnerability: 67, industry: "technology", subnet: "saas" };
  return { criticality: 72, vulnerability: 64, industry: "technology", subnet: "operations" };
}

function scoreBand(score) {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 45) return "medium";
  return "low";
}
function clampScore(value) { return clampRange(value, 0, 100); }
function clampRange(value, min, max) { return Math.max(min, Math.min(max, value)); }

function renderCategoryChart() {
  const counts = aggregateCounts(state.filteredLogs, "category");
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { el.categoryChart.innerHTML = `<div class="empty-state">No events match the current filters.</div>`; return; }
  const max = Math.max(...entries.map(([, count]) => count), 1);
  el.categoryChart.innerHTML = entries.map(([category, count]) => `
    <button class="bar-button ${state.filters.category === category ? "selected" : ""}" type="button" data-category="${escapeHtml(category)}">
      <span class="bar-label">${escapeHtml(toTitle(category))}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(count / max) * 100}%"></div></div>
      <span class="bar-value">${count}</span>
    </button>
  `).join("");
}

function renderSeverityChart() {
  const activeAlerts = getActiveAlerts();
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  activeAlerts.forEach((alert) => { counts[alert.severity] += 1; });
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);

  // Sync tab active state
  document.querySelectorAll(".chart-tab[data-chart-type]").forEach((btn) => {
    const active = btn.dataset.chartType === state.severityChartType;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-selected", active);
  });

  if (!total) {
    el.severityChart.innerHTML = `<div class="empty-state">No active alerts in the current view.</div>`;
    return;
  }

  if (state.severityChartType === "donut") {
    renderSeverityDonut(counts, total);
  } else if (state.severityChartType === "bar") {
    renderSeverityBar(counts, total);
  } else {
    renderSeverityHistogram(counts, total);
  }
}

function renderSeverityDonut(counts, total) {
  let current = 0;
  const gradient = `conic-gradient(${Object.entries(counts).map(([severity, value]) => {
    const start = current;
    current += (value / total) * 360;
    return `${severityColors[severity]} ${start}deg ${current}deg`;
  }).join(", ")})`;
  el.severityChart.className = "severity-chart-wrap donut-wrap";
  el.severityChart.innerHTML = `
    <div class="donut-chart" style="background:${gradient}">
      <div class="donut-center"><div><strong>${total}</strong><div>active alerts</div></div></div>
    </div>
    <div class="legend">${Object.entries(counts).map(([severity, value]) => `
      <button class="legend-item legend-item-btn ${state.severityDrilldown === severity ? "legend-item-active" : ""}"
        type="button" data-severity="${severity}"
        title="Click to view ${value} ${severity} alerts">
        <span class="legend-swatch" style="background:${severityColors[severity]}"></span>
        ${escapeHtml(toTitle(severity))}
        <span class="legend-count">${value}</span>
      </button>
    `).join("")}</div>
    ${state.severityDrilldown ? `<div class="sev-total-note">Filtered: <strong>${escapeHtml(toTitle(state.severityDrilldown))}</strong> <button class="sev-clear-btn" type="button">✕ Clear</button></div>` : ""}
  `;
}

function renderSeverityBar(counts, total) {
  const max = Math.max(...Object.values(counts), 1);
  el.severityChart.className = "severity-chart-wrap sev-bar-wrap";
  el.severityChart.innerHTML = `
    <div class="sev-bar-chart">
      ${Object.entries(counts).map(([severity, value], i) => {
        const pct = Math.round((value / total) * 100);
        const barH = Math.max((value / max) * 100, value > 0 ? 6 : 0);
        const isActive = state.severityDrilldown === severity;
        return `
          <button class="sev-bar-col ${isActive ? "sev-col-active" : ""}" type="button"
            data-severity="${severity}"
            title="Click to view ${value} ${severity} alert${value !== 1 ? "s" : ""}"
            style="animation:fadeUp 0.4s ${i * 60}ms var(--ease,ease) both">
            <div class="sev-bar-count">${value}</div>
            <div class="sev-bar-track">
              <div class="sev-bar-fill" style="height:${barH}%;background:${severityColors[severity]};opacity:0.88"></div>
            </div>
            <div class="sev-bar-label-row">
              <span class="sev-bar-name badge ${severity}">${escapeHtml(toTitle(severity))}</span>
              <span class="sev-bar-pct">${pct}%</span>
            </div>
          </button>
        `;
      }).join("")}
    </div>
    <div class="sev-total-note">Total: <strong>${total}</strong> active alerts${state.severityDrilldown ? ` · Filtered: <strong>${escapeHtml(toTitle(state.severityDrilldown))}</strong> <button class="sev-clear-btn" type="button">✕ Clear</button>` : ""}</div>
  `;
}

function renderSeverityHistogram(counts, total) {
  // Histogram: horizontal bars showing count + percentage distribution
  const max = Math.max(...Object.values(counts), 1);
  el.severityChart.className = "severity-chart-wrap sev-histogram-wrap";
  el.severityChart.innerHTML = `
    <div class="sev-histogram">
      ${Object.entries(counts).map(([severity, value], i) => {
        const pct = Math.round((value / total) * 100);
        const barW = Math.max((value / max) * 100, value > 0 ? 4 : 0);
        const isActive = state.severityDrilldown === severity;
        return `
          <button class="sev-histo-row ${isActive ? "sev-row-active" : ""}" type="button"
            data-severity="${severity}"
            title="Click to view ${value} ${severity} alert${value !== 1 ? "s" : ""}"
            style="animation:fadeUp 0.35s ${i * 55}ms var(--ease,ease) both">
            <div class="sev-histo-label">
              <span class="badge ${severity}">${escapeHtml(toTitle(severity))}</span>
            </div>
            <div class="sev-histo-track">
              <div class="sev-histo-fill" style="width:${barW}%;background:${severityColors[severity]}">
                <span class="sev-histo-inner-count">${value > 0 ? value : ""}</span>
              </div>
            </div>
            <div class="sev-histo-meta">
              <span class="sev-histo-count">${value}</span>
              <span class="sev-histo-pct">${pct}%</span>
            </div>
          </button>
        `;
      }).join("")}
    </div>
    <div class="sev-total-note">Total: <strong>${total}</strong> active alerts${state.severityDrilldown ? ` · Filtered: <strong>${escapeHtml(toTitle(state.severityDrilldown))}</strong> <button class="sev-clear-btn" type="button">✕ Clear</button>` : ""}</div>
  `;
}

// ── Severity drilldown: open inline drawer of alerts for a severity ──
function openSeverityDrilldown(severity) {
  // Toggle: clicking the same severity again closes the drawer
  if (state.severityDrilldown === severity) {
    state.severityDrilldown = null;
    closeSeverityDrawer();
    renderSeverityChart();
    return;
  }
  state.severityDrilldown = severity;
  renderSeverityChart();
  renderSeverityDrawer(severity);
}

function closeSeverityDrawer() {
  state.severityDrilldown = null;
  const drawer = document.getElementById("sev-drawer");
  if (drawer) {
    drawer.classList.remove("sev-drawer-open");
    setTimeout(() => drawer.remove(), 300);
  }
  renderSeverityChart();
}

function renderSeverityDrawer(severity) {
  // Remove any existing drawer
  const existing = document.getElementById("sev-drawer");
  if (existing) existing.remove();

  // Get alerts for this severity only
  const alerts = getActiveAlerts().filter((a) => a.severity === severity);
  const color = severityColors[severity];

  // Build the drawer element
  const drawer = document.createElement("div");
  drawer.id = "sev-drawer";
  drawer.className = "sev-drawer";
  drawer.setAttribute("role", "dialog");
  drawer.setAttribute("aria-label", `${toTitle(severity)} alerts`);

  drawer.innerHTML = `
    <div class="sev-drawer-header" style="border-left:3px solid ${color}">
      <div class="sev-drawer-title">
        <span class="badge ${severity}">${escapeHtml(toTitle(severity))}</span>
        <span class="sev-drawer-count">${alerts.length} alert${alerts.length !== 1 ? "s" : ""}</span>
      </div>
      <button class="sev-drawer-close" type="button" aria-label="Close">✕</button>
    </div>
    <div class="sev-drawer-body">
      ${alerts.length === 0
        ? `<div class="empty-state">No active ${severity} alerts in the current view.</div>`
        : alerts.map((alert) => {
            const review = getAlertReview(alert.id);
            const isSelected = state.selected?.type === "alert" && state.selected.id === alert.id;
            return `
              <button class="sev-drawer-item ${isSelected ? "sev-drawer-item-selected" : ""}"
                type="button" data-drawer-alert-id="${escapeHtml(alert.id)}">
                <div class="sev-drawer-item-top">
                  <strong>${escapeHtml(alert.name)}</strong>
                  <span class="review-chip ${review.verdict}">${escapeHtml(verdictLabel(review.verdict))}</span>
                </div>
                <p class="sev-drawer-item-detail">${escapeHtml(alert.detail)}</p>
                <div class="sev-drawer-item-meta">
                  <span class="sev-drawer-item-src">⬤ ${escapeHtml(alert.source)}</span>
                  <span class="sev-drawer-item-target">→ ${escapeHtml(alert.target)}</span>
                  <span class="sev-drawer-item-time">${escapeHtml(formatTime(alert.timestamp))}</span>
                </div>
              </button>
            `;
          }).join("")}
    </div>
  `;

  // Insert the drawer right after the severity chart panel
  const chartPanel = el.severityChart.closest("article.panel");
  if (chartPanel && chartPanel.parentNode) {
    chartPanel.parentNode.insertBefore(drawer, chartPanel.nextSibling);
  } else {
    el.severityChart.after(drawer);
  }

  // Trigger open animation on next frame
  requestAnimationFrame(() => drawer.classList.add("sev-drawer-open"));

  // Scroll into view smoothly
  setTimeout(() => drawer.scrollIntoView({ behavior: "smooth", block: "nearest" }), 80);
}

function renderTrendChart() {
  const series = buildDailySeries();
  if (!series.length) { el.trendChart.innerHTML = `<div class="empty-state">No day-level trend is available for the current filters.</div>`; return; }
  const max = Math.max(...series.map((item) => item.total), 1);
  el.trendChart.innerHTML = series.map((item) => `
    <button class="trend-column ${isSingleDaySelected(item.day) ? "selected" : ""}" type="button" data-day="${item.day}">
      <div class="trend-bars">
        <span class="trend-bar total" style="height:${Math.max((item.total / max) * 100, item.total ? 10 : 6)}%"></span>
        <span class="trend-bar critical" style="height:${item.critical ? Math.max((item.critical / max) * 100, 8) : 6}%"></span>
      </div>
      <div class="trend-meta">
        <strong>${escapeHtml(formatDay(item.day))}</strong>
        <span>${item.total} events | ${item.critical} critical</span>
      </div>
    </button>
  `).join("");
}

function buildDailySeries() {
  if (!state.filters.startDate || !state.filters.endDate) return [];
  const byDay = new Map();
  state.filteredLogs.forEach((log) => {
    const day = toDateValue(log.timestamp);
    const entry = byDay.get(day) || { total: 0, critical: 0 };
    entry.total += 1;
    if (log.severity === "critical") entry.critical += 1;
    byDay.set(day, entry);
  });
  const series = [];
  for (let cursor = startOfDay(state.filters.startDate); cursor <= startOfDay(state.filters.endDate); cursor = addDays(cursor, 1)) {
    const day = toDateValue(cursor);
    const entry = byDay.get(day) || { total: 0, critical: 0 };
    series.push({ day, ...entry });
  }
  return series;
}

function renderAlerts() {
  const activeAlerts = getActiveAlerts();
  el.alertCountNote.textContent = `${activeAlerts.length} active alerts`;
  if (!activeAlerts.length) { el.alertsList.innerHTML = `<div class="empty-state">No active alerts match the current filters.</div>`; return; }
  el.alertsList.innerHTML = activeAlerts.slice(0, 10).map((alert) => `
    <button class="interactive-card ${state.selected?.type === "alert" && state.selected.id === alert.id ? "selected" : ""}" type="button" data-alert-id="${escapeHtml(alert.id)}">
      <div class="alert-top"><strong>${escapeHtml(alert.name)}</strong><span class="badge ${alert.severity}">${escapeHtml(alert.severity)}</span></div>
      <p class="alert-copy">${escapeHtml(alert.detail)}</p>
      <p class="alert-copy">Rule: ${escapeHtml(alert.rule)}</p>
      <p class="alert-copy">Verdict: <span class="review-chip ${getAlertReview(alert.id).verdict}">${escapeHtml(verdictLabel(getAlertReview(alert.id).verdict))}</span></p>
      <p class="alert-copy">Source: ${escapeHtml(alert.source)} | Target: ${escapeHtml(alert.target)}</p>
    </button>
  `).join("");
}

function renderInvestigatedAlerts() {
  const investigatedAlerts = getInvestigatedAlerts();
  el.investigatedCountNote.textContent = `${investigatedAlerts.length} investigated alerts`;
  if (!investigatedAlerts.length) { el.investigatedAlertsList.innerHTML = `<div class="empty-state">Saved TP and FP cases will appear here after investigation.</div>`; return; }
  el.investigatedAlertsList.innerHTML = investigatedAlerts.slice(0, 10).map((alert) => {
    const review = getAlertReview(alert.id);
    const savedVerdict = review.savedVerdict || review.verdict;
    return `
      <button class="interactive-card investigated-card ${state.selected?.type === "alert" && state.selected.id === alert.id ? "selected" : ""}" type="button" data-alert-id="${escapeHtml(alert.id)}">
        <div class="alert-top"><strong>${escapeHtml(alert.name)}</strong><span class="badge ${alert.severity}">${escapeHtml(alert.severity)}</span></div>
        <p class="alert-copy">${escapeHtml(alert.detail)}</p>
        <p class="alert-copy">Verdict: <span class="review-chip ${savedVerdict}">${escapeHtml(verdictLabel(savedVerdict))}</span></p>
        <p class="alert-copy">Saved: ${escapeHtml(review.savedAt ? formatTime(review.savedAt) : "Browser draft only")}</p>
        <p class="alert-copy">Source: ${escapeHtml(alert.source)} | Target: ${escapeHtml(alert.target)}</p>
      </button>
    `;
  }).join("");
}

function renderTopSources() {
  const entries = Object.entries(aggregateCounts(state.filteredLogs.filter((log) => severityWeights[log.severity] >= 2), "source"))
    .sort((a, b) => b[1] - a[1]).slice(0, 6);
  if (!entries.length) { el.topSources.innerHTML = `<div class="empty-state">No suspicious sources in the current view.</div>`; return; }
  el.topSources.innerHTML = entries.map(([source, count]) => `
    <button class="interactive-card" type="button" data-source="${escapeHtml(source)}">
      <div class="source-top"><strong>${escapeHtml(source)}</strong><span class="source-value">${count}</span></div>
      <p class="alert-copy">Click to search this host or IP across the dashboard.</p>
    </button>
  `).join("");
}

function renderTimeline() {
  const items = [...state.windowLogs].slice(0, 12).reverse();
  if (!items.length) { el.timelineStream.innerHTML = `<div class="empty-state">No recent activity is available inside the selected date window.</div>`; return; }
  el.timelineStream.innerHTML = items.map((log) => `
    <button class="timeline-card ${state.selected?.type === "log" && state.selected.id === log.id ? "selected" : ""}" type="button" data-log-id="${escapeHtml(log.id)}">
      <div class="timeline-head"><span class="badge ${log.severity}">${escapeHtml(log.severity)}</span><span class="timeline-time">${escapeHtml(formatTime(log.timestamp))}</span></div>
      <p class="timeline-copy">${escapeHtml(toTitle(log.event_type))}</p>
      <p class="timeline-copy">${escapeHtml(log.source)}</p>
    </button>
  `).join("");
}

function renderTable() {
  el.eventCountNote.textContent = `${state.filteredLogs.length} visible events`;
  if (!state.filteredLogs.length) { el.eventsTable.innerHTML = `<tr><td colspan="7"><div class="empty-state">No events match the current filters.</div></td></tr>`; return; }
  el.eventsTable.innerHTML = state.filteredLogs.map((log) => `
    <tr class="${state.selected?.type === "log" && state.selected.id === log.id ? "selected" : ""}" data-log-id="${escapeHtml(log.id)}">
      <td>${escapeHtml(formatTime(log.timestamp))}</td>
      <td>${escapeHtml(toTitle(log.event_type))}</td>
      <td>${escapeHtml(log.source)}</td>
      <td>${escapeHtml(log.target)}</td>
      <td><span class="badge ${log.severity}">${escapeHtml(log.severity)}</span></td>
      <td><span class="status-pill">${escapeHtml(toTitle(log.status))}</span></td>
      <td>${escapeHtml(log.message)}</td>
    </tr>
  `).join("");
}

function renderDetails() {
  if (!state.selected) { el.detailPanel.innerHTML = `<div class="empty-state">Select an alert or event to begin investigating.</div>`; return; }
  if (state.selected.type === "alert") {
    const alert = state.alerts.find((item) => item.id === state.selected.id);
    if (!alert) { el.detailPanel.innerHTML = `<div class="empty-state">The selected alert is no longer visible.</div>`; return; }
    const review = getAlertReview(alert.id);
    const saveInfo = buildReviewStatus(review);
    const related = state.logs.filter((log) => alert.relatedEventIds.includes(log.id)).slice(0, 5);
    el.detailPanel.innerHTML = `
      <section class="detail-card">
        <div class="detail-header"><h3>${escapeHtml(alert.name)}</h3><span class="badge ${alert.severity}">${escapeHtml(alert.severity)}</span></div>
        <p class="detail-description">${escapeHtml(alert.detail)}</p>
        <dl class="detail-list">
          <div><dt>Detection rule</dt><dd>${escapeHtml(alert.rule)}</dd></div>
          <div><dt>Source</dt><dd>${escapeHtml(alert.source)}</dd></div>
          <div><dt>Target</dt><dd>${escapeHtml(alert.target)}</dd></div>
          <div><dt>Category</dt><dd>${escapeHtml(toTitle(alert.category))}</dd></div>
          <div><dt>Verdict</dt><dd><span class="review-chip ${review.verdict}">${escapeHtml(verdictLabel(review.verdict))}</span></dd></div>
          <div><dt>Database</dt><dd>${escapeHtml(review.savedAt ? `Saved ${formatTime(review.savedAt)}` : review.saveState === "saved-local" ? "Browser draft only" : "Not saved yet")}</dd></div>
          <div><dt>Recommended action</dt><dd>${escapeHtml(buildRecommendation(alert.category))}</dd></div>
        </dl>
      </section>
      <section class="detail-card">
        <h3>Triage And Report</h3>
        <div class="triage-actions">
          <button class="triage-button ${review.verdict === "true-positive" ? "is-selected" : ""}" type="button" data-verdict="true-positive">True Positive</button>
          <button class="triage-button ${review.verdict === "false-positive" ? "is-selected" : ""}" type="button" data-verdict="false-positive">False Positive</button>
          <button class="triage-button ${review.verdict === "needs-review" ? "is-selected" : ""}" type="button" data-verdict="needs-review">Needs Review</button>
        </div>
        <label class="filter-box" for="alertNotesInput">
          <span>Analyst Notes</span>
          <textarea id="alertNotesInput" class="analyst-notes" rows="5" placeholder="Add evidence, containment steps, scope, or why this is a false positive...">${escapeHtml(review.notes)}</textarea>
        </label>
        <p class="save-status ${saveInfo.tone}" data-review-status>${escapeHtml(saveInfo.text)}</p>
        <div class="detail-actions">
          <button class="action-button primary" type="button" data-review-action="save" ${review.saveState === "saving" ? "disabled" : ""}>${review.saveState === "saving" ? "Saving..." : "Save Review"}</button>
          <button class="action-button" type="button" data-review-action="save-next" ${review.saveState === "saving" ? "disabled" : ""}>Save And Next Alert</button>
          <button class="action-button" type="button" data-report-action="copy">Copy Report</button>
          <button class="action-button" type="button" data-report-action="download">Download Report</button>
        </div>
        <pre class="report-preview">${escapeHtml(buildAlertReport(alert))}</pre>
      </section>
      <section class="detail-card">
        <h3>Related Events</h3>
        <dl class="detail-list">${related.map((log) => `
          <div><dt>${escapeHtml(formatTime(log.timestamp))} | ${escapeHtml(toTitle(log.event_type))}</dt><dd>${escapeHtml(log.message)}</dd></div>
        `).join("")}</dl>
      </section>
    `;
    return;
  }
  const log = state.logs.find((item) => item.id === state.selected.id);
  if (!log) { el.detailPanel.innerHTML = `<div class="empty-state">The selected event is no longer visible.</div>`; return; }
  el.detailPanel.innerHTML = `
    <section class="detail-card">
      <div class="detail-header"><h3>${escapeHtml(toTitle(log.event_type))}</h3><span class="badge ${log.severity}">${escapeHtml(log.severity)}</span></div>
      <p class="detail-description">${escapeHtml(log.message)}</p>
      <dl class="detail-list">
        <div><dt>Timestamp</dt><dd>${escapeHtml(formatTime(log.timestamp))}</dd></div>
        <div><dt>Source</dt><dd>${escapeHtml(log.source)}</dd></div>
        <div><dt>Target</dt><dd>${escapeHtml(log.target)}</dd></div>
        <div><dt>Status</dt><dd>${escapeHtml(toTitle(log.status))}</dd></div>
        <div><dt>Category</dt><dd>${escapeHtml(toTitle(log.category))}</dd></div>
        <div><dt>Suggested next step</dt><dd>${escapeHtml(buildRecommendation(log.category))}</dd></div>
      </dl>
    </section>
  `;
}

function updateStatus() {
  const _ts = state.logs[0]?.timestamp || new Date().toISOString(); const _d = new Date(_ts); el.lastUpdated.textContent = `Last updated ${_d.toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" })}`;
  el.feedStatus.textContent = state.streamTimer ? "Auto stream running" : "Live feed ready";
  // v2: update only the text span inside streamBtn (preserves SVG icon)
  const _streamSpan = el.streamBtn ? el.streamBtn.querySelector("span") : null;
  if (_streamSpan) { _streamSpan.textContent = state.streamTimer ? "Stop Stream" : "Auto Stream"; }
  else if (el.streamBtn) { el.streamBtn.textContent = state.streamTimer ? "Stop Stream" : "Auto Stream"; }
  el.streamBtn.classList.toggle("is-active", Boolean(state.streamTimer));
  el.windowSummary.textContent = buildWindowSummary();
}

function renderCategoryOptions() {
  const categories = [...new Set(state.logs.map((log) => log.category))].sort();
  const current = state.filters.category;
  el.categoryFilter.innerHTML = [`<option value="all">All categories</option>`, ...categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(toTitle(category))}</option>`)].join("");
  el.categoryFilter.value = categories.includes(current) ? current : "all";
  if (!categories.includes(current)) state.filters.category = "all";
}

function buildWindowSummary() {
  const activeDays = new Set(state.windowLogs.map((log) => toDateValue(log.timestamp))).size;
  return `Showing ${formatDateOnly(state.filters.startDate)} to ${formatDateOnly(state.filters.endDate)} | ${activeDays} active days | ${getActiveAlerts().length} active alerts | ${getInvestigatedAlerts().length} investigated`;
}

function normalizeAlertReview(review = {}) {
  const verdicts = new Set(["true-positive", "false-positive", "needs-review"]);
  return {
    verdict: verdicts.has(review.verdict) ? review.verdict : "needs-review",
    notes: typeof review.notes === "string" ? review.notes : "",
    updatedAt: typeof review.updatedAt === "string" && review.updatedAt ? review.updatedAt : (typeof review.savedAt === "string" ? review.savedAt : ""),
    savedAt: typeof review.savedAt === "string" ? review.savedAt : "",
    savedVerdict: verdicts.has(review.savedVerdict) ? review.savedVerdict : ((typeof review.savedAt === "string" || review.saveState === "saved-local") && verdicts.has(review.verdict) ? review.verdict : ""),
    report: typeof review.report === "string" ? review.report : "",
    saveState: typeof review.saveState === "string" ? review.saveState : (review.savedAt ? "saved" : review.updatedAt ? "dirty" : "idle"),
    saveError: typeof review.saveError === "string" ? review.saveError : ""
  };
}

function normalizeAlertReviewMap(reviews = {}) {
  return Object.fromEntries(Object.entries(reviews).map(([alertId, review]) => [alertId, normalizeAlertReview({ ...review, saveState: "saved", saveError: "" })]));
}

function getAlertReview(alertId) { return normalizeAlertReview(state.alertReviews[alertId]); }

function setAlertReview(alertId, changes, options = {}) {
  const current = getAlertReview(alertId);
  const nextReview = normalizeAlertReview({ ...current, ...changes, updatedAt: options.touch === false ? current.updatedAt : (changes.updatedAt || new Date().toISOString()) });
  if (options.markDirty !== false) { nextReview.saveState = changes.saveState || "dirty"; nextReview.saveError = changes.saveError || ""; }
  state.alertReviews[alertId] = nextReview;
  return nextReview;
}

function loadLocalAlertReviews() {
  try { const saved = window.localStorage.getItem(reviewDraftStorageKey); return saved ? JSON.parse(saved) : {}; } catch (error) { return {}; }
}

function saveLocalAlertReviews(reviews) {
  try { window.localStorage.setItem(reviewDraftStorageKey, JSON.stringify(reviews)); } catch (error) { /* Ignore */ }
}

function getReviewApiCandidates() {
  const candidates = [];
  const sameOriginApi = window.location.protocol.startsWith("http") ? `${window.location.origin}/api/reviews` : "";
  [sameOriginApi, fallbackReviewApiUrl].forEach((url) => { if (url && !candidates.includes(url)) candidates.push(url); });
  return candidates;
}

function isVercelHosted() { return window.location.hostname.endsWith(".vercel.app"); }

function formatReviewApiError(error) {
  const message = error?.message || "";
  if (!message || message === "Failed to fetch") {
    return isVercelHosted()
      ? "Review storage is not configured for this Vercel deployment. Add a Vercel Blob store and redeploy."
      : "Unable to reach the local review database.";
  }
  return message;
}

async function requestReviewApi(method = "GET", payload) {
  let lastError = null;
  for (const url of getReviewApiCandidates()) {
    try {
      const response = await fetch(url, {
        method,
        headers: method === "POST" ? { "Content-Type": "application/json" } : undefined,
        body: method === "POST" ? JSON.stringify(payload) : undefined,
        cache: "no-store"
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) { lastError = new Error(data.error || `Review API request failed at ${url}.`); continue; }
      return { data, url };
    } catch (error) { lastError = error; }
  }
  throw new Error(formatReviewApiError(lastError) || "Review service unavailable. Run node server.js to enable database saves.");
}

async function loadAlertReviews() {
  try {
    const { data } = await requestReviewApi("GET");
    return normalizeAlertReviewMap(data.reviews || {});
  } catch (error) {
    const localReviews = normalizeAlertReviewMap(loadLocalAlertReviews());
    const withLocalState = Object.fromEntries(Object.entries(localReviews).map(([alertId, review]) => [alertId, normalizeAlertReview({ ...review, saveState: "saved-local", saveError: "" })]));
    console.warn("Review database unavailable, continuing with local draft review state.", error);
    return withLocalState;
  }
}

function getSelectedAlert() {
  if (state.selected?.type !== "alert") return null;
  return state.alerts.find((alert) => alert.id === state.selected.id) || null;
}

function getNextAlertId(currentAlertId) {
  const activeAlerts = getActiveAlerts();
  const currentIndex = activeAlerts.findIndex((alert) => alert.id === currentAlertId);
  if (currentIndex === -1) return "";
  return activeAlerts[currentIndex + 1]?.id || activeAlerts[currentIndex - 1]?.id || "";
}

function buildReviewStatus(review) {
  if (review.saveState === "saving") return { tone: "info", text: "Saving review to the database..." };
  if (review.saveState === "saved-local") return { tone: "success", text: "Review saved successfully." };
  if (review.saveState === "error") return { tone: "error", text: review.saveError || "Unable to save review to the database." };
  if (review.savedAt && review.saveState === "saved") return { tone: "success", text: `Saved to database ${formatTime(review.savedAt)}` };
  if (review.updatedAt) return { tone: "warning", text: "Unsaved changes. Save this verdict and report to keep them in the database." };
  return { tone: "muted", text: "Choose TP or FP, write notes, then save the review to the database." };
}

function refreshReviewDetail(alertId) {
  if (state.selected?.type !== "alert" || state.selected.id !== alertId) return;
  const alert = state.alerts.find((item) => item.id === alertId);
  if (!alert) return;
  const review = getAlertReview(alertId);
  const saveInfo = buildReviewStatus(review);
  const statusNode = el.detailPanel.querySelector("[data-review-status]");
  if (statusNode) { statusNode.textContent = saveInfo.text; statusNode.className = `save-status ${saveInfo.tone}`; }
  const previewNode = el.detailPanel.querySelector(".report-preview");
  if (previewNode) previewNode.textContent = buildAlertReport(alert);
  el.detailPanel.querySelectorAll("[data-review-action]").forEach((button) => { button.disabled = review.saveState === "saving"; });
}

function buildReviewPayload(alert) {
  const review = getAlertReview(alert.id);
  return {
    alertId: alert.id, alertName: alert.name, severity: alert.severity,
    category: alert.category, source: alert.source, target: alert.target,
    detail: alert.detail, detectionRule: alert.rule, alertTimestamp: alert.timestamp,
    relatedEventIds: alert.relatedEventIds, verdict: review.verdict, notes: review.notes,
    report: buildAlertReport(alert), updatedAt: review.updatedAt || new Date().toISOString()
  };
}

async function saveAlertReview(alertId, moveToNextAlert = false) {
  const alert = state.alerts.find((item) => item.id === alertId);
  if (!alert) return;
  const nextAlertId = moveToNextAlert ? getNextAlertId(alertId) : "";
  setAlertReview(alertId, { saveState: "saving", saveError: "" }, { markDirty: false, touch: false });
  renderAlerts(); renderDetails();
  try {
    const { data } = await requestReviewApi("POST", buildReviewPayload(alert));
    state.alertReviews = { ...normalizeAlertReviewMap(data.reviews || {}), ...state.alertReviews };
    if (data.review) {
      state.alertReviews[alertId] = normalizeAlertReview({ ...data.review, savedVerdict: data.review.verdict, saveState: "saved", saveError: "" });
    }
    saveLocalAlertReviews(state.alertReviews);
    state.selected = { type: "alert", id: moveToNextAlert && nextAlertId ? nextAlertId : alertId };
    render();
  } catch (error) {
    setAlertReview(alertId, { report: buildAlertReport(alert), savedVerdict: getAlertReview(alertId).verdict, savedAt: new Date().toISOString(), saveState: "saved", saveError: "" }, { markDirty: false, touch: false });
    saveLocalAlertReviews(state.alertReviews);
    state.selected = { type: "alert", id: moveToNextAlert && nextAlertId ? nextAlertId : alertId };
    render();
  }
}

function verdictLabel(verdict) {
  return { "true-positive": "True Positive", "false-positive": "False Positive", "needs-review": "Needs Review" }[verdict] || "Needs Review";
}

function buildAlertReport(alert) {
  const review = getAlertReview(alert.id);
  const related = state.logs.filter((log) => alert.relatedEventIds.includes(log.id)).slice(0, 10);
  return [
    `# SIEM Alert Report`,``,
    `Alert Name: ${alert.name}`, `Verdict: ${verdictLabel(review.verdict)}`,
    `Severity: ${toTitle(alert.severity)}`, `Category: ${toTitle(alert.category)}`,
    `Source: ${alert.source}`, `Target: ${alert.target}`,
    `Detection Rule: ${alert.rule}`, `Alert Time: ${formatTime(alert.timestamp)}`,
    `Analyst Notes: ${review.notes || "No analyst notes added yet."}`, ``,
    `## Summary`, `${alert.detail}`, ``,
    `## Recommended Action`, `${buildRecommendation(alert.category)}`, ``,
    `## Related Events`,
    ...related.map((log) => `- ${formatTime(log.timestamp)} | ${toTitle(log.event_type)} | ${log.message}`)
  ].join("\n");
}

function buildReviewedAlertsReport() {
  const reviewedAlerts = getInvestigatedAlerts(state.alerts);
  if (!reviewedAlerts.length) {
    if (state.selected?.type === "alert") {
      const selectedAlert = state.alerts.find((alert) => alert.id === state.selected.id);
      return selectedAlert ? buildAlertReport(selectedAlert) : "";
    }
    return "";
  }
  return ["# SIEM Investigation Report","",`Generated: ${formatTime(new Date().toISOString())}`,`Reviewed Alerts: ${reviewedAlerts.length}`,"",
    ...reviewedAlerts.flatMap((alert, index) => [`## Case ${index + 1}: ${alert.name}`, buildAlertReport(alert), ""])
  ].join("\n");
}

async function copyReportText(text) {
  if (!text) return;
  try { await navigator.clipboard.writeText(text); } catch (error) {
    const area = document.createElement("textarea"); area.value = text; document.body.append(area); area.select(); document.execCommand("copy"); area.remove();
  }
}

function downloadReportFile(filename, text) {
  if (!text) return;
  const blob = new Blob([text], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a"); link.href = url; link.download = filename;
  document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
}

function buildRecommendation(category) {
  return {
    identity: "Validate user activity, block the source if malicious, and reset impacted credentials.",
    malware: "Isolate the endpoint, preserve artifacts, and confirm quarantine or remediation status.",
    execution: "Review the process tree, command line, and parent process for unauthorized script execution.",
    "command-and-control": "Block outbound communication and inspect DNS or proxy history for beaconing.",
    reconnaissance: "Confirm whether scanning is authorized and isolate the originating host if not.",
    privilege: "Revert unauthorized access changes and review all admin activity around the event window.",
    exfiltration: "Review outbound transfer volume, isolate the host, and preserve evidence for scope analysis.",
    persistence: "Remove autoruns or scheduled tasks, then verify the endpoint for additional footholds.",
    movement: "Segment the affected systems and review credential usage for lateral spread.",
    cloud: "Inspect workload permissions and container runtime activity for breakout exposure.",
    "defense-evasion": "Confirm which security controls were tampered with and restore logging or protection immediately.",
    application: "Review request payloads, affected files, and any follow-on execution on the application host.",
    network: "Validate the block action and correlate the source with other denied or suspicious connections.",
    operations: "Confirm the health signal is expected and use it as supporting context during investigation."
  }[category] || "Collect more telemetry and validate the event against approved change activity.";
}

function aggregateCounts(items, key) {
  return items.reduce((acc, item) => { acc[item[key]] = (acc[item[key]] || 0) + 1; return acc; }, {});
}

function applyTimePreset(preset, autoSelect = true) {
  const { min, max } = getDateBounds(state.logs);
  state.filters.timePreset = preset;
  if (preset === "all") { state.filters.startDate = min; state.filters.endDate = max; }
  else {
    const days = presetDays[preset] || 7;
    const start = addDays(startOfDay(max), -(days - 1));
    state.filters.startDate = toDateValue(start < startOfDay(min) ? startOfDay(min) : start);
    state.filters.endDate = max;
  }
  syncDateInputs();
  if (autoSelect) recalculate(true);
}

function setCustomRange(start, end) {
  const bounds = getDateBounds(state.logs);
  let safeStart = start || bounds.min, safeEnd = end || bounds.max;
  if (safeStart > safeEnd) [safeStart, safeEnd] = [safeEnd, safeStart];
  state.filters.timePreset = safeStart === bounds.min && safeEnd === bounds.max ? "all" : "custom";
  state.filters.startDate = safeStart < bounds.min ? bounds.min : safeStart;
  state.filters.endDate = safeEnd > bounds.max ? bounds.max : safeEnd;
  syncDateInputs(); recalculate(true);
}

function syncDateBounds() {
  const { min, max } = getDateBounds(state.logs);
  el.startDateInput.min = min; el.startDateInput.max = max;
  el.endDateInput.min = min; el.endDateInput.max = max;
}

function syncDateInputs() {
  el.startDateInput.value = state.filters.startDate; el.endDateInput.value = state.filters.endDate;
  el.startDateInput.max = state.filters.endDate; el.endDateInput.min = state.filters.startDate;
}

function getDateBounds(logs) {
  if (!logs.length) return { min: "", max: "" };
  const ordered = [...logs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  return { min: toDateValue(ordered[0].timestamp), max: toDateValue(ordered[ordered.length - 1].timestamp) };
}

function injectScenario() {
  const scenarios = [
    () => [
      createLog("failed_login","91.240.118.14","vpn-gateway","medium","investigate","Burst of failed VPN logins against service account","identity"),
      createLog("failed_login","91.240.118.14","vpn-gateway","high","escalated","Password spray activity observed on VPN gateway","identity"),
      createLog("failed_login","91.240.118.14","vpn-gateway","high","escalated","Repeated authentication failure threshold reached","identity")
    ],
    () => [
      createLog("powershell_abuse","WS-LEGAL-04","powershell.exe","critical","escalated","Encoded PowerShell downloader launched from user profile","execution"),
      createLog("dns_tunnel","WS-LEGAL-04","resolver01","high","investigate","Long DNS TXT queries indicate potential tunneling","command-and-control")
    ],
    () => [
      createLog("malware_detected","WS-OPS-02","endpoint-protection","critical","contained","Trojan loader detected in unsigned payroll_update.exe","malware"),
      createLog("service_disabled","WS-OPS-02","defender","high","investigate","Endpoint protection service tampering detected after malware hit","defense-evasion")
    ],
    () => [
      createLog("port_scan","10.22.4.19","DMZ-SRV-04","medium","investigate","Horizontal scan detected from engineering subnet","reconnaissance"),
      createLog("port_scan","10.22.4.19","DMZ-SRV-05","medium","investigate","Follow-on scan detected against adjacent DMZ host","reconnaissance")
    ],
    () => [
      createLog("data_exfiltration","WS-ENG-09","198.51.100.99","critical","escalated","Outbound archive transfer exceeded engineering baseline","exfiltration"),
      createLog("beaconing","WS-ENG-09","104.244.76.5","high","investigate","Short interval beacon pattern follows large outbound transfer","command-and-control")
    ]
  ];
  const newLogs = scenarios[state.scenarioCursor % scenarios.length]();
  state.scenarioCursor += 1;
  state.logs = [...newLogs, ...state.logs].sort(sortByNewest);
  syncDateBounds();
  if (state.filters.timePreset !== "custom") applyTimePreset(state.filters.timePreset, false);
  recalculate(true);
}

function createLog(event_type, source, target, severity, status, message, category) {
  simulationClock = new Date(simulationClock.getTime() + 15 * 60 * 1000);
  return withId({ event_type, source, target, severity, status, message, category, timestamp: simulationClock.toISOString() });
}

function toggleStream() {
  if (state.streamTimer) { clearInterval(state.streamTimer); state.streamTimer = null; updateStatus(); return; }
  state.streamTimer = window.setInterval(injectScenario, 4000);
  updateStatus();
}

function resetFilters() {
  state.filters.severity = "all"; state.filters.category = "all"; state.filters.search = "";
  el.severityFilter.value = "all"; el.categoryFilter.value = "all"; el.searchInput.value = "";
  applyTimePreset("7d");
}

async function ingestLogFile(file) {
  if (!file) return;
  setUploadStatus(`Importing ${file.name}...`);
  try {
    const text = await file.text();
    const records = parseLogFileText(text, file.name);
    const importedLogs = records.map((record, index) => normalizeLogRecord(record, index, file.name)).filter(Boolean).map(withId);
    if (!importedLogs.length) throw new Error("No valid log records were detected in the uploaded file.");
    state.logs = [...importedLogs, ...state.logs].sort(sortByNewest);
    simulationClock = new Date(state.logs[0]?.timestamp || new Date().toISOString());
    syncDateBounds(); applyTimePreset("all", false); recalculate(true);
    setUploadStatus(`Imported ${importedLogs.length} events from ${file.name}`);
  } catch (error) {
    setUploadStatus(error.message || "Import failed.", true);
  } finally { el.uploadInput.value = ""; }
}

function setUploadStatus(message, isError = false) {
  // Works with both old el.uploadStatus and new UI's upload-status-text span
  const target = el.uploadStatus || document.getElementById("uploadStatus");
  if (!target) return;
  target.textContent = message;
  target.classList.toggle("is-error", isError);
}

function parseLogFileText(text, fileName) {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("The uploaded file is empty.");
  const lowerName = fileName.toLowerCase();
  if (lowerName.endsWith(".csv")) return parseCsvRecords(trimmed);
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try { return parseJsonRecords(trimmed); } catch (error) {
      const ndjson = parseNdjsonRecords(trimmed, true);
      if (ndjson.length) return ndjson;
      throw error;
    }
  }
  if (trimmed.includes(",") && trimmed.split(/\r?\n/, 1)[0].includes(",")) return parseCsvRecords(trimmed);
  return parseNdjsonRecords(trimmed, false);
}

function parseJsonRecords(text) {
  const parsed = JSON.parse(text);
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.logs)) return parsed.logs;
  if (Array.isArray(parsed.events)) return parsed.events;
  return [parsed];
}

function parseNdjsonRecords(text, allowFailure) {
  const records = [];
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    try { records.push(JSON.parse(line)); } catch (error) {
      if (!allowFailure) throw new Error("Unsupported log format. Use JSON, NDJSON, or CSV with headers.");
      return [];
    }
  }
  return records;
}

function parseCsvRecords(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  if (lines.length < 2) throw new Error("CSV upload needs a header row and at least one data row.");
  const headers = splitCsvLine(lines[0]).map((header) => header.trim().toLowerCase().replace(/\s+/g, "_"));
  return lines.slice(1).map((line) => {
    const values = splitCsvLine(line);
    return headers.reduce((record, header, index) => { record[header] = values[index] ?? ""; return record; }, {});
  });
}

function splitCsvLine(line) {
  const values = []; let current = "", inQuotes = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index], next = line[index + 1];
    if (char === '"') { if (inQuotes && next === '"') { current += '"'; index += 1; } else { inQuotes = !inQuotes; } continue; }
    if (char === "," && !inQuotes) { values.push(current.trim()); current = ""; continue; }
    current += char;
  }
  values.push(current.trim()); return values;
}

function normalizeLogRecord(record, index, fileName) {
  if (!record || typeof record !== "object") return null;
  const eventType = slugify(pickField(record, ["event_type","eventtype","type","event","activity","signature"]) || "uploaded_event", "_");
  const category = slugify(inferCategory(record, eventType), "-");
  return {
    timestamp: normalizeTimestamp(pickField(record, ["timestamp","time","date","datetime","event_time"])),
    event_type: eventType, source: pickField(record, ["source","src","source_ip","host","hostname","computer","client_ip"]) || "uploaded-source",
    target: pickField(record, ["target","dst","destination","dest_ip","service","resource","user","account"]) || "uploaded-target",
    severity: normalizeSeverity(pickField(record, ["severity","level","priority","risk","score"])),
    status: normalizeStatus(pickField(record, ["status","action","result","disposition"])),
    message: pickField(record, ["message","msg","description","details","summary"]) || `Imported event ${index + 1} from ${fileName}`,
    category
  };
}

function pickField(record, keys) {
  for (const key of keys) { if (record[key] !== undefined && record[key] !== null && String(record[key]).trim()) return String(record[key]).trim(); }
  return "";
}

function normalizeTimestamp(value) {
  const parsed = new Date(value || new Date().toISOString());
  return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

function normalizeSeverity(value) {
  const normalized = String(value || "medium").trim().toLowerCase(), score = Number(normalized);
  if (normalized.includes("crit") || (!Number.isNaN(score) && score >= 5)) return "critical";
  if (normalized.includes("high") || (!Number.isNaN(score) && score >= 4)) return "high";
  if (normalized.includes("low")  || (!Number.isNaN(score) && score <= 1)) return "low";
  return "medium";
}

function normalizeStatus(value) {
  const normalized = String(value || "investigate").trim().toLowerCase();
  if (normalized.includes("contain")) return "contained";
  if (normalized.includes("close") || normalized.includes("allow")) return "closed";
  if (normalized.includes("escalat") || normalized.includes("block")) return "escalated";
  return "investigate";
}

function inferCategory(record, eventType) {
  const explicit = pickField(record, ["category","tactic","domain","group","log_type"]);
  if (explicit) return explicit;
  const text = `${eventType} ${pickField(record, ["message","msg","description","details","summary"])}`.toLowerCase();
  if (/login|auth|credential|password|account/.test(text)) return "identity";
  if (/malware|trojan|virus|ransomware/.test(text)) return "malware";
  if (/powershell|script|macro|command/.test(text)) return "execution";
  if (/dns|beacon|c2|tunnel/.test(text)) return "command-and-control";
  if (/scan|recon/.test(text)) return "reconnaissance";
  if (/exfil|upload|transfer|usb/.test(text)) return "exfiltration";
  if (/privilege|admin/.test(text)) return "privilege";
  return "operations";
}

function slugify(value, separator) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, separator).replace(new RegExp(`^${separator}+|${separator}+$`, "g"), "") || "uploaded";
}

function startOfDay(value) { const [year, month, day] = String(value).split("-").map(Number); return new Date(year, month - 1, day, 0, 0, 0, 0); }
function endOfDay(value) { const date = startOfDay(value); date.setHours(23, 59, 59, 999); return date; }
function addDays(date, amount) { const next = new Date(date); next.setDate(next.getDate() + amount); return next; }
function toDateValue(value) { const date = new Date(value); return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`; }
function formatTime(value) { return new Date(value).toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }); }
function formatDateOnly(value) { return value ? startOfDay(value).toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" }) : "N/A"; }
function formatDay(value) { return startOfDay(value).toLocaleDateString("en-IN", { day: "2-digit", month: "short" }); }
function isSingleDaySelected(day) { return state.filters.timePreset === "custom" && state.filters.startDate === day && state.filters.endDate === day; }
function toTitle(value) { return String(value).replace(/[_-]/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()); }
function escapeHtml(value) { return String(value).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;"); }

el.severityFilter.addEventListener("change", (event) => { state.filters.severity = event.target.value; recalculate(); });
el.categoryFilter.addEventListener("change", (event) => { state.filters.category = event.target.value; recalculate(); });
el.searchInput.addEventListener("input", (event) => { state.filters.search = event.target.value; recalculate(); });
el.timeRangeButtons.addEventListener("click", (event) => { const button = event.target.closest("[data-preset]"); if (button) applyTimePreset(button.dataset.preset); });
el.startDateInput.addEventListener("change", (event) => setCustomRange(event.target.value, el.endDateInput.value));
el.endDateInput.addEventListener("change", (event) => setCustomRange(el.startDateInput.value, event.target.value));
el.simulateBtn.addEventListener("click", injectScenario);
el.streamBtn.addEventListener("click", toggleStream);
el.resetBtn.addEventListener("click", resetFilters);
el.uploadBtn.addEventListener("click", () => el.uploadInput.click());
el.uploadInput.addEventListener("change", (event) => ingestLogFile(event.target.files?.[0]));

["dragenter","dragover"].forEach((eventName) => { el.uploadDropzone.addEventListener(eventName, (event) => { event.preventDefault(); el.uploadDropzone.classList.add("drag-over"); }); });
["dragleave","dragend","drop"].forEach((eventName) => { el.uploadDropzone.addEventListener(eventName, (event) => { event.preventDefault(); el.uploadDropzone.classList.remove("drag-over"); }); });
el.uploadDropzone.addEventListener("drop", (event) => { const file = event.dataTransfer?.files?.[0]; ingestLogFile(file); });

el.exposureMap.addEventListener("click", (event) => {
  const button = event.target.closest("[data-asset]");
  if (button) { el.searchInput.value = button.dataset.asset; state.filters.search = button.dataset.asset; recalculate(); }
});
el.categoryChart.addEventListener("click", (event) => {
  const button = event.target.closest("[data-category]");
  if (!button) return;
  state.filters.category = state.filters.category === button.dataset.category ? "all" : button.dataset.category;
  el.categoryFilter.value = state.filters.category; recalculate();
});
el.trendChart.addEventListener("click", (event) => { const button = event.target.closest("[data-day]"); if (button) setCustomRange(button.dataset.day, button.dataset.day); });
el.attackPathGraph.addEventListener("click", (event) => {
  const button = event.target.closest("[data-attack-event]");
  if (button?.dataset.attackEvent) { el.searchInput.value = button.dataset.attackEvent; state.filters.search = button.dataset.attackEvent; recalculate(); }
});
el.detailPanel.addEventListener("click", async (event) => {
  const selectedAlert = getSelectedAlert();
  if (!selectedAlert) return;
  const alertId = selectedAlert.id;
  const verdictButton = event.target.closest("[data-verdict]");
  if (verdictButton) { setAlertReview(alertId, { verdict: verdictButton.dataset.verdict }); renderAlerts(); renderDetails(); return; }
  const reviewButton = event.target.closest("[data-review-action]");
  if (reviewButton) { await saveAlertReview(alertId, reviewButton.dataset.reviewAction === "save-next"); return; }
  const reportButton = event.target.closest("[data-report-action]");
  if (!reportButton) return;
  const report = buildAlertReport(selectedAlert);
  if (reportButton.dataset.reportAction === "copy") { await copyReportText(report); return; }
  downloadReportFile(`${slugify(selectedAlert.name, "-") || "alert-report"}.md`, report);
});
el.detailPanel.addEventListener("input", (event) => {
  if (event.target.id !== "alertNotesInput" || state.selected?.type !== "alert") return;
  setAlertReview(state.selected.id, { notes: event.target.value });
  refreshReviewDetail(state.selected.id);
});
el.alertsList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-alert-id]");
  if (button) { state.selected = { type: "alert", id: button.dataset.alertId }; renderDetails(); renderAlerts(); renderInvestigatedAlerts(); }
});
el.investigatedAlertsList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-alert-id]");
  if (button) { state.selected = { type: "alert", id: button.dataset.alertId }; renderDetails(); renderAlerts(); renderInvestigatedAlerts(); }
});
el.topSources.addEventListener("click", (event) => {
  const button = event.target.closest("[data-source]");
  if (button) { el.searchInput.value = button.dataset.source; state.filters.search = button.dataset.source; recalculate(); }
});
el.timelineStream.addEventListener("click", (event) => {
  const button = event.target.closest("[data-log-id]");
  if (button) { state.selected = { type: "log", id: button.dataset.logId }; renderDetails(); renderTimeline(); renderTable(); }
});
el.eventsTable.addEventListener("click", (event) => {
  const row = event.target.closest("[data-log-id]");
  if (row) { state.selected = { type: "log", id: row.dataset.logId }; renderDetails(); renderTimeline(); renderTable(); }
});
el.exportReportsBtn.addEventListener("click", async () => {
  const report = buildReviewedAlertsReport();
  if (!report) return;
  downloadReportFile("siem-investigation-report.md", report);
});

window.addEventListener("beforeunload", () => { if (state.streamTimer) clearInterval(state.streamTimer); });

// ── Severity chart type switcher ─────────────────────────────────
document.addEventListener("click", (e) => {
  // Switch chart type tab
  const tab = e.target.closest(".chart-tab[data-chart-type]");
  if (tab) {
    state.severityChartType = tab.dataset.chartType;
    // Clear drilldown when switching chart type
    state.severityDrilldown = null;
    closeSeverityDrawer();
    renderSeverityChart();
    return;
  }

  // Click on a severity bar / histogram row / donut legend item
  const sevEl = e.target.closest("[data-severity]");
  if (sevEl && el.severityChart.contains(sevEl)) {
    openSeverityDrilldown(sevEl.dataset.severity);
    return;
  }

  // Click "✕ Clear" button in chart note
  if (e.target.closest(".sev-clear-btn")) {
    closeSeverityDrawer();
    return;
  }

  // Click close button in drawer
  if (e.target.closest(".sev-drawer-close")) {
    closeSeverityDrawer();
    return;
  }

  // Click an alert item inside the drawer
  const drawerItem = e.target.closest("[data-drawer-alert-id]");
  if (drawerItem) {
    const alertId = drawerItem.dataset.drawerAlertId;
    state.selected = { type: "alert", id: alertId };
    renderDetails();
    renderAlerts();
    renderInvestigatedAlerts();
    // Highlight the selected item in the drawer
    document.querySelectorAll(".sev-drawer-item").forEach((el) => {
      el.classList.toggle("sev-drawer-item-selected", el.dataset.drawerAlertId === alertId);
    });
    return;
  }
});

loadLogs().catch((error) => {
  el.feedStatus.textContent = "Telemetry load failed";
  el.lastUpdated.textContent = "Unable to initialize dashboard";
  el.windowSummary.textContent = "Could not load the SIEM telemetry dataset.";
  console.error(error);
});
