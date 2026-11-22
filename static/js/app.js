/* Sentinel NIDS — console application (vanilla JS, no framework). */
(function () {
  "use strict";

  // ------------------------------------------------------------------ utils
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const CSRF = document.querySelector('meta[name="csrf-token"]').content;
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  const esc = (v) =>
    String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const fmtNum = (n) => {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(1) + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e4) return (n / 1e3).toFixed(1) + "k";
    return n.toLocaleString();
  };
  const fmtBytes = (b) => {
    b = Number(b) || 0;
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(1) : b) + " " + u[i];
  };
  const fmtDur = (ms) => {
    ms = Number(ms) || 0;
    if (ms < 1) return ms.toFixed(2) + " ms";
    if (ms < 1000) return ms.toFixed(0) + " ms";
    if (ms < 60000) return (ms / 1000).toFixed(1) + " s";
    return (ms / 60000).toFixed(1) + " min";
  };
  const fmtTime = (ts) => {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    const today = new Date().toDateString() === d.toDateString();
    const t = d.toLocaleTimeString([], { hour12: false });
    if (today) return t;
    const sameYear = d.getFullYear() === new Date().getFullYear();
    return d.toLocaleDateString([], sameYear ? { month: "short", day: "numeric" } : { year: "numeric", month: "short", day: "numeric" }) + " " + t;
  };
  const fmtAgo = (ts) => {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return fmtTime(ts);
  };
  const fmtUptime = (s) => {
    s = Math.floor(s);
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return (d ? d + "d " : "") + (h ? h + "h " : "") + m + "m";
  };

  const SEV_COLOR = { critical: "--critical", high: "--serious", medium: "--warning", low: "--accent", info: "--muted" };
  const sevBadge = (sev) => `<span class="badge badge--${esc(sev)}">${esc(sev[0].toUpperCase() + sev.slice(1))}</span>`;
  const verdictBadge = (f) => {
    const text = f.verdict === "benign" ? "Benign" : f.label === "Benign" ? "Anomalous" : f.label;
    return `<span class="badge badge--${esc(f.verdict)}">${esc(text)}</span>`;
  };
  const riskCell = (risk, sev) =>
    `<span class="risk"><span>${Math.round(risk)}</span><span class="risk__bar"><i style="width:${Math.min(100, risk)}%;background:var(${SEV_COLOR[sev] || "--muted"})"></i></span></span>`;
  const cc = (c) => (c ? `<span class="cc" title="${c === "LAN" ? "Private network" : "Country: " + esc(c)}">${esc(c)}</span>` : "");
  const endpoint = (ip, port, country) =>
    `<span class="endpoint">${esc(ip)}<span class="port">:${esc(port)}</span></span>${cc(country)}`;

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      credentials: "same-origin",
      ...opts,
      headers: { "X-CSRF-Token": CSRF, ...(opts.body && !(opts.body instanceof FormData) ? { "Content-Type": "application/json" } : {}), ...(opts.headers || {}) },
    });
    if (res.status === 401) { location.href = "/login?next=/"; throw new Error("auth"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  function toast(title, body, kind) {
    const el = document.createElement("div");
    el.className = "toast" + (kind ? " toast--" + kind : "");
    el.innerHTML = `<strong>${esc(title)}</strong>${esc(body || "")}`;
    $("#toasts").appendChild(el);
    setTimeout(() => el.remove(), 6000);
    while ($("#toasts").children.length > 4) $("#toasts").firstChild.remove();
  }

  function hbars(container, rows, opts = {}) {
    if (!rows.length) { container.innerHTML = `<div class="empty">${esc(opts.empty || "No data yet")}</div>`; return; }
    const max = Math.max(...rows.map((r) => r.value), 1);
    container.innerHTML = rows.map((r) => `
      <div class="hbar" title="${esc(r.title || r.label + ": " + r.value.toLocaleString())}" ${r.ip ? `data-ip="${esc(r.ip)}"` : ""}>
        <span class="hbar__label ${opts.mono ? "mono" : ""}">${r.html || esc(r.label)}</span>
        <span class="hbar__value">${esc(r.display != null ? r.display : r.value.toLocaleString())}</span>
        <span class="hbar__track"><span class="hbar__fill" style="width:${(r.value / max) * 100}%;${r.color ? "background:" + r.color : ""}"></span></span>
      </div>`).join("");
  }

  // ------------------------------------------------------------------ state
  const state = {
    view: "overview",
    summary: null,
    feed: [],
    flows: { offset: 0, limit: 50, total: 0 },
    alertStatus: "open",
    sound: localStorage.getItem("nids.sound") === "1",
    lastFlowsFetch: 0,
    lastAlertsFetch: 0,
    knownSources: new Set(),
  };

  // ------------------------------------------------------------------ routing
  const VIEWS = {
    overview: ["Overview", "Real-time network threat posture"],
    traffic: ["Traffic", "Explore and filter every classified flow"],
    alerts: ["Alerts", "Triage correlated detections"],
    forensics: ["Forensics", "Offline analysis of packet captures"],
    system: ["System", "Capture, model and configuration"],
  };

  function route() {
    const hash = location.hash.replace(/^#/, "") || "overview";
    if (hash.startsWith("flow/")) {
      const id = parseInt(hash.split("/")[1], 10);
      if (id) openFlow(id);
      if (!state.viewInit) showView("overview");
      return;
    }
    showView(VIEWS[hash] ? hash : "overview");
  }

  function showView(name) {
    state.view = name;
    state.viewInit = true;
    $$(".view").forEach((v) => (v.hidden = v.id !== "view-" + name));
    $$(".nav__item").forEach((a) => a.classList.toggle("is-active", a.dataset.view === name));
    $("#view-title").textContent = VIEWS[name][0];
    $("#view-sub").textContent = VIEWS[name][1];
    if (name === "traffic") loadFlows();
    if (name === "alerts") loadAlerts();
    if (name === "system") loadSystem();
    if (name === "forensics" && state.summary) renderJobs(state.summary.jobs);
  }

  // ------------------------------------------------------------------ overview
  let timeline;
  function initChart() {
    const grid = css("--grid"), muted = css("--muted");
    Chart.defaults.font.family = css("--font");
    Chart.defaults.color = muted;
    const ds = (label, color) => ({ label, data: [], backgroundColor: color, borderColor: css("--surface"), borderWidth: { top: 2 }, borderSkipped: false, borderRadius: 2, barPercentage: 0.9, categoryPercentage: 0.95 });
    timeline = new Chart($("#timeline-chart"), {
      type: "bar",
      data: { labels: [], datasets: [ds("Benign", css("--s-benign")), ds("Suspicious", css("--s-suspicious")), ds("Malicious", css("--s-malicious"))] },
      options: {
        responsive: true, maintainAspectRatio: false, animation: { duration: 250 },
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: css("--surface-3"), borderColor: css("--border-strong"), borderWidth: 1, titleColor: css("--text"),
            bodyColor: css("--text-2"), padding: 10, boxPadding: 4, usePointStyle: true,
            callbacks: { footer: (items) => "Total: " + items.reduce((a, i) => a + i.parsed.y, 0) },
          },
        },
        scales: {
          x: { stacked: true, grid: { display: false }, border: { color: css("--axis") }, ticks: { maxTicksLimit: 7, maxRotation: 0, font: { size: 11 } } },
          y: { stacked: true, beginAtZero: true, grid: { color: grid }, border: { display: false }, ticks: { precision: 0, maxTicksLimit: 5, font: { size: 11 } } },
        },
      },
    });
  }

  function renderSummary(s) {
    state.summary = s;
    const v = s.verdicts || {};
    const total = s.flows_total || 0;
    $("#kpi-flows").textContent = fmtNum(total);
    $("#kpi-flows-meta").textContent = fmtBytes(s.bytes_total) + " observed · up " + fmtUptime(s.uptime);
    $("#kpi-malicious").textContent = fmtNum(v.malicious || 0);
    $("#kpi-malicious-meta").textContent = (total ? (((v.malicious || 0) / total) * 100).toFixed(2) : "0") + "% of traffic";
    $("#kpi-suspicious").textContent = fmtNum(v.suspicious || 0);
    const open = s.alerts.open || 0;
    const bySev = s.alerts.open_by_severity || {};
    $("#kpi-alerts").textContent = fmtNum(open);
    $("#kpi-alerts-meta").textContent = open ? `${bySev.critical || 0} critical · ${bySev.high || 0} high` : "nothing to triage";
    $("#kpi-pps").textContent = fmtNum(Math.round(s.pps));
    $("#kpi-active").textContent = fmtNum(s.active_flows);
    $("#kpi-active-meta").textContent = s.dropped ? `${fmtNum(s.dropped)} dropped (overload)` : `queue ${s.queue_depth}`;

    const badge = $("#nav-alert-badge");
    badge.hidden = !open;
    badge.textContent = open > 99 ? "99+" : open;

    // capture pill
    const cap = s.capture || {};
    const pill = $("#capture-pill .dot");
    pill.className = "dot " + (cap.status === "running" ? "dot--live" : cap.status === "error" ? "dot--critical" : "dot--warning");
    $("#capture-text").textContent =
      cap.status === "running" ? `Live · ${cap.interface}` : cap.status === "error" ? "Capture error" : "Capture stopped";
    $("#capture-pill").title = cap.error || "";

    const b = s.baseline || {};
    $("#baseline-meta").textContent = b.calibrated ? `Baseline calibrated · ${fmtNum(b.samples)} samples` : `Baseline learning · ${b.samples}/${b.warmup}`;

    // timeline
    if (timeline) {
      timeline.data.labels = s.timeline.map((r) => new Date(r[0] * 1000).toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }));
      [1, 2, 3].forEach((i) => (timeline.data.datasets[i - 1].data = s.timeline.map((r) => r[i])));
      timeline.update("none");
    }

    // threat categories
    const labels = s.labels || {};
    const cats = Object.keys(labels).filter((k) => k !== "Benign" && labels[k] > 0).map((k) => ({ label: k, value: labels[k], color: "var(--s-malicious)" }));
    if (s.anomalies) cats.push({ label: "Anomaly (autoencoder)", value: s.anomalies, color: "var(--s-suspicious)" });
    cats.sort((a, b) => b.value - a.value);
    hbars($("#threat-categories"), cats, { empty: "No attack-class detections yet" });

    hbars($("#top-threat-src"), (s.top_threat_src || []).map(([ip, n]) => ({ label: ip, value: n, ip, color: "var(--s-malicious)" })), { mono: true, empty: "No threat sources" });
    hbars($("#top-ports"), (s.top_dports || []).map(([p, n, svc]) => ({ label: p + (svc ? " · " + svc : ""), value: n })), { empty: "No traffic yet" });

    if (state.view === "forensics") renderJobs(s.jobs);
    (s.jobs || []).forEach((j) => addSourceOption("pcap:" + j.name));
  }

  function renderFeed() {
    const tb = $("#live-feed tbody");
    if (!state.feed.length) {
      tb.innerHTML = `<tr class="empty-row"><td colspan="7">Waiting for traffic… flows appear here once they complete.</td></tr>`;
      return;
    }
    tb.innerHTML = state.feed.map((f) => `
      <tr data-id="${f.id}" class="is-${esc(f.verdict)} ${f._new ? "is-new" : ""}">
        <td class="mono">${fmtTime(f.ts_end)}</td>
        <td>${endpoint(f.src, f.sport, f.src_country)}</td>
        <td>${endpoint(f.dst, f.dport, f.dst_country)}</td>
        <td>${esc(f.proto)}</td>
        <td>${esc(f.process || "—")}</td>
        <td>${verdictBadge(f)}</td>
        <td class="num">${riskCell(f.risk, f.severity)}</td>
      </tr>`).join("");
    state.feed.forEach((f) => (f._new = false));
  }

  async function loadRecentAlerts() {
    try {
      const { alerts } = await api("/api/alerts?status=open&limit=6");
      const ul = $("#recent-alerts");
      if (!alerts.length) { ul.innerHTML = `<li class="empty">No open alerts — all clear.</li>`; return; }
      ul.innerHTML = alerts.map((a) => `
        <li class="alert-item" data-flow="${a.flow_id}">
          ${sevBadge(a.severity)}
          <div><div class="alert-item__title">${esc(a.category)}${a.count > 1 ? ` <span class="muted">×${a.count}</span>` : ""}</div>
          <div class="alert-item__meta">${esc(a.src)} → ${esc(a.dst)}:${esc(a.dport)} · ${esc(a.intel.tactic)}</div></div>
          <div class="alert-item__time">${fmtAgo(a.last_seen)}</div>
        </li>`).join("");
    } catch (e) { /* ignore */ }
  }

  // ------------------------------------------------------------------ traffic
  function flowQuery() {
    const p = new URLSearchParams();
    const q = $("#flt-q").value.trim(); if (q) p.set("q", q);
    const v = $("#flt-verdict").value; if (v) p.set("verdict", v);
    const l = $("#flt-label").value; if (l) p.set("label", l);
    const s = $("#flt-source").value; if (s) p.set("source", s);
    return p;
  }

  async function loadFlows() {
    state.lastFlowsFetch = Date.now();
    const p = flowQuery();
    $("#export-flows").href = "/api/export/flows.csv?" + p.toString();
    p.set("limit", state.flows.limit);
    p.set("offset", state.flows.offset);
    try {
      const { flows, total } = await api("/api/flows?" + p.toString());
      state.flows.total = total;
      const tb = $("#flows-table tbody");
      tb.innerHTML = flows.length ? flows.map((f) => `
        <tr data-id="${f.id}" class="is-${esc(f.verdict)}">
          <td class="mono muted">${f.id}</td>
          <td class="mono">${fmtTime(f.ts_end)}</td>
          <td>${endpoint(f.src, f.sport, f.src_country)}</td>
          <td>${endpoint(f.dst, f.dport, f.dst_country)}</td>
          <td>${esc(f.proto)}</td>
          <td class="num">${fmtNum(f.packets)}</td>
          <td class="num">${fmtBytes(f.bytes)}</td>
          <td class="num">${fmtDur(f.duration_ms)}</td>
          <td>${esc(f.process || "—")}${f.pid ? ` <span class="muted">(${f.pid})</span>` : ""}</td>
          <td>${verdictBadge(f)}</td>
          <td class="num">${(f.confidence * 100).toFixed(0)}%</td>
          <td class="num">${riskCell(f.risk, f.severity)}</td>
        </tr>`).join("") : `<tr class="empty-row"><td colspan="12">No flows match these filters.</td></tr>`;
      const from = total ? state.flows.offset + 1 : 0;
      const to = Math.min(state.flows.offset + state.flows.limit, total);
      $("#flows-count").textContent = `Showing ${from.toLocaleString()}–${to.toLocaleString()} of ${total.toLocaleString()} flows`;
      $("#flows-prev").disabled = state.flows.offset === 0;
      $("#flows-next").disabled = to >= total;
    } catch (e) { toast("Could not load flows", e.message, "critical"); }
  }

  function addSourceOption(src) {
    if (state.knownSources.has(src)) return;
    state.knownSources.add(src);
    const o = document.createElement("option");
    o.value = src; o.textContent = src.replace(/^pcap:/, "PCAP · ");
    $("#flt-source").appendChild(o);
  }

  // ------------------------------------------------------------------ alerts
  async function loadAlerts() {
    state.lastAlertsFetch = Date.now();
    const p = new URLSearchParams({ status: state.alertStatus, limit: 200 });
    const sev = $("#alert-sev").value; if (sev) p.set("severity", sev);
    try {
      const { alerts, total } = await api("/api/alerts?" + p.toString());
      const tb = $("#alerts-table tbody");
      tb.innerHTML = alerts.length ? alerts.map((a) => `
        <tr data-alert="${a.id}">
          <td>${sevBadge(a.severity)}</td>
          <td><div style="font-weight:550">${esc(a.category)}</div><div class="muted" style="font-size:12px">${esc(a.intel.tactic)} · ${esc(a.intel.technique)}</div></td>
          <td><span class="endpoint">${esc(a.src)}</span><span class="arrow">→</span><span class="endpoint">${esc(a.dst)}<span class="port">:${esc(a.dport)}</span></span> <span class="muted">${esc(a.proto)}</span></td>
          <td class="num">${fmtNum(a.count)}</td>
          <td class="mono">${fmtTime(a.first_seen)}</td>
          <td class="mono">${fmtTime(a.last_seen)}</td>
          <td class="num">${Math.round(a.max_risk)}</td>
          <td><span class="status-tag status-tag--${esc(a.status)}">${esc(a.status)}</span>${a.updated_by ? `<div class="muted" style="font-size:11.5px">by ${esc(a.updated_by)}</div>` : ""}</td>
          <td><div class="actions">
            <button class="btn btn--sm" data-act="view" data-flow="${a.flow_id}">Investigate</button>
            ${a.status === "open" ? `<button class="btn btn--sm" data-act="acknowledged">Acknowledge</button>` : ""}
            ${a.status !== "resolved" ? `<button class="btn btn--sm" data-act="resolved">Resolve</button>` : `<button class="btn btn--sm" data-act="open">Reopen</button>`}
          </div></td>
        </tr>`).join("") : `<tr class="empty-row"><td colspan="9">No ${state.alertStatus === "all" ? "" : esc(state.alertStatus)} alerts.</td></tr>`;
      $("#alerts-count").textContent = `${total.toLocaleString()} alert${total === 1 ? "" : "s"}`;
    } catch (e) { toast("Could not load alerts", e.message, "critical"); }
  }

  async function updateAlert(id, status) {
    try {
      await api(`/api/alerts/${id}`, { method: "POST", body: JSON.stringify({ status }) });
      toast("Alert updated", `Alert #${id} marked ${status}.`);
      loadAlerts(); loadRecentAlerts();
    } catch (e) { toast("Update failed", e.message, "critical"); }
  }

  // ------------------------------------------------------------------ forensics
  function renderJobs(jobs) {
    const tb = $("#jobs-table tbody");
    if (!jobs || !jobs.length) { tb.innerHTML = `<tr class="empty-row"><td colspan="7">No captures analyzed in this session.</td></tr>`; return; }
    const st = { completed: "benign", running: "low", analyzing: "low", queued: "info", failed: "critical" };
    tb.innerHTML = jobs.map((j) => `
      <tr>
        <td class="mono">${esc(j.name)}</td>
        <td><span class="badge badge--${st[j.status] || "info"}" title="${esc(j.error || "")}">${esc(j.status)}</span></td>
        <td class="num">${fmtNum(j.packets)}</td>
        <td class="num">${fmtNum(j.flows)}</td>
        <td class="num">${fmtNum(j.threats)}</td>
        <td class="mono">${fmtTime(j.started)}</td>
        <td><button class="btn btn--sm" data-source="${esc("pcap:" + j.name)}">View flows</button></td>
      </tr>`).join("");
  }

  function uploadPcap(file) {
    if (!file) return;
    const box = $("#upload-status");
    box.hidden = false;
    box.innerHTML = `Uploading <strong>${esc(file.name)}</strong>…<div class="progress"><i style="width:0%"></i></div>`;
    const fd = new FormData();
    fd.append("file", file);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/pcap");
    xhr.setRequestHeader("X-CSRF-Token", CSRF);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) $(".progress i", box).style.width = (e.loaded / e.total) * 100 + "%"; };
    xhr.onload = () => {
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch (e) { /* noop */ }
      if (xhr.status === 202) {
        box.innerHTML = `<strong>${esc(file.name)}</strong> queued for analysis. Results stream into Traffic and Alerts.`;
        toast("Capture uploaded", file.name + " is being analyzed.");
        addSourceOption("pcap:" + data.job.name);
      } else {
        box.innerHTML = `<div class="callout">Upload failed: ${esc(data.error || xhr.statusText)}</div>`;
      }
    };
    xhr.onerror = () => (box.innerHTML = `<div class="callout">Upload failed: network error</div>`);
    xhr.send(fd);
  }

  // ------------------------------------------------------------------ system
  const kv = (el, rows) => (el.innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join(""));

  async function loadSystem() {
    try {
      const s = await api("/api/system");
      const c = s.config, cap = s.capture;
      kv($("#capture-info"), [
        ["Status", cap.status === "running" ? '<span class="badge badge--benign">Running</span>' : cap.status === "error" ? '<span class="badge badge--critical">Error</span>' : '<span class="badge badge--info">Stopped</span>'],
        ["Interface", esc(c.interface)],
        ["BPF filter", `<span class="mono">${esc(c.bpf_filter || "none")}</span>`],
        ["Idle / active timeout", `${c.idle_timeout}s / ${c.active_timeout}s`],
        ["Flow table capacity", fmtNum(c.max_active_flows)],
        ["Process attribution", s.process_attribution ? "Enabled" : "Unavailable (needs elevated privileges)"],
      ]);
      const err = $("#capture-error");
      err.hidden = !cap.error;
      if (cap.error) err.innerHTML = `<strong>Capture error:</strong> ${esc(cap.error)}<br>Run the console as Administrator (Windows, with <a href="https://npcap.com" target="_blank" rel="noopener">Npcap</a>) or root / CAP_NET_RAW (Linux). Choose an interface with <span class="mono">--iface</span>; list them with <span class="mono">--list-interfaces</span>.`;
      $("#capture-start").disabled = cap.status === "running";
      $("#capture-stop").disabled = cap.status !== "running";

      const m = s.model, b = s.baseline;
      kv($("#model-info"), [
        ["Classifier", `${esc(m.type)} · ${m.n_estimators || "?"} trees · ${m.features} features`],
        ["Classes", m.classes.map((x) => `<span class="badge badge--plain badge--info">${esc(x)}</span>`).join(" ")],
        ["Anomaly model", `Dense autoencoder · ${m.autoencoder_layers} layers (NumPy runtime)`],
        ["Adaptive baseline", b.calibrated ? `Calibrated on ${fmtNum(b.samples)} benign flows · threshold ${b.threshold.toExponential(2)}` : `Learning (${b.samples}/${b.warmup} benign flows)`],
        ["Alert confidence ≥", (c.alert_min_confidence * 100).toFixed(0) + "%"],
        ["Anomaly alerts", c.anomaly_alerts ? `On · p${c.anomaly_percentile} of baseline` : "Off"],
      ]);
      hbars($("#importance"), m.global_importance.map((g) => ({ label: g.feature, value: g.importance, display: (g.importance * 100).toFixed(1) + "%" })));
      kv($("#config-info"), [
        ["Console bind", `<span class="mono">${esc(c.host)}:${c.port}</span>`],
        ["Authentication", c.auth_enabled ? "Enabled" : '<span class="badge badge--medium">Disabled</span>'],
        ["Alert de-dup window", c.alert_dedup_window + "s"],
        ["Allow-list", c.allowlist.length ? `<span class="mono">${esc(c.allowlist.join(", "))}</span>` : "—"],
        ["Block-list (threat intel)", c.blocklist.length ? `<span class="mono">${esc(c.blocklist.join(", "))}</span>` : "—"],
        ["GeoIP enrichment", c.geoip_enabled ? "ipinfo.io" : "Off"],
        ["Webhook notifications", c.webhook_configured ? "Configured" : "Not configured"],
        ["SIEM log", '<span class="mono">data/alerts.jsonl</span> (ECS JSON lines)'],
        ["Retention", c.retention_days + " days"],
        ["Version", esc(s.version)],
      ]);
    } catch (e) { toast("Could not load system info", e.message, "critical"); }
  }

  async function capture(action) {
    try {
      const st = await api("/api/capture", { method: "POST", body: JSON.stringify({ action }) });
      toast("Capture " + (action === "start" ? "start" : "stop") + " requested", st.error ? "Error: " + st.error : "Status: " + st.status, st.error ? "critical" : "");
    } catch (e) { toast("Capture control failed", e.message, "critical"); }
    loadSystem();
  }

  // ------------------------------------------------------------------ drawer
  async function openFlow(id) {
    const drawer = $("#flow-drawer");
    $("#drawer-backdrop").hidden = false;
    drawer.classList.add("is-open");
    drawer.setAttribute("aria-hidden", "false");
    $("#drawer-title").textContent = "Flow #" + id;
    $("#drawer-eyebrow").textContent = "Loading…";
    $("#drawer-body").innerHTML = `<div class="empty">Analyzing flow…</div>`;
    try {
      const f = await api("/api/flows/" + id);
      renderFlow(f);
    } catch (e) {
      $("#drawer-body").innerHTML = `<div class="callout">Could not load flow: ${esc(e.message)}</div>`;
    }
  }

  function closeFlow() {
    $("#flow-drawer").classList.remove("is-open");
    $("#flow-drawer").setAttribute("aria-hidden", "true");
    $("#drawer-backdrop").hidden = true;
    if (location.hash.startsWith("#flow/")) history.replaceState(null, "", "#" + state.view);
  }

  function renderFlow(f) {
    $("#drawer-eyebrow").innerHTML = `Flow #${f.id} · ${esc(f.proto)} · ${esc(f.source)} ${verdictBadge(f)} ${sevBadge(f.severity)}`;
    $("#drawer-title").innerHTML = `${esc(f.src)}:${esc(f.sport)} <span class="arrow">→</span> ${esc(f.dst)}:${esc(f.dport)}`;

    const probs = Object.entries(f.probs).sort((a, b) => b[1] - a[1]);
    const ex = f.explanation;
    const maxW = Math.max(...ex.contributions.map((c) => Math.abs(c.weight)), 1e-9);
    const rec = f.reconstruction;
    const intel = f.intel;

    $("#drawer-body").innerHTML = `
      <section class="stat-grid">
        <div class="stat"><div class="stat__label">Risk score</div><div class="stat__value">${Math.round(f.risk)} / 100</div></div>
        <div class="stat"><div class="stat__label">Model confidence${f.detection ? ` (${esc(probs[0] ? probs[0][0] : "")})` : ""}</div><div class="stat__value">${(f.confidence * 100).toFixed(1)}%</div></div>
        <div class="stat"><div class="stat__label">Anomaly score</div><div class="stat__value">${f.anomaly_score ? f.anomaly_score.toFixed(2) + "×" : "—"}</div></div>
        <div class="stat"><div class="stat__label">Duration</div><div class="stat__value">${fmtDur(f.duration_ms)}</div></div>
        <div class="stat"><div class="stat__label">Packets / bytes</div><div class="stat__value">${fmtNum(f.packets)} / ${fmtBytes(f.bytes)}</div></div>
        <div class="stat"><div class="stat__label">Process</div><div class="stat__value" style="font-size:14px">${esc(f.process || "—")}${f.pid ? ` <span class="muted">PID ${f.pid}</span>` : ""}</div></div>
      </section>

      <section>
        <h3>Threat intelligence</h3>
        <div class="intel">
          <dl class="kv">
            <dt>Classification</dt><dd>${esc(f.label)}${f.verdict === "suspicious" && f.label === "Benign" ? " (anomalous)" : ""}</dd>
            ${f.detection ? `<dt>Correlation</dt><dd>${esc(f.detection)} <span class="muted">(overrides the per-flow model verdict)</span></dd>` : ""}
            <dt>MITRE ATT&amp;CK tactic</dt><dd>${esc(intel.tactic)}</dd>
            <dt>Technique</dt><dd>${esc(intel.technique)}</dd>
            <dt>Source / destination</dt><dd>${endpoint(f.src, f.sport, f.src_country)} → ${endpoint(f.dst, f.dport, f.dst_country)}</dd>
            <dt>Observed</dt><dd>${fmtTime(f.ts_start)} → ${fmtTime(f.ts_end)} · ended by ${esc(f.end_reason)}</dd>
          </dl>
          <p>${esc(intel.description)}</p>
          <p><strong>Recommended action:</strong> ${esc(intel.recommendation)}</p>
        </div>
      </section>

      <section>
        <h3>Class probabilities</h3>
        <div class="hbars hbars--compact" id="d-probs"></div>
      </section>

      <section>
        <h3>Why this verdict</h3>
        <p class="muted" style="margin:-4px 0 10px;font-size:12.5px">Local feature influence on P(${esc(ex.target_class)}) = ${(ex.target_probability * 100).toFixed(1)}% · ${esc(ex.method)}</p>
        ${ex.contributions.map((c) => {
          const w = (Math.abs(c.weight) / maxW) * 100;
          return `<div class="contrib" title="${esc(c.feature)} = ${esc(c.value.toLocaleString())} · weight ${c.weight}">
            <span class="contrib__label">${esc(c.feature)}</span>
            <span class="contrib__neg">${c.weight < 0 ? `<i style="width:${w}%"></i>` : ""}</span>
            <span class="contrib__pos">${c.weight > 0 ? `<i style="width:${w}%"></i>` : ""}</span>
            <span class="contrib__val">${c.weight > 0 ? "+" : ""}${c.weight.toFixed(4)}</span></div>`;
        }).join("")}
        <div class="contrib-legend"><span>← lowers ${esc(ex.target_class)}</span><span>raises ${esc(ex.target_class)} →</span></div>
      </section>

      <section>
        <h3>Autoencoder reconstruction</h3>
        <p class="muted" style="margin:-4px 0 10px;font-size:12.5px">MSE ${rec.mse.toExponential(3)}${rec.threshold ? ` · adaptive threshold ${rec.threshold.toExponential(3)} · ${rec.score.toFixed(2)}× baseline` : " · baseline still calibrating"}. Features the model of normal traffic struggled to reproduce:</p>
        <div class="hbars hbars--compact" id="d-recon"></div>
      </section>

      <section>
        <details class="features">
          <summary>All ${f.feature_table.length} flow features</summary>
          <table class="table"><tbody>
            ${f.feature_table.map((r) => `<tr><td>${esc(r.label)}</td><td class="num mono">${esc(Number(r.value).toLocaleString(undefined, { maximumFractionDigits: 4 }))}</td></tr>`).join("")}
          </tbody></table>
        </details>
      </section>

      <section class="btn-group">
        <button class="btn" data-filter-ip="${esc(f.src)}">Flows from ${esc(f.src)}</button>
        <button class="btn" data-filter-ip="${esc(f.dst)}">Flows with ${esc(f.dst)}</button>
      </section>`;

    hbars($("#d-probs"), probs.map(([k, p]) => ({ label: k, value: p, display: (p * 100).toFixed(1) + "%", color: k === "Benign" ? "var(--s-benign)" : "var(--s-malicious)" })));
    hbars($("#d-recon"), rec.top.map((t) => ({ label: t.feature, value: t.error, display: t.error.toFixed(4), color: "var(--s-suspicious)" })));
  }

  // ------------------------------------------------------------------ live channel
  function playAlarm() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      [0, 0.18].forEach((t) => {
        const o = ctx.createOscillator(), g = ctx.createGain();
        o.type = "sine"; o.frequency.value = 880;
        g.gain.setValueAtTime(0.06, ctx.currentTime + t);
        g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + t + 0.14);
        o.connect(g); g.connect(ctx.destination);
        o.start(ctx.currentTime + t); o.stop(ctx.currentTime + t + 0.15);
      });
    } catch (e) { /* noop */ }
  }

  function onTick(msg) {
    renderSummary(msg.summary);

    if (msg.flows && msg.flows.length) {
      msg.flows.forEach((f) => (f._new = true));
      state.feed = msg.flows.slice().reverse().concat(state.feed).slice(0, 12);
      renderFeed();
      msg.flows.forEach((f) => addSourceOption(f.source));
      if (state.view === "traffic" && $("#flt-live").checked && state.flows.offset === 0 && Date.now() - state.lastFlowsFetch > 2000) loadFlows();
    }

    if (msg.alerts && msg.alerts.length) {
      loadRecentAlerts();
      if (state.view === "alerts" && Date.now() - state.lastAlertsFetch > 1500) loadAlerts();
      const fresh = msg.alerts.filter((a) => a.is_new);
      fresh.filter((a) => a.severity === "critical" || a.severity === "high").slice(0, 3).forEach((a) =>
        toast(`${a.severity.toUpperCase()} · ${a.category}`, `${a.src} → ${a.dst}:${a.dport}`, a.severity === "critical" ? "critical" : ""));
      const crit = fresh.find((a) => a.severity === "critical");
      if (crit) {
        $("#critical-banner").hidden = false;
        $("#critical-banner-text").textContent = ` ${crit.category} from ${crit.src} → ${crit.dst}:${crit.dport}`;
        if (state.sound) playAlarm();
      }
    }
  }

  function connect() {
    const socket = io("/live", { transports: ["websocket", "polling"] });
    socket.on("connect", () => $("#engine-meta").textContent = "RF + Autoencoder · connected");
    socket.on("disconnect", () => {
      $("#engine-meta").textContent = "Reconnecting…";
      $("#capture-pill .dot").className = "dot dot--warning";
      $("#capture-text").textContent = "Console offline";
    });
    socket.on("tick", onTick);
  }

  // ------------------------------------------------------------------ wiring
  function wire() {
    window.addEventListener("hashchange", route);

    document.addEventListener("click", (e) => {
      const row = e.target.closest("#live-feed tbody tr[data-id], #flows-table tbody tr[data-id]");
      if (row) return openFlow(+row.dataset.id);
      const al = e.target.closest(".alert-item[data-flow]");
      if (al) return openFlow(+al.dataset.flow);
      const act = e.target.closest("[data-act]");
      if (act) {
        const id = +act.closest("tr").dataset.alert;
        return act.dataset.act === "view" ? openFlow(+act.dataset.flow) : updateAlert(id, act.dataset.act);
      }
      const ipEl = e.target.closest("[data-filter-ip], .hbar[data-ip]");
      if (ipEl) {
        closeFlow();
        $("#flt-q").value = ipEl.dataset.filterIp || ipEl.dataset.ip;
        $("#flt-verdict").value = ""; $("#flt-label").value = ""; $("#flt-source").value = "";
        state.flows.offset = 0;
        location.hash = "traffic"; if (state.view === "traffic") loadFlows();
        return;
      }
      const srcBtn = e.target.closest("[data-source]");
      if (srcBtn) {
        addSourceOption(srcBtn.dataset.source);
        $("#flt-source").value = srcBtn.dataset.source;
        $("#flt-q").value = ""; $("#flt-verdict").value = ""; $("#flt-label").value = "";
        state.flows.offset = 0;
        location.hash = "traffic"; if (state.view === "traffic") loadFlows();
      }
    });

    $("#drawer-close").addEventListener("click", closeFlow);
    $("#drawer-backdrop").addEventListener("click", closeFlow);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeFlow(); });

    let debounce;
    $("#flt-q").addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(() => { state.flows.offset = 0; loadFlows(); }, 300); });
    ["#flt-verdict", "#flt-label", "#flt-source"].forEach((s) => $(s).addEventListener("change", () => { state.flows.offset = 0; loadFlows(); }));
    $("#flows-prev").addEventListener("click", () => { state.flows.offset = Math.max(0, state.flows.offset - state.flows.limit); loadFlows(); });
    $("#flows-next").addEventListener("click", () => { state.flows.offset += state.flows.limit; loadFlows(); });

    $("#global-search").addEventListener("submit", (e) => {
      e.preventDefault();
      $("#flt-q").value = $("#global-search input").value.trim();
      state.flows.offset = 0;
      location.hash = "traffic"; if (state.view === "traffic") loadFlows();
    });

    $$("#alert-tabs .tab").forEach((t) => t.addEventListener("click", () => {
      $$("#alert-tabs .tab").forEach((x) => x.classList.toggle("is-active", x === t));
      state.alertStatus = t.dataset.status; loadAlerts();
    }));
    $("#alert-sev").addEventListener("change", loadAlerts);

    const dz = $("#dropzone");
    $("#pcap-input").addEventListener("change", (e) => uploadPcap(e.target.files[0]));
    ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("is-over"); }));
    ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("is-over"); }));
    dz.addEventListener("drop", (e) => uploadPcap(e.dataTransfer.files[0]));

    $("#capture-start").addEventListener("click", () => capture("start"));
    $("#capture-stop").addEventListener("click", () => capture("stop"));

    const snd = $("#sound-toggle");
    snd.setAttribute("aria-pressed", String(state.sound));
    snd.addEventListener("click", () => {
      state.sound = !state.sound;
      localStorage.setItem("nids.sound", state.sound ? "1" : "0");
      snd.setAttribute("aria-pressed", String(state.sound));
      toast("Audible alerts " + (state.sound ? "on" : "off"), state.sound ? "A tone plays for new critical alerts." : "");
    });
    $("#critical-banner-close").addEventListener("click", () => ($("#critical-banner").hidden = true));
  }

  document.addEventListener("DOMContentLoaded", () => {
    initChart();
    wire();
    renderFeed();
    route();
    loadRecentAlerts();
    api("/api/summary").then(renderSummary).catch(() => {});
    api("/api/flows?limit=12").then(({ flows }) => { state.feed = flows; renderFeed(); }).catch(() => {});
    connect();
  });
})();
