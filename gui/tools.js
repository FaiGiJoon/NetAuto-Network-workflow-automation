/* NetAuto Console: the working tools (Wi-Fi scan, nmap, packet capture, ping,
 * trace route, Zabbix, Git & GitHub), Diagnostics with the debug log, and
 * Settings. Everything runs on this computer through the local server. */
(() => {
  "use strict";

  const A = window.NETAUTO_APP;
  const { $, $$, esc, api } = A;
  const PAGES = (window.NETAUTO_PAGES = {});
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const fmtBytes = (n) => (n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n > 1e3 ? `${(n / 1e3).toFixed(1)} kB` : `${n} B`);
  const ago = (t) => { const s = Math.max(0, Date.now() / 1000 - t); return s < 60 ? `${s | 0} s ago` : s < 3600 ? `${(s / 60) | 0} min ago` : s < 86400 ? `${(s / 3600) | 0} h ago` : `${(s / 86400) | 0} d ago`; };
  const errText = (e) => (e && e.message) || String(e);

  const S = {
    tool: localStorage.getItem("netauto-tool") || "checkup",
    tools: null, netinfo: null, ifaces: [], ifaceError: "",
    runs: {},              // tool id -> latest job view (with .all lines)
    extra: {},             // tool id -> extra data (github overview ...)
    log: [], logSince: 0, logTimer: null,
    diag: null, slug: null,
  };

  // ------------------------------------------------------------------ jobs
  async function runJob(kind, params, onUpdate) {
    const first = await api("api/jobs", { kind, params: params || {} });
    const all = [];
    let since = 0;
    let view = { ...first, all };
    onUpdate && onUpdate(view);
    for (;;) {
      await sleep(view.status === "running" ? 450 : 0);
      let v;
      try { v = await api(`api/jobs/${first.id}?since=${since}`); } catch (e) { await sleep(1000); continue; }
      all.push(...v.lines);
      since = v.next;
      view = { ...v, all };
      onUpdate && onUpdate(view);
      if (v.status !== "running") return view;
    }
  }
  const stopJob = (id) => api(`api/jobs/${id}/cancel`, {}).catch(() => {});

  function consoleHtml(view) {
    if (!view) return "";
    const state = view.status === "running" ? `<span class="spin"></span>running ${view.seconds} s`
      : view.status === "done" ? `done in ${view.seconds} s` : view.status === "cancelled" ? "stopped" : `failed${view.error ? ": " + esc(view.error) : ""}`;
    return `<details class="console-box" ${view.status === "running" || view.status === "failed" ? "open" : ""}>
      <summary><span class="job-badge ${view.status}">${view.status}</span> ${state}<code>${esc(view.cmd || view.title)}</code></summary>
      <pre class="console">${esc((view.all || []).join("\n")) || "(no output yet)"}</pre></details>`;
  }

  function scrollConsole(root) {
    $$("pre.console", root).forEach((pre) => { pre.scrollTop = pre.scrollHeight; });
  }

  // ------------------------------------------------------------------ tool registry
  const TOOLS = [
    { id: "checkup", name: "Network check-up", sub: "Find and fix problems automatically", need: null },
    { id: "wifi", name: "Wi-Fi scan", sub: "Networks, signal, channels, security", need: "wifi" },
    { id: "nmap", name: "Network scan", sub: "Devices and open ports with nmap", need: "nmap" },
    { id: "capture", name: "Packet capture", sub: "Live packets with Wireshark's tshark", need: "tshark" },
    { id: "ping", name: "Ping", sub: "Is it up, and how fast", need: "ping" },
    { id: "trace", name: "Trace route", sub: "Every hop to a host", need: "traceroute" },
    { id: "zabbix", name: "Zabbix", sub: "Open problems and hosts", need: null },
    { id: "git", name: "Git & GitHub", sub: "Status, fetch, pull, PRs, Actions", need: "git" },
  ];

  const found = (need) => !need || !S.tools || (S.tools.tools[need] || {}).found;

  async function loadToolInfo(force) {
    if (S.tools && !force) return;
    try {
      [S.tools, S.netinfo] = await Promise.all([api("api/tools"), api("api/netinfo")]);
    } catch (e) { S.tools = null; }
  }

  function renderToolList() {
    $("#tool-list").innerHTML = TOOLS.map((t) => {
      const ok = found(t.need);
      return `<button class="wf tool-item${t.id === S.tool ? " open" : ""}" data-tool="${t.id}">
        <span class="avail ${ok ? "ok" : "miss"}" title="${ok ? "installed" : "not installed"}"></span>
        <span class="t"><b>${esc(t.name)}</b><span>${esc(t.sub)}</span></span>
        <svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg></button>`;
    }).join("");
    const n = S.netinfo, t = S.tools;
    $("#netinfo").innerHTML = n ? `<div class="h-small">This computer</div><dl class="kv small">
      <dt>Name</dt><dd>${esc(n.hostname)}</dd><dt>Address</dt><dd>${esc(n.local_ip || "?")}</dd>
      <dt>Gateway</dt><dd>${esc(n.gateway || "?")}</dd><dt>Network</dt><dd>${esc(n.suggested_subnet || "?")}</dd>
      <dt>Rights</dt><dd>${t && t.admin ? "administrator" : "normal user"}</dd></dl>` : "";
  }

  function missingNote(tool) {
    if (found(tool.need)) return "";
    const info = S.tools.tools[tool.need];
    return `<div class="warnbox"><b>${esc(tool.name)} needs ${esc(tool.need === "wifi" ? "a Wi-Fi scanner" : tool.need)}, and it was not found.</b>
      ${info.hint ? `Install it: <code>${esc(info.hint)}</code>` : ""} Then click <button class="linkbtn" data-recheck>check again</button>.
      ${canInstall(tool.need) ? `<div class="row-actions"><button class="btn primary" data-install="${esc(tool.need)}">Install ${esc(tool.need)} now</button></div>` : ""}</div>`;
  }

  const canInstall = (need) => S.tools && ["nmap", "tshark", "wireshark", "git"].includes(need) &&
    ((S.tools.system === "Windows" && (S.tools.tools.winget || {}).found) || (S.tools.system === "Darwin" && (S.tools.tools.brew || {}).found));

  // ------------------------------------------------------------------ tools page
  PAGES.tools = async () => {
    if (!A.state.live) {
      $("#tool-list").innerHTML = "";
      $("#tool-main").innerHTML = `<div class="offline-note">The tools run on your computer through the local server.
        Start the console with <code>python apps/netauto_cli.py gui</code> and open the address it prints.</div>`;
      return;
    }
    await loadToolInfo(true);
    renderToolList();
    renderTool();
  };

  function renderTool() {
    const t = TOOLS.find((x) => x.id === S.tool) || TOOLS[0];
    const n = S.netinfo || {};
    let form = "";
    const chips = (items) => `<div class="quick">${items.filter((i) => i[1]).map(([label, value]) => `<button type="button" data-fill="${esc(value)}">${esc(label)}</button>`).join("")}</div>`;
    if (t.id === "checkup") {
      const mt = S.tools && S.tools.mikrotik;
      form = `<p class="muted">Your automated network engineer. It tests the connection to your router and the internet, DNS, your Wi-Fi, scans the devices on your network for risky open ports and new devices, and audits your MikroTik. Every finding comes with a fix; router fixes can be applied from here.</p>
        <div class="checks">
          <label><input type="checkbox" id="c-wifi" checked> Wi-Fi</label>
          <label><input type="checkbox" id="c-devices" ${found("nmap") ? "checked" : "disabled"}> Devices on my network ${found("nmap") ? "" : "(needs nmap)"}</label>
          <label><input type="checkbox" id="c-mikrotik" ${mt ? "checked" : "disabled"}> My MikroTik ${mt ? "" : '(set it up on <button class="linkbtn" data-goto="settings">Settings</button>)'}</label>
        </div>
        <div class="row-actions"><button class="btn primary" data-run>Run check-up</button><span class="muted small-text">Takes 20 seconds to a few minutes, depending on the device scan.</span></div>`;
    } else if (t.id === "wifi") {
      form = `<p class="muted">Lists every Wi-Fi network your computer can hear: name, signal, channel, band and security. Use it to pick a quiet channel and to spot open networks.</p>
        <div class="row-actions"><button class="btn primary" data-run>Scan Wi-Fi</button></div>`;
    } else if (t.id === "nmap") {
      const profiles = (S.tools && S.tools.nmap_profiles) || {};
      form = `<p class="muted">Finds the devices on a network and the ports they have open. Only scan networks you own or may test.</p>
        <div class="form-grid">
          <label>Target<input id="f-target" value="${esc(n.suggested_subnet || "")}" placeholder="192.168.1.0/24, 192.168.1.10 or a host name" spellcheck="false"></label>
          <label>Scan<select id="f-profile">${Object.entries(profiles).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("")}</select></label>
        </div>
        ${chips([["My network " + (n.suggested_subnet || ""), n.suggested_subnet], ["Gateway " + (n.gateway || ""), n.gateway], ["This computer", n.local_ip]])}
        <div class="row-actions"><button class="btn primary" data-run>Start scan</button><button class="btn" data-stop hidden>Stop</button></div>`;
    } else if (t.id === "capture") {
      const presets = [["Everything", ""], ["Web (443)", "tcp port 443"], ["DNS", "udp port 53"], ["ICMP", "icmp"], ["ARP", "arp"],
        ["DHCP", "udp port 67 or udp port 68"], ["Gateway", n.gateway ? `host ${n.gateway}` : ""]];
      form = `<p class="muted">Captures live packets on a network card, like Wireshark. You get a table here, a .pcapng file to download, and a button to open it in Wireshark.</p>
        <div class="form-grid">
          <label>Interface<select id="f-iface">${S.ifaces.map((i) => `<option value="${esc(i.index)}">${esc(i.index)}. ${esc(i.label)}${i.label !== i.name ? "" : ""}</option>`).join("") || "<option value=''>(click Refresh)</option>"}</select></label>
          <label>Packets<input id="f-count" type="number" min="1" max="10000" value="300"></label>
          <label>Seconds<input id="f-seconds" type="number" min="1" max="600" value="20"></label>
          <label class="span2">Capture filter (BPF, optional)<input id="f-filter" placeholder="e.g. tcp port 443, host 192.168.1.1, udp port 53" spellcheck="false"></label>
        </div>
        <div class="quick">${presets.filter((p) => p[0] === "Everything" || p[1]).map(([l, v]) => `<button type="button" data-filter="${esc(v)}">${esc(l)}</button>`).join("")}</div>
        ${S.ifaceError ? `<div class="warnbox">${esc(S.ifaceError)}</div>` : ""}
        <div class="row-actions"><button class="btn primary" data-run>Start capture</button><button class="btn" data-stop hidden>Stop</button>
          <button class="btn" data-ifaces>Refresh interfaces</button></div>`;
    } else if (t.id === "ping") {
      form = `<p class="muted">Sends a few echo requests and shows how many come back and how fast.</p>
        <div class="form-grid"><label>Host<input id="f-target" value="${esc(n.gateway || "1.1.1.1")}" spellcheck="false"></label>
          <label>Count<input id="f-count" type="number" min="1" max="50" value="4"></label></div>
        ${chips([["Gateway", n.gateway], ["Cloudflare 1.1.1.1", "1.1.1.1"], ["Google DNS 8.8.8.8", "8.8.8.8"], ["github.com", "github.com"]])}
        <div class="row-actions"><button class="btn primary" data-run>Ping</button><button class="btn" data-stop hidden>Stop</button></div>`;
    } else if (t.id === "trace") {
      form = `<p class="muted">Shows every router between this computer and a host, with the delay to each one.</p>
        <div class="form-grid"><label>Host<input id="f-target" value="1.1.1.1" spellcheck="false"></label>
          <label>Max hops<input id="f-hops" type="number" min="1" max="40" value="20"></label></div>
        ${chips([["Cloudflare 1.1.1.1", "1.1.1.1"], ["github.com", "github.com"], ["Gateway", n.gateway]])}
        <div class="row-actions"><button class="btn primary" data-run>Trace</button><button class="btn" data-stop hidden>Stop</button></div>`;
    } else if (t.id === "zabbix") {
      form = `<p class="muted">Reads the open problems and the number of hosts from your Zabbix server through its API. Set the address and an API token on the <button class="linkbtn" data-goto="settings">Settings</button> page.</p>
        <div class="row-actions"><button class="btn primary" data-run>Load from Zabbix</button></div>`;
    } else if (t.id === "git") {
      form = `<p class="muted">Your repo's Git status and its GitHub page: open pull requests and the latest Actions runs. Fetch and Pull only fast-forward; nothing is pushed.</p>
        <div class="row-actions"><button class="btn primary" data-run>Refresh</button><button class="btn" data-git="git-fetch">Fetch</button>
          <button class="btn" data-git="git-pull">Pull (fast-forward)</button></div>`;
    }
    $("#tool-main").innerHTML = `<div class="card tool-card">
        <div class="card-head"><span class="dash"></span>${esc(t.name)}<span class="right">${t.need && S.tools && S.tools.tools[t.need] ? esc(S.tools.tools[t.need].path) : ""}</span></div>
        ${missingNote(t)}${form}</div>
      <div id="tool-result"></div><div id="tool-console"></div>`;
    if (t.id === "capture" && !S.ifaces.length && !S.ifaceError && found("tshark")) refreshIfaces();
    paintRun(t.id);
    if (t.id === "git" && !S.runs.git) runTool();
  }

  async function refreshIfaces() {
    try {
      const r = await api("api/capture/interfaces");
      S.ifaces = r.interfaces; S.ifaceError = r.error;
      // prefer an interface that looks like Wi-Fi or Ethernet
      if (S.tool === "capture") {
        renderTool();
        const pick = S.ifaces.find((i) => /wi-?fi|wlan|wireless|ethernet|^en0$|^eth0$|^wlp/i.test(i.label + " " + i.name));
        if (pick && $("#f-iface")) $("#f-iface").value = pick.index;
      }
    } catch (e) { S.ifaceError = errText(e); if (S.tool === "capture") renderTool(); }
  }

  function paintRun(toolId) {
    if (toolId !== S.tool || !$("#tool-result")) return;
    const view = S.runs[toolId];
    const running = view && view.status === "running";
    $$("#tool-main [data-run]").forEach((b) => { b.disabled = running; });
    $$("#tool-main [data-stop]").forEach((b) => { b.hidden = !running; });
    $("#tool-result").innerHTML = view && view.uiError ? `<div class="card"><div class="badline">${esc(view.uiError)}</div></div>` : resultHtml(toolId, view);
    $("#tool-console").innerHTML = view && view.id ? consoleHtml(view) : "";
    scrollConsole($("#tool-console"));
  }

  async function runTool(kindOverride) {
    const t = S.tool;
    const v = (id) => ($(id) || {}).value;
    let kind, params = {};
    if (t === "checkup") { kind = "checkup"; params = { wifi: !!($("#c-wifi") || {}).checked, devices: !!($("#c-devices") || {}).checked, mikrotik: !!($("#c-mikrotik") || {}).checked }; }
    if (t === "wifi") kind = "wifi";
    if (t === "nmap") { kind = "nmap"; params = { target: v("#f-target"), profile: v("#f-profile") }; }
    if (t === "capture") { kind = "capture"; params = { interface: v("#f-iface"), count: v("#f-count"), seconds: v("#f-seconds"), filter: v("#f-filter") }; }
    if (t === "ping") { kind = "ping"; params = { target: v("#f-target"), count: v("#f-count") }; }
    if (t === "trace") { kind = "traceroute"; params = { target: v("#f-target"), max_hops: v("#f-hops") }; }
    if (t === "zabbix") kind = "zabbix";
    if (t === "git") kind = kindOverride || "github";
    const tool = t;
    S.runs[tool] = { status: "running", all: [], title: "", seconds: 0 };
    paintRun(tool);
    try {
      const final = await runJob(kind, params, (view) => { S.runs[tool] = view; paintRun(tool); });
      if (tool === "git" && kind !== "github") {          // after fetch/pull, refresh the overview but keep the output
        const out = final;
        const overview = await runJob("github", {}, null);
        S.runs[tool] = { ...overview, all: out.all, cmd: out.cmd, title: out.title, status: out.status, error: out.error, seconds: out.seconds };
        paintRun(tool);
      }
    } catch (e) {
      S.runs[tool] = { status: "failed", uiError: errText(e), all: [] };
      paintRun(tool);
    }
  }

  // ------------------------------------------------------------------ result views
  const PALETTE = ["#1f7a4d", "#4338ca", "#c2410c", "#0369a1", "#a21caf", "#0f766e", "#b45309", "#7c3aed", "#b42318", "#64748b"];
  const PALETTE_DARK = ["#5fd39a", "#a5b4fc", "#fb923c", "#5ac8f0", "#e879f9", "#5eead4", "#fbbf24", "#c4a5ff", "#ff8a80", "#a8b3c7"];
  function hashColor(text) {
    let h = 0;
    for (const c of String(text)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    const pal = A.state.theme === "dark" ? PALETTE_DARK : PALETTE;
    return pal[h % pal.length];
  }
  const bar = (pct, color) => `<span class="meter"><i style="width:${Math.max(2, Math.min(100, pct))}%;background:${color || "var(--primary)"}"></i></span>`;
  const stat = (n, label) => `<div class="stat"><b>${esc(n)}</b><span>${esc(label)}</span></div>`;

  function resultHtml(tool, view) {
    if (!view) return "";
    const r = view.result;
    const problem = r && r.problem ? `<div class="problem"><b>Why this did not work:</b> ${esc(r.problem)}</div>` : "";
    return problem + resultBody(tool, view, r);
  }

  function resultBody(tool, view, r) {
    if (tool === "checkup" && r) return checkupHtml(r);
    if (r && r.problem && !(r.networks || []).length && !(r.rows || []).length && !(r.hosts || []).length) return "";
    if (tool === "wifi" && r) return wifiHtml(r);
    if (tool === "nmap" && r) return nmapHtml(r);
    if (tool === "capture" && r) return captureHtml(r);
    if (tool === "ping" && r) return `<div class="stats">${stat(r.loss_percent ?? "?", "% loss")}${stat(r.replies, "replies")}${stat(r.avg_ms ?? "–", "ms average")}${stat(view.status, "status")}</div>`;
    if (tool === "trace" && r) return traceHtml(r);
    if (tool === "zabbix" && r) return zabbixHtml(r);
    if (tool === "git" && r) return gitHtml(r);
    return "";
  }

  function checkupHtml(r) {
    const sevName = { bad: "problem", warn: "warning", info: "info", good: "ok" };
    const sevClass = { bad: "bad", warn: "warn", info: "", good: "ok" };
    const areas = [];
    for (const f of r.findings) {
      let a = areas.find((x) => x.name === f.area);
      if (!a) areas.push((a = { name: f.area, items: [] }));
      a.items.push(f);
    }
    const order = { bad: 0, warn: 1, info: 2, good: 3 };
    const tone = r.score >= 90 ? "ok" : r.score >= 60 ? "warn" : "bad";
    const devices = r.devices || [];
    const newOnes = devices.filter((d) => d.new);
    return `<div class="score-row">
        <div class="score ${tone}"><b>${r.score}</b><span>/100</span><em>${esc(r.grade)}</em></div>
        <div class="stats">${stat(r.counts.bad, "problems")}${stat(r.counts.warn, "warnings")}${stat(r.counts.good, "ok")}${stat(devices.length, "devices")}</div>
      </div>
      ${areas.map((a) => `<div class="card"><div class="card-head">${esc(a.name)}<span class="right">${a.items.filter((f) => f.severity === "bad" || f.severity === "warn").length} to fix</span></div>
        <table class="grid-table findings"><tbody>${a.items.sort((x, y) => order[x.severity] - order[y.severity]).map((f, i) => `<tr>
          <td class="sev"><span class="badge ${sevClass[f.severity]}">${sevName[f.severity]}</span></td>
          <td><b>${esc(f.title)}</b>${f.detail ? `<div class="muted">${esc(f.detail)}</div>` : ""}${f.fix ? `<div class="fix">${esc(f.fix)}</div>` : ""}</td>
          <td class="nowrap">${f.action ? `<button class="btn small primary" data-fix='${esc(JSON.stringify(f.action))}' data-title="${esc(f.title)}">Fix it</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`).join("")}
      ${devices.length ? `<div class="card"><div class="card-head">devices on ${esc(r.network.suggested_subnet || "")}<span class="right">${newOnes.length} new</span></div>
        ${newOnes.length ? `<div class="row-actions"><button class="btn" data-accept>Accept all as known</button></div>` : ""}
        <div class="table-scroll"><table class="grid-table"><thead><tr><th>address</th><th>name</th><th>mac / vendor</th><th>open risky ports</th><th></th></tr></thead><tbody>
        ${devices.map((h) => `<tr><td class="mono"><b>${esc(h.ip)}</b> ${h.new ? '<span class="badge warn">new</span>' : ""}</td><td>${esc(h.hostname || "–")}</td>
          <td class="mono">${esc(h.mac || "")} <span class="muted">${esc(h.vendor || "")}</span></td>
          <td>${(h.ports || []).map((p) => `<span class="port">${p.port} ${esc(p.service)}</span>`).join(" ") || '<span class="muted">none</span>'}</td>
          <td class="nowrap"><button class="btn small" data-host="${esc(h.ip)}" data-act="ports">Scan</button></td></tr>`).join("")}</tbody></table></div></div>` : ""}`;
  }

  async function previewFix(action, title) {
    const dlg = $("#jobdlg"), btn = $("#jobdlg-apply"), extra = $("#jobdlg-extra"), con = $("#jobdlg-console");
    $("#jobdlg-title").textContent = `Fix: ${title}`;
    extra.innerHTML = ""; btn.hidden = true; btn.disabled = false; con.textContent = "Loading…";
    dlg.showModal();
    const show = (r, note) => {
      con.textContent = `${r.title}\n\n` + r.steps.map((st) =>
        `RouterOS command:  ${st.cli}\nREST call sent:    ${st.rest}` +
        (st.current !== undefined ? `\nRouter now:        ${st.current}    after the fix: ${st.target}${st.needed === false ? "   (already set)" : ""}` : "") +
        (st.after !== undefined ? `\nRead back:         ${st.after}    ${st.ok ? "OK, verified" : "NOT as expected"}` : "")).join("\n\n") +
        (note ? `\n\n${note}` : "");
    };
    const call = (mode, confirm = false) => api("api/fix", { action: action.id, params: action.params, mode, confirm });
    try {
      const pv = await call("preview");
      show(pv, "Step 1 of 2: dry run. It reads the current values from your router and changes nothing.");
      $("#jobdlg-state").innerHTML = '<span class="job-badge">preview</span>';
      btn.textContent = "Dry run"; btn.hidden = false;
      btn.onclick = async () => {
        btn.hidden = true;
        try {
          const dr = await call("dry-run");
          $("#jobdlg-state").innerHTML = '<span class="job-badge cancelled">dry run done</span>';
          if (!dr.steps.some((st) => st.needed)) { show(dr, "Nothing to do: the router already has these values."); return; }
          if (dr.dry_run_setting) {
            show(dr, `${dr.message}\n\nStep 2 is blocked because Dry run is on in Settings (NETOPS_DRY_RUN=true). ` +
              "Set it to false on the Settings page, then open this fix again to apply it.");
            return;
          }
          show(dr, `${dr.message}\n\nStep 2 of 2: tick the box, then click "Apply to router".`);
          extra.innerHTML = '<label class="confirm"><input type="checkbox" id="fix-confirm"> I have read the commands above and want to change my router now.</label>';
          btn.textContent = "Apply to router"; btn.hidden = false; btn.disabled = true;
          $("#fix-confirm").onchange = (e) => { btn.disabled = !e.target.checked; };
          btn.onclick = async () => {
            btn.hidden = true; extra.innerHTML = "";
            try {
              const ap = await call("apply", true);
              show(ap, ap.message);
              $("#jobdlg-state").innerHTML = ap.verified ? '<span class="job-badge done">applied and verified</span>' : '<span class="job-badge failed">check the router</span>';
            } catch (e) { show(dr, `Not applied: ${errText(e)}`); }
          };
        } catch (e) { con.textContent = `Dry run failed: ${errText(e)}`; }
      };
    } catch (e) { con.textContent = errText(e); }
  }

  function wifiHtml(r) {
    const s = r.summary;
    const maxCount = Math.max(1, ...Object.values(s.channels));
    const ch24 = Array.from({ length: 13 }, (_, i) => i + 1);
    const ch5 = Object.keys(s.channels).map(Number).filter((c) => c > 14);
    const col = (c) => `<div class="chan"><span class="chan-bar"><i style="height:${((s.channels[c] || 0) / maxCount) * 100}%"></i></span><b>${c}</b><small>${s.channels[c] || ""}</small></div>`;
    return `<div class="stats">${stat(s.networks, "networks")}${stat(s.access_points, "access points")}${stat(Object.keys(s.channels).length, "channels in use")}${stat(s.open_or_wep.length, "open or WEP")}</div>
      ${r.hint ? `<div class="warnbox">${esc(r.hint)}</div>` : ""}
      ${s.open_or_wep.length ? `<div class="warnbox">Open or WEP networks (anyone can listen in): ${s.open_or_wep.map(esc).join(", ")}</div>` : ""}
      <div class="card"><div class="card-head"><span class="dash"></span>Channels<span class="right">fewer networks on a channel = less interference</span></div>
        <div class="chans"><div class="chan-group"><div class="h-small">2.4 GHz</div><div class="chan-row">${ch24.map(col).join("")}</div></div>
        ${ch5.length ? `<div class="chan-group"><div class="h-small">5 / 6 GHz</div><div class="chan-row">${ch5.map(col).join("")}</div></div>` : ""}</div></div>
      <div class="card"><div class="card-head"><span class="dash"></span>Networks</div><div class="table-scroll"><table class="grid-table">
        <thead><tr><th>Network</th><th>Signal</th><th>Channel</th><th>Band</th><th>Security</th><th>Access point</th></tr></thead><tbody>
        ${r.networks.map((n) => `<tr><td><b>${esc(n.ssid)}</b> ${n.connected ? '<span class="badge ok">connected</span>' : ""}</td>
          <td class="mono">${bar(n.signal || 0, (n.signal || 0) > 60 ? "var(--ok)" : (n.signal || 0) > 35 ? "var(--warn)" : "var(--bad)")} ${n.signal ?? "?"}%</td>
          <td class="mono">${n.channel ?? "?"}</td><td>${esc(n.band)}</td>
          <td>${/open|wep|none/i.test(n.security || "open") ? `<span class="badge bad">${esc(n.security || "Open")}</span>` : esc(n.security)}</td>
          <td class="mono">${esc(n.bssid)}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">No networks found. Is Wi-Fi switched on? On macOS, allow Location for Terminal.</td></tr>`}
        </tbody></table></div></div>`;
  }

  function nmapHtml(r) {
    const hosts = r.hosts || [];
    const ports = hosts.reduce((n, h) => n + h.ports.length, 0);
    return `<div class="stats">${stat(hosts.length, "devices up")}${stat(ports, "open ports")}${stat(hosts.filter((h) => h.vendor).length, "with vendor")}${stat(hosts.filter((h) => h.os).length, "with OS guess")}</div>
      ${r.summary ? `<p class="muted">${esc(r.summary)}</p>` : ""}
      <div class="card"><div class="card-head"><span class="dash"></span>Devices</div><div class="table-scroll"><table class="grid-table">
      <thead><tr><th>Address</th><th>Name</th><th>MAC / vendor</th><th>Open ports</th><th>OS</th><th></th></tr></thead><tbody>
      ${hosts.map((h) => `<tr><td class="mono"><b>${esc(h.ip)}</b></td><td>${esc(h.hostname || "–")}</td>
        <td class="mono">${esc(h.mac || "")}${h.vendor ? `<br><span class="muted">${esc(h.vendor)}</span>` : ""}</td>
        <td>${h.ports.map((p) => `<span class="port" title="${esc(p.version)}">${p.port}/${esc(p.proto)} ${esc(p.service)}</span>`).join(" ") || '<span class="muted">none found</span>'}</td>
        <td>${esc(h.os || "")}</td>
        <td class="nowrap"><button class="btn small" data-host="${esc(h.ip)}" data-act="ping">Ping</button>
          <button class="btn small" data-host="${esc(h.ip)}" data-act="trace">Trace</button>
          <button class="btn small" data-host="${esc(h.ip)}" data-act="ports">Ports</button></td></tr>`).join("")
        || `<tr><td colspan="6" class="muted">No devices answered.</td></tr>`}</tbody></table></div></div>`;
  }

  function captureHtml(r) {
    const s = r.summary;
    const maxP = Math.max(1, ...s.protocols.map((p) => p[1]));
    const maxT = Math.max(1, ...s.top_talkers.map((p) => p[1]));
    const live = A.state.live && r.file;
    const ws = S.tools && S.tools.tools.wireshark && S.tools.tools.wireshark.found;
    return `<div class="stats">${stat(s.packets, "packets")}${stat(fmtBytes(s.bytes), "captured")}${stat(s.protocols.length, "protocols")}${stat(s.conversations.length, "conversations")}</div>
      ${live ? `<div class="row-actions"><a class="btn" href="api/files/${esc(r.file)}" data-download>Download ${esc(r.file)}</a>
        <button class="btn" data-wireshark="${esc(r.file)}" ${ws ? "" : "disabled title='Wireshark is not installed'"}>Open in Wireshark</button>
        <span class="muted small-text">Saved in ${esc(r.path)}</span></div>` : ""}
      <div class="two">
        <div class="card"><div class="card-head"><span class="dash"></span>Protocols</div>
          ${s.protocols.map(([p, n]) => `<div class="barrow"><span>${esc(p)}</span>${bar((n / maxP) * 100, hashColor(p))}<b>${n}</b></div>`).join("")}</div>
        <div class="card"><div class="card-head"><span class="dash"></span>Top talkers (bytes sent)</div>
          ${s.top_talkers.map(([h, n]) => `<div class="barrow"><span class="mono">${esc(h)}</span>${bar((n / maxT) * 100)}<b>${fmtBytes(n)}</b></div>`).join("")}</div>
      </div>
      <div class="card"><div class="card-head"><span class="dash"></span>Packets<span class="right">${r.rows.length} shown</span></div>
        <div class="table-scroll tall"><table class="events packets"><thead><tr><th>No.</th><th class="num">Time (s)</th><th>Source</th><th>Destination</th><th>Protocol</th><th class="num">Bytes</th><th>Info</th></tr></thead><tbody>
        ${r.rows.map((p) => `<tr style="--c:${hashColor(p.proto)}"><td><span class="no">${p.no}</span></td><td class="num">${p.time.toFixed(3)}</td>
          <td class="mono">${esc(p.src)}${p.sport ? `:${esc(p.sport)}` : ""}</td><td class="mono">${esc(p.dst)}${p.dport ? `:${esc(p.dport)}` : ""}</td>
          <td><span class="proto"><i></i>${esc(p.proto)}</span></td><td class="num">${p.len}</td><td class="sum" title="${esc(p.info)}">${esc(p.info)}</td></tr>`).join("")
          || `<tr><td colspan="7" class="muted">No packets were captured. Try another interface or an empty filter.</td></tr>`}</tbody></table></div></div>`;
  }

  function traceHtml(r) {
    const max = Math.max(1, ...r.hops.map((h) => h.ms || 0));
    return `<div class="card"><div class="card-head"><span class="dash"></span>Hops<span class="right">${r.hops.length} hops</span></div>
      <table class="grid-table"><thead><tr><th>Hop</th><th>Address</th><th>Delay</th><th></th></tr></thead><tbody>
      ${r.hops.map((h) => `<tr><td class="mono">${h.hop}</td><td class="mono">${h.timeout ? '<span class="muted">* no answer</span>' : esc(h.address)}</td>
        <td class="mono">${h.ms != null ? h.ms + " ms" : "–"}</td><td style="width:40%">${h.ms != null ? bar((h.ms / max) * 100) : ""}</td></tr>`).join("")}</tbody></table></div>`;
  }

  function zabbixHtml(r) {
    if (!r.configured) return `<div class="warnbox">Zabbix is not set up yet. Add its address and an API token on the <button class="linkbtn" data-goto="settings">Settings</button> page.</div>`;
    const sevClass = { Disaster: "bad", High: "bad", Average: "warn", Warning: "warn" };
    return `<div class="stats">${stat(r.version, "Zabbix version")}${stat(r.hosts ?? "?", "hosts")}${stat((r.problems || []).length, "open problems")}${stat(new URL(r.url).host, "server")}</div>
      ${r.error ? `<div class="warnbox">${esc(r.error)}</div>` : ""}
      <div class="card"><div class="card-head"><span class="dash"></span>Open problems</div><table class="grid-table">
      <thead><tr><th>Severity</th><th>Host</th><th>Problem</th><th>Since</th></tr></thead><tbody>
      ${(r.problems || []).map((p) => `<tr><td><span class="badge ${sevClass[p.severity] || ""}">${esc(p.severity)}</span></td><td><b>${esc(p.host)}</b></td>
        <td>${esc(p.problem)}</td><td class="mono">${ago(p.since)}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">No open problems.</td></tr>`}</tbody></table></div>`;
  }

  function gitHtml(r) {
    const g = r.git || {};
    if (!g.is_repo) return `<div class="warnbox">${esc(g.error || "Not a Git repository.")}</div>`;
    S.slug = r.slug || S.slug;
    const runIcon = (x) => x.status !== "completed" ? `<span class="badge warn">${esc(x.status)}</span>` :
      `<span class="badge ${x.conclusion === "success" ? "ok" : x.conclusion === "failure" ? "bad" : ""}">${esc(x.conclusion || "?")}</span>`;
    return `<div class="stats">${stat(g.branch, "branch")}${stat(g.behind ?? "–", "behind")}${stat(g.ahead ?? "–", "ahead")}${stat(g.changed_files.length, "changed files")}</div>
      <div class="two">
        <div class="card"><div class="card-head"><span class="dash"></span>Git<span class="right">${esc(g.upstream || "no upstream")}</span></div>
          <dl class="kv"><dt>Remote</dt><dd>${esc(g.remote || "none")}</dd><dt>Folder</dt><dd>${esc(g.root)}</dd></dl>
          ${g.changed_files.length ? `<div class="h-small">Changed files</div><div class="cmds">${g.changed_files.slice(0, 12).map((f) => `<code>${esc(f)}</code>`).join("")}</div>` : ""}
          <div class="h-small">Last commits</div>
          <ul class="commits">${g.commits.map((c) => `<li><code>${esc(c.hash)}</code> ${esc(c.subject)} <span class="muted">${esc(c.author)}, ${esc(c.when)}</span></li>`).join("")}</ul></div>
        <div class="card"><div class="card-head"><span class="dash"></span>GitHub<span class="right">${r.token ? "token set" : "no token: public data only"}</span></div>
          ${!r.slug ? `<p class="muted">The remote 'origin' is not on GitHub.</p>` : r.repo ? `
            <p><a href="${esc(r.repo.html_url)}" target="_blank" rel="noopener">${esc(r.repo.full_name)}</a> · ${r.repo.private ? "private" : "public"} · default branch <code>${esc(r.repo.default_branch)}</code> · ${r.repo.open_issues_count} open issues and PRs</p>
            <div class="h-small">Open pull requests</div>
            <ul class="commits">${(r.pulls || []).map((p) => `<li><a href="${esc(p.url)}" target="_blank" rel="noopener">#${p.number} ${esc(p.title)}</a> <span class="muted">${esc(p.user)}, ${esc(p.branch)}${p.draft ? ", draft" : ""}</span></li>`).join("") || '<li class="muted">none</li>'}</ul>
            <div class="h-small">Latest Actions runs</div>
            <ul class="commits">${(r.runs || []).map((x) => `<li>${runIcon(x)} <a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.name)}</a> <span class="muted">${esc(x.branch)}, ${esc(x.event)}, ${esc(new Date(x.when).toLocaleString())}</span></li>`).join("") || '<li class="muted">none</li>'}</ul>`
            : `<div class="warnbox">GitHub did not return ${esc(r.slug)} (${esc(r.repo_error || "")}). For a private repo, add a token on the <button class="linkbtn" data-goto="settings">Settings</button> page.</div>`}</div>
      </div>`;
  }

  // ------------------------------------------------------------------ tools page events
  function bindTools() {
    $("#tool-list").addEventListener("click", (e) => {
      const b = e.target.closest("[data-tool]");
      if (!b) return;
      S.tool = b.dataset.tool;
      localStorage.setItem("netauto-tool", S.tool);
      renderToolList();
      renderTool();
    });
    $("#tool-main").addEventListener("click", async (e) => {
      const el = e.target.closest("button, a");
      if (!el) return;
      if (el.hasAttribute("data-run")) return runTool();
      if (el.dataset.fix) return previewFix(JSON.parse(el.dataset.fix), el.dataset.title);
      if (el.hasAttribute("data-accept")) {
        try { const r = await api("api/devices/accept", {}); el.textContent = `Saved: ${r.known} known devices`; el.disabled = true; }
        catch (err) { alert(errText(err)); }
        return;
      }
      if (el.dataset.install) {
        const tool = S.tool, name = el.dataset.install;
        S.runs[tool] = { status: "running", all: [] };
        paintRun(tool);
        try {
          await runJob("install", { tool: name }, (v) => { S.runs[tool] = v; paintRun(tool); });
          await loadToolInfo(true); renderToolList(); renderTool();
        } catch (err) { S.runs[tool] = { status: "failed", uiError: errText(err), all: [] }; paintRun(tool); }
        return;
      }
      if (el.hasAttribute("data-stop")) { const v = S.runs[S.tool]; if (v && v.id) stopJob(v.id); return; }
      if (el.dataset.git) return runTool(el.dataset.git);
      if (el.hasAttribute("data-ifaces")) return refreshIfaces();
      if (el.hasAttribute("data-recheck")) { await loadToolInfo(true); renderToolList(); renderTool(); return; }
      if (el.dataset.fill !== undefined) { const t = $("#f-target"); if (t) t.value = el.dataset.fill; return; }
      if (el.dataset.filter !== undefined) { $("#f-filter").value = el.dataset.filter; return; }
      if (el.dataset.goto) { A.setPage(el.dataset.goto); return; }
      if (el.dataset.wireshark) {
        try { await api("api/wireshark", { file: el.dataset.wireshark }); el.textContent = "Opened in Wireshark"; }
        catch (err) { alert(errText(err)); }
        return;
      }
      if (el.dataset.download !== undefined) {      // the token goes in a header, so download through fetch
        e.preventDefault();
        const r = await fetch(el.getAttribute("href"), { headers: { "X-NetAuto-Token": tokenValue() } });
        const blob = await r.blob();
        const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: el.getAttribute("href").split("/").pop() });
        document.body.appendChild(a); a.click(); a.remove();
        return;
      }
      if (el.dataset.host) {
        const ip = el.dataset.host, act = el.dataset.act;
        S.tool = act === "ports" ? "nmap" : act === "trace" ? "trace" : "ping";
        localStorage.setItem("netauto-tool", S.tool);
        renderToolList(); renderTool();
        $("#f-target").value = ip;
        if (act === "ports") $("#f-profile").value = "services";
        runTool();
      }
    });
    $("#tool-main").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.target.matches("input")) { e.preventDefault(); runTool(); }
    });
  }
  const tokenValue = () => (document.querySelector('meta[name="netauto-token"]') || {}).content || "";

  // ------------------------------------------------------------------ programs: run a check
  PAGES.runProgram = async (program, action) => {
    const dlg = $("#jobdlg");
    $("#jobdlg-title").textContent = `${program} ${action}`;
    $("#jobdlg-console").textContent = "starting…";
    $("#jobdlg-state").innerHTML = '<span class="job-badge running">running</span>';
    dlg.showModal();
    try {
      const view = await runJob("program", { program, action }, (v) => {
        $("#jobdlg-console").textContent = v.all.join("\n") || "(no output yet)";
        $("#jobdlg-console").scrollTop = 1e9;
        $("#jobdlg-state").innerHTML = `<span class="job-badge ${v.status}">${v.status}</span> ${v.seconds} s`;
      });
      if (view.status !== "done") $("#jobdlg-console").textContent += `\n\nThe check found problems. Fix the settings on the Settings page and run it again.`;
    } catch (e) {
      $("#jobdlg-console").textContent = errText(e);
      $("#jobdlg-state").innerHTML = '<span class="job-badge failed">failed</span>';
    }
  };

  // ------------------------------------------------------------------ diagnostics
  const ICON = { ok: "✓", warn: "!", fail: "✕", skip: "–" };

  function diagHtml(checks, filter) {
    const groups = [];
    for (const c of checks) {
      if (filter && !filter(c)) continue;
      let g = groups.find((x) => x.name === c.group);
      if (!g) groups.push((g = { name: c.group, items: [] }));
      g.items.push(c);
    }
    return groups.map((g) => `<div class="card"><div class="card-head"><span class="dash"></span>${esc(g.name)}
      <span class="right">${g.items.filter((c) => c.status === "ok").length} of ${g.items.length} ok</span></div>
      <table class="grid-table diag"><tbody>${g.items.map((c) => `<tr class="st-${c.status}"><td class="ic"><span class="dot ${c.status}">${ICON[c.status]}</span></td>
        <td><b>${esc(c.name)}</b></td><td>${esc(c.detail)}${c.fix ? `<div class="fix">${esc(c.fix)}</div>` : ""}</td></tr>`).join("")}</tbody></table></div>`).join("");
  }

  function countsHtml(counts) {
    return ["fail", "warn", "ok", "skip"].map((k) => `<span class="count ${k}"><b>${counts[k] || 0}</b> ${{ fail: "failed", warn: "warnings", ok: "ok", skip: "skipped" }[k]}</span>`).join("");
  }

  async function runDiagnostics(target, filter) {
    const btn = $("#btn-run-diag");
    btn.disabled = true;
    try {
      const view = await runJob("diagnostics", {}, (v) => {
        const checks = (v.result && v.result.checks) || [];
        S.diag = { checks, counts: v.result && v.result.counts };
        const counts = {};
        checks.forEach((c) => { counts[c.status] = (counts[c.status] || 0) + 1; });
        if (target === "diag") {
          $("#diag-counts").innerHTML = (v.status === "running" ? '<span class="spin"></span>' : "") + countsHtml(counts);
          $("#diag-results").innerHTML = diagHtml(checks);
        } else {
          $("#settings-result").innerHTML = (v.status === "running" ? '<p class="muted"><span class="spin"></span>Testing…</p>' : "") + diagHtml(checks, filter);
        }
      });
      const gh = (view.result.checks || []).find((c) => c.group === "GitHub" && c.name === "Repository" && c.status === "ok");
      if (gh) S.slug = gh.detail.split(" ")[0];
    } catch (e) {
      (target === "diag" ? $("#diag-results") : $("#settings-result")).innerHTML = `<div class="card"><p class="badline">${esc(errText(e))}</p></div>`;
    } finally { btn.disabled = false; }
  }

  async function runTests() {
    const card = $("#tests-card"), btn = $("#btn-run-tests");
    card.hidden = false; btn.disabled = true;
    try {
      const view = await runJob("tests", {}, (v) => {
        $("#tests-console").textContent = v.all.slice(-400).join("\n");
        $("#tests-console").scrollTop = 1e9;
        $("#tests-state").textContent = v.status === "running" ? `running ${v.seconds} s` : "";
      });
      const r = view.result || {};
      $("#tests-state").innerHTML = r.ok ? `<span class="badge ok">${r.ran} tests passed in ${r.seconds} s</span>`
        : `<span class="badge bad">failed${r.failures ? ": " + esc(r.failures) : ""}</span>`;
    } catch (e) {
      $("#tests-console").textContent = errText(e);
    } finally { btn.disabled = false; }
  }

  async function pollLog() {
    if (A.state.page !== "diagnostics" || !A.state.live) { clearInterval(S.logTimer); S.logTimer = null; return; }
    try {
      const r = await api(`api/debug?since=${S.logSince}`);
      if (r.log.length) {
        S.log.push(...r.log);
        S.log = S.log.slice(-1000);
        S.logSince = S.log[S.log.length - 1].n;
        renderLog();
      }
    } catch (e) { /* the server may be restarting */ }
  }

  function renderLog() {
    const level = $("#log-level").value;
    const keep = (i) => !level || (level === "warn" ? i.level !== "info" : i.level === "error");
    const items = S.log.filter(keep).slice(-300).reverse();
    $("#debug-log").innerHTML = items.map((i) => `<div class="log-row ${i.level}"><span class="mono">${new Date(i.t * 1000).toLocaleTimeString()}</span>
      <span class="lvl ${i.level}">${i.level}</span><span class="src">${esc(i.source)}</span>
      <span class="msg">${i.detail ? `<details><summary>${esc(i.message)}</summary><pre>${esc(i.detail)}</pre></details>` : esc(i.message)}</span></div>`).join("")
      || '<p class="muted">Nothing logged yet.</p>';
  }

  function debugReport() {
    const st = A.state.status || {};
    const lines = [`### NetAuto console debug report`, ``, `- netauto ${st.version || "?"} on ${st.system || navigator.platform}`,
      `- browser: ${navigator.userAgent}`, `- page: ${A.state.page}`, ``];
    if (S.diag && S.diag.checks.length) {
      lines.push("#### Checks", "");
      S.diag.checks.filter((c) => c.status !== "skip").forEach((c) => lines.push(`- ${c.status.toUpperCase()} ${c.group} / ${c.name}: ${c.detail}`));
      lines.push("");
    }
    lines.push("#### Last log entries", "", "```");
    S.log.slice(-60).forEach((i) => lines.push(`${new Date(i.t * 1000).toISOString()} ${i.level} ${i.source}: ${i.message}`));
    lines.push("```");
    const errors = S.log.filter((i) => i.level === "error" && i.detail).slice(-2);
    if (errors.length) { lines.push("", "#### Last error details", "", "```"); errors.forEach((i) => lines.push(i.detail)); lines.push("```"); }
    return lines.join("\n").replace(/(https?:\/\/)[^/@\s]+@/g, "$1***@").replace(/\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, "***");
  }

  async function copyText(text, btn) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) {
      const ta = Object.assign(document.createElement("textarea"), { value: text });
      document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
    }
    const old = btn.textContent; btn.textContent = "Copied"; setTimeout(() => { btn.textContent = old; }, 1400);
  }

  PAGES.diagnostics = async () => {
    if (!A.state.live) return;
    if (S.diag) { $("#diag-results").innerHTML = diagHtml(S.diag.checks); }
    if (!S.logTimer) { pollLog(); S.logTimer = setInterval(pollLog, 2000); }
    if (!S.slug) runJob("git-status", {}, null).then((v) => { S.slug = v.result && v.result.github; }).catch(() => {});
  };

  // ------------------------------------------------------------------ settings
  let settingsData = null;
  const removeSecret = new Set();

  PAGES.settings = async () => {
    if (!A.state.live) { $("#settings").innerHTML = ""; return; }
    try { settingsData = await api("api/settings"); } catch (e) { $("#settings").innerHTML = `<p class="badline">${esc(errText(e))}</p>`; return; }
    removeSecret.clear();
    $("#settings-path").innerHTML = `Saved in <code>${esc(settingsData.path)}</code>, the same file every netops program reads. Secrets are never shown again after you save them.`;
    const groups = [];
    for (const f of settingsData.fields) {
      let g = groups.find((x) => x.name === f.group);
      if (!g) groups.push((g = { name: f.group, fields: [] }));
      g.fields.push(f);
    }
    $("#settings").innerHTML = groups.map((g) => `<div class="card"><div class="card-head"><span class="dash"></span>${esc(g.name)}
      <span class="right">${g.fields.filter((f) => f.set).length} of ${g.fields.length} set</span></div>
      ${g.fields.map((f) => `<label class="setting"><span>${esc(f.label)} <code>${esc(f.key)}</code>${f.from_env ? ' <span class="badge">from environment</span>' : ""}</span>
        <span class="row"><input data-key="${esc(f.key)}" type="${f.secret ? "password" : "text"}" autocomplete="off" spellcheck="false"
          value="${esc(f.value)}" placeholder="${esc(f.secret && f.set ? "saved – leave empty to keep" : f.placeholder)}">
        ${f.secret && f.set ? `<button type="button" class="btn small" data-remove="${esc(f.key)}">Remove</button>` : ""}</span></label>`).join("")}</div>`).join("");
  };

  async function saveSettings() {
    const values = {};
    $$("#settings input[data-key]").forEach((inp) => {
      const f = settingsData.fields.find((x) => x.key === inp.dataset.key);
      const v = inp.value.trim();
      if (f.secret) { if (v) values[f.key] = v; else if (removeSecret.has(f.key)) values[f.key] = ""; }
      else if (v !== (f.value || "")) values[f.key] = v;
    });
    const out = $("#settings-result");
    if (!Object.keys(values).length) { out.innerHTML = '<p class="muted">Nothing changed.</p>'; return; }
    try {
      const r = await api("api/settings", { values });
      out.innerHTML = `<div class="okline">✓ Saved ${r.saved.length} setting(s) in ${esc(r.path)}. Click “Test connections” to check them.</div>`;
      await PAGES.settings();
    } catch (e) { out.innerHTML = `<div class="badline">${esc(errText(e))}</div>`; }
  }

  // ------------------------------------------------------------------ wire up
  function bind() {
    bindTools();
    $("#btn-run-diag").addEventListener("click", () => runDiagnostics("diag"));
    $("#btn-run-tests").addEventListener("click", runTests);
    $("#log-level").addEventListener("change", renderLog);
    $("#btn-copy-report").addEventListener("click", (e) => copyText(debugReport(), e.currentTarget));
    $("#btn-report-bug").addEventListener("click", () => {
      const body = debugReport().slice(0, 6000);
      if (!S.slug) { copyText(body, $("#btn-report-bug")); alert("No GitHub repository found for this folder. The report is copied: paste it in a new issue."); return; }
      const url = `https://github.com/${S.slug}/issues/new?title=${encodeURIComponent("Bug: ")}&body=${encodeURIComponent("**What happened?**\n\n**What did you expect?**\n\n" + body)}`;
      window.open(url, "_blank", "noopener");
    });
    $("#btn-save-settings").addEventListener("click", saveSettings);
    $("#btn-test-conn").addEventListener("click", () => runDiagnostics("settings", (c) => ["Services", "GitHub"].includes(c.group) || c.name === "Connection to origin"));
    $("#settings").addEventListener("click", (e) => {
      const b = e.target.closest("[data-remove]");
      if (!b) return;
      removeSecret.add(b.dataset.remove);
      b.textContent = "Removed on save";
      b.disabled = true;
    });
  }

  bind();
  // The page may already be open (hash link) before this script loaded.
  if (PAGES[A.state.page]) PAGES[A.state.page]();
})();
